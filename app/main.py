import asyncio
import logging
import re
import time
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.utils._redis import init_redis_client, close_redis_client, get_redis_client
from app.utils.db import AsyncSessionLocal, init_db
from app.models.connections import purge_expired_drops
from app.utils.limiter import Limiter
from app.utils.logger import log_event, logger, request_id_context, safe_exception
from app.rules import rules
from app.routers import api_router


DROP_CLEANUP_INTERVAL_SECONDS = 300


async def _drop_cleanup_loop() -> None:
    """Periodically delete expired contact/dh drops.

    Reads already filter on expiry, so this only reclaims rows that would
    otherwise sit forever in inboxes nobody ever fetches.
    """
    while True:
        try:
            async with AsyncSessionLocal() as db:
                removed = await purge_expired_drops(db)
            if removed:
                logger.info("Purged %s expired contact/dh drop(s)", removed)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("Drop cleanup failed: %s", safe_exception(exc))
        await asyncio.sleep(DROP_CLEANUP_INTERVAL_SECONDS)


class CustomTimeoutException(Exception):
    pass


class CustomPayloadTooLargeException(Exception):
    pass


class RequestLoggingMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = uuid4().hex
        request_token = request_id_context.set(request_id)
        started = time.perf_counter()
        status_code = 500

        async def tracking_send(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                headers = list(message.get("headers", []))
                headers.append((b"x-request-id", request_id.encode("ascii")))
                message = {**message, "headers": headers}
            await send(message)

        route = "<unmatched>"
        try:
            log_event(logging.INFO, "request.start", method=scope.get("method", "-"))
            await self.app(scope, receive, tracking_send)
        except Exception as exc:
            log_event(logging.ERROR, "request.error", error=safe_exception(exc))
            raise
        finally:
            route_obj = scope.get("route")
            if route_obj is not None:
                route = getattr(route_obj, "path", route)
            log_event(
                logging.INFO if status_code < 400 else logging.WARNING,
                "request.complete",
                method=scope.get("method", "-"),
                route=route,
                status_code=status_code,
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )
            request_id_context.reset(request_token)


class RateLimitMiddleware:
    def __init__(self, app: ASGIApp, limiter: Limiter, rules_map: dict[str, str]):
        self.app = app
        self.limiter = limiter
        self.rules_map = rules_map
        self.pattern_rules = []

        for path_pattern, rule in rules_map.items():
            if "{" in path_pattern and "}" in path_pattern:
                regex_pattern = re.escape(path_pattern)
                regex_pattern = regex_pattern.replace(r"\{", "{").replace(r"\}", "}")
                regex_pattern = re.sub(r"\{[^/]+\}", "[^/]+", regex_pattern)
                self.pattern_rules.append((re.compile(r"^" + regex_pattern + r"$"), rule))

    def _find_matching_rule(self, path: str):
        if path in self.rules_map:
            return self.rules_map[path]
        for regex, rule in self.pattern_rules:
            if regex.match(path):
                return rule
        return None

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        rule = self._find_matching_rule(request.url.path)
        if rule:
            allowed, stage = await self.limiter.hit(rule, request, request.url.path)
            if not allowed:
                await asyncio.sleep(min((stage + 1) * 1.5, 6))
                response = JSONResponse(
                    {"detail": "Too many requests"}, status_code=429
                )
                await response(scope, receive, send)
                return

        await self.app(scope, receive, send)


class EnforceJSONMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            content_length = request.headers.get("content-length")
            transfer_encoding = request.headers.get("transfer-encoding", "")
            has_body = (
                (content_length is not None and content_length != "0")
                or "chunked" in transfer_encoding.lower()
            )
            content_type = request.headers.get("content-type", "").lower()
            if has_body and "application/json" not in content_type and "+json" not in content_type:
                response = JSONResponse(
                    {"detail": "Only application/json is allowed"}, status_code=415
                )
                await response(scope, receive, send)
                return

        await self.app(scope, receive, send)


class BodySizeLimiter:
    def __init__(self, app: ASGIApp, max_size: int = 20_000, timeout: int = 5):
        self.app = app
        self.max_size = max_size
        self.timeout = timeout

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        total_size = 0
        body_done = False
        response_started = False

        async def limited_receive():
            nonlocal total_size, body_done
            if body_done:
                return await receive()

            try:
                message = await asyncio.wait_for(receive(), timeout=self.timeout)
            except asyncio.TimeoutError as exc:
                raise CustomTimeoutException() from exc

            if message["type"] == "http.request":
                total_size += len(message.get("body", b""))
                if total_size > self.max_size:
                    body_done = True
                    raise CustomPayloadTooLargeException()
                if not message.get("more_body", False):
                    body_done = True
            elif message["type"] == "http.disconnect":
                body_done = True
            return message

        async def tracking_send(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except CustomTimeoutException:
            if response_started:
                raise
            await JSONResponse({"detail": "Request timeout"}, status_code=408)(scope, receive, send)
        except CustomPayloadTooLargeException:
            if response_started:
                raise
            await JSONResponse({"detail": "Request too large"}, status_code=413)(scope, receive, send)


def create_app() -> FastAPI:
    app = FastAPI(
        title="Null Service",
        docs_url="/docs",
        redoc_url="/redoc"
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"]
    )
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(RateLimitMiddleware, limiter=Limiter(), rules_map=rules)
    app.add_middleware(EnforceJSONMiddleware)
    app.add_middleware(BodySizeLimiter, max_size=20_000, timeout=5)
    app.include_router(api_router)

    @app.on_event("startup")
    async def startup_event():
        await init_db()
        await init_redis_client()
        app.state.redis = get_redis_client()
        app.state.drop_cleanup_task = asyncio.create_task(_drop_cleanup_loop())
        logger.info("Database tables ensured, Redis client initialized and app started")

    @app.on_event("shutdown")
    async def shutdown_event():
        cleanup_task = getattr(app.state, "drop_cleanup_task", None)
        if cleanup_task is not None:
            cleanup_task.cancel()
            try:
                await cleanup_task
            except asyncio.CancelledError:
                pass
        await close_redis_client()
        logger.info("Redis client closed and app stopped")

    @app.get("/")
    async def root():
        return {"message": "Hello welcome to Null Service"}

    return app

app= create_app()

