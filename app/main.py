import asyncio
import re

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.utils._redis import init_redis_client, close_redis_client, get_redis_client
from app.utils.limiter import Limiter
from app.utils.logger import logger
from app.rules import rules
from app.routers import api_router


class CustomTimeoutException(Exception):
    pass


class CustomPayloadTooLargeException(Exception):
    pass


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
    app.add_middleware(RateLimitMiddleware, limiter=Limiter(), rules_map=rules)
    app.add_middleware(EnforceJSONMiddleware)
    app.add_middleware(BodySizeLimiter, max_size=20_000, timeout=5)
    app.include_router(api_router)

    @app.on_event("startup")
    async def startup_event():
        await init_redis_client()
        app.state.redis = get_redis_client()
        logger.info("Redis client initialized and app started")

    @app.on_event("shutdown")
    async def shutdown_event():
        await close_redis_client()
        logger.info("Redis client closed and app stopped")

    @app.get("/")
    async def root():
        return {"message": "Hello welcome to Null Service"}

    return app

app= create_app()

