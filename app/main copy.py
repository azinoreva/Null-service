import os, hashlib, json, asyncio, re
from fastapi import APIRouter, FastAPI, WebSocket, WebSocketDisconnect, HTTPException, status, Request
from pydantic import BaseModel
import redis.asyncio as aioredis

from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Scope, Receive, Send
from pathlib import Path
from app.log import logger
from app.utility.limiter import Limiter
from app.utility._redis import get_redis_client, close_redis, init_redis
from app.rules import rules
from app.utility.config import settings
from app.utility.peers import (
    start_directory_refresh_loop,
    start_socket_sweeper,
    stop_all,
)
from app.routers import api_router


class CustomTimeoutException(Exception):
    """Internal exception to trigger a 408 response cleanly."""
    pass


class CustomPayloadTooLargeException(Exception):
    """Internal exception to trigger a 413 response cleanly."""
    pass


class RateLimitMiddleware:
    def __init__(self, app: ASGIApp, limiter, rules_map):
        self.app = app
        self.limiter = limiter
        self.rules_map = rules_map
        self.pattern_rules = []

        for path_pattern, rule in rules_map.items():
            if "{" in path_pattern and "}" in path_pattern:
                regex_pattern = re.escape(path_pattern)
                regex_pattern = regex_pattern.replace("\\{", "{").replace("\\}", "}")
                regex_pattern = re.sub(r"\{[^/]+\}", "[^/]+", regex_pattern)
                regex = re.compile(r"^" + regex_pattern + r"$")
                self.pattern_rules.append((regex, rule))

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
        path = request.url.path
        rule = self._find_matching_rule(path)

        if rule:
            allowed, stage = await self.limiter.hit(rule, request, path)
            if not allowed:
                delay = min((stage + 1) * 1.5, 6)
                await asyncio.sleep(delay)
                response = JSONResponse(
                    status_code=429,
                    content={"detail": "Too many requests"}
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

            if has_body:
                content_type = request.headers.get("content-type", "").lower()
                if (
                    "application/json" not in content_type
                    and "+json" not in content_type
                ):
                    response = JSONResponse(
                        {"detail": "Only application/json is allowed"},
                        status_code=415,
                    )
                    await response(scope, receive, send)
                    return

        await self.app(scope, receive, send)


class BodySizeLimiter:
    """
    Enforces a max size + read timeout on the *inbound request body only*.

    Important: `receive()` is reused by ASGI for more than just body chunks.
    Once the body has been fully read, downstream code (e.g. Starlette's
    StreamingResponse / EventSourceResponse for SSE, or the disconnect
    listener that wraps every response) keeps calling `receive()` to detect
    client disconnects. For an SSE endpoint that connection can legitimately
    sit open for minutes or hours. If we keep wrapping that call in our
    request-body timeout, we kill the stream a few seconds in for no reason.

    So: apply the timeout/size checks strictly while `body_done` is False.
    Once the body is fully consumed (or there was never a body — GET/SSE
    subscribe requests), pass `receive()` straight through untouched.

    We also track whether a response has already started, so that if the
    timeout/size exception fires *after* the downstream app already began
    sending a response (e.g. mid-SSE-stream), we don't attempt to originate
    a second response and blow up ASGI's response-start invariant.
    """

    def __init__(self, app: ASGIApp, max_size=20_000, timeout=5):
        self.app = app
        self.max_size = max_size
        self.timeout = timeout

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        total_size = 0
        body_done = False

        async def limited_receive():
            nonlocal total_size, body_done

            if body_done:
                # No longer reading the request body - this is disconnect
                # monitoring (e.g. SSE) or a repeat call after body end.
                # Let it block/behave normally, no timeout applied.
                return await receive()

            try:
                message = await asyncio.wait_for(receive(), timeout=self.timeout)
            except asyncio.TimeoutError:
                raise CustomTimeoutException()

            if message["type"] == "http.request":
                body = message.get("body", b"")
                total_size += len(body)
                if total_size > self.max_size:
                    body_done = True
                    raise CustomPayloadTooLargeException()
                if not message.get("more_body", False):
                    body_done = True
            elif message["type"] == "http.disconnect":
                body_done = True

            return message

        response_started = False

        async def tracking_send(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except CustomTimeoutException:
            if response_started:
                # Too late to send a fresh response (e.g. mid SSE-stream).
                # Let it propagate; Uvicorn logs it and drops the connection.
                raise
            response = JSONResponse({"detail": "Request timeout"}, status_code=408)
            await response(scope, receive, send)
        except CustomPayloadTooLargeException:
            if response_started:
                raise
            response = JSONResponse({"detail": "Request too large"}, status_code=413)
            await response(scope, receive, send)


def create_app() -> FastAPI:
    app = FastAPI(
        title="Null-Backend",
        docs_url="/docs",
        redoc_url="/redoc"
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Middleware execution order runs from bottom-to-top
    app.add_middleware(
        RateLimitMiddleware,
        limiter=Limiter(),
        rules_map=rules
    )
    app.add_middleware(EnforceJSONMiddleware)
    app.add_middleware(BodySizeLimiter, max_size=20_000, timeout=5)

    app.include_router(api_router)

    @app.on_event("startup")
    async def startup_event():
        await init_redis(settings.redis_url)
        app.state.redis = get_redis_client()
        logger.info("Startup: Redis initialized and stored on app.state.redis")
        # Federation: pull the directory once so routing works for the very
        # first message, then keep it warm on the daily loop.
        await start_directory_refresh_loop(app.state.redis)
        await start_socket_sweeper(app.state.redis)

    @app.on_event("shutdown")
    async def shutdown_event():
        await stop_all()
        await close_redis()
        logger.info("Shutdown: Redis connection closed")

    @app.get("/")
    async def root() -> dict:
        return {"message": "Null-Backend running", "status": "healthy"}

    return app


app = create_app()