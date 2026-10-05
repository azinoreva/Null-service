from __future__ import annotations

import inspect
import logging
import re
import time
from contextvars import ContextVar
from functools import wraps
from typing import Any, Callable


logger = logging.getLogger("logger")
logger.setLevel(logging.INFO)
logger.propagate = False

if not logger.handlers:
	console_handler = logging.StreamHandler()
	console_format = logging.Formatter(
		"%(asctime)s - %(name)s - %(levelname)s - %(message)s"
	)
	console_handler.setFormatter(console_format)
	logger.addHandler(console_handler)


request_id_context: ContextVar[str] = ContextVar("request_id", default="-")

_SENSITIVE_KEY_PARTS = (
	"password", "token", "secret", "authorization", "cookie", "otp", "pin",
	"private", "credential", "encrypted_blob", "encrypted", "salt", "signature",
	"dh_enc", "public_key", "jwe", "passport",
)
_REDACTED = "<redacted>"
_MAX_LOG_STRING_LENGTH = 256


def _is_sensitive_key(key: object) -> bool:
	normalized = str(key).lower().replace("-", "_")
	return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def _redact_text(value: str) -> str:
	value = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer " + _REDACTED, value)
	value = re.sub(r"(?i)(password|token|secret|authorization|cookie|otp|pin)\s*[:=]\s*[^\s,;]+", r"\1=" + _REDACTED, value)
	value = re.sub(r"\beyJ[A-Za-z0-9_-]{20,}\b", _REDACTED, value)
	value = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "<redacted-email>", value)
	value = re.sub(r"(?<!\d)\+?\d[\d ()-]{8,}\d(?!\d)", "<redacted-phone>", value)
	if len(value) > _MAX_LOG_STRING_LENGTH:
		return value[:_MAX_LOG_STRING_LENGTH] + "..."
	return value


def redact(value: Any, *, key: object | None = None, depth: int = 0) -> Any:
	"""Return a bounded, JSON-like value safe for diagnostic logging."""
	if key is not None and _is_sensitive_key(key):
		return _REDACTED
	if depth > 4:
		return "<nested-value>"
	if value is None or isinstance(value, (bool, int, float)):
		return value
	if isinstance(value, str):
		return _redact_text(value)
	if isinstance(value, bytes):
		return f"<bytes:{len(value)}>"
	if isinstance(value, dict):
		return {str(k): redact(v, key=k, depth=depth + 1) for k, v in value.items()}
	if isinstance(value, (list, tuple, set)):
		items = list(value)
		result = [redact(item, depth=depth + 1) for item in items[:20]]
		if len(items) > 20:
			result.append("<items-truncated>")
		return result
	return _redact_text(repr(value))


def safe_exception(exc: BaseException) -> str:
	"""Keep exception diagnostics useful without exposing HTTP details or secrets."""
	status_code = getattr(exc, "status_code", None)
	if status_code is not None:
		return f"{type(exc).__name__}(status_code={status_code})"
	return f"{type(exc).__name__}: {_redact_text(str(exc))}"


def log_event(level: int, event: str, **fields: Any) -> None:
	safe_fields = {"request_id": request_id_context.get(), **fields}
	logger.log(level, "%s %s", event, redact(safe_fields))


def logged_endpoint(endpoint: Callable[..., Any], route_path: str) -> Callable[..., Any]:
	"""Log route lifecycle events without serializing endpoint arguments/results."""
	if getattr(endpoint, "_redacted_logged", False):
		return endpoint

	@wraps(endpoint)
	async def wrapped(*args: Any, **kwargs: Any) -> Any:
		started = time.perf_counter()
		log_event(logging.INFO, "route.start", route=route_path)
		try:
			result = endpoint(*args, **kwargs)
			if inspect.isawaitable(result):
				result = await result
			log_event(
				logging.INFO,
				"route.complete",
				route=route_path,
				duration_ms=round((time.perf_counter() - started) * 1000, 2),
			)
			return result
		except Exception as exc:
			log_event(
				logging.ERROR,
				"route.error",
				route=route_path,
				duration_ms=round((time.perf_counter() - started) * 1000, 2),
				error=safe_exception(exc),
			)
			raise

	wrapped._redacted_logged = True
	return wrapped


class LoggedAPIRouterMixin:
	def add_api_route(self, path: str, endpoint: Callable[..., Any], **kwargs: Any) -> None:
		super().add_api_route(path, logged_endpoint(endpoint, path), **kwargs)

