"""
SafeBaseModel: defense-in-depth against payload bloat that slips past
byte-size middleware.
 
Why this is needed even with a body-size limiter middleware:
 
1. `str_max_length` in Pydantic's model_config ONLY constrains fields
   typed as `str`. Fields typed as `dict`, `list`, `Any`, or nested
   models with those types are completely unconstrained -- a `dict`
   field can hold a million tiny keys and Pydantic won't blink.
 
2. Byte-size middleware measures raw bytes on the wire. It says
   nothing about:
     - nesting depth (a few KB of "[[[[[...]]]]]" can blow the
       recursion limit during JSON parsing / model validation)
     - item count in wide collections (many short keys/values can
       fit under a byte cap while still causing O(n) or worse
       downstream cost -- hashing, DB writes, logging, etc.)
     - post-decompression size, if gzip/deflate is enabled anywhere
       upstream of your middleware (a small compressed body can
       decompress into something far larger than the cap you set)
 
This module doesn't replace the middleware -- it complements it by
validating the *shape* of the parsed data, not just its wire size.
"""
 
from __future__ import annotations
 
from typing import Any
 
from pydantic import BaseModel, ConfigDict, model_validator
 
# Tune these to your actual data shapes. Keep them well below what your
# middleware allows in bytes, since a 200KB budget can still encode a
# surprising number of nodes if values are short.
MAX_STRING_LENGTH = 10_000
MAX_COLLECTION_ITEMS = 1_000
MAX_DEPTH = 10
MAX_TOTAL_NODES = 10_000  # guards against wide+deep combinations
 
 
class PayloadTooComplex(ValueError):
    """Raised when parsed request data exceeds structural size limits."""
 
 
def _check_size(value: Any, depth: int, node_counter: list[int]) -> None:
    node_counter[0] += 1
    if node_counter[0] > MAX_TOTAL_NODES:
        raise PayloadTooComplex(
            f"payload exceeds max node count ({MAX_TOTAL_NODES})"
        )
    if depth > MAX_DEPTH:
        raise PayloadTooComplex(
            f"payload exceeds max nesting depth ({MAX_DEPTH})"
        )
 
    if isinstance(value, str):
        if len(value) > MAX_STRING_LENGTH:
            raise PayloadTooComplex(
                f"string exceeds max length ({MAX_STRING_LENGTH})"
            )
 
    elif isinstance(value, dict):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise PayloadTooComplex(
                f"dict exceeds max items ({MAX_COLLECTION_ITEMS})"
            )
        for key, item in value.items():
            if isinstance(key, str) and len(key) > MAX_STRING_LENGTH:
                raise PayloadTooComplex("dict key exceeds max length")
            _check_size(item, depth + 1, node_counter)
 
    elif isinstance(value, (list, tuple, set)):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise PayloadTooComplex(
                f"collection exceeds max items ({MAX_COLLECTION_ITEMS})"
            )
        for item in value:
            _check_size(item, depth + 1, node_counter)
 
    # numbers, bools, None: no size concept worth enforcing here.
    # Extend if you need to bound huge ints (e.g. len(str(value))).
 
 
class SafeBaseModel(BaseModel):
    """
    Base class for request models. Enforces:
      - max string length (also set via model_config for direct str fields)
      - max items per dict/list/set
      - max nesting depth
      - max total node count (catches wide-and-deep combinations that
        individually look fine)
 
    Runs as a `mode="before"` validator, so it inspects the raw parsed
    JSON (dict/list/str/etc.) before Pydantic coerces it into typed
    fields -- this is what lets it catch bloat inside `dict`, `list`,
    and `Any` typed fields that Pydantic's own constraints ignore.
 
    Usage:
        class SignInRequest(SafeBaseModel):
            password: str
            metadata: dict[str, Any] = {}
 
    Override limits per-model by subclassing and setting class
    attributes before calling super():
 
        class BulkImportRequest(SafeBaseModel):
            _max_collection_items = 5_000
            items: list[dict[str, Any]]
    """
 
    model_config = ConfigDict(str_max_length=MAX_STRING_LENGTH, extra="forbid")
 
    # Per-model overrides -- subclasses can tighten or loosen these.
    _max_string_length: int = MAX_STRING_LENGTH
    _max_collection_items: int = MAX_COLLECTION_ITEMS
    _max_depth: int = MAX_DEPTH
    _max_total_nodes: int = MAX_TOTAL_NODES
 
    @model_validator(mode="before")
    @classmethod
    def _enforce_size_limits(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
 
        node_counter = [0]
        for _, value in data.items():
            _check_size(value, depth=0, node_counter=node_counter)
 
        return data
 