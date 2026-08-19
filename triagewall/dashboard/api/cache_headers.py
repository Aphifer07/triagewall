"""Cache-Control and ETag helpers for cheap API polling."""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, TypeVar

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ValidationError

logger = logging.getLogger(__name__)

ModelT = TypeVar("ModelT", bound=BaseModel)


def weak_etag_for_payload(payload: Any) -> str:
    """Build a weak ETag from a JSON-serializable payload."""
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return f'W/"{digest}"'


def _conditional_response(
    request: Request,
    body: Any,
    *,
    max_age: int,
    status_code: int,
    no_store: bool = False,
) -> Response:
    if no_store:
        # Per-event responses change the moment an operator saves feedback, so
        # they are never stored. No validator is emitted either: an ETag would
        # let a revalidating cache answer 304 and hand back the pre-feedback
        # body, which is exactly the staleness this avoids.
        return JSONResponse(
            body,
            status_code=status_code,
            headers={"Cache-Control": "private, no-store"},
        )
    etag = weak_etag_for_payload(body)
    if_none_match = request.headers.get("if-none-match")
    headers = {
        "Cache-Control": f"private, max-age={max_age}",
        "ETag": etag,
    }
    if if_none_match and etag in {
        part.strip() for part in if_none_match.split(",")
    }:
        return Response(status_code=304, headers=headers)
    return JSONResponse(body, status_code=status_code, headers=headers)


def cached_json_response(
    request: Request,
    payload: Any,
    *,
    max_age: int,
    status_code: int = 200,
) -> Response:
    """Return JSON with Cache-Control and honor If-None-Match.

    Prefer :func:`validated_json_response` for the versioned contract. This
    unvalidated form remains for the deprecated unversioned aliases, whose
    shapes are frozen and must not change before removal.
    """
    return _conditional_response(
        request,
        payload,
        max_age=max_age,
        status_code=status_code,
    )


def validated_json_response(
    request: Request,
    payload: Any,
    *,
    model: type[ModelT],
    max_age: int,
    status_code: int = 200,
    no_store: bool = False,
) -> Response:
    """Serve ``payload`` only after it satisfies its declared response model.

    Routes that return an explicit ``Response`` bypass FastAPI's own
    ``response_model`` serialization and validation, so the declared model
    documents a contract nothing enforces. This validates first, serializes the
    validated model with JSON-compatible output, and derives the ETag from that
    representation -- so the cache key and the bytes on the wire always agree,
    and an undocumented field or wrong type cannot reach a v1 client.

    Conditional (304) handling, cache headers and non-200 status codes are all
    preserved. Pass ``no_store`` for responses that a client must never reuse;
    validation still applies, but no validator is emitted.
    """
    try:
        validated = model.model_validate(payload)
    except ValidationError as exc:
        # Fail closed: never emit a response that violates the published
        # contract. The error count is safe to log; field values are not.
        logger.error(
            "API response failed %s validation with %d error(s)",
            model.__name__,
            exc.error_count(),
        )
        raise HTTPException(
            status_code=500,
            detail="response failed contract validation",
        ) from exc
    return _conditional_response(
        request,
        validated.model_dump(mode="json"),
        max_age=max_age,
        status_code=status_code,
        no_store=no_store,
    )
