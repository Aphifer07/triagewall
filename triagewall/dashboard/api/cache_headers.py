"""Cache-Control and ETag helpers for cheap API polling."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse, Response


def weak_etag_for_payload(payload: Any) -> str:
    """Build a weak ETag from a JSON-serializable payload."""
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return f'W/"{digest}"'


def cached_json_response(
    request: Request,
    payload: Any,
    *,
    max_age: int,
    status_code: int = 200,
) -> Response:
    """Return JSON with Cache-Control and honor If-None-Match."""
    etag = weak_etag_for_payload(payload)
    if_none_match = request.headers.get("if-none-match")
    headers = {
        "Cache-Control": f"private, max-age={max_age}",
        "ETag": etag,
    }
    if if_none_match and etag in {
        part.strip() for part in if_none_match.split(",")
    }:
        return Response(status_code=304, headers=headers)
    return JSONResponse(payload, status_code=status_code, headers=headers)
