"""Stable authenticated API v1 routes."""

from __future__ import annotations

from typing import Callable

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse

from triagewall.dashboard.api.auth import AuthContext, AuthState
from triagewall.dashboard.api.cache_headers import validated_json_response
from triagewall.dashboard.api import metrics as metrics_mod
from triagewall.dashboard.api import services
from triagewall.dashboard.api.v1.models import (
    FeedbackRequest,
    FeedbackResponse,
    HealthResponse,
    ModelFilter,
    ReviewFilter,
    SourceFilter,
    SpcAnomaliesResponse,
    StatsModel,
    StatsResponse,
    TimelineInterval,
    TimelineResponse,
    VerdictFilter,
    VerdictDetailResponse,
    VerdictsResponse,
)
from triagewall.time_utils import utc_now_iso


def create_v1_router(
    *,
    auth: AuthState,
    db_factory: Callable,
    get_mode: Callable[[], str],
    get_db_path: Callable,
    get_stale_threshold: Callable[[], int],
    row_to_dict: Callable,
    mask_ip_fn: Callable,
    redact_ips: Callable[[], bool],
    get_ip_secret: Callable[[], bytes | None] = lambda: None,
) -> APIRouter:
    """Build the v1 router with injected app dependencies."""
    router = APIRouter(prefix="/api/v1", tags=["v1"])
    require_read = auth.require_read
    require_write = auth.require_feedback_write

    @router.get(
        "/health",
        response_model=HealthResponse,
        responses={503: {"model": HealthResponse}},
    )
    def health(request: Request):
        payload, status_code = services.compute_health(
            db_factory,
            get_db_path(),
            stale_threshold_seconds=get_stale_threshold(),
            include_storage=False,
        )
        return validated_json_response(
            request,
            payload,
            model=HealthResponse,
            max_age=5,
            status_code=status_code,
        )

    @router.get("/stats", response_model=StatsResponse)
    def stats(
        request: Request,
        _auth: AuthContext = Depends(require_read),
    ):
        stats_dict, generated_at = services.get_cached_stats(db_factory)
        payload = {
            "generated_at": generated_at,
            "mode": get_mode(),
            "stats": StatsModel.model_validate(stats_dict).model_dump(),
        }
        return validated_json_response(
            request,
            payload,
            model=StatsResponse,
            max_age=int(services.STATS_TTL),
        )

    @router.get("/verdicts", response_model=VerdictsResponse)
    def list_verdicts(
        request: Request,
        verdict: VerdictFilter | None = None,
        signature: str | None = Query(
            default=None,
            max_length=services.MAX_SIGNATURE_SEARCH_LENGTH,
        ),
        model: ModelFilter | None = None,
        source: SourceFilter | None = None,
        review: ReviewFilter | None = None,
        limit: int = Query(
            default=services.DEFAULT_VERDICT_LIMIT,
            ge=1,
            le=services.MAX_VERDICT_LIMIT,
        ),
        cursor: str | None = Query(
            default=None,
            max_length=services.MAX_CURSOR_LENGTH,
        ),
        _auth: AuthContext = Depends(require_read),
    ):
        with db_factory(readonly=True) as conn:
            rows, next_cursor = services.fetch_verdicts(
                conn,
                verdict=verdict,
                signature=signature,
                model=model,
                source=source,
                review=review,
                limit=limit,
                cursor=cursor,
            )
        payload = {
            "generated_at": utc_now_iso(),
            "mode": get_mode(),
            "verdicts": [row_to_dict(r) for r in rows],
            "next_cursor": next_cursor,
        }
        return validated_json_response(
            request,
            payload,
            model=VerdictsResponse,
            max_age=5,
        )

    @router.get("/verdicts/{event_id}", response_model=VerdictDetailResponse)
    def get_verdict(
        request: Request,
        event_id: int,
        _auth: AuthContext = Depends(require_read),
    ):
        with db_factory(readonly=True) as conn:
            row = services.fetch_verdict(conn, event_id)
        if row is None:
            raise HTTPException(status_code=404, detail="event not found")
        payload = {
            "generated_at": utc_now_iso(),
            "mode": get_mode(),
            "verdict": row_to_dict(row),
        }
        return validated_json_response(
            request,
            payload,
            model=VerdictDetailResponse,
            max_age=5,
        )

    @router.post(
        "/feedback/{event_id}",
        response_model=FeedbackResponse,
    )
    def feedback(
        event_id: int,
        body: FeedbackRequest,
        _auth: AuthContext = Depends(require_write),
    ):
        return services.submit_feedback(
            db_factory,
            mode=get_mode(),
            event_id=event_id,
            human_verdict=body.human_verdict,
            notes=body.notes,
        )

    @router.get("/timeline", response_model=TimelineResponse)
    def timeline(
        request: Request,
        hours: int = Query(default=24, ge=1, le=services.MAX_TIMELINE_HOURS),
        interval: TimelineInterval = Query(default="1h"),
        _auth: AuthContext = Depends(require_read),
    ):
        buckets, generated_at = services.get_timeline(
            db_factory,
            hours=hours,
            interval=interval,
        )
        payload = {
            "generated_at": generated_at,
            "hours": hours,
            "interval": interval,
            "buckets": buckets,
        }
        return validated_json_response(
            request,
            payload,
            model=TimelineResponse,
            max_age=int(services.TIMELINE_TTL),
        )

    @router.get("/spc-anomalies", response_model=SpcAnomaliesResponse)
    def spc_anomalies(
        request: Request,
        _auth: AuthContext = Depends(require_read),
    ):
        payload, generated_at = services.get_spc_anomalies(
            db_factory,
            mode=get_mode(),
            mask_ip_fn=mask_ip_fn,
            redact_ips=redact_ips(),
            ip_secret=get_ip_secret(),
        )
        body = {"generated_at": generated_at, **payload}
        return validated_json_response(
            request,
            body,
            model=SpcAnomaliesResponse,
            max_age=int(services.SPC_TTL),
        )

    return router


def create_metrics_handler(
    *,
    auth: AuthState,
    db_factory: Callable,
    get_db_path: Callable,
    get_stale_threshold: Callable[[], int],
):
    """Return a /metrics endpoint handler."""

    def metrics(
        _auth: AuthContext = Depends(auth.require_read),
    ):
        stats_dict, _ = services.get_cached_stats(db_factory)
        health_payload, _ = services.compute_health(
            db_factory,
            get_db_path(),
            stale_threshold_seconds=get_stale_threshold(),
            include_storage=False,
        )
        body = metrics_mod.metrics_from_stats(
            stats_dict,
            last_alert_age_seconds=health_payload["last_alert_age_seconds"],
        )
        return PlainTextResponse(
            body,
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    return metrics
