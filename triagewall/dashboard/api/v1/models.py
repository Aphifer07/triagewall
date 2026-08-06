"""Pydantic models for the Triagewall API v1 contract."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class StatsModel(BaseModel):
    """Rolling 24h counters plus lifetime total."""

    model_config = ConfigDict(extra="forbid")

    total: int
    real: int
    real_: int = Field(
        description="Deprecated alias for real; removed after 2026-12-31."
    )
    fp: int
    unc: int
    reviewed: int
    agreed: int
    disagreed: int
    prefilter_count: int
    llm_count: int
    today_total: int
    today_prefilter: int
    today_llm: int


class StatsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generated_at: str
    mode: Literal["local", "demo"]
    stats: StatsModel


class AgentContext(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: Any = None
    name: Any = None


class SensorContext(BaseModel):
    model_config = ConfigDict(extra="allow")

    source: str | None = None
    instance: str | None = None
    event_id: str | None = None
    agent: AgentContext | None = None


class AssetContext(BaseModel):
    model_config = ConfigDict(extra="allow")

    source: dict[str, Any] | None = None
    destination: dict[str, Any] | None = None


class VerdictRow(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: int
    timestamp: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    proto: str | None = None
    signature_id: int | None = None
    signature: str | None = None
    category: str | None = None
    severity: int | None = None
    verdict: str | None = None
    confidence: float | None = None
    reasoning: str | None = None
    model_used: str | None = None
    processed_at: str | None = None
    human_verdict: str | None = None
    human_notes: str | None = None
    agreed: int | None = None
    reviewed_at: str | None = None
    asset_context: AssetContext | None = None
    sensor_context: SensorContext | None = None
    raw_alert: str | None = None


class VerdictsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generated_at: str
    mode: Literal["local", "demo"]
    verdicts: list[VerdictRow]
    next_cursor: str | None = None


class TimelineBucket(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: str
    total_alerts: int
    prefiltered_count: int
    prefilter_percentage: float
    real_count: int


class TimelineResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generated_at: str
    hours: int
    interval: Literal["1h"]
    buckets: list[TimelineBucket]


class SpcAnomaly(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detected_at: str | None = None
    feature: str | None = None
    ip: str | None = None
    signature_id: int | None = None
    z: float | None = None
    note: str | None = None


class SpcAnomaliesResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generated_at: str
    available: bool
    anomalies: list[SpcAnomaly]
    count_24h: int | None = None


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["ok", "stale"]
    last_alert_age_seconds: int
    generated_at: str


class FeedbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    human_verdict: Literal["real", "false_positive", "uncertain"]
    notes: str = ""


class FeedbackResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool
    agreed: bool


class LegacyHealthResponse(BaseModel):
    """Deprecated /api/health shape including storage metrics."""

    model_config = ConfigDict(extra="allow")

    status: Literal["ok", "stale"]
    last_alert_age_seconds: int
    generated_at: str | None = None
    storage: dict[str, Any] | None = None


class LegacyVerdictsResponse(BaseModel):
    """Deprecated combined /api/verdicts shape."""

    model_config = ConfigDict(extra="forbid")

    mode: Literal["local", "demo"]
    stats: StatsModel
    verdicts: list[VerdictRow]
