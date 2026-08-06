"""Hand-rolled Prometheus text exposition (no prometheus_client dependency)."""

from __future__ import annotations

from typing import Any


def render_prometheus_metrics(
    *,
    up: int,
    last_alert_age_seconds: int,
    lifetime_total: int,
    window_total: int,
    window_real: int,
    window_fp: int,
    window_uncertain: int,
) -> str:
    """Render a small Prometheus text payload for scrape endpoints."""
    lines = [
        "# HELP triagewall_up 1 when the dashboard API process is serving.",
        "# TYPE triagewall_up gauge",
        f"triagewall_up {up}",
        "# HELP triagewall_last_alert_age_seconds Age of newest processed alert.",
        "# TYPE triagewall_last_alert_age_seconds gauge",
        f"triagewall_last_alert_age_seconds {last_alert_age_seconds}",
        "# HELP triagewall_events_lifetime_total Lifetime triage_events from sqlite_sequence.",
        "# TYPE triagewall_events_lifetime_total gauge",
        f"triagewall_events_lifetime_total {lifetime_total}",
        "# HELP triagewall_stats_window_total Events in the rolling 24h stats window.",
        "# TYPE triagewall_stats_window_total gauge",
        f"triagewall_stats_window_total {window_total}",
        "# HELP triagewall_stats_window_real Real verdicts in the rolling 24h window.",
        "# TYPE triagewall_stats_window_real gauge",
        f"triagewall_stats_window_real {window_real}",
        "# HELP triagewall_stats_window_false_positive FP verdicts in the rolling 24h window.",
        "# TYPE triagewall_stats_window_false_positive gauge",
        f"triagewall_stats_window_false_positive {window_fp}",
        "# HELP triagewall_stats_window_uncertain Uncertain verdicts in the rolling 24h window.",
        "# TYPE triagewall_stats_window_uncertain gauge",
        f"triagewall_stats_window_uncertain {window_uncertain}",
        "",
    ]
    return "\n".join(lines)


def metrics_from_stats(
    stats: dict[str, Any],
    *,
    last_alert_age_seconds: int,
) -> str:
    return render_prometheus_metrics(
        up=1,
        last_alert_age_seconds=max(0, int(last_alert_age_seconds)),
        lifetime_total=int(stats.get("total") or 0),
        window_total=int(stats.get("today_total") or 0),
        window_real=int(stats.get("real") or stats.get("real_") or 0),
        window_fp=int(stats.get("fp") or 0),
        window_uncertain=int(stats.get("unc") or 0),
    )
