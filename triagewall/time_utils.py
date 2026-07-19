"""Canonical UTC timestamp parsing and formatting."""

from datetime import datetime, timezone


UTC = timezone.utc


def parse_utc_timestamp(value: str | datetime) -> datetime:
    """Parse an ISO-8601 value and return an aware UTC datetime."""
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
    else:
        raise ValueError("timestamp must be a non-empty ISO-8601 value")

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def format_utc_timestamp(value: str | datetime) -> str:
    """Return the project's fixed-width, browser-safe UTC representation."""
    return (
        parse_utc_timestamp(value)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def utc_now() -> datetime:
    return datetime.now(UTC)


def utc_now_iso() -> str:
    return format_utc_timestamp(utc_now())


def utc_hour_timestamp(value: str | datetime) -> str:
    hour = parse_utc_timestamp(value).replace(
        minute=0,
        second=0,
        microsecond=0,
    )
    return format_utc_timestamp(hour)
