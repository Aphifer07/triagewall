"""Shared environment-value parsing for Triagewall services."""


TRUE_VALUES = frozenset({"true", "1", "yes", "on"})
FALSE_VALUES = frozenset({"false", "0", "no", "off", ""})


def parse_boolean(value: str, name: str) -> bool:
    """Parse one strict boolean setting consistently across processes."""
    normalized = value.strip().lower()
    if normalized in TRUE_VALUES:
        return True
    if normalized in FALSE_VALUES:
        return False
    raise RuntimeError(f"{name} must be a boolean value")
