"""Server-side helpers for TEA API implementations.

Provides utilities for servers that import py-libtea models as response schemas.
"""

from datetime import datetime, timezone

__all__ = ["tea_datetime_serializer"]


def tea_datetime_serializer(dt: datetime) -> str:
    """Serialize a datetime to TEA spec format: ``YYYY-MM-DDThh:mm:ssZ``.

    The TEA spec requires strictly UTC timestamps with no milliseconds
    and no timezone offsets other than ``Z``.

    Args:
        dt: A timezone-aware datetime to serialize.

    Returns:
        Formatted string in TEA datetime format.

    Raises:
        ValueError: If ``dt`` is naive (no timezone info).
    """
    if dt.tzinfo is None:
        raise ValueError("tea_datetime_serializer requires a timezone-aware datetime")
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
