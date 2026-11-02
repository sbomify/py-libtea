"""Server-side helpers for TEA API implementations.

Provides utilities for servers that import py-libtea models as response schemas.
"""

from collections.abc import Sequence
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel

from libtea.models import Collection, ComponentReleaseWithCollection

__all__ = ["tea_datetime_serializer", "to_wire"]


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


def to_wire(data: BaseModel | Sequence[BaseModel], *, legacy: bool = False) -> Any:
    """Serialize libtea models to the TEA wire format, ready for ``json.dumps``.

    ``model_dump()`` gives libtea's Python shape; this gives what a TEA server sends:

    - camelCase keys; fields that are ``None`` or were never set are left out, so neither ``null`` nor an
      empty default (such as ``"checksums": []`` on a server-hosted format) is sent;
    - timestamps as ``YYYY-MM-DDThh:mm:ssZ`` (see :func:`tea_datetime_serializer`), enums as plain strings;
    - a ``ComponentReleaseWithCollection`` flattened as TEA 1.0.0 defines it. With ``legacy=True``
      (TEA 0.4.0) it stays nested under ``release``, and every collection's ``createdDate`` is named
      ``date``, at any depth.

    Args:
        data: A model, or a list of models (for array responses such as ``/discovery``).
        legacy: Emit the TEA 0.4.0 shape instead of TEA 1.0.0.

    Returns:
        A dict, or a list of dicts for a list input.

    Raises:
        ValueError: If a model holds a naive datetime.
    """
    if not isinstance(data, BaseModel):
        return [to_wire(item, legacy=legacy) for item in data]
    wire = _plain(data.model_dump(by_alias=True, exclude_none=True, exclude_unset=True))
    if legacy:
        _legacy_collection_dates(data, wire)
    elif isinstance(data, ComponentReleaseWithCollection):
        wire = {**wire.pop("release"), **wire}
    return wire


def _legacy_collection_dates(model: BaseModel, wire: dict[str, Any]) -> None:
    """Rename each collection's ``createdDate`` to TEA 0.4.0's ``date``, walking the model alongside its dump."""
    if isinstance(model, Collection) and "createdDate" in wire:
        renamed = [("date" if key == "createdDate" else key, value) for key, value in wire.items()]
        wire.clear()
        wire.update(renamed)
    for name, field in type(model).model_fields.items():
        key = field.alias or name
        if key not in wire:
            continue
        value = getattr(model, name)
        if isinstance(value, BaseModel):
            _legacy_collection_dates(value, wire[key])
        elif isinstance(value, tuple):
            for item, item_wire in zip(value, wire[key]):
                if isinstance(item, BaseModel):
                    _legacy_collection_dates(item, item_wire)


def _plain(value: Any) -> Any:
    if isinstance(value, datetime):
        return tea_datetime_serializer(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value
