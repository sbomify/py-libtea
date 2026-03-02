"""Shared input-validation helpers used by TeaClient and (future) AsyncTeaClient.

These are pure functions with no HTTP dependency, making them safe to import
from any client implementation without pulling in the requests stack.
"""

import uuid as _uuid
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from libtea.exceptions import TeaValidationError

_M = TypeVar("_M", bound=BaseModel)


def _validate(model_cls: type[_M], data: Any) -> _M:
    """Validate a JSON-decoded value against a Pydantic model.

    Wraps :meth:`pydantic.BaseModel.model_validate`, converting any
    :class:`~pydantic.ValidationError` into :class:`TeaValidationError`
    so callers only need to catch the ``TeaError`` hierarchy.
    """
    try:
        return model_cls.model_validate(data)
    except ValidationError as exc:
        raise TeaValidationError(f"Invalid {model_cls.__name__} response: {exc}") from exc


def _validate_list(model_cls: type[_M], data: Any) -> list[_M]:
    """Validate a JSON array where each element conforms to a Pydantic model.

    Raises :class:`TeaValidationError` if ``data`` is not a list or any
    element fails validation.
    """
    if not isinstance(data, list):
        raise TeaValidationError(f"Expected list for {model_cls.__name__}, got {type(data).__name__}")
    try:
        return [model_cls.model_validate(item) for item in data]
    except ValidationError as exc:
        raise TeaValidationError(f"Invalid {model_cls.__name__} response: {exc}") from exc


def _validate_path_segment(value: str, name: str = "uuid") -> str:
    """Validate that a value is a valid UUID per TEA spec (RFC 4122).

    The TEA OpenAPI spec defines all path ``{uuid}`` parameters as
    ``format: uuid`` with pattern ``^[0-9a-f]{8}-...-[0-9a-f]{12}$``.

    Raises:
        TeaValidationError: If the value is empty or not a valid UUID.
    """
    if not value:
        raise TeaValidationError(f"Invalid {name}: must not be empty.")
    try:
        parsed = _uuid.UUID(value)
    except ValueError as exc:
        raise TeaValidationError(
            f"Invalid {name}: {value!r}. Must be a valid UUID (e.g. 'd4d9f54a-abcf-11ee-ac79-1a52914d44b1')."
        ) from exc
    return str(parsed)


_MAX_PAGE_SIZE = 10000


def _validate_page_size(page_size: int) -> None:
    """Validate that page_size is within acceptable bounds."""
    if page_size < 1 or page_size > _MAX_PAGE_SIZE:
        raise TeaValidationError(f"page_size must be between 1 and {_MAX_PAGE_SIZE}, got {page_size}")


def _validate_page_offset(page_offset: int) -> None:
    """Validate that page_offset is non-negative."""
    if page_offset < 0:
        raise TeaValidationError(f"page_offset must be >= 0, got {page_offset}")


def _validate_collection_version(version: int) -> None:
    """Validate that a collection version number is >= 1 per spec."""
    if version < 1:
        raise TeaValidationError(f"Collection version must be >= 1, got {version}")
