"""Shared input-validation helpers used by TeaClient and (future) AsyncTeaClient.

These are pure functions with no HTTP dependency, making them safe to import
from any client implementation without pulling in the requests stack.
"""

import uuid as _uuid
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from libtea.exceptions import TeaValidationError

_M = TypeVar("_M", bound=BaseModel)


def _context(legacy: bool) -> dict[str, bool] | None:
    # No context means 1.0.0 rules; 0.4.0 compatibility shims key off ``tea_legacy``.
    return {"tea_legacy": True} if legacy else None


def _validate(model_cls: type[_M], data: Any, *, legacy: bool = False) -> _M:
    """Validate a JSON-decoded value against a Pydantic model.

    Wraps :meth:`pydantic.BaseModel.model_validate`, converting any
    :class:`~pydantic.ValidationError` into :class:`TeaValidationError`
    so callers only need to catch the ``TeaError`` hierarchy. With
    ``legacy=True`` the model is validated in the 0.4.0 compatibility context.
    """
    try:
        return model_cls.model_validate(data, context=_context(legacy))
    except ValidationError as exc:
        raise TeaValidationError(f"Invalid {model_cls.__name__} response: {exc}") from exc


def _validate_list(model_cls: type[_M], data: Any, *, legacy: bool = False) -> list[_M]:
    """Validate a JSON array where each element conforms to a Pydantic model.

    Raises :class:`TeaValidationError` if ``data`` is not a list or any
    element fails validation.
    """
    if not isinstance(data, list):
        raise TeaValidationError(f"Expected list for {model_cls.__name__}, got {type(data).__name__}")
    context = _context(legacy)
    try:
        return [model_cls.model_validate(item, context=context) for item in data]
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


_MAX_PAGE_SIZE = 10000  # TEA 0.4.0
_MAX_PAGE_SIZE_V1 = 100  # TEA 1.0.0 ``pageSize`` maximum


def _validate_page_size(page_size: int, max_size: int = _MAX_PAGE_SIZE) -> None:
    """Validate that page_size is within acceptable bounds."""
    if page_size < 1 or page_size > max_size:
        raise TeaValidationError(f"page_size must be between 1 and {max_size}, got {page_size}")


def _validate_collection_version(version: int) -> None:
    """Validate that a collection version number is >= 1 per spec."""
    if version < 1:
        raise TeaValidationError(f"Collection version must be >= 1, got {version}")


def _validate_artifact_version(version: int) -> None:
    """Validate that an artifact version number is >= 1 per spec."""
    if version < 1:
        raise TeaValidationError(f"Artifact version must be >= 1, got {version}")
