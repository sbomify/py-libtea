from typing import Any

import pytest
from pydantic import BaseModel, ValidationInfo, field_validator

from libtea._validation import (
    _MAX_PAGE_SIZE,
    _validate,
    _validate_artifact_version,
    _validate_collection_version,
    _validate_list,
    _validate_page_size,
    _validate_path_segment,
)
from libtea.exceptions import TeaValidationError


class _EchoContext(BaseModel):
    """Stores the validation context it was validated with in ``n``."""

    n: Any = None

    @field_validator("n", mode="before")
    @classmethod
    def _echo(cls, _value: Any, info: ValidationInfo) -> Any:
        return info.context


class TestValidationContext:
    def test_validate_passes_no_context_by_default(self):
        assert _validate(_EchoContext, {"n": 1}).n is None

    def test_validate_passes_legacy_context(self):
        assert _validate(_EchoContext, {"n": 1}, legacy=True).n == {"tea_legacy": True}

    def test_validate_list_passes_no_context_by_default(self):
        assert [m.n for m in _validate_list(_EchoContext, [{"n": 1}, {"n": 2}])] == [None, None]

    def test_validate_list_passes_legacy_context(self):
        assert [m.n for m in _validate_list(_EchoContext, [{"n": 1}, {"n": 2}], legacy=True)] == [
            {"tea_legacy": True}
        ] * 2


class TestValidatePathSegment:
    def test_accepts_uuid(self):
        assert _validate_path_segment("d4d9f54a-abcf-11ee-ac79-1a52914d44b1") == "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"

    def test_normalizes_uppercase_uuid(self):
        assert _validate_path_segment("D4D9F54A-ABCF-11EE-AC79-1A52914D44B1") == "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"

    def test_normalizes_uuid_without_hyphens(self):
        assert _validate_path_segment("d4d9f54aabcf11eeac791a52914d44b1") == "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"

    @pytest.mark.parametrize(
        "value",
        [
            "../../etc/passwd",
            "abc-123",
            "not-a-uuid",
            "",
            "abc\x00def",
        ],
    )
    def test_rejects_unsafe_values(self, value):
        with pytest.raises(TeaValidationError, match="Invalid uuid"):
            _validate_path_segment(value)

    def test_error_message_includes_guidance(self):
        with pytest.raises(TeaValidationError, match="valid UUID"):
            _validate_path_segment("../traversal")


class TestPageSizeValidation:
    """page_size parameter is validated in search/paginated methods."""

    def test_validate_page_size_rejects_zero(self):
        with pytest.raises(TeaValidationError, match="page_size must be between 1"):
            _validate_page_size(0)

    def test_validate_page_size_rejects_negative(self):
        with pytest.raises(TeaValidationError, match="page_size must be between 1"):
            _validate_page_size(-1)

    def test_validate_page_size_rejects_too_large(self):
        with pytest.raises(TeaValidationError, match="page_size must be between 1"):
            _validate_page_size(_MAX_PAGE_SIZE + 1)

    def test_validate_page_size_accepts_one(self):
        _validate_page_size(1)  # should not raise

    def test_validate_page_size_accepts_max(self):
        _validate_page_size(_MAX_PAGE_SIZE)  # should not raise

    def test_search_products_rejects_bad_page_size(self, client):
        with pytest.raises(TeaValidationError, match="page_size"):
            client.search_products("PURL", "pkg:pypi/foo", page_size=0)

    def test_get_product_releases_rejects_bad_page_size(self, client):
        with pytest.raises(TeaValidationError, match="page_size"):
            client.get_product_releases("a1b2c3d4-e5f6-7890-abcd-ef1234567890", page_size=-1)

    def test_search_product_releases_rejects_bad_page_size(self, client):
        with pytest.raises(TeaValidationError, match="page_size"):
            client.search_product_releases("PURL", "pkg:pypi/foo", page_size=_MAX_PAGE_SIZE + 1)


class TestPageTokenValidation:
    """page_token must be an integer offset on TEA 0.x servers."""

    def test_search_products_rejects_negative_offset(self, client):
        with pytest.raises(TeaValidationError, match="integer offset"):
            client.search_products("PURL", "pkg:pypi/foo", page_token="-1")

    def test_get_product_releases_rejects_negative_offset(self, client):
        with pytest.raises(TeaValidationError, match="integer offset"):
            client.get_product_releases("a1b2c3d4-e5f6-7890-abcd-ef1234567890", page_token="-1")

    def test_search_product_releases_rejects_negative_offset(self, client):
        with pytest.raises(TeaValidationError, match="integer offset"):
            client.search_product_releases("PURL", "pkg:pypi/foo", page_token="-1")


class TestCollectionVersionValidation:
    """Collection version parameter is validated before making API calls."""

    def test_validate_collection_version_rejects_zero(self):
        with pytest.raises(TeaValidationError, match="Collection version must be >= 1"):
            _validate_collection_version(0)

    def test_validate_collection_version_rejects_negative(self):
        with pytest.raises(TeaValidationError, match="Collection version must be >= 1"):
            _validate_collection_version(-1)

    def test_validate_collection_version_accepts_one(self):
        _validate_collection_version(1)  # should not raise

    def test_get_product_release_collection_rejects_zero(self, client):
        with pytest.raises(TeaValidationError, match="Collection version"):
            client.get_product_release_collection("b2c3d4e5-f6a7-8901-bcde-f12345678901", 0)

    def test_get_component_release_collection_rejects_zero(self, client):
        with pytest.raises(TeaValidationError, match="Collection version"):
            client.get_component_release_collection("d4e5f6a7-b8c9-0123-defa-234567890123", 0)


class TestArtifactVersionValidation:
    """Artifact version parameter is validated before making API calls."""

    def test_validate_artifact_version_rejects_zero(self):
        with pytest.raises(TeaValidationError, match="Artifact version must be >= 1"):
            _validate_artifact_version(0)

    def test_validate_artifact_version_rejects_negative(self):
        with pytest.raises(TeaValidationError, match="Artifact version must be >= 1"):
            _validate_artifact_version(-1)

    def test_validate_artifact_version_accepts_one(self):
        _validate_artifact_version(1)  # should not raise

    def test_validate_artifact_version_accepts_large(self):
        _validate_artifact_version(999)  # should not raise
