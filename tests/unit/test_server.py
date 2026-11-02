import json
from datetime import datetime, timedelta, timezone

import pytest

from libtea.models import (
    Collection,
    ComponentReleaseWithCollection,
    DiscoveryInfo,
    ErrorResponse,
    ErrorType,
    PaginatedProductResponse,
    Product,
    ProductRelease,
    TeaServerInfo,
)
from libtea.server import tea_datetime_serializer, to_wire
from tests.spec_data import (
    COMPONENT_RELEASE,
    LEGACY,
    PRODUCT,
    PRODUCT_RELEASE,
    V1_COLLECTION,
    V1_PRODUCT_RELEASE,
    V1_RELEASE,
)


class TestToWire:
    def test_component_release_flattened_by_default(self):
        crwc = ComponentReleaseWithCollection.model_validate({**V1_RELEASE, "latestCollection": V1_COLLECTION})
        wire = to_wire(crwc)
        assert "release" not in wire
        assert wire["uuid"] == COMPONENT_RELEASE
        assert wire["latestCollection"]["version"] == 2
        assert ComponentReleaseWithCollection.model_validate(wire) == crwc

    def test_component_release_nested_for_legacy(self):
        crwc = ComponentReleaseWithCollection.model_validate(
            {"release": V1_RELEASE, "latestCollection": V1_COLLECTION}, context=LEGACY
        )
        wire = to_wire(crwc, legacy=True)
        assert set(wire) == {"release", "latestCollection"}
        assert ComponentReleaseWithCollection.model_validate(wire, context=LEGACY) == crwc

    def test_unset_optional_fields_left_out(self):
        wire = to_wire(ProductRelease.model_validate(V1_PRODUCT_RELEASE))
        assert None not in wire.values()
        assert "releaseDate" not in wire
        assert to_wire(ErrorResponse(error=ErrorType.OBJECT_UNKNOWN)) == {"error": "OBJECT_UNKNOWN"}

    def test_timestamps_in_tea_format(self):
        wire = to_wire(Collection.model_validate(V1_COLLECTION))
        assert wire["createdDate"] == "2025-05-12T18:08:00Z"
        assert wire["artifacts"][0]["createdDate"] == "2024-12-13T00:00:00Z"

    def test_output_is_plain_json(self):
        wire = to_wire(Collection.model_validate(V1_COLLECTION))
        assert type(wire["belongsTo"]) is str
        assert json.loads(json.dumps(wire)) == wire

    def test_v1_page_has_no_offset_fields(self):
        page = PaginatedProductResponse(
            has_next=True, next_page_token="t2", results=(Product(uuid=PRODUCT, name="P", identifiers=()),)
        )
        assert to_wire(page) == {
            "hasNext": True,
            "nextPageToken": "t2",
            "results": [{"uuid": PRODUCT, "name": "P", "identifiers": []}],
        }

    def test_list_of_models(self):
        info = DiscoveryInfo(
            product_release_uuid=PRODUCT_RELEASE,
            servers=(TeaServerInfo(root_url="https://api.example.com", versions=("1.0.0",)),),
        )
        assert to_wire([info]) == [
            {
                "productReleaseUuid": PRODUCT_RELEASE,
                "servers": [{"rootUrl": "https://api.example.com", "versions": ["1.0.0"]}],
            }
        ]


class TestTeaDatetimeSerializer:
    def test_utc_datetime(self):
        dt = datetime(2024, 3, 20, 15, 30, 0, tzinfo=timezone.utc)
        assert tea_datetime_serializer(dt) == "2024-03-20T15:30:00Z"

    def test_strips_milliseconds(self):
        dt = datetime(2024, 3, 20, 15, 30, 0, 123456, tzinfo=timezone.utc)
        assert tea_datetime_serializer(dt) == "2024-03-20T15:30:00Z"

    def test_converts_non_utc_to_utc(self):
        est = timezone(timedelta(hours=-5))
        dt = datetime(2024, 3, 20, 10, 30, 0, tzinfo=est)
        # 10:30 EST = 15:30 UTC
        assert tea_datetime_serializer(dt) == "2024-03-20T15:30:00Z"

    def test_naive_datetime_raises(self):
        dt = datetime(2024, 3, 20, 15, 30, 0)
        with pytest.raises(ValueError, match="timezone-aware"):
            tea_datetime_serializer(dt)
