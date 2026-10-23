from unittest.mock import patch

import pytest
import responses
from responses import matchers

from libtea._validation import _validate, _validate_list
from libtea.client import TeaClient
from libtea.exceptions import TeaChecksumError, TeaRequestError, TeaServerError, TeaValidationError
from libtea.models import Checksum
from tests.spec_data import (
    ARTIFACT,
    COMPONENT,
    COMPONENT_RELEASE,
    LEGACY_BASE_URL,
    MD5_HEX,
    PRODUCT,
    PRODUCT_RELEASE,
    V1_ARTIFACT,
    V1_BASE_URL,
    V1_COLLECTION,
    V1_PRODUCT_RELEASE,
    V1_RELEASE,
    product,
)


class TestSpecVersion:
    def test_inferred_from_base_url(self):
        c = TeaClient(LEGACY_BASE_URL)
        assert (c.spec_version, c.is_legacy) == ("0.4.0", True)

    def test_build_metadata_kept(self):
        assert TeaClient("https://api.example.com/v1.0.0+build.5").spec_version == "1.0.0+build.5"

    def test_defaults_to_1_0_0_without_semver_suffix(self):
        c = TeaClient("https://api.example.com/tea/v1")
        assert (c.spec_version, c.is_legacy) == ("1.0.0", False)

    def test_explicit_overrides_url(self):
        assert TeaClient(V1_BASE_URL, spec_version="0.4.0").is_legacy is True

    @pytest.mark.parametrize("v", ["2.0.0", "not-semver"])
    def test_rejects_unsupported(self, v):
        with pytest.raises(ValueError, match="Unsupported TEA spec version"):
            TeaClient("https://api.example.com", spec_version=v)


CASES = [("legacy", LEGACY_BASE_URL, True), ("v1", V1_BASE_URL, False)]


class TestLegacyFlagReachesValidation:
    @responses.activate
    @pytest.mark.parametrize("fixture, base_url, expected", CASES)
    def test_validate(self, request, fixture, base_url, expected):
        client = request.getfixturevalue(fixture)
        responses.get(f"{base_url}/product/{PRODUCT}", json=product(PRODUCT, "Widget"))
        with patch("libtea.client._validate", wraps=_validate) as spy:
            client.get_product(PRODUCT)
        assert spy.call_args.kwargs == {"legacy": expected}

    @responses.activate
    @pytest.mark.parametrize("fixture, base_url, expected", CASES)
    def test_validate_list(self, request, fixture, base_url, expected):
        client = request.getfixturevalue(fixture)
        responses.get(
            f"{base_url}/discovery",
            json=[
                {
                    "productReleaseUuid": PRODUCT_RELEASE,
                    "servers": [{"rootUrl": "https://api.example.com", "versions": ["1.0.0"]}],
                }
            ],
        )
        with patch("libtea.client._validate_list", wraps=_validate_list) as spy:
            client.discover("urn:tei:purl:example.com:pkg:pypi/lib@1.0")
        assert spy.call_args.kwargs == {"legacy": expected}


@responses.activate
def test_discover_passes_tei_verbatim(v1):
    tei = "tei://Example.com/uuid/x"
    responses.get(
        f"{V1_BASE_URL}/discovery",
        match=[matchers.query_param_matcher({"tei": tei})],
        json=[
            {
                "productReleaseUuid": PRODUCT_RELEASE,
                "servers": [{"rootUrl": "https://api.example.com", "versions": ["1.0.0"]}],
            }
        ],
    )
    assert v1.discover(tei)[0].product_release_uuid == PRODUCT_RELEASE


@responses.activate
def test_discover_by_purl(v1):
    purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.24.3"
    responses.get(
        f"{V1_BASE_URL}/discovery",
        match=[matchers.query_param_matcher({"purl": purl})],
        json=[
            {
                "productReleaseUuid": PRODUCT_RELEASE,
                "servers": [{"rootUrl": "https://api.example.com", "versions": ["1.0.0"]}],
            }
        ],
    )
    assert v1.discover(purl=purl)[0].product_release_uuid == PRODUCT_RELEASE


@responses.activate
@pytest.mark.parametrize("kwargs", [{}, {"tei": "tei://example.com/uuid/x", "purl": "pkg:x/y"}])
def test_discover_needs_exactly_one(v1, kwargs):
    with pytest.raises(TeaValidationError, match="exactly one"):
        v1.discover(**kwargs)
    assert len(responses.calls) == 0


@responses.activate
def test_purl_rejected_on_legacy(legacy):
    with pytest.raises(TeaValidationError, match="TEA 1.x"):
        legacy.discover(purl="pkg:x/y")
    assert len(responses.calls) == 0


@responses.activate
def test_discover_empty_array_rejected_on_v1(v1):
    responses.get(f"{V1_BASE_URL}/discovery", json=[])
    with pytest.raises(TeaValidationError, match="non-empty"):
        v1.discover("tei://example.com/uuid/x")


@responses.activate
def test_v1_client_rejects_incomplete_collection():
    responses.get(
        f"{V1_BASE_URL}/componentRelease/{COMPONENT_RELEASE}/collection/latest",
        json={"uuid": COMPONENT_RELEASE, "version": 1},
    )
    with pytest.raises(TeaValidationError, match="TEA 1.0.0"):
        TeaClient(V1_BASE_URL).get_component_release_collection_latest(COMPONENT_RELEASE)


@responses.activate
def test_v1_artifact_with_md5_rejected():
    art = {
        **V1_ARTIFACT,
        "formats": [{**V1_ARTIFACT["formats"][0], "checksums": [{"algType": "MD5", "algValue": MD5_HEX}]}],
    }
    responses.get(f"{V1_BASE_URL}/artifact/{ARTIFACT}/latest", json=art)
    with pytest.raises(TeaValidationError, match="MD5"):
        TeaClient(V1_BASE_URL).get_artifact(ARTIFACT)


# --- Token pagination ---


@responses.activate
def test_first_page_omits_token(v1):
    responses.get(
        f"{V1_BASE_URL}/products",
        match=[matchers.query_param_matcher({"pageSize": "100"})],
        json={"hasNext": False, "results": []},
    )
    assert v1.list_products().has_next is False
    assert len(responses.calls) == 1


@responses.activate
def test_page_token_sent(v1):
    responses.get(
        f"{V1_BASE_URL}/products",
        match=[matchers.query_param_matcher({"pageSize": "100", "pageToken": "tok-1"})],
        json={"hasNext": False, "results": []},
    )
    v1.list_products(page_token="tok-1")
    assert len(responses.calls) == 1


def test_page_size_capped_at_100_on_v1(v1):
    with pytest.raises(TeaValidationError, match="between 1 and 100"):
        v1.list_products(page_size=101)


@responses.activate
def test_iter_follows_tokens(v1):
    responses.get(
        f"{V1_BASE_URL}/productReleases",
        match=[matchers.query_param_matcher({"idType": "PURL", "idValue": "pkg:x", "pageSize": "100"})],
        json={"hasNext": True, "nextPageToken": "t2", "results": [V1_PRODUCT_RELEASE]},
    )
    responses.get(
        f"{V1_BASE_URL}/productReleases",
        match=[
            matchers.query_param_matcher({"idType": "PURL", "idValue": "pkg:x", "pageSize": "100", "pageToken": "t2"})
        ],
        json={"hasNext": False, "results": [V1_PRODUCT_RELEASE]},
    )
    assert len(list(v1.iter_product_releases("PURL", "pkg:x"))) == 2


@responses.activate
def test_iter_raises_on_repeated_token(v1):  # Review Focus 1
    responses.get(
        f"{V1_BASE_URL}/products",
        json={"hasNext": True, "nextPageToken": "same", "results": [product(PRODUCT, "P")]},
    )
    with pytest.raises(TeaServerError, match="repeated"):
        list(v1.iter_products("PURL", "pkg:x"))


@responses.activate
def test_iter_raises_on_token_cycle(v1):
    url = f"{V1_BASE_URL}/products"
    for sent, nxt in [(None, "A"), ("A", "B"), ("B", "A")]:
        query = {"idType": "PURL", "idValue": "pkg:x", "pageSize": "100", **({"pageToken": sent} if sent else {})}
        responses.get(
            url,
            match=[matchers.query_param_matcher(query)],
            json={"hasNext": True, "nextPageToken": nxt, "results": [product(PRODUCT, "P")]},
        )
    with pytest.raises(TeaServerError, match="repeated"):
        list(v1.iter_products("PURL", "pkg:x"))
    assert len(responses.calls) == 3


@responses.activate
def test_iter_stops_at_page_cap(v1, monkeypatch):
    monkeypatch.setattr("libtea.client._MAX_PAGES", 2)
    url = f"{V1_BASE_URL}/products"
    for sent, nxt in [(None, "t1"), ("t1", "t2")]:
        query = {"idType": "PURL", "idValue": "pkg:x", "pageSize": "100", **({"pageToken": sent} if sent else {})}
        responses.get(
            url,
            match=[matchers.query_param_matcher(query)],
            json={"hasNext": True, "nextPageToken": nxt, "results": [product(PRODUCT, "P")]},
        )
    with pytest.raises(TeaServerError, match="Pagination exceeded 2 pages"):
        list(v1.iter_products("PURL", "pkg:x"))
    assert len(responses.calls) == 2


@responses.activate
def test_iter_follows_token_past_empty_page(v1):
    """An empty page with ``hasNext`` and a fresh token is not the end of the results."""
    url = f"{V1_BASE_URL}/products"
    pages = [
        (None, {"hasNext": True, "nextPageToken": "t1", "results": [product(PRODUCT, "P1")]}),
        ("t1", {"hasNext": True, "nextPageToken": "t2", "results": []}),
        ("t2", {"hasNext": False, "results": [product(PRODUCT, "P2"), product(PRODUCT, "P3")]}),
    ]
    for sent, page in pages:
        query = {"idType": "PURL", "idValue": "pkg:x", "pageSize": "100", **({"pageToken": sent} if sent else {})}
        responses.get(url, match=[matchers.query_param_matcher(query)], json=page)
    assert [p.name for p in v1.iter_products("PURL", "pkg:x")] == ["P1", "P2", "P3"]
    assert len(responses.calls) == 3


@responses.activate
def test_iter_raises_on_repeated_token_with_empty_pages(v1):
    responses.get(f"{V1_BASE_URL}/products", json={"hasNext": True, "nextPageToken": "t", "results": []})
    with pytest.raises(TeaServerError, match="repeated"):
        list(v1.iter_products("PURL", "pkg:x"))
    assert len(responses.calls) == 2


@responses.activate
def test_component_releases_collects_pages_on_v1(v1):
    url = f"{V1_BASE_URL}/component/{COMPONENT}/releases"
    responses.get(
        url,
        match=[matchers.query_param_matcher({"pageSize": "100"})],
        json={"hasNext": True, "nextPageToken": "n", "results": [V1_RELEASE]},
    )
    responses.get(
        url,
        match=[matchers.query_param_matcher({"pageSize": "100", "pageToken": "n"})],
        json={"hasNext": False, "results": [V1_RELEASE]},
    )
    assert len(v1.get_component_releases(COMPONENT)) == 2


@responses.activate
@pytest.mark.parametrize(
    ("method", "path", "uuid"),
    [
        ("get_product_release_collections", "productRelease", PRODUCT_RELEASE),
        ("get_component_release_collections", "componentRelease", COMPONENT_RELEASE),
    ],
)
def test_collections_collects_pages_on_v1(v1, method, path, uuid):
    url = f"{V1_BASE_URL}/{path}/{uuid}/collections"
    responses.get(
        url,
        match=[matchers.query_param_matcher({"pageSize": "100"})],
        json={"hasNext": True, "nextPageToken": "n", "results": [V1_COLLECTION]},
    )
    responses.get(
        url,
        match=[matchers.query_param_matcher({"pageSize": "100", "pageToken": "n"})],
        json={"hasNext": False, "results": [V1_COLLECTION]},
    )
    assert len(getattr(v1, method)(uuid)) == 2


@responses.activate
def test_legacy_token_maps_to_offset(legacy):
    responses.get(
        f"{LEGACY_BASE_URL}/products",
        match=[matchers.query_param_matcher({"pageOffset": "200", "pageSize": "100"})],
        json={
            "timestamp": "2024-03-20T15:30:00Z",
            "pageStartIndex": 200,
            "pageSize": 100,
            "totalResults": 200,
            "results": [],
        },
    )
    legacy.list_products(page_token="200")
    assert len(responses.calls) == 1


@responses.activate
@pytest.mark.parametrize("token", ["abc", "-1", "²", ""])
def test_legacy_non_numeric_token_rejected(legacy, token):  # Review Focus 2
    with pytest.raises(TeaValidationError, match="integer offset"):
        legacy.list_products(page_token=token)
    assert len(responses.calls) == 0


@responses.activate
@pytest.mark.parametrize("fixture", ["v1", "legacy"])
def test_non_string_page_token_rejected(request, fixture):
    """An int carried over from the old ``page_offset`` argument fails cleanly before any request."""
    client = request.getfixturevalue(fixture)
    with pytest.raises(TeaValidationError, match="page_token must be a string"):
        client.list_products(page_token=200)
    assert len(responses.calls) == 0


def test_legacy_page_size_allows_10000(legacy):
    with pytest.raises(TeaValidationError, match="between 1 and 10000"):
        legacy.list_products(page_size=10001)


@responses.activate
def test_legacy_page_size_10000_accepted(legacy):
    responses.get(
        f"{LEGACY_BASE_URL}/products",
        match=[matchers.query_param_matcher({"pageOffset": "0", "pageSize": "10000"})],
        json={"timestamp": "2024-03-20T15:30:00Z", "pageStartIndex": 0, "pageSize": 10000, "totalResults": 0},
    )
    legacy.list_products(page_size=10000)
    assert len(responses.calls) == 1


@responses.activate
def test_get_product_release_v1(v1):
    responses.get(
        f"{V1_BASE_URL}/productRelease/{PRODUCT_RELEASE}",
        json={**V1_PRODUCT_RELEASE, "latestCollection": {**V1_COLLECTION, "belongsTo": "PRODUCT_RELEASE"}},
    )
    assert v1.get_product_release(PRODUCT_RELEASE).latest_collection.belongs_to == "PRODUCT_RELEASE"


@responses.activate
def test_get_product_release_v1_without_collection_rejected(v1):
    responses.get(f"{V1_BASE_URL}/productRelease/{PRODUCT_RELEASE}", json=V1_PRODUCT_RELEASE)
    with pytest.raises(TeaValidationError, match="latest_collection"):
        v1.get_product_release(PRODUCT_RELEASE)


@responses.activate
def test_get_component_release_v1_flattened(v1):
    responses.get(
        f"{V1_BASE_URL}/componentRelease/{COMPONENT_RELEASE}",
        json={**V1_RELEASE, "latestCollection": V1_COLLECTION},
    )
    result = v1.get_component_release(COMPONENT_RELEASE)
    assert (result.release.component, result.latest_collection.version) == (COMPONENT, 2)


@responses.activate
def test_get_component_release_legacy_nested(legacy):
    responses.get(
        f"{LEGACY_BASE_URL}/componentRelease/{COMPONENT_RELEASE}",
        json={"release": V1_RELEASE, "latestCollection": V1_COLLECTION},
    )
    assert legacy.get_component_release(COMPONENT_RELEASE).release.uuid == COMPONENT_RELEASE


# --- Server-hosted artifact download (TEA 1.0.0) ---

MEDIA = "application/vnd.cyclonedx+json"
EMPTY_JSON_SHA256 = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"  # sha256(b"{}")


@responses.activate
def test_token_not_forwarded_on_redirect(tmp_path):  # Review Focus 4
    c = TeaClient(V1_BASE_URL, token="secret")
    responses.get(
        f"{V1_BASE_URL}/artifact/{ARTIFACT}/2/download",
        match=[matchers.query_param_matcher({"mediaType": MEDIA})],
        status=302,
        headers={"Location": "https://cdn.example.com/blob/abc"},
    )
    responses.get("https://cdn.example.com/blob/abc", body=b"{}")
    c.download_artifact_content(
        ARTIFACT,
        tmp_path / "a.json",
        media_type=MEDIA,
        version=2,
        verify_checksums=[Checksum(algorithm_type="SHA-256", algorithm_value=EMPTY_JSON_SHA256)],
    )
    assert responses.calls[0].request.headers["Authorization"] == "Bearer secret"
    assert "Authorization" not in responses.calls[1].request.headers


@responses.activate
def test_token_not_forwarded_on_redirect_to_api_host(tmp_path):
    c = TeaClient(V1_BASE_URL, token="secret")
    responses.get(
        f"{V1_BASE_URL}/artifact/{ARTIFACT}/2/download",
        status=302,
        headers={"Location": "/blobs/abc"},
    )
    responses.get("https://api.example.com/blobs/abc", body=b"{}")
    c.download_artifact_content(ARTIFACT, tmp_path / "a.json", media_type=MEDIA, version=2)
    assert responses.calls[0].request.headers["Authorization"] == "Bearer secret"
    assert responses.calls[1].request.url == "https://api.example.com/blobs/abc"
    assert "Authorization" not in responses.calls[1].request.headers


@responses.activate
def test_basic_auth_not_forwarded_on_redirect(tmp_path):
    c = TeaClient(V1_BASE_URL, basic_auth=("u", "p"))
    responses.get(
        f"{V1_BASE_URL}/artifact/{ARTIFACT}/2/download",
        status=302,
        headers={"Location": "https://cdn.example.com/blob/abc"},
    )
    responses.get("https://cdn.example.com/blob/abc", body=b"{}")
    c.download_artifact_content(ARTIFACT, tmp_path / "a.json", media_type=MEDIA, version=2)
    assert responses.calls[0].request.headers["Authorization"] == "Basic dTpw"  # base64("u:p")
    assert "Authorization" not in responses.calls[1].request.headers


@responses.activate
def test_download_rejects_https_to_http_redirect(tmp_path):
    c = TeaClient(V1_BASE_URL, token="secret")
    responses.get(
        f"{V1_BASE_URL}/artifact/{ARTIFACT}/2/download",
        status=302,
        headers={"Location": "http://cdn.example.com/blob/abc"},
    )
    dest = tmp_path / "a.json"
    with pytest.raises(TeaValidationError, match="HTTPS to HTTP"):
        c.download_artifact_content(ARTIFACT, dest, media_type=MEDIA, version=2)
    assert len(responses.calls) == 1
    assert not dest.exists()


@responses.activate
def test_latest_when_version_omitted(v1, tmp_path):
    responses.get(f"{V1_BASE_URL}/artifact/{ARTIFACT}/latest/download", body=b"{}")
    assert v1.download_artifact_content(ARTIFACT, tmp_path / "a", media_type=MEDIA).read_bytes() == b"{}"


@responses.activate
def test_server_download_rejected_on_legacy(legacy, tmp_path):
    with pytest.raises(TeaValidationError, match="TEA 1.x"):
        legacy.download_artifact_content(ARTIFACT, tmp_path / "a", media_type=MEDIA)
    assert len(responses.calls) == 0


@responses.activate
def test_server_download_no_acceptable_format(v1, tmp_path):
    responses.get(
        f"{V1_BASE_URL}/artifact/{ARTIFACT}/latest/download", status=406, json={"error": "NO_ACCEPTABLE_FORMAT"}
    )
    dest = tmp_path / "a"
    with pytest.raises(TeaRequestError) as exc_info:
        v1.download_artifact_content(ARTIFACT, dest, media_type=MEDIA)
    assert exc_info.value.error_type == "NO_ACCEPTABLE_FORMAT"
    assert not dest.exists()


@responses.activate
def test_server_download_checksum_mismatch_deletes_file(v1, tmp_path):
    responses.get(f"{V1_BASE_URL}/artifact/{ARTIFACT}/latest/download", body=b"[]")
    dest = tmp_path / "a"
    with pytest.raises(TeaChecksumError):
        v1.download_artifact_content(
            ARTIFACT,
            dest,
            media_type=MEDIA,
            verify_checksums=[Checksum(algorithm_type="SHA-256", algorithm_value=EMPTY_JSON_SHA256)],
        )
    assert not dest.exists()


@responses.activate
def test_server_download_trusts_private_api_base(tmp_path):
    """The first hop is the configured API base, exempt from SSRF checks like every other API call."""
    c = TeaClient("https://10.0.0.5/tea/v1.0.0")
    responses.get(f"https://10.0.0.5/tea/v1.0.0/artifact/{ARTIFACT}/latest/download", body=b"{}")
    assert c.download_artifact_content(ARTIFACT, tmp_path / "a", media_type=MEDIA).read_bytes() == b"{}"
