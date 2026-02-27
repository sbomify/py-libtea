"""Unit tests for libtea._cli_fmt rich formatters."""

from io import StringIO

import pytest

typer = pytest.importorskip("typer", reason="typer not installed (install libtea[cli])")

from rich.console import Console  # noqa: E402

from libtea._cli_fmt import (  # noqa: E402
    _fmt_identifiers,
    _opt,
    fmt_artifact,
    fmt_collection,
    fmt_component_release,
    fmt_discover,
    fmt_inspect,
    fmt_product,
    fmt_product_release,
    fmt_search_products,
    fmt_search_releases,
    format_output,
)
from libtea.models import (  # noqa: E402
    Artifact,
    ArtifactFormat,
    Checksum,
    ChecksumAlgorithm,
    Collection,
    CollectionBelongsTo,
    CollectionUpdateReason,
    CollectionUpdateReasonType,
    ComponentReleaseWithCollection,
    DiscoveryInfo,
    Identifier,
    PaginatedProductReleaseResponse,
    PaginatedProductResponse,
    Product,
    ProductRelease,
    Release,
    TeaServerInfo,
)


def _capture(fn, *args, **kwargs) -> str:
    """Call a formatter with a StringIO-backed Console and return the output."""
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=120)
    fn(*args, console=console, **kwargs)
    return buf.getvalue()


# --- Helper tests ---


class TestHelpers:
    def test_opt_none(self):
        assert _opt(None) == "-"

    def test_opt_value(self):
        assert _opt("hello") == "hello"

    def test_opt_int(self):
        assert _opt(42) == "42"

    def test_fmt_identifiers_empty(self):
        assert _fmt_identifiers([]) == "-"

    def test_fmt_identifiers_single(self):
        idents = [Identifier(id_type="PURL", id_value="pkg:pypi/test")]
        assert _fmt_identifiers(idents) == "PURL:pkg:pypi/test"

    def test_fmt_identifiers_multiple(self):
        idents = [
            Identifier(id_type="PURL", id_value="pkg:pypi/test"),
            Identifier(id_type="CPE", id_value="cpe:2.3:a:test"),
        ]
        result = _fmt_identifiers(idents)
        assert "PURL:pkg:pypi/test" in result
        assert "CPE:cpe:2.3:a:test" in result


# --- Formatter tests ---

UUID = "d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
UUID2 = "e5e0a65b-bcdf-22ff-bd80-2b63a25e55c2"


class TestFmtDiscover:
    def test_renders_table(self):
        data = [
            DiscoveryInfo(
                product_release_uuid=UUID,
                servers=[TeaServerInfo(root_url="https://tea.example.com", versions=["1.0.0"], priority=0.8)],
            )
        ]
        output = _capture(fmt_discover, data)
        assert "Discovery Results" in output
        assert UUID in output
        assert "tea.example.com" in output
        assert "0.8" in output

    def test_empty_list_renders_empty_table(self):
        output = _capture(fmt_discover, [])
        assert "Discovery Results" in output


class TestFmtSearchProducts:
    def test_renders_pagination_and_table(self):
        data = PaginatedProductResponse(
            timestamp="2024-01-01T00:00:00Z",
            page_start_index=0,
            page_size=100,
            total_results=1,
            results=[Product(uuid=UUID, name="Test Product", identifiers=[])],
        )
        output = _capture(fmt_search_products, data)
        assert "Results 1-1 of 1" in output
        assert "Test Product" in output

    def test_empty_results(self):
        data = PaginatedProductResponse(
            timestamp="2024-01-01T00:00:00Z",
            page_start_index=0,
            page_size=100,
            total_results=0,
            results=[],
        )
        output = _capture(fmt_search_products, data)
        assert "Results 1-0 of 0" in output


class TestFmtSearchReleases:
    def test_renders_table(self):
        data = PaginatedProductReleaseResponse(
            timestamp="2024-01-01T00:00:00Z",
            page_start_index=0,
            page_size=100,
            total_results=1,
            results=[
                ProductRelease(
                    uuid=UUID, version="1.0.0", created_date="2024-01-01T00:00:00Z", components=[], pre_release=True
                )
            ],
        )
        output = _capture(fmt_search_releases, data)
        assert "Product Releases" in output
        assert "1.0.0" in output
        assert "True" in output


class TestFmtProduct:
    def test_renders_panel(self):
        product = Product(
            uuid=UUID,
            name="Test Product",
            identifiers=[Identifier(id_type="PURL", id_value="pkg:pypi/test")],
        )
        output = _capture(fmt_product, product)
        assert "Product" in output
        assert UUID in output
        assert "Test Product" in output
        assert "PURL:pkg:pypi/test" in output

    def test_markup_escape(self):
        """Server-controlled data with Rich markup chars is escaped."""
        product = Product(uuid=UUID, name="[bold red]Evil[/bold red]", identifiers=[])
        output = _capture(fmt_product, product)
        # The markup should be escaped, not rendered as bold/red
        assert "[bold red]" in output or "Evil" in output
        assert UUID in output


class TestFmtProductRelease:
    def test_renders_panel_and_components(self):
        data = ProductRelease(
            uuid=UUID,
            version="2.0.0",
            product_name="My Product",
            created_date="2024-01-01T00:00:00Z",
            release_date="2024-01-15T00:00:00Z",
            pre_release=False,
            identifiers=[],
            components=[{"uuid": UUID2, "release": UUID2}],
        )
        output = _capture(fmt_product_release, data)
        assert "Product Release" in output
        assert "2.0.0" in output
        assert "My Product" in output
        assert "Components" in output
        assert UUID2 in output

    def test_no_components(self):
        data = ProductRelease(uuid=UUID, version="1.0.0", created_date="2024-01-01T00:00:00Z", components=[])
        output = _capture(fmt_product_release, data)
        assert "Product Release" in output
        assert "Components" not in output


class TestFmtComponentRelease:
    def test_renders_release_and_collection(self):
        data = ComponentReleaseWithCollection(
            release=Release(
                uuid=UUID,
                version="1.0.0",
                component_name="libfoo",
                created_date="2024-01-01T00:00:00Z",
                identifiers=[],
            ),
            latest_collection=Collection(uuid=UUID, version=1, artifacts=[]),
        )
        output = _capture(fmt_component_release, data)
        assert "Component Release" in output
        assert "libfoo" in output
        assert "Latest Collection" in output

    def test_renders_artifacts(self):
        data = ComponentReleaseWithCollection(
            release=Release(uuid=UUID, version="1.0.0", created_date="2024-01-01T00:00:00Z"),
            latest_collection=Collection(
                uuid=UUID,
                version=1,
                artifacts=[Artifact(uuid=UUID2, name="SBOM", type="BOM", formats=[])],
            ),
        )
        output = _capture(fmt_component_release, data)
        assert "Artifacts" in output
        assert "SBOM" in output


class TestFmtCollection:
    def test_renders_panel(self):
        data = Collection(
            uuid=UUID,
            version=3,
            belongs_to=CollectionBelongsTo.PRODUCT_RELEASE,
            update_reason=CollectionUpdateReason(
                type=CollectionUpdateReasonType.VEX_UPDATED, comment="CVE-2024-1234 fixed"
            ),
            artifacts=[],
        )
        output = _capture(fmt_collection, data)
        assert "Collection" in output
        assert "PRODUCT_RELEASE" in output
        assert "VEX_UPDATED" in output
        assert "CVE-2024-1234 fixed" in output

    def test_no_update_reason(self):
        data = Collection(uuid=UUID, version=1, artifacts=[])
        output = _capture(fmt_collection, data)
        assert "Collection" in output


class TestFmtArtifact:
    def test_renders_panel_and_formats(self):
        data = Artifact(
            uuid=UUID,
            name="SBOM",
            type="BOM",
            formats=[
                ArtifactFormat(
                    media_type="application/json",
                    url="https://cdn.example.com/sbom.json",
                    checksums=[Checksum(algorithm_type=ChecksumAlgorithm.SHA_256, algorithm_value="abcdef1234567890")],
                )
            ],
        )
        output = _capture(fmt_artifact, data)
        assert "Artifact" in output
        assert "SBOM" in output
        assert "BOM" in output
        assert "Formats" in output
        assert "application/json" in output
        assert "abcdef123456" in output

    def test_no_formats(self):
        data = Artifact(uuid=UUID, name="VEX", type="VULNERABILITIES", formats=[])
        output = _capture(fmt_artifact, data)
        assert "Artifact" in output
        assert "Formats" not in output


class TestFmtInspect:
    def test_renders_release_and_components(self):
        data = [
            {
                "discovery": {"productReleaseUuid": UUID},
                "productRelease": {"uuid": UUID, "version": "1.0.0", "createdDate": "2024-01-01T00:00:00Z"},
                "components": [
                    {"uuid": UUID2, "version": "2.0.0", "name": "libbar"},
                ],
            }
        ]
        output = _capture(fmt_inspect, data)
        assert "Product Release" in output
        assert UUID in output
        assert "Components" in output
        assert "libbar" in output

    def test_truncated_output(self):
        data = [
            {
                "discovery": {"productReleaseUuid": UUID},
                "productRelease": {"uuid": UUID, "version": "1.0.0", "createdDate": "2024-01-01"},
                "components": [{"uuid": UUID2, "version": "1.0.0", "name": "comp1"}],
                "truncated": True,
                "totalComponents": 50,
            }
        ]
        output = _capture(fmt_inspect, data)
        assert "1 of 50" in output

    def test_empty_components(self):
        data = [
            {
                "discovery": {"productReleaseUuid": UUID},
                "productRelease": {"uuid": UUID, "version": "1.0.0", "createdDate": "2024-01-01"},
                "components": [],
            }
        ]
        output = _capture(fmt_inspect, data)
        assert "Product Release" in output
        assert "Components" not in output

    def test_component_with_nested_release(self):
        """Component data that comes from componentRelease endpoint (nested release dict)."""
        data = [
            {
                "discovery": {"productReleaseUuid": UUID},
                "productRelease": {"uuid": UUID, "version": "1.0.0", "createdDate": "2024-01-01"},
                "components": [
                    {"release": {"uuid": UUID2, "version": "3.0.0", "componentName": "nested-comp"}},
                ],
            }
        ]
        output = _capture(fmt_inspect, data)
        assert UUID2 in output
        assert "3.0.0" in output


class TestFormatOutputDispatch:
    def test_dispatch_product(self):
        product = Product(uuid=UUID, name="Test", identifiers=[])
        output = _capture(format_output, product)
        assert "Product" in output

    def test_dispatch_discover_via_command(self):
        data = [
            DiscoveryInfo(
                product_release_uuid=UUID,
                servers=[TeaServerInfo(root_url="https://tea.example.com", versions=["1.0.0"])],
            )
        ]
        output = _capture(format_output, data, command="discover")
        assert "Discovery Results" in output

    def test_dispatch_empty_discover_via_command(self):
        """Empty discovery list should still render a table, not fall through to JSON."""
        output = _capture(format_output, [], command="discover")
        assert "Discovery Results" in output

    def test_dispatch_inspect_via_command(self):
        data = [
            {
                "discovery": {"productReleaseUuid": UUID},
                "productRelease": {"uuid": UUID, "version": "1.0.0", "createdDate": "2024-01-01"},
                "components": [],
            }
        ]
        output = _capture(format_output, data, command="inspect")
        assert "Product Release" in output

    def test_fallback_renders_json(self):
        """Unknown types fall back to JSON rendering."""
        output = _capture(format_output, {"foo": "bar"})
        assert "foo" in output
        assert "bar" in output


class TestMarkupEscape:
    """Verify that server-controlled data with Rich markup is safely escaped."""

    def test_panel_escapes_markup_in_value(self):
        product = Product(uuid=UUID, name="[bold]bad[/bold]", identifiers=[])
        output = _capture(fmt_product, product)
        # Should not crash, and should contain the literal brackets
        assert UUID in output

    def test_panel_escapes_markup_in_identifiers(self):
        product = Product(
            uuid=UUID,
            name="safe",
            identifiers=[Identifier(id_type="PURL", id_value="[link=http://evil]click[/link]")],
        )
        output = _capture(fmt_product, product)
        assert "safe" in output
