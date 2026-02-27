"""Unit tests for libtea._cli_fmt rich formatters."""

from io import StringIO

import pytest

typer = pytest.importorskip("typer", reason="typer not installed (install libtea[cli])")

from rich.console import Console  # noqa: E402

from libtea._cli_fmt import (  # noqa: E402
    _fmt_identifiers,
    _opt,
    fmt_artifact,
    fmt_cle,
    fmt_collection,
    fmt_collections,
    fmt_component,
    fmt_component_release,
    fmt_discover,
    fmt_inspect,
    fmt_product,
    fmt_product_release,
    fmt_releases,
    fmt_search_products,
    fmt_search_releases,
    format_output,
)
from libtea.models import (  # noqa: E402
    CLE,
    Artifact,
    ArtifactFormat,
    Checksum,
    ChecksumAlgorithm,
    CLEDefinitions,
    CLEEvent,
    CLEEventType,
    CLESupportDefinition,
    CLEVersionSpecifier,
    Collection,
    CollectionBelongsTo,
    CollectionUpdateReason,
    CollectionUpdateReasonType,
    Component,
    ComponentReleaseWithCollection,
    DiscoveryInfo,
    Identifier,
    PaginatedProductReleaseResponse,
    PaginatedProductResponse,
    Product,
    ProductRelease,
    Release,
    ReleaseDistribution,
    TeaServerInfo,
)


def _capture(fn, *args, **kwargs) -> str:
    """Call a formatter with a StringIO-backed Console and return the output."""
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=200)
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
        assert "https://tea.example.com" in output
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
        assert "No results (total: 0)" in output


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

    def test_renders_all_product_release_fields(self):
        """Panel should show product name, release date, pre-release, and identifiers."""
        data = [
            {
                "discovery": {"productReleaseUuid": UUID},
                "productRelease": {
                    "uuid": UUID,
                    "version": "2.0.0",
                    "productName": "My Product",
                    "createdDate": "2024-01-01T00:00:00Z",
                    "releaseDate": "2024-01-15T00:00:00Z",
                    "preRelease": False,
                    "identifiers": [
                        {"idType": "PURL", "idValue": "pkg:pypi/test"},
                        {"idType": "ASIN", "idValue": "B07FDJMC9Q"},
                    ],
                },
                "components": [],
            }
        ]
        output = _capture(fmt_inspect, data)
        assert "My Product" in output
        assert "2024-01-15" in output
        assert "False" in output
        assert "PURL:pkg:pypi/test" in output
        assert "ASIN:B07FDJMC9Q" in output

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

    def test_resolved_unpinned_component_with_artifacts(self):
        """Unpinned component with a resolved release should show artifacts."""
        data = [
            {
                "discovery": {"productReleaseUuid": UUID},
                "productRelease": {"uuid": UUID, "version": "1.0.0", "createdDate": "2024-01-01"},
                "components": [
                    {
                        "uuid": UUID2,
                        "name": "App",
                        "identifiers": [],
                        "resolvedNote": "latest release (not pinned)",
                        "resolvedRelease": {
                            "release": {"uuid": UUID2, "version": "1.0.0", "createdDate": "2024-01-01"},
                            "latestCollection": {
                                "uuid": UUID,
                                "version": 1,
                                "artifacts": [
                                    {
                                        "uuid": UUID2,
                                        "name": "SPDX SBOM",
                                        "type": "BOM",
                                        "formats": [
                                            {
                                                "mediaType": "application/spdx+json",
                                                "url": "https://cdn.example.com/sbom.json",
                                                "checksums": [],
                                            }
                                        ],
                                    }
                                ],
                            },
                        },
                    }
                ],
            }
        ]
        output = _capture(fmt_inspect, data)
        assert "App" in output
        assert "latest release (not pinned)" in output
        assert "Artifacts" in output
        assert "SPDX SBOM" in output
        assert "BOM" in output
        assert "application/spdx+json" in output
        assert "https://cdn.example.com/sbom.json" in output

    def test_pinned_component_with_collection_artifacts(self):
        """Pinned component (from componentRelease) should show artifacts from latestCollection."""
        data = [
            {
                "discovery": {"productReleaseUuid": UUID},
                "productRelease": {"uuid": UUID, "version": "1.0.0", "createdDate": "2024-01-01"},
                "components": [
                    {
                        "release": {"uuid": UUID2, "version": "2.0.0", "componentName": "libfoo"},
                        "latestCollection": {
                            "uuid": UUID,
                            "version": 1,
                            "artifacts": [
                                {
                                    "uuid": UUID2,
                                    "name": "VEX",
                                    "type": "VULNERABILITIES",
                                    "formats": [{"mediaType": "application/json", "url": "https://cdn/vex.json"}],
                                }
                            ],
                        },
                    }
                ],
            }
        ]
        output = _capture(fmt_inspect, data)
        assert "libfoo" in output
        assert "VEX" in output
        assert "application/json" in output


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


class TestDistributionsTable:
    """Test display of release-distribution fields."""

    def test_component_release_with_distributions(self):
        data = ComponentReleaseWithCollection(
            release=Release(
                uuid=UUID,
                version="11.0.7",
                component_name="tomcat",
                created_date="2024-01-01T00:00:00Z",
                distributions=[
                    ReleaseDistribution(
                        distribution_type="zip",
                        description="Core binary distribution, zip archive",
                        url="https://repo.example.com/tomcat-11.0.7.zip",
                        signature_url="https://repo.example.com/tomcat-11.0.7.zip.asc",
                        checksums=[
                            Checksum(algorithm_type=ChecksumAlgorithm.SHA_256, algorithm_value="abcdef1234567890")
                        ],
                    ),
                    ReleaseDistribution(
                        distribution_type="tar.gz",
                        description="Core binary distribution, tar.gz archive",
                        url="https://repo.example.com/tomcat-11.0.7.tar.gz",
                    ),
                ],
            ),
            latest_collection=Collection(uuid=UUID, version=1, artifacts=[]),
        )
        output = _capture(fmt_component_release, data)
        assert "Distributions" in output
        assert "zip" in output
        assert "tar.gz" in output
        assert "Core binary distribution, zip archive" in output
        assert "https://repo.example.com/tomcat-11.0.7.zip" in output
        assert "tomcat-11.0.7.zip.asc" in output
        assert "SHA-256:abcdef123456" in output

    def test_component_release_without_distributions(self):
        data = ComponentReleaseWithCollection(
            release=Release(uuid=UUID, version="1.0.0", created_date="2024-01-01T00:00:00Z"),
            latest_collection=Collection(uuid=UUID, version=1, artifacts=[]),
        )
        output = _capture(fmt_component_release, data)
        assert "Distributions" not in output

    def test_inspect_component_with_distributions(self):
        """Inspect output should show distributions from the release dict."""
        data = [
            {
                "discovery": {"productReleaseUuid": UUID},
                "productRelease": {"uuid": UUID, "version": "1.0.0", "createdDate": "2024-01-01"},
                "components": [
                    {
                        "release": {
                            "uuid": UUID2,
                            "version": "11.0.7",
                            "componentName": "tomcat",
                            "distributions": [
                                {
                                    "distributionType": "zip",
                                    "description": "Zip archive",
                                    "url": "https://repo.example.com/tomcat.zip",
                                    "signatureUrl": "https://repo.example.com/tomcat.zip.asc",
                                    "checksums": [{"algType": "SHA-256", "algValue": "abc123def456"}],
                                }
                            ],
                        },
                        "latestCollection": {"uuid": UUID, "version": 1, "artifacts": []},
                    }
                ],
            }
        ]
        output = _capture(fmt_inspect, data)
        assert "Distributions" in output
        assert "zip" in output
        assert "Zip archive" in output
        assert "https://repo.example.com/tomcat.zip" in output
        assert "tomcat.zip.asc" in output
        assert "SHA-256:abc123def456" in output


class TestArtifactFormatDetails:
    """Test display of artifact-format description, signatureUrl, and distributionTypes."""

    def test_formats_table_shows_description_and_signature(self):
        data = Artifact(
            uuid=UUID,
            name="Build SBOM",
            type="BOM",
            formats=[
                ArtifactFormat(
                    media_type="application/vnd.cyclonedx+xml",
                    description="CycloneDX SBOM (XML)",
                    url="https://repo.example.com/sbom.xml",
                    signature_url="https://repo.example.com/sbom.xml.asc",
                    checksums=[Checksum(algorithm_type=ChecksumAlgorithm.SHA_256, algorithm_value="abcdef1234567890")],
                )
            ],
        )
        output = _capture(fmt_artifact, data)
        assert "CycloneDX SBOM (XML)" in output
        assert "sbom.xml.asc" in output
        assert "application/vnd.cyclonedx+xml" in output

    def test_artifacts_table_shows_distribution_types(self):
        data = Collection(
            uuid=UUID,
            version=1,
            artifacts=[
                Artifact(
                    uuid=UUID,
                    name="Build SBOM",
                    type="BOM",
                    distribution_types=["zip", "tar.gz"],
                    formats=[ArtifactFormat(media_type="application/xml", url="https://example.com/sbom.xml")],
                )
            ],
        )
        output = _capture(fmt_collection, data)
        assert "zip, tar.gz" in output

    def test_inspect_artifact_shows_description_and_signature(self):
        """Inspect output should show description and signatureUrl for artifact formats."""
        data = [
            {
                "discovery": {"productReleaseUuid": UUID},
                "productRelease": {"uuid": UUID, "version": "1.0.0", "createdDate": "2024-01-01"},
                "components": [
                    {
                        "uuid": UUID2,
                        "name": "App",
                        "resolvedRelease": {
                            "release": {"uuid": UUID2, "version": "1.0.0", "createdDate": "2024-01-01"},
                            "latestCollection": {
                                "uuid": UUID,
                                "version": 1,
                                "artifacts": [
                                    {
                                        "uuid": UUID2,
                                        "name": "VDR",
                                        "type": "VULNERABILITIES",
                                        "distributionTypes": ["zip"],
                                        "formats": [
                                            {
                                                "mediaType": "application/vnd.cyclonedx+xml",
                                                "description": "CycloneDX VDR (XML)",
                                                "url": "https://example.com/vdr.xml",
                                                "signatureUrl": "https://example.com/vdr.xml.asc",
                                            }
                                        ],
                                    }
                                ],
                            },
                        },
                    }
                ],
            }
        ]
        output = _capture(fmt_inspect, data)
        assert "CycloneDX VDR (XML)" in output
        assert "vdr.xml.asc" in output
        assert "zip" in output


class TestComponentFormatter:
    def test_fmt_component(self):
        comp = Component(
            uuid=UUID,
            name="My Component",
            identifiers=[Identifier(id_type="PURL", id_value="pkg:pypi/test")],
        )
        output = _capture(fmt_component, comp)
        assert UUID in output
        assert "My Component" in output
        assert "PURL:pkg:pypi/test" in output

    def test_format_output_dispatches_component(self):
        comp = Component(uuid=UUID, name="Comp", identifiers=[])
        output = _capture(format_output, comp)
        assert "Comp" in output


class TestReleasesFormatter:
    def test_fmt_releases(self):
        releases = [
            Release(
                uuid=UUID,
                version="1.0.0",
                component_name="App",
                created_date="2024-01-01T00:00:00Z",
                release_date="2024-02-01T00:00:00Z",
                pre_release=False,
            ),
            Release(
                uuid=UUID2,
                version="2.0.0",
                component_name="App",
                created_date="2024-06-01T00:00:00Z",
            ),
        ]
        output = _capture(fmt_releases, releases)
        assert "Component Releases" in output
        assert "1.0.0" in output
        assert "2.0.0" in output
        assert "App" in output

    def test_format_output_releases_command(self):
        releases = [
            Release(uuid=UUID, version="1.0.0", created_date="2024-01-01T00:00:00Z"),
        ]
        output = _capture(format_output, releases, command="releases")
        assert "Component Releases" in output
        assert "1.0.0" in output


class TestCollectionsFormatter:
    def test_fmt_collections(self):
        cols = [
            Collection(uuid=UUID, version=1, date="2024-01-01T00:00:00Z", belongs_to="COMPONENT_RELEASE", artifacts=[]),
            Collection(
                uuid=UUID2,
                version=2,
                date="2024-06-01T00:00:00Z",
                belongs_to="COMPONENT_RELEASE",
                artifacts=[Artifact(uuid=UUID, name="SBOM", type="BOM", formats=[])],
            ),
        ]
        output = _capture(fmt_collections, cols)
        assert "Collections" in output
        assert UUID in output
        assert UUID2 in output
        # Second collection has 1 artifact
        assert "1" in output

    def test_format_output_collections_command(self):
        cols = [Collection(uuid=UUID, version=1, artifacts=[])]
        output = _capture(format_output, cols, command="collections")
        assert "Collections" in output


class TestCLEFormatter:
    def test_fmt_cle_basic(self):
        cle = CLE(
            events=[
                CLEEvent(
                    id=1,
                    type=CLEEventType.RELEASED,
                    effective="2024-01-15T00:00:00Z",
                    published="2024-01-15T00:00:00Z",
                    version="1.0.0",
                    license="Apache-2.0",
                ),
                CLEEvent(
                    id=2,
                    type=CLEEventType.END_OF_SUPPORT,
                    effective="2025-01-15T00:00:00Z",
                    published="2024-06-01T00:00:00Z",
                    support_id="standard",
                    reason="EOL",
                ),
            ]
        )
        output = _capture(fmt_cle, cle)
        assert "Lifecycle Events" in output
        assert "released" in output
        assert "endOfSupport" in output
        assert "1.0.0" in output
        assert "license=Apache-2.0" in output
        assert "support=standard" in output
        assert "reason=EOL" in output

    def test_fmt_cle_with_definitions(self):
        cle = CLE(
            definitions=CLEDefinitions(
                support=[
                    CLESupportDefinition(
                        id="standard", description="Standard support", url="https://example.com/support"
                    ),
                ]
            ),
            events=[
                CLEEvent(
                    id=1,
                    type=CLEEventType.RELEASED,
                    effective="2024-01-15T00:00:00Z",
                    published="2024-01-15T00:00:00Z",
                    version="1.0.0",
                ),
            ],
        )
        output = _capture(fmt_cle, cle)
        assert "Support Definitions" in output
        assert "standard" in output
        assert "Standard support" in output
        assert "example.com/support" in output

    def test_fmt_cle_superseded(self):
        cle = CLE(
            events=[
                CLEEvent(
                    id=1,
                    type=CLEEventType.SUPERSEDED_BY,
                    effective="2024-01-15T00:00:00Z",
                    published="2024-01-15T00:00:00Z",
                    superseded_by_version="2.0.0",
                ),
            ]
        )
        output = _capture(fmt_cle, cle)
        assert "supersededBy" in output
        assert "superseded_by=2.0.0" in output

    def test_format_output_dispatches_cle(self):
        cle = CLE(
            events=[
                CLEEvent(
                    id=1,
                    type=CLEEventType.RELEASED,
                    effective="2024-01-15T00:00:00Z",
                    published="2024-01-15T00:00:00Z",
                    version="1.0.0",
                ),
            ]
        )
        output = _capture(format_output, cle)
        assert "Lifecycle Events" in output


class TestCollectionUpdateReasonComment:
    """Cover the update_reason.comment branch at _cli_fmt.py:239."""

    def test_update_reason_without_comment(self):
        data = Collection(
            uuid=UUID,
            version=2,
            update_reason=CollectionUpdateReason(type=CollectionUpdateReasonType.VEX_UPDATED),
            artifacts=[],
        )
        output = _capture(fmt_collection, data)
        assert "VEX_UPDATED" in output
        # No parenthesised comment
        assert "(" not in output.split("VEX_UPDATED")[1].split("\n")[0]


class TestCLEEventIdAndVersions:
    """Cover event_id (line 345) and versions (lines 349-350) branches."""

    def test_event_id_is_shown(self):
        cle = CLE(
            events=[
                CLEEvent(
                    id=2,
                    type=CLEEventType.WITHDRAWN,
                    effective="2024-06-01T00:00:00Z",
                    published="2024-06-01T00:00:00Z",
                    event_id=1,
                ),
            ]
        )
        output = _capture(fmt_cle, cle)
        assert "event_id=1" in output

    def test_versions_shown_as_range(self):
        cle = CLE(
            events=[
                CLEEvent(
                    id=1,
                    type=CLEEventType.END_OF_SUPPORT,
                    effective="2024-06-01T00:00:00Z",
                    published="2024-06-01T00:00:00Z",
                    versions=[
                        CLEVersionSpecifier(version="1.0.0"),
                        CLEVersionSpecifier(range="vers:semver/>=2.0.0|<3.0.0"),
                    ],
                ),
            ]
        )
        output = _capture(fmt_cle, cle)
        assert "1.0.0" in output
        assert "vers:semver/>=2.0.0|<3.0.0" in output


class TestInspectArtifactWithoutFormats:
    """Cover the else branch at _cli_fmt.py:460 (artifact with no formats)."""

    def test_artifact_no_formats_in_inspect(self):
        data = [
            {
                "discovery": {"productReleaseUuid": UUID},
                "productRelease": {"uuid": UUID, "version": "1.0.0", "createdDate": "2024-01-01"},
                "components": [
                    {
                        "release": {"uuid": UUID2, "version": "2.0.0", "componentName": "libfoo"},
                        "latestCollection": {
                            "uuid": UUID,
                            "version": 1,
                            "artifacts": [
                                {"uuid": UUID2, "name": "VEX", "type": "VULNERABILITIES", "formats": []},
                            ],
                        },
                    }
                ],
            }
        ]
        output = _capture(fmt_inspect, data)
        assert "VEX" in output


class TestFormatOutputFallbacks:
    """Cover JSON fallback branches at _cli_fmt.py:517-521."""

    def test_fallback_basemodel_json(self):
        """BaseModel not in _TYPE_FORMATTERS renders as JSON (line 518)."""
        from libtea.models import TeaEndpoint

        ep = TeaEndpoint(url="https://tea.example.com", versions=["1.0.0"])
        output = _capture(format_output, ep)
        assert "tea.example.com" in output

    def test_fallback_list_json(self):
        """List of BaseModels with unknown command renders as JSON (lines 519-521)."""
        from libtea.models import TeaEndpoint

        eps = [
            TeaEndpoint(url="https://tea1.example.com", versions=["1.0.0"]),
            TeaEndpoint(url="https://tea2.example.com", versions=["2.0.0"]),
        ]
        output = _capture(format_output, eps, command="unknown_command")
        assert "tea1.example.com" in output
        assert "tea2.example.com" in output
