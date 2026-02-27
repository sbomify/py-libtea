"""CLI for the Transparency Exchange API.

Provides the ``tea-cli`` command backed by typer. Each subcommand maps
to a :class:`~libtea.client.TeaClient` method and outputs rich-formatted
tables and panels by default (or JSON when ``--json`` is specified).
All commands accept ``--base-url`` / ``--domain`` for server selection,
and ``--token`` / ``--auth`` / ``--client-cert`` for authentication.
"""

import json
import logging
import sys
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from pydantic import BaseModel

from libtea._http import MtlsConfig
from libtea.client import TEA_SPEC_VERSION, TeaClient
from libtea.discovery import parse_tei
from libtea.exceptions import TeaDiscoveryError, TeaError
from libtea.models import Checksum, ChecksumAlgorithm, normalize_algorithm_name

logger = logging.getLogger("libtea")

app = typer.Typer(help="TEA (Transparency Exchange API) CLI client.", no_args_is_help=True)

_json_output: bool = False

# --- Shared options ---

_base_url_opt = typer.Option(envvar="TEA_BASE_URL", help="TEA server base URL")
_token_opt = typer.Option(
    envvar="TEA_TOKEN", help="Bearer token (prefer TEA_TOKEN env var to avoid shell history exposure)"
)
_auth_opt = typer.Option(envvar="TEA_AUTH", help="Basic auth as USER:PASSWORD (prefer TEA_AUTH env var)")
_domain_opt = typer.Option(help="Discover server from domain's .well-known/tea")
_timeout_opt = typer.Option(help="Request timeout in seconds")
_use_http_opt = typer.Option(help="Use HTTP instead of HTTPS for discovery")
_port_opt = typer.Option(help="Port for well-known resolution")
_client_cert_opt = typer.Option(help="Path to client certificate for mTLS")
_client_key_opt = typer.Option(help="Path to client private key for mTLS")
_ca_bundle_opt = typer.Option(help="Path to CA bundle for mTLS server verification")


def _parse_basic_auth(auth: str | None) -> tuple[str, str] | None:
    """Parse a ``USER:PASSWORD`` string into a ``(user, password)`` tuple.

    Returns ``None`` if ``auth`` is ``None`` or empty. Calls :func:`_error`
    (which exits) if the format is invalid.
    """
    if not auth:
        return None
    if ":" not in auth:
        _error("Invalid --auth format. Expected USER:PASSWORD")
    user, password = auth.split(":", 1)
    return (user, password)


def _build_mtls(client_cert: str | None, client_key: str | None, ca_bundle: str | None) -> MtlsConfig | None:
    """Build an :class:`~libtea.MtlsConfig` from CLI options, or return ``None``.

    Both ``--client-cert`` and ``--client-key`` must be provided together.
    Calls :func:`_error` if only one is specified.
    """
    if not client_cert and not client_key:
        return None
    if client_cert and not client_key:
        _error("--client-key is required when --client-cert is specified")
    if client_key and not client_cert:
        _error("--client-cert is required when --client-key is specified")
    return MtlsConfig(
        client_cert=Path(client_cert),
        client_key=Path(client_key),
        ca_bundle=Path(ca_bundle) if ca_bundle else None,
    )


def _domain_from_tei(tei: str | None) -> str | None:
    """Extract the domain component from a TEI URN for auto-discovery.

    Returns ``None`` if ``tei`` is falsy or not a valid TEI URN.
    """
    if not tei:
        return None
    try:
        _, domain, _ = parse_tei(tei)
        return domain
    except TeaDiscoveryError:
        return None


def _build_client(
    base_url: str | None,
    token: str | None,
    domain: str | None,
    timeout: float,
    use_http: bool,
    port: int | None,
    auth: str | None = None,
    client_cert: str | None = None,
    client_key: str | None = None,
    ca_bundle: str | None = None,
    tei: str | None = None,
) -> TeaClient:
    """Build a TeaClient from CLI options.

    When neither --base-url nor --domain is provided, the domain is extracted
    from the TEI URN (if given) and used for .well-known/tea discovery.
    """
    if base_url and domain:
        _error("Cannot use both --base-url and --domain")
    if not base_url and not domain:
        domain = _domain_from_tei(tei)
    if not base_url and not domain:
        _error("Must specify either --base-url or --domain (or provide a TEI to auto-discover)")
    basic_auth = _parse_basic_auth(auth)
    mtls = _build_mtls(client_cert, client_key, ca_bundle)
    if base_url:
        return TeaClient(base_url=base_url, token=token, basic_auth=basic_auth, timeout=timeout, mtls=mtls)
    scheme = "http" if use_http else "https"
    return TeaClient.from_well_known(
        domain, token=token, basic_auth=basic_auth, timeout=timeout, scheme=scheme, port=port, mtls=mtls
    )


def _output(data: Any, *, command: str | None = None) -> None:
    """Output ``data`` as JSON (when ``--json``) or rich-formatted tables/panels.

    In JSON mode, Pydantic models are serialized via ``model_dump(mode="json",
    by_alias=True)`` to produce camelCase keys matching the TEA API wire format.
    """
    if _json_output:
        if isinstance(data, BaseModel):
            data = data.model_dump(mode="json", by_alias=True)
        elif isinstance(data, list):
            data = [
                item.model_dump(mode="json", by_alias=True) if isinstance(item, BaseModel) else item for item in data
            ]
        json.dump(data, sys.stdout, indent=2, default=str)
        print()
    else:
        from libtea._cli_fmt import format_output

        format_output(data, command=command)


def _error(message: str) -> NoReturn:
    """Print an error message to stderr and exit with code 1."""
    print(f"Error: {message}", file=sys.stderr)
    raise typer.Exit(1)


# --- Commands ---


@app.command()
def discover(
    tei: str,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Output only UUIDs, one per line")] = False,
    base_url: Annotated[str | None, _base_url_opt] = None,
    token: Annotated[str | None, _token_opt] = None,
    auth: Annotated[str | None, _auth_opt] = None,
    domain: Annotated[str | None, _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[int | None, _port_opt] = None,
    client_cert: Annotated[str | None, _client_cert_opt] = None,
    client_key: Annotated[str | None, _client_key_opt] = None,
    ca_bundle: Annotated[str | None, _ca_bundle_opt] = None,
):
    """Resolve a TEI to product release UUID(s)."""
    try:
        with _build_client(
            base_url, token, domain, timeout, use_http, port, auth, client_cert, client_key, ca_bundle, tei=tei
        ) as client:
            result = client.discover(tei)
        if quiet:
            for d in result:
                print(d.product_release_uuid)
        else:
            _output(result, command="discover")
    except TeaError as exc:
        _error(str(exc))


@app.command("search-products")
def search_products(
    id_type: Annotated[str, typer.Option("--id-type", help="Identifier type (CPE, TEI, PURL)")],
    id_value: Annotated[str, typer.Option("--id-value", help="Identifier value")],
    page_offset: Annotated[int, typer.Option("--page-offset", help="Page offset")] = 0,
    page_size: Annotated[int, typer.Option("--page-size", help="Page size")] = 100,
    base_url: Annotated[str | None, _base_url_opt] = None,
    token: Annotated[str | None, _token_opt] = None,
    auth: Annotated[str | None, _auth_opt] = None,
    domain: Annotated[str | None, _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[int | None, _port_opt] = None,
    client_cert: Annotated[str | None, _client_cert_opt] = None,
    client_key: Annotated[str | None, _client_key_opt] = None,
    ca_bundle: Annotated[str | None, _ca_bundle_opt] = None,
):
    """Search for products by identifier."""
    try:
        with _build_client(
            base_url, token, domain, timeout, use_http, port, auth, client_cert, client_key, ca_bundle
        ) as client:
            result = client.search_products(id_type, id_value, page_offset=page_offset, page_size=page_size)
        _output(result)
    except TeaError as exc:
        _error(str(exc))


@app.command("search-releases")
def search_releases(
    id_type: Annotated[str, typer.Option("--id-type", help="Identifier type (CPE, TEI, PURL)")],
    id_value: Annotated[str, typer.Option("--id-value", help="Identifier value")],
    page_offset: Annotated[int, typer.Option("--page-offset", help="Page offset")] = 0,
    page_size: Annotated[int, typer.Option("--page-size", help="Page size")] = 100,
    base_url: Annotated[str | None, _base_url_opt] = None,
    token: Annotated[str | None, _token_opt] = None,
    auth: Annotated[str | None, _auth_opt] = None,
    domain: Annotated[str | None, _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[int | None, _port_opt] = None,
    client_cert: Annotated[str | None, _client_cert_opt] = None,
    client_key: Annotated[str | None, _client_key_opt] = None,
    ca_bundle: Annotated[str | None, _ca_bundle_opt] = None,
):
    """Search for product releases by identifier."""
    try:
        with _build_client(
            base_url, token, domain, timeout, use_http, port, auth, client_cert, client_key, ca_bundle
        ) as client:
            result = client.search_product_releases(id_type, id_value, page_offset=page_offset, page_size=page_size)
        _output(result)
    except TeaError as exc:
        _error(str(exc))


@app.command("get-product")
def get_product(
    uuid: str,
    base_url: Annotated[str | None, _base_url_opt] = None,
    token: Annotated[str | None, _token_opt] = None,
    auth: Annotated[str | None, _auth_opt] = None,
    domain: Annotated[str | None, _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[int | None, _port_opt] = None,
    client_cert: Annotated[str | None, _client_cert_opt] = None,
    client_key: Annotated[str | None, _client_key_opt] = None,
    ca_bundle: Annotated[str | None, _ca_bundle_opt] = None,
):
    """Get a product by UUID."""
    try:
        with _build_client(
            base_url, token, domain, timeout, use_http, port, auth, client_cert, client_key, ca_bundle
        ) as client:
            result = client.get_product(uuid)
        _output(result)
    except TeaError as exc:
        _error(str(exc))


@app.command("get-release")
def get_release(
    uuid: str,
    component: Annotated[
        bool, typer.Option("--component", help="Get a component release instead of product release")
    ] = False,
    base_url: Annotated[str | None, _base_url_opt] = None,
    token: Annotated[str | None, _token_opt] = None,
    auth: Annotated[str | None, _auth_opt] = None,
    domain: Annotated[str | None, _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[int | None, _port_opt] = None,
    client_cert: Annotated[str | None, _client_cert_opt] = None,
    client_key: Annotated[str | None, _client_key_opt] = None,
    ca_bundle: Annotated[str | None, _ca_bundle_opt] = None,
):
    """Get a product or component release by UUID."""
    try:
        with _build_client(
            base_url, token, domain, timeout, use_http, port, auth, client_cert, client_key, ca_bundle
        ) as client:
            if component:
                result = client.get_component_release(uuid)
            else:
                result = client.get_product_release(uuid)
        _output(result)
    except TeaError as exc:
        _error(str(exc))


@app.command("get-collection")
def get_collection(
    uuid: str,
    version: Annotated[int | None, typer.Option("--version", help="Collection version (default: latest)")] = None,
    component: Annotated[
        bool, typer.Option("--component", help="Get from component release instead of product release")
    ] = False,
    base_url: Annotated[str | None, _base_url_opt] = None,
    token: Annotated[str | None, _token_opt] = None,
    auth: Annotated[str | None, _auth_opt] = None,
    domain: Annotated[str | None, _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[int | None, _port_opt] = None,
    client_cert: Annotated[str | None, _client_cert_opt] = None,
    client_key: Annotated[str | None, _client_key_opt] = None,
    ca_bundle: Annotated[str | None, _ca_bundle_opt] = None,
):
    """Get a collection (latest or by version)."""
    try:
        with _build_client(
            base_url, token, domain, timeout, use_http, port, auth, client_cert, client_key, ca_bundle
        ) as client:
            if component:
                if version is not None:
                    result = client.get_component_release_collection(uuid, version)
                else:
                    result = client.get_component_release_collection_latest(uuid)
            else:
                if version is not None:
                    result = client.get_product_release_collection(uuid, version)
                else:
                    result = client.get_product_release_collection_latest(uuid)
        _output(result)
    except TeaError as exc:
        _error(str(exc))


@app.command("get-product-releases")
def get_product_releases(
    uuid: str,
    page_offset: Annotated[int, typer.Option("--page-offset", help="Page offset")] = 0,
    page_size: Annotated[int, typer.Option("--page-size", help="Page size")] = 100,
    base_url: Annotated[str | None, _base_url_opt] = None,
    token: Annotated[str | None, _token_opt] = None,
    auth: Annotated[str | None, _auth_opt] = None,
    domain: Annotated[str | None, _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[int | None, _port_opt] = None,
    client_cert: Annotated[str | None, _client_cert_opt] = None,
    client_key: Annotated[str | None, _client_key_opt] = None,
    ca_bundle: Annotated[str | None, _ca_bundle_opt] = None,
):
    """List releases for a product UUID."""
    try:
        with _build_client(
            base_url, token, domain, timeout, use_http, port, auth, client_cert, client_key, ca_bundle
        ) as client:
            result = client.get_product_releases(uuid, page_offset=page_offset, page_size=page_size)
        _output(result)
    except TeaError as exc:
        _error(str(exc))


@app.command("get-component")
def get_component(
    uuid: str,
    base_url: Annotated[str | None, _base_url_opt] = None,
    token: Annotated[str | None, _token_opt] = None,
    auth: Annotated[str | None, _auth_opt] = None,
    domain: Annotated[str | None, _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[int | None, _port_opt] = None,
    client_cert: Annotated[str | None, _client_cert_opt] = None,
    client_key: Annotated[str | None, _client_key_opt] = None,
    ca_bundle: Annotated[str | None, _ca_bundle_opt] = None,
):
    """Get a component by UUID."""
    try:
        with _build_client(
            base_url, token, domain, timeout, use_http, port, auth, client_cert, client_key, ca_bundle
        ) as client:
            result = client.get_component(uuid)
        _output(result)
    except TeaError as exc:
        _error(str(exc))


@app.command("get-component-releases")
def get_component_releases(
    uuid: str,
    base_url: Annotated[str | None, _base_url_opt] = None,
    token: Annotated[str | None, _token_opt] = None,
    auth: Annotated[str | None, _auth_opt] = None,
    domain: Annotated[str | None, _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[int | None, _port_opt] = None,
    client_cert: Annotated[str | None, _client_cert_opt] = None,
    client_key: Annotated[str | None, _client_key_opt] = None,
    ca_bundle: Annotated[str | None, _ca_bundle_opt] = None,
):
    """List releases for a component UUID."""
    try:
        with _build_client(
            base_url, token, domain, timeout, use_http, port, auth, client_cert, client_key, ca_bundle
        ) as client:
            result = client.get_component_releases(uuid)
        _output(result, command="releases")
    except TeaError as exc:
        _error(str(exc))


@app.command("list-collections")
def list_collections(
    uuid: str,
    component: Annotated[
        bool, typer.Option("--component", help="List collections for a component release instead of product release")
    ] = False,
    base_url: Annotated[str | None, _base_url_opt] = None,
    token: Annotated[str | None, _token_opt] = None,
    auth: Annotated[str | None, _auth_opt] = None,
    domain: Annotated[str | None, _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[int | None, _port_opt] = None,
    client_cert: Annotated[str | None, _client_cert_opt] = None,
    client_key: Annotated[str | None, _client_key_opt] = None,
    ca_bundle: Annotated[str | None, _ca_bundle_opt] = None,
):
    """List all collection versions for a release UUID."""
    try:
        with _build_client(
            base_url, token, domain, timeout, use_http, port, auth, client_cert, client_key, ca_bundle
        ) as client:
            if component:
                result = client.get_component_release_collections(uuid)
            else:
                result = client.get_product_release_collections(uuid)
        _output(result, command="collections")
    except TeaError as exc:
        _error(str(exc))


@app.command("get-cle")
def get_cle(
    uuid: str,
    entity: Annotated[
        str,
        typer.Option(
            "--entity",
            help="Entity type: product, product-release, component, or component-release",
        ),
    ] = "product-release",
    base_url: Annotated[str | None, _base_url_opt] = None,
    token: Annotated[str | None, _token_opt] = None,
    auth: Annotated[str | None, _auth_opt] = None,
    domain: Annotated[str | None, _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[int | None, _port_opt] = None,
    client_cert: Annotated[str | None, _client_cert_opt] = None,
    client_key: Annotated[str | None, _client_key_opt] = None,
    ca_bundle: Annotated[str | None, _ca_bundle_opt] = None,
):
    """Get Common Lifecycle Enumeration (CLE) for an entity."""
    entity_methods = {
        "product": "get_product_cle",
        "product-release": "get_product_release_cle",
        "component": "get_component_cle",
        "component-release": "get_component_release_cle",
    }
    if entity not in entity_methods:
        _error(f"Invalid --entity: {entity!r}. Must be one of: {', '.join(entity_methods)}")
    try:
        with _build_client(
            base_url, token, domain, timeout, use_http, port, auth, client_cert, client_key, ca_bundle
        ) as client:
            result = getattr(client, entity_methods[entity])(uuid)
        _output(result)
    except TeaError as exc:
        _error(str(exc))


@app.command("get-artifact")
def get_artifact(
    uuid: str,
    base_url: Annotated[str | None, _base_url_opt] = None,
    token: Annotated[str | None, _token_opt] = None,
    auth: Annotated[str | None, _auth_opt] = None,
    domain: Annotated[str | None, _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[int | None, _port_opt] = None,
    client_cert: Annotated[str | None, _client_cert_opt] = None,
    client_key: Annotated[str | None, _client_key_opt] = None,
    ca_bundle: Annotated[str | None, _ca_bundle_opt] = None,
):
    """Get artifact metadata by UUID."""
    try:
        with _build_client(
            base_url, token, domain, timeout, use_http, port, auth, client_cert, client_key, ca_bundle
        ) as client:
            result = client.get_artifact(uuid)
        _output(result)
    except TeaError as exc:
        _error(str(exc))


@app.command()
def download(
    url: str,
    dest: Path,
    checksum: Annotated[list[str] | None, typer.Option("--checksum", help="Checksum as ALG:VALUE (repeatable)")] = None,
    max_download_bytes: Annotated[
        int | None, typer.Option("--max-download-bytes", help="Maximum download size in bytes")
    ] = None,
    base_url: Annotated[str | None, _base_url_opt] = None,
    token: Annotated[str | None, _token_opt] = None,
    auth: Annotated[str | None, _auth_opt] = None,
    domain: Annotated[str | None, _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[int | None, _port_opt] = None,
    client_cert: Annotated[str | None, _client_cert_opt] = None,
    client_key: Annotated[str | None, _client_key_opt] = None,
    ca_bundle: Annotated[str | None, _ca_bundle_opt] = None,
):
    """Download an artifact file with optional checksum verification."""
    checksums = None
    if checksum:
        checksums = []
        for cs in checksum:
            if ":" not in cs:
                _error(f"Invalid checksum format: {cs!r}. Expected ALG:VALUE (e.g. SHA-256:abcdef...)")
            alg, value = cs.split(":", 1)
            # Normalize underscore form (SHA_256) to hyphen form (SHA-256)
            alg = normalize_algorithm_name(alg)
            try:
                alg_enum = ChecksumAlgorithm(alg)
            except ValueError:
                _error(
                    f"Unknown checksum algorithm: {alg!r}. Supported: {', '.join(e.value for e in ChecksumAlgorithm)}"
                )
            checksums.append(Checksum(algorithm_type=alg_enum, algorithm_value=value))

    try:
        with _build_client(
            base_url, token, domain, timeout, use_http, port, auth, client_cert, client_key, ca_bundle
        ) as client:
            result = client.download_artifact(
                url, dest, verify_checksums=checksums, max_download_bytes=max_download_bytes
            )
        print(f"Downloaded to {result}", file=sys.stderr)
    except TeaError as exc:
        _error(str(exc))


@app.command()
def inspect(
    tei: str,
    max_components: Annotated[
        int, typer.Option("--max-components", help="Maximum number of components to fetch per release")
    ] = 50,
    base_url: Annotated[str | None, _base_url_opt] = None,
    token: Annotated[str | None, _token_opt] = None,
    auth: Annotated[str | None, _auth_opt] = None,
    domain: Annotated[str | None, _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[int | None, _port_opt] = None,
    client_cert: Annotated[str | None, _client_cert_opt] = None,
    client_key: Annotated[str | None, _client_key_opt] = None,
    ca_bundle: Annotated[str | None, _ca_bundle_opt] = None,
):
    """Full flow: TEI -> discovery -> releases -> artifacts."""
    try:
        with _build_client(
            base_url, token, domain, timeout, use_http, port, auth, client_cert, client_key, ca_bundle, tei=tei
        ) as client:
            discoveries = client.discover(tei)
            result = []
            for disc in discoveries:
                pr = client.get_product_release(disc.product_release_uuid)
                components = []
                for comp_ref in pr.components[:max_components]:
                    if comp_ref.release:
                        cr = client.get_component_release(comp_ref.release)
                        components.append(cr.model_dump(mode="json", by_alias=True))
                    else:
                        # Unpinned component — resolve latest release like rearm does
                        comp = client.get_component(comp_ref.uuid)
                        comp_data = comp.model_dump(mode="json", by_alias=True)
                        try:
                            releases = client.get_component_releases(comp_ref.uuid)
                            if releases:
                                latest = releases[0]
                                cr = client.get_component_release(latest.uuid)
                                comp_data["resolvedRelease"] = cr.model_dump(mode="json", by_alias=True)
                                comp_data["resolvedNote"] = "latest release (not pinned)"
                        except TeaError as exc:
                            logger.debug("Could not resolve releases for component %s: %s", comp_ref.uuid, exc)
                        components.append(comp_data)
                truncated = len(pr.components) > max_components
                entry: dict[str, Any] = {
                    "discovery": disc.model_dump(mode="json", by_alias=True),
                    "productRelease": pr.model_dump(mode="json", by_alias=True),
                    "components": components,
                }
                if truncated:
                    entry["truncated"] = True
                    entry["totalComponents"] = len(pr.components)
                    print(
                        f"Warning: truncated {len(pr.components)} components to {max_components} "
                        f"(use --max-components to increase)",
                        file=sys.stderr,
                    )
                result.append(entry)
            _output(result, command="inspect")
    except TeaError as exc:
        _error(str(exc))


def _version_callback(value: bool) -> None:
    """Eager callback for ``--version`` that prints version info and exits."""
    if value:
        from libtea import __version__

        print(f"tea-cli {__version__} (TEA spec {TEA_SPEC_VERSION})")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None, typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version")
    ] = None,
    output_json: Annotated[
        bool, typer.Option("--json", help="Output raw JSON instead of rich-formatted tables")
    ] = False,
    debug: Annotated[bool, typer.Option("--debug", "-d", help="Show debug output (HTTP requests, timing)")] = False,
):
    """TEA (Transparency Exchange API) CLI client."""
    global _json_output  # noqa: PLW0603
    _json_output = output_json
    if debug:
        logging.basicConfig(format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
        logging.getLogger("libtea").setLevel(logging.DEBUG)
