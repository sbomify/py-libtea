"""CLI for the Transparency Exchange API."""

import json
import sys
from pathlib import Path
from typing import Annotated, Any, NoReturn, Optional

import typer
from pydantic import BaseModel

from libtea._http import MtlsConfig
from libtea.client import TEA_SPEC_VERSION, TeaClient
from libtea.exceptions import TeaError
from libtea.models import Checksum, ChecksumAlgorithm

app = typer.Typer(help="TEA (Transparency Exchange API) CLI client.", no_args_is_help=True)

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
    """Parse 'USER:PASSWORD' into a tuple, or return None."""
    if not auth:
        return None
    if ":" not in auth:
        _error("Invalid --auth format. Expected USER:PASSWORD")
    user, password = auth.split(":", 1)
    return (user, password)


def _build_mtls(client_cert: str | None, client_key: str | None, ca_bundle: str | None) -> MtlsConfig | None:
    """Build MtlsConfig from CLI options, or return None."""
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
) -> TeaClient:
    """Build a TeaClient from CLI options."""
    if base_url and domain:
        _error("Cannot use both --base-url and --domain")
    if not base_url and not domain:
        _error("Must specify either --base-url or --domain")
    basic_auth = _parse_basic_auth(auth)
    mtls = _build_mtls(client_cert, client_key, ca_bundle)
    if base_url:
        return TeaClient(base_url=base_url, token=token, basic_auth=basic_auth, timeout=timeout, mtls=mtls)
    scheme = "http" if use_http else "https"
    return TeaClient.from_well_known(
        domain, token=token, basic_auth=basic_auth, timeout=timeout, scheme=scheme, port=port, mtls=mtls
    )


def _output(data: Any) -> None:
    """Print JSON to stdout."""
    if isinstance(data, BaseModel):
        data = data.model_dump(mode="json", by_alias=True)
    elif isinstance(data, list):
        data = [item.model_dump(mode="json", by_alias=True) if isinstance(item, BaseModel) else item for item in data]
    json.dump(data, sys.stdout, indent=2, default=str)
    print()


def _error(message: str) -> NoReturn:
    """Print error to stderr and exit."""
    print(f"Error: {message}", file=sys.stderr)
    raise typer.Exit(1)


# --- Commands ---


@app.command()
def discover(
    tei: str,
    base_url: Annotated[Optional[str], _base_url_opt] = None,
    token: Annotated[Optional[str], _token_opt] = None,
    auth: Annotated[Optional[str], _auth_opt] = None,
    domain: Annotated[Optional[str], _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[Optional[int], _port_opt] = None,
    client_cert: Annotated[Optional[str], _client_cert_opt] = None,
    client_key: Annotated[Optional[str], _client_key_opt] = None,
    ca_bundle: Annotated[Optional[str], _ca_bundle_opt] = None,
):
    """Resolve a TEI to product release UUID(s)."""
    try:
        with _build_client(
            base_url, token, domain, timeout, use_http, port, auth, client_cert, client_key, ca_bundle
        ) as client:
            result = client.discover(tei)
        _output(result)
    except TeaError as exc:
        _error(str(exc))


@app.command("search-products")
def search_products(
    id_type: Annotated[str, typer.Option("--id-type", help="Identifier type (CPE, TEI, PURL)")],
    id_value: Annotated[str, typer.Option("--id-value", help="Identifier value")],
    page_offset: Annotated[int, typer.Option("--page-offset", help="Page offset")] = 0,
    page_size: Annotated[int, typer.Option("--page-size", help="Page size")] = 100,
    base_url: Annotated[Optional[str], _base_url_opt] = None,
    token: Annotated[Optional[str], _token_opt] = None,
    auth: Annotated[Optional[str], _auth_opt] = None,
    domain: Annotated[Optional[str], _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[Optional[int], _port_opt] = None,
    client_cert: Annotated[Optional[str], _client_cert_opt] = None,
    client_key: Annotated[Optional[str], _client_key_opt] = None,
    ca_bundle: Annotated[Optional[str], _ca_bundle_opt] = None,
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
    base_url: Annotated[Optional[str], _base_url_opt] = None,
    token: Annotated[Optional[str], _token_opt] = None,
    auth: Annotated[Optional[str], _auth_opt] = None,
    domain: Annotated[Optional[str], _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[Optional[int], _port_opt] = None,
    client_cert: Annotated[Optional[str], _client_cert_opt] = None,
    client_key: Annotated[Optional[str], _client_key_opt] = None,
    ca_bundle: Annotated[Optional[str], _ca_bundle_opt] = None,
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
    base_url: Annotated[Optional[str], _base_url_opt] = None,
    token: Annotated[Optional[str], _token_opt] = None,
    auth: Annotated[Optional[str], _auth_opt] = None,
    domain: Annotated[Optional[str], _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[Optional[int], _port_opt] = None,
    client_cert: Annotated[Optional[str], _client_cert_opt] = None,
    client_key: Annotated[Optional[str], _client_key_opt] = None,
    ca_bundle: Annotated[Optional[str], _ca_bundle_opt] = None,
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
    base_url: Annotated[Optional[str], _base_url_opt] = None,
    token: Annotated[Optional[str], _token_opt] = None,
    auth: Annotated[Optional[str], _auth_opt] = None,
    domain: Annotated[Optional[str], _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[Optional[int], _port_opt] = None,
    client_cert: Annotated[Optional[str], _client_cert_opt] = None,
    client_key: Annotated[Optional[str], _client_key_opt] = None,
    ca_bundle: Annotated[Optional[str], _ca_bundle_opt] = None,
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
    version: Annotated[Optional[int], typer.Option("--version", help="Collection version (default: latest)")] = None,
    component: Annotated[
        bool, typer.Option("--component", help="Get from component release instead of product release")
    ] = False,
    base_url: Annotated[Optional[str], _base_url_opt] = None,
    token: Annotated[Optional[str], _token_opt] = None,
    auth: Annotated[Optional[str], _auth_opt] = None,
    domain: Annotated[Optional[str], _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[Optional[int], _port_opt] = None,
    client_cert: Annotated[Optional[str], _client_cert_opt] = None,
    client_key: Annotated[Optional[str], _client_key_opt] = None,
    ca_bundle: Annotated[Optional[str], _ca_bundle_opt] = None,
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


@app.command("get-artifact")
def get_artifact(
    uuid: str,
    base_url: Annotated[Optional[str], _base_url_opt] = None,
    token: Annotated[Optional[str], _token_opt] = None,
    auth: Annotated[Optional[str], _auth_opt] = None,
    domain: Annotated[Optional[str], _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[Optional[int], _port_opt] = None,
    client_cert: Annotated[Optional[str], _client_cert_opt] = None,
    client_key: Annotated[Optional[str], _client_key_opt] = None,
    ca_bundle: Annotated[Optional[str], _ca_bundle_opt] = None,
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
    checksum: Annotated[
        Optional[list[str]], typer.Option("--checksum", help="Checksum as ALG:VALUE (repeatable)")
    ] = None,
    max_download_bytes: Annotated[
        Optional[int], typer.Option("--max-download-bytes", help="Maximum download size in bytes")
    ] = None,
    base_url: Annotated[Optional[str], _base_url_opt] = None,
    token: Annotated[Optional[str], _token_opt] = None,
    auth: Annotated[Optional[str], _auth_opt] = None,
    domain: Annotated[Optional[str], _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[Optional[int], _port_opt] = None,
    client_cert: Annotated[Optional[str], _client_cert_opt] = None,
    client_key: Annotated[Optional[str], _client_key_opt] = None,
    ca_bundle: Annotated[Optional[str], _ca_bundle_opt] = None,
):
    """Download an artifact file with optional checksum verification."""
    checksums = None
    if checksum:
        checksums = []
        for cs in checksum:
            if ":" not in cs:
                _error(f"Invalid checksum format: {cs!r}. Expected ALG:VALUE (e.g. SHA-256:abcdef...)")
            alg, value = cs.split(":", 1)
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
    base_url: Annotated[Optional[str], _base_url_opt] = None,
    token: Annotated[Optional[str], _token_opt] = None,
    auth: Annotated[Optional[str], _auth_opt] = None,
    domain: Annotated[Optional[str], _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[Optional[int], _port_opt] = None,
    client_cert: Annotated[Optional[str], _client_cert_opt] = None,
    client_key: Annotated[Optional[str], _client_key_opt] = None,
    ca_bundle: Annotated[Optional[str], _ca_bundle_opt] = None,
):
    """Full flow: TEI -> discovery -> releases -> artifacts."""
    try:
        with _build_client(
            base_url, token, domain, timeout, use_http, port, auth, client_cert, client_key, ca_bundle
        ) as client:
            discoveries = client.discover(tei)
            result = []
            for disc in discoveries:
                pr = client.get_product_release(disc.product_release_uuid)
                components = []
                for comp_ref in pr.components[:max_components]:
                    cr = client.get_component_release(comp_ref.uuid)
                    components.append(cr.model_dump(mode="json", by_alias=True))
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
            _output(result)
    except TeaError as exc:
        _error(str(exc))


def _version_callback(value: bool) -> None:
    if value:
        from libtea import __version__

        print(f"tea-cli {__version__} (TEA spec {TEA_SPEC_VERSION})")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        Optional[bool], typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version")
    ] = None,
):
    """TEA (Transparency Exchange API) CLI client."""
