"""CLI for the Transparency Exchange API."""

import json
import sys
from pathlib import Path
from typing import Annotated, Any, NoReturn, Optional

try:
    import typer
except ImportError:
    print("Error: CLI dependencies not installed. Run: pip install libtea[cli]", file=sys.stderr)
    raise SystemExit(1)

from libtea.client import TEA_SPEC_VERSION, TeaClient
from libtea.exceptions import TeaError
from libtea.models import Checksum, ChecksumAlgorithm

app = typer.Typer(help="TEA (Transparency Exchange API) CLI client.", no_args_is_help=True)

# --- Shared options ---

_base_url_opt = typer.Option(envvar="TEA_BASE_URL", help="TEA server base URL")
_token_opt = typer.Option(envvar="TEA_TOKEN", help="Bearer token for authentication")
_domain_opt = typer.Option(help="Discover server from domain's .well-known/tea")
_timeout_opt = typer.Option(help="Request timeout in seconds")
_use_http_opt = typer.Option(help="Use HTTP instead of HTTPS for discovery")
_port_opt = typer.Option(help="Port for well-known resolution")


def _build_client(
    base_url: str | None,
    token: str | None,
    domain: str | None,
    timeout: float,
    use_http: bool,
    port: int | None,
) -> TeaClient:
    """Build a TeaClient from CLI options."""
    if base_url and domain:
        _error("Cannot use both --base-url and --domain")
    if not base_url and not domain:
        _error("Must specify either --base-url or --domain")
    if base_url:
        return TeaClient(base_url=base_url, token=token, timeout=timeout)
    scheme = "http" if use_http else "https"
    return TeaClient.from_well_known(domain, token=token, timeout=timeout, scheme=scheme, port=port)


def _output(data: Any) -> None:
    """Print JSON to stdout."""
    if hasattr(data, "model_dump"):
        data = data.model_dump(mode="json", by_alias=True)
    elif isinstance(data, list):
        data = [item.model_dump(mode="json", by_alias=True) if hasattr(item, "model_dump") else item for item in data]
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
    domain: Annotated[Optional[str], _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[Optional[int], _port_opt] = None,
):
    """Resolve a TEI to product release UUID(s)."""
    try:
        with _build_client(base_url, token, domain, timeout, use_http, port) as client:
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
    domain: Annotated[Optional[str], _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[Optional[int], _port_opt] = None,
):
    """Search for products by identifier."""
    try:
        with _build_client(base_url, token, domain, timeout, use_http, port) as client:
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
    domain: Annotated[Optional[str], _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[Optional[int], _port_opt] = None,
):
    """Search for product releases by identifier."""
    try:
        with _build_client(base_url, token, domain, timeout, use_http, port) as client:
            result = client.search_product_releases(id_type, id_value, page_offset=page_offset, page_size=page_size)
        _output(result)
    except TeaError as exc:
        _error(str(exc))


@app.command("get-product")
def get_product(
    uuid: str,
    base_url: Annotated[Optional[str], _base_url_opt] = None,
    token: Annotated[Optional[str], _token_opt] = None,
    domain: Annotated[Optional[str], _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[Optional[int], _port_opt] = None,
):
    """Get a product by UUID."""
    try:
        with _build_client(base_url, token, domain, timeout, use_http, port) as client:
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
    domain: Annotated[Optional[str], _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[Optional[int], _port_opt] = None,
):
    """Get a product or component release by UUID."""
    try:
        with _build_client(base_url, token, domain, timeout, use_http, port) as client:
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
    domain: Annotated[Optional[str], _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[Optional[int], _port_opt] = None,
):
    """Get a collection (latest or by version)."""
    try:
        with _build_client(base_url, token, domain, timeout, use_http, port) as client:
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
    domain: Annotated[Optional[str], _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[Optional[int], _port_opt] = None,
):
    """Get artifact metadata by UUID."""
    try:
        with _build_client(base_url, token, domain, timeout, use_http, port) as client:
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
    base_url: Annotated[Optional[str], _base_url_opt] = None,
    token: Annotated[Optional[str], _token_opt] = None,
    domain: Annotated[Optional[str], _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[Optional[int], _port_opt] = None,
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
        with _build_client(base_url, token, domain, timeout, use_http, port) as client:
            result = client.download_artifact(url, dest, verify_checksums=checksums)
        print(f"Downloaded to {result}", file=sys.stderr)
    except TeaError as exc:
        _error(str(exc))


@app.command()
def inspect(
    tei: str,
    base_url: Annotated[Optional[str], _base_url_opt] = None,
    token: Annotated[Optional[str], _token_opt] = None,
    domain: Annotated[Optional[str], _domain_opt] = None,
    timeout: Annotated[float, _timeout_opt] = 30.0,
    use_http: Annotated[bool, _use_http_opt] = False,
    port: Annotated[Optional[int], _port_opt] = None,
):
    """Full flow: TEI -> discovery -> releases -> artifacts."""
    try:
        with _build_client(base_url, token, domain, timeout, use_http, port) as client:
            discoveries = client.discover(tei)
            result = []
            for disc in discoveries:
                pr = client.get_product_release(disc.product_release_uuid)
                components = []
                for comp_ref in pr.components:
                    cr = client.get_component_release(comp_ref.uuid)
                    components.append(cr.model_dump(mode="json", by_alias=True))
                result.append(
                    {
                        "productRelease": pr.model_dump(mode="json", by_alias=True),
                        "components": components,
                    }
                )
            _output(result)
    except TeaError as exc:
        _error(str(exc))


def _version_callback(value: bool):
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
