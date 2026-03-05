"""CLI for the Transparency Exchange API.

Provides the ``tea-cli`` command backed by click. Each subcommand maps
to a :class:`~libtea.client.TeaClient` method and outputs rich-formatted
tables and panels by default (or JSON when ``--json`` is specified).
All commands accept ``--base-url`` / ``--domain`` / ``--tei`` for server selection,
and ``--token`` / ``--auth`` for authentication.
"""

import functools
import json
import logging
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import urlparse

import click
from pydantic import BaseModel

from libtea.client import TEA_SPEC_VERSION, TeaClient
from libtea.discovery import parse_tei
from libtea.exceptions import TeaAuthenticationError, TeaChecksumError, TeaConnectionError, TeaDiscoveryError, TeaError
from libtea.models import (
    Artifact,
    ArtifactFormat,
    Checksum,
    ChecksumAlgorithm,
    ComponentReleaseWithCollection,
    ProductRelease,
    normalize_algorithm_name,
)

logger = logging.getLogger("libtea")


def _configure_logging(*, verbose: bool, debug: bool) -> None:
    """Set up logging based on --verbose / --debug flags."""
    if debug:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
        logging.getLogger("libtea").setLevel(logging.DEBUG)
        # Ensure full firehose even if --verbose was applied first (e.g. group-level -v, subcommand -d)
        logging.getLogger("urllib3").setLevel(logging.DEBUG)
        logging.getLogger("requests").setLevel(logging.DEBUG)
    elif verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
        logging.getLogger("libtea").setLevel(logging.DEBUG)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("requests").setLevel(logging.WARNING)


# --- Shared options decorator ---


def shared_options(fn):  # type: ignore[no-untyped-def]
    """Apply connection options and global flags to a command function.

    Global flags (``--json``, ``--verbose``, ``--debug``, ``--allow-private-ips``)
    are applied per-command so they work in any position (before or after
    the subcommand name).
    """

    @click.option(
        "-o",
        "--output",
        "output_file",
        type=click.Path(dir_okay=False, resolve_path=True),
        default=None,
        help="Write output to file instead of stdout",
    )
    @click.option("--no-color", is_flag=True, help="Disable colored output")
    @click.option("--no-input", is_flag=True, help="Never prompt for input (for scripts and CI)")
    @click.option("--tei", "tei_urn", default=None, help="TEI URN for domain auto-discovery")
    @click.option("--port", type=int, default=None, help="Port for well-known resolution")
    @click.option("--use-http", is_flag=True, help="Use HTTP instead of HTTPS for discovery")
    @click.option("--timeout", type=click.FloatRange(min=0.1), default=30.0, help="Request timeout in seconds")
    @click.option("--domain", default=None, help="Discover server from domain's .well-known/tea")
    @click.option(
        "--auth", envvar="TEA_AUTH", default=None, help="Basic auth as USER:PASSWORD (prefer TEA_AUTH env var)"
    )
    @click.option(
        "--token",
        envvar="TEA_TOKEN",
        default=None,
        help="Bearer token (prefer TEA_TOKEN env var to avoid shell history exposure)",
    )
    @click.option("--base-url", envvar="TEA_BASE_URL", default=None, help="TEA server base URL")
    @click.option(
        "--allow-private-ips",
        is_flag=True,
        help="Allow artifact downloads from private/internal IPs (relaxes SSRF checks for downloads only)",
    )
    @click.option("--json", "output_json", is_flag=True, help="Output raw JSON instead of rich-formatted tables")
    @click.option("-v", "--verbose", is_flag=True, help="Show verbose output (libtea debug logs)")
    @click.option("-d", "--debug", is_flag=True, help="Show debug output (HTTP requests, timing)")
    @functools.wraps(fn)
    @click.pass_context
    def wrapper(
        ctx: click.Context,
        /,
        *args: Any,
        output_json: bool = False,
        verbose: bool = False,
        debug: bool = False,
        **kwargs: Any,
    ) -> Any:
        ctx.ensure_object(dict)
        if output_json:
            ctx.obj["json"] = True
        no_input = kwargs.pop("no_input", False)
        if no_input:
            ctx.obj["no_input"] = True
        no_color = kwargs.pop("no_color", False)
        if no_color:
            ctx.obj["no_color"] = True
        output_file = kwargs.pop("output_file", None)
        if output_file:
            ctx.obj["output_file"] = output_file
        # Merge group-level flags with subcommand-level flags
        if ctx.obj.get("allow_private_ips"):
            kwargs["allow_private_ips"] = True
        verbose = verbose or ctx.obj.get("verbose", False)
        debug = debug or ctx.obj.get("debug", False)
        _configure_logging(verbose=verbose, debug=debug)
        # Store --tei in context; commands that need it read from kwargs (positional) or ctx.obj
        tei_urn = kwargs.pop("tei_urn", None)
        if tei_urn:
            ctx.obj["tei_urn"] = tei_urn
        return ctx.invoke(fn, *args, **kwargs)

    return wrapper


# --- Helper functions ---


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
    if not user:
        _error("Invalid --auth format: username must not be empty")
    if not password:
        logger.debug("Basic auth password is empty for user %r", user)
    return (user, password)


def _domain_from_tei(tei: str | None) -> str | None:
    """Extract the domain component from a TEI URN for auto-discovery.

    Returns ``None`` if ``tei`` is falsy or not a valid TEI URN.
    """
    if not tei:
        return None
    try:
        _, domain, _ = parse_tei(tei)
        return domain
    except TeaDiscoveryError as exc:
        logger.debug("Could not extract domain from TEI %r: %s", tei, exc)
        return None


def _build_client(
    base_url: str | None,
    token: str | None,
    domain: str | None,
    timeout: float,
    use_http: bool,
    port: int | None,
    auth: str | None = None,
    tei: str | None = None,
    allow_private_ips: bool = False,
) -> TeaClient:
    """Build a TeaClient from CLI options.

    When neither --base-url nor --domain is provided, the domain is extracted
    from the TEI URN (if given) and used for .well-known/tea discovery.
    """
    # Fall back to --tei from shared_options (stored in ctx.obj) when tei is not provided directly
    if not tei:
        ctx = click.get_current_context(silent=True)
        if ctx and ctx.obj:
            tei = ctx.obj.get("tei_urn")
    if base_url and domain:
        _error("Cannot use both --base-url and --domain")
    if not base_url and not domain:
        domain = _domain_from_tei(tei)
    if not base_url and not domain:
        _error("Must specify either --base-url or --domain (or provide a TEI to auto-discover)")
    basic_auth = _parse_basic_auth(auth)
    try:
        if base_url:
            return TeaClient(
                base_url=base_url,
                token=token,
                basic_auth=basic_auth,
                timeout=timeout,
                allow_private_ips=allow_private_ips,
            )
        if domain is None:  # pragma: no cover — unreachable; _error() above guarantees non-None
            _error("Internal error: domain is unexpectedly None")
        scheme = "http" if use_http else "https"
        return TeaClient.from_well_known(
            domain,
            token=token,
            basic_auth=basic_auth,
            timeout=timeout,
            scheme=scheme,
            port=port,
            allow_private_ips=allow_private_ips,
        )
    except ValueError as exc:
        _error(str(exc))


@contextmanager
def _client_session(
    base_url: str | None,
    token: str | None,
    domain: str | None,
    timeout: float,
    use_http: bool,
    port: int | None,
    auth: str | None = None,
    tei: str | None = None,
    allow_private_ips: bool = False,
) -> Iterator[TeaClient]:
    """Build a TeaClient and handle TeaError, yielding the client for use."""
    try:
        with _build_client(
            base_url, token, domain, timeout, use_http, port, auth, tei=tei, allow_private_ips=allow_private_ips
        ) as client:
            yield client
    except TeaError as exc:
        _error(str(exc))


def _is_json_output() -> bool:
    """Check if JSON output mode is active via Click context."""
    ctx = click.get_current_context(silent=True)
    return bool(ctx and ctx.obj and ctx.obj.get("json"))


def _get_output_options() -> tuple[str | None, bool]:
    """Return (output_file, no_color) from the current Click context."""
    ctx = click.get_current_context(silent=True)
    if ctx and ctx.obj:
        return ctx.obj.get("output_file"), ctx.obj.get("no_color", False)
    return None, False


def _output(data: Any, *, command: str | None = None) -> None:
    """Output ``data`` as JSON (when ``--json``) or rich-formatted tables/panels.

    In JSON mode, Pydantic models are serialized via ``model_dump(mode="json",
    by_alias=True)`` to produce camelCase keys matching the TEA API wire format.
    """
    output_file, no_color = _get_output_options()
    if _is_json_output():
        if isinstance(data, BaseModel):
            data = data.model_dump(mode="json", by_alias=True)
        elif isinstance(data, list):
            data = [
                item.model_dump(mode="json", by_alias=True) if isinstance(item, BaseModel) else item for item in data
            ]
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
                f.write("\n")
        else:
            json.dump(data, sys.stdout, indent=2, default=str)
            print()
    else:
        try:
            from libtea._cli_fmt import format_output
        except ImportError:
            _error("Rich output requires the 'rich' package. Install with: pip install 'libtea[cli]'")
        from rich.console import Console

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                console = Console(file=f, no_color=no_color)
                format_output(data, command=command, console=console)
        elif no_color:
            console = Console(no_color=True)
            format_output(data, command=command, console=console)
        else:
            format_output(data, command=command)


def _error(message: str) -> NoReturn:
    """Print an error message to stderr and exit with code 1."""
    try:
        print(f"Error: {message}", file=sys.stderr)
    except OSError:
        pass
    raise SystemExit(1)


# --- Main group ---


@click.group(
    help="""TEA (Transparency Exchange API) CLI client.

\b
Quick start:
  tea-cli inspect 'urn:tei:purl:example.com:pkg:pypi/requests@2.31.0'
  tea-cli download 'urn:tei:purl:example.com:pkg:pypi/requests@2.31.0' ./sboms/

\b
Environment variables:
  TEA_BASE_URL   TEA server base URL
  TEA_TOKEN      Bearer token for authentication
  TEA_AUTH       Basic auth as USER:PASSWORD

\b
Exit codes:
  0   Success
  1   Error (connection, auth, not found, etc.)
  2   Usage error (missing arguments)

\b
Use 'tea-cli COMMAND --help' for more information on a command.""",
)
@click.version_option(
    package_name="libtea",
    prog_name="tea-cli",
    message=f"%(prog)s %(version)s (TEA spec {TEA_SPEC_VERSION})",
)
@click.option("--json", "output_json", is_flag=True, hidden=True)
@click.option("-v", "--verbose", is_flag=True, hidden=True)
@click.option("-d", "--debug", is_flag=True, hidden=True)
@click.option("--allow-private-ips", is_flag=True, hidden=True)
@click.pass_context
def app(ctx: click.Context, output_json: bool, verbose: bool, debug: bool, allow_private_ips: bool) -> None:
    """TEA (Transparency Exchange API) CLI client."""
    ctx.ensure_object(dict)
    if output_json:
        ctx.obj["json"] = True
    if allow_private_ips:
        ctx.obj["allow_private_ips"] = True
    if verbose:
        ctx.obj["verbose"] = True
    if debug:
        ctx.obj["debug"] = True
    _configure_logging(verbose=verbose, debug=debug)


# --- Commands ---


@app.command()
@click.argument("tei")
@click.option("--quiet", "-q", is_flag=True, help="Output only UUIDs, one per line")
@shared_options
def discover(
    tei: str,
    quiet: bool,
    base_url: str | None,
    token: str | None,
    auth: str | None,
    domain: str | None,
    timeout: float,
    use_http: bool,
    port: int | None,
    allow_private_ips: bool,
) -> None:
    """Resolve a TEI to product release UUID(s).

    \b
    Examples:
      tea-cli discover 'urn:tei:purl:example.com:pkg:pypi/requests@2.31.0' --domain example.com
      tea-cli discover 'urn:tei:purl:example.com:pkg:pypi/requests@2.31.0' --quiet
    """
    with _client_session(
        base_url, token, domain, timeout, use_http, port, auth, tei=tei, allow_private_ips=allow_private_ips
    ) as client:
        result = client.discover(tei)
    if quiet:
        for d in result:
            print(d.product_release_uuid)
    else:
        _output(result, command="discover")


@app.command("search-products")
@click.option("--id-type", required=True, help="Identifier type (CPE, TEI, PURL)")
@click.option("--id-value", required=True, help="Identifier value")
@click.option("--page-offset", type=int, default=0, help="Page offset")
@click.option("--page-size", type=int, default=100, help="Page size")
@shared_options
def search_products(
    id_type: str,
    id_value: str,
    page_offset: int,
    page_size: int,
    base_url: str | None,
    token: str | None,
    auth: str | None,
    domain: str | None,
    timeout: float,
    use_http: bool,
    port: int | None,
    allow_private_ips: bool,
    tei: str | None = None,
) -> None:
    """Search for products by identifier.

    \b
    Examples:
      tea-cli search-products --id-type PURL --id-value 'pkg:pypi/requests' --domain example.com
      tea-cli search-products --id-type CPE --id-value 'cpe:2.3:a:*:requests:*' --base-url https://tea.example.com
    """
    with _client_session(
        base_url, token, domain, timeout, use_http, port, auth, tei=tei, allow_private_ips=allow_private_ips
    ) as client:
        result = client.search_products(id_type, id_value, page_offset=page_offset, page_size=page_size)
    _output(result)


@app.command("search-releases")
@click.option("--id-type", required=True, help="Identifier type (CPE, TEI, PURL)")
@click.option("--id-value", required=True, help="Identifier value")
@click.option("--page-offset", type=int, default=0, help="Page offset")
@click.option("--page-size", type=int, default=100, help="Page size")
@shared_options
def search_releases(
    id_type: str,
    id_value: str,
    page_offset: int,
    page_size: int,
    base_url: str | None,
    token: str | None,
    auth: str | None,
    domain: str | None,
    timeout: float,
    use_http: bool,
    port: int | None,
    allow_private_ips: bool,
    tei: str | None = None,
) -> None:
    """Search for product releases by identifier.

    \b
    Examples:
      tea-cli search-releases --id-type PURL --id-value 'pkg:pypi/requests' --domain example.com
      tea-cli search-releases --id-type TEI --id-value 'urn:tei:purl:example.com:pkg:pypi/requests@2.31.0' --json
    """
    with _client_session(
        base_url, token, domain, timeout, use_http, port, auth, tei=tei, allow_private_ips=allow_private_ips
    ) as client:
        result = client.search_product_releases(id_type, id_value, page_offset=page_offset, page_size=page_size)
    _output(result)


@app.command("get-product")
@click.argument("uuid")
@shared_options
def get_product(
    uuid: str,
    base_url: str | None,
    token: str | None,
    auth: str | None,
    domain: str | None,
    timeout: float,
    use_http: bool,
    port: int | None,
    allow_private_ips: bool,
    tei: str | None = None,
) -> None:
    """Get a product by UUID.

    \b
    Examples:
      tea-cli get-product 550e8400-e29b-41d4-a716-446655440000 --base-url https://tea.example.com
      tea-cli get-product 550e8400-e29b-41d4-a716-446655440000 --json
    """
    with _client_session(
        base_url, token, domain, timeout, use_http, port, auth, tei=tei, allow_private_ips=allow_private_ips
    ) as client:
        result = client.get_product(uuid)
    _output(result)


@app.command("get-release")
@click.argument("uuid")
@click.option("--component", is_flag=True, help="Get a component release instead of product release")
@shared_options
def get_release(
    uuid: str,
    component: bool,
    base_url: str | None,
    token: str | None,
    auth: str | None,
    domain: str | None,
    timeout: float,
    use_http: bool,
    port: int | None,
    allow_private_ips: bool,
    tei: str | None = None,
) -> None:
    """Get a product or component release by UUID.

    \b
    Examples:
      tea-cli get-release 550e8400-e29b-41d4-a716-446655440000 --base-url https://tea.example.com
      tea-cli get-release 550e8400-e29b-41d4-a716-446655440000 --component --json
    """
    with _client_session(
        base_url, token, domain, timeout, use_http, port, auth, tei=tei, allow_private_ips=allow_private_ips
    ) as client:
        result: ProductRelease | ComponentReleaseWithCollection
        if component:
            result = client.get_component_release(uuid)
        else:
            result = client.get_product_release(uuid)
    _output(result)


@app.command("get-collection")
@click.argument("uuid")
@click.option("--version", type=int, default=None, help="Collection version (default: latest)")
@click.option("--component", is_flag=True, help="Get from component release instead of product release")
@shared_options
def get_collection(
    uuid: str,
    version: int | None,
    component: bool,
    base_url: str | None,
    token: str | None,
    auth: str | None,
    domain: str | None,
    timeout: float,
    use_http: bool,
    port: int | None,
    allow_private_ips: bool,
    tei: str | None = None,
) -> None:
    """Get a collection (latest or by version).

    \b
    Examples:
      tea-cli get-collection 550e8400-e29b-41d4-a716-446655440000 --base-url https://tea.example.com
      tea-cli get-collection 550e8400-e29b-41d4-a716-446655440000 --version 3 --component
    """
    with _client_session(
        base_url, token, domain, timeout, use_http, port, auth, tei=tei, allow_private_ips=allow_private_ips
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


@app.command("get-product-releases")
@click.argument("uuid")
@click.option("--page-offset", type=int, default=0, help="Page offset")
@click.option("--page-size", type=int, default=100, help="Page size")
@shared_options
def get_product_releases(
    uuid: str,
    page_offset: int,
    page_size: int,
    base_url: str | None,
    token: str | None,
    auth: str | None,
    domain: str | None,
    timeout: float,
    use_http: bool,
    port: int | None,
    allow_private_ips: bool,
    tei: str | None = None,
) -> None:
    """List releases for a product UUID.

    \b
    Examples:
      tea-cli get-product-releases 550e8400-e29b-41d4-a716-446655440000 --base-url https://tea.example.com
      tea-cli get-product-releases 550e8400-e29b-41d4-a716-446655440000 --page-size 10 --json
    """
    with _client_session(
        base_url, token, domain, timeout, use_http, port, auth, tei=tei, allow_private_ips=allow_private_ips
    ) as client:
        result = client.get_product_releases(uuid, page_offset=page_offset, page_size=page_size)
    _output(result)


@app.command("get-component")
@click.argument("uuid")
@shared_options
def get_component(
    uuid: str,
    base_url: str | None,
    token: str | None,
    auth: str | None,
    domain: str | None,
    timeout: float,
    use_http: bool,
    port: int | None,
    allow_private_ips: bool,
    tei: str | None = None,
) -> None:
    """Get a component by UUID.

    \b
    Examples:
      tea-cli get-component 550e8400-e29b-41d4-a716-446655440000 --base-url https://tea.example.com
      tea-cli get-component 550e8400-e29b-41d4-a716-446655440000 --json
    """
    with _client_session(
        base_url, token, domain, timeout, use_http, port, auth, tei=tei, allow_private_ips=allow_private_ips
    ) as client:
        result = client.get_component(uuid)
    _output(result)


@app.command("get-component-releases")
@click.argument("uuid")
@shared_options
def get_component_releases(
    uuid: str,
    base_url: str | None,
    token: str | None,
    auth: str | None,
    domain: str | None,
    timeout: float,
    use_http: bool,
    port: int | None,
    allow_private_ips: bool,
    tei: str | None = None,
) -> None:
    """List releases for a component UUID.

    \b
    Examples:
      tea-cli get-component-releases 550e8400-e29b-41d4-a716-446655440000 --base-url https://tea.example.com
      tea-cli get-component-releases 550e8400-e29b-41d4-a716-446655440000 --json
    """
    with _client_session(
        base_url, token, domain, timeout, use_http, port, auth, tei=tei, allow_private_ips=allow_private_ips
    ) as client:
        result = client.get_component_releases(uuid)
    _output(result, command="releases")


@app.command("list-collections")
@click.argument("uuid")
@click.option("--component", is_flag=True, help="List collections for a component release instead of product release")
@shared_options
def list_collections(
    uuid: str,
    component: bool,
    base_url: str | None,
    token: str | None,
    auth: str | None,
    domain: str | None,
    timeout: float,
    use_http: bool,
    port: int | None,
    allow_private_ips: bool,
    tei: str | None = None,
) -> None:
    """List all collection versions for a release UUID.

    \b
    Examples:
      tea-cli list-collections 550e8400-e29b-41d4-a716-446655440000 --base-url https://tea.example.com
      tea-cli list-collections 550e8400-e29b-41d4-a716-446655440000 --component --json
    """
    with _client_session(
        base_url, token, domain, timeout, use_http, port, auth, tei=tei, allow_private_ips=allow_private_ips
    ) as client:
        if component:
            result = client.get_component_release_collections(uuid)
        else:
            result = client.get_product_release_collections(uuid)
    _output(result, command="collections")


@app.command("get-cle")
@click.argument("uuid")
@click.option(
    "--entity",
    type=click.Choice(["product", "product-release", "component", "component-release"]),
    default="product-release",
    help="Entity type",
)
@shared_options
def get_cle(
    uuid: str,
    entity: str,
    base_url: str | None,
    token: str | None,
    auth: str | None,
    domain: str | None,
    timeout: float,
    use_http: bool,
    port: int | None,
    allow_private_ips: bool,
    tei: str | None = None,
) -> None:
    """Get Common Lifecycle Enumeration (CLE) for an entity.

    \b
    Examples:
      tea-cli get-cle 550e8400-e29b-41d4-a716-446655440000 --base-url https://tea.example.com
      tea-cli get-cle 550e8400-e29b-41d4-a716-446655440000 --entity component-release --json
    """
    entity_methods = {
        "product": "get_product_cle",
        "product-release": "get_product_release_cle",
        "component": "get_component_cle",
        "component-release": "get_component_release_cle",
    }
    with _client_session(
        base_url, token, domain, timeout, use_http, port, auth, tei=tei, allow_private_ips=allow_private_ips
    ) as client:
        result = getattr(client, entity_methods[entity])(uuid)
    _output(result)


@app.command("get-artifact")
@click.argument("uuid")
@shared_options
def get_artifact(
    uuid: str,
    base_url: str | None,
    token: str | None,
    auth: str | None,
    domain: str | None,
    timeout: float,
    use_http: bool,
    port: int | None,
    allow_private_ips: bool,
    tei: str | None = None,
) -> None:
    """Get artifact metadata by UUID.

    \b
    Examples:
      tea-cli get-artifact 550e8400-e29b-41d4-a716-446655440000 --base-url https://tea.example.com
      tea-cli get-artifact 550e8400-e29b-41d4-a716-446655440000 --json
    """
    with _client_session(
        base_url, token, domain, timeout, use_http, port, auth, tei=tei, allow_private_ips=allow_private_ips
    ) as client:
        result = client.get_artifact(uuid)
    _output(result)


_MEDIA_TYPE_EXTENSIONS: dict[str, str] = {
    "application/json": ".json",
    "application/xml": ".xml",
    "text/xml": ".xml",
    "application/spdx+json": ".spdx.json",
    "application/vnd.cyclonedx+json": ".cdx.json",
    "application/vnd.cyclonedx+xml": ".cdx.xml",
}


def _ext_from_media_type(media_type: str | None) -> str:
    """Map a media type to a file extension, or empty string if unknown."""
    if media_type:
        ext = _MEDIA_TYPE_EXTENSIONS.get(media_type)
        if ext is None:
            logger.debug("No file extension mapping for media type: %s", media_type)
            return ""
        return ext
    return ""


def _sanitize_filename(name: str) -> str:
    """Strip path separators and traversal from a filename to prevent directory escape."""
    # Take only the final component, stripping any directory traversal
    name = Path(name).name
    if not name or name in (".", ".."):
        return ""
    return name


def _artifact_filename(fmt: ArtifactFormat, artifact: Artifact, index: int) -> str:
    """Derive a filename for a downloaded artifact format."""
    if fmt.url:
        basename = Path(urlparse(fmt.url).path).name
        # Only use URL basename if it looks like a real filename (has an extension).
        # Skips generic path segments like "download" or "latest".
        if basename and "." in basename:
            return _sanitize_filename(basename) or f"artifact-{index}"
    name = artifact.name or f"artifact-{index}"
    ext = _ext_from_media_type(fmt.media_type)
    return _sanitize_filename(f"{name}{ext}") or f"artifact-{index}"


def _deduplicate_filename(filename: str, seen: set[str]) -> str:
    """Append a numeric suffix if filename already exists in seen set."""
    if filename not in seen:
        seen.add(filename)
        return filename
    # Split on last dot so multi-dot stems (e.g. report.v1.json) keep internal dots
    if "." in filename:
        base, _, ext = filename.rpartition(".")
    else:
        base, ext = filename, ""
    counter = 1
    while True:
        candidate = f"{base}-{counter}.{ext}" if ext else f"{base}-{counter}"
        if candidate not in seen:
            seen.add(candidate)
            return candidate
        counter += 1


def _download_from_tei(
    client: TeaClient,
    tei: str,
    dest_dir: Path,
    max_download_bytes: int | None,
    *,
    quiet: bool = False,
    dry_run: bool = False,
) -> None:
    """Discover a TEI and download all artifacts into dest_dir."""
    discoveries = client.discover(tei)
    if not discoveries:
        _error(f"No results found for TEI: {tei}")
    if not dry_run:
        dest_dir.mkdir(parents=True, exist_ok=True)
    downloaded = 0
    attempted = 0
    seen_filenames: set[str] = set()
    for disc in discoveries:
        collection = client.get_product_release_collection_latest(disc.product_release_uuid)
        for art_idx, artifact in enumerate(collection.artifacts):
            for fmt in artifact.formats:
                if not fmt.url:
                    continue
                filename = _artifact_filename(fmt, artifact, art_idx)
                filename = _deduplicate_filename(filename, seen_filenames)
                dest_path = dest_dir / filename
                checksums = [cs for cs in fmt.checksums if cs.algorithm_type and cs.algorithm_value]
                attempted += 1
                if dry_run:
                    if not quiet:
                        print(f"Would download: {filename} → {dest_path}", file=sys.stderr)
                    downloaded += 1
                    continue
                try:
                    client.download_artifact(
                        fmt.url,
                        dest_path,
                        verify_checksums=checksums or None,
                        max_download_bytes=max_download_bytes,
                    )
                    if not quiet:
                        checksum_note = " (checksum OK)" if checksums else ""
                        print(f"Downloaded {filename}{checksum_note}", file=sys.stderr)
                    downloaded += 1
                except TeaChecksumError as exc:
                    print(f"Checksum FAILED for {filename}: {exc}", file=sys.stderr)
                except (TeaAuthenticationError, TeaConnectionError) as exc:
                    _error(str(exc))
                except TeaError as exc:
                    print(f"Warning: failed to download {filename}: {exc}", file=sys.stderr)
                except OSError as exc:
                    print(f"Warning: I/O error downloading {filename}: {exc}", file=sys.stderr)
    if downloaded == 0:
        if attempted == 0:
            _error("No downloadable artifact URLs found in the collection(s)")
        else:
            _error(f"All {attempted} artifact download(s) failed")


@app.command()
@click.argument("source")
@click.argument("dest", type=click.Path(), required=False, default=None)
@click.option("--checksum", multiple=True, help="Checksum as ALG:VALUE (repeatable, URL mode only)")
@click.option("--max-download-bytes", type=click.IntRange(min=1), default=None, help="Maximum download size in bytes")
@click.option("-y", "--yes", is_flag=True, help="Skip confirmation prompt for TEI download into current directory")
@click.option("-n", "--dry-run", is_flag=True, help="Show what would be downloaded without downloading (TEI mode only)")
@click.option("-q", "--quiet", is_flag=True, help="Suppress progress output (errors still shown)")
@shared_options
def download(
    source: str,
    dest: str | None,
    checksum: tuple[str, ...],
    max_download_bytes: int | None,
    yes: bool,
    dry_run: bool,
    quiet: bool,
    base_url: str | None,
    token: str | None,
    auth: str | None,
    domain: str | None,
    timeout: float,
    use_http: bool,
    port: int | None,
    allow_private_ips: bool,
    tei: str | None = None,
) -> None:
    """Fetch artifact(s) from a URL or TEI URN.

    SOURCE is a direct artifact URL or a TEI URN (urn:tei:...).

    \b
    URL mode:   download <url> <destination-file>
    TEI mode:   download <tei> [destination-directory]

    In TEI mode, if DEST is omitted you will be prompted before downloading
    into the current directory (use -y to skip the prompt).

    \b
    Examples:
      tea-cli download 'urn:tei:purl:example.com:pkg:pypi/requests@2.31.0' ./sboms/
      tea-cli download https://tea.example.com/artifacts/abc/download output.json --checksum SHA-256:abcdef...
    """
    if source.startswith("urn:tei:"):
        if checksum:
            _error("--checksum is not supported in TEI mode (checksums come from server metadata)")
        if dest is None:
            cwd = Path.cwd()
            ctx = click.get_current_context()
            no_input = ctx.obj.get("no_input", False) if ctx.obj else False
            if not yes and not no_input and not dry_run:
                click.confirm(f"Download artifacts into current directory ({cwd})?", abort=True)
            dest = "."
        try:
            with _client_session(
                base_url, token, domain, timeout, use_http, port, auth, tei=source, allow_private_ips=allow_private_ips
            ) as client:
                _download_from_tei(client, source, Path(dest), max_download_bytes, quiet=quiet, dry_run=dry_run)
        except OSError as exc:
            _error(f"I/O error: {exc}")
        return

    # URL mode: existing direct download behavior
    if dry_run:
        _error("--dry-run is only supported in TEI mode (urn:tei:... source)")
    if dest is None:
        _error("DEST is required when downloading from a URL")
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
        with _client_session(
            base_url, token, domain, timeout, use_http, port, auth, tei=tei, allow_private_ips=allow_private_ips
        ) as client:
            result = client.download_artifact(
                source, Path(dest), verify_checksums=checksums, max_download_bytes=max_download_bytes
            )
        if not quiet:
            print(f"Downloaded to {result}", file=sys.stderr)
    except OSError as exc:
        _error(f"I/O error: {exc}")


@app.command()
@click.argument("tei")
@click.option(
    "--max-components", type=click.IntRange(min=1), default=50, help="Maximum number of components to fetch per release"
)
@shared_options
def inspect(
    tei: str,
    max_components: int,
    base_url: str | None,
    token: str | None,
    auth: str | None,
    domain: str | None,
    timeout: float,
    use_http: bool,
    port: int | None,
    allow_private_ips: bool,
) -> None:
    """Full flow: TEI -> discovery -> releases -> artifacts.

    \b
    Examples:
      tea-cli inspect 'urn:tei:purl:example.com:pkg:pypi/requests@2.31.0' --domain example.com
      tea-cli inspect 'urn:tei:purl:example.com:pkg:pypi/requests@2.31.0' --json
    """
    with _client_session(
        base_url, token, domain, timeout, use_http, port, auth, tei=tei, allow_private_ips=allow_private_ips
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
                        print(
                            f"Warning: could not resolve releases for component {comp_ref.uuid}: {exc}",
                            file=sys.stderr,
                        )
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


@app.command()
@click.option("--base-url", required=True, envvar="TEA_BASE_URL", help="TEA server base URL")
@click.option("--tei", default=None, help="TEI for discovery-driven testing")
@click.option("--product-uuid", default=None, help="Product UUID for direct testing")
@click.option("--release-uuid", default=None, help="Product release UUID")
@click.option("--component-uuid", default=None, help="Component UUID")
@click.option("--component-release-uuid", default=None, help="Component release UUID")
@click.option("--artifact-uuid", default=None, help="Artifact UUID")
@click.option("--timeout", type=click.FloatRange(min=0.1), default=30.0, help="Request timeout in seconds")
@click.option("--token", envvar="TEA_TOKEN", default=None, help="Bearer token")
@click.option("--auth", envvar="TEA_AUTH", default=None, help="Basic auth as USER:PASSWORD")
@click.option("--allow-private-ips", is_flag=True, help="Allow private IPs")
@click.option("--json", "output_json", is_flag=True, help="Output results as JSON")
@click.option("-v", "--verbose", is_flag=True, help="Show failure details and increase logging verbosity")
@click.option("-d", "--debug", is_flag=True, help="Show debug output")
@click.pass_context
def conformance(
    ctx: click.Context,
    base_url: str,
    tei: str | None,
    product_uuid: str | None,
    release_uuid: str | None,
    component_uuid: str | None,
    component_release_uuid: str | None,
    artifact_uuid: str | None,
    timeout: float,
    token: str | None,
    auth: str | None,
    allow_private_ips: bool,
    output_json: bool,
    verbose: bool,
    debug: bool,
) -> None:
    """Run TEA conformance checks against a server.

    \b
    Examples:
      tea-cli conformance --base-url https://tea.example.com --tei 'urn:tei:purl:example.com:pkg:pypi/requests@2.31.0'
      tea-cli conformance --base-url https://tea.example.com --verbose
    """
    ctx.ensure_object(dict)
    if output_json:
        ctx.obj["json"] = True
    verbose = verbose or ctx.obj.get("verbose", False)
    debug = debug or ctx.obj.get("debug", False)
    _configure_logging(verbose=verbose, debug=debug)
    basic_auth = _parse_basic_auth(auth)

    from libtea.conformance import run_conformance

    try:
        result = run_conformance(
            base_url,
            tei=tei,
            product_uuid=product_uuid,
            product_release_uuid=release_uuid,
            component_uuid=component_uuid,
            component_release_uuid=component_release_uuid,
            artifact_uuid=artifact_uuid,
            token=token,
            basic_auth=basic_auth,
            timeout=timeout,
            allow_private_ips=allow_private_ips,
        )
    except TeaError as exc:
        _error(str(exc))
    except ValueError as exc:
        _error(str(exc))
    else:
        if _is_json_output():
            import dataclasses

            json.dump(dataclasses.asdict(result), sys.stdout, indent=2, default=str)
            print()
        else:
            try:
                from libtea._cli_fmt import format_conformance
            except ImportError:
                for check in result.checks:
                    status_label = check.status.value.upper()
                    msg = check.message
                    if verbose and check.details and check.status.value == "fail":
                        msg = f"{check.message}\n    {check.details}"
                    print(f"  {status_label:4s}  {check.name} — {msg}")
                print(f"\nResults: {result.passed} passed, {result.failed} failed, {result.skipped} skipped")
                raise SystemExit(1 if result.failed > 0 else 0)
            format_conformance(result, verbose=verbose)

        raise SystemExit(1 if result.failed > 0 else 0)
