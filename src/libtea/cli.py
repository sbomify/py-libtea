"""CLI for the Transparency Exchange API.

Provides the ``tea-cli`` command backed by click. Each subcommand maps
to a :class:`~libtea.client.TeaClient` method and outputs rich-formatted
tables and panels by default (or JSON when ``--json`` is specified).
All commands accept ``--base-url`` / ``--domain`` for server selection,
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

import click
from pydantic import BaseModel

from libtea.client import TEA_SPEC_VERSION, TeaClient
from libtea.discovery import parse_tei
from libtea.exceptions import TeaDiscoveryError, TeaError
from libtea.models import (
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
        # Merge group-level flags with subcommand-level flags
        if ctx.obj.get("allow_private_ips"):
            kwargs["allow_private_ips"] = True
        verbose = verbose or ctx.obj.get("verbose", False)
        debug = debug or ctx.obj.get("debug", False)
        _configure_logging(verbose=verbose, debug=debug)
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


def _output(data: Any, *, command: str | None = None) -> None:
    """Output ``data`` as JSON (when ``--json``) or rich-formatted tables/panels.

    In JSON mode, Pydantic models are serialized via ``model_dump(mode="json",
    by_alias=True)`` to produce camelCase keys matching the TEA API wire format.
    """
    if _is_json_output():
        if isinstance(data, BaseModel):
            data = data.model_dump(mode="json", by_alias=True)
        elif isinstance(data, list):
            data = [
                item.model_dump(mode="json", by_alias=True) if isinstance(item, BaseModel) else item for item in data
            ]
        json.dump(data, sys.stdout, indent=2, default=str)
        print()
    else:
        try:
            from libtea._cli_fmt import format_output
        except ImportError:
            _error("Rich output requires the 'rich' package. Install with: pip install 'libtea[cli]'")
        format_output(data, command=command)


def _error(message: str) -> NoReturn:
    """Print an error message to stderr and exit with code 1."""
    try:
        print(f"Error: {message}", file=sys.stderr)
    except OSError:
        pass
    raise SystemExit(1)


# --- Main group ---


@click.group(help="TEA (Transparency Exchange API) CLI client.")
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
    """Resolve a TEI to product release UUID(s)."""
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
) -> None:
    """Search for products by identifier."""
    with _client_session(
        base_url, token, domain, timeout, use_http, port, auth, allow_private_ips=allow_private_ips
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
) -> None:
    """Search for product releases by identifier."""
    with _client_session(
        base_url, token, domain, timeout, use_http, port, auth, allow_private_ips=allow_private_ips
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
) -> None:
    """Get a product by UUID."""
    with _client_session(
        base_url, token, domain, timeout, use_http, port, auth, allow_private_ips=allow_private_ips
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
) -> None:
    """Get a product or component release by UUID."""
    with _client_session(
        base_url, token, domain, timeout, use_http, port, auth, allow_private_ips=allow_private_ips
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
) -> None:
    """Get a collection (latest or by version)."""
    with _client_session(
        base_url, token, domain, timeout, use_http, port, auth, allow_private_ips=allow_private_ips
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
) -> None:
    """List releases for a product UUID."""
    with _client_session(
        base_url, token, domain, timeout, use_http, port, auth, allow_private_ips=allow_private_ips
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
) -> None:
    """Get a component by UUID."""
    with _client_session(
        base_url, token, domain, timeout, use_http, port, auth, allow_private_ips=allow_private_ips
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
) -> None:
    """List releases for a component UUID."""
    with _client_session(
        base_url, token, domain, timeout, use_http, port, auth, allow_private_ips=allow_private_ips
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
) -> None:
    """List all collection versions for a release UUID."""
    with _client_session(
        base_url, token, domain, timeout, use_http, port, auth, allow_private_ips=allow_private_ips
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
) -> None:
    """Get Common Lifecycle Enumeration (CLE) for an entity."""
    entity_methods = {
        "product": "get_product_cle",
        "product-release": "get_product_release_cle",
        "component": "get_component_cle",
        "component-release": "get_component_release_cle",
    }
    with _client_session(
        base_url, token, domain, timeout, use_http, port, auth, allow_private_ips=allow_private_ips
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
) -> None:
    """Get artifact metadata by UUID."""
    with _client_session(
        base_url, token, domain, timeout, use_http, port, auth, allow_private_ips=allow_private_ips
    ) as client:
        result = client.get_artifact(uuid)
    _output(result)


@app.command()
@click.argument("url")
@click.argument("dest", type=click.Path())
@click.option("--checksum", multiple=True, help="Checksum as ALG:VALUE (repeatable)")
@click.option("--max-download-bytes", type=click.IntRange(min=1), default=None, help="Maximum download size in bytes")
@shared_options
def download(
    url: str,
    dest: str,
    checksum: tuple[str, ...],
    max_download_bytes: int | None,
    base_url: str | None,
    token: str | None,
    auth: str | None,
    domain: str | None,
    timeout: float,
    use_http: bool,
    port: int | None,
    allow_private_ips: bool,
) -> None:
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
        with _client_session(
            base_url, token, domain, timeout, use_http, port, auth, allow_private_ips=allow_private_ips
        ) as client:
            result = client.download_artifact(
                url, Path(dest), verify_checksums=checksums, max_download_bytes=max_download_bytes
            )
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
    """Full flow: TEI -> discovery -> releases -> artifacts."""
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
