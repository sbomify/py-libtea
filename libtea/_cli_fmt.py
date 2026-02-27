"""Rich formatters for CLI output.

Each ``fmt_*`` function renders a specific TEA model type as a rich table or
panel.  :func:`format_output` dispatches by type or by explicit ``command``
name (``"discover"`` and ``"inspect"`` use command-based dispatch because
their data is ``list`` which is ambiguous by type alone).
"""

import json

from pydantic import BaseModel
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from libtea.models import (
    Artifact,
    ArtifactFormat,
    Collection,
    ComponentReleaseWithCollection,
    DiscoveryInfo,
    Identifier,
    PaginatedProductReleaseResponse,
    PaginatedProductResponse,
    Product,
    ProductRelease,
)

_console = Console()


# --- Helpers ---


def _opt(value: object) -> str:
    """Return ``"-"`` for ``None``, otherwise ``str(value)``."""
    return "-" if value is None else str(value)


def _fmt_identifiers(identifiers: list[Identifier]) -> str:
    """Format a list of :class:`Identifier` objects as comma-joined ``type:value``."""
    if not identifiers:
        return "-"
    return ", ".join(f"{i.id_type}:{i.id_value}" for i in identifiers)


def _kv_panel(title: str, fields: list[tuple[str, str]], *, console: Console) -> None:
    """Render a key-value panel with aligned labels."""
    lines: list[str] = []
    for label, value in fields:
        lines.append(f"[bold]{escape(label)}:[/bold] {escape(value)}")
    console.print(Panel("\n".join(lines), title=escape(title), expand=False))


def _pagination_header(data: PaginatedProductResponse | PaginatedProductReleaseResponse, *, console: Console) -> None:
    """Render a dim pagination summary line."""
    end = data.page_start_index + len(data.results)
    console.print(Text(f"Results {data.page_start_index + 1}-{end} of {data.total_results}", style="dim"))


def _artifacts_table(artifacts: list[Artifact], *, console: Console) -> None:
    """Render a table of :class:`Artifact` model objects."""
    if not artifacts:
        return
    tbl = Table(title="Artifacts")
    tbl.add_column("UUID", style="cyan", no_wrap=True)
    tbl.add_column("Name")
    tbl.add_column("Type")
    tbl.add_column("Formats")
    for a in artifacts:
        fmt_str = ", ".join(f.media_type for f in a.formats) or "-"
        tbl.add_row(a.uuid, a.name, a.type, fmt_str)
    console.print(tbl)


def _formats_table(formats: list[ArtifactFormat], *, console: Console) -> None:
    """Render a table of artifact formats with checksums."""
    if not formats:
        return
    tbl = Table(title="Formats")
    tbl.add_column("Media Type")
    tbl.add_column("URL")
    tbl.add_column("Checksums")
    for f in formats:
        checksums = ", ".join(f"{cs.algorithm_type}:{cs.algorithm_value[:12]}..." for cs in f.checksums) or "-"
        tbl.add_row(f.media_type, f.url, checksums)
    console.print(tbl)


# --- Per-command formatters ---


def fmt_discover(data: list[DiscoveryInfo], *, console: Console) -> None:
    """Render discovery results as a table."""
    tbl = Table(title="Discovery Results")
    tbl.add_column("Product Release UUID", style="cyan", no_wrap=True)
    tbl.add_column("Server URL")
    tbl.add_column("API Versions")
    tbl.add_column("Priority", justify="right")
    for d in data:
        for s in d.servers:
            tbl.add_row(d.product_release_uuid, s.root_url, ", ".join(s.versions), _opt(s.priority))
    console.print(tbl)


def fmt_search_products(data: PaginatedProductResponse, *, console: Console) -> None:
    """Render paginated product search results."""
    _pagination_header(data, console=console)
    tbl = Table(title="Products")
    tbl.add_column("UUID", style="cyan", no_wrap=True)
    tbl.add_column("Name")
    tbl.add_column("Identifiers")
    for p in data.results:
        tbl.add_row(p.uuid, p.name, _fmt_identifiers(p.identifiers))
    console.print(tbl)


def fmt_search_releases(data: PaginatedProductReleaseResponse, *, console: Console) -> None:
    """Render paginated product-release search results."""
    _pagination_header(data, console=console)
    tbl = Table(title="Product Releases")
    tbl.add_column("UUID", style="cyan", no_wrap=True)
    tbl.add_column("Version")
    tbl.add_column("Product")
    tbl.add_column("Release Date")
    tbl.add_column("Pre-release")
    for r in data.results:
        tbl.add_row(r.uuid, r.version, _opt(r.product_name), _opt(r.release_date), _opt(r.pre_release))
    console.print(tbl)


def fmt_product(data: Product, *, console: Console) -> None:
    """Render a single product as a panel."""
    _kv_panel(
        "Product",
        [("UUID", data.uuid), ("Name", data.name), ("Identifiers", _fmt_identifiers(data.identifiers))],
        console=console,
    )


def fmt_product_release(data: ProductRelease, *, console: Console) -> None:
    """Render a product release as a panel with component refs."""
    _kv_panel(
        "Product Release",
        [
            ("UUID", data.uuid),
            ("Version", data.version),
            ("Product", _opt(data.product_name)),
            ("Created", str(data.created_date)),
            ("Released", _opt(data.release_date)),
            ("Pre-release", _opt(data.pre_release)),
            ("Identifiers", _fmt_identifiers(data.identifiers)),
        ],
        console=console,
    )
    if data.components:
        tbl = Table(title="Components")
        tbl.add_column("UUID", style="cyan", no_wrap=True)
        tbl.add_column("Release UUID")
        for comp in data.components:
            tbl.add_row(comp.uuid, _opt(comp.release))
        console.print(tbl)


def fmt_component_release(data: ComponentReleaseWithCollection, *, console: Console) -> None:
    """Render a component release + its latest collection."""
    r = data.release
    _kv_panel(
        "Component Release",
        [
            ("UUID", r.uuid),
            ("Version", r.version),
            ("Component", _opt(r.component_name)),
            ("Created", str(r.created_date)),
            ("Released", _opt(r.release_date)),
            ("Pre-release", _opt(r.pre_release)),
            ("Identifiers", _fmt_identifiers(r.identifiers)),
        ],
        console=console,
    )
    col = data.latest_collection
    _kv_panel(
        "Latest Collection",
        [
            ("UUID", _opt(col.uuid)),
            ("Version", _opt(col.version)),
            ("Date", _opt(col.date)),
            ("Belongs To", _opt(col.belongs_to)),
        ],
        console=console,
    )
    _artifacts_table(col.artifacts, console=console)


def fmt_collection(data: Collection, *, console: Console) -> None:
    """Render a collection as a panel with artifacts table."""
    reason = "-"
    if data.update_reason:
        reason = data.update_reason.type
        if data.update_reason.comment:
            reason += f" ({data.update_reason.comment})"
    _kv_panel(
        "Collection",
        [
            ("UUID", _opt(data.uuid)),
            ("Version", _opt(data.version)),
            ("Date", _opt(data.date)),
            ("Belongs To", _opt(data.belongs_to)),
            ("Update Reason", reason),
        ],
        console=console,
    )
    _artifacts_table(data.artifacts, console=console)


def fmt_artifact(data: Artifact, *, console: Console) -> None:
    """Render artifact metadata as a panel with formats table."""
    _kv_panel(
        "Artifact",
        [("UUID", data.uuid), ("Name", data.name), ("Type", data.type)],
        console=console,
    )
    _formats_table(data.formats, console=console)


def fmt_inspect(data: list[dict], *, console: Console) -> None:
    """Render the full inspect output (discovery + release + components)."""
    for entry in data:
        disc = entry["discovery"]
        pr = entry["productRelease"]
        _kv_panel(
            "Product Release",
            [
                ("UUID", pr["uuid"]),
                ("Version", pr["version"]),
                ("Created", str(pr.get("createdDate", "-"))),
                ("Discovery UUID", disc["productReleaseUuid"]),
            ],
            console=console,
        )
        components = entry.get("components", [])
        if components:
            tbl = Table(title="Components")
            tbl.add_column("UUID", style="cyan", no_wrap=True)
            tbl.add_column("Version")
            tbl.add_column("Name")
            for comp in components:
                comp_uuid = comp.get("uuid") or comp.get("release", {}).get("uuid", "-")
                version = comp.get("version") or comp.get("release", {}).get("version", "-")
                name = comp.get("name") or comp.get("release", {}).get("componentName", "-")
                tbl.add_row(str(comp_uuid), str(version), _opt(name))
            console.print(tbl)
        if entry.get("truncated"):
            console.print(Text(f"Showing {len(components)} of {entry['totalComponents']} components", style="dim"))


# --- Dispatch ---

_TYPE_FORMATTERS = {
    Product: fmt_product,
    ProductRelease: fmt_product_release,
    ComponentReleaseWithCollection: fmt_component_release,
    Collection: fmt_collection,
    Artifact: fmt_artifact,
    PaginatedProductResponse: fmt_search_products,
    PaginatedProductReleaseResponse: fmt_search_releases,
}


def format_output(data: object, *, command: str | None = None, console: Console | None = None) -> None:
    """Dispatch *data* to the appropriate rich formatter.

    Falls back to :meth:`Console.print_json` for unrecognised types.
    """
    c = console or _console

    if command == "inspect" and isinstance(data, list):
        fmt_inspect(data, console=c)
        return

    if command == "discover" and isinstance(data, list):
        fmt_discover(data, console=c)
        return

    for model_type, formatter in _TYPE_FORMATTERS.items():
        if isinstance(data, model_type):
            formatter(data, console=c)
            return

    # Fallback: render as JSON
    if isinstance(data, BaseModel):
        c.print_json(json.dumps(data.model_dump(mode="json", by_alias=True), default=str))
    elif isinstance(data, list):
        items = [item.model_dump(mode="json", by_alias=True) if isinstance(item, BaseModel) else item for item in data]
        c.print_json(json.dumps(items, default=str))
    else:
        c.print_json(json.dumps(data, default=str))
