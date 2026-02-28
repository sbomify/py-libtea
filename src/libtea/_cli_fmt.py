"""Rich formatters for CLI output.

Each ``fmt_*`` function renders a specific TEA model type as a rich table or
panel.  :func:`format_output` dispatches by type or by explicit ``command``
name (``"discover"`` and ``"inspect"`` use command-based dispatch because
their data is ``list`` which is ambiguous by type alone).
"""

import json
from collections.abc import Sequence
from typing import Any

from pydantic import BaseModel
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from libtea.models import (
    CLE,
    Artifact,
    ArtifactFormat,
    Collection,
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
)

_console = Console()


# --- Helpers ---


def _opt(value: object) -> str:
    """Return ``"-"`` for ``None``, otherwise ``str(value)``."""
    return "-" if value is None else str(value)


def _esc(value: object) -> str:
    """Like :func:`_opt` but also escapes Rich markup for safe table rendering."""
    return escape(_opt(value))


def _fmt_identifiers(identifiers: Sequence[Identifier]) -> str:
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
    if not data.results:
        console.print(Text(f"No results (total: {data.total_results})", style="dim"))
    else:
        end = data.page_start_index + len(data.results)
        console.print(Text(f"Results {data.page_start_index + 1}-{end} of {data.total_results}", style="dim"))


def _distributions_table(distributions: Sequence[ReleaseDistribution], *, console: Console) -> None:
    """Render a table of :class:`ReleaseDistribution` objects."""
    if not distributions:
        return
    tbl = Table(title="Distributions")
    tbl.add_column("Type")
    tbl.add_column("Description")
    tbl.add_column("URL")
    tbl.add_column("Signature URL")
    tbl.add_column("Checksums")
    for d in distributions:
        checksums = ", ".join(f"{cs.algorithm_type}:{cs.algorithm_value[:12]}..." for cs in d.checksums) or "-"
        tbl.add_row(
            _esc(d.distribution_type), _esc(d.description), _esc(d.url), _esc(d.signature_url), escape(checksums)
        )
    console.print(tbl)


def _artifacts_table(artifacts: Sequence[Artifact], *, console: Console) -> None:
    """Render a table of :class:`Artifact` model objects."""
    if not artifacts:
        return
    tbl = Table(title="Artifacts")
    tbl.add_column("UUID", style="cyan", no_wrap=True)
    tbl.add_column("Name")
    tbl.add_column("Type")
    tbl.add_column("Applies To")
    tbl.add_column("Formats")
    for a in artifacts:
        fmt_str = ", ".join(f.media_type for f in a.formats) or "-"
        applies = ", ".join(a.distribution_types) if a.distribution_types else "-"
        tbl.add_row(escape(a.uuid), escape(a.name), escape(a.type), escape(applies), escape(fmt_str))
    console.print(tbl)


def _formats_table(formats: Sequence[ArtifactFormat], *, console: Console) -> None:
    """Render a table of artifact formats with checksums."""
    if not formats:
        return
    tbl = Table(title="Formats")
    tbl.add_column("Media Type")
    tbl.add_column("Description")
    tbl.add_column("URL")
    tbl.add_column("Signature URL")
    tbl.add_column("Checksums")
    for f in formats:
        checksums = ", ".join(f"{cs.algorithm_type}:{cs.algorithm_value[:12]}..." for cs in f.checksums) or "-"
        tbl.add_row(escape(f.media_type), _esc(f.description), escape(f.url), _esc(f.signature_url), escape(checksums))
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
            tbl.add_row(
                escape(d.product_release_uuid), escape(s.root_url), escape(", ".join(s.versions)), _esc(s.priority)
            )
    console.print(tbl)


def fmt_search_products(data: PaginatedProductResponse, *, console: Console) -> None:
    """Render paginated product search results."""
    _pagination_header(data, console=console)
    tbl = Table(title="Products")
    tbl.add_column("UUID", style="cyan", no_wrap=True)
    tbl.add_column("Name")
    tbl.add_column("Identifiers")
    for p in data.results:
        tbl.add_row(escape(p.uuid), escape(p.name), escape(_fmt_identifiers(p.identifiers)))
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
        tbl.add_row(escape(r.uuid), escape(r.version), _esc(r.product_name), _esc(r.release_date), _esc(r.pre_release))
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
            tbl.add_row(escape(comp.uuid), _esc(comp.release))
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
    _distributions_table(r.distributions, console=console)
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


def fmt_component(data: Component, *, console: Console) -> None:
    """Render a single component as a panel."""
    _kv_panel(
        "Component",
        [("UUID", data.uuid), ("Name", data.name), ("Identifiers", _fmt_identifiers(data.identifiers))],
        console=console,
    )


def fmt_releases(data: list[Release], *, console: Console) -> None:
    """Render a list of component releases as a table."""
    tbl = Table(title="Component Releases")
    tbl.add_column("UUID", style="cyan", no_wrap=True)
    tbl.add_column("Version")
    tbl.add_column("Component")
    tbl.add_column("Created")
    tbl.add_column("Released")
    tbl.add_column("Pre-release")
    tbl.add_column("Identifiers")
    for r in data:
        tbl.add_row(
            escape(r.uuid),
            escape(r.version),
            _esc(r.component_name),
            escape(str(r.created_date)),
            _esc(r.release_date),
            _esc(r.pre_release),
            escape(_fmt_identifiers(r.identifiers)),
        )
    console.print(tbl)


def fmt_collections(data: list[Collection], *, console: Console) -> None:
    """Render a list of collections as a table."""
    tbl = Table(title="Collections")
    tbl.add_column("UUID", style="cyan", no_wrap=True)
    tbl.add_column("Version", justify="right")
    tbl.add_column("Date")
    tbl.add_column("Belongs To")
    tbl.add_column("Artifacts")
    for col in data:
        tbl.add_row(
            _esc(col.uuid),
            _esc(col.version),
            _esc(col.date),
            _esc(col.belongs_to),
            str(len(col.artifacts)),
        )
    console.print(tbl)


def fmt_cle(data: CLE, *, console: Console) -> None:
    """Render a CLE document with events table and optional definitions."""
    if data.definitions and data.definitions.support:
        tbl = Table(title="Support Definitions")
        tbl.add_column("ID", style="cyan")
        tbl.add_column("Description")
        tbl.add_column("URL")
        for defn in data.definitions.support:
            tbl.add_row(escape(defn.id), escape(defn.description), _esc(defn.url))
        console.print(tbl)

    tbl = Table(title="Lifecycle Events")
    tbl.add_column("ID", justify="right")
    tbl.add_column("Type", style="bold")
    tbl.add_column("Effective")
    tbl.add_column("Published")
    tbl.add_column("Version")
    tbl.add_column("Details")
    for ev in data.events:
        details_parts: list[str] = []
        if ev.support_id:
            details_parts.append(f"support={ev.support_id}")
        if ev.license:
            details_parts.append(f"license={ev.license}")
        if ev.superseded_by_version:
            details_parts.append(f"superseded_by={ev.superseded_by_version}")
        if ev.reason:
            details_parts.append(f"reason={ev.reason}")
        if ev.event_id is not None:
            details_parts.append(f"event_id={ev.event_id}")
        details = ", ".join(details_parts) or "-"
        version = ev.version or "-"
        if ev.versions:
            ranges = ", ".join(v.version or v.range or "?" for v in ev.versions)
            version = ranges
        tbl.add_row(
            str(ev.id),
            escape(ev.type.value),
            escape(str(ev.effective)),
            escape(str(ev.published)),
            escape(version),
            escape(details),
        )
    console.print(tbl)


def fmt_inspect(data: list[dict[str, Any]], *, console: Console) -> None:
    """Render the full inspect output (discovery + release + components)."""
    for entry in data:
        # Discovery servers
        disc = entry.get("discovery")
        if disc:
            servers = disc.get("servers", [])
            if servers:
                tbl = Table(title="Discovery Servers")
                tbl.add_column("Server URL")
                tbl.add_column("API Versions")
                tbl.add_column("Priority", justify="right")
                for s in servers:
                    tbl.add_row(
                        escape(s.get("rootUrl", "-")),
                        escape(", ".join(s.get("versions", []))),
                        _esc(s.get("priority")),
                    )
                console.print(tbl)

        pr = entry["productRelease"]
        fields = [
            ("UUID", pr["uuid"]),
            ("Product", _opt(pr.get("productName"))),
            ("Version", pr["version"]),
            ("Created", str(pr.get("createdDate", "-"))),
            ("Released", _opt(pr.get("releaseDate"))),
            ("Pre-release", _opt(pr.get("preRelease"))),
        ]
        identifiers = pr.get("identifiers", [])
        if identifiers:
            id_str = ", ".join(f"{i['idType']}:{i['idValue']}" for i in identifiers)
            fields.append(("Identifiers", id_str))
        _kv_panel("Product Release", fields, console=console)
        components = entry.get("components", [])
        if components:
            tbl = Table(title="Components")
            tbl.add_column("UUID", style="cyan", no_wrap=True)
            tbl.add_column("Version")
            tbl.add_column("Name")
            tbl.add_column("Note", style="dim")
            for comp in components:
                comp_uuid = comp.get("uuid") or comp.get("release", {}).get("uuid", "-")
                version = comp.get("version") or comp.get("release", {}).get("version", "-")
                name = comp.get("name") or comp.get("release", {}).get("componentName", "-")
                note = comp.get("resolvedNote", "")
                tbl.add_row(escape(str(comp_uuid)), escape(str(version)), _esc(name), escape(note))
            console.print(tbl)
            # Show artifact details for each component
            for comp in components:
                _inspect_component_details(comp, console=console)
        if entry.get("truncated"):
            console.print(Text(f"Showing {len(components)} of {entry['totalComponents']} components", style="dim"))


def _inspect_component_details(comp: dict[str, Any], *, console: Console) -> None:
    """Render distributions and artifact details for a component in inspect output."""
    # Distributions come from the release object
    release = comp.get("release") or (comp.get("resolvedRelease") or {}).get("release") or {}
    distributions = release.get("distributions") or []
    if distributions:
        comp_name = comp.get("name") or release.get("componentName", "Component")
        tbl = Table(title=f"Distributions ({_esc(comp_name)})")
        tbl.add_column("Type")
        tbl.add_column("Description")
        tbl.add_column("URL")
        tbl.add_column("Signature URL")
        tbl.add_column("Checksums")
        for d in distributions:
            checksums_list = d.get("checksums") or []
            checksums = (
                ", ".join(f"{cs.get('algType', '?')}:{cs.get('algValue', '')[:12]}..." for cs in checksums_list) or "-"
            )
            tbl.add_row(
                escape(d.get("distributionType", "-")),
                _esc(d.get("description")),
                _esc(d.get("url")),
                _esc(d.get("signatureUrl")),
                escape(checksums),
            )
        console.print(tbl)

    # Artifacts come from either a direct componentRelease or a resolvedRelease
    release_data = comp.get("latestCollection") or (comp.get("resolvedRelease") or {}).get("latestCollection")
    if not release_data:
        return
    artifacts = release_data.get("artifacts", [])
    if not artifacts:
        return
    comp_name = comp.get("name") or comp.get("release", {}).get("componentName", "Component")
    tbl = Table(title=f"Artifacts ({escape(str(comp_name))})")
    tbl.add_column("UUID", style="cyan", no_wrap=True)
    tbl.add_column("Name")
    tbl.add_column("Type")
    tbl.add_column("Applies To")
    tbl.add_column("Media Type")
    tbl.add_column("Description")
    tbl.add_column("URL")
    tbl.add_column("Signature URL")
    for art in artifacts:
        applies = ", ".join(art.get("distributionTypes") or []) or "-"
        formats = art.get("formats", [])
        if formats:
            for fmt in formats:
                tbl.add_row(
                    escape(art.get("uuid", "-")),
                    escape(art.get("name", "-")),
                    escape(art.get("type", "-")),
                    escape(applies),
                    escape(fmt.get("mediaType", "-")),
                    _esc(fmt.get("description")),
                    escape(fmt.get("url", "-")),
                    _esc(fmt.get("signatureUrl")),
                )
        else:
            tbl.add_row(
                escape(art.get("uuid", "-")),
                escape(art.get("name", "-")),
                escape(art.get("type", "-")),
                escape(applies),
                "-",
                "-",
                "-",
                "-",
            )
    console.print(tbl)


# --- Dispatch ---

_TYPE_FORMATTERS = {
    Product: fmt_product,
    ProductRelease: fmt_product_release,
    ComponentReleaseWithCollection: fmt_component_release,
    Collection: fmt_collection,
    Artifact: fmt_artifact,
    Component: fmt_component,
    CLE: fmt_cle,
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

    if command == "releases" and isinstance(data, list):
        fmt_releases(data, console=c)
        return

    if command == "collections" and isinstance(data, list):
        fmt_collections(data, console=c)
        return

    for model_type, formatter in _TYPE_FORMATTERS.items():
        if isinstance(data, model_type):
            formatter(data, console=c)  # type: ignore[operator]
            return

    # Fallback: render as JSON
    if isinstance(data, BaseModel):
        c.print_json(json.dumps(data.model_dump(mode="json", by_alias=True), default=str))
    elif isinstance(data, list):
        items = [item.model_dump(mode="json", by_alias=True) if isinstance(item, BaseModel) else item for item in data]
        c.print_json(json.dumps(items, default=str))
    else:
        c.print_json(json.dumps(data, default=str))
