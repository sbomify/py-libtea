"""Entry point wrapper for tea-cli that handles missing typer gracefully."""

import sys


def main() -> None:
    """Launch the tea-cli app, or print a helpful error if typer is not installed."""
    try:
        from libtea.cli import app
    except ImportError:
        print("Error: CLI dependencies not installed. Run: pip install libtea[cli]", file=sys.stderr)
        raise SystemExit(1)
    app()
