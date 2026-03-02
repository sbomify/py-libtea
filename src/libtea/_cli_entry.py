"""Entry point wrapper for tea-cli that handles missing click gracefully."""

import signal
import sys


def main() -> None:
    """Launch the tea-cli app, or print a helpful error if click is not installed."""
    # Reset SIGPIPE so piping to head/grep exits silently instead of BrokenPipeError.
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    try:
        from libtea.cli import app
    except ImportError:
        print("Error: CLI dependencies not installed. Run: pip install libtea[cli]", file=sys.stderr)
        raise SystemExit(1)
    app()
