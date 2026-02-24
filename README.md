# libtea

Python client library for the [Transparency Exchange API (TEA)](https://transparency.exchange/).

> **Status**: Alpha — API is subject to change.

## Installation

```bash
pip install libtea
```

## Development

This project uses [uv](https://docs.astral.sh/uv/) for dependency management.

```bash
# Install dependencies
uv sync

# Run tests
uv run pytest

# Lint
uv run ruff check .

# Format check
uv run ruff format --check .

# Build
uv build
```

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.
