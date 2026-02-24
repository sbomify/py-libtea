# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**py-libtea** is a Python client library for the Transparency Exchange API (TEA), maintained under the sbomify organization.

- **License**: Apache 2.0
- **Repository**: https://github.com/sbomify/py-libtea

## Build & Dev Commands

```bash
uv sync                        # Install dependencies
uv run pytest                  # Run tests (with coverage)
uv run ruff check .            # Lint
uv run ruff format --check .   # Format check
uv build                       # Build wheel and sdist
```

## Code Conventions

- **Layout**: Flat package layout (`libtea/`)
- **Build backend**: Hatchling
- **Line length**: 120
- **Lint/Format**: Ruff (rules: E, F, I)
- **Tests**: pytest with pytest-cov, test files in `tests/`
- **Python**: >=3.11
- **Type checking**: PEP 561 (`py.typed` marker)
