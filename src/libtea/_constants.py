"""Shared constants used across multiple libtea modules."""


def _get_package_version() -> str:
    """Get the package version for User-Agent header."""
    try:
        from importlib.metadata import PackageNotFoundError, version

        return version("libtea")
    except (PackageNotFoundError, ValueError):
        return "unknown"


USER_AGENT = f"py-libtea/{_get_package_version()} (hello@sbomify.com)"
