"""libtea - Python client library for the Transparency Exchange API (TEA)."""

from importlib.metadata import version

from libtea.client import TeaClient

__version__ = version("libtea")
__all__ = ["TeaClient", "__version__"]
