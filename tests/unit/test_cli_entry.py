"""Tests for libtea._cli_entry — does NOT require CLI extras to be installed."""

import sys
from unittest.mock import patch

import pytest

from libtea._cli_entry import main


class TestCliEntryMissingDeps:
    """Exercise the ImportError branch when CLI extras are not installed."""

    def test_prints_install_hint_and_exits(self, capsys):
        """When libtea.cli cannot be imported, main() prints a help message and exits 1."""
        with patch.dict(sys.modules, {"libtea.cli": None}):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "pip install libtea[cli]" in captured.err
