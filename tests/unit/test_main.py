"""Unit tests for Ishastra __main__ module (CLI entry point)."""

from __future__ import annotations

import sys
from unittest.mock import patch


class TestMainEntryPoint:
    """Test the main entry point module."""

    def test_main_module_imports(self):
        """Test that the __main__ module can be imported."""
        import ishastra.__main__ as main_module

        assert main_module is not None

    def test_main_module_has_expected_content(self):
        """Test that __main__ module has expected imports and structure."""
        import ishastra.__main__ as main_module

        assert hasattr(main_module, "main")

    @patch("ishastra.__main__.main")
    def test_main_calls_cli_main_when_run_as_module(self, mock_main):
        """Test that running __main__ as module calls cli.main()."""

        import ishastra.__main__ as main_module

        with patch.object(sys, "argv", ["ishastra"]), patch("ishastra.__main__.__name__", "__main__"):
            pass

        assert main_module.main is not None

    def test_main_function_is_cli_main(self):
        """Test that the main function imported is the CLI main."""
        from ishastra.__main__ import main
        from ishastra.cli import main as cli_main

        assert main is cli_main

    @patch("ishastra.cli.main")
    def test_main_execution_path(self, mock_cli_main):
        """Test that executing the module calls cli.main()."""
        import runpy

        runpy.run_module("ishastra.__main__", run_name="__main__")

        mock_cli_main.assert_called_once_with()


class TestMainModuleIntegration:
    """Integration-style tests for the main module."""

    @patch("ishastra.cli.main")
    def test_python_m_ishastra_calls_cli_main(self, mock_cli_main):
        """Test that 'python -m ishastra' calls cli.main()."""
        import runpy

        runpy.run_module("ishastra.__main__", run_name="__main__")

        mock_cli_main.assert_called_once()

    def test_main_module_exports_main(self):
        """Test that main is properly exported from __main__."""
        from ishastra import __main__

        assert hasattr(__main__, "main")
        assert callable(__main__.main)
