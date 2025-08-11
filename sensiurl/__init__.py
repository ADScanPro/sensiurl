"""SensiURL - Sensitive URL Scanner

Modular scanner for exposed sensitive files and directories.
Designed to be used as both a script and a library.
"""

from .scanner import run_scan

__all__ = ["run_scan"]
__version__ = "0.1.0"