"""Locate application resources in source and PyInstaller builds."""

from pathlib import Path
import sys


def application_root():
    bundled = getattr(sys, "_MEIPASS", None)
    return Path(bundled) if bundled else Path(__file__).resolve().parents[2]
