"""WinMend core: registry."""

from __future__ import annotations

from contextlib import contextmanager
import winreg


@contextmanager
def open_reg_key(root, path, access=winreg.KEY_READ):
    """Context manager around winreg.OpenKey that guarantees the handle is closed."""
    key = winreg.OpenKey(root, path, 0, access)
    try:
        yield key
    finally:
        winreg.CloseKey(key)


@contextmanager
def create_reg_key(root, path):
    """Context manager around winreg.CreateKey that guarantees the handle is closed."""
    key = winreg.CreateKey(root, path)
    try:
        yield key
    finally:
        winreg.CloseKey(key)
