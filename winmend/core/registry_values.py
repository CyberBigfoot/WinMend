"""WinMend core: registry values."""

from __future__ import annotations

try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


_ROOTS = {
    "HKCU": "HKEY_CURRENT_USER",
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKU": "HKEY_USERS",
}


def _hive(root):
    return getattr(winreg, _ROOTS[root])


def _hive(name):
    return {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCR": winreg.HKEY_CLASSES_ROOT}[name]
