"""WinMend features: startup: helpers."""

from __future__ import annotations

import os
import struct
import time
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


# ---------------------------------------------------------------------------
# Startup Manager support
#
# Enable/disable uses the same Task Manager-compatible StartupApproved values
# the bulk "Optimize Startup Apps" task already writes: the Run value or .lnk
# is never touched, only flagged, so every change is reversible from WinMend,
# Task Manager, or Settings > Apps > Startup.
# ---------------------------------------------------------------------------

_STARTUP_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


_STARTUP_RUN_KEY_WOW = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"


_STARTUP_APPROVED_BASE = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"


# 100ns intervals between the FILETIME epoch (1601) and the Unix epoch (1970).
_FILETIME_EPOCH_OFFSET = 11644473600


def startup_blob_is_disabled(blob):
    """A StartupApproved value's first byte carries the state: even = enabled,
    odd (0x03) = disabled. A missing or malformed value means enabled."""
    if not isinstance(blob, (bytes, bytearray)) or not blob:
        return False
    return bool(blob[0] & 0x01)


def startup_enable_blob():
    return struct.pack("<I", 2) + b"\x00" * 8


def startup_disable_blob(now=None):
    """Flag 0x03 plus the FILETIME of the disable -- the same 12-byte layout
    Task Manager writes, so its Startup tab shows the change immediately."""
    if now is None:
        now = time.time()
    filetime = max(0, int((now + _FILETIME_EPOCH_OFFSET) * 10_000_000))
    return struct.pack("<I", 3) + struct.pack("<Q", filetime)


def exe_from_command(command, exists=os.path.exists):
    """Best-effort executable path from a Run-key command line.

    Handles quoted paths, unquoted paths containing spaces (by accumulating
    tokens until an existing file appears), and env-var references."""
    raw = os.path.expandvars((command or "").strip())
    if not raw:
        return ""
    if raw.startswith('"'):
        end = raw.find('"', 1)
        return raw[1:end] if end > 1 else raw.strip('"')
    tokens = raw.split()
    candidate = ""
    for token in tokens:
        candidate = f"{candidate} {token}".strip()
        if candidate.lower().endswith((".exe", ".com", ".bat", ".cmd")) and exists(candidate):
            return candidate
    first = tokens[0]
    if first.lower().endswith(".exe") or os.sep in first:
        return first
    return raw


def file_company(path):
    """CompanyName from a file's version resource, or "". Pure ctypes -- no
    subprocess, so it is cheap enough to call once per startup entry."""
    if not path:
        return ""
    try:
        import ctypes
        version = ctypes.windll.version
        size = version.GetFileVersionInfoSizeW(path, None)
        if not size:
            return ""
        data = ctypes.create_string_buffer(size)
        if not version.GetFileVersionInfoW(path, 0, size, data):
            return ""
        ptr = ctypes.c_void_p()
        length = ctypes.c_uint()
        if not version.VerQueryValueW(data, r"\VarFileInfo\Translation",
                                      ctypes.byref(ptr), ctypes.byref(length)) or length.value < 4:
            return ""
        lang, codepage = struct.unpack("<HH", ctypes.string_at(ptr.value, 4))
        sub_block = "\\StringFileInfo\\%04x%04x\\CompanyName" % (lang, codepage)
        if not version.VerQueryValueW(data, sub_block, ctypes.byref(ptr), ctypes.byref(length)):
            return ""
        return ctypes.wstring_at(ptr.value, max(0, length.value - 1)).strip("\x00").strip()
    except Exception:
        return ""


def _resolve_lnk(path):
    """Target and arguments of a .lnk, via the shell COM object."""
    try:
        import pythoncom
        pythoncom.CoInitialize()  # enumeration runs on a worker thread
    except Exception:
        pass
    try:
        import win32com.client
        shortcut = win32com.client.Dispatch("WScript.Shell").CreateShortCut(path)
        return (shortcut.Targetpath or "").strip(), (shortcut.Arguments or "").strip()
    except Exception:
        return "", ""


def _startup_entry_enabled(entry):
    if winreg is None:
        return True
    root = winreg.HKEY_CURRENT_USER if entry["root"] == "HKCU" else winreg.HKEY_LOCAL_MACHINE
    try:
        with winreg.OpenKey(root, entry["approved_subkey"]) as key:
            blob, _kind = winreg.QueryValueEx(key, entry["value"])
    except OSError:
        return True
    return not startup_blob_is_disabled(blob)


def list_startup_entries():
    """Everything Task Manager's Startup tab shows: Run keys (user, machine,
    machine 32-bit) plus the two Startup folders, each with its enabled state."""
    entries = []
    if winreg is not None:
        locations = (
            ("HKCU", winreg.HKEY_CURRENT_USER, 0, "User registry",
             _STARTUP_APPROVED_BASE + r"\Run", "HKCU\\" + _STARTUP_RUN_KEY),
            ("HKLM", winreg.HKEY_LOCAL_MACHINE, 0, "Machine registry",
             _STARTUP_APPROVED_BASE + r"\Run", "HKLM\\" + _STARTUP_RUN_KEY),
            ("HKLM", winreg.HKEY_LOCAL_MACHINE, getattr(winreg, "KEY_WOW64_32KEY", 0),
             "Machine registry (32-bit)",
             _STARTUP_APPROVED_BASE + r"\Run32", "HKLM\\" + _STARTUP_RUN_KEY_WOW),
        )
        for root_name, root, wow_flag, source, approved, location in locations:
            try:
                key = winreg.OpenKey(root, _STARTUP_RUN_KEY, 0, winreg.KEY_READ | wow_flag)
            except OSError:
                continue
            with key:
                try:
                    value_count = winreg.QueryInfoKey(key)[1]
                except OSError:
                    continue
                for index in range(value_count):
                    try:
                        name, value, _kind = winreg.EnumValue(key, index)
                    except OSError:
                        continue
                    command = str(value).strip()
                    if not name or not command:
                        continue
                    entries.append({
                        "name": name,
                        "command": command,
                        "exe": exe_from_command(command),
                        "source": source,
                        "kind": "run",
                        "root": root_name,
                        "approved_subkey": approved,
                        "value": name,
                        "location": location,
                    })
    folders = (
        (os.path.join(os.environ.get("APPDATA", ""),
                      r"Microsoft\Windows\Start Menu\Programs\Startup"),
         "HKCU", "User startup folder"),
        (os.path.join(os.environ.get("PROGRAMDATA", ""),
                      r"Microsoft\Windows\Start Menu\Programs\StartUp"),
         "HKLM", "Common startup folder"),
    )
    for folder, root_name, source in folders:
        try:
            items = sorted(os.scandir(folder), key=lambda item: item.name.lower())
        except OSError:
            continue
        for item in items:
            if not item.is_file() or item.name.lower() == "desktop.ini":
                continue
            target, args = ("", "")
            if item.name.lower().endswith(".lnk"):
                target, args = _resolve_lnk(item.path)
            entries.append({
                "name": os.path.splitext(item.name)[0],
                "command": (f'"{target}" {args}'.strip() if target else item.path),
                "exe": target or item.path,
                "source": source,
                "kind": "folder",
                "root": root_name,
                "approved_subkey": _STARTUP_APPROVED_BASE + r"\StartupFolder",
                "value": item.name,
                "location": item.path,
            })
    for entry in entries:
        entry["enabled"] = _startup_entry_enabled(entry)
    return entries


def set_startup_entry_enabled(entry, enabled):
    """Flag one startup entry on or off. Returns "" on success, else a
    human-readable reason. Never deletes anything."""
    if winreg is None:
        return "Registry access is unavailable."
    root = winreg.HKEY_CURRENT_USER if entry["root"] == "HKCU" else winreg.HKEY_LOCAL_MACHINE
    blob = startup_enable_blob() if enabled else startup_disable_blob()
    try:
        with winreg.CreateKeyEx(root, entry["approved_subkey"], 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, entry["value"], 0, winreg.REG_BINARY, blob)
        return ""
    except PermissionError:
        return ("This item starts for every user on the PC — restart WinMend "
                "as administrator to change it.")
    except OSError as exc:
        return f"Windows refused the change: {exc}"
