"""WinMend diagnostics: repairs: network config."""

from __future__ import annotations

from pathlib import Path
from winmend.diagnostics.collectors.deep import DeepProbe
from winmend.diagnostics.repairs.base import _result, _run_command
import os
import shutil
import time
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


# -- reversible settings actions --------------------------------------------

_PROXY_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def _do_clear_proxy(params, log):
    if winreg is None:
        return _result(False, "Registry access is unavailable.")
    previous = {}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _PROXY_KEY, 0,
                            winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
            for name in ("ProxyEnable", "ProxyServer", "AutoConfigURL"):
                try:
                    value, kind = winreg.QueryValueEx(key, name)
                    previous[name] = [value, kind]
                except OSError:
                    previous[name] = None
            log("Recording the current proxy settings so this can be undone...")
            try:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            except OSError:
                pass
            for name in ("ProxyServer", "AutoConfigURL"):
                try:
                    winreg.DeleteValue(key, name)
                except OSError:
                    pass
    except OSError as exc:
        return _result(False, f"Windows refused the change: {exc}")
    return _result(True, "Proxy settings cleared. Web traffic now goes direct.",
                   undo={"kind": "proxy", "previous": previous})


def _undo_clear_proxy(payload, log):
    if winreg is None:
        return _result(False, "Registry access is unavailable.")
    previous = payload.get("previous") or {}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _PROXY_KEY, 0,
                            winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
            for name, stored in previous.items():
                if stored is None:
                    try:
                        winreg.DeleteValue(key, name)
                    except OSError:
                        pass
                    continue
                value, kind = stored
                winreg.SetValueEx(key, name, 0, int(kind), value)
    except OSError as exc:
        return _result(False, f"Windows refused the change: {exc}")
    return _result(True, "The previous proxy settings were restored.")


_DEFAULT_HOSTS = (
    "# Copyright (c) 1993-2009 Microsoft Corp.\r\n"
    "#\r\n"
    "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n"
    "#\r\n"
    "# This file was reset by WinMend. The previous file was backed up alongside it.\r\n"
    "#\r\n"
    "#\t127.0.0.1       localhost\r\n"
    "#\t::1             localhost\r\n"
)


def _hosts_path():
    return Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"


def _do_restore_hosts(params, log):
    path = _hosts_path()
    backup = path.with_name(f"hosts.winmend-{int(time.time())}.bak")
    try:
        shutil.copy2(path, backup)
    except OSError as exc:
        return _result(False, f"The current hosts file could not be backed up, so nothing was changed: {exc}")
    log(f"Backed up the existing hosts file to {backup.name}.")
    try:
        path.write_text(_DEFAULT_HOSTS, encoding="utf-8")
    except OSError as exc:
        return _result(False, f"Windows refused to write the hosts file: {exc}")
    _run_command(["ipconfig", "/flushdns"], timeout=30)
    return _result(True, "The hosts file was reset to the Windows default and DNS cache flushed.",
                   undo={"kind": "hosts", "backup": str(backup)})


def _undo_restore_hosts(payload, log):
    backup = Path(str(payload.get("backup", "")))
    if not backup.exists():
        return _result(False, f"The backup {backup.name} is no longer present.")
    try:
        shutil.copy2(backup, _hosts_path())
    except OSError as exc:
        return _result(False, f"The hosts file could not be restored: {exc}")
    _run_command(["ipconfig", "/flushdns"], timeout=30)
    return _result(True, "The previous hosts file was restored.")


def _do_reset_dns(params, log):
    probe = DeepProbe()
    current = probe.dns_servers()
    if not current.get("available"):
        return _result(False, "The current DNS configuration could not be read, so nothing was changed.")
    previous = []
    changed = []
    for entry in current.get("interfaces", []):
        name = entry.get("interface", "")
        servers = [s["address"] for s in entry.get("servers", [])]
        if not name or not servers:
            continue
        previous.append({"interface": name, "servers": servers})
        log(f"Returning {name} to automatic DNS...")
        rc, out, err = _run_command(
            ["netsh", "interface", "ip", "set", "dns", f"name={name}", "source=dhcp"], timeout=60)
        if rc == 0:
            changed.append(name)
    if not changed:
        return _result(False, "No interface accepted the change.")
    _run_command(["ipconfig", "/flushdns"], timeout=30)
    return _result(True, f"DNS returned to automatic on {', '.join(changed)}.",
                   undo={"kind": "dns", "previous": previous})


def _undo_reset_dns(payload, log):
    restored = []
    for entry in payload.get("previous") or []:
        name = entry.get("interface")
        servers = entry.get("servers") or []
        if not name or not servers:
            continue
        for index, address in enumerate(servers):
            command = (["netsh", "interface", "ip", "set", "dns", f"name={name}",
                        "static", address, "primary"] if index == 0 else
                       ["netsh", "interface", "ip", "add", "dns", f"name={name}",
                        address, f"index={index + 1}"])
            _run_command(command, timeout=60)
        restored.append(name)
    if not restored:
        return _result(False, "There were no recorded DNS servers to restore.")
    return _result(True, f"The previous DNS servers were restored on {', '.join(restored)}.")
