"""WinMend diagnostics: repairs: boot."""

from __future__ import annotations

from winmend.diagnostics.repairs.base import _result, _run_command
from winmend.diagnostics.repairs.common import (
    _registry_apply,
    _registry_restore,
    _registry_snapshot,
)
import re
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


# -- boot, power, and sleep --------------------------------------------------

def _do_clear_safe_boot(params, log):
    """Stop Windows booting into Safe Mode every time.

    ``bcdedit`` is given no identifier on purpose. The documented ``{current}``
    form is rejected outright by the Windows 11 parser ("the specified entry
    type is invalid") before it even opens the store, and both /set and
    /deletevalue already default to the running entry.
    """
    rc, out, err = _run_command(["bcdedit", "/enum", "ACTIVE"], timeout=30)
    if rc != 0:
        return _result(False, "The boot configuration could not be read: "
                              + (err or out or "administrator rights are needed").strip()[:160])
    previous = ""
    for line in out.splitlines():
        name, _, value = line.strip().partition(" ")
        if name.strip().lower() == "safeboot":
            previous = value.strip()
            break
    if not previous:
        return _result(True, "This PC was not set to boot into Safe Mode, so nothing "
                             "needed changing.")
    log(f"Removing the safeboot setting ({previous})...")
    rc, out, err = _run_command(["bcdedit", "/deletevalue", "safeboot"], timeout=30)
    if rc != 0:
        return _result(False, "The setting could not be removed: "
                              + (err or out or "").strip()[:160])
    return _result(
        True,
        "Removed the setting that was forcing Safe Mode. The next restart will be a normal one.",
        undo={"kind": "safeboot", "value": previous}, needs_restart=True)


def _undo_clear_safe_boot(payload, log):
    value = str(payload.get("value", "")).strip()
    if value not in ("minimal", "network", "dsrepair"):
        return _result(False, f"{value!r} is not a Safe Mode setting, so it was not put back.")
    rc, out, err = _run_command(["bcdedit", "/set", "safeboot", value], timeout=30)
    if rc != 0:
        return _result(False, (err or out or "").strip()[:160])
    return _result(True, f"Safe Mode ({value}) was set again, as it was before.",
                   needs_restart=True)


_POWER_KEY = r"SYSTEM\CurrentControlSet\Control\Session Manager\Power"


def _do_disable_fast_startup(params, log):
    """Make "Shut down" really shut the PC down."""
    if winreg is None:
        return _result(False, "Registry access is unavailable.")
    previous = _registry_snapshot(winreg.HKEY_LOCAL_MACHINE, _POWER_KEY, ("HiberbootEnabled",))
    entry = previous.get("HiberbootEnabled")
    if entry is not None and not entry[0]:
        return _result(True, "Fast startup was already off, so nothing needed changing.")
    log("Turning fast startup off...")
    error = _registry_apply(winreg.HKEY_LOCAL_MACHINE, _POWER_KEY,
                            {"HiberbootEnabled": [0, winreg.REG_DWORD]})
    if error:
        return _result(False, f"The setting could not be changed: {error}")
    return _result(
        True,
        "Fast startup is off. From the next shutdown onwards, shutting down will fully stop "
        "Windows instead of hibernating it -- which is what makes a shutdown able to clear "
        "the same things a restart does.",
        undo={"kind": "power", "previous": previous})


def _undo_disable_fast_startup(payload, log):
    if winreg is None:
        return _result(False, "Registry access is unavailable.")
    error = _registry_restore(winreg.HKEY_LOCAL_MACHINE, _POWER_KEY,
                              payload.get("previous") or {})
    if error:
        return _result(False, error)
    return _result(True, "Fast startup was put back the way it was.")


def _do_disable_wake_timers(params, log):
    """Stop scheduled tasks from waking this PC up on their own."""
    rc, out, _ = _run_command(
        ["powercfg", "/query", "SCHEME_CURRENT", "SUB_SLEEP", "RTCWAKE"], timeout=30)
    if rc != 0:
        return _result(False, "The current power plan could not be read. This needs "
                              "administrator rights.")
    settings = re.findall(r"Current (AC|DC) Power Setting Index:\s*0x([0-9a-fA-F]+)", out)
    previous = {kind: int(value, 16) for kind, value in settings}
    if previous and not any(previous.values()):
        return _result(True, "Wake timers were already switched off, so nothing changed.")
    log("Switching wake timers off for the current power plan...")
    for command in (
        ["powercfg", "/setacvalueindex", "SCHEME_CURRENT", "SUB_SLEEP", "RTCWAKE", "0"],
        ["powercfg", "/setdcvalueindex", "SCHEME_CURRENT", "SUB_SLEEP", "RTCWAKE", "0"],
    ):
        _run_command(command, timeout=30)
    _run_command(["powercfg", "/setactive", "SCHEME_CURRENT"], timeout=30)
    return _result(
        True,
        "Wake timers are off for the current power plan. Scheduled maintenance can no longer "
        "wake this PC; pressing the power button or a keyboard still will.",
        undo={"kind": "waketimers", "previous": previous})


def _undo_disable_wake_timers(payload, log):
    previous = payload.get("previous") or {}
    if not previous:
        return _result(False, "Nothing was recorded, so the old setting cannot be put back.")
    for kind, flag in ("AC", "setacvalueindex"), ("DC", "setdcvalueindex"):
        value = previous.get(kind)
        if value is None:
            continue
        _run_command(["powercfg", f"/{flag}", "SCHEME_CURRENT", "SUB_SLEEP", "RTCWAKE",
                      str(int(value))], timeout=30)
    _run_command(["powercfg", "/setactive", "SCHEME_CURRENT"], timeout=30)
    return _result(True, "Wake timers were put back the way they were.")
