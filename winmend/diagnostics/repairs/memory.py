"""WinMend diagnostics: repairs: memory."""

from __future__ import annotations

from winmend.diagnostics.repairs.base import _result, _run_command
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


_MEMORY_KEY = r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"


def _do_enable_pagefile(params, log):
    if winreg is None:
        return _result(False, "Registry access is unavailable.")
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _MEMORY_KEY, 0,
                            winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
            try:
                previous = list(winreg.QueryValueEx(key, "PagingFiles")[0] or [])
            except OSError:
                previous = []
            log("Restoring system-managed virtual memory...")
            winreg.SetValueEx(key, "PagingFiles", 0, winreg.REG_MULTI_SZ,
                              ["?:\\pagefile.sys"])
    except OSError as exc:
        return _result(False, f"Windows refused the change: {exc}")
    # AutomaticManagedPagefile lives in WMI, not the registry, and without it
    # Windows keeps the explicit list instead of managing the file itself.
    _run_command(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "RemoteSigned", "-Command",
         "$c=Get-CimInstance Win32_ComputerSystem; $c.AutomaticManagedPagefile=$true; "
         "Set-CimInstance -InputObject $c"], timeout=60)
    return _result(True, "Windows will manage the page file again. This takes effect after a restart.",
                   undo={"kind": "pagefile", "previous": previous}, needs_restart=True)


def _undo_enable_pagefile(payload, log):
    if winreg is None:
        return _result(False, "Registry access is unavailable.")
    previous = payload.get("previous") or []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _MEMORY_KEY, 0,
                            winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "PagingFiles", 0, winreg.REG_MULTI_SZ, list(previous))
    except OSError as exc:
        return _result(False, f"Windows refused the change: {exc}")
    return _result(True, "The previous page file configuration was restored.", needs_restart=True)


def _do_schedule_memory_test(params, log):
    """Queue the Windows Memory Diagnostic to run at the next restart.

    ``bcdedit /bootsequence`` is what the Memory Diagnostic control panel uses
    itself. Scheduling rather than restarting is the point -- the user chooses
    when to lose the machine for twenty minutes.
    """
    rc, out, err = _run_command(
        ["bcdedit", "/bootsequence", "{memdiag}", "/addlast"], timeout=60)
    if rc != 0:
        return _result(False,
                       "The memory test could not be scheduled: "
                       + (err or out or "bcdedit refused the change").strip()[:200])
    log("Queued the Windows Memory Diagnostic for the next restart.")
    return _result(
        True,
        "The Windows Memory Diagnostic will run at the next restart. It takes roughly 15-30 "
        "minutes and the PC cannot be used while it runs. Results appear in the event log "
        "afterwards.",
        undo={"kind": "memtest"}, needs_restart=True)


def _undo_schedule_memory_test(payload, log):
    if (payload or {}).get("kind") != "memtest":
        return _result(False, "No scheduled memory test was recorded, so there is "
                              "nothing to cancel.")
    rc, out, err = _run_command(["bcdedit", "/deletevalue", "{fwbootmgr}", "bootsequence"],
                                timeout=60)
    # The boot sequence entry is consumed by the restart it applies to, so a
    # failure here most often means it has already run rather than that
    # anything is wrong.
    if rc != 0:
        return _result(True, "The scheduled memory test is no longer queued.")
    return _result(True, "The scheduled memory test was cancelled.")
