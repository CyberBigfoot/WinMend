"""WinMend diagnostics: repairs: desktop."""

from __future__ import annotations

from pathlib import Path
from winmend.diagnostics.reference import _POLICY_WATCHLIST
from winmend.diagnostics.repairs.base import _result, _run_command
from winmend.diagnostics.repairs.common import (
    _ps_run,
    _registry_apply,
    _registry_restore,
    _registry_snapshot,
)
import os
import re
import subprocess
import time
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


# -- apps, shell, and devices ------------------------------------------------

def _do_reregister_app(params, log):
    """Re-register one Store app against the files it already has."""
    name = str(params.get("name", "")).strip()
    if not re.fullmatch(r"[A-Za-z0-9._\-]{1,80}", name):
        return _result(False, f"{name!r} is not a package name.")
    log(f"Re-registering {name}...")
    rc, out, err = _ps_run(
        f"$p=Get-AppxPackage -Name '{name}' -ErrorAction SilentlyContinue;"
        "if(-not $p){Write-Output 'MISSING';exit 0};"
        "foreach($x in $p){"
        "$m=Join-Path $x.InstallLocation 'AppXManifest.xml';"
        "if(Test-Path $m){Add-AppxPackage -DisableDevelopmentMode -Register $m "
        "-ErrorAction Stop; Write-Output 'DONE'}else{Write-Output 'NOFILES'}}", timeout=180)
    text = (out or "").upper()
    if "MISSING" in text:
        return _result(False, f"{name} is not installed for this user, so there was nothing "
                              f"to re-register. It has to be reinstalled from the Store.")
    if "NOFILES" in text:
        return _result(False, f"{name} is registered but its files are gone, so it cannot be "
                              f"repaired in place. It has to be reinstalled from the Store.")
    if rc != 0 or "DONE" not in text:
        return _result(False, f"{name} could not be re-registered: "
                              + (err or out or "").strip()[:200])
    return _result(True, f"{name} was registered again against its existing files. It should "
                         f"start normally now.")


def _do_restart_explorer(params, log):
    """Restart the desktop, taskbar, and Start menu."""
    log("Restarting Explorer...")
    _run_command(["taskkill", "/f", "/im", "explorer.exe"], timeout=60)
    time.sleep(1.0)
    try:
        subprocess.Popen(
            [str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "explorer.exe")],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except OSError as exc:
        return _result(False, f"Explorer was stopped but could not be started again: {exc}. "
                              f"Sign out and back in to recover the desktop.")
    return _result(True, "The desktop, taskbar, and Start menu were restarted. Open windows "
                         "in other programs were not affected.")


def _do_restart_audio(params, log):
    """Restart the audio stack in the order its dependencies require."""
    # Audiosrv depends on AudioEndpointBuilder, so the builder has to stop last
    # and start first or the restart silently leaves audio down.
    for service in ("Audiosrv", "AudioEndpointBuilder"):
        log(f"Stopping {service}...")
        _run_command(["net", "stop", service, "/y"], timeout=90)
    started = []
    for service in ("AudioEndpointBuilder", "Audiosrv"):
        log(f"Starting {service}...")
        rc, _out, _err = _run_command(["net", "start", service], timeout=90)
        if rc == 0:
            started.append(service)
    if len(started) < 2:
        return _result(False, "The audio services could not all be started again. A restart "
                              "will bring them back.")
    return _result(True, "The audio services were restarted and the playback devices were "
                         "rebuilt. Sound should work again without a restart.")


def _do_start_onedrive(params, log):
    """Start the OneDrive client so redirected folders sync again."""
    candidates = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "OneDrive" / "OneDrive.exe",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Microsoft OneDrive" / "OneDrive.exe",
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft OneDrive" / "OneDrive.exe",
    ]
    # Only these three fixed locations are ever launched. The path is not taken
    # from collected data, because starting a program is an execution primitive.
    target = next((path for path in candidates if path.exists()), None)
    if target is None:
        return _result(False, "OneDrive is not installed in any of the standard locations, so "
                              "it cannot be started. Your files are still in the folder it "
                              "points at.")
    try:
        subprocess.Popen([str(target), "/background"],
                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except OSError as exc:
        return _result(False, f"OneDrive could not be started: {exc}")
    return _result(True, "OneDrive was started. It will sign in and begin syncing; anything "
                         "saved to the Desktop or Documents while it was closed uploads now.")


# -- system integrity and policy ---------------------------------------------

_ENVIRONMENT_KEY = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"


def _do_repair_path(params, log):
    """Put the standard Windows folders back on the system PATH.

    Deliberately additive. The PATH is the one value where a well-meant rewrite
    breaks every program a user has installed, so entries are only ever
    prepended -- nothing existing is reordered or removed.
    """
    if winreg is None:
        return _result(False, "Registry access is unavailable.")
    previous = _registry_snapshot(winreg.HKEY_LOCAL_MACHINE, _ENVIRONMENT_KEY, ("Path",))
    entry = previous.get("Path")
    if entry is None:
        return _result(False, "The system PATH could not be read.")
    raw, kind = str(entry[0] or ""), int(entry[1])
    existing = {part.strip().rstrip("\\").lower()
                for part in raw.split(";") if part.strip()}
    root = os.environ.get("SystemRoot", r"C:\Windows")
    required = [
        os.path.join(root, "System32"),
        root,
        os.path.join(root, "System32", "Wbem"),
        os.path.join(root, "System32", "WindowsPowerShell", "v1.0"),
    ]
    missing = [path for path in required
               if path.rstrip("\\").lower() not in existing and os.path.isdir(path)]
    if not missing:
        return _result(True, "Every standard Windows folder was already on the PATH, so "
                             "nothing was changed.")
    repaired = ";".join(missing + ([raw] if raw.strip() else []))
    log("Adding " + ", ".join(missing) + " to the system PATH...")
    error = _registry_apply(winreg.HKEY_LOCAL_MACHINE, _ENVIRONMENT_KEY,
                            {"Path": [repaired, kind]})
    if error:
        return _result(False, f"The PATH could not be written: {error}")
    return _result(
        True,
        "Added " + ", ".join(missing) + " to the front of the system PATH. Programs started "
        "from now on will find them; anything already running keeps the old value until it is "
        "restarted.",
        undo={"kind": "path", "previous": previous}, needs_restart=True)


def _undo_repair_path(payload, log):
    if winreg is None:
        return _result(False, "Registry access is unavailable.")
    error = _registry_restore(winreg.HKEY_LOCAL_MACHINE, _ENVIRONMENT_KEY,
                              payload.get("previous") or {})
    if error:
        return _result(False, error)
    return _result(True, "The system PATH was put back exactly as it was.")


def _do_remove_policy(params, log):
    """Remove one policy value that is switching a Windows feature off.

    Only values on the watchlist can be removed. The hive and path arrive from
    collected data, and deleting an arbitrary registry value on request is not
    something a repair should be able to be talked into -- the same restriction
    that keeps ``run_scheduled_task`` to Windows' own maintenance tasks.
    """
    if winreg is None:
        return _result(False, "Registry access is unavailable.")
    wanted_path = str(params.get("path", "")).strip()
    wanted_name = str(params.get("value", "")).strip()
    wanted_hive = str(params.get("hive", "")).strip().upper()
    match = next((entry for entry in _POLICY_WATCHLIST
                  if entry[1].lower() == wanted_path.lower()
                  and entry[2].lower() == wanted_name.lower()
                  and ("HKLM" if entry[0] == winreg.HKEY_LOCAL_MACHINE else "HKCU") == wanted_hive),
                 None)
    if match is None:
        return _result(False, f"{wanted_hive}\\{wanted_path}\\{wanted_name} is not one of the "
                              f"policies this repair is allowed to remove.")
    hive, path, name, meaning, _area = match
    previous = _registry_snapshot(hive, path, (name,))
    if previous.get(name) is None:
        return _result(True, f"{name} was not set, so nothing needed removing.")
    log(f"Removing the {name} policy...")
    error = _registry_apply(hive, path, {name: None})
    if error:
        return _result(False, f"The policy could not be removed: {error}")
    return _result(
        True,
        f"Removed the policy: {meaning[0].lower() + meaning[1:] if meaning else name} is no "
        f"longer in force. Some policies only take effect again after signing out.",
        undo={"kind": "policy", "hive": wanted_hive, "path": path, "value": name,
              "previous": previous})


def _undo_remove_policy(payload, log):
    if winreg is None:
        return _result(False, "Registry access is unavailable.")
    hive = (winreg.HKEY_LOCAL_MACHINE if str(payload.get("hive", "")).upper() == "HKLM"
            else winreg.HKEY_CURRENT_USER)
    path = str(payload.get("path", "")).strip()
    if not any(entry[1].lower() == path.lower() for entry in _POLICY_WATCHLIST):
        return _result(False, "The recorded policy is not one this repair manages.")
    error = _registry_restore(hive, path, payload.get("previous") or {})
    if error:
        return _result(False, error)
    return _result(True, "The policy was put back exactly as it was.")
