"""WinMend diagnostics: repairs: updates."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from winmend.diagnostics.repairs.base import _result, _run_command
from winmend.diagnostics.repairs.common import (
    _START_WORDS,
    _registry_apply,
    _registry_restore,
    _registry_snapshot,
    _service_start,
    _valid_service_name,
)
import os
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


_WU_POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"


_WU_AU_KEY = _WU_POLICY_KEY + r"\AU"


_WU_UX_KEY = r"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"


_WU_SERVICES = ("wuauserv", "bits", "UsoSvc", "WaaSMedicSvc")


def _do_unblock_updates(params, log):
    """Undo whatever stopped Windows Update from running.

    Three separate mechanisms end up here, and a PC that has been through a
    "debloat" script usually has all three: policy values, a pause date in the
    future, and the services set to Disabled.
    """
    if winreg is None:
        return _result(False, "Registry access is unavailable.")
    undo = {"kind": "updates", "policy": {}, "au": {}, "ux": {}, "services": {}}
    cleared = []
    policy = _registry_snapshot(winreg.HKEY_LOCAL_MACHINE, _WU_POLICY_KEY,
                               ("DoNotConnectToWindowsUpdateInternetLocations",
                                "DisableWindowsUpdateAccess"))
    if any(entry is not None for entry in policy.values()):
        undo["policy"] = policy
        _registry_apply(winreg.HKEY_LOCAL_MACHINE, _WU_POLICY_KEY,
                        {name: None for name, entry in policy.items() if entry is not None})
        cleared.append("the policies blocking access to Windows Update")
    au = _registry_snapshot(winreg.HKEY_LOCAL_MACHINE, _WU_AU_KEY, ("NoAutoUpdate",))
    if au.get("NoAutoUpdate") is not None:
        undo["au"] = au
        _registry_apply(winreg.HKEY_LOCAL_MACHINE, _WU_AU_KEY, {"NoAutoUpdate": None})
        cleared.append("the policy turning automatic updates off")
    ux = _registry_snapshot(winreg.HKEY_LOCAL_MACHINE, _WU_UX_KEY,
                            ("PauseUpdatesExpiryTime", "PauseFeatureUpdatesEndTime",
                             "PauseQualityUpdatesEndTime"))
    if any(entry is not None for entry in ux.values()):
        undo["ux"] = ux
        _registry_apply(winreg.HKEY_LOCAL_MACHINE, _WU_UX_KEY,
                        {name: None for name, entry in ux.items() if entry is not None})
        cleared.append("the pause on updates")
    for name in _WU_SERVICES:
        start = _service_start(name)
        if start != 4:
            continue
        undo["services"][name] = start
        log(f"Setting the {name} service back to starting on demand...")
        # 3 (Manual) is what Windows ships these as: they are trigger-started
        # when an update check runs, not left running.
        _run_command(["sc", "config", name, "start=", "demand"], timeout=60)
        cleared.append(f"the {name} service being disabled")
    if not cleared:
        return _result(True, "Nothing was blocking Windows Update, so nothing was changed.")
    _run_command(["sc", "start", "wuauserv"], timeout=60)
    return _result(True, "Removed " + ", ".join(cleared) + ". Windows Update can run again -- "
                         "check for updates to confirm it finds something.", undo=undo)


def _undo_unblock_updates(payload, log):
    if winreg is None:
        return _result(False, "Registry access is unavailable.")
    restored = 0
    for key, path in ((payload.get("policy"), _WU_POLICY_KEY),
                      (payload.get("au"), _WU_AU_KEY),
                      (payload.get("ux"), _WU_UX_KEY)):
        if key:
            _registry_restore(winreg.HKEY_LOCAL_MACHINE, path, key)
            restored += 1
    for name, start in (payload.get("services") or {}).items():
        if not _valid_service_name(name) or start not in _START_WORDS:
            continue
        _run_command(["sc", "config", name, "start=", _START_WORDS[int(start)]], timeout=60)
        if int(start) == 4:
            _run_command(["sc", "stop", name], timeout=60)
        restored += 1
    if not restored:
        return _result(True, "Nothing was recorded as changed, so nothing needed putting back.")
    return _result(True, "Windows Update was put back to the blocked state it was in.")


# -- Windows servicing -------------------------------------------------------

_WU_REDIRECT_VALUES = ("WUServer", "WUStatusServer", "TargetReleaseVersion",
                       "TargetReleaseVersionInfo", "ProductVersion",
                       "DeferFeatureUpdatesPeriodInDays",
                       "DeferQualityUpdatesPeriodInDays")


def _do_clear_update_policy(params, log):
    """Point Windows Update back at Microsoft.

    Separate from ``unblock_updates``, which undoes updates being switched
    *off*. This undoes them being pointed somewhere else or pinned to a version,
    which reports success while delivering nothing.
    """
    if winreg is None:
        return _result(False, "Registry access is unavailable.")
    policy = _registry_snapshot(winreg.HKEY_LOCAL_MACHINE, _WU_POLICY_KEY, _WU_REDIRECT_VALUES)
    au = _registry_snapshot(winreg.HKEY_LOCAL_MACHINE, _WU_AU_KEY, ("UseWUServer",))
    set_policy = {name: None for name, entry in policy.items() if entry is not None}
    set_au = {name: None for name, entry in au.items() if entry is not None}
    if not set_policy and not set_au:
        return _result(True, "Nothing was redirecting or pinning Windows Update, so nothing "
                             "was changed.")
    log("Removing the update redirection policies...")
    for hive_path, changes in ((_WU_POLICY_KEY, set_policy), (_WU_AU_KEY, set_au)):
        if changes:
            error = _registry_apply(winreg.HKEY_LOCAL_MACHINE, hive_path, changes)
            if error:
                return _result(False, f"The policy could not be removed: {error}")
    _run_command(["net", "stop", "wuauserv"], timeout=90)
    _run_command(["net", "start", "wuauserv"], timeout=90)
    removed = ", ".join(sorted(set(set_policy) | set(set_au)))
    return _result(
        True,
        f"Removed {removed}. Windows Update talks to Microsoft again -- check for updates to "
        f"confirm it now finds something.",
        undo={"kind": "wupolicy", "policy": policy, "au": au})


def _undo_clear_update_policy(payload, log):
    if winreg is None:
        return _result(False, "Registry access is unavailable.")
    for path, previous in ((_WU_POLICY_KEY, payload.get("policy")),
                           (_WU_AU_KEY, payload.get("au"))):
        if previous:
            _registry_restore(winreg.HKEY_LOCAL_MACHINE, path, previous)
    return _result(True, "The update policies were put back exactly as they were.")


def _do_clear_update_cache(params, log):
    """Throw away the half-downloaded update files and start again."""
    root = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "SoftwareDistribution"
    if not root.exists():
        return _result(True, "There is no update download folder to clear.")
    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    moved = root.with_name(f"SoftwareDistribution.winmend-{stamp}")
    for service in ("wuauserv", "bits", "cryptsvc"):
        log(f"Stopping {service}...")
        _run_command(["net", "stop", service, "/y"], timeout=120)
    try:
        root.rename(moved)
    except OSError as exc:
        for service in ("cryptsvc", "bits", "wuauserv"):
            _run_command(["net", "start", service], timeout=120)
        return _result(False, f"The download folder is still in use and could not be moved: {exc}")
    for service in ("cryptsvc", "bits", "wuauserv"):
        log(f"Starting {service}...")
        _run_command(["net", "start", service], timeout=120)
    # One-way on purpose: Windows rebuilds this folder on the next update check,
    # and putting the old broken downloads back would only restore the fault.
    # The old folder is left on disk rather than deleted so nothing is lost.
    return _result(
        True,
        f"The update download folder was set aside as {moved.name} and Windows will build a "
        f"fresh one on the next check. The old folder can be deleted once updates work again.")
