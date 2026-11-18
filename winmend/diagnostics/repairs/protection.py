"""WinMend diagnostics: repairs: protection."""

from __future__ import annotations

from winmend.diagnostics.repairs.base import _result
from winmend.diagnostics.repairs.common import _ps_run, _valid_drive
import os


def _do_enable_system_restore(params, log):
    drive = str(params.get("drive", os.environ.get("SystemDrive", "C:"))).strip().rstrip("\\")
    if not _valid_drive(drive):
        return _result(False, f"{drive!r} is not a drive letter.")
    log(f"Turning System Protection back on for {drive}...")
    rc, out, err = _ps_run(
        f"Enable-ComputerRestore -Drive '{drive}\\' -ErrorAction Stop; Write-Output 'ON'",
        timeout=180)
    if "ON" not in out:
        return _result(False, f"System Protection could not be turned on: "
                              f"{(out + err).strip()[-200:]}")
    log("Creating a first restore point to roll back to...")
    rc2, out2, err2 = _ps_run(
        "Checkpoint-Computer -Description 'WinMend baseline' "
        "-RestorePointType MODIFY_SETTINGS -ErrorAction Stop; Write-Output 'POINT'",
        timeout=300)
    if "POINT" in out2:
        return _result(True, f"System Protection is on for {drive} and a restore point was "
                             f"created. WinMend's own repairs can now be rolled back.")
    # Windows refuses more than one restore point in 24 hours by default, which
    # is not a failure of the thing this repair was asked to do.
    return _result(True, f"System Protection is on for {drive}. Windows declined to create a "
                         f"restore point right now -- it allows one per day by default -- so "
                         f"the next change that needs one will make it.")
