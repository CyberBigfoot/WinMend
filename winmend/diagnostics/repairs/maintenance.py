"""WinMend diagnostics: repairs: maintenance."""

from __future__ import annotations

from winmend.diagnostics.reference import BENIGN_TASK_RESULTS, _maintenance_task
from winmend.diagnostics.repairs.base import _result
from winmend.diagnostics.repairs.common import _ps_run
import re


def _do_run_scheduled_task(params, log):
    path = str(params.get("task", "")).strip()
    # The task path arrives from collected data, and "run this scheduled task"
    # is an execution primitive. Only the exact tasks in MAINTENANCE_TASKS are
    # ever started from here, and only the ones flagged as meaningful to start
    # by hand -- see the note on that table for what prefix matching cost.
    known = _maintenance_task(path)
    if known is None:
        return _result(
            False,
            f"{path or 'That task'} is not one of the Windows maintenance tasks WinMend "
            "recognises, so it will not be run. Third-party tasks, and the broker tasks "
            "Windows launches with its own arguments, are left alone.")
    consequence, runnable = known
    leaf = path.rpartition("\\")[2]
    if not runnable:
        return _result(
            False,
            f"{leaf} is reported rather than run: Windows starts it with arguments that are "
            f"not available from outside, so starting it by hand only ever fails. What its "
            f"failure means is that {consequence}.")
    if not re.fullmatch(r"[\w \\\-.()]{1,200}", path):
        return _result(False, "That task name contains characters WinMend will not pass on.")
    folder = path.rpartition("\\")[0]
    log(f"Running {leaf} now to see whether it still fails...")
    rc, out, err = _ps_run(
        f"$t=Get-ScheduledTask -TaskPath '{folder}\\' -TaskName '{leaf}' -ErrorAction Stop;"
        "if ($t.State -eq 'Disabled') { Enable-ScheduledTask -InputObject $t | Out-Null;"
        " Write-Output 'ENABLED' };"
        "Start-ScheduledTask -InputObject $t -ErrorAction Stop;"
        "$deadline=(Get-Date).AddSeconds(120);"
        "do { Start-Sleep -Seconds 3; $i=$t | Get-ScheduledTaskInfo } "
        "while ($i.LastTaskResult -eq 267009 -and (Get-Date) -lt $deadline);"
        "Write-Output ('R|'+[string]$i.LastTaskResult)", timeout=200)
    code = None
    for line in out.splitlines():
        if line.startswith("R|"):
            try:
                code = int(line.split("|")[1]) & 0xFFFFFFFF
            except (IndexError, ValueError):
                code = None
    enabled = "ENABLED" in out
    if code is None:
        text = (out + err).strip()
        # Task Scheduler answers a non-elevated caller with a PowerShell error
        # blob. Passing that through verbatim tells the user nothing.
        if "permissiondenied" in text.lower() or "access is denied" in text.lower():
            return _result(False, f"Windows would not let WinMend start {leaf}. Scheduled tasks "
                                  f"under \\Microsoft\\Windows can only be run by an "
                                  f"administrator -- restart WinMend as administrator.")
        return _result(False, f"{leaf} did not report a result: {text[-200:]}")
    # 0x00041301 is "still running". Defrag and the component cleanup routinely
    # outlast the two minutes spent waiting, and finishing later is not failing.
    if code == 0x00041301:
        return _result(True, f"{leaf} started and is still running. It was the last run that "
                             f"failed, and this one has already got further than that.")
    if code in BENIGN_TASK_RESULTS:
        return _result(True, f"{leaf} ran and completed"
                             + (" (it was disabled, and is now enabled)." if enabled else "."))
    return _result(
        False,
        f"{leaf} ran again and failed the same way (0x{code:08X}), so the failure is real "
        f"rather than a one-off. While it stays broken, {consequence}."
        + (" Restore points and backups both run through the Volume Shadow Copy service, "
           "which is the usual thing to check next."
           if "restore point" in consequence or "backed up" in consequence else ""))
