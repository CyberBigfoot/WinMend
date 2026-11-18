"""WinMend features: scheduled tasks."""

from __future__ import annotations

from datetime import datetime
from winmend.core.processes import _no_console_startupinfo, wm_run
from winmend.core.search import _wm_last_line
import os
import time


class ScheduledTasksTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    def run_scheduled_task_audit(self):
        """List non-Microsoft scheduled tasks; flag suspicious paths and launchers."""
        label = "Sched Task Audit"
        self.queue.put(f"PROGRESS:{label}:Auditing scheduled tasks for suspicious persistence...")
        try:
            desktop = self._get_desktop_dir()
            ts = time.strftime("%Y%m%d_%H%M%S")
            report_path = os.path.join(desktop, f"Scheduled_Task_Audit_{ts}.txt")

            # The patterns sit in single-quoted PowerShell strings, where a
            # backslash is literal: \\ is one escaped backslash to the regex
            # engine. The old script doubled them again (\\\\Temp\\\\), which
            # demanded two backslashes in a row, so no real path ever matched
            # and every audit reported zero flagged tasks. It also looked for
            # -enc in the executable name, never in its arguments.
            ps_script = r'''
            $folders = '(?i)(\\Temp\\|\\AppData\\|\\ProgramData\\(?!Microsoft)|\\Users\\Public\\|\\Downloads\\)'
            $launch = '(?i)(\s-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{16,}|\bmshta(\.exe)?\b)'
            $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
                Where-Object { $_.TaskPath -notlike "\Microsoft\*" -and $_.State -ne "Disabled" }
            $rows = foreach ($t in $tasks) {
                $info = $t | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
                foreach ($act in $t.Actions) {
                    if (-not $act.Execute) { continue }
                    $exe = [Environment]::ExpandEnvironmentVariables("$($act.Execute)")
                    $arguments = "$($act.Arguments)"
                    $why = @()
                    if ($exe -match $folders) { $why += 'runs from a user-writable folder' }
                    if (" $exe $arguments" -match $launch) { $why += 'hidden or encoded script launcher' }
                    [pscustomobject]@{
                        Flag = $(if ($why) { '[FLAG] ' + ($why -join '; ') } else { '' })
                        Task = $t.TaskPath + $t.TaskName
                        Exe  = $exe
                        Args = $arguments
                        Last = $info.LastRunTime
                        State = $t.State
                    }
                }
            }
            $rows | Sort-Object Flag -Descending | Format-List | Out-String -Width 260
            '''
            r = wm_run(['powershell', '-NoProfile', '-ExecutionPolicy', 'RemoteSigned', '-Command', ps_script],
                       capture_output=True, text=True, encoding='utf-8', errors='replace',
                       cancel_event=self.cancel_event, startupinfo=_no_console_startupinfo())
            if self.cancel_event.is_set():
                return
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write("=== WINMEND SCHEDULED TASK AUDIT ===\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write("Entries marked [FLAG] run from a folder any program can write to (Temp,\n")
                f.write("AppData, ProgramData outside Microsoft, Public, Downloads) or launch an\n")
                f.write("encoded PowerShell command or mshta. Browser and app updaters often run\n")
                f.write("from AppData legitimately -- check the publisher before deleting anything.\n\n")
                f.write(r.stdout or "(no output)")
                if r.stderr and r.stderr.strip():
                    f.write("\n\n=== stderr ===\n" + r.stderr.strip())

            flagged = (r.stdout or "").count("[FLAG]")
            self.queue.put(f"PROGRESS:{label}:Report saved to {report_path}")
            self.queue.put(f"PROGRESS:{label}:Flagged tasks: {flagged}.")
            if r.returncode != 0 and not (r.stdout or "").strip():
                self._report_failure(f"PROGRESS:{label}:The task list could not be read: "
                                     f"{_wm_last_line(r.stderr) or r.returncode}")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")
