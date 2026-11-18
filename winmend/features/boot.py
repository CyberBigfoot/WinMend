"""WinMend features: boot."""

from __future__ import annotations

from winmend.core.processes import _no_console_startupinfo, wm_run
from winmend.core.prompts import messagebox
from winmend.core.registry import create_reg_key, open_reg_key
from winmend.core.search import _wm_last_line
from winmend.core.security import SecurityUtils
from winmend.features.office.helpers import service_state
from datetime import datetime, timezone
import ctypes
import re
import winreg


class BootTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    def run_toggle_safe_mode(self):
        label = "Safe Mode"
        self.queue.put(f"PROGRESS:{label}:Checking current boot configuration...")
        res = wm_run(['bcdedit'], capture_output=True, text=True, encoding='utf-8', errors='replace',
                     startupinfo=_no_console_startupinfo())
        if res.returncode != 0:
            detail = _wm_last_line(res.stderr, res.stdout) or f"rc={res.returncode}"
            self._report_failure(f"PROGRESS:{label}:Could not read the boot configuration: {detail}")
            return

        # Look only at the entry Windows is running from: a second Windows on
        # a dual-boot PC may carry its own safeboot value.
        current_block = ""
        for block in re.split(r"\r?\n\s*\r?\n", res.stdout or ""):
            if re.search(r"^identifier\s+\{current\}", block, re.IGNORECASE | re.MULTILINE):
                current_block = block
                break
        scheduled = bool(re.search(r"^safeboot\s", current_block, re.IGNORECASE | re.MULTILINE))
        # 0 = normal boot, 1 = Safe Mode, 2 = Safe Mode with Networking.
        in_safe_mode = ctypes.windll.user32.GetSystemMetrics(67) != 0

        if scheduled:
            self.queue.put(f"PROGRESS:{label}:Safe Mode is switched on. Switching it off...")
            args = ['bcdedit', '/deletevalue', '{current}', 'safeboot']
        else:
            self.queue.put(f"PROGRESS:{label}:Safe Mode is off. Switching on Safe Mode with Networking...")
            args = ['bcdedit', '/set', '{current}', 'safeboot', 'network']
        change = wm_run(args, capture_output=True, text=True, encoding='utf-8', errors='replace',
                        startupinfo=_no_console_startupinfo())
        if change.returncode != 0:
            detail = _wm_last_line(change.stderr, change.stdout) or f"rc={change.returncode}"
            self._report_failure(f"PROGRESS:{label}:bcdedit refused the change: {detail}")
            return

        if scheduled:
            self.queue.put(f"PROGRESS:{label}:Safe Mode is switched OFF -- Windows starts normally again.")
            if in_safe_mode:
                self.queue.put(f"REBOOTRECOMMEND:{label}:Safe Mode was switched off; restart to "
                               f"leave it.")
        else:
            self.queue.put(f"PROGRESS:{label}:Safe Mode with Networking is switched ON. It stays on for "
                           f"EVERY restart until you run this task again to switch it off.")
            self.queue.put(f"REBOOTRECOMMEND:{label}:Safe Mode with Networking is switched on; the "
                           f"next restart -- and every one after it, until you switch it off "
                           f"here -- starts in Safe Mode.")

    def run_boot_advanced_options(self):
        # Prompt user first to prevent accidentally restarting the computer.
        # This deliberately uses the module-global `messagebox` (the Qt shim): a
        # local `from tkinter import messagebox` used to shadow it here, which
        # meant the one confirmation standing between a click and an immediate
        # reboot was built by a second toolkit, off the UI thread.
        response = messagebox.askyesno("Reboot Required", "Are you sure you want to reboot into the Advanced Startup / BIOS menu? Your computer will restart immediately. Ensure all work is saved.", icon='warning')
        if not response:
            self._report_skip("PROGRESS:Advanced Boot:Reboot cancelled by user.")
            return

        self.queue.put("PROGRESS:Advanced Boot:Preparing to reboot into Advanced Options / Firmware...")
        self.queue.put("PROGRESS:Advanced Boot:Attempting to schedule UEFI firmware reboot...")
        
        # Try to set UEFI boot flag
        res = wm_run(['shutdown', '/r', '/fw', '/f', '/t', '0'], capture_output=True, timeout=15, startupinfo=_no_console_startupinfo())
        if res.returncode != 0:
            self.queue.put("PROGRESS:Advanced Boot:Firmware boot unavailable (legacy BIOS?). Falling back to Advanced Options menu...")
            res2 = wm_run(['shutdown', '/r', '/o', '/f', '/t', '0'], capture_output=True, timeout=15, startupinfo=_no_console_startupinfo())
            if res2.returncode != 0:
                self._report_failure("PROGRESS:Advanced Boot:Windows refused both the firmware and the "
                                     "Advanced Options restart -- nothing was scheduled.")

    def perform_disable_fast_startup(self):
        """Disable Windows Fast Startup (the hybrid shutdown), keeping Hibernate."""
        label = "Disable Fast Startup"
        self.queue.put(f"PROGRESS:{label}:Starting fast startup disable process...")
        registry_key_path = r"SYSTEM\CurrentControlSet\Control\Session Manager\Power"
        try:
            SecurityUtils.validate_registry_key(registry_key_path)
            # Only HiberbootEnabled. The old version also ran `powercfg /h off`,
            # which switches hibernation off altogether -- deleting hiberfil.sys
            # and the Hibernate option with it, including a laptop's
            # hibernate-on-low-battery -- a far bigger change than the name says.
            self.queue.put(f"PROGRESS:{label}:Setting HiberbootEnabled to 0...")
            with create_reg_key(winreg.HKEY_LOCAL_MACHINE, registry_key_path) as key:
                winreg.SetValueEx(key, "HiberbootEnabled", 0, winreg.REG_DWORD, 0)
            with open_reg_key(winreg.HKEY_LOCAL_MACHINE, registry_key_path, winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, "HiberbootEnabled")
            if value != 0:
                self._report_failure(f"PROGRESS:{label}:HiberbootEnabled still reads {value} after the "
                                     f"write -- a policy may be setting it.")
                return
            self.queue.put(f"PROGRESS:{label}:Fast startup disabled (HiberbootEnabled=0, verified). "
                           f"Shutdowns are now full shutdowns; Hibernate is still available.")
            try:
                with open_reg_key(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Power",
                                  winreg.KEY_READ) as key:
                    if winreg.QueryValueEx(key, "HibernateEnabled")[0] == 0:
                        self.queue.put(f"PROGRESS:{label}:Note: hibernation itself is switched off on this "
                                       f"PC (earlier WinMend versions did that). 'Reset Windows "
                                       f"Defaults' turns it back on.")
            except OSError:
                pass
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error disabling fast startup: {str(e)}")

    def run_boot_time_analyzer(self):
        """Report recent boot durations and what slowed them, from the event log.

        Windows writes these records through the Diagnostic Policy Service, and
        RAM Optimizations disables that service. With it off nothing new is
        recorded: the log either holds nothing, which used to surface as a bare
        "No events were found", or only boots from before it was turned off,
        which used to be listed as if they were recent. Both now say so.
        """
        label = "Boot Time"
        dps = service_state("DPS")
        dps_off = None
        if dps is not None and dps.get("status") != "running":
            how = "disabled" if dps.get("start") == "disabled" else "not running"
            dps_off = (f"Windows times each start through the Diagnostic Policy Service, which is "
                       f"{how} on this PC (RAM Optimizations disables it), so starts are not being "
                       f"measured. To measure them again, set that service to Automatic in "
                       f"services.msc, or run 'Reset Windows Defaults (Undo Tweaks)', which undoes "
                       f"all of RAM Optimizations. The first restart after that is recorded.")
        self.queue.put(f"PROGRESS:{label}:Reading the boot-performance event log...")
        ps_script = r'''
        try {
            $log = 'Microsoft-Windows-Diagnostics-Performance/Operational'
            $boots = @(Get-WinEvent -FilterHashtable @{ LogName = $log; Id = 100 } -MaxEvents 10 -ErrorAction Stop)
            "NEWEST=" + $boots[0].TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss')
            "== Last $($boots.Count) boot(s) =="
            foreach ($e in $boots) {
                $x = [xml]$e.ToXml(); $d = @{}
                foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
                "{0:yyyy-MM-dd HH:mm}   total {1,6:N1}s   (to desktop {2,6:N1}s, background {3,6:N1}s)   {4}" -f `
                    $e.TimeCreated, ([double]$d['BootTime'] / 1000),
                    ([double]$d['MainPathBootTime'] / 1000),
                    ([double]$d['BootPostBootTime'] / 1000), $e.LevelDisplayName
            }
            $slow = Get-WinEvent -FilterHashtable @{ LogName = $log; Id = @(101,102,103,106,109,110) } -MaxEvents 8 -ErrorAction SilentlyContinue
            if ($slow) {
                "== What slowed boot down recently =="
                foreach ($e in $slow) { "{0:yyyy-MM-dd}   {1}" -f $e.TimeCreated, (($e.Message -split "`r?`n")[0]) }
            }
        } catch {
            # Unelevated, an unreadable log reports this too, not access denied.
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { 'NOEVENTS'; exit 0 }
            "ERROR: Could not read the boot-performance log: $($_.Exception.Message)"; exit 1
        }
        '''
        try:
            r = self._run_ps(ps_script)
            newest, lines = None, []
            for line in (r.stdout or "").splitlines():
                if line.startswith("NEWEST="):
                    try:
                        newest = datetime.strptime(line[7:].strip(), "%Y-%m-%dT%H:%M:%S") \
                            .replace(tzinfo=timezone.utc).timestamp()
                    except ValueError:
                        pass
                elif line.strip():
                    lines.append(line.rstrip())
            if r.returncode == 0 and lines == ["NOEVENTS"]:
                if not self.admin_status:
                    reason = ("This log can only be read with administrator rights; restart WinMend "
                              "as administrator.")
                elif dps_off:
                    reason = dps_off
                else:
                    reason = ("Windows writes a record a few minutes after each start; restart, wait "
                              "five minutes, then run this again.")
                self._report_failure(f"PROGRESS:{label}:Windows has no boot timing on record. {reason}")
                return
            if r.returncode != 0 or not lines:
                detail = "\n".join(lines or [(r.stderr or 'No boot events found.').strip()])[:200]
                if not self.admin_status:
                    detail += " -- this log needs administrator rights; restart WinMend as administrator"
                self._report_failure(f"PROGRESS:{label}:{detail}")
                return
            for line in lines:
                self.queue.put(f"PROGRESS:{label}:{line}")
            try:
                import psutil
                booted = psutil.boot_time()
            except Exception:
                booted = None
            if newest is not None and booted is not None and newest < booted:
                stamp = datetime.fromtimestamp(newest).strftime("%Y-%m-%d %H:%M")
                started = datetime.fromtimestamp(booted).strftime("%Y-%m-%d %H:%M")
                if dps_off:
                    self.queue.put(f"PROGRESS:{label}:These are older starts: the newest record is "
                                   f"from {stamp}, and this PC has started again since then "
                                   f"({started}). {dps_off}")
                else:
                    self.queue.put(f"PROGRESS:{label}:The current start ({started}) is not in the "
                                   f"record. Windows adds one a few minutes after the desktop "
                                   f"appears, and does not time every start.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")
