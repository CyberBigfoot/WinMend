"""WinMend features: system repair."""

from __future__ import annotations

import os
import re
import winreg


class SystemRepairTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    def repair_system_files(self):
        """Repair Windows system files using SFC and DISM"""
        label = "System Repair"
        self.queue.put(f"PROGRESS:{label}:Starting Windows system file repair...")
        self.queue.put(f"PROGRESS:{label}:This process may take 30 minutes or more. Please be patient.")

        def sfc(step):
            self.queue.put(f"PROGRESS:{label}:=== {step}: System File Checker (sfc /scannow) ===")
            lines = []
            # sfc writes UTF-16 when its output is piped. Read any other way,
            # every letter arrives followed by a NUL and its verdict line is
            # unreadable in the log.
            rc, _ = self._run_live_command(['sfc', '/scannow'], label, encoding='utf-16-le',
                                           output=lines)
            text = " ".join(lines).lower()
            if "did not find any integrity violations" in text:
                return rc, "clean"
            if "successfully repaired" in text:
                return rc, "repaired"
            if "unable to fix" in text:
                return rc, "unfixable"
            if "repair pending" in text:
                return rc, "pending"
            if "could not perform" in text:
                return rc, "error"
            return rc, "clean" if rc == 0 else "unknown"

        rc, first = sfc("Step 1")
        if self.cancel_event.is_set():
            return
        if first == "pending":
            self.queue.put(f"REBOOTRECOMMEND:{label}:Windows has a system repair waiting for a restart; "
                           f"run 'Repair damaged Windows files' again afterwards.")
            self._report_failure(f"PROGRESS:{label}:SFC cannot run until Windows finishes a pending "
                                 f"repair at the next restart.")
            return

        self.queue.put(f"PROGRESS:{label}:=== Step 2: DISM /Online /Cleanup-Image /RestoreHealth ===")
        dism_rc, _ = self._run_live_command(
            ['DISM', '/Online', '/Cleanup-Image', '/RestoreHealth'], label, timeout=1800)
        if self.cancel_event.is_set():
            return
        if dism_rc != 0:
            self._report_failure(f"PROGRESS:{label}:DISM could not repair the component store (code "
                                 f"{dism_rc}); SFC can only restore files from a healthy store.")

        rc, final = sfc("Step 3")
        if self.cancel_event.is_set():
            return
        verdicts = {
            "clean": "Windows system files check out -- no integrity violations.",
            "repaired": "SFC found corrupt system files and repaired them.",
            "unfixable": "SFC still finds corrupt files it cannot fix.",
            "error": "SFC could not perform the scan.",
            "unknown": f"SFC finished with code {rc}.",
        }
        message = verdicts.get(final, verdicts["unknown"])
        if final in ("unfixable", "error", "unknown"):
            self._report_failure(f"PROGRESS:{label}:{message}")
        else:
            self.queue.put(f"PROGRESS:{label}:{message}")
        if "repaired" in (first, final):
            self.queue.put(f"REBOOTRECOMMEND:{label}:Repaired system files are only loaded after a "
                           f"restart.")

    def run_chk_dsk(self):
        """Check a drive for file-system errors: now if it is free, else at the next restart."""
        label = "CHKDSK"
        system_drive = os.environ.get('SystemDrive', 'C:').upper()
        try:
            import psutil
            drives = []
            for part in psutil.disk_partitions(all=False):
                letter = part.device[:2].upper()
                if part.fstype.upper() in ("NTFS", "FAT32", "FAT", "EXFAT") and letter[1:] == ":":
                    try:
                        size = f"{psutil.disk_usage(part.mountpoint).total / 1024 ** 3:.0f} GB"
                    except OSError:
                        size = "?"
                    drives.append((letter, part.fstype, size))
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Could not list the drives: {e}")
            return
        if not drives:
            self._report_failure(f"PROGRESS:{label}:No drive that chkdsk can check was found.")
            return

        # Asked here, inside the task: the Qt runner has no pre-run prompt
        # phase, so the old version silently checked the system drive with
        # the quick mode every time, whatever the title promised.
        options = [(letter, f"{letter}  ({fs}, {size})" + ("  -- the Windows drive: checked at the next "
                                                          "restart" if letter == system_drive else ""))
                   for letter, fs, size in drives]
        drive = self._ui_radio_picker("Check Disk", "Which drive should be checked?", options,
                                      default=system_drive)
        if not drive:
            self._report_skip(f"PROGRESS:{label}:Cancelled -- nothing was checked.")
            return
        mode = self._ui_radio_picker(
            "Check Disk", f"How thorough should the check of {drive} be?",
            [("fix", "Fix file-system errors (/F) -- usually a few minutes"),
             ("thorough", "Also scan the whole surface for bad sectors (/R) -- can take hours "
                          "on a large drive")],
            default="fix")
        if not mode:
            self._report_skip(f"PROGRESS:{label}:Cancelled -- nothing was checked.")
            return
        flags = ['/F', '/R'] if mode == "thorough" else ['/F']

        # chkdsk stops to ask questions when it cannot lock the drive, and
        # with no one to answer it gave up without booking anything. For the
        # Windows drive the one question is "check at the next restart?" --
        # yes. For another drive in use, the first question offers to force it
        # off-line, which would invalidate every open file on it -- no; the
        # second is the same "at the next restart?" -- yes.
        answers = "Y\r\n" if drive == system_drive else "N\r\nY\r\n"
        self.queue.put(f"PROGRESS:{label}:Running: chkdsk {drive} {' '.join(flags)}")
        lines = []
        rc, _ = self._run_live_command(['chkdsk', drive] + flags, label, answers=answers, output=lines)
        if self.cancel_event.is_set():
            return
        booked = self._chkdsk_booked(drive)
        questions = len(re.findall(r"\(\w/\w\)", " ".join(lines)))
        if not booked and drive != system_drive and questions == 1:
            # A drive that can never be taken off-line (a page file on it) asks
            # only the restart question, which the "N" above just declined.
            rc, _ = self._run_live_command(['chkdsk', drive] + flags, label, answers="Y\r\n")
            booked = self._chkdsk_booked(drive)

        if booked:
            self.queue.put(f"PROGRESS:{label}:{drive} will be checked at the next restart "
                           f"({' '.join(flags)}). Windows shows the progress before it loads.")
            self.queue.put(f"REBOOTRECOMMEND:{label}:Check Disk is booked for {drive} and runs when "
                           f"Windows restarts -- that restart can take a long time.")
        elif questions == 0 and rc in (0, 1):
            self.queue.put(f"PROGRESS:{label}:{drive} was checked now: "
                           + ("no problems found." if rc == 0 else "errors were found and fixed."))
        else:
            self._report_failure(f"PROGRESS:{label}:{drive} was neither checked nor booked for the next "
                                 f"restart (chkdsk code {rc}). The lines above say why.")

    @staticmethod
    def _chkdsk_booked(drive):
        """True when BootExecute names `drive` for a check at the next boot.

        The value is read rather than chkntfs's output: it is locale-proof, and
        "autocheck autochk *" alone means nothing is queued.
        """
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SYSTEM\CurrentControlSet\Control\Session Manager") as key:
                entries = winreg.QueryValueEx(key, "BootExecute")[0]
        except OSError:
            return False
        wanted = drive.upper()
        return any(match.group(1).upper() == wanted
                   for entry in (entries or [])
                   for match in re.finditer(r"\\\?\?\\([A-Za-z]:)", str(entry)))

    def run_service_dependency_repair(self):
        """Turn switched-off core services back on, and start the ones that should run."""
        label = "Service Repair"
        self.queue.put(f"PROGRESS:{label}:Checking core Windows services and their dependencies...")
        # Each service's Windows default. Only a service that was switched off
        # is changed -- the old version set all nine to Automatic, turning the
        # ones Windows starts on demand (Windows Update, BITS) into
        # always-running services, which is not a repair.
        ps_script = r'''
        $defaults = [ordered]@{ wuauserv = 'demand'; bits = 'demand'; cryptsvc = 'auto'; eventlog = 'auto';
                                WinDefend = 'auto'; Dnscache = 'auto'; Dhcp = 'auto'; nlasvc = 'auto'; WlanSvc = 'auto' }
        # Defender stands down by design while another antivirus is registered,
        # and Windows will not let anything start it then.
        $otherAv = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue |
                     Where-Object { $_.displayName -notmatch 'Defender' })
        foreach ($name in $defaults.Keys) {
            $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
            if (-not $svc) { Write-Output "Not installed on this PC: $name"; continue }
            if ($name -eq 'WinDefend' -and $otherAv) {
                Write-Output "Left alone: WinDefend -- $($otherAv[0].displayName) is the active antivirus, so Defender stays off by design"
                continue
            }
            $want = $defaults[$name]
            if ($svc.StartType -eq 'Disabled') {
                $out = & sc.exe config $name start= $want 2>&1
                if ($LASTEXITCODE -eq 0) { Write-Output "Switched back on: $name (start type $want)" }
                else { Write-Output ("WM_FAIL|$name|was switched off and Windows refused to change it: " + (($out | Out-String).Trim())) }
            }
            if ($want -ne 'auto') { Write-Output "OK: $name starts on demand, as Windows intends"; continue }
            $svc = Get-Service -Name $name
            if ($svc.Status -eq 'Running') { Write-Output "OK: $name is running"; continue }
            foreach ($dep in $svc.RequiredServices) {
                if ($dep.Status -ne 'Running') {
                    try { Start-Service -Name $dep.Name -ErrorAction Stop; Write-Output "Started dependency $($dep.Name) for $name" }
                    catch { Write-Output "Could not start dependency $($dep.Name) for ${name}: $($_.Exception.Message)" }
                }
            }
            try { Start-Service -Name $name -ErrorAction Stop; Write-Output "Started: $name" }
            catch { Write-Output ("WM_FAIL|$name|would not start: " + $_.Exception.Message) }
        }
        '''
        try:
            lines = []
            rc, _ = self._run_live_command(['powershell', '-NoProfile', '-ExecutionPolicy', 'RemoteSigned',
                                    '-Command', ps_script], label, output=lines)
            if self.cancel_event.is_set():
                return
            if rc != 0 or not lines:
                self._report_failure(f"PROGRESS:{label}:Service repair returned no complete result (code {rc}).")
                return
            failures = [line.split("|", 2) for line in lines if line.startswith("WM_FAIL|")]
            for _tag, name, why in failures:
                self._report_failure(f"PROGRESS:{label}:{name} {why}")
            if not failures:
                self.queue.put(f"PROGRESS:{label}:Service dependency repair completed.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {str(e)}")
