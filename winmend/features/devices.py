"""WinMend features: devices."""

from __future__ import annotations

from winmend.core.prompts import messagebox
from winmend.features.office.helpers import service_state
import os
import re


class DevicesTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    def run_clear_print_spooler(self):
        label = "Print Spooler"
        self.queue.put(f"PROGRESS:{label}:Stopping Print Spooler service...")
        rc, _ = self._run_live_command(['net', 'stop', 'spooler', '/y'], label, timeout=30)
        if self.cancel_event.is_set():
            return
        stopped = service_state("Spooler") or {}
        if stopped.get("status") != "stopped":
            self._report_failure(f"PROGRESS:{label}:The Print Spooler could not be confirmed stopped "
                                 f"(rc={rc}, now {stopped.get('status', 'unknown')}); print jobs were left in place.")
            return

        spool = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'spool', 'PRINTERS')
        self.queue.put(f"PROGRESS:{label}:Deleting stuck print jobs in {spool}...")
        removed = locked = 0
        try:
            for entry in os.scandir(spool):
                if entry.is_file():
                    try:
                        os.remove(entry.path)
                        removed += 1
                    except OSError:
                        locked += 1
        except OSError as exc:
            self._report_failure(f"PROGRESS:{label}:Could not open the spool folder: {exc}")
        self.queue.put(f"PROGRESS:{label}:Removed {removed} spooled file(s)"
                       + (f"; {locked} still locked" if locked else "") + ".")
        if locked:
            self._report_failure(f"PROGRESS:{label}:{locked} spooled file(s) could not be removed.")

        self.queue.put(f"PROGRESS:{label}:Starting Print Spooler service...")
        rc, _ = self._run_live_command(['net', 'start', 'spooler'], label, timeout=30)
        state = service_state("Spooler") or {}
        if state.get("status") == "running":
            if getattr(self, "_task_failure", None):
                self.queue.put(f"PROGRESS:{label}:Print Spooler is running again; queue cleanup was incomplete.")
            else:
                self.queue.put(f"PROGRESS:{label}:Print Spooler cleared and running again.")
        else:
            self._report_failure(f"PROGRESS:{label}:The Print Spooler did not start again "
                                 f"(rc={rc}, now {state.get('status', 'unknown')}). Nothing will "
                                 f"print until it does.")

    def run_usb_enumerate(self):
        """List USB devices, and offer to safely eject USB drives when there are any."""
        label = "USB Devices"
        self.queue.put(f"PROGRESS:{label}:Enumerating USB devices...")
        try:
            r = self._run_ps(
                "Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | "
                "Where-Object { $_.InstanceId -match '^USB' } | "
                "Select-Object Class, FriendlyName, Status | Format-Table -AutoSize | Out-String -Width 200",
                timeout=60)
            output = (r.stdout or "").strip()
            if r.returncode != 0:
                self._report_failure(f"PROGRESS:{label}:USB enumeration failed: "
                                     f"{(r.stderr or output or str(r.returncode)).strip()}")
                return
            if output:
                for line in output.splitlines():
                    if line.strip():
                        self.queue.put(f"PROGRESS:{label}:  {line.rstrip()}")
            else:
                self.queue.put(f"PROGRESS:{label}:No USB devices detected.")

            # Only offer to eject when there is something to eject: removable
            # volumes, plus volumes on USB-attached disks (external drives
            # report as fixed, not removable).
            drives = self._run_ps(
                "$l = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2' -ErrorAction SilentlyContinue | "
                "ForEach-Object { $_.DeviceID }); "
                "$l += @(Get-Disk -ErrorAction SilentlyContinue | Where-Object { $_.BusType -eq 'USB' } | "
                "Get-Partition -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter } | "
                "ForEach-Object { \"$($_.DriveLetter):\" }); $l | Sort-Object -Unique", timeout=60)
            letters = sorted({d.strip().upper() for d in (drives.stdout or "").splitlines()
                              if re.fullmatch(r"[A-Za-z]:", d.strip())})
            if not letters:
                self.queue.put(f"PROGRESS:{label}:No USB drive is connected -- nothing to eject.")
                return
            if not messagebox.askyesno(
                    "Safely Eject USB Drives",
                    f"Safely eject {', '.join(letters)} now?\n\n(No data is lost; Windows finishes "
                    f"writing to the drive first. Close any files open on it.)"):
                return

            eject = r'''
            $shell = New-Object -ComObject Shell.Application
            foreach ($d in @(%LETTERS%)) {
                $item = $shell.NameSpace(17).ParseName($d)
                if ($item) { $item.InvokeVerb('Eject') }
            }
            Start-Sleep -Seconds 4
            foreach ($d in @(%LETTERS%)) { if (Test-Path "$d\") { Write-Output "STILL|$d" } else { Write-Output "GONE|$d" } }
            '''.replace("%LETTERS%", ",".join(f"'{d}'" for d in letters))
            result = self._run_ps(eject, timeout=60)
            if result.returncode != 0 or not (result.stdout or "").strip():
                self._report_failure(f"PROGRESS:{label}:Ejection could not be verified: "
                                     f"{(result.stderr or 'no result returned').strip()}")
                return
            for line in (result.stdout or "").splitlines():
                kind, _, drive = line.strip().partition("|")
                if kind == "GONE":
                    self.queue.put(f"PROGRESS:{label}:{drive} ejected -- safe to unplug.")
                elif kind == "STILL":
                    self._report_failure(f"PROGRESS:{label}:{drive} is still in use and was not ejected. "
                                         f"Close anything using it and try again.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")

    def run_bluetooth_repair(self):
        """Restart Bluetooth services and power-cycle the radio."""
        label = "Bluetooth"
        self.queue.put(f"PROGRESS:{label}:Restarting Bluetooth services and radio...")
        ps_script = r'''
        $out = @()
        foreach ($svc in 'bthserv', 'BthAvctpSvc') {
            $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if (-not $s) { continue }
            # Both ship as Manual (started on demand). Only a service someone
            # switched off is changed -- the old script made both Automatic.
            if ("$($s.StartType)" -eq 'Disabled') {
                try { Set-Service -Name $svc -StartupType Manual -ErrorAction Stop; $out += "Switched $svc back on (Manual, the Windows default)" }
                catch { $out += "WM_FAIL|$svc is switched off and could not be switched back on: $($_.Exception.Message)" }
            }
            try { Restart-Service -Name $svc -Force -ErrorAction Stop; $out += "Restarted service: $svc" }
            catch {
                try { Start-Service -Name $svc -ErrorAction Stop; $out += "Started service: $svc" }
                catch { $out += "WM_FAIL|could not start ${svc}: $($_.Exception.Message)" }
            }
        }
        $all = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue
        if (-not $all) { $out += "WM_NOHW" }
        else {
            # Radios enumerate on USB/PCI; paired peripherals enumerate as BTHENUM/BTHLE.
            $radios = @($all | Where-Object { $_.InstanceId -notlike 'BTH*' })
            foreach ($r in $radios) {
                try {
                    Disable-PnpDevice -InstanceId $r.InstanceId -Confirm:$false -ErrorAction Stop
                    Start-Sleep -Seconds 2
                    Enable-PnpDevice -InstanceId $r.InstanceId -Confirm:$false -ErrorAction Stop
                    $out += "Power-cycled radio: $($r.FriendlyName)"
                } catch { $out += "WM_FAIL|could not power-cycle $($r.FriendlyName): $($_.Exception.Message)" }
            }
            if (-not $radios.Count) { $out += "Services restarted; no separate radio device to power-cycle." }
        }
        $out
        '''
        try:
            r = self._run_ps(ps_script, timeout=120)
            lines = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()]
            if not lines:
                self._report_failure(f"PROGRESS:{label}:No output — "
                                     f"{(r.stderr or 'unknown error').strip()[:200]}")
                return
            for line in lines:
                if not line.startswith("WM_"):
                    self.queue.put(f"PROGRESS:{label}:{line}")
            failures = [line.split("|", 1)[1] for line in lines if line.startswith("WM_FAIL|")]
            for why in failures:
                self._report_failure(f"PROGRESS:{label}:{why}")
            if "WM_NOHW" in lines:
                self._report_failure(f"PROGRESS:{label}:Windows lists no Bluetooth hardware. If this PC "
                                     f"has Bluetooth, check that airplane mode is off and the radio is "
                                     f"enabled in the BIOS, then install its driver (Install System "
                                     f"Drivers).")
            elif not failures:
                self.queue.put(f"PROGRESS:{label}:Done. Re-pair the device if it still won't connect.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")

    def run_audio_repair(self):
        """Restart Windows audio services; the standard 'no sound' fix."""
        label = "Audio Repair"
        self.queue.put(f"PROGRESS:{label}:Restarting Windows audio services...")
        ps_script = r'''
        $out = @()
        foreach ($svc in 'AudioEndpointBuilder', 'Audiosrv') {
            $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if (-not $s) { $out += "WM_FAIL|the $svc service is missing"; continue }
            try { Set-Service -Name $svc -StartupType Automatic -ErrorAction SilentlyContinue } catch {}
            try { Restart-Service -Name $svc -Force -ErrorAction Stop }
            catch { try { Start-Service -Name $svc -ErrorAction Stop } catch {} }
            $s = Get-Service -Name $svc
            $out += "$svc is now $($s.Status)"
            if ("$($s.Status)" -ne 'Running') { $out += "WM_FAIL|$svc would not start" }
        }
        $dev = Get-CimInstance Win32_SoundDevice -ErrorAction SilentlyContinue |
               Select-Object -ExpandProperty Name
        if ($dev) { $out += "Sound devices: " + ($dev -join '; ') }
        else { $out += "No sound devices detected." }
        $out
        '''
        try:
            r = self._run_ps(ps_script, timeout=90)
            lines = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()]
            if not lines:
                self._report_failure(f"PROGRESS:{label}:No output — "
                                     f"{(r.stderr or 'unknown error').strip()[:200]}")
                return
            for line in lines:
                if not line.startswith("WM_"):
                    self.queue.put(f"PROGRESS:{label}:{line}")
            for line in lines:
                if line.startswith("WM_FAIL|"):
                    self._report_failure(f"PROGRESS:{label}:{line.split('|', 1)[1]}")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")
