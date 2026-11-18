"""WinMend features: security."""

from __future__ import annotations

from datetime import datetime
from winmend.core.processes import _no_console_startupinfo, wm_run
from winmend.core.search import _wm_last_line
import html as _html
import json
import os
import platform
import time
import webbrowser
import winreg


class SecurityTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    def run_defender_scan(self):
        """Trigger a full system scan using Windows Defender"""
        self.queue.put("PROGRESS:Defender Full Scan:Starting Windows Defender full system scan...")
        self.queue.put("PROGRESS:Defender Full Scan:This will take a LONG time. Scan runs in the background.")

        try:
            # Find MpCmdRun.exe
            mp_path = os.path.join(os.environ.get('ProgramFiles', r'C:\Program Files'),
                                   'Windows Defender', 'MpCmdRun.exe')
            if not os.path.exists(mp_path):
                # Try alternate location
                mp_path = os.path.join(os.environ.get('ProgramW6432', r'C:\Program Files'),
                                       'Windows Defender', 'MpCmdRun.exe')

            if not os.path.exists(mp_path):
                self._report_failure("PROGRESS:Defender Full Scan:MpCmdRun.exe not found. Is Windows Defender installed?")
                return

            self.queue.put(f"PROGRESS:Defender Full Scan:Using: {mp_path}")
            self.queue.put("PROGRESS:Defender Full Scan:Updating definitions first...")

            # Update definitions
            rc, _ = self._run_live_command(
                [mp_path, '-SignatureUpdate'], 'Defender Full Scan', timeout=120)
            if self.cancel_event.is_set():
                return
            if rc != 0:
                self._report_failure(f"PROGRESS:Defender Full Scan:Definition update failed (code {rc}); "
                                     "the scan will use the existing definitions.")

            # Start full scan
            self.queue.put("PROGRESS:Defender Full Scan:Starting full scan (type 2)...")
            rc, timed_out = self._run_live_command(
                [mp_path, '-Scan', '-ScanType', '2'], 'Defender Full Scan', timeout=7200)  # 2hr timeout

            if rc == 0:
                self.queue.put("PROGRESS:Defender Full Scan:Full scan completed. Review the output above and Windows Security for findings and remediation.")
            elif rc == 2:
                # Microsoft documents code 2 as either a scan error or malware
                # requiring action; it is not proof that a threat was found.
                self._report_failure("PROGRESS:Defender Full Scan:Defender reported scan errors or threats needing further action (code 2). Open Windows Security and review the output above.")
            elif not self.cancel_event.is_set():
                # Most often another antivirus is in charge and Defender is in
                # passive mode, which refuses on-demand scans.
                self._report_failure(f"PROGRESS:Defender Full Scan:The scan did not run (code "
                                     f"0x{rc & 0xFFFFFFFF:08X}). If another antivirus is installed, "
                                     f"scan with that instead.")

        except Exception as e:
            self._report_failure(f"PROGRESS:Defender Full Scan:Error: {str(e)}")

    def run_smart_malware_remediation(self):
        """Run layered malware remediation and persistence inventory, and write a Desktop report."""
        label = "Smart Malware"
        self.queue.put(f"PROGRESS:{label}:Starting smart remediation workflow...")
        try:
            desktop = self._get_desktop_dir()
            ts = time.strftime("%Y%m%d_%H%M%S")
            report_path = os.path.join(desktop, f"Smart_Malware_Remediation_{ts}.txt")

            ps_script = r'''
            Write-Output "Updating Defender signatures..."
            try { Update-MpSignature -ErrorAction Stop; Write-Output "Signatures updated." }
            catch { Write-Output "Signature update failed: $($_.Exception.Message)" }
            Write-Output "Running Defender quick scan..."
            try { Start-MpScan -ScanType QuickScan -ErrorAction Stop; Write-Output "Quick scan finished." }
            catch { Write-Output "WM_SCANFAIL|$($_.Exception.Message)" }
            Write-Output ""
            Write-Output "Recent threat detections:"
            $det = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Sort-Object InitialDetectionTime -Descending | Select-Object -First 30)
            if ($det) { $det | Format-Table InitialDetectionTime, ThreatID, ActionSuccess, Resources -AutoSize | Out-String -Width 240 }
            else { Write-Output "  None recorded." }
            Write-Output ""
            Write-Output "Startup persistence inventory:"
            Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | Format-Table Name, Command, Location, User -AutoSize | Out-String -Width 260
            Write-Output "Scheduled tasks from outside Microsoft:"
            Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
                $actions = @($_.Actions | ForEach-Object { ("$($_.Execute) $($_.Arguments)").Trim() }) -join ' ; '
                [pscustomobject]@{ Task = $_.TaskPath + $_.TaskName; State = $_.State; RunsAs = $_.Principal.UserId; Action = $actions }
            } | Format-Table -AutoSize | Out-String -Width 260
            '''

            # One run, streamed to the log and captured for the report. The old
            # version ran the whole script a second time just to capture its
            # text, which updated signatures and ran the quick scan twice.
            lines = []
            rc, _ = self._run_live_command(['powershell', '-NoProfile', '-ExecutionPolicy', 'RemoteSigned',
                                    '-Command', ps_script], label, output=lines)
            if self.cancel_event.is_set():
                return
            if rc != 0 or not lines:
                self._report_failure(f"PROGRESS:{label}:The Defender workflow did not produce a complete result (code {rc}).")
            scan_failure = next((line.split("|", 1)[1] for line in lines
                                 if line.startswith("WM_SCANFAIL|")), "")

            report = ["=== WINMEND SMART MALWARE REMEDIATION REPORT ===",
                      f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "",
                      "=== Defender + Persistence Inventory ==="]
            report += [line for line in lines if not line.startswith("WM_SCANFAIL|")]
            try:
                with open(report_path, 'w', encoding='utf-8') as f:
                    f.write("\n".join(report))
                self.queue.put(f"PROGRESS:{label}:Report saved to {report_path}")
            except Exception as write_err:
                self._report_failure(f"PROGRESS:{label}:Could not write report file: {write_err}")

            if scan_failure:
                self._report_failure(f"PROGRESS:{label}:Defender could not scan ({scan_failure}). If "
                                     f"another antivirus is installed, scan with that instead.")
            self.run_msrt_scan()
            self.queue.put(f"PROGRESS:{label}:Remediation workflow complete.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {str(e)}")

    def run_firewall_audit(self):
        """Inventory enabled inbound firewall rules and flag unsigned programs."""
        label = "Firewall Audit"
        self.queue.put(f"PROGRESS:{label}:Inventorying enabled inbound firewall rules...")
        try:
            desktop = self._get_desktop_dir()
            ts = time.strftime("%Y%m%d_%H%M%S")
            report_path = os.path.join(desktop, f"Firewall_Audit_{ts}.txt")

            # Rules store program paths the way Windows writes them --
            # %SystemRoot%\system32\svchost.exe -- and Test-Path does not expand
            # variables, so the old audit skipped every such rule. The filters
            # are also read in one call and joined by rule, instead of one
            # lookup per rule, and each program's signature is checked once.
            ps_script = r'''
            $apps = @{}
            Get-NetFirewallApplicationFilter -All -ErrorAction SilentlyContinue | ForEach-Object { $apps[$_.InstanceID] = $_.Program }
            $sigs = @{}
            $rows = @()
            $rules = @(Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue)
            foreach ($r in $rules) {
                $prog = [Environment]::ExpandEnvironmentVariables("$($apps[$r.InstanceID])")
                $flag = ""
                if ($prog -and $prog -ne "Any" -and $prog -ne "System" -and (Test-Path -LiteralPath $prog -ErrorAction SilentlyContinue)) {
                    if (-not $sigs.ContainsKey($prog)) {
                        $status = 'Unknown'
                        try { $status = "$((Get-AuthenticodeSignature -FilePath $prog -ErrorAction Stop).Status)" } catch {}
                        $sigs[$prog] = $status
                    }
                    if ($sigs[$prog] -ne 'Valid') { $flag = "[FLAG] " }
                }
                $rows += [pscustomobject]@{
                    Flag    = $flag
                    Name    = $r.DisplayName
                    Profile = ($r.Profile -join ',')
                    Action  = $r.Action
                    Program = $prog
                }
            }
            Write-Output "Rules checked: $($rules.Count); programs checked: $($sigs.Count)"
            $rows | Sort-Object -Property @{Expression="Flag";Descending=$true}, Name | Format-Table -AutoSize | Out-String -Width 220
            '''
            r = wm_run(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'RemoteSigned', '-Command', ps_script],
                capture_output=True, text=True, encoding='utf-8', errors='replace',
                cancel_event=self.cancel_event, startupinfo=_no_console_startupinfo()
            )
            if self.cancel_event.is_set():
                return
            if not (r.stdout or "").strip():
                self._report_failure(f"PROGRESS:{label}:The firewall rules could not be read: "
                                     f"{_wm_last_line(r.stderr) or r.returncode}")
                return

            with open(report_path, 'w', encoding='utf-8') as f:
                f.write("=== EAWTECH FIREWALL RULES AUDIT ===\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write("Lines beginning with [FLAG] open a port for an unsigned or\n")
                f.write("invalid-signature executable. Review them carefully.\n\n")
                f.write(r.stdout or "(no output)")
                if r.stderr and r.stderr.strip():
                    f.write("\n\n=== stderr ===\n")
                    f.write(r.stderr.strip())

            flagged = (r.stdout or "").count("[FLAG]")
            summary = next((ln.strip() for ln in (r.stdout or "").splitlines()
                            if ln.startswith("Rules checked:")), "")
            self.queue.put(f"PROGRESS:{label}:Report saved to {report_path}")
            if summary:
                self.queue.put(f"PROGRESS:{label}:{summary}")
            self.queue.put(f"PROGRESS:{label}:Flagged inbound rules: {flagged}.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")

    def run_security_posture_report(self):
        """Collect security posture and build an HTML report on the Desktop."""
        label = "Security Report"
        self.queue.put(f"PROGRESS:{label}:Collecting Defender, UAC, SmartScreen, "
                       f"BitLocker, and firewall state...")
        ps_script = r'''
        $ErrorActionPreference = 'SilentlyContinue'
        $mp  = Get-MpComputerStatus
        $pol = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $ss  = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer').SmartScreenEnabled
        $fw  = Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Enabled = [bool]$_.Enabled } }
        $bl  = Get-BitLockerVolume | ForEach-Object { [pscustomobject]@{ Mount = $_.MountPoint; Protection = "$($_.ProtectionStatus)" } }
        $hf  = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
        [pscustomobject]@{
            DefenderEnabled  = if ($mp) { [bool]$mp.AntivirusEnabled } else { $null }
            RealTime         = if ($mp) { [bool]$mp.RealTimeProtectionEnabled } else { $null }
            DefsAgeDays      = if ($mp) { [int]$mp.AntivirusSignatureAge } else { $null }
            TamperProtection = if ($mp) { [bool]$mp.IsTamperProtected } else { $null }
            UacEnabled       = ($pol.EnableLUA -eq 1)
            SmartScreen      = "$ss"
            Firewall         = @($fw)
            BitLocker        = @($bl)
            LastHotfix       = if ($hf) { "$($hf.HotFixID) installed $($hf.InstalledOn)" } else { 'unknown' }
        } | ConvertTo-Json -Depth 4
        '''
        try:
            r = self._run_ps(ps_script, timeout=120)
            if r.returncode != 0:
                self._report_failure(f"PROGRESS:{label}:Security data collection failed: "
                                     f"{(r.stderr or str(r.returncode)).strip()[:200]}")
                return
            try:
                data = json.loads((r.stdout or '').strip())
            except Exception:
                self._report_failure(f"PROGRESS:{label}:Could not collect security data: "
                               f"{(r.stderr or r.stdout or 'no output').strip()[:200]}")
                return

            rows = []  # (check, state: True ok / False bad / None info, detail)
            rows.append(("Defender antivirus", data.get("DefenderEnabled"),
                         "enabled" if data.get("DefenderEnabled") else "DISABLED or unavailable"))
            rows.append(("Real-time protection", data.get("RealTime"),
                         "on" if data.get("RealTime") else "OFF"))
            age = data.get("DefsAgeDays")
            rows.append(("Virus definitions", None if age is None else age <= 7,
                         "unknown" if age is None else f"{age} day(s) old"))
            rows.append(("Tamper protection", data.get("TamperProtection"),
                         "on" if data.get("TamperProtection") else "off"))
            rows.append(("UAC", bool(data.get("UacEnabled")),
                         "enabled" if data.get("UacEnabled") else "DISABLED"))
            ss = (data.get("SmartScreen") or "").strip()
            rows.append(("SmartScreen", None if not ss else ss.lower() != "off",
                         ss or "not configured"))
            fw = data.get("Firewall") or []
            if isinstance(fw, dict):
                fw = [fw]
            fw_bad = [p.get("Name") for p in fw if not p.get("Enabled")]
            rows.append(("Firewall", (not fw_bad) if fw else None,
                         "all profiles on" if fw and not fw_bad else
                         (f"OFF for: {', '.join(fw_bad)}" if fw_bad else "unknown")))
            bl = data.get("BitLocker") or []
            if isinstance(bl, dict):
                bl = [bl]
            if bl:
                on = [v.get("Mount") for v in bl if str(v.get("Protection")) in ("1", "On")]
                rows.append(("BitLocker", bool(on),
                             f"protected: {', '.join(on)}" if on else "no protected volumes"))
            else:
                rows.append(("BitLocker", None, "not available on this edition"))
            rows.append(("Latest update", None, str(data.get("LastHotfix", "unknown"))))

            for name, ok, detail in rows:
                mark = "OK " if ok else ("!! " if ok is False else "-- ")
                self.queue.put(f"PROGRESS:{label}:{mark}{name}: {detail}")

            cells = ""
            for name, ok, detail in rows:
                color = "#2e7d32" if ok else ("#c62828" if ok is False else "#616161")
                word = "PASS" if ok else ("ATTENTION" if ok is False else "INFO")
                cells += (f"<tr><td>{_html.escape(name)}</td>"
                          f"<td style='color:#fff;background:{color};text-align:center;"
                          f"font-weight:700'>{word}</td>"
                          f"<td>{_html.escape(str(detail))}</td></tr>")
            page = (
                "<html><head><meta charset='utf-8'><title>Security Posture Report</title>"
                "<style>body{font-family:Segoe UI,Arial,sans-serif;background:#101418;"
                "color:#e8eef4;margin:40px}h1{font-size:22px}table{border-collapse:collapse;"
                "min-width:640px}td,th{border:1px solid #2a3340;padding:9px 14px;font-size:14px}"
                "th{background:#1a222c;text-align:left}</style></head><body>"
                f"<h1>Security Posture Report — {platform.node()}</h1>"
                f"<p>Generated {time.strftime('%Y-%m-%d %H:%M')} by WinMend.</p>"
                "<table><tr><th>Check</th><th>Status</th><th>Detail</th></tr>"
                f"{cells}</table></body></html>")
            report_path = os.path.join(self._get_desktop_dir(),
                                       f"Security_Posture_{time.strftime('%Y%m%d_%H%M%S')}.html")
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(page)
            self.queue.put(f"PROGRESS:{label}:Report saved to {report_path}")
            try:
                webbrowser.open(f"file:///{report_path}")
            except Exception:
                pass
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")

    def run_camera_mic_audit(self):
        """List apps allowed to use the camera/microphone and when they last did."""
        label = "Camera/Mic"

        def filetime_str(v):
            if not v:
                return "never"
            try:
                secs = v / 10_000_000 - 11644473600
                return time.strftime("%Y-%m-%d %H:%M", time.localtime(secs))
            except Exception:
                return "?"

        def read_store(device):
            base = (r"Software\Microsoft\Windows\CurrentVersion"
                    r"\CapabilityAccessManager\ConsentStore" + "\\" + device)
            rows = []
            try:
                root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, base)
            except OSError:
                return rows
            with root:
                names = []
                desktop_default = None  # the 'Let desktop apps access...' toggle
                i = 0
                while True:
                    try:
                        sub = winreg.EnumKey(root, i)
                    except OSError:
                        break
                    i += 1
                    if sub == "NonPackaged":
                        try:
                            with winreg.OpenKey(root, sub) as np:
                                try:
                                    desktop_default = str(winreg.QueryValueEx(np, "Value")[0])
                                except OSError:
                                    pass
                                j = 0
                                while True:
                                    try:
                                        names.append(sub + "\\" + winreg.EnumKey(np, j))
                                    except OSError:
                                        break
                                    j += 1
                        except OSError:
                            pass
                    else:
                        names.append(sub)
                for sk in names:
                    try:
                        with winreg.OpenKey(root, sk) as k:
                            try:
                                allow = str(winreg.QueryValueEx(k, "Value")[0])
                            except OSError:
                                # Desktop apps rarely carry their own Value; they
                                # follow the store-wide desktop-apps toggle.
                                if sk.startswith("NonPackaged\\") and desktop_default:
                                    allow = desktop_default
                                else:
                                    allow = "?"
                            try:
                                last = winreg.QueryValueEx(k, "LastUsedTimeStop")[0]
                            except OSError:
                                last = 0
                        # NonPackaged keys are exe paths with '#' standing in for '\'
                        name = sk.split("\\")[-1].replace("#", "\\")
                        rows.append((name, allow, last))
                    except OSError:
                        pass
            return rows

        try:
            for device, nice in (("webcam", "Camera"), ("microphone", "Microphone")):
                rows = read_store(device)
                allowed = [r for r in rows if r[1] == "Allow"]
                self.queue.put(f"PROGRESS:{label}:== {nice}: {len(allowed)} app(s) allowed, "
                               f"{len(rows)} total ==")
                if not rows:
                    self.queue.put(f"PROGRESS:{label}:  (no per-app entries found)")
                    continue
                for name, allow, last in sorted(rows, key=lambda x: (x[1] != "Allow", -(x[2] or 0))):
                    self.queue.put(f"PROGRESS:{label}:  {allow:<6}  last used "
                                   f"{filetime_str(last):<16}  {name}")
            self.queue.put(f"PROGRESS:{label}:Change access under Settings > Privacy & "
                           f"security > Camera / Microphone.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")

    def run_account_audit(self):
        """List local accounts/admins and flag weak configurations. Read-only."""
        label = "Account Audit"
        self.queue.put(f"PROGRESS:{label}:Auditing local accounts and administrators...")
        ps_script = r'''
        $ErrorActionPreference = 'SilentlyContinue'
        "== Local accounts =="
        Get-LocalUser | Sort-Object Enabled -Descending |
            Format-Table Name, Enabled, PasswordRequired, PasswordLastSet, LastLogon -AutoSize |
            Out-String -Width 200
        $admName = (Get-LocalGroup -SID 'S-1-5-32-544').Name
        $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544')
        "== Members of $admName ($($admins.Count)) =="
        $admins | Format-Table Name, PrincipalSource -AutoSize | Out-String -Width 200
        "== Flags =="
        $flags = 0
        foreach ($u in Get-LocalUser) {
            if ($u.Enabled -and -not $u.PasswordRequired) {
                "WARNING: '$($u.Name)' is enabled and requires NO password."; $flags++
            }
        }
        foreach ($u in Get-LocalUser) {
            if ($u.SID.Value -like 'S-1-5-*-500' -and $u.Enabled) {
                "WARNING: built-in Administrator account is ENABLED."; $flags++
            }
            if ($u.SID.Value -like 'S-1-5-*-501' -and $u.Enabled) {
                "WARNING: Guest account is ENABLED."; $flags++
            }
        }
        if ($admins.Count -gt 2) { "NOTE: $($admins.Count) accounts have admin rights - review whether all are needed." }
        if ($flags -eq 0) { "No account red flags found." }
        '''
        try:
            r = self._run_ps(ps_script, timeout=60)
            text = (r.stdout or "").strip()
            if r.returncode != 0 or not text:
                self._report_failure(f"PROGRESS:{label}:Account audit failed — {(r.stderr or 'no output').strip()[:200]}")
                return
            for line in text.splitlines():
                if line.strip():
                    self.queue.put(f"PROGRESS:{label}:{line.rstrip()}")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")

    def run_open_ports_viewer(self):
        """List listening TCP/UDP ports with the owning process name."""
        label = "Open Ports"
        self.queue.put(f"PROGRESS:{label}:Collecting listening ports and their owning processes...")
        # OwningProcess is a UInt32 and Process.Id an Int32, and a PowerShell
        # hashtable treats 1234 and [uint32]1234 as different keys -- so the old
        # lookup never matched and every owner showed "(unknown)".
        ps_script = r'''
        try {
            $tcp = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                   Select-Object @{n='Proto';e={'TCP'}}, LocalAddress, LocalPort, OwningProcess
            $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
                   Select-Object @{n='Proto';e={'UDP'}}, LocalAddress, LocalPort, OwningProcess
            $all = @($tcp) + @($udp)
            $procMap = @{}
            Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procMap[[int]$_.Id] = $_.ProcessName }
            $all | ForEach-Object {
                $name = $procMap[[int]$_.OwningProcess]
                if (-not $name) { $name = "(unknown)" }
                [pscustomobject]@{
                    Proto   = $_.Proto
                    Local   = "$($_.LocalAddress):$($_.LocalPort)"
                    PID     = $_.OwningProcess
                    Process = $name
                }
            } | Sort-Object Proto, @{e={[int]$_.Local.Split(':')[-1]}} | Format-Table -AutoSize | Out-String -Width 220
        } catch {
            Write-Error $_.Exception.Message
            exit 1
        }
        '''
        try:
            r = wm_run(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'RemoteSigned', '-Command', ps_script],
                capture_output=True, text=True, encoding='utf-8', errors='replace',
                timeout=60, startupinfo=_no_console_startupinfo()
            )
            text = (r.stdout or "").strip()
            if text:
                for line in text.splitlines():
                    if line.strip():
                        self.queue.put(f"PROGRESS:{label}:  {line.rstrip()}")
            else:
                self._report_failure(f"PROGRESS:{label}:The port list could not be read: "
                                     f"{_wm_last_line(r.stderr) or r.returncode}")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")
