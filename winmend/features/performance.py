"""WinMend features: performance."""

from __future__ import annotations

from winmend.core.processes import _no_console_startupinfo, wm_run
from winmend.core.prompts import messagebox
from winmend.core.search import _wm_last_line
from winmend.core.security import SecurityUtils
import ctypes
import subprocess
import winreg


class PerformanceTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    def run_ram_optimizations(self):
        """Reclaim the RAM four always-on background services hold.

        Stops and disables SysMain, DiagTrack, Windows Search and the Diagnostic
        Policy Service; turns off optional diagnostic data and Delivery
        Optimization peer downloads; and turns memory compression off when
        Get-MMAgent reports it on.

        Order is deliberate: the MMAgent step runs FIRST, while SysMain is still
        running. Disable-MMAgent drives the Store Manager that SysMain hosts, and
        once that service is stopped and set to Disabled the cmdlet can refuse --
        so doing it last would silently leave memory compression on.

        Nothing here is measured by assuming the commands worked: after the
        script finishes, every one of the seven settings is read back off the
        machine and reported from that reading.
        """
        label = "RAM Optimizations"
        if not messagebox.askyesno(
            "RAM Optimizations",
            "This frees the memory and CPU four background services hold onto:\n\n"
            "  - SysMain (Superfetch) - stopped and disabled\n"
            "  - Connected User Experiences and Telemetry - stopped and disabled\n"
            "  - Windows Search - stopped and disabled\n"
            "  - Diagnostic Policy Service - stopped and disabled\n"
            "  - Send optional diagnostic data - turned off\n"
            "  - Delivery Optimization downloads from other PCs - turned off\n"
            "  - Memory compression - turned off if Get-MMAgent reports it on\n\n"
            "What you give up: Windows stops indexing for search, so searching "
            "inside files gets slower, and while the Diagnostic Policy Service is "
            "disabled the built-in Windows troubleshooters stop working and Windows "
            "stops recording how long each start takes (Boot Time Analyzer reads "
            "that record).\n\n"
            "All of it is reversible - 'Reset Windows Defaults (Undo Tweaks)' in "
            "Repair & Recovery turns every one of these back on.\n\n"
            "A restart is recommended when this finishes.\n\nContinue?"
        ):
            self._report_skip(f"PROGRESS:{label}:Cancelled by user.")
            return

        self.queue.put(f"PROGRESS:{label}:Applying RAM optimizations...")

        ps_script = r"""
        $ErrorActionPreference = "Continue"

        function Disable-WMService {
            param([string]$Name, [string]$Friendly)

            $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
            if (-not $svc) {
                Write-Host "$Friendly ($Name): not present on this Windows build - skipped"
                return
            }

            # Stopping a service takes its dependents down with it. Name them
            # rather than letting them vanish quietly.
            $running = @($svc.DependentServices | Where-Object { $_.Status -eq 'Running' })
            if ($running.Count -gt 0) {
                $names = ($running | ForEach-Object { $_.Name }) -join ', '
                Write-Host "$Friendly ($Name): these dependent services stop with it: $names"
            }

            if ($svc.Status -ne 'Stopped') {
                try {
                    Stop-Service -Name $Name -Force -ErrorAction Stop
                    Write-Host "$Friendly ($Name): stopped"
                } catch {
                    Write-Host "$Friendly ($Name): could not stop - $($_.Exception.Message)"
                }
            } else {
                Write-Host "$Friendly ($Name): already stopped"
            }

            try {
                Set-Service -Name $Name -StartupType Disabled -ErrorAction Stop
            } catch {
                # Protected services refuse Set-Service; sc.exe writes the same
                # Start value. ('sc' alone is an alias for Set-Content.)
                $out = & sc.exe config $Name start= disabled
                Write-Host "$Friendly ($Name): Set-Service refused, used sc.exe instead - $(($out | Out-String).Trim())"
            }

            $after = Get-Service -Name $Name -ErrorAction SilentlyContinue
            $start = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -Name Start -ErrorAction SilentlyContinue).Start
            Write-Host "$Friendly ($Name): now $($after.Status), start type $($after.StartType) (registry Start=$start, 4=disabled)"
        }

        Write-Host "=== Memory compression (first, while SysMain is still running) ==="
        $mm = $null
        try { $mm = Get-MMAgent -ErrorAction Stop } catch {
            Write-Host "Get-MMAgent failed: $($_.Exception.Message)"
        }
        if ($mm) {
            Write-Host "Get-MMAgent reports MemoryCompression = $($mm.MemoryCompression)"
            if ($mm.MemoryCompression) {
                try {
                    Disable-MMAgent -MemoryCompression -ErrorAction Stop
                    $now = (Get-MMAgent).MemoryCompression
                    Write-Host "Disable-MMAgent -MemoryCompression applied; MemoryCompression is now $now"
                } catch {
                    Write-Host "Disable-MMAgent -MemoryCompression failed: $($_.Exception.Message)"
                }
            } else {
                Write-Host "Memory compression is already off - nothing to change"
            }
        }

        Write-Host "=== Services ==="
        Disable-WMService -Name "SysMain"   -Friendly "SysMain (Superfetch)"
        Disable-WMService -Name "DiagTrack" -Friendly "Connected User Experiences and Telemetry"

        Write-Host "=== Send optional diagnostic data ==="
        $dc = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
        if (-not (Test-Path $dc)) { New-Item -Path $dc -Force | Out-Null }
        $cur = (Get-ItemProperty -Path $dc -Name "AllowTelemetry" -ErrorAction SilentlyContinue).AllowTelemetry
        if ($null -ne $cur -and [int]$cur -le 1) {
            # 0 (Security) is stricter than the 1 the toggle writes; do not loosen it.
            Write-Host "Send optional diagnostic data: already off (AllowTelemetry=$cur) - left as it is"
        } else {
            Set-ItemProperty -Path $dc -Name "AllowTelemetry" -Type DWord -Value 1 -Force
            $new = (Get-ItemProperty -Path $dc -Name "AllowTelemetry" -ErrorAction SilentlyContinue).AllowTelemetry
            if ($null -eq $cur) { $cur = "(not set)" }
            Write-Host "Send optional diagnostic data: off (AllowTelemetry $cur -> $new)"
        }
        $gp = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue).AllowTelemetry
        if ($null -ne $gp) {
            Write-Host "Note: a group policy also sets AllowTelemetry=$gp; that is what greys the toggle out in Settings."
        }

        Write-Host "=== Delivery Optimization: allow downloads from other devices ==="
        $doBefore = $null
        try { $doBefore = Get-DODownloadMode -ErrorAction Stop } catch {}
        if ($null -eq $doBefore) { $doBefore = "(unreadable)" }
        Write-Host "Download mode before: $doBefore"
        $doSet = $false
        if (Get-Command Set-DODownloadMode -ErrorAction SilentlyContinue) {
            try {
                Set-DODownloadMode -DownloadMode CdnOnly -ErrorAction Stop
                $doSet = $true
            } catch {
                Write-Host "Set-DODownloadMode failed: $($_.Exception.Message)"
            }
        }
        if (-not $doSet) {
            # Builds without the cmdlet: write the value the DO service reads.
            $doCfg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"
            if (-not (Test-Path $doCfg)) { New-Item -Path $doCfg -Force | Out-Null }
            Set-ItemProperty -Path $doCfg -Name "DODownloadMode" -Type DWord -Value 0 -Force
            Write-Host "Set-DODownloadMode was unavailable; wrote DODownloadMode=0 to the config key instead"
        }
        $doAfter = $null
        try { $doAfter = Get-DODownloadMode -ErrorAction Stop } catch {}
        if ($null -eq $doAfter) { $doAfter = "(unreadable)" }
        Write-Host "Download mode after: $doAfter  (CdnOnly means downloads come from Microsoft only)"

        Write-Host "=== Services (continued) ==="
        Disable-WMService -Name "WSearch" -Friendly "Windows Search"
        Disable-WMService -Name "DPS"     -Friendly "Diagnostic Policy Service"

        Write-Host "RAM optimizations applied."
        """

        try:
            rc, _ = self._run_live_command(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'RemoteSigned',
                 '-Command', ps_script],
                label, timeout=300)
            if rc != 0:
                self._report_failure(f"PROGRESS:{label}:PowerShell exited with code {rc}.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error applying RAM optimizations: {e}")
            return

        if self.cancel_event.is_set():
            return

        # ---- verify: read every setting back off the machine ----
        self.queue.put(f"PROGRESS:{label}:Reading the settings back to confirm they stuck...")
        verify_script = (
            "$ErrorActionPreference='SilentlyContinue'; "
            "foreach ($n in 'SysMain','DiagTrack','WSearch','DPS') { "
            "  $s = Get-Service -Name $n -ErrorAction SilentlyContinue; "
            "  if ($s) { \"SVC|$n|$($s.Status)|$($s.StartType)\" } else { \"SVC|$n|absent|absent\" } }; "
            "\"TELEMETRY|$((Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection'"
            " -Name AllowTelemetry -ErrorAction SilentlyContinue).AllowTelemetry)\"; "
            "$d=$null; try { $d = Get-DODownloadMode -ErrorAction Stop } catch {}; \"DO|$d\"; "
            "$m=$null; try { $m = (Get-MMAgent -ErrorAction Stop).MemoryCompression } catch {}; \"MM|$m\""
        )
        services, checks = {}, {}
        try:
            r = wm_run(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'RemoteSigned',
                 '-Command', verify_script],
                capture_output=True, text=True, encoding='utf-8', errors='replace',
                timeout=120, startupinfo=_no_console_startupinfo()
            )
            for line in (r.stdout or "").splitlines():
                line = line.strip()
                if line.startswith("SVC|"):
                    bits = line.split("|")
                    if len(bits) >= 4:
                        services[bits[1]] = (bits[2], bits[3])
                elif "|" in line:
                    k, v = line.split("|", 1)
                    checks[k] = v.strip()
        except Exception as e:
            self.queue.put(f"PROGRESS:{label}:Could not read the settings back: {e}")

        # Three buckets, kept apart on purpose: a setting that was measured and
        # is wrong is a different claim from one that could not be measured at
        # all, and neither of them may be reported as "applied".
        applied, failures, unknown = [], [], []
        services_off = []
        friendly = [
            ("SysMain", "SysMain (Superfetch)"),
            ("DiagTrack", "Connected User Experiences and Telemetry"),
            ("WSearch", "Windows Search"),
            ("DPS", "Diagnostic Policy Service"),
        ]
        for key, nice in friendly:
            status, start = services.get(key, ("", ""))
            if not status:
                unknown.append(f"{nice}: could not be read back.")
            elif status == "absent":
                self.queue.put(f"PROGRESS:{label}:{nice}: not present on this build.")
            else:
                self.queue.put(f"PROGRESS:{label}:{nice}: {status}, start type {start}.")
                stopped = status.lower() == "stopped"
                disabled = start.lower() == "disabled"
                if not stopped:
                    failures.append(f"{nice} is still {status}.")
                if not disabled:
                    failures.append(f"{nice} start type is {start}, not Disabled.")
                if stopped and disabled:
                    applied.append(f"{nice} stopped and disabled")
                    services_off.append(nice)

        tel = checks.get("TELEMETRY", "")
        if tel.isdigit() and int(tel) <= 1:
            self.queue.put(f"PROGRESS:{label}:Send optional diagnostic data: off (AllowTelemetry={tel}).")
            applied.append("optional diagnostic data off")
        elif tel:
            failures.append(f"Optional diagnostic data is still on (AllowTelemetry={tel}).")
        else:
            unknown.append("Optional diagnostic data could not be read back.")

        do_mode = checks.get("DO", "")
        if do_mode.lower() in ("cdnonly", "simple", "bypass"):
            self.queue.put(f"PROGRESS:{label}:Downloads from other devices: off (download mode {do_mode}).")
            applied.append("downloads from other devices off")
        elif do_mode:
            failures.append(f"Downloads from other devices are still allowed (download mode {do_mode}).")
        else:
            unknown.append("Delivery Optimization download mode could not be read back.")

        mem = checks.get("MM", "").lower()
        if mem == "false":
            self.queue.put(f"PROGRESS:{label}:Memory compression: off (Get-MMAgent reports MemoryCompression=False).")
            applied.append("memory compression off")
        elif mem == "true":
            failures.append("Memory compression is still on - Get-MMAgent still reports MemoryCompression=True.")
        else:
            unknown.append("Memory compression could not be read back from Get-MMAgent "
                           "(that call needs administrator rights).")

        for p in failures:
            self._report_failure(f"PROGRESS:{label}:WARNING - {p}")
        for p in unknown:
            self._report_failure(f"PROGRESS:{label}:Could not confirm the change - {p}")

        total = len(applied) + len(failures) + len(unknown)
        if not failures and not unknown:
            self.queue.put(f"PROGRESS:{label}:RESULT: all {total} change(s) confirmed on this PC.")
        else:
            tail = []
            if failures:
                tail.append(f"{len(failures)} did not take")
            if unknown:
                tail.append(f"{len(unknown)} could not be checked")
            self.queue.put(f"PROGRESS:{label}:RESULT: {len(applied)} of {total} confirmed applied, "
                           + " and ".join(tail) + ".")

        # Ask for the restart only on the strength of what was actually
        # measured, and name exactly that rather than the intended list.
        if applied:
            covered = {f"{n} stopped and disabled" for n in services_off}
            bits = []
            if services_off:
                bits.append(f"{len(services_off)} background service(s) stopped and disabled "
                            f"({', '.join(services_off)})")
            bits.extend(b for b in applied if b not in covered)
            self.queue.put(
                f"REBOOTRECOMMEND:{label}:RAM Optimizations \u2014 " + "; ".join(bits)
                + ". Windows only hands back the memory they were holding once you restart."
            )
        else:
            self.queue.put(f"PROGRESS:{label}:Nothing could be confirmed as applied, so no "
                           "restart is being suggested. Re-run this as administrator.")

    def perform_windows_adjustments(self):
        """Apply various Windows system adjustments for better performance"""
        label = "Windows Adjustments"
        self.queue.put(f"PROGRESS:{label}:Starting Windows adjustments...")
        self.queue.put(f"PROGRESS:{label}:This will modify focus, visual effects and gaming settings.")

        try:
            adjustments = [
                {"name": "Focus Assist",
                 "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\QuietHours",
                 "values": [("QuietHoursState", 0)]},
                {"name": "Transparency Effects",
                 "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize",
                 "values": [("EnableTransparency", 0)]},
                {"name": "Visual Effects Mode (Custom)",
                 "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects",
                 "values": [("VisualFXSetting", 3)]},
                {"name": "Visual Effects Custom Flags",
                 "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
                 "values": [("TaskbarAnimations", 0), ("ListviewShadow", 0),
                            ("ListviewAlphaSelect", 1), ("IconsOnly", 0)]},
                {"name": "Game Bar",
                 "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR",
                 "values": [("AppCaptureEnabled", 0), ("BackgroundRecordingEnabled", 0)]},
                {"name": "Game Mode",
                 "path": r"SOFTWARE\Microsoft\GameBar",
                 "values": [("AllowAutoGameMode", 0), ("AutoGameModeEnabled", 0)]},
                {"name": "Game DVR",
                 "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR",
                 "values": [("AllowGameDVR", 0)]},
                {"name": "Game Capture",
                 "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR",
                 "values": [("GameCaptureEnabled", 0)]},
            ]

            for i, adjustment in enumerate(adjustments):
                try:
                    self.queue.put(f"PROGRESS:{label}:Processing adjustment {i + 1}/{len(adjustments)}: "
                                   f"{adjustment['name']}...")
                    SecurityUtils.validate_registry_key(adjustment["path"])
                    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, adjustment["path"], 0,
                                            winreg.KEY_WRITE) as key:
                        for value_name, value_data in adjustment["values"]:
                            winreg.SetValueEx(key, value_name, 0, winreg.REG_DWORD, value_data)
                    self.queue.put(f"PROGRESS:{label}:{adjustment['name']} disabled")
                except Exception as e:
                    self._report_failure(f"PROGRESS:{label}:Error disabling {adjustment['name']}: {str(e)}")

            self.queue.put(f"PROGRESS:{label}:Applying custom visual-effects profile...")
            self._apply_visual_effects(label, reduced=True)

            # Marking a network Private lets other PCs on it find this one and
            # see what it shares. That is a security decision about a specific
            # network, not a performance tweak, and it was being made silently
            # for every network -- public Wi-Fi included. Ask, per run.
            profiles = self._run_ps(
                "Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { "
                "Write-Output ($_.Name + '|' + $_.InterfaceAlias + '|' + $_.NetworkCategory) }",
                timeout=60)
            rows = [line.split("|") for line in (profiles.stdout or "").splitlines() if line.count("|") == 2]
            public = [r for r in rows if r[2].strip().lower() == "public"]
            if not public:
                self.queue.put(f"PROGRESS:{label}:Network profiles left as they are (none is Public).")
            elif messagebox.askyesno(
                    "Mark networks as Private?",
                    "Also mark these networks as Private?\n\n"
                    + "\n".join(f"  -  {r[0]} ({r[1]})" for r in public)
                    + "\n\nPrivate lets other computers on the same network find this PC and "
                      "see anything it shares. Only do this on your own home or office "
                      "network -- never on public Wi-Fi."):
                result = self._run_ps(
                    "Get-NetConnectionProfile | Where-Object { $_.NetworkCategory -eq 'Public' } | "
                    "Set-NetConnectionProfile -NetworkCategory Private -ErrorAction Stop; "
                    "Write-Output 'OK'", timeout=60)
                if "OK" in (result.stdout or ""):
                    self.queue.put(f"PROGRESS:{label}:Networks marked Private: "
                                   f"{', '.join(r[0] for r in public)}")
                else:
                    self._report_failure(f"PROGRESS:{label}:Could not change the network profile: "
                                         f"{_wm_last_line(result.stderr) or 'unknown error'}")
            else:
                self.queue.put(f"PROGRESS:{label}:Network profiles left as they are.")

            self.queue.put(f"PROGRESS:{label}:Windows adjustments completed!")
            self.queue.put(f"PROGRESS:{label}:Some changes may require a restart or logout to take effect.")

        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error in Windows adjustments: {str(e)}")

    def _apply_visual_effects(self, label, reduced):
        """Set the individual visual effects Performance Options lists.

        reduced=True is Performance Adjustments' profile: a few effects kept,
        the menu and tooltip animations off. reduced=False switches them all
        back on, which is what 'Let Windows choose' shows on a modern PC --
        Reset Windows Defaults used to write only the VisualFXSetting marker,
        so the dialog said "Let Windows choose" while the animations stayed off.
        """
        flags = 0x01 | 0x02  # SPIF_UPDATEINIFILE | SPIF_SENDCHANGE
        user32 = ctypes.windll.user32

        def by_value(action, enabled, name):
            # These SET actions read the BOOL *by value* from pvParam. byref()
            # always yields a non-null address, which Windows reads as TRUE --
            # so passing byref() would leave every effect ON.
            ok = user32.SystemParametersInfoW(action, 0, ctypes.c_void_p(1 if enabled else 0), flags)
            if ok:
                self.queue.put(f"PROGRESS:{label}:{name} set to {'ON' if enabled else 'OFF'}")
            else:
                self._report_failure(f"PROGRESS:{label}:Could not apply {name} (API returned false)")

        def by_param(action, enabled, name):
            ok = user32.SystemParametersInfoW(action, 1 if enabled else 0, 0, flags)
            if ok:
                self.queue.put(f"PROGRESS:{label}:{name} set to {'ON' if enabled else 'OFF'}")
            else:
                self._report_failure(f"PROGRESS:{label}:Could not apply {name} (API returned false)")

        by_value(0x1043, True, "Animate controls and elements inside windows")
        by_value(0x1025, True, "Show shadows under windows")
        by_param(0x0025, True, "Show window contents while dragging")
        by_param(0x004B, True, "Smooth edges of screen fonts")
        by_value(0x1007, True, "Smooth-scroll list boxes")
        on = not reduced
        by_value(0x1003, on, "Fade or slide menus into view")
        by_value(0x1005, on, "Slide open combo boxes")
        by_value(0x1013, on, "Fade out menu items after clicking")
        by_value(0x1015, on, "Selection fade")
        by_value(0x1017, on, "Fade or slide ToolTips into view")
        by_value(0x1019, on, "Fade ToolTips")
        by_value(0x101B, on, "Show shadows under mouse pointer")
        by_value(0x100F, on, "Hot tracking")

        class ANIMATIONINFO(ctypes.Structure):
            _fields_ = [("cbSize", ctypes.c_uint), ("iMinAnimate", ctypes.c_int)]

        anim = ANIMATIONINFO(ctypes.sizeof(ANIMATIONINFO), 1 if on else 0)
        if user32.SystemParametersInfoW(0x0049, anim.cbSize, ctypes.byref(anim), flags):
            self.queue.put(f"PROGRESS:{label}:Animate windows when minimizing/maximizing set to "
                           f"{'ON' if on else 'OFF'}")
        else:
            self._report_failure(f"PROGRESS:{label}:Could not change minimize/maximize animation.")
        # ClearType for smoother edges.
        if not user32.SystemParametersInfoW(0x200B, 0, ctypes.c_void_p(2), flags):
            self._report_failure(f"PROGRESS:{label}:Could not apply ClearType font smoothing.")
        try:
            wm_run(['RUNDLL32.EXE', 'user32.dll,UpdatePerUserSystemParameters', '1', 'True'],
                   capture_output=True, startupinfo=_no_console_startupinfo())
        except Exception:
            pass

    def disable_all_gaming_features(self):
        """Turn off all Windows gaming features: Game Bar, Game DVR, Game Mode, and captures"""
        self.queue.put("PROGRESS:Gaming Features:Disabling all Windows gaming features...")
        try:
            ps_script = '''
            try {
                $ErrorActionPreference = "Stop"
                Write-Host "=== Disabling Windows Gaming Features ==="

                # Disable Game Bar
                Write-Host "Disabling Game Bar..."
                $gamingPath = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\GameDVR"
                if (-not (Test-Path $gamingPath)) { New-Item -Path $gamingPath -Force | Out-Null }
                Set-ItemProperty -Path $gamingPath -Name "AppCaptureEnabled" -Value 0 -Type DWord -Force
                Write-Host "  - Game Bar capture disabled"

                $gameBarPath = "HKCU:\\Software\\Microsoft\\GameBar"
                if (-not (Test-Path $gameBarPath)) { New-Item -Path $gameBarPath -Force | Out-Null }
                Set-ItemProperty -Path $gameBarPath -Name "UseNexusForGameBarEnabled" -Value 0 -Type DWord -Force
                Set-ItemProperty -Path $gameBarPath -Name "AutoGameModeEnabled" -Value 0 -Type DWord -Force
                Write-Host "  - Game Bar overlay disabled"

                # Disable Game DVR
                Write-Host "Disabling Game DVR..."
                $gameDVRPolicy = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR"
                if (-not (Test-Path $gameDVRPolicy)) { New-Item -Path $gameDVRPolicy -Force | Out-Null }
                Set-ItemProperty -Path $gameDVRPolicy -Name "AllowGameDVR" -Value 0 -Type DWord -Force
                $gameDVRPolicyUser = "HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR"
                if (-not (Test-Path $gameDVRPolicyUser)) { New-Item -Path $gameDVRPolicyUser -Force | Out-Null }
                Set-ItemProperty -Path $gameDVRPolicyUser -Name "AllowGameDVR" -Value 0 -Type DWord -Force
                Write-Host "  - Game DVR recording disabled"

                # Disable Game Mode
                Write-Host "Disabling Game Mode..."
                $gameModePath = "HKCU:\\Software\\Microsoft\\GameBar"
                Set-ItemProperty -Path $gameModePath -Name "AllowAutoGameMode" -Value 0 -Type DWord -Force
                Write-Host "  - Auto Game Mode disabled"

                $gameConfigPath = "HKCU:\\System\\GameConfigStore"
                if (-not (Test-Path $gameConfigPath)) { New-Item -Path $gameConfigPath -Force | Out-Null }
                Set-ItemProperty -Path $gameConfigPath -Name "GameDVR_Enabled" -Value 0 -Type DWord -Force
                Set-ItemProperty -Path $gameConfigPath -Name "GameDVR_FSEBehaviorMode" -Value 2 -Type DWord -Force
                Set-ItemProperty -Path $gameConfigPath -Name "GameDVR_HonorUserFSEBehaviorMode" -Value 1 -Type DWord -Force
                Set-ItemProperty -Path $gameConfigPath -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Value 1 -Type DWord -Force
                Set-ItemProperty -Path $gameConfigPath -Name "GameDVR_EFSEFeatureFlags" -Value 0 -Type DWord -Force
                Write-Host "  - Game optimizations disabled"

                # Disable Game Capture features
                Write-Host "Disabling Game Capture..."
                Set-ItemProperty -Path $gamingPath -Name "HistoricalCaptureEnabled" -Value 0 -Type DWord -Force
                Write-Host "  - Background recording disabled"

                # Disable "Use Game Bar for supported controllers" (Guide button)
                Write-Host "Disabling Game Bar controller guide button..."
                Set-ItemProperty -Path $gameBarPath -Name "ShowStartupPanel" -Value 0 -Type DWord -Force
                Set-ItemProperty -Path $gameBarPath -Name "GamePanelStartupTipIndex" -Value 3 -Type DWord -Force
                Write-Host "  - Game Bar guide button disabled"

                # Disable optimizations for windowed games
                Write-Host "Disabling optimizations for windowed games..."
                Set-ItemProperty -Path $gameConfigPath -Name "GameDVR_DSEBehavior" -Value 2 -Type DWord -Force
                $graphicsPath = "HKCU:\\Software\\Microsoft\\DirectX\\UserGpuPreferences"
                if (-not (Test-Path $graphicsPath)) { New-Item -Path $graphicsPath -Force | Out-Null }
                $fullscreenOptPath = "HKCU:\\System\\GameConfigStore"
                Set-ItemProperty -Path $fullscreenOptPath -Name "GameDVR_FSEBehavior" -Value 2 -Type DWord -Force
                Write-Host "  - Windowed games optimizations disabled"

                # Disable Xbox Game Monitoring
                Write-Host "Disabling Xbox Game Monitoring..."
                $xboxPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\xbgm"
                if (Test-Path $xboxPath) {
                    Set-ItemProperty -Path $xboxPath -Name "Start" -Value 4 -Type DWord -Force
                    Write-Host "  - Xbox Game Monitoring service disabled"
                }

                Write-Host ""
                Write-Host "=== All gaming features have been disabled! ==="
                Write-Host "Disabled: Game Bar, Game DVR, Game Mode, Background Recording,"
                Write-Host "          Controller Guide Button, Windowed Games Optimizations"
                Write-Host "Note: Some changes may require a restart to take effect."

            } catch {
                Write-Error "Error disabling gaming features: $($_.Exception.Message)"
                exit 1
            }
            '''

            self.queue.put("PROGRESS:Gaming Features:Executing gaming features disable script...")
            result = wm_run(
                ['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned', '-Command', ps_script],
                capture_output=True,
                text=True, encoding='utf-8', errors='replace',
                check=False,
                timeout=60,
                startupinfo=_no_console_startupinfo()
            )

            if result.stdout.strip():
                self.queue.put("PROGRESS:Gaming Features:Script output:")
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        self.queue.put(f"PROGRESS:Gaming Features:  {line.strip()}")

            if result.stderr.strip():
                self.queue.put("PROGRESS:Gaming Features:Script errors:")
                for line in result.stderr.strip().split('\n'):
                    if line.strip():
                        self.queue.put(f"PROGRESS:Gaming Features:  {line.strip()}")

            if result.returncode != 0:
                self._report_failure(f"PROGRESS:Gaming Features:Not every setting could be changed "
                                     f"(code {result.returncode}); the errors above say which.")

        except Exception as e:
            self._report_failure(f"PROGRESS:Gaming Features:Error disabling gaming features: {str(e)}")

    def enable_all_gaming_features(self):
        """Turn on gaming features and apply high-performance graphics preferences for detected games."""
        self.queue.put("PROGRESS:Gaming Features:Enabling all Windows gaming features...")
        try:
            ps_script = r'''
            try {
                $ErrorActionPreference = "Stop"
                Write-Host "=== Enabling Windows Gaming Features ==="

                # Core paths
                $gameBarPath = "HKCU:\Software\Microsoft\GameBar"
                $gameDvrPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR"
                $gameConfigPath = "HKCU:\System\GameConfigStore"
                $gpuPrefsPath = "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences"

                foreach ($p in @($gameBarPath, $gameDvrPath, $gameConfigPath, $gpuPrefsPath)) {
                    if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
                }

                # Turn ON Game Bar + Guide button behavior
                Write-Host "Enabling Game Bar..."
                Set-ItemProperty -Path $gameBarPath -Name "UseNexusForGameBarEnabled" -Type DWord -Value 1 -Force
                Set-ItemProperty -Path $gameBarPath -Name "ShowStartupPanel" -Type DWord -Value 1 -Force
                Set-ItemProperty -Path $gameBarPath -Name "GamePanelStartupTipIndex" -Type DWord -Value 0 -Force
                Set-ItemProperty -Path $gameBarPath -Name "AutoGameModeEnabled" -Type DWord -Value 1 -Force
                Set-ItemProperty -Path $gameBarPath -Name "AllowAutoGameMode" -Type DWord -Value 1 -Force
                Write-Host "  - Game Bar enabled"

                # Turn ON Game DVR + captures (user & policy)
                Write-Host "Enabling Game DVR..."
                Set-ItemProperty -Path $gameDvrPath -Name "AppCaptureEnabled" -Type DWord -Value 1 -Force
                Set-ItemProperty -Path $gameDvrPath -Name "HistoricalCaptureEnabled" -Type DWord -Value 1 -Force

                $gameDvrPolicyMachine = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
                $gameDvrPolicyUser = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
                if (-not (Test-Path $gameDvrPolicyMachine)) { New-Item -Path $gameDvrPolicyMachine -Force | Out-Null }
                if (-not (Test-Path $gameDvrPolicyUser)) { New-Item -Path $gameDvrPolicyUser -Force | Out-Null }
                Set-ItemProperty -Path $gameDvrPolicyMachine -Name "AllowGameDVR" -Type DWord -Value 1 -Force
                Set-ItemProperty -Path $gameDvrPolicyUser -Name "AllowGameDVR" -Type DWord -Value 1 -Force
                Write-Host "  - Game DVR policy enabled"

                # Turn ON Game Mode + windowed optimizations
                Write-Host "Enabling Game Mode and windowed game optimizations..."
                Set-ItemProperty -Path $gameConfigPath -Name "GameDVR_Enabled" -Type DWord -Value 1 -Force
                Set-ItemProperty -Path $gameConfigPath -Name "GameDVR_DSEBehavior" -Type DWord -Value 0 -Force
                Set-ItemProperty -Path $gameConfigPath -Name "GameDVR_FSEBehavior" -Type DWord -Value 0 -Force
                Set-ItemProperty -Path $gameConfigPath -Name "GameDVR_FSEBehaviorMode" -Type DWord -Value 2 -Force
                Set-ItemProperty -Path $gameConfigPath -Name "GameDVR_HonorUserFSEBehaviorMode" -Type DWord -Value 1 -Force
                Set-ItemProperty -Path $gameConfigPath -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Type DWord -Value 1 -Force
                Set-ItemProperty -Path $gameConfigPath -Name "GameDVR_EFSEFeatureFlags" -Type DWord -Value 1 -Force
                Write-Host "  - Game Mode and windowed optimizations enabled"

                # Enable HAGS (Hardware-accelerated GPU scheduling)
                Write-Host "Enabling Hardware-Accelerated GPU Scheduling..."
                $graphicsDriversPath = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
                if (-not (Test-Path $graphicsDriversPath)) { New-Item -Path $graphicsDriversPath -Force | Out-Null }
                Set-ItemProperty -Path $graphicsDriversPath -Name "HwSchMode" -Type DWord -Value 2 -Force
                Write-Host "  - HAGS enabled (restart may be required)"

                # Turn OFF Memory Integrity (Core Isolation / HVCI). It sits on the
                # kernel hot path and costs frames, so a gaming profile turns it off.
                Write-Host "Turning off Memory Integrity (Core Isolation)..."
                $hvciPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
                try {
                    if (-not (Test-Path $hvciPath)) { New-Item -Path $hvciPath -Force | Out-Null }

                    # The greyed-out switch -- "This setting is managed by your
                    # administrator" -- is Locked. Clear it first or Enabled will
                    # not take, and the toggle stays unclickable in Windows Security.
                    $lockedBefore = $null
                    try { $lockedBefore = (Get-ItemProperty -Path $hvciPath -Name "Locked" -ErrorAction Stop).Locked } catch {}

                    # Remember what was there -- once, so a second run keeps the
                    # original -- so Reset Windows Defaults can put it back.
                    $undo = "HKCU:\Software\WinMend\Undo"
                    if (-not (Test-Path $undo)) { New-Item -Path $undo -Force | Out-Null }
                    if ($null -eq (Get-ItemProperty -Path $undo -Name "MemoryIntegrityRecorded" -ErrorAction SilentlyContinue)) {
                        $enabledBefore = $null
                        try { $enabledBefore = (Get-ItemProperty -Path $hvciPath -Name "Enabled" -ErrorAction Stop).Enabled } catch {}
                        New-ItemProperty -Path $undo -Name "MemoryIntegrityEnabled" -PropertyType DWord -Value ([int]($enabledBefore -eq 1)) -Force | Out-Null
                        New-ItemProperty -Path $undo -Name "MemoryIntegrityLocked" -PropertyType DWord -Value ([int]$lockedBefore) -Force | Out-Null
                        New-ItemProperty -Path $undo -Name "MemoryIntegrityRecorded" -PropertyType DWord -Value 1 -Force | Out-Null
                    }

                    if ($null -ne $lockedBefore -and $lockedBefore -ne 0) {
                        Set-ItemProperty -Path $hvciPath -Name "Locked" -Type DWord -Value 0 -Force
                        Write-Host ("  - Locked was " + $lockedBefore + " (switch greyed out) -> set to 0")
                    }

                    Set-ItemProperty -Path $hvciPath -Name "Enabled" -Type DWord -Value 0 -Force

                    # Report what the registry says now, not what was intended.
                    $hvciAfter = $null
                    try { $hvciAfter = (Get-ItemProperty -Path $hvciPath -Name "Enabled" -ErrorAction Stop).Enabled } catch {}
                    if ($hvciAfter -eq 0) {
                        Write-Host "  - Memory Integrity set to off (Enabled=0)"
                        # Only an HVCI that is actually running still needs a restart
                        # to stand down; if it was already off, do not ask for one.
                        $hvciRunning = $false
                        try {
                            $dg = Get-CimInstance -Namespace "root\Microsoft\Windows\DeviceGuard" -ClassName Win32_DeviceGuard -ErrorAction Stop
                            if ($dg.SecurityServicesRunning -contains 2) { $hvciRunning = $true }
                        } catch {}
                        if ($hvciRunning) {
                            Write-Host "  - Still loaded in this session; it stops running after a restart"
                            Write-Host "WM_MEMINTEGRITY_RESTART"
                        } else {
                            Write-Host "  - It was not running, so there is nothing left to unload"
                        }
                    } else {
                        Write-Host ("  - WARNING: Memory Integrity still reads Enabled=" + $hvciAfter + " after the write")
                    }

                    # A real Group Policy outranks the key above and will put it
                    # straight back, so say so rather than claim a clean result.
                    $dgPolicyRoot = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
                    $policyForcing = $false
                    foreach ($pp in @($dgPolicyRoot, ($dgPolicyRoot + "\Scenarios\HypervisorEnforcedCodeIntegrity"))) {
                        if (Test-Path $pp) {
                            $pv = Get-ItemProperty -Path $pp -ErrorAction SilentlyContinue
                            if ($pv) {
                                foreach ($n in @("Enabled", "EnableVirtualizationBasedSecurity", "HypervisorEnforcedCodeIntegrity", "HVCIMATRequired")) {
                                    if ($null -ne $pv.$n -and $pv.$n -ne 0) { $policyForcing = $true }
                                }
                            }
                        }
                    }
                    if ($policyForcing) {
                        Write-Host "  - NOTE: a Device Guard Group Policy is also set on this PC and will re-enable Memory Integrity at the next policy refresh. That one has to be cleared by whoever manages the machine."
                    }
                } catch {
                    Write-Host ("  - Could not change Memory Integrity: " + $_.Exception.Message)
                }

                # Enable VRR + Windowed optimization global switches
                Write-Host "Enabling VRR and global graphics optimization flags..."
                $globalSettings = ""
                try { $globalSettings = (Get-ItemProperty -Path $gpuPrefsPath -Name "DirectXUserGlobalSettings" -ErrorAction Stop).DirectXUserGlobalSettings } catch {}
                $settingsMap = @{}
                if ($globalSettings) {
                    foreach ($token in ($globalSettings -split ';')) {
                        if ($token -match '=') {
                            $kv = $token -split '=', 2
                            if ($kv.Count -eq 2) { $settingsMap[$kv[0]] = $kv[1] }
                        }
                    }
                }
                $settingsMap["SwapEffectUpgradeEnable"] = "1"
                $settingsMap["VRROptimizeEnable"] = "1"
                $settingsMap["VariableRefreshRateEnable"] = "1"
                $newGlobal = (($settingsMap.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ';') + ';'
                Set-ItemProperty -Path $gpuPrefsPath -Name "DirectXUserGlobalSettings" -Value $newGlobal -Type String -Force
                Set-ItemProperty -Path $gameConfigPath -Name "VRROptimizeEnable" -Type DWord -Value 1 -Force
                Write-Host "  - VRR enabled"

                # Add detected game executables to Graphics custom app list (High Performance)
                Write-Host "Detecting game executables and applying high-performance GPU preference..."
                $gameRoots = New-Object System.Collections.Generic.List[string]
                $relPaths = @(
                    "Program Files (x86)\Steam\steamapps\common",
                    "SteamLibrary\steamapps\common",
                    "Program Files\Epic Games",
                    "Epic Games",
                    "GOG Games",
                    "Games",
                    "XboxGames",
                    "Program Files\Ubisoft",
                    "Program Files (x86)\Ubisoft"
                )
                $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\' }
                foreach ($d in $drives) {
                    foreach ($rel in $relPaths) {
                        $candidate = Join-Path $d.Root $rel
                        if (Test-Path $candidate) { $gameRoots.Add($candidate) | Out-Null }
                    }
                }

                $excludeRegex = "(?i)(\\_CommonRedist\\|\\Redist\\|\\Installer\\|\\CrashReport\\|EasyAntiCheat|BattlEye|vcredist|unins)"
                $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                # A preference the user already set -- in Settings or here -- is
                # left exactly as it is; only games with none get one. Each one
                # added is recorded, so Reset Windows Defaults can remove them.
                $existing = @((Get-Item -Path $gpuPrefsPath -ErrorAction SilentlyContinue).Property)
                $addedNow = New-Object System.Collections.Generic.List[string]
                foreach ($root in $gameRoots) {
                    Get-ChildItem -Path $root -Recurse -Filter *.exe -File -ErrorAction SilentlyContinue | ForEach-Object {
                        $exe = $_.FullName
                        if ($exe -notmatch $excludeRegex) {
                            if ($seen.Add($exe) -and $existing -notcontains $exe) {
                                New-ItemProperty -Path $gpuPrefsPath -Name $exe -Value "GpuPreference=2;" -PropertyType String -Force | Out-Null
                                $addedNow.Add($exe)
                            }
                        }
                    }
                }
                if ($addedNow.Count) {
                    $undo = "HKCU:\Software\WinMend\Undo"
                    if (-not (Test-Path $undo)) { New-Item -Path $undo -Force | Out-Null }
                    $prior = @((Get-ItemProperty -Path $undo -Name "GpuPreferencesAdded" -ErrorAction SilentlyContinue).GpuPreferencesAdded)
                    $all = @(@($prior) + @($addedNow) | Where-Object { $_ } | Select-Object -Unique)
                    New-ItemProperty -Path $undo -Name "GpuPreferencesAdded" -PropertyType MultiString -Value ([string[]]$all) -Force | Out-Null
                }
                Write-Host ("  - Added a high-performance GPU preference for " + $addedNow.Count + " game executables (existing preferences left as they were)")

                Write-Host ""
                Write-Host "=== Gaming features enabled successfully ==="
                Write-Host "Enabled: Game Bar, Guide button, Game Mode, windowed game optimizations, HAGS, VRR"
                Write-Host "Disabled: Memory Integrity (Core Isolation)"
                Write-Host "Note: Some settings require sign-out/restart to fully apply."
            } catch {
                Write-Error ("Error enabling gaming features: " + $_.Exception.Message)
                exit 1
            }
            '''

            self.queue.put("PROGRESS:Gaming Features:Executing gaming features enable script...")
            result = wm_run(
                ['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned', '-Command', ps_script],
                capture_output=True,
                text=True, encoding='utf-8', errors='replace',
                check=False,
                timeout=300,
                startupinfo=_no_console_startupinfo()
            )

            # The script prints a marker when it measured Memory Integrity as still
            # loaded, which is the one change here that genuinely needs a restart.
            memory_integrity_restart = False

            if result.stdout.strip():
                self.queue.put("PROGRESS:Gaming Features:Script output:")
                for line in result.stdout.strip().split('\n'):
                    text = line.strip()
                    if not text:
                        continue
                    if text == "WM_MEMINTEGRITY_RESTART":
                        memory_integrity_restart = True
                        continue
                    self.queue.put(f"PROGRESS:Gaming Features:  {text}")

            if result.stderr.strip():
                self.queue.put("PROGRESS:Gaming Features:Script errors:")
                for line in result.stderr.strip().split('\n'):
                    if line.strip():
                        self.queue.put(f"PROGRESS:Gaming Features:  {line.strip()}")

            if result.returncode != 0:
                self._report_failure(f"PROGRESS:Gaming Features:Not every setting could be changed "
                                     f"(code {result.returncode}); the errors above say which.")

            if memory_integrity_restart:
                self.queue.put(
                    "REBOOTRECOMMEND:Gaming Features:Memory Integrity (Core Isolation) is "
                    "switched off in the registry, but it is still loaded in this Windows "
                    "session and keeps running until you restart."
                )

        except subprocess.TimeoutExpired:
            self.queue.put("PROGRESS:Gaming Features:Enable operation timed out")
        except Exception as e:
            self._report_failure(f"PROGRESS:Gaming Features:Error enabling gaming features: {str(e)}")

    def optimize_virtual_memory(self):
        """Set the page file to start at RAM size and grow to twice it -- if there is room."""
        label = "Virtual Memory"
        self.queue.put(f"PROGRESS:{label}:Analyzing system RAM and optimizing virtual memory...")
        ps_script = r'''
        try {
            $ErrorActionPreference = "Stop"
            $ramModules = Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction SilentlyContinue
            if ($ramModules) { $ramBytes = ($ramModules | Measure-Object -Property Capacity -Sum).Sum }
            if (-not $ramBytes -or $ramBytes -le 0) { $ramBytes = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory }
            if (-not $ramBytes -or $ramBytes -le 0) { throw "Unable to detect installed RAM." }
            $ramGB = [math]::Round($ramBytes / 1GB, 2)
            $ramMB = [int][math]::Ceiling($ramBytes / 1MB)
            $initialSizeMB = $ramMB
            $maxSizeMB = $ramMB * 2
            $drive = $env:SystemDrive
            Write-Host "Detected RAM: $ramGB GB ($ramMB MB)"
            Write-Host "Target: start at $initialSizeMB MB, grow to $maxSizeMB MB, on $drive"

            $cs = Get-CimInstance -ClassName Win32_ComputerSystem
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
            $currentPF = @(Get-CimInstance -ClassName Win32_PageFileUsage -ErrorAction SilentlyContinue)
            $currentMB = 0
            foreach ($p in $currentPF) {
                Write-Host "Current page file: $($p.Name), $($p.AllocatedBaseSize) MB"
                if ($p.Name -like "$drive*") { $currentMB += [int]$p.AllocatedBaseSize }
            }
            if ($cs.AutomaticManagedPagefile) { Write-Host "Currently managed by Windows" }

            # The page file is allocated at its initial size straight away, and
            # the old version never checked it would fit. Refuse rather than fill
            # the Windows drive -- the current page file's space comes back when
            # it is replaced, so that counts as free.
            $vol = Get-Volume -DriveLetter $drive.TrimEnd(':') -ErrorAction Stop
            $freeAfterMB = [math]::Floor($vol.SizeRemaining / 1MB) + $currentMB - $initialSizeMB
            $floorMB = [math]::Max(15360, [math]::Floor($vol.Size / 1MB * 0.10))
            if ($freeAfterMB -lt $floorMB) {
                Write-Host ("WM_NOROOM|A $initialSizeMB MB page file would leave only {0:N1} GB free on $drive (the minimum kept free is {1:N1} GB)." -f ($freeAfterMB / 1024), ($floorMB / 1024))
                exit 3
            }

            # Remember the setting WinMend replaces -- once, so a second run does
            # not overwrite the original -- so Reset Windows Defaults can put it back.
            $undo = "HKCU:\Software\WinMend\Undo"
            if (-not (Test-Path $undo)) { New-Item -Path $undo -Force | Out-Null }
            if ($null -eq (Get-ItemProperty -Path $undo -Name PagefileRecorded -ErrorAction SilentlyContinue)) {
                $prev = @((Get-ItemProperty -Path $regPath -Name PagingFiles -ErrorAction SilentlyContinue).PagingFiles | Where-Object { $_ })
                New-ItemProperty -Path $undo -Name PagingFiles -PropertyType MultiString -Value ([string[]]$prev) -Force | Out-Null
                New-ItemProperty -Path $undo -Name AutomaticManagedPagefile -PropertyType DWord -Value ([int][bool]$cs.AutomaticManagedPagefile) -Force | Out-Null
                New-ItemProperty -Path $undo -Name PagefileRecorded -PropertyType DWord -Value 1 -Force | Out-Null
            }

            if ($cs.AutomaticManagedPagefile -eq $true) {
                Set-CimInstance -InputObject $cs -Property @{ AutomaticManagedPagefile = $false } | Out-Null
                Write-Host "Disabled automatic page file management"
            }
            $pageFileValue = "$drive\pagefile.sys $initialSizeMB $maxSizeMB"
            Set-ItemProperty -Path $regPath -Name "PagingFiles" -Value @($pageFileValue) -Type MultiString -Force
            $verifyPF = (Get-ItemProperty -Path $regPath -Name "PagingFiles").PagingFiles
            Write-Host "Verified registry value: $verifyPF"
            if ("$verifyPF" -ne $pageFileValue) { throw "PagingFiles reads '$verifyPF' after the write" }
            Write-Host "WM_APPLIED"
        } catch {
            Write-Host "Error optimizing virtual memory: $($_.Exception.Message)"
            exit 1
        }
        '''
        try:
            lines = []
            rc, _ = self._run_live_command(
                ['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned',
                 '-Command', ps_script], label, output=lines)
            if self.cancel_event.is_set():
                return
            noroom = next((line.split("|", 1)[1] for line in lines if line.startswith("WM_NOROOM|")), "")
            if noroom:
                self._report_failure(f"PROGRESS:{label}:Not changed: {noroom} Free up space first, or "
                                     f"leave the page file managed by Windows.")
            elif rc != 0 or "WM_APPLIED" not in lines:
                self._report_failure(f"PROGRESS:{label}:The page file setting was not changed; the "
                                     f"lines above say why.")
            else:
                self.queue.put(f"PROGRESS:{label}:Page file updated. 'Reset Windows Defaults' puts the "
                               f"previous setting back.")
                self.queue.put(f"REBOOTRECOMMEND:{label}:The new page file size takes effect at the "
                               f"next restart.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error optimizing virtual memory: {str(e)}")
