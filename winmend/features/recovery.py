"""WinMend features: recovery."""

from __future__ import annotations

from winmend.core.processes import _no_console_startupinfo, wm_run
from winmend.core.prompts import messagebox
from winmend.core.search import _wm_last_line


class RecoveryTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    # ======================================================================
    # v1.8 NEW OPTION HANDLERS
    # ======================================================================


    def run_reset_to_defaults(self):
        """Undo WinMend's tweaks -- from what WinMend recorded before changing them."""
        label = "Reset Defaults"
        if not messagebox.askyesno(
            "Reset Windows Defaults",
            "This will revert WinMend tweaks back to Windows defaults:\n"
            " - Visual effects and animations \u2192 'Let Windows choose'\n"
            " - Focus Assist / Transparency \u2192 enabled\n"
            " - Game Bar / DVR / Game Mode \u2192 enabled, and the Game DVR policy removed\n"
            " - Edge policies WinMend set (Startup Boost, background mode, search engine, "
            "new tab page) \u2192 removed\n"
            " - Fast Startup (Hibernation) \u2192 enabled\n"
            " - Background apps \u2192 allowed\n"
            " - SysMain / Telemetry / Windows Search / Diagnostic Policy \u2192 "
            "Automatic and running\n"
            " - Memory compression + Delivery Optimization peer downloads \u2192 on\n"
            " - Page file \u2192 back to how it was before WinMend changed it\n"
            " - Memory Integrity \u2192 back on, if WinMend turned it off\n"
            " - Graphics preferences WinMend added for games \u2192 removed\n"
            " - AMD External Events Utility \u2192 back to its old start type, if SSD Saver "
            "disabled it\n\n"
            "Network profile (Private/Public) is NOT changed \u2014 that was your own "
            "choice for each network. Optional diagnostic data stays off \u2014 off is the "
            "Windows default, so turning it back on would not be a reset.\n\n"
            "Continue?"
        ):
            self._report_skip(f"PROGRESS:{label}:Cancelled by user.")
            return

        self.queue.put(f"PROGRESS:{label}:Reverting tweaks via registry + SystemParametersInfo...")
        # Every section runs even if an earlier one fails, and a failure names
        # itself -- the old script put everything in one try block, so the first
        # refusal skipped the rest and still reported "Defaults restored".
        ps_script = r'''
        $ErrorActionPreference = 'Stop'
        function Step([string]$what, [scriptblock]$body) {
            try { & $body } catch { Write-Output ("WM_FAIL|" + $what + ": " + $_.Exception.Message) }
        }
        function Ensure([string]$path) { if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null } }
        $undo = 'HKCU:\Software\WinMend\Undo'

        Step 'Visual effects' {
            $ve = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
            Ensure $ve
            Set-ItemProperty -Path $ve -Name 'VisualFXSetting' -Type DWord -Value 0 -Force
            $adv = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            Ensure $adv
            foreach ($n in 'TaskbarAnimations', 'ListviewShadow', 'ListviewAlphaSelect') {
                Set-ItemProperty -Path $adv -Name $n -Type DWord -Value 1 -Force
            }
            Set-ItemProperty -Path $adv -Name 'IconsOnly' -Type DWord -Value 0 -Force
            Write-Output 'Visual effects: Let Windows choose'
        }

        Step 'Focus Assist and transparency' {
            $qh = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\QuietHours'
            if (Test-Path $qh) { Remove-ItemProperty -Path $qh -Name 'QuietHoursState' -ErrorAction SilentlyContinue }
            $pers = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize'
            Ensure $pers
            Set-ItemProperty -Path $pers -Name 'EnableTransparency' -Type DWord -Value 1 -Force
            Write-Output 'Focus Assist and transparency: back on'
        }

        Step 'Game Bar, Game DVR and Game Mode' {
            $dvr = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR'
            Ensure $dvr
            foreach ($n in 'AppCaptureEnabled', 'HistoricalCaptureEnabled', 'AllowGameDVR', 'GameCaptureEnabled') {
                Set-ItemProperty -Path $dvr -Name $n -Type DWord -Value 1 -Force
            }
            $bar = 'HKCU:\SOFTWARE\Microsoft\GameBar'
            Ensure $bar
            foreach ($n in 'AllowAutoGameMode', 'AutoGameModeEnabled', 'UseNexusForGameBarEnabled') {
                Set-ItemProperty -Path $bar -Name $n -Type DWord -Value 1 -Force
            }
            $cfg = 'HKCU:\System\GameConfigStore'
            Ensure $cfg
            Set-ItemProperty -Path $cfg -Name 'GameDVR_Enabled' -Type DWord -Value 1 -Force
            # 'Turn Off All Gaming Features' also sets the Game DVR *policy*,
            # which outranks every setting above. Windows' default is no policy.
            foreach ($p in 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR', 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\GameDVR') {
                if ($null -ne (Get-ItemProperty -Path $p -Name 'AllowGameDVR' -ErrorAction SilentlyContinue)) {
                    Remove-ItemProperty -Path $p -Name 'AllowGameDVR'
                }
            }
            Write-Output 'Game Bar, Game DVR and Game Mode: back on (Game DVR policy removed)'
        }

        Step 'Edge policies' {
            # Only values still holding what WinMend wrote are removed -- a
            # policy an organisation set is not WinMend's to delete.
            $mine = [ordered]@{
                StartupBoostEnabled = '0'; BackgroundModeEnabled = '0'
                DefaultSearchProviderEnabled = '1'; DefaultSearchProviderName = 'Google'
                DefaultSearchProviderKeyword = 'google.com'
                DefaultSearchProviderSearchURL = 'https://www.google.com/search?q={searchTerms}'
                DefaultSearchProviderSuggestURL = 'https://www.google.com/complete/search?output=chrome&q={searchTerms}'
                NewTabPageContentEnabled = '0'; NewTabPageHideDefaultTopSites = '1'
            }
            $removed = 0
            foreach ($p in 'HKCU:\SOFTWARE\Policies\Microsoft\Edge', 'HKLM:\SOFTWARE\Policies\Microsoft\Edge') {
                $vals = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
                if (-not $vals) { continue }
                foreach ($n in $mine.Keys) {
                    if ($null -ne $vals.$n -and "$($vals.$n)" -eq $mine[$n]) {
                        Remove-ItemProperty -Path $p -Name $n
                        $removed++
                    }
                }
            }
            Write-Output "Edge: removed $removed policy value(s) WinMend had set"
        }

        Step 'Fast Startup' {
            $power = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -ErrorAction SilentlyContinue
            if ($power.HibernateEnabled -ne 1) {
                $out = & powercfg.exe /hibernate on 2>&1
                if ($LASTEXITCODE -ne 0) { throw ("hibernation could not be turned on: " + ("$out".Trim())) }
            }
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled' -Type DWord -Value 1 -Force
            Write-Output 'Hibernation and Fast Startup: on'
        }

        Step 'Background apps' {
            $ba = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications'
            if ($null -ne (Get-ItemProperty -Path $ba -Name 'GlobalUserDisabled' -ErrorAction SilentlyContinue)) {
                Remove-ItemProperty -Path $ba -Name 'GlobalUserDisabled'
            }
            Write-Output 'Background apps: allowed'
        }

        # Undo RAM Optimizations: services back to Automatic and running.
        # WSearch ships as Automatic (Delayed Start), which sc.exe can express.
        foreach ($name in 'SysMain', 'DiagTrack', 'WSearch', 'DPS') {
            Step $name {
                $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
                if (-not $svc) { return }
                $mode = if ($name -eq 'WSearch') { 'delayed-auto' } else { 'auto' }
                $out = & sc.exe config $name start= $mode 2>&1
                if ($LASTEXITCODE -ne 0) { throw ("Windows refused to set it to Automatic: " + ("$out".Trim())) }
                try { Start-Service -Name $name -ErrorAction Stop } catch {
                    Write-Output "$name : set to Automatic but would not start yet - $($_.Exception.Message)"
                }
                $now = Get-Service -Name $name
                Write-Output "$name : $($now.Status), start type $($now.StartType)"
            }
        }

        Step 'Memory compression' {
            if (-not (Get-MMAgent).MemoryCompression) {
                Enable-MMAgent -MemoryCompression
                Write-Output 'Memory compression re-enabled'
            }
        }

        Step 'Delivery Optimization' {
            if (Get-Command Set-DODownloadMode -ErrorAction SilentlyContinue) {
                Set-DODownloadMode -DownloadMode Lan
                Write-Output "Delivery Optimization back to $(Get-DODownloadMode)"
            }
        }

        Step 'Page file' {
            $rec = Get-ItemProperty -Path $undo -ErrorAction SilentlyContinue
            if (-not $rec -or -not $rec.PagefileRecorded) { Write-Output 'Page file: WinMend never changed it'; return }
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem
            $prev = @($rec.PagingFiles | Where-Object { $_ })
            if ($rec.AutomaticManagedPagefile -eq 1 -or -not $prev.Count) {
                if (-not $cs.AutomaticManagedPagefile) {
                    Set-CimInstance -InputObject $cs -Property @{ AutomaticManagedPagefile = $true } | Out-Null
                }
                Write-Output 'Page file: managed by Windows again'
            } else {
                if ($cs.AutomaticManagedPagefile) {
                    Set-CimInstance -InputObject $cs -Property @{ AutomaticManagedPagefile = $false } | Out-Null
                }
                Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Type MultiString -Value ([string[]]$prev) -Force
                Write-Output ("Page file: back to " + ($prev -join '; '))
            }
            foreach ($n in 'PagefileRecorded', 'PagingFiles', 'AutomaticManagedPagefile') {
                Remove-ItemProperty -Path $undo -Name $n -ErrorAction SilentlyContinue
            }
            Write-Output 'WM_RESTART|the page file'
        }

        Step 'Memory Integrity' {
            $rec = Get-ItemProperty -Path $undo -ErrorAction SilentlyContinue
            if (-not $rec -or -not $rec.MemoryIntegrityRecorded) { Write-Output 'Memory Integrity: WinMend never changed it'; return }
            if ($rec.MemoryIntegrityEnabled -eq 1) {
                $hvci = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
                Ensure $hvci
                Set-ItemProperty -Path $hvci -Name 'Enabled' -Type DWord -Value 1 -Force
                if ($rec.MemoryIntegrityLocked) {
                    Set-ItemProperty -Path $hvci -Name 'Locked' -Type DWord -Value ([int]$rec.MemoryIntegrityLocked) -Force
                }
                Write-Output 'Memory Integrity: back on'
                Write-Output 'WM_RESTART|Memory Integrity'
            } else {
                Write-Output 'Memory Integrity: it was already off before WinMend, so it stays off'
            }
            foreach ($n in 'MemoryIntegrityRecorded', 'MemoryIntegrityEnabled', 'MemoryIntegrityLocked') {
                Remove-ItemProperty -Path $undo -Name $n -ErrorAction SilentlyContinue
            }
        }

        Step 'Graphics preferences' {
            $added = @((Get-ItemProperty -Path $undo -Name 'GpuPreferencesAdded' -ErrorAction SilentlyContinue).GpuPreferencesAdded | Where-Object { $_ })
            if (-not $added.Count) { Write-Output 'Graphics preferences: WinMend added none'; return }
            $gp = 'HKCU:\Software\Microsoft\DirectX\UserGpuPreferences'
            $cur = Get-ItemProperty -Path $gp -ErrorAction SilentlyContinue
            $removed = 0
            foreach ($exe in $added) {
                # Only while it still holds what WinMend wrote: one the user has
                # changed since, in Settings, is theirs.
                if ($cur -and "$($cur.$exe)" -eq 'GpuPreference=2;') {
                    Remove-ItemProperty -Path $gp -Name $exe
                    $removed++
                }
            }
            Remove-ItemProperty -Path $undo -Name 'GpuPreferencesAdded' -ErrorAction SilentlyContinue
            Write-Output "Graphics preferences: removed $removed that WinMend had added"
        }

        Step 'AMD External Events Utility' {
            # Only what SSD Saver recorded before disabling it. A service the
            # user disabled themselves is theirs, and stays disabled.
            $name = 'AMD External Events Utility'
            $rec = Get-ItemProperty -Path $undo -ErrorAction SilentlyContinue
            if (-not $rec -or -not $rec.AmdExternalEventsRecorded) { Write-Output "${name}: WinMend never changed it"; return }
            $mode = @{ 'automatic' = 'auto'; 'delayed-auto' = 'delayed-auto'; 'manual' = 'demand' }["$($rec.AmdExternalEventsStartType)"]
            if (-not $mode) { throw "the recorded start type '$($rec.AmdExternalEventsStartType)' is not one WinMend writes" }
            if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
                $out = & sc.exe config $name start= $mode 2>&1
                if ($LASTEXITCODE -ne 0) { throw ("Windows refused to change its start type: " + ("$out".Trim())) }
                if ($mode -ne 'demand') {
                    try { Start-Service -Name $name -ErrorAction Stop } catch {
                        Write-Output "${name}: start type restored but it would not start yet - $($_.Exception.Message)"
                    }
                }
                $now = Get-Service -Name $name
                Write-Output "${name}: $($now.Status), start type $($now.StartType)"
            } else {
                Write-Output "${name}: no longer installed, so there was nothing to turn back on"
            }
            foreach ($n in 'AmdExternalEventsRecorded', 'AmdExternalEventsStartType') {
                Remove-ItemProperty -Path $undo -Name $n -ErrorAction SilentlyContinue
            }
        }
        '''
        try:
            lines = []
            rc, _ = self._run_live_command(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'RemoteSigned', '-Command', ps_script],
                label, output=lines)
            if self.cancel_event.is_set():
                return
            self.queue.put(f"PROGRESS:{label}:Switching the animations back on...")
            self._apply_visual_effects(label, reduced=False)

            failures = [line.split("|", 1)[1] for line in lines if line.startswith("WM_FAIL|")]
            for why in failures:
                self._report_failure(f"PROGRESS:{label}:Not restored -- {why}")
            if rc != 0 and not failures:
                self._report_failure(f"PROGRESS:{label}:The reset stopped early (code {rc}); the lines "
                                     f"above show how far it got.")
            restart = [line.split("|", 1)[1] for line in lines if line.startswith("WM_RESTART|")]
            if restart:
                what = " and ".join(restart)
                self.queue.put(f"REBOOTRECOMMEND:Reset Windows Defaults:{what[0].upper()}{what[1:]} "
                               f"only change{'s' if len(restart) == 1 else ''} back at the next restart.")
            if rc == 0 and not failures:
                self.queue.put(f"PROGRESS:{label}:Defaults restored. Some changes take effect after "
                               f"sign-out / reboot.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")

    def run_system_restore_browser(self):
        """List existing restore points and roll back to the chosen one."""
        label = "Restore Browser"
        self.queue.put(f"PROGRESS:{label}:Enumerating restore points...")
        try:
            r = wm_run(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'RemoteSigned', '-Command',
                 "Get-ComputerRestorePoint -ErrorAction Stop | ForEach-Object { "
                 "  $t = $_.ConvertToDateTime($_.CreationTime).ToString('yyyy-MM-dd HH:mm'); "
                 "  Write-Output \"$($_.SequenceNumber)|$t|$($_.Description)\" }"],
                capture_output=True, text=True, encoding='utf-8', errors='replace',
                timeout=60, startupinfo=_no_console_startupinfo()
            )
            lines = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()]
            if not lines and r.returncode != 0:
                self._report_failure(f"PROGRESS:{label}:Could not list restore points: "
                                     f"{_wm_last_line(r.stderr) or r.returncode}")
                return
            if not lines:
                self.queue.put(f"PROGRESS:{label}:No restore points found. Use 'Create Restore Point' first.")
                messagebox.showinfo("System Restore Browser",
                                    "No System Restore checkpoints exist on this PC yet.\n\n"
                                    "Use the 'Create Restore Point (Guardrail)' option to create one.")
                return

            options = []
            for ln in reversed(lines[-30:]):
                parts = ln.split("|", 2)
                if len(parts) == 3 and parts[0].isdigit():
                    seq, dt, desc = parts
                    options.append((seq, f"#{seq}  {dt}  -  {desc[:60]}"))

            if not options:
                self._report_failure(f"PROGRESS:{label}:Could not read the restore-point list.")
                return

            choice = self._ui_radio_picker(
                "System Restore Browser",
                "Select a checkpoint to roll back to. Windows will reboot to perform the restore.",
                options
            )
            if not choice:
                self._report_skip(f"PROGRESS:{label}:Cancelled.")
                return

            if not messagebox.askyesno(
                "Confirm Restore",
                f"About to roll back to restore point #{choice}.\n\n"
                "Windows will reboot and revert system files/settings/installed programs to that state.\n"
                "Your personal documents are not affected.\n\n"
                "Continue?", icon='warning'
            ):
                self._report_skip(f"PROGRESS:{label}:Cancelled at confirmation.")
                return

            self.queue.put(f"PROGRESS:{label}:Initiating restore to checkpoint #{choice}...")
            rc, _ = self._run_live_command(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'RemoteSigned', '-Command',
                 f"Restore-Computer -RestorePoint {int(choice)} -Confirm:$false"],
                'Restore Browser', timeout=60
            )
            if rc == 0:
                self.queue.put(f"PROGRESS:{label}:Restore initiated. System will reboot.")
            elif not self.cancel_event.is_set():
                self._report_failure(f"PROGRESS:{label}:Windows did not start the restore (code {rc}); "
                                     f"the lines above say why. Nothing was changed.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")
