"""WinMend features: privacy."""

from __future__ import annotations

from winmend.core.prompts import messagebox


class PrivacyTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    def run_telemetry_hard_disable(self):
        """Thorough telemetry / tracking shutdown."""
        label = "Telemetry"
        if not messagebox.askyesno(
            "Telemetry Hard-Disable",
            "This will:\n"
            " - Disable DiagTrack (Connected User Experiences and Telemetry) service\n"
            " - Disable scheduled tasks for CompatTelRunner and ProgramDataUpdater\n"
            " - Set telemetry policy to its lowest level\n"
            " - Clear & disable Advertising ID\n"
            " - Disable app-launch tracking, tailored experiences, inking/typing data\n"
            " - Disable feedback prompts\n\n"
            "Sign-out / reboot recommended afterward.\n\nContinue?"
        ):
            self._report_skip(f"PROGRESS:{label}:Cancelled by user.")
            return

        # Each part is checked and names itself when it fails. The old script
        # printed "Disabled task: ..." after every schtasks call whatever it
        # returned -- a native command's failure never reaches a PowerShell
        # catch -- and "stopped + disabled" without reading the service back.
        ps_script = r'''
        $ErrorActionPreference = 'Stop'
        function Step([string]$what, [scriptblock]$body) {
            try { & $body } catch { Write-Output ("WM_FAIL|" + $what + ": " + $_.Exception.Message) }
        }
        function Set-Dword([string]$path, [string]$name, [int]$value) {
            if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
            Set-ItemProperty -Path $path -Name $name -Type DWord -Value $value -Force
        }

        foreach ($svcName in 'DiagTrack', 'dmwappushservice') {
            Step $svcName {
                $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
                if (-not $svc) { Write-Output "${svcName}: not on this PC"; return }
                Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
                Set-Service -Name $svcName -StartupType Disabled
                $now = Get-Service -Name $svcName
                if ("$($now.StartType)" -ne 'Disabled') { throw "it still reads $($now.StartType)" }
                Write-Output "${svcName}: $($now.Status), disabled"
            }
        }

        Step 'Telemetry policy' {
            $dc = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            Set-Dword $dc 'AllowTelemetry' 0
            Set-Dword $dc 'AllowDeviceNameInTelemetry' 0
            Write-Output 'Telemetry policy set to its lowest level (Home and Pro treat 0 as Required)'
        }

        Step 'Advertising ID' {
            $adv = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
            Set-Dword $adv 'Enabled' 0
            Remove-ItemProperty -Path $adv -Name 'Id' -ErrorAction SilentlyContinue
            Write-Output 'Advertising ID disabled and cleared'
        }

        Step 'App launch tracking' {
            Set-Dword 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'Start_TrackProgs' 0
            Write-Output 'App launch tracking disabled'
        }

        Step 'Tailored experiences' {
            Set-Dword 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy' 'TailoredExperiencesWithDiagnosticDataEnabled' 0
            Write-Output 'Tailored experiences disabled'
        }

        Step 'Feedback prompts' {
            $sf = 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules'
            Set-Dword $sf 'NumberOfSIUFInPeriod' 0
            Set-Dword $sf 'PeriodInNanoSeconds' 0
            Write-Output 'Feedback prompts disabled'
        }

        Step 'Inking and typing data' {
            Set-Dword 'HKCU:\SOFTWARE\Microsoft\Input\TIPC' 'Enabled' 0
            $perz = 'HKCU:\SOFTWARE\Microsoft\InputPersonalization'
            Set-Dword $perz 'RestrictImplicitTextCollection' 1
            Set-Dword $perz 'RestrictImplicitInkCollection' 1
            Write-Output 'Inking/typing data collection disabled'
        }

        $tasks = @(
            '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
            '\Microsoft\Windows\Application Experience\ProgramDataUpdater',
            '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
            '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip',
            '\Microsoft\Windows\Autochk\Proxy',
            '\Microsoft\Windows\Feedback\Siuf\DmClient',
            '\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload'
        )
        foreach ($t in $tasks) {
            Step "task $t" {
                $cut = $t.LastIndexOf('\') + 1
                $path = $t.Substring(0, $cut); $name = $t.Substring($cut)
                $task = Get-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction SilentlyContinue
                if (-not $task) { Write-Output "Not on this PC: $t"; return }
                if ("$($task.State)" -eq 'Disabled') { Write-Output "Already disabled: $t"; return }
                Disable-ScheduledTask -TaskPath $path -TaskName $name | Out-Null
                Write-Output "Disabled task: $t"
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
            failures = [line.split("|", 1)[1] for line in lines if line.startswith("WM_FAIL|")]
            for why in failures:
                self._report_failure(f"PROGRESS:{label}:Not applied -- {why}")
            if rc != 0 and not failures:
                self._report_failure(f"PROGRESS:{label}:The script stopped early (code {rc}); the lines "
                                     f"above show how far it got.")
            elif not failures:
                self.queue.put(f"PROGRESS:{label}:Telemetry hardening applied. Sign out or restart for "
                               f"every change to apply.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")
