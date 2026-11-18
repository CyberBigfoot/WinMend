"""WinMend features: startup: operations."""

from __future__ import annotations

from winmend.core.processes import _no_console_startupinfo, wm_run
from winmend.core.search import _wm_last_line
import subprocess


class StartupTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    # ==================== APP SETTINGS METHODS ====================

    def stop_background_apps(self):
        """Stop background applications from running"""
        self.queue.put("PROGRESS:Stop Background Apps:Stopping background apps...")
        failure = None
        try:
            # Safe PowerShell script to disable background apps
            ps_script = '''
            try {
                $ErrorActionPreference = "Stop"

                # Disable background apps globally
                $registryPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\BackgroundAccessApplications"

                # Create registry path if it doesn't exist
                if (-not (Test-Path "HKCU:\\$registryPath")) {
                    New-Item -Path "HKCU:\\$registryPath" -Force | Out-Null
                }

                # Set global disable flag
                Set-ItemProperty -Path "HKCU:\\$registryPath" -Name "GlobalUserDisabled" -Value 1 -Type DWORD -Force

                # Read the flag back so success is a measurement, not an assumption
                $applied = (Get-ItemProperty -Path "HKCU:\\$registryPath" -Name "GlobalUserDisabled").GlobalUserDisabled
                if ($applied -ne 1) {
                    throw "GlobalUserDisabled is $applied after the write, expected 1"
                }

                Write-Host "Background apps disabled successfully (GlobalUserDisabled=1, verified)"
            } catch {
                Write-Error "Error disabling background apps: $($_.Exception.Message)"
                exit 1
            }
            '''

            self.queue.put("PROGRESS:Stop Background Apps:Executing PowerShell script...")
            result = wm_run(
                ['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned', '-Command', ps_script],
                capture_output=True,
                text=True, encoding='utf-8', errors='replace',
                check=False,
                timeout=60,
                startupinfo=_no_console_startupinfo()  # Hide console window
            )

            if result.stdout.strip():
                self.queue.put("PROGRESS:Stop Background Apps:Script output:")
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        self.queue.put(f"PROGRESS:Stop Background Apps:  {line.strip()}")

            if result.stderr.strip():
                self.queue.put("PROGRESS:Stop Background Apps:Script errors:")
                for line in result.stderr.strip().split('\n'):
                    if line.strip():
                        self.queue.put(f"PROGRESS:Stop Background Apps:  {line.strip()}")

            if result.returncode != 0:
                failure = _wm_last_line(result.stderr, result.stdout) or \
                    f"PowerShell exited with code {result.returncode}"

        except subprocess.TimeoutExpired:
            failure = "the operation timed out after 60 seconds"
            self.queue.put("PROGRESS:Stop Background Apps:Background apps operation timed out")
        except Exception as e:
            failure = str(e)
            self.queue.put(f"PROGRESS:Stop Background Apps:Error stopping background apps: {str(e)}")

        # Raised outside the handlers above so the runner marks the task failed
        # instead of logging the problem and calling it done.
        if failure:
            raise RuntimeError(f"Background apps were not disabled: {failure}")

    def disable_startup_apps(self):
        """Disable startup applications except OneDrive using StartupApproved entries"""
        self.queue.put("PROGRESS:Disable Startup Apps:Disabling startup apps (except OneDrive)...")
        failure = None
        try:
            # Uses StartupApproved (Task Manager-compatible) and covers Run keys + Startup folders
            ps_script = '''
            try {
                $ErrorActionPreference = "Stop"
                $disabledCount = 0
                $failedCount = 0

                function Disable-StartupApprovedValue {
                    param(
                        [string]$ApprovedPath,
                        [string]$ItemName,
                        [byte[]]$DisabledValue
                    )

                    if ([string]::IsNullOrWhiteSpace($ItemName)) { return $false }
                    if ($ItemName -like "*OneDrive*") {
                        Write-Host "Skipped OneDrive: $ItemName"
                        return $false
                    }

                    if (-not (Test-Path $ApprovedPath)) {
                        New-Item -Path $ApprovedPath -Force | Out-Null
                    }

                    Set-ItemProperty -Path $ApprovedPath -Name $ItemName -Value $DisabledValue -Type Binary -Force
                    $actual = Get-ItemPropertyValue -Path $ApprovedPath -Name $ItemName -ErrorAction Stop
                    if ([BitConverter]::ToString([byte[]]$actual) -ne [BitConverter]::ToString($DisabledValue)) {
                        throw "The startup approval value did not stick"
                    }
                    Write-Host "Disabled startup item: $ItemName"
                    return $true
                }

                # StartupApproved value format: first byte 0x03 = disabled
                $disabledValue = [byte[]](0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

                # Disable startup items from Run keys (user + machine + 32-bit machine)
                $runLocations = @(
                    @{ RunPath = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"; ApprovedPath = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run" },
                    @{ RunPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"; ApprovedPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run" },
                    @{ RunPath = "HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"; ApprovedPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run32" }
                )

                foreach ($location in $runLocations) {
                    if (Test-Path $location.RunPath) {
                        $runItems = Get-ItemProperty -Path $location.RunPath
                        foreach ($prop in $runItems.PSObject.Properties) {
                            if ($prop.Name -notlike "PS*") {
                                try {
                                    if (Disable-StartupApprovedValue -ApprovedPath $location.ApprovedPath -ItemName $prop.Name -DisabledValue $disabledValue) {
                                        $disabledCount++
                                    }
                                } catch {
                                    $failedCount++
                                    Write-Warning "Could not disable: $($prop.Name) from $($location.RunPath) - $($_.Exception.Message)"
                                }
                            }
                        }
                    }
                }

                # Disable startup items from Startup folders (current user + all users)
                $startupFolderTargets = @(
                    @{ FolderPath = [Environment]::GetFolderPath('Startup'); ApprovedPath = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\StartupFolder" },
                    @{ FolderPath = "$env:ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"; ApprovedPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\StartupFolder" }
                )

                foreach ($target in $startupFolderTargets) {
                    if (Test-Path $target.FolderPath) {
                        Get-ChildItem -Path $target.FolderPath -File -ErrorAction SilentlyContinue | ForEach-Object {
                            $itemName = $_.Name
                            try {
                                if (Disable-StartupApprovedValue -ApprovedPath $target.ApprovedPath -ItemName $itemName -DisabledValue $disabledValue) {
                                    $disabledCount++
                                }
                            } catch {
                                $failedCount++
                                Write-Warning "Could not disable startup folder item: $itemName - $($_.Exception.Message)"
                            }
                        }
                    }
                }

                Write-Host "Total disabled items: $disabledCount"
                if ($failedCount -gt 0) {
                    Write-Error "$failedCount startup item(s) could not be disabled"
                    exit 1
                }
                Write-Host "Startup apps disabled successfully (entries preserved, can be re-enabled)"

            } catch {
                Write-Error "Error disabling startup apps: $($_.Exception.Message)"
                exit 1
            }
            '''

            self.queue.put("PROGRESS:Disable Startup Apps:Executing PowerShell script...")
            result = wm_run(
                ['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned', '-Command', ps_script],
                capture_output=True,
                text=True, encoding='utf-8', errors='replace',
                check=False,
                timeout=120,
                startupinfo=_no_console_startupinfo()  # Hide console window
            )

            if result.stdout.strip():
                self.queue.put("PROGRESS:Disable Startup Apps:Script output:")
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        self.queue.put(f"PROGRESS:Disable Startup Apps:  {line.strip()}")

            if result.stderr.strip():
                self.queue.put("PROGRESS:Disable Startup Apps:Script errors:")
                for line in result.stderr.strip().split('\n'):
                    if line.strip():
                        self.queue.put(f"PROGRESS:Disable Startup Apps:  {line.strip()}")

            if result.returncode != 0:
                self.queue.put(f"PROGRESS:Disable Startup Apps:Script exited with code {result.returncode}")
                failure = _wm_last_line(result.stderr, result.stdout) or \
                    f"PowerShell exited with code {result.returncode}"

        except subprocess.TimeoutExpired:
            failure = "the operation timed out after 120 seconds"
            self.queue.put("PROGRESS:Disable Startup Apps:Startup apps operation timed out")
        except Exception as e:
            failure = str(e)
            self.queue.put(f"PROGRESS:Disable Startup Apps:Error disabling startup apps: {str(e)}")

        # Raised outside the handlers above so the runner marks the task failed
        # instead of logging the problem and calling it done.
        if failure:
            raise RuntimeError(f"Startup apps were not disabled: {failure}")
