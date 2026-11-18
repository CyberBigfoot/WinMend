"""WinMend features: protection."""

from __future__ import annotations

import re


class ProtectionTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    def _create_restore_point_guardrail(self, reason):
        """Attempt to create a restore point guardrail before risky operations."""
        safe_reason = re.sub(r'[^a-zA-Z0-9 _-]', '', str(reason))[:42]
        self.queue.put(f"PROGRESS:Guardrail:Creating restore point before: {safe_reason}")
        ps_script = f'''
        try {{
            $ErrorActionPreference = "Stop"
            
            # Ensure System Restore is enabled on C:
            Enable-ComputerRestore -Drive "C:\\" -ErrorAction SilentlyContinue
            
            # Override 24-hour frequency limit in Windows 10/11
            $regKey = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore"
            New-ItemProperty -Path $regKey -Name "SystemRestorePointCreationFrequency" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
            
            # Use WMI for lightning fast creation
            $desc = "EAWTECH Guardrail - {safe_reason}"
            $wmiClass = Get-WmiObject -List -Namespace "root\\default" | Where-Object {{ $_.Name -eq "SystemRestore" }}
            
            if ($wmiClass) {{
                $result = $wmiClass.CreateRestorePoint($desc, 7, 100)
                if ($result.ReturnValue -in 0, 4096) {{
                    Write-Host "Restore point created successfully via WMI."
                    exit 0
                }} else {{
                    Write-Host "WMI returned $($result.ReturnValue), attempting fallback."
                }}
            }}
            
            # Fallback
            Checkpoint-Computer -Description $desc -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
            Write-Host "Restore point created successfully (fallback)."
            exit 0
            
        }} catch {{
            Write-Host "Restore point creation skipped/failed: $($_.Exception.Message)"
            exit 1
        }}
        '''
        try:
            rc, timed_out = self._run_live_command(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'RemoteSigned', '-Command', ps_script],
                'Guardrail', timeout=120)
            if timed_out:
                self.queue.put("PROGRESS:Guardrail:Restore point creation timed out.")
                return False
            if rc == 0:
                self.queue.put("PROGRESS:Guardrail:Restore point guardrail ready.")
                return True
            self.queue.put("PROGRESS:Guardrail:Using existing system restore history (new checkpoint not created).")
            return False
        except Exception as e:
            self.queue.put(f"PROGRESS:Guardrail:Restore point guardrail error: {str(e)}")
            return False

    def run_create_restore_point_guardrail(self):
        """Manual task: create a restore point."""
        # Asked for by name, so not getting one is this task failing -- it used
        # to end green with "using existing system restore history".
        if not self._create_restore_point_guardrail("Manual Guardrail"):
            self._report_failure("PROGRESS:Guardrail:No restore point was created; the lines above "
                                 "say why. System Protection may be off for C:.")
