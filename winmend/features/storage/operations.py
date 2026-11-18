"""WinMend features: storage: operations."""

from __future__ import annotations




class StorageTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    def run_defrag_optimize(self):
        """Optimize drives - TRIM for SSDs, Defrag for HDDs only. NEVER defrags an SSD."""
        self.queue.put("PROGRESS:Optimize Drives:Starting drive optimization...")
        self.queue.put("PROGRESS:Optimize Drives:Detecting drive types (SSD vs HDD)...")

        try:
            # Use PowerShell to detect drive types and optimize accordingly
            ps_script = '''
            $ErrorActionPreference = "Continue"

            # Get all fixed volumes
            $volumes = Get-Volume | Where-Object { $_.DriveType -eq "Fixed" -and $_.DriveLetter -ne $null }
            $failed = 0

            foreach ($vol in $volumes) {
                $letter = $vol.DriveLetter
                Write-Host ""
                Write-Host "=== Processing Drive $($letter): ==="

                # Detect if the drive is SSD or HDD using Get-PhysicalDisk
                $partition = Get-Partition -DriveLetter $letter -ErrorAction SilentlyContinue
                if ($partition) {
                    $disk = Get-PhysicalDisk | Where-Object { $_.DeviceId -eq $partition.DiskNumber }
                    $mediaType = $disk.MediaType

                    try {
                        if ($mediaType -eq "SSD" -or $mediaType -eq "Unspecified") {
                            # SSD or NVMe -- run TRIM only, NEVER defrag
                            Write-Host "Drive $($letter): is $mediaType -- Running TRIM (retrim)"
                            Write-Host "IMPORTANT: Defrag is SKIPPED for this drive (SSD protection)"
                            Optimize-Volume -DriveLetter $letter -ReTrim -Verbose -ErrorAction Stop
                            Write-Host "TRIM completed for drive $($letter):"
                        } elseif ($mediaType -eq "HDD") {
                            # HDD -- safe to defrag
                            Write-Host "Drive $($letter): is HDD -- Running defragmentation"
                            Optimize-Volume -DriveLetter $letter -Defrag -Verbose -ErrorAction Stop
                            Write-Host "Defragmentation completed for drive $($letter):"
                        } else {
                            Write-Host "Drive $($letter): Unknown media type '$mediaType' -- Running TRIM to be safe"
                            Optimize-Volume -DriveLetter $letter -ReTrim -Verbose -ErrorAction Stop
                        }
                    } catch {
                        $failed++
                        Write-Host "Drive $($letter): could not be optimized -- $($_.Exception.Message)"
                    }
                } else {
                    Write-Host "Could not detect drive type for $($letter): -- skipping"
                }
            }

            Write-Host ""
            Write-Host "=== Drive optimization complete ==="
            if ($failed) { exit 1 }
            '''

            rc, timed_out = self._run_live_command(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'RemoteSigned', '-Command', ps_script],
                'Optimize Drives', timeout=1800)  # 30 min timeout for large HDDs

            if rc == 0:
                self.queue.put("PROGRESS:Optimize Drives:All drives optimized successfully!")
            elif not self.cancel_event.is_set():
                self._report_failure(f"PROGRESS:Optimize Drives:Optimization failed on at least one "
                                     f"drive (code {rc}); the lines above say which.")

        except Exception as e:
            self._report_failure(f"PROGRESS:Optimize Drives:Error: {str(e)}")

    def run_disk_smart_check(self):
        """Read SMART/reliability counters for every physical disk. Read-only."""
        label = "Disk Health"
        self.queue.put(f"PROGRESS:{label}:Reading SMART reliability data for all drives...")
        ps_script = r'''
        try {
            $rows = foreach ($d in (Get-PhysicalDisk | Sort-Object DeviceId)) {
                $r = Get-StorageReliabilityCounter -PhysicalDisk $d -ErrorAction SilentlyContinue
                [pscustomobject]@{
                    Disk       = $d.DeviceId
                    Name       = $d.FriendlyName
                    Media      = "$($d.MediaType)"
                    Health     = "$($d.HealthStatus)"
                    Status     = ($d.OperationalStatus -join ',')
                    SizeGB     = [math]::Round($d.Size / 1GB)
                    TempC      = if ($r -and $r.Temperature) { $r.Temperature } else { '-' }
                    Wear       = if ($r -and $null -ne $r.Wear) { "$($r.Wear)%" } else { '-' }
                    PowerOnHrs = if ($r -and $r.PowerOnHours) { $r.PowerOnHours } else { '-' }
                    ReadErrs   = if ($r -and $null -ne $r.ReadErrorsTotal) { $r.ReadErrorsTotal } else { '-' }
                    WriteErrs  = if ($r -and $null -ne $r.WriteErrorsTotal) { $r.WriteErrorsTotal } else { '-' }
                }
            }
            $rows | Format-Table -AutoSize | Out-String -Width 220
            $bad = @($rows | Where-Object { $_.Health -ne 'Healthy' })
            if ($bad.Count) { "WARNING: drive(s) NOT healthy: " + (($bad | ForEach-Object { $_.Name }) -join '; ') }
            else { "All drives report Healthy." }
        } catch { "ERROR: $($_.Exception.Message)"; exit 1 }
        '''
        try:
            r = self._run_ps(ps_script)
            text = (r.stdout or "").strip()
            if r.returncode != 0 or not text:
                self._report_failure(f"PROGRESS:{label}:Could not read disk health: "
                                     f"{(text or r.stderr or 'no output').strip()[:200]}")
                return
            for line in text.splitlines():
                if line.strip():
                    self.queue.put(f"PROGRESS:{label}:{line.rstrip()}")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")
