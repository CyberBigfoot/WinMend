"""WinMend features: reporting."""

from __future__ import annotations

from pathlib import Path
from winmend.core.search import _wm_last_line
from winmend.reports.system import PCReporter
import os
import csv
import re
import time
import webbrowser


class ReportingTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    # ==================== PC REPORT METHODS ====================
    def generate_pc_report(self):
        """Generate a comprehensive PC report using the new PCReporter class"""
        self.queue.put("PROGRESS:PC Report:Starting comprehensive PC report generation...")
        self.queue.put("PROGRESS:PC Report:This may take several minutes. Please be patient.")

        try:
            # Create a PCReporter instance
            reporter = PCReporter()

            # Collect all system information
            self.queue.put("PROGRESS:PC Report:Collecting system information...")
            reporter.collect_system_info()

            self.queue.put("PROGRESS:PC Report:Collecting hardware information...")
            reporter.collect_hardware_info()

            self.queue.put("PROGRESS:PC Report:Collecting software information...")
            reporter.collect_software_info()

            self.queue.put("PROGRESS:PC Report:Collecting network information...")
            reporter.collect_network_info()

            self.queue.put("PROGRESS:PC Report:Collecting security information...")
            reporter.collect_security_info()

            self.queue.put("PROGRESS:PC Report:Collecting user information...")
            reporter.collect_user_info()

            self.queue.put("PROGRESS:PC Report:Collecting environment variables...")
            reporter.collect_environment_info()

            self.queue.put("PROGRESS:PC Report:Collecting running processes...")
            reporter.collect_process_info()

            self.queue.put("PROGRESS:PC Report:Collecting system services...")
            reporter.collect_service_info()

            self.queue.put("PROGRESS:PC Report:Collecting hardware devices...")
            reporter.collect_device_info()

            self.queue.put("PROGRESS:PC Report:Collecting performance metrics...")
            reporter.collect_performance_metrics()

            self.queue.put("PROGRESS:PC Report:Checking for security vulnerabilities...")
            reporter.collect_vulnerability_info()

            self.queue.put("PROGRESS:PC Report:Collecting startup items information...")
            reporter.collect_startup_info()

            self.queue.put("PROGRESS:PC Report:Collecting installed Windows updates...")
            reporter._collect_windows_updates()

            # Generate HTML report. Saved to the Desktop like every other
            # report: the old relative "PC_Report.html" landed in whatever the
            # working directory was -- beside the exe, or System32 when
            # WinMend had been relaunched elevated.
            reporter.report_file = os.path.join(
                self._get_desktop_dir(), f"PC_Report_{time.strftime('%Y%m%d_%H%M%S')}.html")
            self.queue.put("PROGRESS:PC Report:Generating HTML report...")
            report_path = os.path.abspath(reporter.generate_html_report())

            self.queue.put(f"PROGRESS:PC Report:Report saved to: {report_path}")

            # Open the report in the default browser
            self.queue.put("PROGRESS:PC Report:Opening report in default browser...")
            webbrowser.open(Path(report_path).as_uri())

            self.queue.put("PROGRESS:PC Report:PC Report generation completed successfully!")

        except Exception as e:
            self._report_failure(f"PROGRESS:PC Report:Error generating PC Report: {str(e)}")
            import traceback
            self.queue.put(f"PROGRESS:PC Report:Traceback: {traceback.format_exc()}")

    # Read in memory, never from a script file. This used to write
    # Get-AutoPilotInfo.ps1 into C:\PowerShell and run it from there -- elevated.
    # A folder made at the root of C: inherits "Authenticated Users: Modify", so
    # any account on the PC could swap the script before it ran as
    # administrator, or create C:\PowerShell first as a junction pointing
    # anywhere. The query prints the two values; WinMend writes the CSV itself.
    AUTOPILOT_QUERY = r'''
    $ErrorActionPreference = 'Stop'
    try {
        $serial = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
        $detail = Get-CimInstance -Namespace root/cimv2/mdm/dmmap -ClassName MDM_DevDetail_Ext01 -Filter "InstanceID='Ext'"
        Write-Output ("SERIAL|" + ([string]$serial).Trim())
        Write-Output ("HASH|" + ([string]$detail.DeviceHardwareData).Trim())
    } catch {
        Write-Output "ERR|$($_.Exception.Message)"
        exit 1
    }
    '''

    def create_autopilot_csv(self):
        """Export this PC's serial number and hardware hash for Autopilot enrollment."""
        label = "AutoPilot CSV"
        self.queue.put(f"PROGRESS:{label}:Reading the serial number and hardware hash...")
        try:
            r = self._run_ps(self.AUTOPILOT_QUERY, timeout=300)
        except Exception as exc:
            self._report_failure(f"PROGRESS:{label}:The hardware hash could not be read: {exc}")
            return
        if self.cancel_event.is_set():
            return
        values = {}
        for line in (r.stdout or "").splitlines():
            key, _, value = line.strip().partition("|")
            if key in ("SERIAL", "HASH", "ERR"):
                values[key] = value.strip()
        if r.returncode != 0 or "ERR" in values:
            reason = values.get("ERR") or _wm_last_line(r.stderr) or f"exit code {r.returncode}"
            if not self.admin_status:
                reason += " -- the hardware hash needs WinMend running as administrator"
            self._report_failure(f"PROGRESS:{label}:The hardware hash could not be read: {reason}")
            return
        serial, hardware_hash = values.get("SERIAL", ""), values.get("HASH", "")
        if not serial or not re.fullmatch(r"[A-Za-z0-9+/=]{64,}", hardware_hash):
            self._report_failure(f"PROGRESS:{label}:Windows did not return both a serial number and a "
                                 f"hardware hash, so there is nothing that could enroll this device.")
            return

        folder = self._get_desktop_dir()
        output_file = os.path.join(folder, f"AutoPilot_{time.strftime('%Y%m%d_%H%M%S')}.csv")
        try:
            # Plain ASCII, unquoted, the layout Get-WindowsAutopilotInfo writes.
            with open(output_file, "x", encoding="ascii", errors="strict", newline="") as f:
                writer = csv.writer(f, lineterminator="\r\n")
                writer.writerow(["Device Serial Number", "Windows Product ID", "Hardware Hash"])
                writer.writerow([serial, "", hardware_hash])
            with open(output_file, "r", encoding="ascii", newline="") as f:
                rows = list(csv.DictReader(f))
        except (OSError, UnicodeError, csv.Error) as exc:
            self._report_failure(f"PROGRESS:{label}:The CSV could not be written to {folder}: {exc}")
            return
        if len(rows) != 1 or rows[0].get("Device Serial Number") != serial \
                or rows[0].get("Hardware Hash") != hardware_hash:
            self._report_failure(f"PROGRESS:{label}:The CSV at {output_file} did not read back as "
                                 f"written; do not upload it.")
            return
        self.queue.put(f"PROGRESS:{label}:Serial number {serial}; hardware hash of "
                       f"{len(hardware_hash)} characters.")
        self.queue.put(f"PROGRESS:{label}:Saved to {output_file}. Upload it in Intune under Devices > "
                       f"Windows > Windows enrollment > Devices > Import.")
