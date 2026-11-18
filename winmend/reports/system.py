"""WinMend reports: system."""

from __future__ import annotations

from datetime import datetime
from winmend.core.processes import _no_console_startupinfo, wm_run
from winmend.reports.system_hardware import ReportSystemHardwareMixin
from winmend.reports.system_health import ReportSystemHealthMixin
from winmend.reports.system_html import ReportSystemHtmlMixin
from winmend.reports.system_software import ReportSystemSoftwareMixin
from winmend.reports.system_tables import ReportSystemTablesMixin
import platform
import re
import socket


class PCReporter(
    ReportSystemHardwareMixin,
    ReportSystemSoftwareMixin,
    ReportSystemHealthMixin,
    ReportSystemHtmlMixin,
    ReportSystemTablesMixin,
):

    def __init__(self):
        self.report_data = {
            "system_info": {},
            "hardware": {},
            "software": {},
            "network": {},
            "security": {},
            "users": {},
            "environment": {},
            "processes": [],
            "services": [],
            "devices": [],
            "performance": {},
            "updates": {},
            "vulnerabilities": {},
            "startup_items": {}  # Added for startup items
        }
        self.report_file = "PC_Report.html"
        # Drive letter -> (media type, bus type), read once for every drive.
        self._drive_media = None

    @staticmethod
    def _ps(script):
        """Run one PowerShell query and return its output ('' on any failure).

        The collectors below used to shell out to wmic. Windows 11 24H2 and
        later no longer ship it, and a missing executable raises
        FileNotFoundError -- which is not a SubprocessError, so the fallback
        loops that expected one bailed out before trying their PowerShell
        alternative. Every hardware query now goes straight to WMI through
        PowerShell, which every supported Windows has.
        """
        try:
            result = wm_run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                startupinfo=_no_console_startupinfo())
            return result.stdout or ""
        except Exception:
            return ""

    def _system_uuid(self):
        """The SMBIOS system UUID the firmware reports, or 'Unavailable'."""
        text = self._ps("(Get-CimInstance -ClassName Win32_ComputerSystemProduct "
                        "-ErrorAction Stop).UUID").strip()
        if re.fullmatch(r"[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}", text):
            return text.upper()
        return "Unavailable"

    def collect_system_info(self):
        """Collect basic system information"""
        import psutil
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot_time

        self.report_data["system_info"] = {
            "Computer Name": socket.gethostname(),
            "Operating System": platform.system(),
            "OS Version": platform.version(),
            "OS Release": platform.release(),
            "Architecture": platform.machine(),
            "Processor": platform.processor(),
            # uuid.getnode(), which this used to show, is the network adapter's
            # MAC address, not the machine's UUID.
            "System UUID": self._system_uuid(),
            "Python Version": platform.python_version(),
            "Boot Time": boot_time.strftime("%Y-%m-%d %H:%M:%S"),
            "System Uptime": f"{uptime.days} days, {uptime.seconds // 3600} hours, {(uptime.seconds % 3600) // 60} minutes",
            "Report Generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
