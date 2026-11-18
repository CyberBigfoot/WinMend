"""WinMend features: power."""

from __future__ import annotations

from pathlib import Path
from winmend.core.processes import _no_console_startupinfo, wm_run
from winmend.core.search import _wm_last_line
import os
import re
import time
import webbrowser


class PowerTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    def run_power_plan_switcher(self):
        """Switch active power plan via powercfg."""
        label = "Power Plan"
        options = [
            ("balanced", "Balanced (recommended for most PCs)"),
            ("high", "High Performance"),
            ("saver", "Power Saver (best battery life)"),
            ("ultimate", "Ultimate Performance (unlock if needed)"),
        ]
        choice = self._ui_radio_picker(
            "Power Plan Switcher",
            "Choose a power plan to activate:",
            options, default="balanced"
        )
        if not choice:
            self._report_skip(f"PROGRESS:{label}:Cancelled.")
            return

        # Microsoft's well-known scheme templates.
        templates = {
            "balanced": "381b4222-f694-41f0-9685-ff5bb260df2e",
            "high":     "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
            "saver":    "a1841308-3541-4fab-bc81-f71556f20b4a",
            "ultimate": "e9a42b02-d5df-448d-aa00-03f14749eb61",
        }
        names = {"balanced": "Balanced", "high": "High performance", "saver": "Power saver",
                 "ultimate": "Ultimate Performance"}
        guid_re = r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
        try:
            listing = wm_run(['powercfg', '/list'], capture_output=True, text=True, encoding='utf-8',
                             errors='replace', startupinfo=_no_console_startupinfo())
            schemes = re.findall(guid_re + r"\s+\((.+?)\)", listing.stdout or "")
            template = templates[choice]
            guid = next((g for g, _n in schemes if g.lower() == template), None)
            if guid is None:
                # A plan copied from the template earlier has its own GUID;
                # reuse it rather than adding yet another copy to the list.
                guid = next((g for g, n in schemes if n.strip().lower() == names[choice].lower()), None)
            if guid is None:
                # Not on the list: laptops with Modern Standby ship Balanced
                # only, and Ultimate is hidden everywhere. Copy the template --
                # the copy gets a NEW GUID, which is the one to activate. The
                # old code activated the template's GUID after copying it and
                # added one more duplicate to the list on every run.
                self.queue.put(f"PROGRESS:{label}:Adding the {names[choice]} plan to this PC...")
                dup = wm_run(['powercfg', '-duplicatescheme', template], capture_output=True, text=True,
                             encoding='utf-8', errors='replace', startupinfo=_no_console_startupinfo())
                found = re.search(guid_re, dup.stdout or "")
                guid = found.group(1) if dup.returncode == 0 and found else None
                if guid is None:
                    self._report_failure(f"PROGRESS:{label}:{names[choice]} is not available on this PC: "
                                         f"{_wm_last_line(dup.stdout, dup.stderr) or dup.returncode}")
                    return

            self.queue.put(f"PROGRESS:{label}:Setting active scheme to {names[choice]}...")
            r = wm_run(['powercfg', '/setactive', guid], capture_output=True, text=True,
                       encoding='utf-8', errors='replace', startupinfo=_no_console_startupinfo())
            active = wm_run(['powercfg', '/getactivescheme'], capture_output=True, text=True,
                            encoding='utf-8', errors='replace', startupinfo=_no_console_startupinfo())
            if r.returncode == 0 and guid.lower() in (active.stdout or "").lower():
                self.queue.put(f"PROGRESS:{label}:Active power plan: {names[choice]} (verified).")
            else:
                self._report_failure(f"PROGRESS:{label}:Could not activate {names[choice]}: "
                                     f"{_wm_last_line(r.stdout, r.stderr) or r.returncode}")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")

    def run_battery_health_report(self):
        """Run powercfg /batteryreport and open the HTML."""
        label = "Battery Report"
        try:
            check = wm_run(
                ['powershell', '-NoProfile', '-Command',
                 "(Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue | Measure-Object).Count"],
                capture_output=True, text=True, encoding='utf-8', errors='replace',
                timeout=20, startupinfo=_no_console_startupinfo()
            )
            count = (check.stdout or "0").strip()
            if count == "0":
                self._report_skip(f"PROGRESS:{label}:This PC has no battery, so there is no battery "
                                  f"report to make.")
                return

            desktop = self._get_desktop_dir()
            ts = time.strftime("%Y%m%d_%H%M%S")
            report_path = os.path.join(desktop, f"Battery_Report_{ts}.html")

            self.queue.put(f"PROGRESS:{label}:Generating battery report...")
            r = wm_run(
                ['powercfg', '/batteryreport', '/output', report_path, '/duration', '14'],
                capture_output=True, text=True, encoding='utf-8', errors='replace',
                timeout=120, startupinfo=_no_console_startupinfo()
            )
            if r.returncode == 0 and os.path.exists(report_path):
                self.queue.put(f"PROGRESS:{label}:Report saved to {report_path}")
                try:
                    webbrowser.open(Path(report_path).as_uri())
                except Exception:
                    pass
            else:
                self._report_failure(f"PROGRESS:{label}:powercfg could not write the report: "
                                     f"{_wm_last_line(r.stderr, r.stdout) or r.returncode}")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")
