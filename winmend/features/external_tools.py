"""WinMend features: external tools."""

from __future__ import annotations

from winmend.core.processes import launch_visible
from winmend.core.prompts import messagebox
import hashlib
import os
import subprocess


class ExternalToolsTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    # ==================== CHRIS TITUS UTILITY METHODS ====================
    def run_chris_titus_utility(self):
        """Run Chris Titus Windows Utility using a downloaded script file (no pipe-to-iex)."""
        self.queue.put("PROGRESS:Chris Titus Utility:Starting Chris Titus Windows Utility...")
        self.queue.put("PROGRESS:Chris Titus Utility:Using hardened download-and-run flow (no inline pipe execution).")

        confirm = messagebox.askyesno(
            "Run Remote Utility Script",
            "This task downloads a PowerShell script from christitus.com and executes it locally.\n\n"
            "Only continue if you trust this source and understand what the script does.\n\n"
            "Continue?"
        )
        if not confirm:
            self._report_skip("PROGRESS:Chris Titus Utility:Cancelled by user.")
            return

        try:
            import urllib.request

            url = "https://christitus.com/win"
            temp_dir = os.environ.get('TEMP', r'C:\Windows\Temp')
            script_path = os.path.join(temp_dir, "WinMend_ChrisTitus_Utility.ps1")

            self.queue.put(f"PROGRESS:Chris Titus Utility:Downloading script from {url} ...")
            req = urllib.request.Request(url, headers={'User-Agent': 'WinMend/1.0'})
            with urllib.request.urlopen(req, timeout=60) as response:
                script_bytes = response.read()

            if not script_bytes or len(script_bytes) < 256:
                self._report_failure("PROGRESS:Chris Titus Utility:Downloaded script appears invalid (too small). Aborting.")
                return

            script_hash = hashlib.sha256(script_bytes).hexdigest()
            self.queue.put(f"PROGRESS:Chris Titus Utility:Downloaded SHA256: {script_hash}")

            script_text = script_bytes.decode("utf-8", errors="replace")
            marker_hits = sum(1 for marker in ("Chris Titus", "WinUtil", "PowerShell") if marker in script_text)
            if marker_hits == 0:
                self._report_failure("PROGRESS:Chris Titus Utility:Downloaded content did not match expected utility markers. Aborting.")
                return

            with open(script_path, "wb") as f:
                f.write(script_bytes)
            self.queue.put(f"PROGRESS:Chris Titus Utility:Saved script to {script_path}")

            final_confirm = messagebox.askyesno(
                "Execute Downloaded Script",
                "The utility script was downloaded and saved locally.\n\n"
                f"SHA256:\n{script_hash}\n\n"
                "Do you want to execute this script now?"
            )
            if not final_confirm:
                self._report_skip("PROGRESS:Chris Titus Utility:Execution cancelled by user after download.")
                return

            self.queue.put("PROGRESS:Chris Titus Utility:Executing script file with PowerShell...")
            rc, timed_out = self._run_live_command(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'RemoteSigned', '-File', script_path],
                'Chris Titus Utility',
                timeout=900
            )

            if self.cancel_event.is_set():
                return
            if rc == 0:
                self.queue.put("PROGRESS:Chris Titus Utility:Chris Titus Windows Utility completed successfully")
            else:
                self._report_failure(f"PROGRESS:Chris Titus Utility:Utility failed with return code: {rc}")

        except Exception as e:
            self._report_failure(f"PROGRESS:Chris Titus Utility:Error running Chris Titus Utility: {str(e)}")

    def run_open_msconfig(self):
        """Launch System Configuration (msconfig)."""
        self.queue.put("PROGRESS:Open MSCONFIG:Launching System Configuration...")
        try:
            try:
                os.startfile("msconfig")
            except Exception:
                launch_visible(['msconfig'])
            self.queue.put("PROGRESS:Open MSCONFIG:MSCONFIG opened successfully.")
        except FileNotFoundError:
            self._report_failure("PROGRESS:Open MSCONFIG:msconfig.exe not found on this system.")
        except Exception as e:
            self._report_failure(f"PROGRESS:Open MSCONFIG:Error launching MSCONFIG: {str(e)}")

    def run_sysinternals_autoruns(self):
        """Downloads and launches Sysinternals Autoruns"""
        self._run_sysinternals("sysinternals_autoruns", "Autoruns", "Autoruns64.exe")

    def run_sysinternals_procexp(self):
        """Downloads and launches Sysinternals Process Explorer"""
        self._run_sysinternals("sysinternals_procexp", "Process Explorer", "procexp64.exe")

    def _run_sysinternals(self, task_label, name, exe_name):
        url = f"https://live.sysinternals.com/{exe_name}"
        confirmed = messagebox.askyesno(
            "Download Confirmation",
            f"Sysinternals {name} requires downloading from Microsoft.\n\n"
            f"Source: {url}\n"
            "Publisher: Microsoft Sysinternals\n\n"
            "The file will be saved to your TEMP folder and launched. Launching it this way "
            "accepts the Sysinternals licence terms for you.\n\n"
            "Do you want to proceed?"
        )
        if not confirmed:
            self._report_skip(f"PROGRESS:{task_label}:Download cancelled by user.")
            return

        exe_path = os.path.join(os.environ.get('TEMP', 'C:\\Windows\\Temp'), exe_name)
        self.queue.put(f"PROGRESS:{task_label}:Downloading Sysinternals {name}...")
        try:
            self._download(url, exe_path)
            self.queue.put(f"PROGRESS:{task_label}:Launching {name}...")
            subprocess.Popen([exe_path, "/accepteula"], creationflags=subprocess.DETACHED_PROCESS)
            self.queue.put(f"PROGRESS:{task_label}:{name} launched successfully.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{task_label}:Error executing {name}: {str(e)}")

    def run_reliability_monitor(self):
        """Launch Windows Reliability Monitor (perfmon /rel)."""
        label = "Reliability Monitor"
        self.queue.put(f"PROGRESS:{label}:Launching Reliability Monitor...")
        try:
            launch_visible(['perfmon.exe', '/rel'], creationflags=subprocess.DETACHED_PROCESS)
            self.queue.put(f"PROGRESS:{label}:Reliability Monitor opened.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error launching Reliability Monitor: {e}")

    def run_memory_diagnostic(self):
        """Launch Windows Memory Diagnostic (mdsched.exe)."""
        label = "Memory Diagnostic"
        if not messagebox.askyesno(
            "Memory Diagnostic",
            "Windows Memory Diagnostic will prompt to reboot now (or on next restart) "
            "and test your RAM before Windows loads.\n\n"
            "Save your work first. Continue?", icon='warning'
        ):
            self._report_skip(f"PROGRESS:{label}:Cancelled by user.")
            return
        try:
            launch_visible(['mdsched.exe'], creationflags=subprocess.DETACHED_PROCESS)
            self.queue.put(f"PROGRESS:{label}:Memory Diagnostic prompt opened.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error launching mdsched.exe: {e}")
