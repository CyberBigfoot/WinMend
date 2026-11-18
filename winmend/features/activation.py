"""WinMend features: activation."""

from __future__ import annotations

from winmend.core.processes import _no_console_startupinfo, launch_visible, wm_run
import os
import subprocess


class ActivationTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    def _get_windows_edition(self):
        """Current Windows edition string, e.g. 'Microsoft Windows 11 Pro'. '' on failure."""
        try:
            r = wm_run(
                ['powershell', '-NoProfile', '-Command',
                 "(Get-CimInstance Win32_OperatingSystem).Caption"],
                capture_output=True, text=True, encoding='utf-8', errors='replace',
                timeout=30, startupinfo=_no_console_startupinfo())
            return (r.stdout or "").strip()
        except Exception:
            return ""

    @staticmethod
    def _key_needs_edition_change(slmgr_output):
        """True when slmgr rejected the key because it belongs to a DIFFERENT Windows
        edition (e.g. a Pro key entered on Home). That is not a bad key \u2014 the
        edition-change flow (changepk.exe) must be used instead of slmgr."""
        text = (slmgr_output or "").lower()
        markers = (
            "0xc004f069",   # key is for a different edition/channel
            "0xc004e016",   # key invalid for this edition
            "0xc004f015",   # license/edition relationship mismatch
            "different edition",
            "can only be used for upgrading",
            "cannot be used to activate this edition",
        )
        return any(m in text for m in markers)

    def _launch_edition_change(self, label, key):
        """Hand the key to Windows' own edition-change flow (changepk.exe)."""
        changepk = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'),
                                'System32', 'changepk.exe')
        if not os.path.exists(changepk):
            self.queue.put(f"PROGRESS:{label}:changepk.exe not found. Change the key via "
                           "Settings > System > Activation > Change product key instead.")
            return False
        try:
            launch_visible([changepk, '/ProductKey', key],
                           creationflags=subprocess.DETACHED_PROCESS)
            self.queue.put(f"PROGRESS:{label}:Windows' edition-change dialog has been opened.")
            self.queue.put(f"PROGRESS:{label}:Follow that dialog to finish \u2014 Windows verifies "
                           "the key, switches the edition, and will likely ask to RESTART.")
            return True
        except Exception as e:
            self.queue.put(f"PROGRESS:{label}:Could not launch changepk.exe: {e}")
            self.queue.put(f"PROGRESS:{label}:Use Settings > System > Activation > Change product key.")
            return False

    def run_activate_windows(self):
        """Activate Windows or change the product key/edition.

        slmgr /ipk + /ato can only activate the edition that is already installed.
        A key for a DIFFERENT edition (e.g. Pro key on Home) is detected from the
        slmgr error and routed to changepk.exe, which performs the edition switch."""
        label = "Activate Windows/Change Product Key"
        # The runner calls handlers straight from WM_HANDLERS, with no pre-run
        # prompt phase, so ask for the key here when nothing was supplied.
        key = getattr(self, '_windows_product_key', None)
        if not key:
            key = self._prompt_product_key()
        # One-shot: a second run in the same session must ask again rather than
        # silently reusing the previous key.
        self._windows_product_key = None
        if not key:
            self._report_skip(f"PROGRESS:{label}:No product key provided \u2014 nothing was changed.")
            return
        key = key.strip().upper()

        # slmgr echoes the key back ("Installed product key XXXXX-... successfully"),
        # and the activity log is kept and exported -- only the last group is
        # ever shown, the way Windows itself shows it.
        masked = "XXXXX-XXXXX-XXXXX-XXXXX-" + key[-5:]

        def show(text):
            return text.replace(key, masked)

        slmgr = r"C:\Windows\System32\slmgr.vbs"

        edition_before = self._get_windows_edition()
        if edition_before:
            self.queue.put(f"PROGRESS:{label}:Current edition: {edition_before}")

        # ── Step 1: Install product key (/ipk) ─────────────────────────────────
        self.queue.put(f"PROGRESS:{label}:Step 1/3 \u2014 Installing product key {masked}...")
        try:
            r = wm_run(
                ["cscript", "//nologo", slmgr, "/ipk", key],
                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60,
                startupinfo=_no_console_startupinfo()
            )
            output = show((r.stdout + r.stderr).strip())
            if output:
                self.queue.put(f"PROGRESS:{label}:  {output}")
            if r.returncode != 0 or "error" in output.lower():
                if self._key_needs_edition_change(output):
                    self.queue.put(f"PROGRESS:{label}:This key is for a DIFFERENT Windows edition "
                                   f"than the installed one ({edition_before or 'unknown'}).")
                    self.queue.put(f"PROGRESS:{label}:Switching editions requires Windows' own "
                                   "upgrade flow \u2014 launching it now...")
                    if not self._launch_edition_change(label, key):
                        self._report_failure(f"PROGRESS:{label}:The edition change could not be started.")
                else:
                    self._report_failure(f"PROGRESS:{label}:Product key installation failed \u2014 "
                                         f"verify the key is correct and try again.")
                return
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:ERROR \u2014 /ipk command failed: {show(str(e))}")
            return

        # ── Step 2: Activate online (/ato) ─────────────────────────────────────
        self.queue.put(f"PROGRESS:{label}:Step 2/3 \u2014 Activating Windows online...")
        try:
            r = wm_run(
                ["cscript", "//nologo", slmgr, "/ato"],
                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60,
                startupinfo=_no_console_startupinfo()
            )
            output = show((r.stdout + r.stderr).strip())
            if output:
                self.queue.put(f"PROGRESS:{label}:  {output}")
            if r.returncode != 0 or "error" in output.lower():
                self._report_failure(f"PROGRESS:{label}:Online activation failed \u2014 the key was "
                                     f"installed, but Windows could not activate it. Check the "
                                     f"internet connection, or activate by phone from Settings > "
                                     f"System > Activation.")
                return
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:ERROR \u2014 /ato command failed: {e}")
            return

        # ── Step 3: Check activation / expiry status (/xpr) ───────────────────
        self.queue.put(f"PROGRESS:{label}:Step 3/3 \u2014 Checking activation status...")
        try:
            r = wm_run(
                ["cscript", "//nologo", slmgr, "/xpr"],
                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30,
                startupinfo=_no_console_startupinfo()
            )
            output = show((r.stdout + r.stderr).strip())
            if output:
                self.queue.put(f"PROGRESS:{label}:  {output}")
        except Exception as e:
            self.queue.put(f"PROGRESS:{label}:Could not retrieve activation status: {e}")

        edition_after = self._get_windows_edition()
        if edition_after:
            self.queue.put(f"PROGRESS:{label}:Active edition: {edition_after}")
        self.queue.put(f"PROGRESS:{label}:Windows activation completed successfully! \u2713")
        self.queue.put(f"PROGRESS:{label}:Note: this key matched your installed edition, so the "
                       "edition stays the same \u2014 the key was installed and Windows was activated. "
                       "Keys for a different edition automatically open Windows' edition-change flow.")
