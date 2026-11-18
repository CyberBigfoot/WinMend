"""WinMend features: apps: operations."""

from __future__ import annotations

from winmend.core.processes import _no_console_startupinfo, wm_run
from winmend.core.prompts import messagebox
from winmend.features.apps.winget import parse_winget_upgrade, winget_listing_error
import shutil


class AppsTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    def update_installed_apps(self):
        """Update every app winget can update, showing the list first."""
        label = "Update Apps"
        self.queue.put(f"PROGRESS:{label}:Starting application update process...")
        try:
            if not shutil.which("winget"):
                self._report_failure(f"PROGRESS:{label}:Windows Package Manager (winget) was not found. "
                                     f"Install 'App Installer' from the Microsoft Store.")
                return

            # Plain `winget upgrade` lists what is updatable. The old version
            # asked for `winget upgrade --list`, which winget rejects as an
            # unknown argument, so it never showed the list and always went
            # straight to "upgrade all".
            self.queue.put(f"PROGRESS:{label}:Checking for available updates...")
            listing = wm_run(["winget", "upgrade", "--accept-source-agreements", "--disable-interactivity"],
                             capture_output=True, text=True, encoding="utf-8", errors="replace",
                             cancel_event=self.cancel_event, startupinfo=_no_console_startupinfo())
            if self.cancel_event.is_set():
                return
            error = winget_listing_error(listing, updates=True)
            if error:
                self._report_failure(f"PROGRESS:{label}:Could not check app updates: {error}")
                return
            rows = parse_winget_upgrade(listing.stdout or "")
            if not rows:
                self.queue.put(f"PROGRESS:{label}:No app updates were listed by winget.")
                return
            self.queue.put(f"PROGRESS:{label}:{len(rows)} update(s) available:")
            for row in rows:
                self.queue.put(f"PROGRESS:{label}:  - {row['name']} {row['version']} -> {row['available']}")

            # Run through the shared runner: it drains output on reader threads
            # (the old loop blocked in readline(), so Stop did nothing while
            # winget was quiet) and Stop ends the whole tree -- winget AND the
            # installer it launched, which a plain kill() left running.
            self.queue.put(f"PROGRESS:{label}:Updating...")
            rc, _ = self._run_live_command(
                ['winget', 'upgrade', '--all', '--silent', '--accept-package-agreements',
                 '--accept-source-agreements', '--disable-interactivity'],
                label, encoding="utf-8")
            if rc == 0:
                self.queue.put(f"PROGRESS:{label}:App updates completed successfully")
            elif not self.cancel_event.is_set():
                self._report_failure(f"PROGRESS:{label}:winget could not update every app (exit code "
                                     f"0x{rc & 0xFFFFFFFF:08X}); the lines above say which. The "
                                     f"Updates page can retry them one at a time.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error updating apps: {str(e)}")

    def run_uwp_app_reset(self):
        """Pick an installed Store app and reset it (Reset-AppxPackage)."""
        label = "UWP App Reset"
        common = [
            ("Microsoft.WindowsStore",          "Microsoft Store"),
            ("Microsoft.Windows.Photos",        "Photos"),
            ("Microsoft.WindowsCalculator",     "Calculator"),
            ("Microsoft.WindowsCamera",         "Camera"),
            ("microsoft.windowscommunicationsapps", "Mail & Calendar"),
            ("Microsoft.OutlookForWindows",     "Outlook (new)"),
            ("Microsoft.WindowsNotepad",        "Notepad"),
            ("Microsoft.ScreenSketch",          "Snipping Tool"),
            ("Microsoft.ZuneMusic",             "Media Player"),
            ("Microsoft.ZuneVideo",             "Movies & TV"),
            ("Microsoft.YourPhone",             "Phone Link"),
            ("Microsoft.WindowsTerminal",       "Windows Terminal"),
            ("Microsoft.Paint",                 "Paint"),
            ("Microsoft.MSPaint",               "Paint 3D"),
        ]
        # Offer only what this account has installed: resetting an app that is
        # not there used to "complete" having done nothing.
        probe = self._run_ps(
            "foreach ($n in @(" + ",".join(f"'{n}'" for n, _ in common) + ")) { "
            "if (Get-AppxPackage -Name $n -ErrorAction SilentlyContinue) { Write-Output $n } }",
            timeout=60)
        present = {ln.strip().lower() for ln in (probe.stdout or "").splitlines() if ln.strip()}
        options = [(n, name) for n, name in common if n.lower() in present]
        if not options:
            self._report_failure(f"PROGRESS:{label}:None of the Store apps this can reset are installed "
                                 f"for your account.")
            return
        choice = self._ui_radio_picker(
            "Reset UWP App",
            "Pick a Store/UWP app to fully reset to defaults. App data will be cleared.",
            options
        )
        if not choice:
            self._report_skip(f"PROGRESS:{label}:Cancelled.")
            return
        friendly = dict(common).get(choice, choice)

        if not messagebox.askyesno(
            "Confirm UWP Reset",
            f"This will clear all data for {friendly} and reset it to its installed defaults.\n\n"
            f"Continue?",
            icon='warning'
        ):
            self._report_skip(f"PROGRESS:{label}:Cancelled at confirmation.")
            return

        # Exact name, current account -- what Settings > Apps > Reset does. The
        # old '*name*' wildcard across all users could reset more than one app.
        ps_script = r'''
        $pkgs = @(Get-AppxPackage -Name '%NAME%' -ErrorAction SilentlyContinue)
        if (-not $pkgs) { Write-Output 'WM_FAIL|it is not installed for this account'; exit 0 }
        foreach ($p in $pkgs) {
            try { Reset-AppxPackage -Package $p.PackageFullName -ErrorAction Stop; Write-Output ('Reset: ' + $p.PackageFullName) }
            catch { Write-Output ('WM_FAIL|' + $_.Exception.Message) }
        }
        '''.replace("%NAME%", choice.replace("'", "''"))
        try:
            lines = []
            self._run_live_command(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'RemoteSigned', '-Command', ps_script],
                label, output=lines)
            if self.cancel_event.is_set():
                return
            failures = [line.split("|", 1)[1] for line in lines if line.startswith("WM_FAIL|")]
            for why in failures:
                self._report_failure(f"PROGRESS:{label}:{friendly} could not be reset: {why}")
            if not failures and any(line.startswith("Reset: ") for line in lines):
                self.queue.put(f"PROGRESS:{label}:{friendly} was reset. Open it again to start fresh.")
            elif not failures:
                self._report_failure(f"PROGRESS:{label}:{friendly} could not be reset: no result came back.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")
