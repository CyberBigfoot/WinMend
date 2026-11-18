"""WinMend features: debloat: operations."""

from __future__ import annotations

from winmend.core.search import _wm_last_line
from winmend.features.debloat.helpers import ONEDRIVE_DEBLOAT_KEY, build_debloat_options
import os


class DebloatTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    def run_win11_debloat(self):
        """Remove the preinstalled apps the user ticks (no download, no tweaks)."""
        self._run_debloat("Debloat Windows", extreme=False)

    def run_win11_debloat_extreme(self):
        """The same checklist, extended to Windows' own apps and OEM tools."""
        self._run_debloat("Debloat Windows Extreme", extreme=True)

    def _run_debloat(self, label, extreme):
        """Find which listed apps are on this PC, ask which to remove, remove those.

        The old tasks removed every match silently, for all users, and logged
        "91/91 processed" whatever happened -- the count came from PowerShell's
        exit code, which -ErrorAction SilentlyContinue kept at 0 even when
        nothing was installed. Now every row is a measured package, the user
        chooses, and each removal is checked afterwards and named in the log.
        """
        self.queue.put(f"PROGRESS:{label}:Checking which of these apps are on this PC...")
        inventory = self._run_ps(
            "Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | "
            "ForEach-Object { Write-Output ('I|' + $_.Name) }; "
            "Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | "
            "ForEach-Object { Write-Output ('P|' + $_.DisplayName) }", timeout=300)
        installed, provisioned = set(), set()
        for line in (inventory.stdout or "").splitlines():
            kind, _, name = line.strip().partition("|")
            if name and kind == "I":
                installed.add(name)
            elif name and kind == "P":
                provisioned.add(name)
        if not installed and not provisioned:
            self._report_failure(f"PROGRESS:{label}:Could not list the installed apps: "
                                 f"{_wm_last_line(inventory.stderr) or 'no output'}")
            return

        onedrive_present = any(os.path.exists(p) for p in (
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "OneDrive", "OneDrive.exe"),
            os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Microsoft OneDrive",
                         "OneDrive.exe")))
        holds_files = any(self._is_cloud_synced(p) for p in (self._get_desktop_dir(),
                                                              self._get_documents_dir()))
        options = build_debloat_options(installed, provisioned, extreme,
                                        onedrive_holds_files=holds_files,
                                        onedrive_present=onedrive_present)
        if not options:
            self.queue.put(f"PROGRESS:{label}:None of the apps on this list are on this PC -- nothing "
                           f"to remove.")
            return
        chosen = self._ui_check_picker(
            label,
            f"{len(options)} of these apps are on this PC. Tick the ones to remove -- for every "
            f"user account. Removed apps come back from the Microsoft Store, not from a restore "
            f"point.",
            [{k: o[k] for k in ("key", "label", "detail", "checked")} for o in options],
            ok_text="Remove selected")
        if not chosen:
            self._report_skip(f"PROGRESS:{label}:Nothing selected -- no apps were removed.")
            return

        by_key = {o["key"]: o for o in options}
        owner = {pkg: by_key[key]["label"] for key in chosen for pkg in by_key[key]["packages"]}
        removed, failed = [], []
        if owner:
            names = ",".join("'" + pkg.replace("'", "''") + "'" for pkg in sorted(owner))
            script = r'''
            $targets = @(%NAMES%)
            $prov = @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue)
            $errs = @{}
            foreach ($n in $targets) {
                Write-Output "Removing $n..."
                foreach ($p in @(Get-AppxPackage -Name $n -AllUsers -ErrorAction SilentlyContinue)) {
                    try { Remove-AppxPackage -Package $p.PackageFullName -AllUsers -ErrorAction Stop }
                    catch { $errs[$n] = $_.Exception.Message }
                }
                foreach ($p in @($prov | Where-Object { $_.DisplayName -eq $n })) {
                    try { Remove-AppxProvisionedPackage -Online -AllUsers -PackageName $p.PackageName -ErrorAction Stop | Out-Null }
                    catch { if (-not $errs[$n]) { $errs[$n] = $_.Exception.Message } }
                }
            }
            # Judged afterwards, installed AND provisioned in one pass each: a
            # package still provisioned comes straight back for the next new
            # user account, so it has not been removed.
            $installedNow = @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
            $provNow = @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | ForEach-Object { $_.DisplayName })
            foreach ($n in $targets) {
                if ($installedNow -notcontains $n -and $provNow -notcontains $n) { Write-Output "Removed: $n" }
                else {
                    $why = if ($errs[$n]) { $errs[$n] -replace '\s+', ' ' } else { 'it is still installed' }
                    Write-Output ("Could not remove " + $n + ": " + $why)
                }
            }
            '''.replace("%NAMES%", names)
            lines = []
            self._run_live_command(['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy',
                                    'RemoteSigned', '-Command', script], label, output=lines)
            if self.cancel_event.is_set():
                return
            gone = {line[len("Removed: "):] for line in lines if line.startswith("Removed: ")}
            for pkg, app in owner.items():
                if pkg in gone:
                    removed.append(app)
                else:
                    why = next((line.split(": ", 1)[1] for line in lines
                                if line.startswith(f"Could not remove {pkg}:")), "it is still installed")
                    failed.append((app, why))

        if ONEDRIVE_DEBLOAT_KEY in chosen:
            self.queue.put(f"PROGRESS:{label}:Uninstalling OneDrive through winget...")
            rc, _ = self._run_live_command(
                ['winget', 'uninstall', '--id', 'Microsoft.OneDrive', '--exact', '--silent',
                 '--accept-source-agreements', '--disable-interactivity'], label, encoding="utf-8")
            if rc == 0:
                removed.append("OneDrive")
            elif not self.cancel_event.is_set():
                failed.append(("OneDrive", f"winget exit code 0x{rc & 0xFFFFFFFF:08X}"))

        removed = list(dict.fromkeys(removed))
        if removed:
            self.queue.put(f"PROGRESS:{label}:Removed ({len(removed)}): {', '.join(removed)}")
        for app, why in dict.fromkeys(failed):
            self._report_failure(f"PROGRESS:{label}:Could not remove {app}: {why}")
        if removed:
            self.queue.put(f"PROGRESS:{label}:Anything removed can be reinstalled from the Microsoft Store.")
