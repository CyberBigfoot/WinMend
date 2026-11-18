"""WinMend features: updates."""

from __future__ import annotations

from datetime import datetime, timezone
from winmend.core.processes import _no_console_startupinfo, wm_run
from winmend.core.search import _wm_last_line
import os
import re
import time


# Store app updates log their failures under Windows Update too ("...error
# 0x80073D02: 9PLM9XGG6VKS-OpenAI.Codex" -- an app that was open). They name a
# Store product id and say nothing about Windows Update itself.
_STORE_PRODUCT = re.compile(r"(^|:\s*)9[A-Z0-9]{11}-")


def parse_update_event(line):
    """One "EV|id|utc time|update id|code|title" line from the forensic query,
    as a dict, or None when it is malformed."""
    parts = line.split("|", 5)
    if len(parts) != 6 or parts[0] != "EV" or not parts[1].isdigit():
        return None
    try:
        when = datetime.strptime(parts[2], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return {"id": int(parts[1]), "time": when.astimezone(), "update": parts[3].strip().lower(),
            "code": parts[4].strip(), "title": parts[5].strip()}


def classify_update_errors(events):
    """Split Windows Update errors into (current, resolved), newest first.

    An install failure is resolved once the same update (by its update id)
    installs successfully later -- what happened on this PC with KB5132061,
    which failed with 0x80070002 and installed the next day. An error that
    names no update, such as a failed scan, is resolved by any later successful
    install of a Windows update, which shows the pipeline working end to end.
    Store app failures are left out entirely. `resolved` pairs each error with
    the success that cleared it.
    """
    def from_store(event):
        return bool(_STORE_PRODUCT.search(event["title"]))

    successes = sorted((e for e in events if e["id"] == 19 and not from_store(e)),
                       key=lambda e: e["time"])
    current, resolved = [], []
    for error in sorted(events, key=lambda e: e["time"], reverse=True):
        if error["id"] == 19 or from_store(error):
            continue
        cleared = next((s for s in successes if s["time"] > error["time"]
                        and (not error["update"] or s["update"] == error["update"])), None)
        if cleared:
            resolved.append((error, cleared))
        else:
            current.append(error)
    return current, resolved


def describe_update_error(error):
    """One line for the activity log."""
    if error["id"] == 20:
        code = f" ({error['code']})" if error["code"] else ""
        return f"{error['time']:%Y-%m-%d}: {error['title']} failed to install{code}"
    return f"{error['time']:%Y-%m-%d}: {error['title']}"


class UpdatesTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    # ==================== ADVANCED REPAIR TOOLS ====================

    def reset_windows_update(self):
        """Reset Windows Update components to fix stuck or failing updates"""
        label = "Reset Windows Update"
        self.queue.put(f"PROGRESS:{label}:Starting Windows Update components reset...")
        self.queue.put(f"PROGRESS:{label}:This will stop update services, clear caches, and restart services.")

        try:
            # Step 1: Stop services. /y answers net's "these dependent services
            # will stop too -- continue?" question, which nothing else can.
            services = ['bits', 'wuauserv', 'appidsvc', 'cryptsvc']
            for svc in services:
                self.queue.put(f"PROGRESS:{label}:Stopping service: {svc}...")
                rc, _ = self._run_live_command(['net', 'stop', svc, '/y'], label, timeout=30)
                if rc == 0:
                    self.queue.put(f"PROGRESS:{label}:Service {svc} stopped")
                else:
                    self.queue.put(f"PROGRESS:{label}:Service {svc} may already be stopped (rc={rc})")
            if self.cancel_event.is_set():
                return

            # Step 2: Rename SoftwareDistribution and catroot2 folders
            timestamp = time.strftime("%Y%m%d%H%M%S")
            root = os.environ.get('SystemRoot', r'C:\Windows')
            folders = [(os.path.join(root, 'SoftwareDistribution'), 'SoftwareDistribution', 'wuauserv'),
                       (os.path.join(root, 'System32', 'catroot2'), 'catroot2', 'cryptsvc')]
            renamed = []
            for folder, name, holder in folders:
                self.queue.put(f"PROGRESS:{label}:Renaming {name}...")
                if not os.path.exists(folder):
                    self.queue.put(f"PROGRESS:{label}:{name} folder not found (already reset?)")
                    continue
                new_name = f"{folder}.bak.{timestamp}"
                for attempt in (1, 2):
                    try:
                        os.rename(folder, new_name)
                        renamed.append(name)
                        self.queue.put(f"PROGRESS:{label}:Renamed {name} to {os.path.basename(new_name)}")
                        break
                    except OSError as e:
                        if attempt == 2:
                            self._report_failure(
                                f"PROGRESS:{label}:Could not rename {name} -- it is still in use "
                                f"({e.strerror or e}). Restart Windows and run this again.")
                            break
                        # A trigger-started service can come straight back and
                        # take the folder again; stop it once more and retry.
                        wm_run(['net', 'stop', holder, '/y'], capture_output=True,
                               startupinfo=_no_console_startupinfo())
                        time.sleep(2)

            # Step 3: Restart services
            for svc in services:
                self.queue.put(f"PROGRESS:{label}:Starting service: {svc}...")
                rc, _ = self._run_live_command(['net', 'start', svc], label, timeout=30)
                if rc in (0, 2):  # 2: it was already running
                    self.queue.put(f"PROGRESS:{label}:Service {svc} started")
                elif svc == 'cryptsvc':
                    self._report_failure(f"PROGRESS:{label}:Cryptographic Services did not start "
                                         f"(rc={rc}); updates cannot verify their signatures "
                                         f"until it does.")
                else:
                    # wuauserv, bits and appidsvc are started on demand by Windows.
                    self.queue.put(f"PROGRESS:{label}:{svc} did not start now (rc={rc}); Windows "
                                   f"starts it itself when it is needed.")

            if getattr(self, "_task_failure", None) is None:
                self.queue.put(f"PROGRESS:{label}:Windows Update components have been reset!")
                self.queue.put(f"PROGRESS:{label}:Try checking for updates again now.")

        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error resetting Windows Update: {str(e)}")

    def check_and_install_windows_updates(self):
        """Check for and install the updates Windows itself would install."""
        label = "Windows Updates"
        self.queue.put(f"PROGRESS:{label}:Starting Windows Update process...")
        self.queue.put(f"PROGRESS:{label}:This process may take a long time. Please be patient.")

        # IsHidden=0 skips updates the user hid on purpose; BrowseOnly=0 skips
        # the optional ones (preview cumulative updates, optional drivers) that
        # Windows Update only installs when someone asks for them by name.
        ps_script = '''
        try {
            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $updateSearcher = $updateSession.CreateUpdateSearcher()

            Write-Host "Searching for updates..."
            $searchResult = $updateSearcher.Search("IsInstalled=0 and IsHidden=0 and BrowseOnly=0")

            if ($searchResult.Updates.Count -eq 0) {
                Write-Host "No updates found."
                exit 0
            }

            Write-Host "Found $($searchResult.Updates.Count) updates:"
            foreach ($update in $searchResult.Updates) {
                Write-Host "- $($update.Title)"
            }

            $updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
            foreach ($update in $searchResult.Updates) {
                if (-not $update.IsDownloaded) {
                    $updatesToDownload.Add($update) | Out-Null
                }
            }

            if ($updatesToDownload.Count -gt 0) {
                Write-Host "Downloading $($updatesToDownload.Count) updates..."
                $downloader = $updateSession.CreateUpdateDownloader()
                $downloader.Updates = $updatesToDownload
                $downloadResult = $downloader.Download()
                # OperationResultCode: 2 succeeded, 3 succeeded with errors
                # (some downloaded), 4 failed, 5 aborted. With 3, whatever did
                # download is installed below rather than thrown away.
                if ($downloadResult.ResultCode -ne 2 -and $downloadResult.ResultCode -ne 3) {
                    Write-Host "Failed to download updates. Result code: $($downloadResult.ResultCode)"
                    exit 1
                }
                if ($downloadResult.ResultCode -eq 3) {
                    Write-Host "Some updates could not be downloaded; installing the ones that were."
                } else {
                    Write-Host "Updates downloaded successfully."
                }
            }

            $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
            foreach ($update in $searchResult.Updates) {
                if ($update.IsDownloaded) {
                    $updatesToInstall.Add($update) | Out-Null
                }
            }

            if ($updatesToInstall.Count -gt 0) {
                Write-Host "Installing $($updatesToInstall.Count) updates..."
                $installer = $updateSession.CreateUpdateInstaller()
                $installer.Updates = $updatesToInstall
                $installResult = $installer.Install()
                $code = $installResult.ResultCode
                if ($code -ne 2 -and $code -ne 3) {
                    Write-Host "Failed to install updates. Result code: $code"
                    exit 1
                }
                # Result code 3 means some installed and some did not: say which,
                # and still ask for the restart the installed ones need.
                $installedCount = 0; $failedCount = 0
                for ($i = 0; $i -lt $updatesToInstall.Count; $i++) {
                    $one = $installResult.GetUpdateResult($i)
                    $title = $updatesToInstall.Item($i).Title
                    if ($one.ResultCode -eq 2) {
                        $installedCount++
                        Write-Host "Installed: $title"
                    } else {
                        $failedCount++
                        Write-Host ("Not installed: {0} (result code {1}, error 0x{2:X8})" -f $title, $one.ResultCode, $one.HResult)
                    }
                }
                Write-Host "$installedCount of $($updatesToInstall.Count) update(s) installed."
                if ($installResult.RebootRequired) {
                    Write-Host "A system reboot is required to complete the installation."
                }
                if ($failedCount -gt 0) {
                    if ($installResult.RebootRequired) { exit 4 } else { exit 3 }
                }
                if ($installResult.RebootRequired) { exit 2 }
            }
            exit 0
        }
        catch {
            Write-Error "Error checking/installing updates: $($_.Exception.Message)"
            exit 1
        }
        '''
        try:
            rc, _ = self._run_live_command(['powershell', '-NoProfile', '-Command', ps_script],
                                           label, timeout=7200)
            if rc == 0:
                self.queue.put(f"PROGRESS:{label}:Windows updates completed successfully")
            elif rc == 2:
                self.queue.put(f"PROGRESS:{label}:Windows updates installed successfully")
                # Offered once the whole run is over, like every other restart.
                self.queue.put(f"REBOOTRECOMMEND:{label}:Windows updates were installed and need a "
                               f"restart to finish.")
            elif rc in (3, 4):
                # Some installed, some did not (Windows Update result code 3).
                if rc == 4:
                    self.queue.put(f"REBOOTRECOMMEND:{label}:Some Windows updates were installed and "
                                   f"need a restart to finish.")
                self._report_failure(f"PROGRESS:{label}:Some updates installed and others did not; the "
                                     f"lines above name each one. Run this again after "
                                     + ("the restart." if rc == 4 else "a few minutes."))
            elif not self.cancel_event.is_set():
                self._report_failure(f"PROGRESS:{label}:Windows Update did not finish (code {rc}); the "
                                     f"lines above say which step failed.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error in Windows updates: {str(e)}")

    def check_and_install_device_firmware(self):
        """Install missing OEM driver/firmware updates the user picks from Windows Update."""
        label = "Device Firmware"
        installed = self._install_driver_updates(label)
        if installed is None:
            return  # nothing to do, cancelled, or already reported as failed
        self.queue.put(f"PROGRESS:{label}:For BIOS and firmware that Windows Update does not carry, use "
                       f"your PC maker's updater (Dell Command | Update, HP Support Assistant, "
                       f"Lenovo System Update).")

    def _install_driver_updates(self, label):
        """Search Windows Update for drivers, let the user pick, install those.

        Both driver tasks used to install every driver Windows Update offered,
        optional ones included -- and the optional list routinely carries an
        older graphics driver than the one the GPU maker's own installer put
        on, so "install missing drivers" could downgrade the GPU. Returns the
        number installed, or None when nothing was installed.
        """
        search = r'''
        try {
            $s = New-Object -ComObject Microsoft.Update.Session
            $r = $s.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Driver'")
            foreach ($u in $r.Updates) {
                $date = if ($u.DriverVerDate) { ([datetime]$u.DriverVerDate).ToString('yyyy-MM-dd') } else { '' }
                Write-Output ("UPD|{0}|{1}|{2}|{3}" -f $u.Identity.UpdateID, $u.DriverClass, $date, ($u.Title -replace '\|', '/'))
            }
            Write-Output "DONE"
        } catch { Write-Output "ERR|$($_.Exception.Message)"; exit 1 }
        '''
        self.queue.put(f"PROGRESS:{label}:Searching Windows Update for missing drivers...")
        result = self._run_ps(search, timeout=900)
        found, error = [], ""
        for line in (result.stdout or "").splitlines():
            parts = line.strip().split("|", 4)
            if parts[0] == "UPD" and len(parts) == 5 and re.fullmatch(r"[0-9a-fA-F-]{36}", parts[1]):
                found.append({"id": parts[1], "cls": parts[2], "date": parts[3], "title": parts[4]})
            elif parts[0] == "ERR":
                error = line.split("|", 1)[1]
        if error or result.returncode not in (0, None):
            self._report_failure(f"PROGRESS:{label}:Windows Update could not be searched: "
                                 f"{error or _wm_last_line(result.stderr) or result.returncode}")
            return None
        if not found:
            self.queue.put(f"PROGRESS:{label}:No missing driver updates on Windows Update.")
            return None

        options = []
        for update in found:
            graphics = update["cls"].lower() == "display"
            detail = f"{update['cls'] or 'Driver'} driver" + (f", dated {update['date']}" if update["date"] else "")
            if graphics:
                detail += (". Left unticked: Windows Update often offers an older graphics driver than "
                           "NVIDIA, AMD or Intel's own installer -- get GPU drivers from them.")
            options.append({"key": update["id"], "label": update["title"], "detail": detail,
                            "checked": not graphics})
        chosen = self._ui_check_picker(
            "Driver updates", f"Windows Update has {len(found)} driver update(s) for this PC. "
            "Tick the ones to install:", options)
        if not chosen:
            self.queue.put(f"PROGRESS:{label}:Nothing selected -- no drivers were installed.")
            return None

        wanted = ",".join(f"'{update_id}'" for update_id in chosen)
        install = r'''
        $want = @(%WANT%)
        try {
            $s = New-Object -ComObject Microsoft.Update.Session
            $r = $s.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Driver'")
            $coll = New-Object -ComObject Microsoft.Update.UpdateColl
            foreach ($u in $r.Updates) { if ($want -contains $u.Identity.UpdateID) { [void]$coll.Add($u) } }
            if ($coll.Count -eq 0) { Write-Host "Those updates are no longer offered."; exit 0 }
            $dl = New-Object -ComObject Microsoft.Update.UpdateColl
            foreach ($u in $coll) { if (-not $u.IsDownloaded) { [void]$dl.Add($u) } }
            if ($dl.Count -gt 0) {
                Write-Host "Downloading $($dl.Count) driver update(s)..."
                $d = $s.CreateUpdateDownloader(); $d.Updates = $dl
                $res = $d.Download()
                if ($res.ResultCode -ne 2) { Write-Host "Download failed (result code $($res.ResultCode))."; exit 1 }
            }
            Write-Host "Installing $($coll.Count) driver update(s)..."
            $i = $s.CreateUpdateInstaller(); $i.Updates = $coll
            $res = $i.Install()
            for ($n = 0; $n -lt $coll.Count; $n++) {
                $code = $res.GetUpdateResult($n).ResultCode
                $word = switch ($code) { 2 { 'installed' } 3 { 'installed, with errors' } 4 { 'FAILED' } 5 { 'aborted' } default { "result $code" } }
                Write-Host ("{0}: {1}" -f $coll.Item($n).Title, $word)
            }
            if ($res.RebootRequired) { Write-Host "WM_REBOOT" }
            if ($res.ResultCode -ne 2) { exit 1 }
            exit 0
        } catch { Write-Host "Install failed: $($_.Exception.Message)"; exit 1 }
        '''.replace("%WANT%", wanted)
        lines = []
        rc, _ = self._run_live_command(
            ['powershell', '-NoProfile', '-ExecutionPolicy', 'RemoteSigned', '-Command', install],
            label, timeout=5400, output=lines)
        if self.cancel_event.is_set():
            return None
        if "WM_REBOOT" in lines:
            self.queue.put(f"REBOOTRECOMMEND:{label}:Driver updates were installed and need a restart "
                           f"to finish.")
        if rc != 0:
            self._report_failure(f"PROGRESS:{label}:At least one driver update did not install; the "
                                 f"lines above say which.")
            return None
        self.queue.put(f"PROGRESS:{label}:Driver updates installed.")
        return len(chosen)

    def install_system_drivers_info(self):
        """Install missing drivers the user picks, then display detailed driver information."""
        label = "Install System Drivers"
        self.queue.put(f"PROGRESS:{label}:Starting missing-driver detection and installation...")
        try:
            self._install_driver_updates(label)
            if self.cancel_event.is_set():
                return

            self.queue.put(f"PROGRESS:{label}:Collecting detailed driver inventory...")
            for cmd, name in ((["driverquery", "/v"], "driverquery /v"),
                              (["driverquery", "/si"], "driverquery /si")):
                self.queue.put(f"PROGRESS:{label}:Executing: {name}")
                result = wm_run(cmd, capture_output=True, text=True, encoding='utf-8',
                                errors='replace', check=False, startupinfo=_no_console_startupinfo())
                if result.stdout.strip():
                    self.queue.put(f"PROGRESS:{label}:Output for {name}:")
                    for line in result.stdout.strip().split('\n'):
                        if line.strip():
                            self.queue.put(f"PROGRESS:{label}:  {line.strip()}")
                if result.returncode != 0:
                    self._report_failure(f"PROGRESS:{label}:{name} exited with code {result.returncode}: "
                                         f"{_wm_last_line(result.stderr) or 'driver inventory could not be read'}")

            self.queue.put(f"PROGRESS:{label}:System driver information collection completed")

        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error collecting system driver information: {str(e)}")

    def run_driver_rollback_center(self):
        """Export every third-party driver package, with an inventory and a restore guide."""
        label = "Driver Rollback Center"
        self.queue.put(f"PROGRESS:{label}:Creating a driver snapshot...")
        try:
            ts = time.strftime("%Y%m%d_%H%M%S")
            # A local folder, never the (possibly OneDrive-synced) Desktop:
            # exported driver packages easily run to gigabytes.
            out_dir = os.path.join(os.path.expanduser("~"), "WinMend", "Driver Snapshots", ts)
            drivers_dir = os.path.join(out_dir, "Drivers")
            os.makedirs(drivers_dir, exist_ok=True)

            # The old "snapshot" was text inventories only -- nothing that could
            # put a driver back. pnputil exports the installable packages.
            self.queue.put(f"PROGRESS:{label}:Exporting every third-party driver package to {drivers_dir}...")
            rc, _ = self._run_live_command(['pnputil', '/export-driver', '*', drivers_dir], label)
            if self.cancel_event.is_set():
                return
            packages = [e.name for e in os.scandir(drivers_dir) if e.is_dir()]
            size = sum(os.path.getsize(os.path.join(root, f))
                       for root, _d, files in os.walk(drivers_dir) for f in files)
            if rc != 0 or not packages:
                self._report_failure(f"PROGRESS:{label}:pnputil could not export the drivers (code {rc}).")
            else:
                self.queue.put(f"PROGRESS:{label}:Exported {len(packages)} driver package(s), "
                               f"{size / 1048576:.0f} MB.")

            commands = [
                (['pnputil', '/enum-drivers'], 'pnputil_enum_drivers.txt'),
                (['driverquery', '/v'], 'driverquery_verbose.txt'),
                (['driverquery', '/si'], 'driverquery_signed.txt'),
                (['powershell', '-NoProfile', '-Command',
                  'Get-PnpDevice | Sort-Object Class, Status | Format-Table -AutoSize | Out-String -Width 220'],
                 'pnp_devices.txt'),
            ]
            for cmd, filename in commands:
                try:
                    result = wm_run(cmd, capture_output=True, text=True, encoding='utf-8',
                                    errors='replace', check=False, startupinfo=_no_console_startupinfo())
                    with open(os.path.join(out_dir, filename), 'w', encoding='utf-8') as f:
                        f.write(result.stdout or "")
                        if result.stderr:
                            f.write("\n\n=== STDERR ===\n" + result.stderr)
                except Exception as inner:
                    with open(os.path.join(out_dir, filename), 'w', encoding='utf-8') as f:
                        f.write(f"Collection error: {str(inner)}")

            with open(os.path.join(out_dir, "Rollback_Guide.txt"), 'w', encoding='utf-8') as f:
                f.write(
                    "WinMend Driver Rollback Center\n"
                    "==============================\n"
                    f"Snapshot taken {time.strftime('%Y-%m-%d %H:%M')}. The Drivers folder holds a copy\n"
                    "of every third-party driver that was installed at that moment.\n\n"
                    "To put one of these drivers back:\n"
                    "1. Open Device Manager and find the device (Display adapters, Network, ...).\n"
                    "2. Right-click it > Update driver > Browse my computer for drivers.\n"
                    f"3. Browse to:  {drivers_dir}\n"
                    "   tick 'Include subfolders', and finish the wizard.\n\n"
                    "Or, from an administrator command prompt, reinstall them all at once:\n"
                    f"   pnputil /add-driver \"{drivers_dir}\\*.inf\" /subdirs /install\n\n"
                    "If the PC became unstable after a driver change, 'Roll Back Driver' on the\n"
                    "device's Driver tab, or WinMend's Safety Journal (Undo), are quicker first steps.\n"
                    "pnputil_enum_drivers.txt lists which oemNN.inf belongs to which device.\n")

            self.queue.put(f"PROGRESS:{label}:Snapshot and guide saved to {out_dir}")
            try:
                os.startfile(out_dir)
            except Exception:
                pass
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {str(e)}")

    def run_windows_update_forensic_fixer(self):
        """Diagnose Windows Update first, then repair only what the evidence points at."""
        label = "Update Forensic"
        self.queue.put(f"PROGRESS:{label}:Running Windows Update forensic diagnostics...")
        try:
            diag = self._run_ps(r'''
            foreach ($n in 'wuauserv', 'bits', 'cryptsvc', 'usosvc', 'TrustedInstaller') {
                $s = Get-Service -Name $n -ErrorAction SilentlyContinue
                if ($s) { Write-Output "SVC|$n|$($s.Status)|$($s.StartType)" }
            }
            $pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
            Write-Output "REBOOT|$pending"
            # Every error, and every successful install, of the last 14 days.
            # Event 20 (install failure) is [code, title, update id, revision];
            # event 19 (install success) is [title, update id, revision].
            $log = @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WindowsUpdateClient'; StartTime = (Get-Date).AddDays(-14) }
            $events = @(Get-WinEvent -FilterHashtable ($log + @{ Level = 2 }) -ErrorAction SilentlyContinue) +
                      @(Get-WinEvent -FilterHashtable ($log + @{ Id = 19 }) -ErrorAction SilentlyContinue)
            foreach ($e in $events) {
                $p = @($e.Properties | ForEach-Object { "$($_.Value)" })
                $id = ''; $code = ''; $title = ''
                if ($e.Id -eq 20 -and $p.Count -ge 3) {
                    $n = [int64]$p[0]; if ($n -lt 0) { $n += 4294967296 }
                    $code = '0x{0:X8}' -f $n; $title = $p[1]; $id = $p[2]
                }
                elseif ($e.Id -eq 19 -and $p.Count -ge 2) { $title = $p[0]; $id = $p[1] }
                else { $title = ($e.Message -split "`r?`n")[0] }
                Write-Output ("EV|{0}|{1}|{2}|{3}|{4}" -f $e.Id, $e.TimeCreated.ToUniversalTime().ToString('s'), $id, $code, ($title -replace '\|', '/'))
            }
            ''', timeout=180)
            services, pending, events = {}, False, []
            for line in (diag.stdout or "").splitlines():
                parts = line.strip().split("|")
                if parts[0] == "SVC" and len(parts) == 4:
                    services[parts[1]] = (parts[2], parts[3])
                elif parts[0] == "REBOOT" and len(parts) == 2:
                    pending = parts[1].strip().lower() == "true"
                elif parts[0] == "EV":
                    event = parse_update_event(line.strip())
                    if event:
                        events.append(event)
            current, resolved = classify_update_errors(events)

            for name, (status, start) in services.items():
                self.queue.put(f"PROGRESS:{label}:  {name}: {status}, start type {start}")
            self.queue.put(f"PROGRESS:{label}:  Restart pending: {'yes' if pending else 'no'}")
            self.queue.put(f"PROGRESS:{label}:  Windows Update errors in the last 14 days: "
                           f"{len(current) + len(resolved)}")
            for error, fixed_by in resolved[:5]:
                self.queue.put(f"PROGRESS:{label}:    {describe_update_error(error)} -- already "
                               f"resolved: it installed on {fixed_by['time']:%Y-%m-%d}.")
            for error in current[:5]:
                self.queue.put(f"PROGRESS:{label}:    {describe_update_error(error)}")

            # Services switched off by a "debloat" or privacy tool are the one
            # thing that stops every update outright; put them back first.
            defaults = {"wuauserv": "demand", "bits": "demand", "cryptsvc": "auto",
                        "usosvc": "delayed-auto", "TrustedInstaller": "demand"}
            for name, (_status, start) in services.items():
                if start.lower() == "disabled":
                    rc, _ = self._run_live_command(['sc', 'config', name, 'start=', defaults[name]],
                                                   label, timeout=30)
                    if rc == 0:
                        self.queue.put(f"PROGRESS:{label}:{name} was switched off -- set back to its "
                                       f"Windows default ({defaults[name]}).")
                    else:
                        self._report_failure(f"PROGRESS:{label}:{name} is switched off and Windows "
                                             f"refused to turn it back on (rc={rc}).")

            if pending:
                # Resetting the update folders under a pending install can
                # break the very update that is waiting to finish.
                self.queue.put(f"PROGRESS:{label}:Windows is waiting for a restart to finish installing "
                               f"updates. Nothing else was changed -- restart, then run this again if "
                               f"updates still fail.")
                self.queue.put(f"REBOOTRECOMMEND:{label}:Windows has updates waiting for a restart to "
                               f"finish.")
                return

            if current:
                self.queue.put(f"PROGRESS:{label}:Recent update errors point at the update components -- "
                               f"resetting them.")
                self.reset_windows_update()
            elif resolved:
                # A failure that a later install of the same update cleared is
                # history, not a broken Windows Update; resetting over it only
                # throws away the update cache.
                self.queue.put(f"PROGRESS:{label}:Each of those errors was followed by a successful "
                               f"install, so Windows Update is working -- the components were left "
                               f"as they are.")
            else:
                self.queue.put(f"PROGRESS:{label}:No sign of a broken Windows Update -- the components "
                               f"were left as they are.")
            if self.cancel_event.is_set():
                return
            self.queue.put(f"PROGRESS:{label}:Checking for and installing updates...")
            self.check_and_install_windows_updates()
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {str(e)}")
