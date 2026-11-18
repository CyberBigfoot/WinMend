"""WinMend features: shell."""

from __future__ import annotations

from winmend.core.processes import _no_console_startupinfo, wm_run
from winmend.core.prompts import messagebox
from winmend.core.safe_delete import final_path, remove_tree
from winmend.core.search import _wm_last_line
from winmend.features.explorer.helpers import (
    close_explorer,
    icon_cache_files,
    session_explorer_pids,
    start_explorer,
)
from winmend.features.office.helpers import service_state
from winmend.features.shell_helpers import (
    DISM_UNKNOWN_FEATURE,
    optional_feature_steps,
    reset_user_choices,
)
from winmend.features.storage.scanner import ss_format_size
import ctypes
import os
import re


class ShellTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    def rebuild_icon_and_thumb_cache(self):
        """Clear Explorer's icon and thumbnail caches so Windows rebuilds them.

        Explorer keeps these files open for as long as it runs, so they can only
        go while it is closed. The old script ended Explorer by force, which
        Windows treats as a crash and restarts within a second or two: by the
        time the deletes ran, the new Explorer had the files open again, every
        delete failed without stopping the script, and the task reported
        success. It then started a second Explorer, which opened as a stray
        folder window. So Explorer is now closed the way its own "Exit
        Explorer" closes it, each file is checked, and Explorer is started again
        only if Windows has not already done that.
        """
        label = "Rebuild Icon Cache"
        try:
            base = final_path(os.environ["LOCALAPPDATA"])
        except (KeyError, OSError) as exc:
            self._report_failure(f"PROGRESS:{label}:Could not find this account's local app data "
                                 f"folder ({exc}); nothing was changed.")
            return
        files = icon_cache_files(base)
        if not files:
            self.queue.put(f"PROGRESS:{label}:There are no icon or thumbnail cache files, so there is "
                           f"nothing to clear. Windows creates them as icons are drawn.")
            return
        sizes = {}
        for path in files:
            try:
                sizes[path] = os.lstat(path).st_size
            except OSError:
                sizes[path] = 0
        self.queue.put(f"PROGRESS:{label}:Found {len(files)} cache file(s), "
                       f"{ss_format_size(sum(sizes.values()))}.")
        if self.cancel_event.is_set():
            return

        self.queue.put(f"PROGRESS:{label}:Closing Explorer (the desktop and taskbar disappear for "
                       f"a few seconds)...")
        problem = close_explorer()
        removed, left = [], []
        try:
            if problem:
                self._report_failure(f"PROGRESS:{label}:{problem}, so its cache files are still in use. "
                                     f"Nothing was removed.")
                return
            for path in files:
                # Link-safe: a cache file that is a link, or is reached through
                # one, is refused rather than followed (WinMend runs elevated).
                if remove_tree(path) or not os.path.lexists(path):
                    removed.append(path)
                else:
                    left.append(path)
        finally:
            if session_explorer_pids():
                if not problem:
                    self.queue.put(f"PROGRESS:{label}:Windows had already started Explorer again.")
            else:
                self.queue.put(f"PROGRESS:{label}:Starting Explorer...")
                trouble = start_explorer()
                if trouble:
                    self.queue.put(f"PROGRESS:{label}:{trouble} Press Ctrl+Shift+Esc, then File > "
                                   f"Run new task > explorer.exe")

        freed = ss_format_size(sum(sizes[p] for p in removed))
        if left:
            shown = ", ".join(os.path.basename(p) for p in left[:6])
            if len(left) > 6:
                shown += f" and {len(left) - 6} more"
            self._report_failure(
                f"PROGRESS:{label}:Removed {len(removed)} of {len(files)} cache files ({freed}). "
                f"{len(left)} could not be removed because a program still had them open: {shown}. "
                f"An open Save or Open dialog, or Windows' thumbnail helper, can hold them. "
                f"Sign out and back in, then run this again.")
            return
        self.queue.put(f"PROGRESS:{label}:Removed all {len(files)} cache files ({freed}). Windows "
                       f"rebuilds them as icons and thumbnails are drawn, so the first folders you "
                       f"open are slower for a moment.")

    def run_rebuild_font_cache(self):
        """Rebuild the Windows font cache to fix corrupted/missing fonts"""
        self.queue.put("PROGRESS:Rebuild Font Cache:Starting font cache rebuild...")

        try:
            # Stop the font cache service
            self.queue.put("PROGRESS:Rebuild Font Cache:Stopping Font Cache service...")
            rc, _ = self._run_live_command(['net', 'stop', 'FontCache'], 'Rebuild Font Cache', timeout=30)

            # Also stop FontCache3.0.0.0 if it exists
            self.queue.put("PROGRESS:Rebuild Font Cache:Stopping FontCache3.0.0.0 service...")
            self._run_live_command(['net', 'stop', 'FontCache3.0.0.0'], 'Rebuild Font Cache', timeout=30)

            # Delete font cache files
            self.queue.put("PROGRESS:Rebuild Font Cache:Deleting font cache files...")
            font_cache_dir = os.path.join(os.environ.get('WinDir', r'C:\Windows'), 'ServiceProfiles', 'LocalService', 'AppData', 'Local', 'FontCache')
            deleted = 0
            if os.path.exists(font_cache_dir):
                for f in os.listdir(font_cache_dir):
                    fpath = os.path.join(font_cache_dir, f)
                    try:
                        if os.path.isfile(fpath):
                            os.remove(fpath)
                            deleted += 1
                            self.queue.put(f"PROGRESS:Rebuild Font Cache:Deleted: {f}")
                    except Exception:
                        self._report_failure(f"PROGRESS:Rebuild Font Cache:Could not delete: {f}")

            # Also check for ~FontCache-*.dat in System directory
            sys_dir = os.path.join(os.environ.get('WinDir', r'C:\Windows'), 'System32')
            for f in os.listdir(sys_dir):
                if f.startswith('~FontCache') and f.endswith('.dat'):
                    try:
                        os.remove(os.path.join(sys_dir, f))
                        deleted += 1
                        self.queue.put(f"PROGRESS:Rebuild Font Cache:Deleted: {f}")
                    except Exception:
                        self._report_failure(f"PROGRESS:Rebuild Font Cache:Could not delete: {f}")

            self.queue.put(f"PROGRESS:Rebuild Font Cache:Deleted {deleted} cache files")

            # Restart services
            self.queue.put("PROGRESS:Rebuild Font Cache:Restarting Font Cache service...")
            self._run_live_command(['net', 'start', 'FontCache'], 'Rebuild Font Cache', timeout=30)
            if service_state("FontCache3.0.0.0") is not None:  # WPF font cache; gone on newer builds
                self._run_live_command(['net', 'start', 'FontCache3.0.0.0'], 'Rebuild Font Cache', timeout=30)

            if (service_state("FontCache") or {}).get("status") != "running":
                self._report_failure("PROGRESS:Rebuild Font Cache:The Font Cache service did not start "
                                     "again. Windows starts it on demand, or after a restart.")
                return
            self.queue.put("PROGRESS:Rebuild Font Cache:Font cache rebuilt. Fonts should refresh shortly.")

        except Exception as e:
            self._report_failure(f"PROGRESS:Rebuild Font Cache:Error: {str(e)}")

    def run_reset_search_index(self):
        """Reset Windows Search Index to fix broken search/Cortana"""
        label = "Reset Search Index"
        self.queue.put(f"PROGRESS:{label}:Starting Windows Search index reset...")

        try:
            state = service_state("WSearch")
            if state is None:
                self._report_failure(f"PROGRESS:{label}:Windows Search is not installed on this PC.")
                return
            if state.get("start") == "disabled":
                # RAM Optimizations switches it off on purpose. Deleting the
                # index of a service that is not allowed to run rebuilds
                # nothing -- ask, rather than delete and then fail to start it.
                if not messagebox.askyesno(
                        "Windows Search is switched off",
                        "Windows Search is set to Disabled -- WinMend's RAM Optimizations does "
                        "this. The index can only be rebuilt while it runs.\n\n"
                        "Turn Windows Search back on (Automatic, delayed start) and rebuild the "
                        "index?"):
                    self.queue.put(f"PROGRESS:{label}:Windows Search left switched off; the index "
                                   f"was not touched.")
                    return
                rc, _ = self._run_live_command(['sc', 'config', 'WSearch', 'start=', 'delayed-auto'],
                                               label, timeout=30)
                if rc != 0:
                    self._report_failure(f"PROGRESS:{label}:Windows refused to switch Windows Search "
                                         f"back on (rc={rc}).")
                    return
                self.queue.put(f"PROGRESS:{label}:Windows Search set to start automatically again.")

            # Stop the Windows Search service
            self.queue.put(f"PROGRESS:{label}:Stopping Windows Search service...")
            self._run_live_command(['net', 'stop', 'WSearch', '/y'], label, timeout=30)

            # Delete the search index database
            self.queue.put(f"PROGRESS:{label}:Deleting search index database...")
            search_data_dir = os.path.join(os.environ.get('ProgramData', r'C:\ProgramData'),
                                           'Microsoft', 'Search', 'Data', 'Applications', 'Windows')
            if os.path.exists(search_data_dir):
                deleted = 0
                for root, dirs, files in os.walk(search_data_dir):
                    for f in files:
                        try:
                            os.remove(os.path.join(root, f))
                            deleted += 1
                        except Exception:
                            pass
                self.queue.put(f"PROGRESS:{label}:Deleted {deleted} index files")
            else:
                self.queue.put(f"PROGRESS:{label}:Search data directory not found")

            # Restart Windows Search
            self.queue.put(f"PROGRESS:{label}:Restarting Windows Search service...")
            rc, _ = self._run_live_command(['net', 'start', 'WSearch'], label, timeout=30)
            if (service_state("WSearch") or {}).get("status") != "running":
                self._report_failure(f"PROGRESS:{label}:Windows Search did not start again (rc={rc}). "
                                     f"The index rebuilds once it runs.")
                return

            self.queue.put(f"PROGRESS:{label}:Search index reset! Windows will rebuild the index in the background.")
            self.queue.put(f"PROGRESS:{label}:Search results may be incomplete until indexing finishes.")

        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {str(e)}")

    def run_file_assoc_reset(self):
        """Clear the user's default-app choice for common types so Windows asks again."""
        label = "File Assoc Reset"
        extensions = (".txt", ".html", ".htm", ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".mp4",
                      ".mp3", ".zip")
        protocols = ("http", "https")
        if not messagebox.askyesno(
            "Reset File Associations",
            "This will clear the user-choice default app for these common types:\n"
            "  .txt .html .htm .pdf .jpg .jpeg .png .gif .mp4 .mp3 .zip\n"
            "  and web links (http/https).\n\n"
            "After this, opening one of those will let you pick a fresh default. Windows "
            "protects some of them from changes by any program; for those, Settings opens "
            "so you can choose there.\n\n"
            "Continue?"
        ):
            self._report_skip(f"PROGRESS:{label}:Cancelled by user.")
            return
        try:
            results = reset_user_choices(extensions, protocols)
            cleared = [k for k, v in results.items() if v == "cleared"]
            protected = [k for k, v in results.items() if v == "protected"]
            unset = [k for k, v in results.items() if v == "not set"]
            if cleared:
                self.queue.put(f"PROGRESS:{label}:Cleared the default app for: {' '.join(cleared)}")
            if unset:
                self.queue.put(f"PROGRESS:{label}:No choice was set for: {' '.join(unset)} (already the "
                               f"Windows default)")
            # Tell the shell the associations changed, rather than killing
            # Explorer to make it notice.
            try:
                ctypes.windll.shell32.SHChangeNotify(0x08000000, 0x0000, None, None)  # SHCNE_ASSOCCHANGED
            except Exception:
                pass
            if protected:
                self.queue.put(f"PROGRESS:{label}:Windows protects these defaults from being changed by "
                               f"programs: {' '.join(protected)}. Settings > Apps > Default apps is "
                               f"opening -- pick the app for each there.")
                try:
                    os.startfile("ms-settings:defaultapps")
                except Exception:
                    pass
            self.queue.put(f"PROGRESS:{label}:File-association reset complete.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")

    def run_optional_features_toggle(self):
        """Pop a picker to enable/disable a Windows optional feature via DISM."""
        label = "Optional Features"
        options = [
            ("Microsoft-Hyper-V-All:enable", "Enable Hyper-V (full)"),
            ("Microsoft-Hyper-V-All:disable", "Disable Hyper-V"),
            ("Microsoft-Windows-Subsystem-Linux:enable", "Enable WSL"),
            ("Microsoft-Windows-Subsystem-Linux:disable", "Disable WSL"),
            ("VirtualMachinePlatform:enable", "Enable Virtual Machine Platform"),
            ("VirtualMachinePlatform:disable", "Disable Virtual Machine Platform"),
            ("Containers-DisposableClientVM:enable", "Enable Windows Sandbox"),
            ("Containers-DisposableClientVM:disable", "Disable Windows Sandbox"),
            ("Containers:enable", "Enable Containers"),
            ("Containers:disable", "Disable Containers"),
            # Shipped-but-off components older software still asks for. NetFx3
            # covers .NET Framework 2.0 and 3.x as well as 3.5.
            ("NetFx3:enable", "Enable .NET Framework 3.5 (also covers 2.0 and 3.0)"),
            ("NetFx3:disable", "Disable .NET Framework 3.5"),
            ("LegacyComponents:enable", "Enable DirectPlay (Legacy Components)"),
            ("LegacyComponents:disable", "Disable DirectPlay (Legacy Components)"),
            ("WindowsMediaPlayer:enable", "Enable Windows Media Player (legacy)"),
            ("WindowsMediaPlayer:disable", "Disable Windows Media Player (legacy)"),
            ("ServicesForNFS-ClientOnly:enable", "Enable NFS client"),
            ("ServicesForNFS-ClientOnly:disable", "Disable NFS client"),
        ]
        choice = self._ui_radio_picker(
            "Windows optional features",
            "Choose a Windows optional feature to enable or disable. "
            "A reboot is required for the change to fully take effect.",
            options
        )
        if not choice:
            self._report_skip(f"PROGRESS:{label}:Cancelled.")
            return

        feat, action = choice.split(":", 1)
        verb = "Enabling" if action == "enable" else "Disabling"
        steps = optional_feature_steps(feat, action)
        restart = False
        try:
            for index, (name, args) in enumerate(steps):
                self.queue.put(f"PROGRESS:{label}:{verb} {name}...")
                rc, _ = self._run_live_command(args, label)
                if self.cancel_event.is_set():
                    return
                code = rc & 0xFFFFFFFF
                if rc == 3010:  # success, restart required
                    restart = True
                elif rc != 0:
                    if index < len(steps) - 1 and code == DISM_UNKNOWN_FEATURE:
                        self.queue.put(f"PROGRESS:{label}:{name} is not part of this edition of "
                                       f"Windows, so there is nothing to turn off.")
                        continue
                    self._report_failure(f"PROGRESS:{label}:DISM could not {action} {name} (error "
                                         f"0x{code:08X}); the lines above say why. Some features "
                                         f"need a Pro edition or virtualization turned on in the BIOS.")
                    return

            # Read the result back from Windows rather than trusting the exit
            # code: that is how a parent switched on with nothing under it went
            # unnoticed.
            target = steps[0][0] if action == "enable" else feat
            state = self._optional_feature_state(target)
            expected = (("Enabled", "EnablePending") if action == "enable"
                        else ("Disabled", "DisablePending", "DisabledWithPayloadRemoved"))
            if state is None:
                self.queue.put(f"PROGRESS:{label}:DISM finished without an error, but Windows' own "
                               f"record of {target} could not be read back to confirm it.")
            elif state not in expected:
                self._report_failure(f"PROGRESS:{label}:DISM finished without an error, but Windows "
                                     f"still lists {target} as {state}.")
                return
            else:
                restart = restart or state.endswith("Pending")
                self.queue.put(f"PROGRESS:{label}:Windows now lists {target} as {state}.")
            if restart:
                self.queue.put(f"REBOOTRECOMMEND:Windows Optional Features:{target} is {action}d, but "
                               f"Windows only finishes the change at the next restart.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")

    def _optional_feature_state(self, name):
        """Windows' state for an optional feature ('Enabled', 'EnablePending',
        'Disabled', ...), or None when it cannot be read."""
        if not re.fullmatch(r"[A-Za-z0-9.\-]+", name or ""):
            return None
        try:
            r = self._run_ps(f"(Get-WindowsOptionalFeature -Online -FeatureName '{name}' "
                             f"-ErrorAction Stop).State.ToString()", timeout=180)
        except Exception:
            return None
        text = (r.stdout or "").strip()
        return text if r.returncode == 0 and re.fullmatch(r"[A-Za-z]+", text) else None

    def run_legacy_boot_menu(self):
        """Turn the F8 Advanced Boot Options screen on or off.

        `bcdedit /set {default} bootmenupolicy legacy` restores the pre-Windows 8
        boot menu, which is how you reach Safe Mode on a PC that will not start
        properly -- the modern policy only offers it after Windows has already
        failed twice. `standard` is the Windows default and puts it back.
        """
        label = "Legacy F8 Boot Menu"
        current, readable = "", False
        try:
            probe = wm_run(['bcdedit', '/enum', '{current}'], capture_output=True,
                           text=True, encoding='utf-8', errors='replace',
                           check=False, timeout=30,
                           startupinfo=_no_console_startupinfo())
            readable = probe.returncode == 0
            for line in (probe.stdout or "").splitlines():
                if line.lower().strip().startswith("bootmenupolicy"):
                    current = line.split()[-1].strip().lower()
        except Exception:
            pass

        # Without elevation bcdedit cannot even open the boot store, so there is
        # no honest way to state the current policy -- say so rather than
        # reporting Windows' default as if it had been read. When the store IS
        # readable, an absent bootmenupolicy genuinely means Standard.
        if readable:
            shown = current or "standard (Windows default, not set explicitly)"
        else:
            shown = "could not be read — bcdedit needs administrator rights"
        self.queue.put(f"PROGRESS:{label}:Boot menu policy: {shown}")

        choice = self._ui_radio_picker(
            "Legacy F8 Boot Menu",
            f"The F8 menu is the screen that offers Safe Mode before Windows "
            f"loads.\n\nCurrent setting: {shown}\n\n"
            f"Legacy makes F8 work at every boot, at the cost of a slightly "
            f"slower start. Standard is the Windows default.",
            [("legacy", "Enable — F8 opens Advanced Boot Options"),
             ("standard", "Disable — Windows default (faster boot)")],
            default="legacy" if current != "legacy" else "standard")
        if not choice:
            self._report_skip(f"PROGRESS:{label}:Cancelled — nothing was changed.")
            return
        try:
            result = wm_run(['bcdedit', '/set', '{default}', 'bootmenupolicy', choice],
                            capture_output=True, text=True, encoding='utf-8',
                            errors='replace', check=False, timeout=60,
                            startupinfo=_no_console_startupinfo())
            if result.returncode == 0:
                self.queue.put(f"PROGRESS:{label}:Boot menu policy set to {choice}. "
                               f"It applies at the next restart.")
            else:
                detail = _wm_last_line(result.stderr, result.stdout) or \
                    f"exit code {result.returncode}"
                if not self.is_admin():
                    detail += " -- this needs WinMend running as administrator"
                self._report_failure(f"PROGRESS:{label}:bcdedit refused the change: {detail}")
        except Exception as exc:
            self._report_failure(f"PROGRESS:{label}:Error: {exc}")

    def run_start_menu_reset(self):
        """Reset Start Menu (Start2.bin) and Taskbar layout, restart Explorer."""
        label = "Start/Taskbar Reset"
        if not messagebox.askyesno(
            "Reset Start Menu & Taskbar",
            "This will delete Start Menu and Taskbar layout files and restart Explorer.\n"
            "Pinned items will be lost. Continue?", icon='warning'
        ):
            self._report_skip(f"PROGRESS:{label}:Cancelled by user.")
            return

        # The Start menu is its own process (StartMenuExperienceHost), which
        # keeps the layout in memory and writes it back to start2.bin. Deleting
        # the file under it, then restarting only Explorer, let it put the old
        # pins straight back -- so it is stopped first.
        ps_script = r'''
        Stop-Process -Name StartMenuExperienceHost -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        $targets = @(
            "$env:LOCALAPPDATA\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\start2.bin",
            "$env:LOCALAPPDATA\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\start.bin",
            "$env:LOCALAPPDATA\Microsoft\Windows\Shell\DefaultLayouts.xml",
            "$env:LOCALAPPDATA\Microsoft\Windows\Shell\LayoutModification.xml"
        )
        foreach ($p in $targets) {
            if (Test-Path $p) {
                try { Remove-Item -Path $p -Force -ErrorAction Stop; Write-Output "Deleted: $p" }
                catch { Write-Output "WM_FAIL|could not delete ${p}: $($_.Exception.Message)" }
            }
        }
        $tbPath = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
        if (Test-Path $tbPath) {
            Get-ChildItem -Path $tbPath -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            Write-Output "Cleared TaskBar pinned items"
        }
        $k = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband"
        if (Test-Path $k) {
            try { Remove-Item -Path $k -Recurse -Force -ErrorAction Stop; Write-Output "Removed: $k" }
            catch { Write-Output "WM_FAIL|could not remove ${k}: $($_.Exception.Message)" }
        }
        Write-Output "Restarting Explorer..."
        Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) { Start-Process explorer.exe }
        Write-Output "Done. The Start menu rebuilds from defaults the next time it opens."
        '''
        try:
            lines = []
            rc, _ = self._run_live_command(['powershell', '-NoProfile', '-ExecutionPolicy', 'RemoteSigned',
                                    '-Command', ps_script], label, output=lines)
            if self.cancel_event.is_set():
                return
            if rc != 0 or not lines:
                self._report_failure(f"PROGRESS:{label}:Start/Taskbar reset returned no complete result (code {rc}).")
                return
            failures = [line.split("|", 1)[1] for line in lines if line.startswith("WM_FAIL|")]
            for why in failures:
                self._report_failure(f"PROGRESS:{label}:{why}")
            if not failures:
                self.queue.put(f"PROGRESS:{label}:Start/Taskbar reset complete. Sign out and back in "
                               f"if anything still looks old.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")
