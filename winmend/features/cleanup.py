"""WinMend features: cleanup."""

from __future__ import annotations

from winmend.core.processes import (
    WM_STALL_NOTICE_SECS,
    _no_console_startupinfo,
    wm_kill_tree,
    wm_run,
    wm_track_child,
    wm_untrack_child,
)
from winmend.core.registry import open_reg_key
from winmend.core.safe_delete import clear_folder, final_path, remove_tree
from winmend.core.security import SecurityUtils
from winmend.core.windows import bring_window_to_front, process_prompts
from winmend.features.cleanup_helpers import (
    CLEANMGR_EXCLUDED,
    CLEANMGR_STAGE_SERVICES,
    IdleWatch,
    VOLUME_CACHES_KEY,
    cleanmgr_activity_signature,
    configure_cleanmgr_profile,
    disarm_legacy_profile,
    format_bytes_freed,
    format_elapsed,
    plan_cleanmgr_stages,
    processes_named,
    service_pids,
)
import ctypes
import os
import shutil
import subprocess
import sys
import time
import winreg


class CleanupTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    def run_component_store_cleanup(self):
        """Run DISM Component Store Cleanup to free disk space"""
        self.queue.put("PROGRESS:Component Store Cleanup:Starting DISM Component Store Cleanup...")
        self.queue.put("PROGRESS:Component Store Cleanup:This removes old update backups and may take several minutes.")

        try:
            rc, timed_out = self._run_live_command(
                ['dism', '/Online', '/Cleanup-Image', '/StartComponentCleanup'],
                'Component Store Cleanup', timeout=600)

            if rc == 0:
                self.queue.put("PROGRESS:Component Store Cleanup:Component store cleanup completed successfully!")
            elif not self.cancel_event.is_set():
                self._report_failure(f"PROGRESS:Component Store Cleanup:DISM failed (code {rc}); "
                                     f"the lines above say why.")

        except Exception as e:
            self._report_failure(f"PROGRESS:Component Store Cleanup:Error: {str(e)}")

    def run_clear_browser_cache(self):
        """Clear the cache folders of every profile of the common browsers."""
        label = "Clear Browser Cache"
        self.queue.put(f"PROGRESS:{label}:Starting browser cache cleanup...")
        self.queue.put(f"PROGRESS:{label}:Close all browsers for best results.")

        try:
            local = os.environ.get('LOCALAPPDATA', '')
            # Chromium keeps one folder per profile (Default, Profile 1, ...).
            # Only the cache folders inside it are touched -- never Cookies,
            # History, Login Data or anything else a profile keeps.
            chromium = (
                ("Microsoft Edge", os.path.join(local, "Microsoft", "Edge", "User Data")),
                ("Google Chrome", os.path.join(local, "Google", "Chrome", "User Data")),
                ("Brave", os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data")),
                ("Vivaldi", os.path.join(local, "Vivaldi", "User Data")),
            )
            cache_dirs = ("Cache", "Code Cache", "GPUCache")
            targets = []
            for browser, user_data in chromium:
                try:
                    profiles = sorted(e.path for e in os.scandir(user_data)
                                      if e.is_dir() and os.path.exists(os.path.join(e.path, "Preferences")))
                except OSError:
                    continue
                for profile in profiles:
                    targets.append((f"{browser} ({os.path.basename(profile)})",
                                    [os.path.join(profile, d) for d in cache_dirs]))
            # Opera and Opera GX keep the cache at the top of their local folder.
            try:
                for entry in os.scandir(os.path.join(local, "Opera Software")):
                    if entry.is_dir():
                        targets.append((entry.name, [os.path.join(entry.path, d) for d in cache_dirs]))
            except OSError:
                pass
            # Firefox's disk cache lives under LOCAL app data. The old version
            # looked in the roaming profile folder, where there is no cache2,
            # so it never deleted anything.
            try:
                for entry in os.scandir(os.path.join(local, "Mozilla", "Firefox", "Profiles")):
                    if entry.is_dir():
                        targets.append((f"Firefox ({entry.name})", [os.path.join(entry.path, "cache2")]))
            except OSError:
                pass

            if not targets:
                self.queue.put(f"PROGRESS:{label}:No supported browser profiles were found.")
                return

            total_deleted = total_freed = total_skipped = 0
            for name, folders in targets:
                count = size = skipped = 0
                for folder in folders:
                    try:
                        c, s, k = self._wipe_dir_contents(folder, local)
                    except OSError as exc:
                        self.queue.put(f"PROGRESS:{label}:{name}: {os.path.basename(folder)} "
                                       f"was not cleared: {exc}")
                        continue
                    count, size, skipped = count + c, size + s, skipped + k
                total_deleted += count
                total_freed += size
                total_skipped += skipped
                if count or skipped:
                    suffix = f" · skipped {skipped} (locked)" if skipped else ""
                    self.queue.put(f"PROGRESS:{label}:{name}: Deleted {count} files "
                                   f"({size // 1048576} MB){suffix}")

            skip_note = (f" · skipped {total_skipped} (locked — close browsers and retry)"
                         if total_skipped else "")
            self.queue.put(f"PROGRESS:{label}:Total: {total_deleted} files deleted, "
                           f"{total_freed // 1048576} MB freed{skip_note}")

        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {str(e)}")

    @staticmethod
    def _wipe_dir_contents(folder, base):
        """Delete every file under `folder`, keeping the folders themselves.

        Returns (files deleted, bytes freed, files skipped because in use).
        Browsers expect their cache folders to exist, so only files go.

        Not os.walk: in Python 3.10 it follows directory junctions, and this
        runs elevated over folders the user's own programs can write. `base`
        (the app-data folder `folder` is under) may itself be redirected, so it
        is resolved; nothing below it is followed through a link, and a cache
        folder that is one, or is reached through one, raises OSError.
        """
        try:
            return clear_folder(final_path(base) + "\\" + os.path.relpath(folder, base),
                                keep_dirs=True)
        except FileNotFoundError:
            return 0, 0, 0

    def run_event_log_viewer(self):
        """Show recent errors and warnings from Windows Event Log"""
        label = "Event Log Viewer"
        self.queue.put(f"PROGRESS:{label}:Retrieving recent Event Log entries...")

        # Filter on level inside the query. The old script took the last 500
        # events and kept Level -le 3 -- but classic logs record plenty of
        # informational events at level 0 ("log always"), so success messages
        # such as "the storage optimizer successfully completed" were listed
        # as errors. 1 = critical, 2 = error, 3 = warning.
        ps_script = r'''
        foreach ($log in 'System', 'Application') {
            Write-Output "=== $($log.ToUpper()) LOG - Recent Errors & Warnings (last 25) ==="
            $events = @(Get-WinEvent -FilterHashtable @{ LogName = $log; Level = 1, 2, 3 } -MaxEvents 25 -ErrorAction SilentlyContinue)
            foreach ($evt in $events) {
                $lvl = switch ($evt.Level) { 1 {"CRITICAL"} 2 {"ERROR"} 3 {"WARNING"} }
                $time = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                $text = if ($evt.Message) { ($evt.Message -split "`r?`n")[0] } else { "(no description installed for event $($evt.Id))" }
                Write-Output "[$lvl] $time | Source: $($evt.ProviderName) | Event $($evt.Id)"
                Write-Output "  $text"
            }
            if (-not $events) { Write-Output "No recent errors or warnings in the $log log." }
            Write-Output ""
        }
        '''
        try:
            rc, _ = self._run_live_command(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'RemoteSigned', '-Command', ps_script],
                label, timeout=60)
            if rc == 0:
                self.queue.put(f"PROGRESS:{label}:Event log review complete")
            elif not self.cancel_event.is_set():
                self._report_failure(f"PROGRESS:{label}:Reading the event logs failed (code {rc}).")

        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {str(e)}")

    def run_msrt_scan(self):
        """Run Microsoft Malicious Software Removal Tool"""
        self.queue.put("PROGRESS:MSRT Malware Scan:Starting MSRT malware scan...")

        try:
            # Find MRT.exe
            mrt_path = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'MRT.exe')

            if not os.path.exists(mrt_path):
                self._report_failure("PROGRESS:MSRT Malware Scan:MRT.exe not found. It may not be installed.")
                self.queue.put("PROGRESS:MSRT Malware Scan:MSRT is delivered via Windows Update. Make sure updates are current.")
                return

            self.queue.put(f"PROGRESS:MSRT Malware Scan:Found MRT.exe at: {mrt_path}")
            self.queue.put("PROGRESS:MSRT Malware Scan:Running quick scan (this may take several minutes)...")

            # Run MRT in quiet mode with quick scan (/Q = quiet, /F:Y = full scan, no /F = quick)
            rc, timed_out = self._run_live_command(
                [mrt_path, '/Q'], 'MSRT Malware Scan', timeout=1800)  # 30 min timeout

            if self.cancel_event.is_set():
                return
            if rc == 0:
                self.queue.put("PROGRESS:MSRT Malware Scan:MSRT scan completed: no infection found.")
            elif rc == 6:
                # Microsoft KB891716: detections without execution errors are
                # a completed scan, not a failed command.
                self.queue.put("PROGRESS:MSRT Malware Scan:Infection detected; MSRT completed without errors. Review mrt.log for removal details.")
            elif rc in (10, 13):
                self.queue.put("PROGRESS:MSRT Malware Scan:Infection detected and removed; a restart is needed to finish removal.")
                self.queue.put("REBOOTRECOMMEND:MSRT Malware Scan:MSRT requires a restart to finish removing an infection.")
            else:
                self._report_failure(f"PROGRESS:MSRT Malware Scan:MSRT returned code {rc}; scanning encountered errors or removal needs further action. Review mrt.log.")

            # Check for MSRT log
            mrt_log = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'Debug', 'mrt.log')
            if os.path.exists(mrt_log):
                self.queue.put(f"PROGRESS:MSRT Malware Scan:Detailed log available at: {mrt_log}")

        except Exception as e:
            self._report_failure(f"PROGRESS:MSRT Malware Scan:Error: {str(e)}")

    # ==================== SYSTEM TASKS METHODS ====================

    def clean_temp_files(self):
        """Clean the Windows and user Temp folders."""
        label = "Clean Temp Files"
        self.queue.put(f"PROGRESS:{label}:Starting temporary files cleanup...")

        try:
            system_root = os.environ.get('SystemRoot', 'C:\\Windows')
            temp_paths = []
            for path in (os.environ.get('TEMP'), os.path.join(system_root, 'Temp')):
                if path and os.path.normcase(os.path.abspath(path)) not in \
                        {os.path.normcase(os.path.abspath(p)) for p in temp_paths}:
                    temp_paths.append(path)
            # Prefetch is deliberately not cleaned: Windows reads it to start
            # apps faster, and emptying it makes the next boot and the first
            # launch of every app slower while it is rebuilt.

            # The packaged WinMend.exe unpacks itself into %TEMP%\_MEIxxxxxx and
            # imports from there all session long. Pieces not loaded yet (the
            # TLS modules the Speed Test and every download need, certifi's
            # certificate bundle) are ordinary unlocked files, and deleting them
            # broke those features until WinMend was restarted.
            own_bundle = getattr(sys, "_MEIPASS", None)
            cutoff = time.time() - 24 * 3600

            for i, path in enumerate(temp_paths):
                safe_path = SecurityUtils.sanitize_path(path)
                self.queue.put(f"PROGRESS:{label}:Processing directory {i + 1}/{len(temp_paths)}: {safe_path}")
                if not os.path.isdir(safe_path):
                    self.queue.put(f"PROGRESS:{label}:Path does not exist: {safe_path}")
                    continue
                try:
                    free_before = shutil.disk_usage(safe_path).free
                except OSError:
                    free_before = None
                # Where this Temp folder really is. Every deletion below is
                # checked against it, so nothing reached through a link --
                # including one swapped in while the cleanup runs -- is touched.
                try:
                    real_root = final_path(safe_path)
                except OSError as exc:
                    self._report_failure(f"PROGRESS:{label}:Could not open {safe_path}: {exc}")
                    continue
                deleted = in_use = recent = 0
                for entry in os.scandir(safe_path):
                    if self.cancel_event.is_set():
                        return
                    if own_bundle and entry.name.lower().startswith("_mei"):
                        try:
                            if os.path.samefile(entry.path, own_bundle):
                                continue  # compared as folders: TEMP may be a short 8.3 path
                        except OSError:
                            pass
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError:
                        in_use += 1
                        continue
                    if info.st_mtime > cutoff:
                        recent += 1  # an installer or a running app may still need it
                        continue
                    # Not shutil.rmtree: C:\Windows\Temp is writable by every
                    # standard account, and rmtree on Windows can be raced into
                    # following a junction a user swaps in mid-delete. A link
                    # here is deleted as the link, never its target.
                    if remove_tree(real_root + "\\" + entry.name):
                        deleted += 1
                    else:
                        in_use += 1
                freed = ""
                if free_before is not None:
                    try:
                        gained = shutil.disk_usage(safe_path).free - free_before
                        freed = f", about {max(gained, 0) / 1048576:.0f} MB freed"
                    except OSError:
                        pass
                self.queue.put(f"PROGRESS:{label}:Summary: deleted {deleted} item(s){freed}; "
                               f"{in_use} in use or partly in use; {recent} changed in the last "
                               f"24 hours and kept.")

            self.queue.put(f"PROGRESS:{label}:Temporary files cleanup completed")

        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error in clean temp files: {str(e)}")

    # Deep Disk Cleanup's stuck detector. Both are measured idleness -- no CPU
    # time, no I/O, no free-space change across cleanmgr *and* the servicing
    # processes it waits on -- never wall-clock. A slow handler keeps accruing
    # work and is never touched; only a provably dead one is skipped.
    _CLEANMGR_IDLE_WARN_SECS = 300

    _CLEANMGR_IDLE_SKIP_SECS = 600

    _CLEANMGR_REPORT_EVERY = 30

    def run_disk_cleanup(self):
        """Windows Disk Cleanup, run in stages with measured progress.

        The old version ran one `cleanmgr /sagerun:1` with every handler
        enabled and eased a bar toward 95%, where it sat for as long as cleanmgr
        took -- often 20-40 minutes once Windows Update Cleanup was in the same
        pass -- with no way to tell slow from stuck. Three things change here:

        1. Stages. Handlers run in groups, each under its own sage profile
           (61-64), so the log names the part that is slow and the percentage
           moves when real work completes, not when the clock does.
        2. A stuck detector that measures instead of guessing. Every poll reads
           CPU time and I/O for cleanmgr and the servicing processes it hands
           work to, plus free space on the drive. Unchanged for five minutes is
           reported; unchanged for ten -- provably nothing happening -- skips
           that stage and carries on with the rest. A prompt cleanmgr is
           waiting behind (a corrupted Recycle Bin raises one) is found, read
           out in the log and brought to the front instead.
        3. Four handlers are never enabled: the Downloads folder, Windows ESD
           installation files, File History versions and the Recycle Bin (that
           one is emptied here, afterwards, where a corrupted bin cannot stall
           cleanmgr). Earlier versions enabled all of them in profile 1; that
           profile is disarmed on the way past.
        """
        label = "Disk Cleanup"
        sysdrive = os.environ.get("SystemDrive", "C:") + "\\"
        self.queue.put(f"PROGRESS:{label}:Starting Deep Disk Cleanup. 0%")

        try:
            SecurityUtils.validate_registry_key(VOLUME_CACHES_KEY)
            with open_reg_key(winreg.HKEY_LOCAL_MACHINE, VOLUME_CACHES_KEY, winreg.KEY_READ) as key:
                handlers = [winreg.EnumKey(key, i) for i in range(winreg.QueryInfoKey(key)[0])]
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Could not read the Disk Cleanup handler list: {e}")
            return

        stages, excluded = plan_cleanmgr_stages(handlers)
        self.queue.put(f"PROGRESS:{label}:{len(handlers)} cleanup handlers registered; "
                       f"{sum(len(s['handlers']) for s in stages)} will run in {len(stages)} stages.")
        for name in excluded:
            why = CLEANMGR_EXCLUDED.get(name) or next(
                (w for k, w in CLEANMGR_EXCLUDED.items() if k.lower() == name.lower()), "")
            self.queue.put(f"PROGRESS:{label}:  Left off: {name} — {why}.")
        disarmed = disarm_legacy_profile(handlers)
        if disarmed:
            self.queue.put(f"PROGRESS:{label}:Profile 1 (written by earlier WinMend versions) had "
                           f"these enabled and now does not: {', '.join(disarmed)}. Any other "
                           f"tool running 'cleanmgr /sagerun:1' can no longer delete them.")
        if not stages:
            self.queue.put(f"PROGRESS:{label}:Nothing to run. 100%")
            return

        run_started = time.time()
        try:
            free_at_start = shutil.disk_usage(sysdrive).free
        except OSError:
            free_at_start = None
        outcomes = []
        for index, stage in enumerate(stages, start=1):
            if self.cancel_event.is_set():
                self._report_skip(f"PROGRESS:{label}:Cancelled by user before stage {index}.")
                return
            pct_before = int(90 * (index - 1) / len(stages))
            self.queue.put(f"PROGRESS:{label}:Stage {index} of {len(stages)}: {stage['title']} "
                           f"({len(stage['handlers'])} handler{'s' if len(stage['handlers']) != 1 else ''}, "
                           f"profile {stage['profile']}). {pct_before}%")
            if stage["note"]:
                self.queue.put(f"PROGRESS:{label}:  {stage['note']}")
            written, failures = configure_cleanmgr_profile(stage["profile"], stage["handlers"], handlers)
            for handler, err in failures:
                self._report_failure(f"PROGRESS:{label}:  Could not configure {handler}: {err}")
            if not written:
                self.queue.put(f"PROGRESS:{label}:  Skipping this stage — no handler could be configured.")
                outcomes.append({"stage": stage, "status": "skipped", "freed": 0, "secs": 0,
                                 "why": "the sage profile could not be written"})
                continue

            outcome = self._run_cleanmgr_stage(label, stage, index, len(stages), sysdrive)
            if outcome is None:
                return  # cancelled; already logged
            outcomes.append(outcome)
            if outcome["status"] != "done":
                self._report_failure(f"PROGRESS:{label}:{stage['title']} did not complete: {outcome['why']}.")
            pct_after = int(90 * index / len(stages))
            verb = {"done": "finished", "skipped": "skipped", "failed": "ended"}[outcome["status"]]
            self.queue.put(f"PROGRESS:{label}:Stage {index} of {len(stages)} {verb} in "
                           f"{format_elapsed(outcome['secs'])} — {format_bytes_freed(outcome['freed'])} "
                           f"freed. {pct_after}%")

        # The Recycle Bin handler is deliberately not in any stage: a corrupted
        # bin raises a modal prompt inside cleanmgr. Clear-RecycleBin -Force asks
        # the shell without confirmation UI, so it cannot stall. It throws on an
        # already-empty bin, which is not a failure.
        self.queue.put(f"PROGRESS:{label}:Emptying the Recycle Bin on all drives... 95%")
        try:
            wm_run(['powershell', '-NoProfile', '-NonInteractive', '-Command',
                    'Clear-RecycleBin -Force -ErrorAction SilentlyContinue'],
                   cancel_event=self.cancel_event, capture_output=True,
                   startupinfo=_no_console_startupinfo())
        except Exception as e:
            self.queue.put(f"PROGRESS:{label}:Recycle Bin: {e}")

        try:
            freed_total = shutil.disk_usage(sysdrive).free - free_at_start if free_at_start is not None else None
        except OSError:
            freed_total = None
        finished = sum(1 for o in outcomes if o["status"] == "done")
        skipped = [o for o in outcomes if o["status"] == "skipped"]
        self.queue.put(f"PROGRESS:{label}:Deep Disk Cleanup complete: {finished} of {len(stages)} stages "
                       f"finished, {format_bytes_freed(freed_total)} freed on {sysdrive[:2]} in "
                       f"{format_elapsed(time.time() - run_started)}. 100%")
        for o in skipped:
            self.queue.put(f"PROGRESS:{label}:  Skipped: {o['stage']['title']} — {o['why']}.")
            if o["stage"]["key"] == "updates":
                self.queue.put(f"PROGRESS:{label}:  'Component Store Cleanup (DISM)' on the Cleanup page "
                               f"does the same job through DISM and can be run on its own.")

    def _run_cleanmgr_stage(self, label, stage, index, total, sysdrive):
        """Run one sage profile to completion, or skip it once it is provably dead.

        Returns {"stage", "status": done|skipped|failed, "freed", "secs", "why"},
        or None if the user pressed Stop (already logged, cleanmgr killed).
        """
        try:
            free_before = shutil.disk_usage(sysdrive).free
        except OSError:
            free_before = None
        started = time.time()
        try:
            process = wm_track_child(subprocess.Popen(
                ['cleanmgr', f'/sagerun:{stage["profile"]}'],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                startupinfo=_no_console_startupinfo()))
        except Exception as e:
            self.queue.put(f"PROGRESS:{label}:  Could not start cleanmgr: {e}")
            return {"stage": stage, "status": "failed", "freed": 0, "secs": 0, "why": str(e)}

        extra_pids = service_pids(CLEANMGR_STAGE_SERVICES.get(stage["key"], ()))
        watch = IdleWatch()
        last_report = started
        stall_notified = False
        idle_warned = False
        prompts_seen = {}
        status, why = "done", ""

        while True:
            rc = process.poll()
            if rc is not None:
                if rc not in (0, None):
                    self.queue.put(f"PROGRESS:{label}:  cleanmgr exited with code {rc}.")
                    status = "failed"
                    why = f"cleanmgr exited with code {rc}"
                break

            if self.cancel_event.is_set():
                wm_kill_tree(process)
                try:
                    process.wait(timeout=5)
                except Exception:
                    pass
                wm_untrack_child(process)
                self._report_skip(f"PROGRESS:{label}:Cancelled by user during stage {index} — cleanmgr terminated.")
                return None

            now = time.time()
            elapsed = now - started
            idle = watch.update(cleanmgr_activity_signature(sysdrive, extra_pids))

            if now - last_report >= self._CLEANMGR_REPORT_EVERY:
                last_report = now
                try:
                    freed_so_far = shutil.disk_usage(sysdrive).free - free_before if free_before is not None else None
                except OSError:
                    freed_so_far = None
                self.queue.put(f"PROGRESS:{label}:  Stage {index} of {total}: {format_elapsed(elapsed)} in, "
                               f"{format_bytes_freed(freed_so_far)} freed so far"
                               + (f" — no measurable activity for {format_elapsed(idle)}"
                                  if idle >= 60 else "") + ".")

            if not stall_notified and elapsed > WM_STALL_NOTICE_SECS:
                stall_notified = True
                self.queue.put(f"PROGRESS:{label}:  Still working — cleanmgr shows no progress of its "
                               f"own, so WinMend measures it: CPU time, disk I/O and free space are "
                               f"checked every few seconds. Nothing is cut off while any of them moves.")

            if idle >= self._CLEANMGR_IDLE_WARN_SECS:
                cleanmgr_pids = [p.pid for p in processes_named(("cleanmgr.exe",))]
                prompts = process_prompts(cleanmgr_pids)
                for prompt in prompts:
                    key = (prompt["hwnd"], prompt["text"])
                    if now - prompts_seen.get(key, 0) < 300:
                        continue
                    prompts_seen[key] = now
                    bring_window_to_front(prompt["hwnd"])
                    self.queue.put(f"PROGRESS:{label}:  cleanmgr is waiting on a prompt and has been "
                                   f"brought to the front — \"{prompt['title']}: {prompt['text']}\" "
                                   f"[{' / '.join(prompt['buttons'])}]. Answer it and the cleanup continues; "
                                   f"it will not be cut off while the prompt is on screen.")
                if prompts:
                    time.sleep(3)
                    continue
                if not idle_warned:
                    idle_warned = True
                    self.queue.put(f"PROGRESS:{label}:  No activity for {format_elapsed(idle)}: no CPU time, "
                                   f"no disk I/O and no free-space change across cleanmgr and Windows "
                                   f"servicing. If that continues to "
                                   f"{format_elapsed(self._CLEANMGR_IDLE_SKIP_SECS)} this stage is skipped "
                                   f"and the rest of the cleanup goes on.")
                if idle >= self._CLEANMGR_IDLE_SKIP_SECS:
                    wm_kill_tree(process)
                    try:
                        process.wait(timeout=5)
                    except Exception:
                        pass
                    status = "skipped"
                    why = (f"cleanmgr did no measurable work for {format_elapsed(idle)} "
                           f"(no CPU time, no disk I/O, no free-space change) and was ended")
                    self.queue.put(f"PROGRESS:{label}:  Skipping stage {index}: {why}.")
                    break
            else:
                idle_warned = False
            time.sleep(3)

        wm_untrack_child(process)
        # A cleanmgr instance can hand off to a second one; give stragglers a
        # moment rather than declaring the stage done under them.
        settle_started = time.time()
        while time.time() - settle_started < 30 and processes_named(("cleanmgr.exe",)):
            if self.cancel_event.is_set():
                break
            time.sleep(2)

        try:
            freed = shutil.disk_usage(sysdrive).free - free_before if free_before is not None else None
        except OSError:
            freed = None
        return {"stage": stage, "status": status, "freed": freed,
                "secs": time.time() - started, "why": why}

    def run_windows_old_cleanup(self):
        """Delete C:\\Windows.old after taking ownership. Destructive, confirmed upstream."""
        label = "Windows.old"
        drive = os.environ.get('SystemDrive', 'C:')
        path = os.path.join(drive + os.sep, 'Windows.old')
        if not os.path.isdir(path):
            self.queue.put(f"PROGRESS:{label}:No Windows.old folder on {drive} — nothing to remove.")
            return
        try:
            free_before = shutil.disk_usage(drive + os.sep).free
            self.queue.put(f"PROGRESS:{label}:Taking ownership of {path} (this can take several minutes)...")
            wm_run(['takeown', '/F', path, '/R', '/A', '/D', 'Y'],
                   capture_output=True, cancel_event=self.cancel_event,
                   startupinfo=_no_console_startupinfo())
            if self.cancel_event.is_set():
                return
            self.queue.put(f"PROGRESS:{label}:Granting delete permissions...")
            wm_run(['icacls', path, '/grant', '*S-1-5-32-544:F', '/T', '/C', '/Q'],
                   capture_output=True, cancel_event=self.cancel_event,
                   startupinfo=_no_console_startupinfo())
            if self.cancel_event.is_set():
                return
            self.queue.put(f"PROGRESS:{label}:Deleting {path}...")
            r = wm_run(['cmd', '/c', 'rd', '/s', '/q', path],
                       capture_output=True, cancel_event=self.cancel_event,
                       startupinfo=_no_console_startupinfo())
            if self.cancel_event.is_set():
                return
            freed = max(shutil.disk_usage(drive + os.sep).free - free_before, 0) / 1024**3
            if os.path.isdir(path):
                self._report_failure(f"PROGRESS:{label}:Some files could not be removed (rd returned "
                                     f"{r.returncode}; {freed:.1f} GB freed so far). Restart and run "
                                     f"this again, or use Deep Disk Cleanup.")
            else:
                self.queue.put(f"PROGRESS:{label}:Windows.old removed — reclaimed about {freed:.1f} GB.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")

    def run_restore_point_cleanup(self):
        """Delete every System Restore point except the newest one."""
        label = "Restore Points"
        self.queue.put(f"PROGRESS:{label}:Listing restore points...")
        try:
            r = self._run_ps(
                "Get-ComputerRestorePoint -ErrorAction Stop | ForEach-Object { Write-Output ('RP|' + "
                "$_.SequenceNumber + '|' + $_.ConvertToDateTime($_.CreationTime).ToString('yyyy-MM-dd HH:mm') "
                "+ '|' + $_.Description) }", timeout=120)
            if r.returncode != 0:
                self._report_failure(f"PROGRESS:{label}:Could not list restore points: "
                                     f"{(r.stderr or str(r.returncode)).strip()}")
                return
            points = []
            for line in (r.stdout or "").splitlines():
                parts = line.strip().split("|", 3)
                if len(parts) == 4 and parts[0] == "RP" and parts[1].isdigit():
                    points.append((int(parts[1]), parts[2], parts[3]))
            points.sort()
            if not points:
                self.queue.put(f"PROGRESS:{label}:No restore points found.")
                return
            if len(points) == 1:
                self.queue.put(f"PROGRESS:{label}:Only one restore point exists — keeping it.")
                return
            newest, old = points[-1], points[:-1]
            self.queue.put(f"PROGRESS:{label}:{len(points)} found — deleting {len(old)}, keeping the newest "
                           f"(#{newest[0]}, {newest[1]}, {newest[2]})...")
            # By restore-point number, through System Restore's own API. The
            # old `vssadmin delete shadows /oldest` removed shadow copies of
            # any kind -- including a backup program's snapshots -- and if
            # the newest shadow was one of those, no restore point survived.
            remove = ctypes.windll.srclient.SRRemoveRestorePoint
            deleted = 0
            for seq, when, desc in old:
                if self.cancel_event.is_set():
                    break
                rc = remove(ctypes.c_ulong(seq))
                if rc == 0:
                    deleted += 1
                    self.queue.put(f"PROGRESS:{label}:  deleted #{seq} ({when}, {desc})")
                else:
                    self._report_failure(f"PROGRESS:{label}:  #{seq} could not be deleted (error {rc}).")
            self.queue.put(f"PROGRESS:{label}:Deleted {deleted} old restore point(s); newest kept.")
            s = wm_run(['vssadmin', 'list', 'shadowstorage'], capture_output=True, text=True,
                       encoding='utf-8', errors='replace', startupinfo=_no_console_startupinfo())
            for line in (s.stdout or '').splitlines():
                if 'Used Shadow Copy Storage' in line:
                    self.queue.put(f"PROGRESS:{label}:{line.strip()}")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")
