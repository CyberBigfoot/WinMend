"""WinMend features: explorer: operations."""

from __future__ import annotations

from pathlib import Path
from winmend.core.processes import _no_console_startupinfo, wm_run
from winmend.core.prompts import messagebox
from winmend.features.explorer.helpers import (
    EXPLORER_HISTORY_KEYS,
    EXPLORER_JUMP_LISTS,
    KNOWN_FOLDER_ALIASES,
    QUICK_ACCESS_APPID,
    delete_registry_tree,
    drive_kind,
    host_answers,
    jump_list_kind,
    jump_list_path,
    known_folder_path,
    mapped_drive_target,
    network_shortcuts,
    network_target_host,
    persistent_mapped_drives,
    quick_access_pins,
    read_jump_list,
    recent_items_dir,
    shell_extension_inventory,
    start_explorer,
    stop_explorer,
)
import os
import shutil
import time
import winreg


class ExplorerTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    # ---- File Explorer repair -------------------------------------------------

    _EXPLORER_PROBE_SECS = 5.0

    def _explorer_link_verdict(self, path, cache):
        """Where a Quick Access entry points and whether it still answers.

        Returns (status, detail): 'virtual' for known folders and ::{CLSID}
        items, 'local' for a folder on a local disk, 'missing' for a local
        folder or drive letter that is no longer there, and 'ok' / 'dead' for
        anything on the network. Network targets are tested with a bounded
        TCP probe -- never with Test-Path or os.path.isdir, which on a dead
        server hang for as long as Explorer itself does.
        """
        kind = jump_list_kind(path)
        if kind in ("knownfolder", "shell", "other"):
            return "virtual", ""
        if kind == "unc":
            host = network_target_host(path)
            if not host:
                return "virtual", ""
            if host_answers(host, timeout=self._EXPLORER_PROBE_SECS, cache=cache):
                return "ok", f"{host} answers"
            return "dead", f"{host} does not answer"
        # A lettered path.
        volume = drive_kind(path)
        if volume == "network":
            target = mapped_drive_target(path[:2])
            host = network_target_host(target)
            if not host:
                return "dead", f"drive {path[:2]} is a network mapping whose target could not be read"
            if host_answers(host, timeout=self._EXPLORER_PROBE_SECS, cache=cache):
                return "ok", f"drive {path[:2]} -> {host} answers"
            return "dead", f"drive {path[:2]} -> {host} does not answer"
        if volume in ("absent", "unknown"):
            return "missing", f"drive {path[:2]} is not connected"
        if os.path.isdir(path):
            return "local", ""
        return "missing", "folder no longer exists"

    @staticmethod
    def _quick_access_pin_target(path):
        """What to hand Shell.Application.NameSpace() to pin an old entry back:
        a real path for known folders (via SHGetKnownFolderPath, with the
        virtual 'This PC\\Desktop' mapped to the Desktop folder), the ::{CLSID}
        itself for virtual items, and the path as written for everything else.
        "" when it cannot be resolved."""
        kind = jump_list_kind(path)
        if kind == "knownfolder":
            guid = path.split(":", 1)[1].strip().upper()
            guid = KNOWN_FOLDER_ALIASES.get(guid, guid)
            folder = known_folder_path(guid)
            return folder if folder and os.path.isdir(folder) else ""
        if kind == "shell":
            return path
        if kind == "other":
            return ""
        return path

    @staticmethod
    def _wait_for_quick_access(read_pins, timeout=20.0, interval=1.0, stable_reads=2,
                               sleep=time.sleep, cancelled=lambda: False, clock=time.monotonic):
        """Wait for Explorer to finish writing its fresh Quick Access list.

        After a restart Explorer creates the list and writes its default pins
        into it asynchronously -- two to five seconds in on the PC this was
        built on, and the timing varies from one start to the next. `read_pins`
        returns None while the list is not there or not readable yet, and the
        pin list once it is. Returns that list once `stable_reads` consecutive
        readings an `interval` apart agree, or None at the deadline.

        Pinning against a snapshot taken before Windows has written its
        defaults races them, and because the pin verb is a toggle the race
        ends with a default folder UNPINNED. Both of the first real runs lost
        a pin that way; this wait is what stops it.
        """
        deadline = clock() + timeout
        previous = None
        agreed = 0
        while not cancelled():
            current = read_pins()
            if current is not None and current == previous:
                agreed += 1
                if agreed >= stable_reads:
                    return current
            else:
                agreed = 0
            previous = current
            if clock() >= deadline:
                return None
            sleep(interval)
        return None

    @staticmethod
    def _read_pins_settled(read_pins, sleep, attempts):
        for _ in range(attempts):
            pins = read_pins()
            if pins is not None:
                return pins
            sleep(0.5)
        return None

    @classmethod
    def _pin_and_confirm(cls, path, target, before, read_pins, pin, sleep, attempts):
        """Invoke the verb once and read back until the pin shows. The shell
        may record the pin under another spelling (a known-folder id for a
        path), so exactly one new entry with the count up by one also counts.
        Returns ("", spelling_it_landed_under) when confirmed, else
        (reason, "")."""
        try:
            problem = pin(target)
        except Exception as exc:
            problem = f"pin failed: {exc}"
        if problem:
            return problem, ""
        known = {b.lower() for b in before}
        for _ in range(attempts):
            sleep(0.5)
            after = read_pins()
            if after is None:
                continue
            if any(c.lower() == path.lower() for c in after):
                return "", path
            new = [c for c in after if c.lower() not in known]
            if len(new) == 1 and len(after) == len(before) + 1:
                return "", new[0]
        return "could not be confirmed as pinned", ""

    @classmethod
    def _restore_quick_access_pins(cls, pins, read_pins, pin, cancelled=lambda: False,
                                   sleep=time.sleep, attempts=6):
        """Pin `pins` back in order, skipping any that are already present.

        `read_pins()` returns the pinned paths as Quick Access holds them right
        now -- or None when the list could not be read; `pin(target)` invokes
        the shell verb and returns "" or a reason. Returns (restored, dropped),
        each a list of (path, note).

        The re-read before every single pin is the point of this function:
        the shell's `pintohome` verb is a toggle, and invoking it on a folder
        that is already pinned -- because Windows put its defaults back, or
        because an earlier attempt landed late -- UNPINS it. Reading once up
        front and pinning from a stale list would silently remove folders, and
        so would treating a failed read as an empty list: an unreadable list is
        unknown, and nothing is pinned blind against it.

        A second pass at the end re-reads the finished list and gives any pin
        that is still missing exactly one more attempt. That is the repair for
        the race the read cannot see -- Windows writing a default pin between
        the read and the verb, so the verb unpins it -- and it is safe against
        the opposite mistake because by then every earlier pin has had the
        whole of the first pass to land.
        """
        restored, dropped = [], []
        targets = {}
        spellings = {}   # path -> {spellings it is known to be recorded under}

        def _present(path, current):
            wanted = spellings.get(path, {path.lower()})
            return any(c.lower() in wanted for c in current)

        for path in pins:
            if cancelled():
                break
            target = cls._quick_access_pin_target(path)
            if not target:
                dropped.append((path, "could not be resolved to a folder"))
                continue
            targets[path] = target
            spellings[path] = {path.lower()}
            before = cls._read_pins_settled(read_pins, sleep, attempts)
            if before is None:
                dropped.append((path, "Quick Access could not be read, so it was not pinned "
                                      "blind (pinning a folder that is already there unpins it)"))
                continue
            if _present(path, before):
                restored.append((path, "already back"))
                continue
            problem, landed_as = cls._pin_and_confirm(
                path, target, before, read_pins, pin, sleep, attempts)
            if landed_as:
                spellings[path].add(landed_as.lower())
            (dropped if problem else restored).append((path, problem or "pinned"))

        # Second pass: what is actually pinned now that everything has landed?
        if targets and not cancelled():
            final = cls._read_pins_settled(read_pins, sleep, attempts)
            if final is not None:
                retry = [path for path in pins if path in targets and not _present(path, final)]
                for path in retry:
                    if cancelled():
                        break
                    before = cls._read_pins_settled(read_pins, sleep, attempts)
                    if before is None or _present(path, before):
                        continue
                    problem, landed_as = cls._pin_and_confirm(
                        path, targets[path], before, read_pins, pin, sleep, attempts)
                    if landed_as:
                        spellings[path].add(landed_as.lower())
                    restored = [(p, n) for p, n in restored if p != path]
                    dropped = [(p, n) for p, n in dropped if p != path]
                    (dropped if problem else restored).append(
                        (path, problem or "pinned on the second pass"))
        return restored, dropped

    @staticmethod
    def _export_hkcu_key(subkey, dest):
        """Write an HKCU key to a .reg file the user can double-click to put
        it back. True if the file was written; False when the key does not
        exist (nothing to save) or reg.exe refused."""
        try:
            winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey).Close()
        except OSError:
            return False
        try:
            r = wm_run(["reg", "export", "HKCU\\" + subkey, str(dest), "/y"],
                       capture_output=True, text=True, startupinfo=_no_console_startupinfo())
            return r.returncode == 0 and os.path.isfile(dest)
        except Exception:
            return False

    def run_explorer_repair(self):
        """Reset Quick Access and clear the dead network links Explorer waits on.

        Quick Access is a jump list -- an OLE compound file under
        %APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations. Two things
        make it the usual reason File Explorer opens slowly: the file corrupts,
        and Explorer then sits at "Working on it..." whenever the list is drawn;
        or it fills with folders on servers, NAS boxes and mapped drives that no
        longer answer, each of which Explorer waits on before it draws anything.

        The order below is deliberate:

        1. Read the list through Structured Storage -- never by enumerating the
           Quick Access namespace, which is the very thing that stalls -- and
           note which pins still point somewhere that answers.
        2. Find mapped drives (HKCU\\Network) and network locations whose server
           does not answer within five seconds, and ask before removing any: a
           NAS that is merely switched off is not a fault.
        3. Copy everything that is about to go to a backup folder.
        4. Stop Explorer FIRST, then delete, so Explorer cannot write its
           in-memory copy of the list back over the reset.
        5. Start Explorer, let it rebuild the list, and pin the old pins back one
           at a time. `pintohome` is a TOGGLE -- invoking it on a folder that is
           already pinned unpins it -- so the fresh list is re-read before every
           pin and nothing already present is touched.
        6. Read the result back and report from that reading, never from the
           intent.
        """
        label = "File Explorer Repair"
        if not messagebox.askyesno(
            "Repair File Explorer",
            "This resets Quick Access and clears the dead links File Explorer waits on:\n\n"
            "  - Quick Access's pinned/frequent folder list and recent-files list are\n"
            "    rebuilt. Your pinned folders are put back, except any that point at a\n"
            "    folder, server, or drive that no longer answers.\n"
            "  - Recent Items shortcuts and Explorer's address-bar, search-box and\n"
            "    recent-documents history are cleared.\n"
            "  - Mapped network drives and network locations whose server does not\n"
            "    answer are listed. You are asked before any of them is removed.\n"
            "  - Third-party context-menu and icon-overlay extensions are listed, not\n"
            "    changed.\n\n"
            "Everything removed is copied to a backup folder first, and Explorer\n"
            "restarts (the desktop and taskbar blink; open windows stay open).\n\n"
            "Continue?"
        ):
            self._report_skip(f"PROGRESS:{label}:Cancelled by user.")
            return

        probe_cache = {}
        recent = recent_items_dir()
        quick_access = jump_list_path(QUICK_ACCESS_APPID)

        # ---- 1. Quick Access as it stands -------------------------------------
        self.queue.put(f"PROGRESS:{label}:Reading Quick Access straight from the jump list "
                       f"(not through Explorer, which is what hangs)...")
        old_pins = []
        verdicts = {}
        unreadable = []
        network_entries = 0
        for app_id, what in EXPLORER_JUMP_LISTS:
            path = jump_list_path(app_id)
            if not path.exists():
                continue
            try:
                size_kb = path.stat().st_size / 1024
            except OSError:
                size_kb = 0
            entries = read_jump_list(path)
            if entries is None:
                unreadable.append(what)
                self.queue.put(f"PROGRESS:{label}:{what}: {size_kb:.0f} KB and could not be read. "
                               f"That is what a corrupted list looks like; it will be rebuilt.")
                continue
            pinned = sum(1 for e in entries if e["pinned"])
            self.queue.put(f"PROGRESS:{label}:{what}: {len(entries)} entries "
                           f"({pinned} pinned), {size_kb:.0f} KB.")
            if app_id == QUICK_ACCESS_APPID:
                old_pins = quick_access_pins(entries)
            for e in entries:
                if e["path"] in verdicts:
                    continue
                status, detail = self._explorer_link_verdict(e["path"], probe_cache)
                verdicts[e["path"]] = (status, detail)
                if status in ("ok", "dead"):
                    network_entries += 1
                    self.queue.put(f"PROGRESS:{label}:  network entry {e['path']}: {detail}"
                                   + (" (pinned)" if e["pinned"] else ""))
                elif status == "missing" and e["pinned"]:
                    self.queue.put(f"PROGRESS:{label}:  pinned {e['path']}: {detail}")
        if not old_pins and not unreadable and not quick_access.exists():
            self.queue.put(f"PROGRESS:{label}:No Quick Access list exists yet; Explorer will "
                           f"create a fresh one.")
        dead_pins = [p for p in old_pins if verdicts.get(p, ("", ""))[0] in ("dead", "missing")]
        keep_pins = [p for p in old_pins if p not in dead_pins]
        if old_pins:
            self.queue.put(f"PROGRESS:{label}:{len(old_pins)} pinned folder(s) found; "
                           f"{len(keep_pins)} will be put back"
                           + (f", {len(dead_pins)} will not (no longer reachable)." if dead_pins else "."))

        # ---- 2. Mapped drives and network locations ---------------------------
        self.queue.put(f"PROGRESS:{label}:Checking mapped network drives and network locations "
                       f"(up to {self._EXPLORER_PROBE_SECS:.0f} s each)...")
        drives = persistent_mapped_drives()
        dead_drives = []
        for d in drives:
            ok = bool(d["host"]) and host_answers(d["host"], timeout=self._EXPLORER_PROBE_SECS,
                                                  cache=probe_cache)
            self.queue.put(f"PROGRESS:{label}:Mapped drive {d['letter']} -> {d['remote']}: "
                           f"{'answers' if ok else 'does not answer'}.")
            if not ok:
                dead_drives.append(d)
        shortcuts = network_shortcuts()
        dead_shortcuts = []
        for s in shortcuts:
            if not s["target"]:
                self.queue.put(f"PROGRESS:{label}:Network location '{s['name']}': its shortcut "
                               f"could not be read - left alone.")
                continue
            if not s["host"]:
                self.queue.put(f"PROGRESS:{label}:Network location '{s['name']}' -> {s['target']}: "
                               f"local target, not tested.")
                continue
            ok = host_answers(s["host"], timeout=self._EXPLORER_PROBE_SECS, port=s["port"],
                              cache=probe_cache)
            self.queue.put(f"PROGRESS:{label}:Network location '{s['name']}' -> {s['target']}: "
                           f"{'answers' if ok else 'does not answer'}.")
            if not ok:
                dead_shortcuts.append(s)
        if not drives and not shortcuts:
            self.queue.put(f"PROGRESS:{label}:No mapped network drives or network locations are "
                           f"set up for this account.")

        remove_dead = False
        if dead_drives or dead_shortcuts:
            lines = [f"  - Drive {d['letter']}  ->  {d['remote']}" for d in dead_drives]
            lines += [f"  - Network location '{s['name']}'  ->  {s['target']}" for s in dead_shortcuts]
            remove_dead = messagebox.askyesno(
                "Disconnected network links",
                f"These did not answer within {self._EXPLORER_PROBE_SECS:.0f} seconds. Explorer "
                "waits on each of them whenever it draws This PC:\n\n"
                + "\n".join(lines) + "\n\n"
                "Remove them?\n\n"
                "Choose No if the server is only switched off or you are away from that "
                "network. A mapped drive comes back with one 'net use' command, and the exact "
                "command is written to the log; network locations are moved to the backup "
                "folder. A removed drive letter is fully released at your next sign-in."
            )
            self.queue.put(f"PROGRESS:{label}:Disconnected links will be "
                           f"{'removed' if remove_dead else 'kept, as you chose'}.")

        # ---- 3. Backup ----------------------------------------------------------
        stamp = time.strftime("%Y%m%d_%H%M%S")
        backup = Path(os.environ.get("APPDATA", str(Path.home()))) / "WinMend" / "Backups" / f"FileExplorer_{stamp}"
        try:
            backup.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self.queue.put(f"PROGRESS:{label}:Could not create the backup folder {backup}: {exc}. "
                           f"Stopping here - nothing is removed without a backup.")
            return
        doomed = []
        for app_id, _what in EXPLORER_JUMP_LISTS:
            for kind in ("automatic", "custom"):
                p = jump_list_path(app_id, kind)
                if p.exists():
                    doomed.append(p)
        try:
            recent_links = sorted(p for p in recent.glob("*.lnk") if p.is_file())
        except OSError:
            recent_links = []
        backup_failures = []
        copied = 0
        for p in doomed + recent_links:
            try:
                dest = backup / "Recent" / p.relative_to(recent)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(p, dest)
                copied += 1
            except (OSError, ValueError) as exc:
                backup_failures.append(f"{p.name}: {exc}")
        exported = []
        for subkey, what in EXPLORER_HISTORY_KEYS:
            if self._export_hkcu_key(subkey, backup / (subkey.rsplit("\\", 1)[-1] + ".reg")):
                exported.append(what)
        if remove_dead:
            for d in dead_drives:
                if not self._export_hkcu_key(d["subkey"], backup / f"MappedDrive_{d['letter'][0]}.reg"):
                    backup_failures.append(f"mapped drive {d['letter']} registry entry")
        if backup_failures:
            for item in backup_failures:
                self.queue.put(f"PROGRESS:{label}:Backup could not copy {item}")
            self.queue.put(f"PROGRESS:{label}:Stopping before any change - nothing is removed "
                           f"without a backup. Backup folder: {backup}")
            return
        self.queue.put(f"PROGRESS:{label}:Backup written: {copied} file(s)"
                       + (f" and {len(exported)} registry key(s)" if exported else "")
                       + f" -> {backup}")

        # ---- 4. Stop Explorer, then reset ---------------------------------------
        self.queue.put(f"PROGRESS:{label}:Stopping Explorer (the desktop and taskbar go away for "
                       f"a moment)...")
        problem = stop_explorer()
        if problem:
            self.queue.put(f"PROGRESS:{label}:{problem} Stopping here; nothing has been removed.")
            return
        time.sleep(1.5)
        removed_files = 0
        cleared = []
        failures = []
        removed_drives = []
        removed_shortcuts = []
        try:
            for p in doomed + recent_links:
                try:
                    p.unlink()
                    removed_files += 1
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    failures.append(f"{p.name} could not be removed: {exc}")
            for subkey, what in EXPLORER_HISTORY_KEYS:
                if delete_registry_tree(winreg.HKEY_CURRENT_USER, subkey):
                    cleared.append(what)
                else:
                    failures.append(f"{what} could not be cleared")
            if remove_dead:
                for d in dead_drives:
                    if delete_registry_tree(winreg.HKEY_CURRENT_USER, d["subkey"]):
                        removed_drives.append(d)
                    else:
                        failures.append(f"mapped drive {d['letter']} could not be removed from HKCU\\Network")
                        continue
                    # Best effort: this session's drive table is not the
                    # desktop session's when WinMend is elevated, so the
                    # letter may only be released at the next sign-in.
                    try:
                        wm_run(["net", "use", d["letter"], "/delete", "/y"], capture_output=True,
                               startupinfo=_no_console_startupinfo())
                    except Exception:
                        pass
                for s in dead_shortcuts:
                    try:
                        dest = backup / "Network Shortcuts" / os.path.basename(s["path"])
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        shutil.move(s["path"], dest)
                        removed_shortcuts.append(s)
                    except OSError as exc:
                        failures.append(f"network location '{s['name']}' could not be moved: {exc}")
        finally:
            self.queue.put(f"PROGRESS:{label}:Starting Explorer...")
            problem = start_explorer()
            if problem:
                self.queue.put(f"PROGRESS:{label}:{problem} Press Ctrl+Shift+Esc, then "
                               f"File > Run new task > explorer.exe")

        # ---- 5. Put the pins back -----------------------------------------------
        restored, dropped = [], []
        if keep_pins:
            # Explorer writes its default pins lazily -- on the first
            # enumeration of the Quick Access namespace, and not before. Left
            # to chance that is anywhere from two seconds to never (measured:
            # nothing in 60 s on an idle desktop), and pinning before it
            # happens races it. So enumerate once, now, on purpose. It is safe
            # exactly here and only here: with no list on disk the only
            # entries the shell can produce are Windows' own local defaults.
            # Never against a list that is still there -- one that failed to
            # delete could still hold the dead network entry that hangs.
            if not quick_access.exists():
                time.sleep(2.0)
                self.queue.put(f"PROGRESS:{label}:Asking Explorer to write its fresh Quick "
                               f"Access list...")
                try:
                    import pythoncom
                    import win32com.client
                    pythoncom.CoInitialize()
                    home = win32com.client.Dispatch("Shell.Application").NameSpace(
                        "shell:::{679f85cb-0220-4080-b29b-5540cc05aab6}")
                    if home is not None:
                        home.Items().Count
                except Exception as exc:
                    self.queue.put(f"PROGRESS:{label}:Could not ask ({exc}); waiting for "
                                   f"Explorer to write it on its own.")
            self.queue.put(f"PROGRESS:{label}:Waiting for the fresh Quick Access list to settle "
                           f"before pinning your folders back...")

            def _current_pins():
                # None while the list is not there yet or could not be read
                # (Explorer is mid-write): "unknown", never "empty".
                if not quick_access.exists():
                    return None
                entries = read_jump_list(quick_access)
                return None if entries is None else quick_access_pins(entries)

            settled = self._wait_for_quick_access(_current_pins, cancelled=self.cancel_event.is_set)
            if settled is None and quick_access.exists():
                self.queue.put(f"PROGRESS:{label}:Explorer's fresh list never became readable, "
                               f"so nothing is pinned blind. Your old list is in the backup folder.")
                dropped = [(path, "Quick Access could not be read") for path in keep_pins]
            else:
                if settled is None:
                    # Explorer creates the list when Quick Access is first
                    # shown; with no list there is nothing to toggle, and once
                    # this run writes one Windows will not add its defaults.
                    self.queue.put(f"PROGRESS:{label}:Explorer has not written a fresh list "
                                   f"yet; pinning into an empty one.")

                    def _current_pins():
                        if not quick_access.exists():
                            return []
                        entries = read_jump_list(quick_access)
                        return None if entries is None else quick_access_pins(entries)
                else:
                    self.queue.put(f"PROGRESS:{label}:Explorer rebuilt the list with "
                                   f"{len(settled)} default pin(s).")
                shell = None
                try:
                    import pythoncom
                    import win32com.client
                    pythoncom.CoInitialize()
                    shell = win32com.client.Dispatch("Shell.Application")
                except Exception as exc:
                    self._report_failure(f"PROGRESS:{label}:Automatic re-pinning is unavailable in this "
                                         f"build ({exc}). Your old list is in the backup folder.")

                def _pin(target):
                    folder = shell.NameSpace(target)
                    if folder is None:
                        return "Explorer could not open it"
                    folder.Self.InvokeVerb("pintohome")
                    return ""

                if shell is None:
                    dropped = [(path, "re-pinning unavailable") for path in keep_pins]
                else:
                    restored, dropped = self._restore_quick_access_pins(
                        keep_pins, _current_pins, _pin, cancelled=self.cancel_event.is_set)
        for path in dead_pins:
            dropped.append((path, verdicts.get(path, ("", "not reachable"))[1]))

        # ---- 6. Read the result back --------------------------------------------
        after_entries = None
        for _ in range(4):
            after_entries = read_jump_list(quick_access) if quick_access.exists() else None
            if after_entries is not None or not quick_access.exists():
                break
            time.sleep(0.5)
        self.queue.put(f"PROGRESS:{label}:--- Result ---")
        self.queue.put(f"PROGRESS:{label}:Removed {removed_files} file(s) from Recent Items and "
                       f"the Explorer jump lists; cleared {', '.join(cleared) if cleared else 'no'} "
                       f"history.")
        if not quick_access.exists():
            self.queue.put(f"PROGRESS:{label}:Quick Access list: not written yet - Explorer "
                           f"creates it the first time Quick Access is shown. That is normal "
                           f"right after a reset.")
        elif after_entries is None:
            self.queue.put(f"PROGRESS:{label}:Quick Access list: exists but could not be read back "
                           f"just now (Explorer was still writing it), so its contents are not "
                           f"being reported.")
        else:
            pinned_now = sum(1 for e in after_entries if e["pinned"])
            on_network = sum(1 for e in after_entries
                             if self._explorer_link_verdict(e["path"], probe_cache)[0] in ("ok", "dead"))
            self.queue.put(f"PROGRESS:{label}:Quick Access now: {len(after_entries)} entries, "
                           f"{pinned_now} pinned, {on_network} on the network "
                           f"(was {network_entries}).")
        for path, note in restored:
            self.queue.put(f"PROGRESS:{label}:  kept pin: {self._describe_pin(path)} ({note})")
        for path, note in dropped:
            self.queue.put(f"PROGRESS:{label}:  NOT put back: {self._describe_pin(path)} - {note}")
        if dropped:
            self.queue.put(f"PROGRESS:{label}:To pin any of those again by hand: right-click "
                           f"the folder > Pin to Quick access. The old list is in the backup.")
        for d in removed_drives:
            self.queue.put(f"PROGRESS:{label}:Removed mapped drive {d['letter']} ({d['remote']}). "
                           f"To map it again:  net use {d['letter']} \"{d['remote']}\" /persistent:yes")
        for s in removed_shortcuts:
            self.queue.put(f"PROGRESS:{label}:Moved network location '{s['name']}' "
                           f"({s['target']}) to the backup folder.")
        for item in failures:
            self.queue.put(f"PROGRESS:{label}:WARNING - {item}")
        self.queue.put(f"PROGRESS:{label}:Backup folder: {backup}  (double-click a .reg file "
                       f"to restore that history; copy the Recent files back with Explorer "
                       f"closed to restore the old lists)")

        # ---- 7. What else slows Explorer: settings and shell extensions ----------
        self._report_explorer_environment(label)

        if removed_drives:
            letters = ", ".join(d["letter"] for d in removed_drives)
            self.queue.put(
                f"REBOOTRECOMMEND:{label}:File Explorer Repair — mapped drive(s) {letters} "
                f"removed. Windows only releases a drive letter from the current sign-in "
                f"session at sign-out or restart; until then This PC may still show it."
            )

    @staticmethod
    def _describe_pin(path):
        kind = jump_list_kind(path)
        if kind == "knownfolder":
            guid = path.split(":", 1)[1].strip().upper()
            folder = known_folder_path(KNOWN_FOLDER_ALIASES.get(guid, guid))
            return folder or path
        if kind == "shell":
            names = {"::{645FF040-5081-101B-9F08-00AA002F954E}": "Recycle Bin",
                     "::{20D04FE0-3AEA-1069-A2D8-08002B30309D}": "This PC",
                     "::{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}": "Network"}
            return names.get(path.upper(), path)
        return path

    def _report_explorer_environment(self, label):
        """The settings and extensions that decide how fast Explorer opens,
        reported as measurements. Nothing here is changed."""
        adv = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        base = r"Software\Microsoft\Windows\CurrentVersion\Explorer"

        def _dword(subkey, name):
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey) as key:
                    value, kind = winreg.QueryValueEx(key, name)
                return int(value) if kind == winreg.REG_DWORD else None
            except (OSError, ValueError, TypeError):
                return None

        launch = _dword(adv, "LaunchTo")
        opens_to = {1: "This PC", 2: "Quick Access / Home", 3: "Downloads"}.get(launch)
        if opens_to is None:
            opens_to = "Quick Access / Home (the Windows default)" if launch is None else f"value {launch}"
        show_recent = _dword(base, "ShowRecent")
        show_frequent = _dword(base, "ShowFrequent")
        self.queue.put(f"PROGRESS:{label}:--- Explorer settings (not changed) ---")
        self.queue.put(f"PROGRESS:{label}:File Explorer opens to: {opens_to}. Recent files in "
                       f"Quick Access: {'off' if show_recent == 0 else 'on'}; frequent folders: "
                       f"{'off' if show_frequent == 0 else 'on'}.")
        if launch in (None, 2):
            self.queue.put(f"PROGRESS:{label}:If Explorer is still slow to open, the single most "
                           f"effective setting is opening it to This PC instead: Windows Settings "
                           f"page > 'Home and Gallery in Explorer' > off. Frequent folders and "
                           f"recent files can be turned off in Folder Options > Privacy.")

        inventory = shell_extension_inventory()
        if not inventory.get("available"):
            return
        handlers = inventory["handlers"]
        packaged = [h for h in handlers if h["packaged"]]
        third_party = [h for h in handlers
                       if not h["microsoft"] and not h["packaged"] and not h["blocked"]]
        broken = [h for h in handlers if (h["dll_missing"] or h["unregistered"]) and not h["blocked"]]
        self.queue.put(f"PROGRESS:{label}:--- Shell extensions (not changed) ---")
        self.queue.put(f"PROGRESS:{label}:{len(handlers)} context-menu handler(s) load into Explorer; "
                       f"{len(third_party)} from outside Microsoft"
                       + (f", {len(packaged)} from packaged Store apps (publisher not readable)."
                          if packaged else "."))
        for h in third_party:
            who = h["company"] or "(publisher unknown)"
            self.queue.put(f"PROGRESS:{label}:  {h['name']} - {who} - {h['dll'] or 'no DLL registered'} "
                           f"[{', '.join(h['where'])}]")
        for h in broken:
            self.queue.put(f"PROGRESS:{label}:  BROKEN: {h['name']} ({h['clsid']}) points at "
                           f"{h['dll'] or 'no DLL at all'} - Explorer tries to load it on every "
                           f"right-click. Reinstalling or uninstalling the program that owned it "
                           f"clears this.")
        if third_party and not broken:
            self.queue.put(f"PROGRESS:{label}:Each third-party handler runs inside Explorer on every "
                           f"right-click and folder draw. If Explorer is slow only when right-clicking, "
                           f"one of these is the usual cause; disable it in the program's own "
                           f"settings or with ShellExView, or uninstall the program.")
        overlays = inventory["overlays"]
        limit = inventory["overlay_limit"]
        if overlays:
            names = ", ".join(o["name"].strip() for o in overlays[:limit])
            extra = len(overlays) - limit
            self.queue.put(f"PROGRESS:{label}:{len(overlays)} icon-overlay handler(s) registered "
                           f"(Windows loads the first {limit}): {names}"
                           + (f"; {extra} more never load." if extra > 0 else "."))
        self.queue.put(f"PROGRESS:{label}:Still slow? Rebuild Icon & Thumbnail Cache (Cleanup), "
                       f"Reset Windows Search Index and Repair System (SFC/DISM) (Repair & Recovery), "
                       f"and Schedule Check Disk if folders on one drive are slow.")
