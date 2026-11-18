"""WinMend features: office: operations."""

from __future__ import annotations

from pathlib import Path
from winmend.core.processes import _no_console_startupinfo, launch_visible, wm_run
from winmend.core.prompts import messagebox
from winmend.core.windows import visible_windows
from winmend.features.cleanup_helpers import format_elapsed, processes_named
from winmend.features.explorer.helpers import delete_registry_tree
from winmend.features.office.helpers import (
    CLICKTORUN_SERVICE,
    NEW_OUTLOOK_STORE_ID,
    OFFICE_BACKGROUND_OK,
    OFFICE_COMMON_KEY,
    OFFICE_IDENTITY_KEYS,
    OFFICE_LICENSE_FOLDERS,
    OFFICE_PROCESS_NAMES,
    build_office_repair_options,
    data_file_verdict,
    default_mail_client,
    office_addins,
    office_auth_findings,
    office_c2r_repair_command,
    office_c2r_update_command,
    office_crash_events,
    office_credential_targets,
    office_hardware_acceleration_disabled,
    office_installation,
    office_subscription_accounts,
    outlook_data_files,
    outlook_minimizes_to_tray,
    outlook_profiles,
    outlook_size_limit_mb,
    outlook_store_paths,
    parse_cmdkey_list,
    parse_ospp_status,
    service_state,
    summarize_office_crashes,
    windowless_processes,
)
import os
import shutil
import subprocess
import time
import winreg


class OfficeTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    # ------------------------------------------------------------------
    # Office & Outlook repair
    # ------------------------------------------------------------------


    _OFFICE_REPAIR_ORDER = ("end:", "service:clicktorun", "service:sppsvc", "auth:", "addin:",
                            "graphics:off", "identity:reset", "outlook:rebuild_ost", "repair:",
                            "update:office", "outlook:navpane", "service:wsearch", "install:new_outlook")

    def _office_ospp_script(self, installation):
        """OSPP.VBS for this install, or "". Click-to-Run keeps it under root\\Office16;
        an MSI Office under Office16/15/14."""
        roots = []
        if installation.get("c2r"):
            roots.append(installation["c2r"]["path"])
        roots.extend(installation.get("msi_roots") or [])
        for pf in (os.environ.get("ProgramFiles", r"C:\Program Files"),
                   os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")):
            roots.append(os.path.join(pf, "Microsoft Office"))
        for root in roots:
            for sub in (r"root\Office16", "Office16", "Office15", "Office14"):
                candidate = os.path.join(root, sub, "OSPP.VBS")
                if os.path.isfile(candidate):
                    return candidate
        return ""

    def _office_running(self):
        """[(pid, friendly)] of Office apps currently running, windowed or not."""
        found = []
        for proc in processes_named(list(OFFICE_PROCESS_NAMES)):
            try:
                name = (proc.name() or "").lower()
                if name in OFFICE_BACKGROUND_OK:
                    continue
                found.append((proc.pid, OFFICE_PROCESS_NAMES.get(name, name)))
            except Exception:
                continue
        return found

    def _office_close_apps(self, label, why):
        """Ask before closing open Office apps; True once none are running."""
        running = self._office_running()
        if not running:
            return True
        names = sorted({friendly for _pid, friendly in running})
        if not messagebox.askyesno(
                "Close Office apps",
                f"{', '.join(names)} must be closed to {why}.\n\nSave your work first.\n\n"
                f"Close them now? (No skips this repair.)"):
            self.queue.put(f"PROGRESS:{label}:  Skipped — {', '.join(names)} left open.")
            return False
        import psutil
        for pid, friendly in running:
            try:
                psutil.Process(pid).terminate()
            except Exception:
                pass
        deadline = time.time() + 15
        while time.time() < deadline and self._office_running():
            time.sleep(1)
        for pid, friendly in self._office_running():
            try:
                psutil.Process(pid).kill()
            except Exception:
                pass
        time.sleep(1)
        still = self._office_running()
        if still:
            self.queue.put(f"PROGRESS:{label}:  Could not close: "
                           f"{', '.join(f'{f} (PID {p})' for p, f in still)}.")
            return False
        self.queue.put(f"PROGRESS:{label}:  Closed {', '.join(names)}.")
        return True

    def _office_set_service(self, label, name, start_arg, friendly):
        """Set a service's start type (sc.exe wording) and start it; report the
        readback. start_arg: 'auto' or 'delayed-auto'."""
        before = service_state(name)
        r = wm_run(["sc", "config", name, "start=", start_arg], capture_output=True, text=True,
                   encoding="utf-8", errors="replace", startupinfo=_no_console_startupinfo())
        if r.returncode != 0:
            self.queue.put(f"PROGRESS:{label}:  {friendly}: could not change the start type — "
                           f"{(r.stdout or r.stderr or '').strip()[:160]}")
        wm_run(["sc", "start", name], capture_output=True, text=True, encoding="utf-8",
               errors="replace", startupinfo=_no_console_startupinfo())
        deadline = time.time() + 30
        after = service_state(name)
        while time.time() < deadline and after and after["status"] not in ("running",):
            time.sleep(1)
            after = service_state(name)
        self.queue.put(f"PROGRESS:{label}:  {friendly}: was {before['status']} / {before['start']}"
                       f" → now {after['status']} / {after['start']}." if before and after else
                       f"PROGRESS:{label}:  {friendly}: state could not be read back.")
        if before:
            undo = {"automatic": "auto", "manual": "demand", "disabled": "disabled"}.get(before["start"], "demand")
            self.queue.put(f"PROGRESS:{label}:    Undo: sc config {name} start= {undo}")
        return bool(after and after["status"] == "running")

    def _office_delete_value(self, label, hive_name, key, value):
        hive = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}[hive_name]
        try:
            with winreg.OpenKey(hive, key, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as k:
                old, kind = winreg.QueryValueEx(k, value)
                winreg.DeleteValue(k, value)
        except FileNotFoundError:
            self.queue.put(f"PROGRESS:{label}:  {value} was already absent.")
            return True
        except OSError as exc:
            self.queue.put(f"PROGRESS:{label}:  Could not remove {value}: {exc}")
            return False
        self.queue.put(f"PROGRESS:{label}:  Removed {hive_name}\\{key}\\{value} (was {old}).")
        self.queue.put(f"PROGRESS:{label}:    Undo: reg add \"{hive_name}\\{key}\" /v {value} /t REG_DWORD /d {old} /f")
        return True

    def _office_set_dword(self, label, hive_name, key, value, new):
        hive = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}[hive_name]
        try:
            with winreg.CreateKeyEx(hive, key, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as k:
                try:
                    old = winreg.QueryValueEx(k, value)[0]
                except FileNotFoundError:
                    old = None
                winreg.SetValueEx(k, value, 0, winreg.REG_DWORD, int(new))
        except OSError as exc:
            self.queue.put(f"PROGRESS:{label}:  Could not set {value}: {exc}")
            return False
        self.queue.put(f"PROGRESS:{label}:  {hive_name}\\{key}\\{value} = {new} (was "
                       f"{'not set' if old is None else old}).")
        if old is None:
            self.queue.put(f"PROGRESS:{label}:    Undo: reg delete \"{hive_name}\\{key}\" /v {value} /f")
        else:
            self.queue.put(f"PROGRESS:{label}:    Undo: reg add \"{hive_name}\\{key}\" /v {value} /t REG_DWORD /d {old} /f")
        return True

    def _office_identity_reset(self, label, installation, ospp_products, ospp_script):
        """Microsoft's 'reset Office activation state' procedure, with backups."""
        if not self._office_close_apps(label, "reset the sign-in and licence cache"):
            return False
        stamp = time.strftime("%Y%m%d_%H%M%S")
        backup = Path(os.environ.get("APPDATA", str(Path.home()))) / "WinMend" / "Backups" / f"Office_{stamp}"
        try:
            backup.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self.queue.put(f"PROGRESS:{label}:  Could not create the backup folder {backup}: {exc}. "
                           f"Nothing was removed.")
            return False
        for subkey in OFFICE_IDENTITY_KEYS:
            dest = backup / (subkey.rsplit("\\", 1)[-1] + ".reg")
            if self._export_hkcu_key(subkey, dest):
                self.queue.put(f"PROGRESS:{label}:  Backed up HKCU\\{subkey} → {dest.name}")
            else:
                self.queue.put(f"PROGRESS:{label}:  HKCU\\{subkey}: nothing to back up.")
        for product in ospp_products:
            tail = product.get("key_tail")
            if tail and ospp_script:
                r = wm_run(["cscript", "//nologo", ospp_script, f"/unpkey:{tail}"], capture_output=True,
                           text=True, encoding="utf-8", errors="replace", startupinfo=_no_console_startupinfo())
                note = " ".join((r.stdout or "").split())[-120:]
                self.queue.put(f"PROGRESS:{label}:  Removed product key ending {tail} ({product['name']}): {note}")
        for subkey in OFFICE_IDENTITY_KEYS:
            gone = delete_registry_tree(winreg.HKEY_CURRENT_USER, subkey)
            self.queue.put(f"PROGRESS:{label}:  HKCU\\{subkey}: {'removed' if gone else 'could not be fully removed'}.")
        local = os.environ.get("LOCALAPPDATA", "")
        for rel in OFFICE_LICENSE_FOLDERS:
            src = os.path.join(local, rel)
            if not os.path.isdir(src):
                continue
            dest = backup / rel.replace("\\", "_")
            try:
                shutil.move(src, str(dest))
                self.queue.put(f"PROGRESS:{label}:  Moved {src} → backup.")
            except OSError as exc:
                self.queue.put(f"PROGRESS:{label}:  {src}: in use, left in place ({exc.strerror or exc}). "
                               f"Close Teams/OneDrive and run again if sign-in still fails.")
        r = wm_run(["cmdkey", "/list"], capture_output=True, text=True, encoding="utf-8",
                   errors="replace", startupinfo=_no_console_startupinfo())
        targets = office_credential_targets(parse_cmdkey_list(r.stdout or ""))
        for target in targets:
            wm_run(["cmdkey", f"/delete:{target}"], capture_output=True, startupinfo=_no_console_startupinfo())
        self.queue.put(f"PROGRESS:{label}:  Removed {len(targets)} Office credential entr"
                       f"{'y' if len(targets) == 1 else 'ies'} from Credential Manager.")
        self.queue.put(f"PROGRESS:{label}:  Done. Open any Office app and sign in with "
                       f"{', '.join(office_subscription_accounts()) or 'your Microsoft 365 account'}. "
                       f"Registry backups: {backup}")
        return True

    def _office_rebuild_ost(self, label, files):
        if not self._office_close_apps(label, "rebuild the offline cache"):
            return False
        stamp = time.strftime("%Y%m%d_%H%M%S")
        renamed = 0
        for f in files:
            if f["kind"] not in ("ost", "nst"):
                continue
            src = f["path"]
            dest = f"{src}.winmend-{stamp}.bak"
            try:
                os.rename(src, dest)
                renamed += 1
                self.queue.put(f"PROGRESS:{label}:  Renamed {os.path.basename(src)} → {os.path.basename(dest)} "
                               f"({f['bytes'] / 1024 ** 3:.1f} GB).")
                self.queue.put(f"PROGRESS:{label}:    Undo (with Outlook closed): ren \"{dest}\" \"{os.path.basename(src)}\"")
            except OSError as exc:
                self.queue.put(f"PROGRESS:{label}:  Could not rename {os.path.basename(src)}: {exc.strerror or exc}")
        if renamed:
            self.queue.put(f"PROGRESS:{label}:  Outlook will rebuild the cache from the server on next start; "
                           f"the first start takes longer. Delete the .bak files once mail is back.")
        return renamed > 0

    def _office_c2r_repair(self, label, installation, kind):
        c2r = installation["c2r"]
        argv = office_c2r_repair_command(c2r["repair_exe"], kind, c2r["platform"], c2r["culture"])
        self.queue.put(f"PROGRESS:{label}:  Starting Office {'Quick' if kind == 'quick' else 'Online'} Repair. "
                       f"Office's own progress window opens; open Office apps are closed by it.")
        started = time.time()
        r = wm_run(argv, cancel_event=self.cancel_event, capture_output=True,
                   on_stall=lambda s: self.queue.put(
                       f"PROGRESS:{label}:  Still repairing after {format_elapsed(s)} — Office's window "
                       f"shows progress; nothing is cut off."),
                   visible=True)
        if r.cancelled:
            self.queue.put(f"PROGRESS:{label}:  Repair cancelled.")
            return False
        # The launcher can hand the work to the Click-to-Run service and exit;
        # while Office's repair window is on screen the repair is still running.
        last_note = time.time()
        while not self.cancel_event.is_set():
            ui = [w for w in visible_windows([p.pid for p in processes_named(("officeclicktorun.exe",))])
                  if w[3]]
            if not ui:
                break
            if time.time() - last_note >= 60:
                last_note = time.time()
                self.queue.put(f"PROGRESS:{label}:  Office repair still running "
                               f"({format_elapsed(time.time() - started)}): \"{ui[0][3]}\"")
            time.sleep(3)
        after = office_installation()
        missing = [name for name, _p in after.get("missing", [])]
        self.queue.put(f"PROGRESS:{label}:  Repair finished in {format_elapsed(time.time() - started)} "
                       f"(exit code {r.returncode}). {len(after['apps'])} Office program(s) present"
                       + (f"; still missing: {', '.join(missing)}." if missing else "."))
        return r.returncode == 0 and not missing

    def run_office_repair(self):
        """Find what stands between Outlook/Office and working, then offer the repairs
        the measurements support.

        Everything up to the checklist is read-only: the installation (Click-to-Run,
        MSI, new Outlook), the services Office depends on, Office processes stuck
        without a window, licence state, the Outlook profile and its data files
        against the size ceiling, COM add-ins, sign-in registry overrides, and two
        weeks of crash/hang events with each crash attributed to the module it landed
        in -- an add-in's folder, a display driver, Office's own files, or Windows.
        The checklist ticks only repairs a measurement points at; the rest are
        offered unticked with their cost stated. Reversible steps log their undo.
        """
        label = "Office Repair"
        self.queue.put(f"PROGRESS:{label}:Checking the Office installation...")
        inst = office_installation()
        c2r = inst["c2r"]
        if not (c2r or inst["apps"] or inst["msi_roots"] or inst["new_outlook"]):
            self.queue.put(f"PROGRESS:{label}:No Microsoft Office or Outlook installation was found on this PC, "
                           f"so there is nothing to repair. Microsoft 365 can be installed from the Install "
                           f"Apps page and the new Outlook from the Microsoft Store.")
            return
        if c2r:
            self.queue.put(f"PROGRESS:{label}:Microsoft 365 / Office (Click-to-Run) {c2r['version']} "
                           f"{c2r['platform']} {c2r['culture']} — {', '.join(c2r['products']) or 'unknown product'} "
                           f"at {c2r['path']}.")
            if not c2r["repair_exe"]:
                self.queue.put(f"PROGRESS:{label}:  OfficeClickToRun.exe is missing from Common Files — the "
                               f"Office repair tool itself is gone. Reinstall Office from office.com.")
        for root in inst["msi_roots"]:
            self.queue.put(f"PROGRESS:{label}:Office (MSI install) at {root}.")
        if inst["apps"]:
            self.queue.put(f"PROGRESS:{label}:Programs present: {', '.join(sorted(inst['apps']))}.")
        for name, path in inst["missing"]:
            self.queue.put(f"PROGRESS:{label}:  {name} is registered at {path} but the file is missing — "
                           f"a damaged install.")
        self.queue.put(f"PROGRESS:{label}:New Outlook (Store app): "
                       f"{('version ' + inst['new_outlook']) if inst['new_outlook'] else 'not installed'}.")

        # ---- services --------------------------------------------------------
        clicktorun = service_state(CLICKTORUN_SERVICE) if c2r else None
        if c2r:
            if clicktorun is None:
                self.queue.put(f"PROGRESS:{label}:Click-to-Run service: NOT REGISTERED — Office cannot start "
                               f"without it; Quick Repair re-registers it.")
            else:
                ok = clicktorun["status"] == "running" and clicktorun["start"] == "automatic"
                self.queue.put(f"PROGRESS:{label}:Click-to-Run service: {clicktorun['status']} / "
                               f"{clicktorun['start']}{'' if ok else ' — Office apps need it running'}.")
        sppsvc = service_state("sppsvc")
        if sppsvc:
            self.queue.put(f"PROGRESS:{label}:Software Protection (licensing): {sppsvc['status']} / "
                           f"{sppsvc['start']}{' — DISABLED breaks activation' if sppsvc['start'] == 'disabled' else ''}.")
        wsearch = service_state("WSearch")
        if wsearch and "Outlook" in inst["apps"]:
            self.queue.put(f"PROGRESS:{label}:Windows Search (Outlook search): {wsearch['status']} / "
                           f"{wsearch['start']}"
                           + (" — Outlook search shows 'results may be incomplete'."
                              if wsearch["status"] != "running" else "."))

        # ---- stuck processes -----------------------------------------------
        stuck = windowless_processes(list(OFFICE_PROCESS_NAMES), min_age=60)
        if stuck and outlook_minimizes_to_tray():
            kept = [p for p in stuck if p["friendly"] != "Outlook"]
            if len(kept) != len(stuck):
                self.queue.put(f"PROGRESS:{label}:Outlook is running without a window, but it is set to hide "
                               f"in the tray when minimised, so that is by design.")
            stuck = kept
        for p in stuck:
            self.queue.put(f"PROGRESS:{label}:{p['friendly']} (PID {p['pid']}) has run for "
                           f"{format_elapsed(p['age'])} with no window — a leftover instance like this is "
                           f"the usual reason it 'will not open'.")
        if not stuck:
            self.queue.put(f"PROGRESS:{label}:No Office process is stuck in the background.")

        # ---- licensing -------------------------------------------------------
        ospp_products, ospp_script = [], self._office_ospp_script(inst)
        if ospp_script:
            try:
                r = wm_run(["cscript", "//nologo", ospp_script, "/dstatus"], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", startupinfo=_no_console_startupinfo())
                ospp_products = parse_ospp_status(r.stdout or "")
            except Exception as exc:
                self.queue.put(f"PROGRESS:{label}:Licence check could not run: {exc}")
        accounts = office_subscription_accounts()
        if ospp_products:
            for p in ospp_products:
                bad = p["status"].upper() != "LICENSED"
                self.queue.put(f"PROGRESS:{label}:Licence: {p['name']} — {p['status'] or 'unknown'}"
                               + (f" ({p['error']})" if p["error"] else "")
                               + (f", grace {p['grace']}" if p["grace"] else "")
                               + (" — NOT licensed; Office turns read-only." if bad else "."))
        elif accounts:
            self.queue.put(f"PROGRESS:{label}:Licence: Microsoft 365 subscription tied to "
                           f"{', '.join(accounts)} (no product key — normal for a subscription).")
        elif c2r:
            self.queue.put(f"PROGRESS:{label}:Licence: no product key and no signed-in subscription account "
                           f"recorded — if Office says 'Unlicensed Product', sign in or reset the sign-in cache.")

        # ---- Outlook -------------------------------------------------------
        profiles = outlook_profiles()
        data_files = []
        addins = []
        if "Outlook" in inst["apps"]:
            if profiles["profiles"]:
                self.queue.put(f"PROGRESS:{label}:Outlook profile(s): {', '.join(profiles['profiles'])}"
                               f" (default: {profiles['default'] or 'none set'}).")
            else:
                self.queue.put(f"PROGRESS:{label}:Outlook has no mail profile yet; it runs account setup on "
                               f"first start.")
            limit = outlook_size_limit_mb()
            data_files = outlook_data_files(outlook_store_paths())
            for f in data_files:
                verdict, detail = data_file_verdict(f["bytes"], limit)
                f["verdict"] = verdict
                self.queue.put(f"PROGRESS:{label}:Data file {os.path.basename(f['path'])} ({f['kind'].upper()}): "
                               f"{detail}.")
            addins = office_addins()
            active = [a for a in addins if a["load_behavior"] == 3]
            if addins:
                self.queue.put(f"PROGRESS:{label}:{len(addins)} Outlook add-in registration(s); "
                               f"{len(active)} load at startup: "
                               f"{', '.join(sorted({a['name'] for a in active})) or 'none'}.")
        auth = office_auth_findings()
        for f in auth:
            self.queue.put(f"PROGRESS:{label}:Registry: {f['hive']}\\{f['key']}\\{f['value']} = {f['current']} — "
                           f"{f['harm']}.")
        hw_off = office_hardware_acceleration_disabled()
        if hw_off:
            self.queue.put(f"PROGRESS:{label}:Office hardware graphics acceleration is already turned off.")
        mail = default_mail_client()
        if "Outlook" in inst["apps"] and mail and "outlook" not in mail.lower():
            self.queue.put(f"PROGRESS:{label}:Default mail program is '{mail}', not Outlook — mailto: links "
                           f"and Send-to-mail open there. Change it under Settings > Apps > Default apps.")

        # ---- crash history ----------------------------------------------------
        self.queue.put(f"PROGRESS:{label}:Reading two weeks of application crash and hang events...")
        events = office_crash_events(14)
        office_root = c2r["path"] if c2r else (inst["msi_roots"][0] if inst["msi_roots"] else "")
        if events is None:
            self.queue.put(f"PROGRESS:{label}:The Application event log could not be read; crash history is "
                           f"unknown (not 'clean').")
            crashes = summarize_office_crashes([], addins, office_root)
        else:
            crashes = summarize_office_crashes(events, addins, office_root)
            if not events:
                self.queue.put(f"PROGRESS:{label}:No Office crash or hang events in the last 14 days.")
            else:
                apps = ", ".join(f"{app} ×{n}" for app, n in sorted(crashes["by_app"].items()))
                self.queue.put(f"PROGRESS:{label}:{crashes['total']} Office crash/hang event(s) in 14 days: {apps}.")
                for cat, n in sorted(crashes["by_category"].items()):
                    words = {"addin": "inside an add-in's own code", "gpu": "inside a display-driver module",
                             "office": "inside Office's own files", "windows": "inside Windows system files",
                             "other": "inside a third-party module (antivirus hooks are the usual owner)",
                             "hang": "hangs (no module recorded)", "unknown": "with no module recorded"}
                    self.queue.put(f"PROGRESS:{label}:  {n} {words.get(cat, cat)}.")
                for progid, entry in crashes["addins"].items():
                    self.queue.put(f"PROGRESS:{label}:  Add-in '{entry['addin']['name']}' owns the module in "
                                   f"{entry['count']} crash(es): {entry['addin']['path']}")
                top = sorted(crashes["modules"].items(), key=lambda kv: -kv[1])[:5]
                if top:
                    self.queue.put(f"PROGRESS:{label}:  Faulting modules: "
                                   f"{', '.join(f'{m} ×{n}' for m, n in top)}.")

        # ---- the checklist ---------------------------------------------------
        report = {"c2r": c2r, "apps": inst["apps"], "missing": inst["missing"],
                  "new_outlook": inst["new_outlook"], "clicktorun": clicktorun, "sppsvc": sppsvc,
                  "wsearch": wsearch, "stuck": stuck, "auth": auth, "crashes": crashes,
                  "profiles": profiles, "data_files": data_files, "ospp": ospp_products,
                  "hw_accel_off": hw_off}
        options = build_office_repair_options(report)
        if not options:
            self.queue.put(f"PROGRESS:{label}:Nothing measured needs a repair, and no optional repair applies "
                           f"to this installation.")
            return
        ticked = sum(1 for o in options if o["checked"])
        self.queue.put(f"PROGRESS:{label}:{len(options)} repair(s) available; {ticked} recommended by the "
                       f"measurements above. Waiting for your choice...")
        chosen = self._ui_check_picker(
            "Office & Outlook repairs",
            f"Tick the repairs to run. {ticked} are pre-ticked because a measurement points at them; "
            f"the rest are optional and say what they cost. Nothing runs until you press Run selected.",
            options)
        if chosen is None:
            self._report_skip(f"PROGRESS:{label}:Cancelled — nothing was changed.")
            return
        if not chosen:
            self._report_skip(f"PROGRESS:{label}:No repairs selected — nothing was changed.")
            return

        def _rank(key):
            for i, prefix in enumerate(self._OFFICE_REPAIR_ORDER):
                if key.startswith(prefix):
                    return i
            return len(self._OFFICE_REPAIR_ORDER)
        chosen = sorted(chosen, key=_rank)
        if "repair:full" in chosen and "repair:quick" in chosen:
            chosen.remove("repair:quick")
        by_key = {o["key"]: o for o in options}
        results = []
        for key in chosen:
            if self.cancel_event.is_set():
                self.queue.put(f"PROGRESS:{label}:Stopped before: {by_key[key]['label']}")
                break
            self.queue.put(f"PROGRESS:{label}:▶ {by_key[key]['label']}")
            try:
                ok = self._office_run_repair(label, key, inst, report, ospp_products, ospp_script)
            except Exception as exc:
                ok = False
                self.queue.put(f"PROGRESS:{label}:  Failed: {exc}")
            results.append((by_key[key]["label"], ok))

        # ---- verify what can be re-measured ----------------------------------
        self.queue.put(f"PROGRESS:{label}:Re-measuring...")
        if c2r and clicktorun is not None:
            now = service_state(CLICKTORUN_SERVICE)
            if now:
                self.queue.put(f"PROGRESS:{label}:  Click-to-Run service: {now['status']} / {now['start']}.")
        if wsearch and "Outlook" in inst["apps"]:
            now = service_state("WSearch")
            if now:
                self.queue.put(f"PROGRESS:{label}:  Windows Search: {now['status']} / {now['start']}.")
        still_stuck = windowless_processes(list(OFFICE_PROCESS_NAMES), min_age=60)
        if outlook_minimizes_to_tray():
            still_stuck = [p for p in still_stuck if p["friendly"] != "Outlook"]
        self.queue.put(f"PROGRESS:{label}:  Office processes stuck without a window: {len(still_stuck)}.")
        remaining_auth = office_auth_findings()
        self.queue.put(f"PROGRESS:{label}:  Harmful sign-in overrides remaining: {len(remaining_auth)}.")
        done = [name for name, ok in results if ok]
        failed = [name for name, ok in results if not ok]
        if failed:
            self._report_failure(f"PROGRESS:{label}:Selected repairs did not complete: {'; '.join(failed)}.")
        self.queue.put(f"PROGRESS:{label}:Office repair finished: {len(done)} of {len(results)} step(s) completed"
                       + (f"; not completed: {'; '.join(failed)}" if failed else "") + ".")
        if crashes.get("total"):
            self.queue.put(f"PROGRESS:{label}:Crash history cannot be re-measured until Office has been used "
                           f"again — run this task again in a few days to confirm the crashes stopped.")

    def _office_run_repair(self, label, key, inst, report, ospp_products, ospp_script):
        """Execute one checklist item. Returns True when the step completed."""
        c2r = inst["c2r"]
        if key.startswith("end:"):
            import psutil
            pid = int(key.split(":", 1)[1])
            try:
                proc = psutil.Process(pid)
                name = proc.name()
                proc.terminate()
                try:
                    proc.wait(10)
                except psutil.TimeoutExpired:
                    proc.kill()
                    proc.wait(5)
                self.queue.put(f"PROGRESS:{label}:  Ended {name} (PID {pid}).")
                return True
            except psutil.NoSuchProcess:
                self.queue.put(f"PROGRESS:{label}:  PID {pid} had already exited.")
                return True
        if key == "service:clicktorun":
            return self._office_set_service(label, CLICKTORUN_SERVICE, "auto", "Click-to-Run service")
        if key == "service:sppsvc":
            return self._office_set_service(label, "sppsvc", "auto", "Software Protection")
        if key == "service:wsearch":
            ok = self._office_set_service(label, "WSearch", "delayed-auto", "Windows Search")
            if ok:
                self.queue.put(f"PROGRESS:{label}:  Outlook's index rebuilds in the background over the next "
                               f"hours; search results fill in as it goes.")
            return ok
        if key.startswith("auth:"):
            hive_name, rest = key[5:].split("\\", 1)
            subkey, value = rest.rsplit("\\", 1)
            return self._office_delete_value(label, hive_name, subkey, value)
        if key.startswith("addin:"):
            hive_name, subkey = key[6:].split("\\", 1)
            ok = self._office_set_dword(label, hive_name, subkey, "LoadBehavior", 2)
            if ok:
                self.queue.put(f"PROGRESS:{label}:  Re-enable it later in Outlook under File > Options > "
                               f"Add-ins > COM Add-ins, or with the undo line above.")
            return ok
        if key == "graphics:off":
            return self._office_set_dword(label, "HKCU", OFFICE_COMMON_KEY + r"\Graphics",
                                          "DisableHardwareAcceleration", 1)
        if key == "identity:reset":
            return self._office_identity_reset(label, inst, ospp_products, ospp_script)
        if key == "outlook:rebuild_ost":
            return self._office_rebuild_ost(label, report["data_files"])
        if key in ("repair:quick", "repair:full"):
            return self._office_c2r_repair(label, inst, "quick" if key == "repair:quick" else "full")
        if key == "update:office":
            argv = office_c2r_update_command(c2r["update_exe"])
            r = wm_run(argv, capture_output=True, visible=True)
            self.queue.put(f"PROGRESS:{label}:  Office's updater was asked to check now (exit code {r.returncode}); "
                           f"its own window shows progress and installs anything found.")
            return r.returncode == 0
        if key == "outlook:navpane":
            exe = inst["apps"].get("Outlook")
            if not exe:
                return False
            if not self._office_close_apps(label, "reset the navigation pane"):
                return False
            launch_visible([exe, "/resetnavpane"])
            self.queue.put(f"PROGRESS:{label}:  Outlook started with /resetnavpane; the folder pane is rebuilt "
                           f"as it opens.")
            return True
        if key == "install:new_outlook":
            winget = shutil.which("winget")
            if not winget:
                self.queue.put(f"PROGRESS:{label}:  winget is not available; install the new Outlook from the "
                               f"Microsoft Store app instead.")
                return False
            r = wm_run([winget, "install", "--id", NEW_OUTLOOK_STORE_ID, "--source", "msstore",
                        "--accept-package-agreements", "--accept-source-agreements"],
                       cancel_event=self.cancel_event, capture_output=True, text=True, encoding="utf-8",
                       errors="replace", startupinfo=_no_console_startupinfo())
            tail = " ".join((r.stdout or r.stderr or "").split())[-200:]
            self.queue.put(f"PROGRESS:{label}:  winget exit code {r.returncode}: {tail}")
            return r.returncode == 0
        self.queue.put(f"PROGRESS:{label}:  Unknown repair key {key}.")
        return False
