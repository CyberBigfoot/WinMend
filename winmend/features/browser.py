"""WinMend features: browser."""

from __future__ import annotations

from pathlib import Path
import json
import os
import winreg


class BrowserTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    # Edge reads policy from SOFTWARE\Policies\Microsoft\Edge under either hive.
    # Both need elevation: Windows ships HKCU\SOFTWARE\Policies with the signed-in
    # user granted read only, so that a user cannot apply policy to themselves.
    EDGE_POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Edge"

    def _edge_policy_set(self, label, hive_name, name, kind, new):
        """Write one Edge policy value, verify the readback, and log an undo line.

        Returns True only when the value is present in the registry afterwards,
        so a silent failure cannot be reported as success.
        """
        hive = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}[hive_name]
        key = self.EDGE_POLICY_KEY
        try:
            with winreg.CreateKeyEx(hive, key, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as k:
                try:
                    old = winreg.QueryValueEx(k, name)[0]
                except FileNotFoundError:
                    old = None
                winreg.SetValueEx(k, name, 0, kind, new)
                readback = winreg.QueryValueEx(k, name)[0]
        except OSError as exc:
            self.queue.put(f"PROGRESS:{label}:  Could not set {hive_name}\\{key}\\{name}: {exc}")
            return False

        if readback != new:
            self.queue.put(f"PROGRESS:{label}:  {name} did not stick "
                           f"(wanted {new!r}, registry holds {readback!r}).")
            return False

        if old == new:
            self.queue.put(f"PROGRESS:{label}:  {name} was already {new!r}.")
            return True

        self.queue.put(f"PROGRESS:{label}:  {hive_name}\\{key}\\{name} = {new!r} "
                       f"(was {'not set' if old is None else repr(old)}).")
        reg_type = "REG_DWORD" if kind == winreg.REG_DWORD else "REG_SZ"
        if old is None:
            self.queue.put(f"PROGRESS:{label}:    Undo: reg delete \"{hive_name}\\{key}\" /v {name} /f")
        else:
            self.queue.put(f"PROGRESS:{label}:    Undo: reg add \"{hive_name}\\{key}\" /v {name} "
                           f"/t {reg_type} /d \"{old}\" /f")
        return True

    def _edge_local_state_flags(self):
        """Report what Edge's own Local State currently says, for honest logging.

        Startup Boost and background mode are browser-wide settings in
        'Local State', not per-profile ones in 'Preferences'. We do not write
        this file: Edge rewrites it wholesale when it exits, so an edit made
        while Edge is running is simply lost. The policy values are what we
        rely on; this is only read so the log can say whether anything in
        Edge's own state actually needed changing, rather than implying a
        change where the setting was already off.
        """
        state = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Edge" / "User Data" / "Local State"
        try:
            with open(state, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return None
        return {
            "startup_boost": data.get("startup_boost", {}).get("enabled"),
            "background_mode": data.get("background_mode", {}).get("enabled"),
        }

    def apply_edge_performance_adjustments(self):
        """Disable Edge Startup Boost and background mode, and make Google the default search.

        The previous implementation shelled out to PowerShell and silently did
        nothing. Every write failed on the first one with "Access to the registry
        key HKCU\\SOFTWARE\\Policies\\Microsoft\\Edge is denied" - Windows ships
        that key readable-but-not-writable for the signed-in user, so policy
        cannot be self-applied without elevation - and because the script ran
        under $ErrorActionPreference = "Stop" inside one try/catch, the first
        denial aborted the rest. The caller then only logged the non-zero exit
        code instead of raising, so the task reported success having changed
        nothing. Hence: elevation is checked up front, every write is confirmed
        by reading it back, and a failure raises.

        Default search has to go through policy. Edge keeps
        default_search_provider_data as a MAC-protected preference, so a
        hand-edit of the profile is detected and reverted on the next launch.

        The old script also wrote per-profile "Preferences" keys that do not
        exist in Edge (showContent, showFeed, numRowsOfQuickLinks and friends;
        the real ones are news_feed_display, quick_links_options,
        hide_default_top_sites), and wrote them back with Set-Content -Encoding
        UTF8, which in Windows PowerShell prepends a BOM that Chromium's JSON
        parser rejects - enough to make Edge discard the profile. That block is
        gone; the new tab page is handled by policy instead.
        """
        label = "Edge Performance"
        self.queue.put(f"PROGRESS:{label}:Applying Edge performance adjustments...")

        before = self._edge_local_state_flags()
        if before is not None:
            for flag, human in (("startup_boost", "Startup Boost"),
                                ("background_mode", "Background mode")):
                value = before.get(flag)
                if value is None:
                    shown = "not recorded yet"
                elif value:
                    shown = "on"
                else:
                    shown = "already off"
                self.queue.put(f"PROGRESS:{label}:{human} in Edge's own settings: {shown}.")

        # The adjustments this task promises. Failing any of these means the
        # task failed.
        required = [
            ("StartupBoostEnabled", winreg.REG_DWORD, 0,
             "Startup Boost (Edge preloading itself at sign-in)"),
            ("BackgroundModeEnabled", winreg.REG_DWORD, 0,
             "background mode (Edge staying resident after you close it)"),
            ("DefaultSearchProviderEnabled", winreg.REG_DWORD, 1,
             "default search provider control"),
            ("DefaultSearchProviderName", winreg.REG_SZ, "Google",
             "default search name"),
            ("DefaultSearchProviderKeyword", winreg.REG_SZ, "google.com",
             "default search keyword"),
            ("DefaultSearchProviderSearchURL", winreg.REG_SZ,
             "https://www.google.com/search?q={searchTerms}",
             "default search URL"),
            ("DefaultSearchProviderSuggestURL", winreg.REG_SZ,
             "https://www.google.com/complete/search?output=chrome&q={searchTerms}",
             "search suggestions URL"),
        ]

        # Cuts the new tab page's background fetching. Additive: if a build of
        # Edge ignores these, the task has still done what it advertises.
        optional = [
            ("NewTabPageContentEnabled", winreg.REG_DWORD, 0,
             "new tab page news feed"),
            ("NewTabPageHideDefaultTopSites", winreg.REG_DWORD, 1,
             "new tab page promoted tiles"),
        ]

        # Checked up front so a non-elevated run says why once, instead of
        # reporting access-denied against every value in turn.
        if not self.is_admin():
            raise RuntimeError(
                "Edge settings are applied as policy, under SOFTWARE\\Policies, and "
                "Windows grants the signed-in user read-only access there so that policy "
                "cannot be self-applied. Re-run WinMend elevated to apply these.")

        self.queue.put(f"PROGRESS:{label}:Writing Edge policy (HKCU)...")
        failed = [desc for name, kind, value, desc in required
                  if not self._edge_policy_set(label, "HKCU", name, kind, value)]

        for name, kind, value, desc in optional:
            if not self._edge_policy_set(label, "HKCU", name, kind, value):
                self.queue.put(f"PROGRESS:{label}:  Skipped the {desc} setting; "
                               f"the adjustments above are unaffected.")

        # A machine-wide copy also covers other accounts and survives a reset of
        # this user's policy key. Best-effort: its absence changes nothing here.
        # Probed once so a locked-down HKLM reports a single line rather than one
        # refusal per value.
        try:
            winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, self.EDGE_POLICY_KEY,
                               0, winreg.KEY_READ | winreg.KEY_SET_VALUE).Close()
        except OSError as exc:
            self.queue.put(f"PROGRESS:{label}:Machine-wide policy (HKLM) is not writable "
                           f"({exc.strerror or exc}); the per-user policy above still applies "
                           f"to this account.")
        else:
            self.queue.put(f"PROGRESS:{label}:Mirroring policy machine-wide (HKLM)...")
            for name, kind, value, desc in required + optional:
                self._edge_policy_set(label, "HKLM", name, kind, value)

        if failed:
            raise RuntimeError("Edge adjustments were not applied: " + ", ".join(failed))

        self.queue.put(f"PROGRESS:{label}:Applied. Restart Edge for the changes to take effect.")
        self.queue.put(f"PROGRESS:{label}:Note: search engine is now set by policy, so Edge will "
                       f"show 'managed by your organization' and grey out that setting. "
                       f"The undo lines above remove it.")
