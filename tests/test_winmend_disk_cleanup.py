"""Tests for the staged Deep Disk Cleanup: handler planning, the sage-profile
writer, the idle watch behind the stuck detector, and prompt classification.

Two facts measured on a real Windows 11 PC shape these tests:

* The VolumeCaches key on this machine carries a `DownloadsFolder` handler
  whose Folder is the user's own Downloads directory with FileList `*.*`.
  The old task set StateFlags0001 = 2 on it, so "Deep Disk Cleanup" deleted
  personal downloads. `plan_cleanmgr_stages` must never place it, and
  `disarm_legacy_profile` must switch it off in profile 1.
* A message box owned by another process is a `#32770` window with `Button`
  children (`&Yes`, `&No`) and a `Static` body; cleanmgr's own progress window
  carries an `msctls_progress32` child. That is the whole basis of telling
  "waiting on a prompt" from "working".
"""

import unittest
import uuid
from winmend.features import cleanup as cleanup_module

try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None

from winmend_safety import (
    CLEANMGR_EXCLUDED,
    CLEANMGR_LEGACY_PROFILE,
    CLEANMGR_STAGES,
    IdleWatch,
    classify_prompt,
    cleanmgr_profile_value,
    configure_cleanmgr_profile,
    delete_registry_tree,
    disarm_legacy_profile,
    format_bytes_freed,
    format_elapsed,
    plan_cleanmgr_stages,
)

# The handler list of this Windows 11 Pro machine, verbatim.
REAL_HANDLERS = [
    "Active Setup Temp Folders", "BranchCache", "Content Indexer Cleaner", "D3D Shader Cache",
    "Delivery Optimization Files", "Device Driver Packages", "Diagnostic Data Viewer database files",
    "Downloaded Program Files", "DownloadsFolder", "Feedback Hub Archive log files",
    "Internet Cache Files", "Language Pack", "Offline Pages Files", "Old ChkDsk Files",
    "Previous Installations", "Recycle Bin", "RetailDemo Offline Content", "Setup Log Files",
    "System error memory dump files", "System error minidump files", "Temporary Files",
    "Temporary Setup Files", "Temporary Sync Files", "Thumbnail Cache", "Update Cleanup",
    "Upgrade Discarded Files", "User file versions", "Windows Defender",
    "Windows Error Reporting Files", "Windows ESD installation files", "Windows Reset Log Files",
    "Windows Upgrade Log Files",
]


class PlanTests(unittest.TestCase):
    def test_every_handler_is_placed_once_or_excluded(self):
        stages, excluded = plan_cleanmgr_stages(REAL_HANDLERS)
        placed = [h for s in stages for h in s["handlers"]]
        self.assertEqual(len(placed), len(set(placed)), "a handler ran in two stages")
        self.assertEqual(sorted(placed + excluded), sorted(REAL_HANDLERS))

    def test_personal_data_and_recovery_handlers_are_never_enabled(self):
        stages, excluded = plan_cleanmgr_stages(REAL_HANDLERS)
        placed = {h for s in stages for h in s["handlers"]}
        for name in ("DownloadsFolder", "Windows ESD installation files",
                     "User file versions", "Recycle Bin"):
            self.assertNotIn(name, placed)
            self.assertIn(name, excluded)
            self.assertIn(name, CLEANMGR_EXCLUDED)

    def test_update_cleanup_runs_alone_so_the_log_can_name_the_slow_part(self):
        stages, _ = plan_cleanmgr_stages(REAL_HANDLERS)
        updates = [s for s in stages if s["key"] == "updates"]
        self.assertEqual(len(updates), 1)
        self.assertEqual(updates[0]["handlers"], ["Update Cleanup"])
        self.assertTrue(updates[0]["note"], "the slow stage must warn the user up front")

    def test_stage_order_follows_the_table_and_empty_stages_drop_out(self):
        handlers = ["Temporary Files", "Update Cleanup", "DownloadsFolder"]
        stages, excluded = plan_cleanmgr_stages(handlers)
        self.assertEqual([s["key"] for s in stages], ["quick", "updates"])
        self.assertEqual(excluded, ["DownloadsFolder"])

    def test_matching_is_case_insensitive(self):
        stages, excluded = plan_cleanmgr_stages(["update cleanup", "DOWNLOADSFOLDER", "thumbnail cache"])
        self.assertEqual([s["key"] for s in stages], ["quick", "updates"])
        self.assertEqual(stages[1]["handlers"], ["update cleanup"])
        self.assertEqual(excluded, ["DOWNLOADSFOLDER"])

    def test_unknown_third_party_handlers_land_in_the_quick_stage(self):
        stages, _ = plan_cleanmgr_stages(["Contoso Cache", "Update Cleanup"])
        self.assertEqual(stages[0]["key"], "quick")
        self.assertEqual(stages[0]["handlers"], ["Contoso Cache"])

    def test_profiles_are_distinct_and_leave_profile_1_alone(self):
        profiles = [p for _k, p, _t, _h, _n in CLEANMGR_STAGES]
        self.assertEqual(len(profiles), len(set(profiles)))
        self.assertNotIn(CLEANMGR_LEGACY_PROFILE, profiles)
        self.assertEqual(cleanmgr_profile_value(61), "StateFlags0061")
        self.assertEqual(cleanmgr_profile_value(1), "StateFlags0001")


@unittest.skipIf(winreg is None, "Windows only")
class ProfileWriterTests(unittest.TestCase):
    """Against a scratch key under HKCU, never the real VolumeCaches."""

    def setUp(self):
        self.key = rf"Software\WinMendTests\{uuid.uuid4().hex}\VolumeCaches"
        self.handlers = ["Temporary Files", "DownloadsFolder", "Update Cleanup"]
        for h in self.handlers:
            winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"{self.key}\{h}").Close()

    def tearDown(self):
        parent = self.key.rsplit("\\", 1)[0]
        delete_registry_tree(winreg.HKEY_CURRENT_USER, parent)

    def _flag(self, handler, value):
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, rf"{self.key}\{handler}") as k:
            try:
                return winreg.QueryValueEx(k, value)[0]
            except FileNotFoundError:
                return None

    def test_profile_is_written_exactly_two_for_enabled_zero_for_the_rest(self):
        written, failures = configure_cleanmgr_profile(
            61, ["Temporary Files"], self.handlers, key=self.key, hive=winreg.HKEY_CURRENT_USER)
        self.assertEqual(failures, [])
        self.assertEqual(sorted(written), sorted(self.handlers))
        self.assertEqual(self._flag("Temporary Files", "StateFlags0061"), 2)
        self.assertEqual(self._flag("DownloadsFolder", "StateFlags0061"), 0)
        self.assertEqual(self._flag("Update Cleanup", "StateFlags0061"), 0)

    def test_a_missing_handler_key_is_a_reported_failure_not_a_crash(self):
        written, failures = configure_cleanmgr_profile(
            61, [], self.handlers + ["Ghost"], key=self.key, hive=winreg.HKEY_CURRENT_USER)
        self.assertEqual([h for h, _e in failures], ["Ghost"])
        self.assertEqual(len(written), 3)

    def test_disarm_turns_off_only_armed_excluded_handlers_in_profile_1(self):
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, rf"{self.key}\DownloadsFolder", 0,
                            winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "StateFlags0001", 0, winreg.REG_DWORD, 2)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, rf"{self.key}\Temporary Files", 0,
                            winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "StateFlags0001", 0, winreg.REG_DWORD, 2)
        disarmed = disarm_legacy_profile(self.handlers, key=self.key, hive=winreg.HKEY_CURRENT_USER)
        self.assertEqual(disarmed, ["DownloadsFolder"])
        self.assertEqual(self._flag("DownloadsFolder", "StateFlags0001"), 0)
        # A legitimate handler the user (or anyone) enabled in profile 1 is theirs.
        self.assertEqual(self._flag("Temporary Files", "StateFlags0001"), 2)

    def test_disarm_reports_nothing_when_nothing_was_armed(self):
        self.assertEqual(
            disarm_legacy_profile(self.handlers, key=self.key, hive=winreg.HKEY_CURRENT_USER), [])
        self.assertIsNone(self._flag("DownloadsFolder", "StateFlags0001"))


class IdleWatchTests(unittest.TestCase):
    def test_idle_time_counts_from_the_last_change_not_from_the_start(self):
        ticks = iter([0, 10, 20, 30, 45])
        watch = IdleWatch(clock=lambda: next(ticks))
        self.assertEqual(watch.update((1.0, 10, 500)), 0)
        self.assertEqual(watch.update((1.0, 10, 500)), 10)
        self.assertEqual(watch.update((1.0, 10, 500)), 20)
        self.assertEqual(watch.update((1.5, 10, 500)), 0)    # one CPU tick resets it
        self.assertEqual(watch.update((1.5, 10, 500)), 15)

    def test_any_component_moving_counts_as_activity(self):
        ticks = iter(range(0, 100, 5))
        watch = IdleWatch(clock=lambda: next(ticks))
        watch.update((1.0, 10, 500))
        self.assertEqual(watch.update((1.0, 11, 500)), 0)   # I/O op
        self.assertEqual(watch.update((1.0, 11, 400)), 0)   # free space changed
        self.assertEqual(watch.update((1.0, 11, 400)), 5)


class PromptClassificationTests(unittest.TestCase):
    def test_a_message_box_is_a_prompt(self):
        children = [("Button", "&Yes"), ("Button", "&No"),
                    ("Static", "The Recycle Bin on C: is corrupted. Empty it?")]
        verdict = classify_prompt("Disk Cleanup", children)
        self.assertEqual(verdict["buttons"], ["Yes", "No"])
        self.assertIn("corrupted", verdict["text"])
        self.assertEqual(verdict["title"], "Disk Cleanup")

    def test_cleanmgr_progress_window_is_not_a_prompt(self):
        children = [("Static", "Disk Cleanup is cleaning up unnecessary files on your machine."),
                    ("msctls_progress32", ""), ("Button", "Cancel")]
        self.assertIsNone(classify_prompt("Disk Cleanup", children))

    def test_a_window_without_buttons_is_not_a_prompt(self):
        self.assertIsNone(classify_prompt("Disk Cleanup", [("Static", "Working...")]))
        self.assertIsNone(classify_prompt("Disk Cleanup", []))


class FormattingTests(unittest.TestCase):
    def test_bytes_freed(self):
        self.assertEqual(format_bytes_freed(None), "no change")
        self.assertEqual(format_bytes_freed(-5000), "no change")
        self.assertEqual(format_bytes_freed(300 * 1024 ** 2), "300 MB")
        self.assertEqual(format_bytes_freed(int(1.5 * 1024 ** 3)), "1.50 GB")

    def test_elapsed(self):
        self.assertEqual(format_elapsed(9), "9s")
        self.assertEqual(format_elapsed(125), "2m 05s")
        self.assertEqual(format_elapsed(3725), "1h 02m")


if __name__ == "__main__":
    unittest.main()


class _FakeProcess:
    """Popen stand-in: alive for `alive_polls` polls, then exits 0."""

    def __init__(self, alive_polls):
        self.pid = 4242
        self._left = alive_polls
        self.killed = False

    def poll(self):
        if self.killed:
            return -1
        if self._left <= 0:
            return 0
        self._left -= 1
        return None

    def wait(self, timeout=None):
        return self.poll()


class HandlerLoopTests(unittest.TestCase):
    """Drive run_disk_cleanup with every side effect faked: no cleanmgr, no
    registry writes, no Clear-RecycleBin. What is under test is the loop's
    decisions -- when it reports, when it skips, and when it refuses to."""

    def setUp(self):
        import WinMend as W
        from unittest import mock
        self.W = W
        self.mock = mock
        self.host = W.WMTaskHost(None)
        self.killed = []
        self.patches = [
            mock.patch.object(cleanup_module, "configure_cleanmgr_profile", lambda profile, enabled, handlers: (list(handlers), [])),
            mock.patch.object(cleanup_module, "disarm_legacy_profile", lambda handlers: ["DownloadsFolder"]),
            mock.patch.object(cleanup_module, "wm_run", lambda *a, **k: None),
            mock.patch.object(cleanup_module, "wm_kill_tree", lambda proc: (self.killed.append(proc.pid), setattr(proc, "killed", True))),
            mock.patch.object(cleanup_module, "processes_named", lambda names: []),
            mock.patch.object(cleanup_module, "service_pids", lambda names: set()),
            mock.patch.object(cleanup_module, "cleanmgr_activity_signature", lambda drive, extra_pids=(): (1.0, 1, 1)),
            mock.patch.object(W.time, "sleep", lambda s: None),
            mock.patch.object(cleanup_module, "plan_cleanmgr_stages", lambda handlers: (
                [{"key": "quick", "profile": 61, "title": "Temporary files", "handlers": ["Temporary Files"], "note": ""},
                 {"key": "updates", "profile": 63, "title": "Windows Update Cleanup", "handlers": ["Update Cleanup"], "note": "slow"}],
                ["DownloadsFolder"])),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def _idle_script(self, values):
        vals = iter(values)
        last = {"v": values[-1]}

        class ScriptedWatch:
            def __init__(self_inner, clock=None):
                pass

            def update(self_inner, signature):
                try:
                    last["v"] = next(vals)
                except StopIteration:
                    pass
                return last["v"]

        return self.mock.patch.object(cleanup_module, "IdleWatch", ScriptedWatch)

    def _run(self, procs, idle_values, prompts=None):
        procs = iter(procs)
        with self.mock.patch.object(self.W.subprocess, "Popen", lambda *a, **k: next(procs)), \
             self._idle_script(idle_values), \
             self.mock.patch.object(cleanup_module, "process_prompts", lambda pids: list(prompts or [])), \
             self.mock.patch.object(cleanup_module, "bring_window_to_front", lambda hwnd: True):
            self.host.run_disk_cleanup()
        out = []
        while not self.host.queue.empty():
            out.append(self.host.queue.get())
        return out

    def test_stages_run_in_order_and_the_run_finishes_at_100(self):
        log = self._run([_FakeProcess(1), _FakeProcess(1)], [0])
        joined = "\n".join(log)
        self.assertIn("Stage 1 of 2: Temporary files", joined)
        self.assertIn("Stage 2 of 2: Windows Update Cleanup", joined)
        self.assertIn("Stage 1 of 2 finished", joined)
        self.assertIn("Stage 2 of 2 finished", joined)
        self.assertIn("2 of 2 stages finished", joined)
        self.assertTrue(joined.rstrip().endswith("100%") or "100%" in joined)
        self.assertIn("Left off: DownloadsFolder", joined)
        self.assertIn("Profile 1", joined)
        self.assertEqual(self.killed, [])

    def test_a_provably_idle_stage_is_skipped_and_the_rest_carries_on(self):
        # Stage 1: idle climbs past the warning at 300 and the skip at 600.
        # Stage 2: healthy, exits on its own.
        log = self._run([_FakeProcess(50), _FakeProcess(1)], [0, 120, 350, 650, 0, 0])
        joined = "\n".join(log)
        self.assertIn("No activity for 5m 50s", joined)
        self.assertIn("Skipping stage 1", joined)
        self.assertEqual(self.killed, [4242])
        self.assertIn("Stage 2 of 2 finished", joined)
        self.assertIn("1 of 2 stages finished", joined)
        self.assertIn("Skipped: Temporary files", joined)

    def test_skipping_update_cleanup_points_at_the_dism_task(self):
        log = self._run([_FakeProcess(1), _FakeProcess(50)], [0, 0, 0, 650, 0])
        joined = "\n".join(log)
        self.assertIn("Skipped: Windows Update Cleanup", joined)
        self.assertIn("Component Store Cleanup (DISM)", joined)

    def test_a_visible_prompt_is_reported_and_never_killed(self):
        prompt = [{"hwnd": 7, "pid": 4242, "title": "Disk Cleanup",
                   "text": "The Recycle Bin on C: is corrupted. Empty it?", "buttons": ["Yes", "No"]}]
        # Idle sits far past the skip threshold for many polls; the process only
        # exits when the (simulated) user answers.
        log = self._run([_FakeProcess(6), _FakeProcess(1)], [0, 350, 650, 900, 1200, 1500, 0], prompts=prompt)
        joined = "\n".join(log)
        self.assertIn("waiting on a prompt", joined)
        self.assertIn("corrupted", joined)
        self.assertIn("[Yes / No]", joined)
        self.assertEqual(self.killed, [], "a stage with a prompt on screen must not be ended")
        self.assertIn("Stage 1 of 2 finished", joined)
        self.assertNotIn("Skipping stage", joined)

    def test_stop_kills_cleanmgr_and_ends_the_task(self):
        self.host.cancel_event.set()
        try:
            log = self._run([_FakeProcess(50), _FakeProcess(50)], [0])
        finally:
            self.host.cancel_event.clear()
        joined = "\n".join(log)
        self.assertIn("Cancelled by user", joined)
        self.assertNotIn("100%", joined)
