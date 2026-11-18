"""Regressions for the five faults the option sweep found.

1. GUI tools were started with SW_HIDE and so never appeared.
2. Rebuild Icon & Thumbnail Cache deleted nothing and still reported success.
3. Cancelling the Activate Windows key prompt was reported as Completed.
4. The DirectPlay and NFS entries enabled an empty parent feature.
5. Boot Time Analyzer had nothing to say once RAM Optimizations had turned
   off the service that records boots.

Nothing here changes Windows: launches, DISM, Explorer and PowerShell are
mocked. The icon cache tests delete real files, in a temporary folder.
"""

import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from winmend.core import processes
from winmend.core.processes import WMCompleted, wm_run
from winmend.core.task_runner import TaskRunnerMixin
from winmend.features import activation, boot, crashes, external_tools, shell
from winmend.features.explorer.helpers import icon_cache_files
from winmend.features.office import operations as office_module
from winmend.features.shell_helpers import DISM_UNKNOWN_FEATURE, optional_feature_steps
from winmend.ui.task_host import WMTaskHost


class Runner(TaskRunnerMixin):
    def __init__(self, host):
        self.host = host
        self.simple = False
        self.journal = mock.Mock()


def drain(host):
    lines = []
    while not host.queue.empty():
        lines.append(host.queue.get_nowait())
    return "\n".join(lines)


def _fake_popen():
    popen = mock.MagicMock()
    popen.return_value.communicate.return_value = ("", "")
    popen.return_value.poll.return_value = 0
    popen.return_value.pid = 4242
    return popen


def _hidden(call):
    si = call.kwargs.get("startupinfo")
    return (si is not None and bool(si.dwFlags & subprocess.STARTF_USESHOWWINDOW)
            and si.wShowWindow == 0)


class VisibleLaunchTests(unittest.TestCase):
    """SW_HIDE in a STARTUPINFO hides a GUI program's first window, not only a
    console; every tool the user is meant to see must be started without it."""

    def setUp(self):
        self.host = WMTaskHost(None)

    def assert_shown(self, popen):
        self.assertTrue(popen.call_args_list, "nothing was launched")
        for call in popen.call_args_list:
            self.assertFalse(_hidden(call), f"started hidden: {call.args[0]}")

    def test_wm_run_still_hides_consoles_unless_asked_not_to(self):
        with mock.patch("subprocess.Popen", _fake_popen()) as popen:
            wm_run(["cscript", "x.vbs"], capture_output=True)
            self.assertTrue(_hidden(popen.call_args))
            wm_run(["OfficeClickToRun.exe"], capture_output=True, visible=True,
                   startupinfo=processes._no_console_startupinfo())
            self.assertFalse(_hidden(popen.call_args))

    def test_reliability_monitor_and_memory_diagnostic(self):
        with mock.patch("subprocess.Popen", _fake_popen()) as popen:
            self.host.run_reliability_monitor()
            with mock.patch.object(external_tools.messagebox, "askyesno", return_value=True):
                self.host.run_memory_diagnostic()
        self.assertEqual([c.args[0][0] for c in popen.call_args_list], ["perfmon.exe", "mdsched.exe"])
        self.assert_shown(popen)

    def test_msconfig_fallback(self):
        with mock.patch("subprocess.Popen", _fake_popen()) as popen, \
                mock.patch("os.startfile", side_effect=OSError("no association"), create=True):
            self.host.run_open_msconfig()
        self.assert_shown(popen)

    def test_edition_change_dialog(self):
        with mock.patch("subprocess.Popen", _fake_popen()) as popen, \
                mock.patch.object(activation.os.path, "exists", return_value=True):
            self.assertTrue(self.host._launch_edition_change("Activate", "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE"))
        self.assert_shown(popen)

    def test_windbg(self):
        with mock.patch("subprocess.Popen", _fake_popen()) as popen, \
                mock.patch.object(crashes.shutil, "which", return_value=r"C:\x\windbgx.exe"):
            self.assertTrue(self.host._launch_windbg("windbg"))
        self.assert_shown(popen)

    def test_office_repair_update_and_outlook_navigation_pane(self):
        inst = {"c2r": {"update_exe": r"C:\x\OfficeC2RClient.exe",
                        "repair_exe": r"C:\x\OfficeClickToRun.exe",
                        "platform": "x64", "culture": "en-us"},
                "apps": {"Outlook": r"C:\x\OUTLOOK.EXE"}}
        with mock.patch("subprocess.Popen", _fake_popen()) as popen, \
                mock.patch.object(self.host, "_office_close_apps", return_value=True), \
                mock.patch.object(office_module, "processes_named", return_value=[]), \
                mock.patch.object(office_module, "office_installation",
                                  return_value={"apps": inst["apps"], "missing": []}):
            for key in ("update:office", "outlook:navpane", "repair:quick"):
                self.host._office_run_repair("Office", key, inst, {}, [], None)
        launched = [os.path.basename(c.args[0][0]) for c in popen.call_args_list]
        self.assertEqual(launched, ["OfficeC2RClient.exe", "OUTLOOK.EXE", "OfficeClickToRun.exe"])
        self.assert_shown(popen)


class IconCacheTests(unittest.TestCase):
    def setUp(self):
        self.host = WMTaskHost(None)
        self.runner = Runner(self.host)
        self.base = Path(tempfile.mkdtemp(prefix="wm-iconcache-"))
        self.addCleanup(shutil.rmtree, self.base, True)
        self.explorer_dir = self.base / "Microsoft" / "Windows" / "Explorer"
        self.explorer_dir.mkdir(parents=True)
        for name in ("iconcache_16.db", "iconcache_32.db", "thumbcache_256.db"):
            (self.explorer_dir / name).write_bytes(b"x" * 100)
        (self.explorer_dir / "ExplorerStartupLog.etl").write_bytes(b"keep")
        (self.explorer_dir / "iconcache_folder").mkdir()
        (self.base / "IconCache.db").write_bytes(b"x" * 10)
        env = mock.patch.dict(os.environ, {"LOCALAPPDATA": str(self.base)})
        env.start()
        self.addCleanup(env.stop)

    def run_task(self, close="", explorer_after=()):
        with mock.patch.object(shell, "close_explorer", return_value=close) as closer, \
                mock.patch.object(shell, "session_explorer_pids", return_value=set(explorer_after)), \
                mock.patch.object(shell, "start_explorer", return_value="") as starter:
            state, _message = self.runner._run_task_handler("rebuild_icon_cache", "Rebuild Icon Cache")
        return state, closer, starter, drain(self.host)

    def test_lists_only_cache_files(self):
        from winmend.core.safe_delete import final_path
        names = [os.path.basename(p) for p in icon_cache_files(final_path(str(self.base)))]
        self.assertEqual(names, ["IconCache.db", "iconcache_16.db", "iconcache_32.db",
                                 "thumbcache_256.db"])

    def test_removes_every_cache_file_and_starts_explorer_once(self):
        state, closer, starter, log = self.run_task()
        self.assertEqual(state, "done", log)
        closer.assert_called_once()
        starter.assert_called_once()
        self.assertEqual(sorted(p.name for p in self.explorer_dir.iterdir()),
                         ["ExplorerStartupLog.etl", "iconcache_folder"])
        self.assertFalse((self.base / "IconCache.db").exists())
        self.assertIn("Removed all 4 cache files", log)

    def test_explorer_already_back_is_not_started_a_second_time(self):
        # A second explorer.exe opens as a stray folder window.
        state, _closer, starter, log = self.run_task(explorer_after={1234})
        self.assertEqual(state, "done", log)
        starter.assert_not_called()
        self.assertIn("already started Explorer again", log)

    def test_a_file_still_in_use_is_a_failure_not_a_success(self):
        held = open(self.explorer_dir / "iconcache_32.db", "rb")  # no FILE_SHARE_DELETE
        try:
            state, _closer, _starter, log = self.run_task()
        finally:
            held.close()
        self.assertEqual(state, "fail", log)
        self.assertIn("Removed 3 of 4", log)
        self.assertIn("iconcache_32.db", log)
        self.assertTrue((self.explorer_dir / "iconcache_32.db").exists())

    def test_explorer_that_will_not_close_removes_nothing(self):
        state, _closer, starter, log = self.run_task(close="Explorer would not close",
                                                     explorer_after={1234})
        self.assertEqual(state, "fail", log)
        starter.assert_not_called()
        self.assertEqual(len(list(self.explorer_dir.glob("*cache_*.db"))), 3)

    def test_nothing_to_clear_leaves_explorer_alone(self):
        for path in list(self.explorer_dir.glob("*cache_*.db")) + [self.base / "IconCache.db"]:
            path.unlink()
        state, closer, _starter, log = self.run_task()
        self.assertEqual(state, "done", log)
        closer.assert_not_called()


class ActivationTests(unittest.TestCase):
    def test_cancelled_key_prompt_is_a_skip(self):
        host = WMTaskHost(None)
        with mock.patch.object(host, "_prompt_product_key", return_value=None), \
                mock.patch("subprocess.Popen") as popen:
            state, _ = Runner(host)._run_task_handler("activate_windows", "Activate Windows")
        self.assertEqual(state, "skip")
        popen.assert_not_called()


class OptionalFeatureTests(unittest.TestCase):
    def test_child_features_are_what_gets_enabled(self):
        self.assertEqual(optional_feature_steps("LegacyComponents", "enable"),
                         [("DirectPlay", ["dism", "/online", "/enable-feature",
                                          "/featurename:DirectPlay", "/all", "/norestart"])])
        self.assertEqual([n for n, _ in optional_feature_steps("ServicesForNFS-ClientOnly", "enable")],
                         ["ClientForNFS-Infrastructure"])
        # Children that default on need nothing extra.
        self.assertEqual([n for n, _ in optional_feature_steps("Microsoft-Hyper-V-All", "enable")],
                         ["Microsoft-Hyper-V-All"])

    def test_disabling_turns_children_off_before_the_parent(self):
        self.assertEqual([n for n, _ in optional_feature_steps("ServicesForNFS-ClientOnly", "disable")],
                         ["ClientForNFS-Infrastructure", "NFS-Administration",
                          "ServicesForNFS-ClientOnly"])
        self.assertEqual([n for n, _ in optional_feature_steps("NetFx3", "disable")], ["NetFx3"])

    def run_choice(self, choice, codes, state):
        host = WMTaskHost(None)
        calls = []

        def live(args, label, **_kw):
            calls.append(args)
            return codes[len(calls) - 1], False

        with mock.patch.object(host, "_ui_radio_picker", return_value=choice), \
                mock.patch.object(host, "_run_live_command", side_effect=live), \
                mock.patch.object(host, "_optional_feature_state", return_value=state):
            result, _ = Runner(host)._run_task_handler("optional_features_toggle", "Optional Features")
        return result, calls, drain(host)

    def test_directplay_enable_is_verified_against_windows(self):
        result, calls, log = self.run_choice("LegacyComponents:enable", [0], "Enabled")
        self.assertEqual(result, "done", log)
        self.assertIn("/featurename:DirectPlay", calls[0])
        self.assertIn("Windows now lists DirectPlay as Enabled", log)

    def test_success_code_with_the_feature_still_off_is_a_failure(self):
        result, _calls, log = self.run_choice("LegacyComponents:enable", [0], "Disabled")
        self.assertEqual(result, "fail", log)

    def test_a_child_missing_from_this_edition_does_not_stop_the_disable(self):
        result, calls, log = self.run_choice("ServicesForNFS-ClientOnly:disable",
                                             [0, DISM_UNKNOWN_FEATURE - (1 << 32), 3010], "DisablePending")
        self.assertEqual(result, "done", log)
        self.assertEqual(len(calls), 3)
        self.assertIn("REBOOTRECOMMEND", log)

    def test_progress_words(self):
        _result, _calls, log = self.run_choice("NetFx3:disable", [0], "Disabled")
        self.assertIn("Disabling NetFx3...", log)
        self.assertNotIn("Disableing", log)


class BootTimeTests(unittest.TestCase):
    DPS_OFF = {"status": "stopped", "start": "disabled"}
    DPS_ON = {"status": "running", "start": "automatic"}

    def run_task(self, dps, stdout, admin=True, booted=None):
        host = WMTaskHost(None)
        host.admin_status = admin
        result = WMCompleted(["powershell"], 0, stdout, "")
        with mock.patch.object(boot, "service_state", return_value=dps), \
                mock.patch.object(host, "_run_ps", return_value=result), \
                mock.patch("psutil.boot_time", return_value=booted or time.time()):
            state, _ = Runner(host)._run_task_handler("boot_time_analyzer", "Boot Time Analyzer")
        return state, drain(host)

    def test_no_records_with_the_service_disabled_says_why(self):
        state, log = self.run_task(self.DPS_OFF, "NOEVENTS\n")
        self.assertEqual(state, "fail", log)
        self.assertIn("Diagnostic Policy Service, which is disabled", log)
        self.assertNotIn("No events were found", log)

    def test_unelevated_no_records_points_at_elevation_first(self):
        state, log = self.run_task(self.DPS_OFF, "NOEVENTS\n", admin=False)
        self.assertEqual(state, "fail", log)
        self.assertIn("administrator", log)

    def test_old_records_are_labelled_as_old(self):
        out = ("NEWEST=2026-08-01T08:00:00\n== Last 1 boot(s) ==\n"
               "2026-08-01 10:00   total   40.0s   (to desktop   20.0s, background   20.0s)   Warning\n")
        state, log = self.run_task(self.DPS_OFF, out)
        self.assertEqual(state, "done", log)
        self.assertIn("These are older starts", log)
        self.assertNotIn("NEWEST=", log)

    def test_current_records_get_no_warning(self):
        out = "NEWEST=2026-08-01T08:00:00\n== Last 1 boot(s) ==\n2026-08-01 10:00   total 40.0s\n"
        booted = time.mktime((2026, 7, 31, 0, 0, 0, 0, 0, -1))
        state, log = self.run_task(self.DPS_ON, out, booted=booted)
        self.assertEqual(state, "done", log)
        self.assertNotIn("older starts", log)
        self.assertNotIn("not in the", log)


if __name__ == "__main__":
    unittest.main()
