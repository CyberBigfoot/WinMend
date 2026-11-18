"""Option reporting regressions; Windows changes are mocked, never executed."""

import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from pathlib import Path
from types import SimpleNamespace
import queue
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from winmend.core.activity import TaskActivityQueue
from winmend.core.processes import WMCompleted
from winmend.core.task_runner import TaskRunnerMixin
from winmend.data.task_catalog import WM_HANDLERS, WM_TASKS
from winmend.features import cleanup, devices, external_tools, network, performance, reporting, security
from winmend.ui.task_host import WMTaskHost
from winmend.features.apps.winget import winget_listing_error
from winmend.ui.theme import WM_DARK


class Runner(TaskRunnerMixin):
    def __init__(self, host):
        self.host = host
        self.simple = False
        self.journal = mock.Mock()


class ActivityContractTests(unittest.TestCase):
    def setUp(self):
        self.host = WMTaskHost(None)
        self.runner = Runner(self.host)

    def test_every_catalog_option_uses_the_reporting_contract(self):
        for task in WM_TASKS:
            for expected in ("done", "fail", "skip", "cancel"):
                with self.subTest(task=task.id, outcome=expected):
                    self.host.cancel_event.clear()

                    def handler():
                        if expected == "fail":
                            self.host._report_failure("PROGRESS:Test:Access denied.")
                        elif expected == "skip":
                            self.host._report_skip("PROGRESS:Test:Declined; nothing changed.")
                        else:
                            self.host.queue.put("PROGRESS:Test:Measured result: 3 items processed.")
                            if expected == "cancel":
                                self.host.cancel_event.set()

                    with mock.patch.object(self.host, WM_HANDLERS[task.id], handler):
                        state, message = self.runner._run_task_handler(task.id, task.title)
                    self.assertEqual(state, expected)
                    self.assertTrue(message)

    def test_silent_handler_is_not_reported_as_completed(self):
        with mock.patch.object(self.host, "run_disk_smart_check", return_value=None):
            state, reason = self.runner._run_task_handler("disk_smart_check", "Disk health")
        self.assertEqual(state, "fail")
        self.assertIn("No activity details", reason)
        self.assertIn(reason, self.host.queue.get_nowait())

    def test_failure_outranks_a_skip_and_cancellation_outranks_both(self):
        def handler():
            self.host._report_failure("PROGRESS:X:Failed step.")
            self.host._report_skip("PROGRESS:X:Declined next step.")
        with mock.patch.object(self.host, "run_disk_smart_check", handler):
            self.assertEqual(self.runner._run_task_handler("disk_smart_check", "X")[0], "fail")
            self.host.cancel_event.set()
            self.assertEqual(self.runner._run_task_handler("disk_smart_check", "X")[0], "cancel")

    def test_exception_does_not_leave_activity_tracking_open(self):
        with mock.patch.object(self.host, "run_disk_smart_check", side_effect=RuntimeError("boom")):
            self.assertEqual(self.runner._run_task_handler("disk_smart_check", "X")[0], "fail")
        self.assertIsNone(self.host.queue.end_task())

    def test_unrelated_thread_cannot_supply_missing_task_details(self):
        q = TaskActivityQueue()
        q.begin_task()
        worker = threading.Thread(target=lambda: q.put("PROGRESS:Other:Unrelated output"))
        worker.start()
        worker.join()
        self.assertEqual(q.end_task(), 0)
        self.assertEqual(q.get_nowait(), "PROGRESS:Other:Unrelated output")

    def test_manual_worker_journals_failure_skip_and_success(self):
        task = next(t for t in WM_TASKS if t.id == "disk_smart_check")
        self.host.admin_status = True
        for kind, journal_status in (("fail", "failed"), ("skip", "skipped"), ("done", "done")):
            with self.subTest(kind=kind):
                self.runner.journal.reset_mock()
                self.host.cancel_event.clear()
                def handler():
                    if kind == "fail":
                        self.host._report_failure("PROGRESS:X:Failed check.")
                    elif kind == "skip":
                        self.host._report_skip("PROGRESS:X:Declined check.")
                    else:
                        self.host.queue.put("PROGRESS:X:A sensitive discovered path C:\\private\\data")
                with mock.patch.object(self.host, WM_HANDLERS[task.id], handler):
                    self.runner._worker([task], session_id="test")
                finished = self.runner.journal.task_finished.call_args
                self.assertEqual(finished.args[2], journal_status)
                self.assertNotIn("private", finished.kwargs.get("note", ""))

    def test_guided_step_obeys_missing_activity_and_skips(self):
        step = {"kind": "task", "id": "disk_smart_check", "title": "Disk health", "admin": False}
        with mock.patch.object(self.host, "run_disk_smart_check", return_value=None):
            self.assertEqual(self.runner._run_step(step, lambda _: None)[0], "fail")
        with mock.patch.object(self.host, "run_disk_smart_check", side_effect=lambda:
                               self.host._report_skip("PROGRESS:X:No action chosen")):
            self.assertEqual(self.runner._run_step(step, lambda _: None)[0], "skip")

    def test_page_launchers_report_what_was_opened(self):
        self.host.window = mock.Mock()
        for task_id, category in (("storage_sence", "storage"), ("startup_manager", "startup"),
                                 ("speed_test", "speedtest"), ("app_installer", "apps"),
                                 ("windows_tweaks", "tweaks")):
            with self.subTest(task=task_id):
                state, _ = self.runner._run_task_handler(task_id, task_id)
                self.assertEqual(state, "done")
                self.host.window._show_category.assert_called_with(category)
        self.host.window._show_category.side_effect = RuntimeError("page could not load")
        self.assertEqual(self.runner._run_task_handler("storage_sence", "Storage")[0], "fail")


class LiveCommandLogTests(unittest.TestCase):
    def setUp(self):
        self.host = WMTaskHost(None)

    def log(self):
        lines = []
        while not self.host.queue.empty():
            lines.append(self.host.queue.get_nowait())
        return "\n".join(lines)

    def test_quiet_command_reports_start_and_exit_without_logging_arguments(self):
        secret = "PRIVATE-PRODUCT-KEY"
        rc, _ = self.host._run_live_command([sys.executable, "-c", "pass", secret], "Quiet")
        self.assertEqual(rc, 0)
        text = self.log()
        self.assertIn("Running python.exe", text)
        self.assertIn("exited with code 0", text)
        self.assertNotIn(secret, text)

    def test_stdout_stderr_and_failure_exit_are_visible(self):
        code = "import sys; print('Checked 4 files'); print('access denied',file=sys.stderr); sys.exit(5)"
        rc, _ = self.host._run_live_command([sys.executable, "-c", code], "Check")
        self.assertEqual(rc, 5)
        text = self.log()
        self.assertIn("Checked 4 files", text)
        self.assertIn("[stderr] access denied", text)
        self.assertIn("exited with code 5", text)

    def test_protocol_markers_are_captured_but_not_shown_raw(self):
        output = []
        self.host._run_live_command([sys.executable, "-c", "print('WM_FAIL|test|denied')"], "Check", output=output)
        self.assertEqual(output, ["WM_FAIL|test|denied"])
        self.assertNotIn("WM_FAIL|", self.log())

    def test_cancelled_task_does_not_start_another_command(self):
        self.host.cancel_event.set()
        with mock.patch("winmend.core.task_execution.subprocess.Popen") as popen:
            self.assertEqual(self.host._run_live_command([sys.executable], "Check")[0], -1)
        popen.assert_not_called()

    def test_cancel_still_works_after_a_child_closes_its_output_pipes(self):
        timer = threading.Timer(0.7, self.host.cancel_event.set)
        timer.start()
        started = time.monotonic()
        try:
            rc, _ = self.host._run_live_command(
                [sys.executable, "-c", "import os,time; os.close(1); os.close(2); time.sleep(30)"], "Quiet")
        finally:
            timer.cancel()
        self.assertEqual(rc, -1)
        self.assertLess(time.monotonic() - started, 5)


class OptionFailureTests(unittest.TestCase):
    def setUp(self):
        self.host = WMTaskHost(None)
        self.runner = Runner(self.host)

    def result(self, task_id):
        return self.runner._run_task_handler(task_id, task_id)

    def test_unavailable_security_scan_tools_fail(self):
        for task_id in ("defender_scan", "msrt_scan"):
            with self.subTest(task=task_id), mock.patch.object(os.path, "exists", return_value=False):
                self.assertEqual(self.result(task_id)[0], "fail")

    def test_msrt_nonzero_result_is_not_silently_successful(self):
        with mock.patch.object(os.path, "exists", return_value=True), \
                mock.patch.object(self.host, "_run_live_command", return_value=(5, False)):
            self.assertEqual(self.result("msrt_scan")[0], "fail")

    def test_defender_does_not_claim_zero_threats_from_exit_code_alone(self):
        with mock.patch.object(os.path, "exists", return_value=True), \
                mock.patch.object(self.host, "_run_live_command", return_value=(0, False)):
            self.assertEqual(self.result("defender_scan")[0], "done")
        logs = "\n".join(self.host.queue.queue)
        self.assertNotIn("No threats found", logs)

    def test_defender_definition_failure_is_preserved_after_scan(self):
        with mock.patch.object(os.path, "exists", return_value=True), \
                mock.patch.object(self.host, "_run_live_command", side_effect=[(5, False), (0, False)]):
            self.assertEqual(self.result("defender_scan")[0], "fail")

    def test_defender_code_two_requires_attention_instead_of_success(self):
        with mock.patch.object(os.path, "exists", return_value=True), \
                mock.patch.object(self.host, "_run_live_command", side_effect=[(0, False), (2, False)]):
            self.assertEqual(self.result("defender_scan")[0], "fail")

    def test_msrt_successful_removal_and_restart_codes_are_distinguished(self):
        for rc in (6, 10, 13):
            with self.subTest(rc=rc), mock.patch.object(os.path, "exists", return_value=True), \
                    mock.patch.object(self.host, "_run_live_command", return_value=(rc, False)):
                self.assertEqual(self.result("msrt_scan")[0], "done")
        self.assertTrue(any(line.startswith("REBOOTRECOMMEND:") for line in self.host.queue.queue))

    def test_dns_empty_or_failed_script_does_not_pass(self):
        for result in (WMCompleted([], 0, "", ""), WMCompleted([], 1, "", "access denied")):
            with self.subTest(rc=result.returncode), mock.patch.object(self.host, "_run_ps", return_value=result):
                self.host._task_failure = None
                self.host._apply_dns_script("DNS", "test", "Applied")
                self.assertTrue(self.host._task_failure)

    def test_failed_ip_configuration_is_failed(self):
        with mock.patch.object(network, "wm_run", return_value=WMCompleted([], 1, "", "denied")):
            self.assertEqual(self.result("ipconfig_all")[0], "fail")

    def test_missing_security_and_account_results_fail(self):
        for task_id in ("security_posture_report", "account_audit", "restore_point_cleanup", "usb_enumerate"):
            with self.subTest(task=task_id), mock.patch.object(self.host, "_run_ps", return_value=WMCompleted([], 1, "", "denied")):
                self.assertEqual(self.result(task_id)[0], "fail")

    def test_spooler_stop_failure_does_not_delete_jobs(self):
        with mock.patch.object(self.host, "_run_live_command", return_value=(1, False)), \
                mock.patch.object(devices, "service_state", return_value={"status": "running"}), \
                mock.patch.object(devices.os, "scandir") as scan:
            self.assertEqual(self.result("clear_print_spooler")[0], "fail")
        scan.assert_not_called()

    def test_spooler_directory_failure_still_restarts_service_and_fails(self):
        with mock.patch.object(self.host, "_run_live_command", return_value=(0, False)) as command, \
                mock.patch.object(devices, "service_state", side_effect=[{"status": "stopped"}, {"status": "running"}]), \
                mock.patch.object(devices.os, "scandir", side_effect=PermissionError("denied")):
            self.assertEqual(self.result("clear_print_spooler")[0], "fail")
        self.assertEqual(command.call_args_list[-1].args[0], ["net", "start", "spooler"])

    def test_service_and_start_menu_script_failures_do_not_pass(self):
        for task_id in ("service_dependency_repair", "start_menu_reset"):
            with self.subTest(task=task_id), mock.patch.object(self.host, "_run_live_command", return_value=(1, False)), \
                    mock.patch("winmend.features.shell.messagebox.askyesno", return_value=True):
                self.assertEqual(self.result(task_id)[0], "fail")

    def test_network_ipv6_and_flush_failures_are_not_ignored(self):
        for codes in ((0, 0, 1, 0), (0, 0, 0, 1), (0, 1, 0, 0)):
            with self.subTest(codes=codes), mock.patch.object(self.host, "_run_live_command", side_effect=[(rc, False) for rc in codes]):
                self.assertEqual(self.result("reset_network")[0], "fail")

    def test_visual_effect_api_refusal_is_a_failure(self):
        with mock.patch.object(performance.ctypes.windll.user32, "SystemParametersInfoW", return_value=0), \
                mock.patch.object(performance, "wm_run", return_value=WMCompleted([], 0)):
            self.host._apply_visual_effects("Effects", reduced=True)
        self.assertTrue(self.host._task_failure)

    def test_ram_changes_with_no_readback_are_unverified(self):
        with mock.patch.object(performance.messagebox, "askyesno", return_value=True), \
                mock.patch.object(self.host, "_run_live_command", return_value=(0, False)), \
                mock.patch.object(performance, "wm_run", return_value=WMCompleted([], 0, "", "")):
            self.assertEqual(self.result("ram_optimizations")[0], "fail")

    def test_declined_reboot_is_skipped(self):
        with mock.patch("winmend.ui.task_host.WMMessageBox.askyesno", return_value=False), \
                mock.patch("winmend.ui.task_host.subprocess.run") as command:
            self.assertEqual(self.result("restart_windows")[0], "skip")
        command.assert_not_called()

    def test_invalid_autopilot_results_do_not_pass(self):
        good = "SERIAL|ABC123\nHASH|" + "T0FBM" * 40 + "\n"
        for result, expected in ((WMCompleted([], 1, "ERR|Access denied\n", ""), "fail"),
                                 (WMCompleted([], 0, "SERIAL|ABC123\nHASH|\n", ""), "fail"),
                                 (WMCompleted([], 0, "SERIAL|\nHASH|" + "T0FBM" * 40 + "\n", ""), "fail"),
                                 (WMCompleted([], 0, good, ""), "done")):
            with self.subTest(expected=expected, out=result.stdout[:30]), \
                    tempfile.TemporaryDirectory() as folder:
                with mock.patch.object(self.host, "_get_desktop_dir", return_value=folder), \
                        mock.patch.object(self.host, "_run_ps", return_value=result):
                    self.assertEqual(self.result("autopilot_csv")[0], expected)
                self.assertEqual(len(os.listdir(folder)), 1 if expected == "done" else 0)

    def test_failed_update_listing_is_not_reported_as_up_to_date(self):
        with mock.patch("winmend.features.apps.operations.shutil.which", return_value="winget"), \
                mock.patch("winmend.features.apps.operations.wm_run", return_value=WMCompleted([], 1, "", "source unavailable")), \
                mock.patch.object(self.host, "_run_live_command") as install:
            self.assertEqual(self.result("update_apps")[0], "fail")
        install.assert_not_called()


class WingetQueryTests(unittest.TestCase):
    def test_real_empty_results_accept_both_signed_and_unsigned_hresult(self):
        for code in (0x8A150014, 0x8A15002B):
            for value in (code, code - 2**32):
                self.assertIsNone(winget_listing_error(WMCompleted([], value, "", ""), updates=True))

    def test_failed_or_silent_query_preserves_unknown_state(self):
        self.assertIn("unknown", winget_listing_error(WMCompleted([], 0, "", "")))
        self.assertIn("source unavailable", winget_listing_error(WMCompleted([], 1, "", "source unavailable")))


class PageActivityTests(unittest.TestCase):
    def test_apps_and_updates_forward_output_to_the_main_activity_log(self):
        from winmend.ui.pages.apps import WMAppInstallerPage
        from winmend.ui.widgets.winget import WMWingetPanel
        for cls in (WMAppInstallerPage, WMWingetPanel):
            with self.subTest(page=cls.__name__):
                page = mock.MagicMock(T=WM_DARK)
                page.q = queue.Queue()
                page.q.put(("line", "Installer checked package and applied version 2."))
                cls._drain(page)
                page.win._log.assert_called_with("Installer checked package and applied version 2.", WM_DARK['text_2'])

    def test_storage_scan_exception_survives_the_done_event(self):
        from winmend.ui.pages import storage
        page = mock.MagicMock(T=WM_DARK)
        page._scan_error = "access denied"
        page.scan_path = "C:\\"
        page.results = {}
        page.started = time.time()
        page.scanner.is_running = True
        page.scanner.total_files = 3
        page.scanner.total_errors = 0
        with mock.patch.object(storage, "wm_build_tree", return_value=SimpleNamespace(size=0)):
            storage.WMStoragePage._finish_scan(page)
        status = page.status.setText.call_args.args[0]
        self.assertIn("Scan failed: access denied", status)
        self.assertNotIn("Scan complete", status)
        self.assertEqual(page.win._log.call_args.args[1], WM_DARK['danger'])

    def test_unreadable_tweak_readback_is_not_success(self):
        from winmend.ui.pages import tweaks
        tweak = SimpleNamespace(id="example", name="Example", after="reboot")
        page = mock.MagicMock(T=WM_DARK)
        page._applying = False
        page.rows = {"example": (mock.Mock(), mock.Mock(), mock.Mock())}
        page.win.journal.start_session.return_value = "session"
        with mock.patch.object(tweaks, "apply_tweak", return_value=None), \
                mock.patch.object(tweaks, "read_tweak_state", return_value=None):
            tweaks.WMTweaksPage._on_toggled(page, tweak, True)
        self.assertEqual(page.win.journal.task_finished.call_args.args[2], "failed")
        page._show_restart_bar.assert_not_called()

    def test_skipped_unstarted_step_uses_its_title_and_leaves_no_pending_row(self):
        from winmend.ui.window_queue import WindowQueueMixin
        task = next(t for t in WM_TASKS if t.id == "disk_smart_check")
        window = mock.MagicMock(T=WM_DARK)
        window.host.queue = queue.Queue()
        window.host.queue.put(f"TASKEND:{task.id}:skip")
        window.pending = [task]
        window.simple = False
        window.running_task = None
        window.finished = []
        WindowQueueMixin._drain_queue(window)
        self.assertEqual(window.pending, [])
        self.assertEqual(window.finished, [(task.title, "skip", 0)])

    def test_batch_summary_shows_failures_and_skips(self):
        from winmend.ui.window_queue import WindowQueueMixin
        window = mock.MagicMock(T=WM_DARK)
        window.host.queue = queue.Queue()
        window.host.queue.put("ALLDONE::")
        window.finished = [("A", "done", 0), ("B", "fail", 0), ("C", "skip", 0)]
        window.guided_page = window.journal_page = None
        window._reboot_reasons = []
        WindowQueueMixin._drain_queue(window)
        window._log.assert_called_with("Run finished: 1 completed, 1 failed, 1 skipped.", WM_DARK['danger'])


class DiskCleanupResultTests(unittest.TestCase):
    def setUp(self):
        self.host = WMTaskHost(None)
        self.stage = {"key": "quick", "profile": 61, "title": "Temporary files", "handlers": ["Temporary Files"], "note": ""}

    def test_stage_freed_bytes_and_nonzero_exit(self):
        for rc in (0, 5):
            with self.subTest(rc=rc):
                process = mock.Mock(pid=123)
                process.poll.return_value = rc
                with mock.patch.object(cleanup.subprocess, "Popen", return_value=process), \
                        mock.patch.object(cleanup, "wm_track_child", side_effect=lambda p: p), \
                        mock.patch.object(cleanup, "wm_untrack_child"), \
                        mock.patch.object(cleanup, "processes_named", return_value=[]), \
                        mock.patch.object(cleanup.shutil, "disk_usage", side_effect=[SimpleNamespace(free=100), SimpleNamespace(free=250)]):
                    result = self.host._run_cleanmgr_stage("Cleanup", self.stage, 1, 1, "C:\\")
                self.assertEqual(result["freed"], 150)
                self.assertEqual(result["status"], "done" if rc == 0 else "failed")

    def test_failed_stage_marks_whole_option_failed_and_total_bytes_are_positive(self):
        with mock.patch.object(cleanup, "open_reg_key"), \
                mock.patch.object(cleanup.winreg, "QueryInfoKey", return_value=(1, 0, 0)), \
                mock.patch.object(cleanup.winreg, "EnumKey", return_value="Temporary Files"), \
                mock.patch.object(cleanup, "plan_cleanmgr_stages", return_value=([self.stage], [])), \
                mock.patch.object(cleanup, "disarm_legacy_profile", return_value=[]), \
                mock.patch.object(cleanup, "configure_cleanmgr_profile", return_value=(["Temporary Files"], [])), \
                mock.patch.object(self.host, "_run_cleanmgr_stage", return_value={"stage": self.stage, "status": "failed", "freed": 0, "secs": 1, "why": "access denied"}), \
                mock.patch.object(cleanup, "wm_run", return_value=WMCompleted([], 0)), \
                mock.patch.object(cleanup.shutil, "disk_usage", side_effect=[SimpleNamespace(free=0), SimpleNamespace(free=100 * 1024**2)]):
            state, reason = Runner(self.host)._run_task_handler("disk_cleanup", "Disk Cleanup")
        self.assertEqual(state, "fail")
        self.assertIn("access denied", reason)
        self.assertIn("100 MB freed", "\n".join(self.host.queue.queue))


if __name__ == "__main__":
    unittest.main()
