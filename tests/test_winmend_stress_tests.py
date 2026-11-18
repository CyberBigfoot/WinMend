"""Stress workloads, evidence and cancellation; normal tests never load hardware."""

import json
import os
from pathlib import Path
import threading
from types import SimpleNamespace
import unittest
import weakref
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from winmend.core.processes import WMCompleted
from winmend.core.task_runner import TaskRunnerMixin
from winmend.features import gpu_stress, hardware_tests as hardware
from winmend.ui.task_host import WMTaskHost


class Runner(TaskRunnerMixin):
    def __init__(self, host):
        self.host = host


class ClockEvent(threading.Event):
    def __init__(self, clock, cancel_at=None):
        super().__init__()
        self.clock = clock
        self.cancel_at = cancel_at

    def wait(self, timeout=None):
        self.clock.now += timeout or 0
        if self.cancel_at is not None and self.clock.now >= self.cancel_at:
            self.set()
        return self.is_set()


class HardwareHarness(unittest.TestCase):
    def setUp(self):
        self.host = WMTaskHost(None)
        self.runner = Runner(self.host)

    def log(self):
        return "\n".join(self.host.queue.queue)

    def run_task(self, task):
        return self.runner._run_task_handler(task, task)[0]


class CPUStressTests(HardwareHarness):
    def simulate(self, sample="99|100", sample_rc=0, whea=(0, 0), cancel_at=None,
                 worker_exit=None, accepted=True):
        clock = SimpleNamespace(now=0.0)
        self.host.cancel_event = ClockEvent(clock, cancel_at)
        workers = [mock.Mock(), mock.Mock()]
        for worker in workers:
            worker.poll.return_value = worker_exit
        def shell(script, **kwargs):
            if "Win32_Processor" in script:
                return WMCompleted([], 0, "Test CPU|2|2|3000")
            return WMCompleted([], sample_rc, sample)
        with mock.patch.object(hardware.messagebox, "askyesno", return_value=accepted), \
                mock.patch.object(hardware.time, "monotonic", lambda: clock.now), \
                mock.patch.object(self.host, "_run_ps", side_effect=shell), \
                mock.patch.object(self.host, "_get_whea_error_count", side_effect=whea) as events, \
                mock.patch.object(hardware.subprocess, "Popen", side_effect=workers) as spawn, \
                mock.patch.object(hardware, "wm_track_child", side_effect=lambda p: p), \
                mock.patch.object(hardware, "wm_kill_tree") as kill, \
                mock.patch.object(hardware, "wm_untrack_child") as untrack:
            state = self.run_task("cpu_stress_test")
        return state, events, spawn, kill, untrack

    def test_completed_measured_run_passes_and_reaps_every_worker(self):
        state, _, spawn, kill, untrack = self.simulate()
        self.assertEqual(state, "done")
        self.assertIn("RESULT: PASS", self.log())
        self.assertEqual(spawn.call_count, 2)
        self.assertEqual(untrack.call_count, 2)
        self.assertGreaterEqual(kill.call_count, 2)
        for call in spawn.call_args_list:
            self.assertIn("TotalSeconds -lt 90", call.args[0][-1])

    def test_cancel_during_wait_never_claims_pass_or_queries_after_load(self):
        state, events, _, kill, untrack = self.simulate(cancel_at=5)
        self.assertEqual(state, "cancel")
        self.assertNotIn("RESULT: PASS", self.log())
        self.assertEqual(events.call_count, 1)
        self.assertEqual(kill.call_count, 2)
        self.assertEqual(untrack.call_count, 2)

    def test_failed_and_empty_counters_never_pass(self):
        for value, rc in (("", 0), ("99|100", 1), ("bad|bad", 0), ("0|100", 0)):
            with self.subTest(value=value, rc=rc):
                self.setUp()
                self.assertEqual(self.simulate(sample=value, sample_rc=rc)[0], "fail")
                self.assertNotIn("RESULT: PASS", self.log())

    def test_missing_clock_or_event_log_is_incomplete(self):
        for sample, whea in (("99|", (0, 0)), ("99|100", (-1, -1)), ("99|100", (5, 0))):
            with self.subTest(sample=sample, whea=whea):
                self.setUp()
                self.assertEqual(self.simulate(sample=sample, whea=whea)[0], "fail")
                self.assertIn("RESULT: INCOMPLETE", self.log())

    def test_new_hardware_error_marks_task_failed(self):
        self.assertEqual(self.simulate(whea=(0, 2))[0], "fail")
        self.assertIn("2 new WHEA", self.log())

    def test_early_worker_exit_marks_task_failed_and_stops_other_workers(self):
        state, _, _, kill, untrack = self.simulate(worker_exit=1)
        self.assertEqual(state, "fail")
        self.assertIn("exited early", self.log())
        self.assertEqual(kill.call_count, 2)
        self.assertEqual(untrack.call_count, 2)

    def test_declining_never_starts_load(self):
        state, events, spawn, _, _ = self.simulate(accepted=False)
        self.assertEqual(state, "skip")
        events.assert_not_called()
        spawn.assert_not_called()

    def test_clock_drop_reports_warning_instead_of_pass(self):
        self.assertEqual(self.simulate(sample="99|65")[0], "done")
        self.assertIn("WARNING", self.log())
        self.assertNotIn("RESULT: PASS", self.log())


class EventEvidenceTests(HardwareHarness):
    def test_empty_failed_or_partial_whea_output_is_unavailable(self):
        for output, rc, expected in (("", 0, -1), ("0", 0, -1), ("WHEA_OK|0", 1, -1),
                                     ("WHEA_OK|0", 0, 0), ("WHEA_OK|3", 0, 3)):
            with self.subTest(output=output, rc=rc):
                with mock.patch.object(self.host, "_run_ps", return_value=WMCompleted([], rc, output)):
                    self.assertEqual(self.host._get_whea_error_count(), expected)

    def test_display_query_is_time_scoped_and_distinguishes_unreadable_log(self):
        with mock.patch.object(self.host, "_run_ps", return_value=WMCompleted([], 0, "DISPLAY_OK|0")) as run:
            self.assertEqual(self.host._get_display_errors(since=1234.9), (0, []))
        script = run.call_args.args[0]
        self.assertIn("FromUnixTimeSeconds(1234)", script)
        self.assertIn("NoMatchingEventsFound", script)
        for rc, output in ((1, "DISPLAY_OK|0"), (0, "")):
            with mock.patch.object(self.host, "_run_ps", return_value=WMCompleted([], rc, output)):
                self.assertEqual(self.host._get_display_errors()[0], -1)


class GPUStressTests(HardwareHarness):
    def simulate(self, result=None, rc=0, events=(0, []), cancel=False, accepted=True):
        if result is None:
            result = {"state": "done", "renderer": "Test hardware GPU", "frames": 200, "elapsed": 60}
        worker = mock.Mock(returncode=rc)
        report_path = []
        def spawn(command, **kwargs):
            path = Path(command[command.index("--report") + 1])
            report_path.append(path)
            # Write running first; the terminal record appears between the
            # parent's read and poll, reproducing the final-read race.
            path.write_text(json.dumps({"state": "running"}))
            def poll():
                path.write_text(json.dumps(result))
                return rc
            worker.poll.side_effect = poll
            if cancel:
                self.host.cancel_event.set()
            return worker
        with mock.patch.object(hardware.messagebox, "askyesno", return_value=accepted), \
                mock.patch.object(hardware.subprocess, "Popen", side_effect=spawn) as launch, \
                mock.patch.object(hardware, "wm_track_child", side_effect=lambda p: p), \
                mock.patch.object(hardware, "wm_kill_tree") as kill, \
                mock.patch.object(hardware, "wm_untrack_child") as untrack, \
                mock.patch.object(self.host, "_get_display_errors", return_value=events) as query:
            state = self.run_task("gpu_stress_test")
        self.assertTrue(all(not path.parent.exists() for path in report_path))
        return state, launch, kill, untrack, query

    def test_real_worker_command_and_terminal_result_are_required(self):
        state, launch, kill, untrack, query = self.simulate()
        self.assertEqual(state, "done")
        self.assertIn("completed 60s", self.log())
        self.assertIn("--gpu-stress-worker", launch.call_args.args[0])
        self.assertEqual(launch.call_args.kwargs["env"]["QT_OPENGL"], "desktop")
        kill.assert_called()
        untrack.assert_called_once()
        query.assert_called_once()

    def test_failed_short_empty_and_software_runs_never_complete(self):
        for result, rc in (({"state": "failed", "error": "shader failed"}, 1),
                           ({"state": "done", "renderer": "llvmpipe", "frames": 200, "elapsed": 60}, 0),
                           ({"state": "done", "renderer": "GPU", "frames": 200, "elapsed": 10}, 0),
                           ({"state": "done", "renderer": "GPU", "frames": 0, "elapsed": 60}, 0)):
            with self.subTest(result=result):
                self.setUp()
                self.assertEqual(self.simulate(result=result, rc=rc)[0], "fail")
                self.assertNotIn("RESULT: completed", self.log())

    def test_cancel_stops_and_untracks_child_without_querying_events(self):
        state, _, kill, untrack, query = self.simulate(cancel=True)
        self.assertEqual(state, "cancel")
        kill.assert_called()
        untrack.assert_called_once()
        query.assert_not_called()
        self.assertNotIn("RESULT: completed", self.log())

    def test_unavailable_events_and_new_driver_errors_do_not_complete(self):
        for events in ((-1, []), (1, ["driver reset"])):
            with self.subTest(events=events):
                self.setUp()
                self.assertEqual(self.simulate(events=events)[0], "fail")

    def test_decline_starts_no_child(self):
        state, launch, _, _, query = self.simulate(accepted=False)
        self.assertEqual(state, "skip")
        launch.assert_not_called()
        query.assert_not_called()

    def test_frozen_worker_launch_does_not_invoke_normal_startup(self):
        with mock.patch.object(hardware.sys, "frozen", True, create=True):
            state, launch, _, _, _ = self.simulate()
        self.assertEqual(state, "done")
        self.assertEqual(launch.call_args.args[0][1], "--gpu-stress-worker")


class GPUDiagnosticTests(HardwareHarness):
    def simulate(self, inventory="GPU|1.2|2026-10-01|OK|0\nGPU_OK", inventory_rc=0,
                 events=(0, []), notes="No problems found.", report=True):
        def dxdiag(command, **kwargs):
            if report:
                body = "<DxDiagNotes>" + (f"<DisplayTab1>{notes}</DisplayTab1>" if notes else "") + "</DxDiagNotes>"
                Path(command[-1]).write_text("<DxDiag>" + body + "</DxDiag>", encoding="utf-16")
            self.assertIs(kwargs["cancel_event"], self.host.cancel_event)
            return WMCompleted(command, 0)
        with mock.patch.object(self.host, "_run_ps", return_value=WMCompleted([], inventory_rc, inventory)), \
                mock.patch.object(self.host, "_get_display_errors", return_value=events), \
                mock.patch.object(hardware.shutil, "which", return_value=None), \
                mock.patch.object(hardware.os.path, "exists", return_value=False), \
                mock.patch.object(hardware, "wm_run", side_effect=dxdiag):
            return self.run_task("gpu_diagnostic")

    def test_pass_requires_complete_inventory_event_log_and_real_display_notes(self):
        self.assertEqual(self.simulate(), "done")
        self.assertIn("RESULT: PASS", self.log())
        self.assertIn("telemetry unavailable", self.log())

    def test_unavailable_evidence_cannot_pass(self):
        for kwargs in ({"inventory": "GPU_OK"}, {"inventory": ""}, {"inventory_rc": 1},
                       {"inventory": "GPU|1.2|date|OK|\nGPU_OK"}, {"events": (-1, [])},
                       {"notes": ""}, {"report": False}):
            with self.subTest(kwargs=kwargs):
                self.setUp()
                self.assertEqual(self.simulate(**kwargs), "fail")
                self.assertNotIn("RESULT: PASS", self.log())

    def test_device_fault_and_crash_history_fail_the_option(self):
        self.assertEqual(self.simulate(inventory="GPU|1.2|date|Error|43\nGPU_OK"), "fail")
        self.assertIn("Code 43", self.log())

    def test_non_english_or_problem_notes_require_review_without_claiming_a_pass(self):
        for notes in ("No errors found.", "Keine Probleme gefunden.", "Display device problem"):
            with self.subTest(notes=notes):
                self.setUp()
                self.assertEqual(self.simulate(notes=notes), "fail")
                self.assertIn("needs review", self.log())


class RAMPatternTests(HardwareHarness):
    def simulate(self, available=16384, cancel=False, fail_at=None):
        live = []
        class Buffer(bytearray):
            pass
        def allocate(data):
            if fail_at is not None and len(live) >= fail_at:
                raise MemoryError()
            # The previous chunks must still be alive, covering distinct
            # allocations instead of writing the same freed page repeatedly.
            self.assertTrue(all(reference() is not None for reference in live))
            buffer = Buffer(data)
            live.append(weakref.ref(buffer))
            if cancel:
                self.host.cancel_event.set()
            return buffer
        def memory_status(pointer):
            pointer._obj.ullAvailPhys = available
            return 1
        with mock.patch.object(hardware, "RAM_CHUNK_BYTES", 1024), \
                mock.patch.object(hardware, "bytearray", side_effect=allocate, create=True), \
                mock.patch.object(hardware.ctypes.windll.kernel32, "GlobalMemoryStatusEx", side_effect=memory_status), \
                mock.patch.object(self.host, "_run_ps", return_value=WMCompleted([], 0, "")) as shell, \
                mock.patch.object(self.host, "_get_whea_error_count", return_value=0):
            state = self.run_task("ram_quick_test")
        return state, live, shell

    def test_pattern_check_holds_every_tested_chunk_until_the_end(self):
        state, allocations, _ = self.simulate()
        self.assertEqual(state, "done")
        self.assertEqual(len(allocations), 4)
        self.assertTrue(all(reference() is None for reference in allocations))

    def test_low_or_unknown_free_memory_skips_all_allocations(self):
        for available in (0, 1024):
            with self.subTest(available=available):
                self.setUp()
                state, allocations, _ = self.simulate(available=available)
                self.assertEqual(state, "skip")
                self.assertEqual(allocations, [])

    def test_memory_pressure_does_not_become_a_successful_check(self):
        state, _, _ = self.simulate(fail_at=1)
        self.assertEqual(state, "fail")
        self.assertIn("RESULT: INCOMPLETE", self.log())

    def test_cancel_does_not_report_a_success_or_start_more_chunks(self):
        state, allocations, shell = self.simulate(cancel=True)
        self.assertEqual(state, "cancel")
        self.assertEqual(len(allocations), 1)
        self.assertEqual(shell.call_count, 1)  # Module inventory only, no post-test query.
        self.assertNotIn("RESULT:", self.log())


if __name__ == "__main__":
    unittest.main()
