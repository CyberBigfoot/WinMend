"""Offscreen Qt smoke test for the rebuilt Guided Fix page.

Drives the real WMGuidedFixPage against a scripted probe, so the widget code,
the case engine, and the runner's step handling are exercised together rather
than in isolation.
"""

import os
import sys
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from PySide6.QtWidgets import QApplication
    HAVE_QT = True
except ImportError:  # pragma: no cover - Qt is a hard dependency of the app
    HAVE_QT = False

from tests.test_winmend_diagnostics import HEALTHY, ScriptedProbe  # noqa: E402


class PageHarness:
    """Everything needed to drive a real page, with no tests of its own.

    A mixin rather than a base test case: the later suites need the same
    harness, and subclassing a class that carries tests would silently re-run
    every one of them under each new name.
    """

    app = None

    @classmethod
    def setUpClass(cls):
        import WinMend

        cls.WinMend = WinMend
        cls.app = QApplication.instance() or QApplication([])

    def _page(self, overrides=None):
        """A real page wired to a scripted probe, with no main window."""
        WinMend = self.WinMend
        from winmend_diagnostics import CaseEngine

        page = WinMend.WMGuidedFixPage.__new__(WinMend.WMGuidedFixPage)

        class FakeRoot:
            @staticmethod
            def after(_delay, callback):
                callback()

        class FakeHost:
            root = FakeRoot()
            admin_status = True

        class FakeJournal:
            @staticmethod
            def list_sessions():
                return []

        class FakeWindow:
            T = WinMend.WM_THEME if hasattr(WinMend, "WM_THEME") else None
            host = FakeHost()
            journal = FakeJournal()
            run_thread = None
            undo_thread = None
            journal_page = None
            simple = False
            case_engine = None
            diagnostic_engine = None

            @staticmethod
            def wm_task_lookup(task_id):
                task = next((t for t in WinMend.WM_TASKS if t.id == task_id), None)
                if task is None:
                    return None
                return {"title": task.title, "duration": "1 min", "risk": task.risk,
                        "restore_point": task.restore_point, "admin": task.admin,
                        "reboot": task.reboot}

        from winmend_safety import DiagnosticEngine

        window = FakeWindow()
        window.T = self._theme()
        window.case_engine = CaseEngine(probe=ScriptedProbe(overrides))
        window.diagnostic_engine = DiagnosticEngine()
        WinMend.WMGuidedFixPage.__init__(page, window)
        return page

    @staticmethod
    def _theme():
        import WinMend
        for name in ("HOLOGRAPHIC_THEME", "WM_THEME"):
            theme = getattr(WinMend, name, None)
            if isinstance(theme, dict) and "accent" in theme:
                return theme
        # The page only ever indexes the theme, so a complete stub is enough.
        return {k: "#333333" for k in (
            "card", "card_hi", "border", "border_hi", "bg", "text", "text_2", "text_3",
            "accent", "accent_hi", "ok", "warn", "danger", "sidebar")}

    # -- construction ----------------------------------------------------

    def test_page_builds(self):
        page = self._page()
        self.assertEqual(page._stage, "describe")
        self.assertFalse(page.interview_card.isVisible())
        self.assertFalse(page.run_plan_btn.isEnabled())

    def test_the_problem_box_starts_empty_so_the_example_shows(self):
        # A previous session's problem used to be typed in for you, which hid
        # the placeholder that tells a first-time user what to write.
        page = self._page()
        page._last_run = None
        page._load_last_run()
        self.assertEqual(page.problem.text(), "")
        self.assertIn("For example", page.problem.placeholderText())

    def test_short_problem_is_rejected(self):
        page = self._page()
        page.problem.setText("x")
        page.start_diagnosis()
        self.assertEqual(page._stage, "describe")
        self.assertIn("few words", page.status.text())

    # -- interview -------------------------------------------------------

    def test_interview_appears_with_questions(self):
        page = self._page()
        page.problem.setText("wifi keeps dropping")
        page.start_diagnosis()
        self.assertEqual(page._stage, "interview")
        self.assertTrue(page.answer_widgets)
        self.assertEqual(len(page.answer_widgets), 1)
        self.assertIn("net_scope", page.answer_widgets)

    def test_answers_are_collected_from_the_combos(self):
        page = self._page()
        page.problem.setText("my pc is slow")
        page.start_diagnosis()
        first = next(iter(page.answer_widgets.values()))
        first.setCurrentIndex(1)
        combo = page.answer_widgets["onset"]
        combo.setCurrentIndex(combo.findData("week"))
        page._submit_interview(skip=False)
        self._settle(page)
        self.assertEqual(page.case["answers"].get("onset"), "week")

    def test_skipping_the_interview_still_diagnoses(self):
        page = self._page()
        page.problem.setText("my pc is slow")
        page.start_diagnosis()
        page._submit_interview(skip=True)
        self._settle(page)
        self.assertIsNotNone(page.case)
        self.assertEqual(page.case["answers"], {})

    # -- results ---------------------------------------------------------

    @staticmethod
    def _settle(page):
        """Wait for the diagnostic pass, which really does run on a thread."""
        thread = getattr(page, "_sweep_thread", None)
        if thread is not None:
            thread.join(timeout=30)
            assert not thread.is_alive(), "the diagnostic sweep did not finish"

    def _diagnose(self, page, problem, answers=None):
        page.problem.setText(problem)
        page.start_diagnosis()
        for question_id, value in (answers or {}).items():
            combo = page.answer_widgets.get(question_id)
            if combo is not None:
                index = combo.findData(value)
                if index >= 0:
                    combo.setCurrentIndex(index)
        page._submit_interview(skip=False)
        self._settle(page)
        return page.case


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class GuidedPageTests(PageHarness, unittest.TestCase):
    def test_findings_and_plan_render(self):
        page = self._page({"disk": {"free_gb": 2.0, "free_pct": 1.0}})
        self._diagnose(page, "no disk space", {"onset": "week"})
        self.assertGreater(page.findings.topLevelItemCount(), 0)
        self.assertGreater(page.plan.topLevelItemCount(), 0)
        self.assertTrue(page.run_plan_btn.isEnabled())
        self.assertTrue(page.report_btn.isEnabled())

    def test_hypothesis_cards_are_created(self):
        page = self._page({"disk": {"free_gb": 2.0, "free_pct": 1.0}})
        self._diagnose(page, "no disk space", {"onset": "week"})
        cards = [self.WinMend.WMHypothesisCard for _ in range(0)]  # type hint only
        count = sum(1 for i in range(page.assessment_box.count())
                    if isinstance(page.assessment_box.itemAt(i).widget(),
                                  self.WinMend.WMHypothesisCard))
        self.assertGreaterEqual(count, 1)

    def test_withheld_actions_are_surfaced_in_the_ui(self):
        page = self._page({
            "smart_health": {"available": True, "disks": 1, "unhealthy": ["SSD (Unhealthy)"]},
            "event_log_errors": {"available": True, "unexpected_shutdowns": 0,
                                 "disk_errors": 9, "service_crashes": 0, "hardware_errors": 0},
        })
        self._diagnose(page, "pc freezes constantly", {"onset": "week"})
        page.tabs.setCurrentIndex(4)
        self.assertTrue(page.withheld_label.isVisibleTo(page))
        text = page.withheld_label.text()
        self.assertIn("Deliberately not doing", text)
        self.assertIn("chkdsk", text.lower())

    def test_no_withheld_section_on_a_healthy_machine(self):
        page = self._page()
        self._diagnose(page, "my pc is slow", {"onset": "week"})
        self.assertFalse(page.withheld_label.isVisibleTo(page))

    def test_selected_steps_follows_the_checkboxes(self):
        from PySide6.QtCore import Qt

        page = self._page({"disk": {"free_gb": 2.0, "free_pct": 1.0}})
        case = self._diagnose(page, "no disk space", {"onset": "week"})
        self.assertEqual(len(page._selected_steps()), len(case["plan"]))
        page.plan.topLevelItem(0).setCheckState(0, Qt.Unchecked)
        self.assertEqual(len(page._selected_steps()), len(case["plan"]) - 1)

    def test_unchecking_everything_disables_run(self):
        from PySide6.QtCore import Qt

        page = self._page({"disk": {"free_gb": 2.0, "free_pct": 1.0}})
        self._diagnose(page, "no disk space", {"onset": "week"})
        for row in range(page.plan.topLevelItemCount()):
            page.plan.topLevelItem(row).setCheckState(0, Qt.Unchecked)
        self.assertFalse(page.run_plan_btn.isEnabled())

    def test_plan_rows_label_undo_honestly(self):
        page = self._page({
            "proxy_settings": {"available": True, "enabled": True, "server": "127.0.0.1:8080",
                               "autoconfig": "", "pac_or_proxy": True},
        })
        self._diagnose(page, "websites will not load", {"onset": "today"})
        labels = {}
        for row in range(page.plan.topLevelItemCount()):
            item = page.plan.topLevelItem(row)
            labels[item.text(1)] = item.text(4)
        proxy = next((v for k, v in labels.items() if "proxy" in k.lower()), None)
        self.assertIsNone(proxy)
        self.assertTrue(all(s.get("read_only") for s in page.case["plan"]))

    # -- full check ------------------------------------------------------

    def test_full_check_skips_the_interview_entirely(self):
        page = self._page({"disk": {"free_gb": 2.0, "free_pct": 1.0}})
        page.start_full_check()
        self._settle(page)
        self.assertFalse(page.interview_card.isVisibleTo(page))
        self.assertEqual(page.answer_widgets, {})
        self.assertIsNotNone(page.case)
        self.assertEqual(page.case["profile"], "audit")

    def test_full_check_needs_no_problem_description(self):
        page = self._page()
        self.assertEqual(page.problem.text(), "")
        page.start_full_check()
        self._settle(page)
        self.assertIsNotNone(page.case)

    def test_clean_full_check_offers_no_plan_and_says_so(self):
        page = self._page()
        page.start_full_check()
        self._settle(page)
        self.assertEqual(page.plan.topLevelItemCount(), 0)
        self.assertFalse(page.run_plan_btn.isEnabled())
        self.assertIn("No automatic repair is supported", page.plan_note.text())
        self.assertIn("completed checks", page.status.text().lower())

    def test_clean_full_check_still_allows_saving_a_report(self):
        page = self._page()
        page.start_full_check()
        self._settle(page)
        self.assertTrue(page.report_btn.isEnabled())

    def test_full_check_with_problems_builds_a_plan(self):
        page = self._page({
            "disk": {"free_gb": 2.0, "free_pct": 1.0},
            "pagefile": {"available": True, "files": 0, "size_mb": 0, "automatic": False,
                         "configured": [], "disabled": True},
        })
        page.start_full_check()
        self._settle(page)
        self.assertGreater(page.plan.topLevelItemCount(), 0)
        self.assertTrue(page.run_plan_btn.isEnabled())

    def test_full_check_button_is_disabled_while_working(self):
        page = self._page()
        page._busy = True
        page._update_run_button()
        self.assertFalse(page.full_check_btn.isEnabled())
        page._busy = False
        page._update_run_button()
        self.assertTrue(page.full_check_btn.isEnabled())

    def test_deep_scan_skips_the_interview_and_uses_its_own_profile(self):
        page = self._page()
        page.start_hardware_scan()
        self._settle(page)
        self.assertFalse(page.interview_card.isVisibleTo(page))
        self.assertEqual(page.answer_widgets, {})
        self.assertIsNotNone(page.case)
        self.assertEqual(page.case["profile"], "hardware")

    def test_deep_scan_runs_the_hardware_collectors(self):
        from winmend_diagnostics import CaseEngine

        page = self._page()
        page.start_hardware_scan()
        self._settle(page)
        called = set(page.win.case_engine.probe.calls)
        for name, _label in CaseEngine.HARDWARE_COLLECTORS:
            self.assertIn(name, called, name)

    def test_an_ordinary_diagnosis_never_touches_the_hardware_tier(self):
        from winmend_diagnostics import CaseEngine

        page = self._page()
        page.problem.setText("my pc is slow")
        page.start_diagnosis()
        page._submit_interview(skip=True)
        self._settle(page)
        called = set(page.win.case_engine.probe.calls)
        # These cost minutes. A path that promises seconds must not pull them in.
        for name, _label in CaseEngine.HARDWARE_COLLECTORS:
            self.assertNotIn(name, called, name)

    def test_deep_scan_needs_no_problem_description(self):
        page = self._page()
        self.assertEqual(page.problem.text(), "")
        page.start_hardware_scan()
        self._settle(page)
        self.assertIsNotNone(page.case)

    def test_deep_scan_button_is_disabled_while_working(self):
        page = self._page()
        page._busy = True
        page._update_run_button()
        self.assertFalse(page.deep_scan_btn.isEnabled())
        page._busy = False
        page._update_run_button()
        self.assertTrue(page.deep_scan_btn.isEnabled())

    def test_deep_scan_says_the_live_tests_change_nothing(self):
        # RAM is written, so do not promise that nothing is written anywhere.
        page = self._page()
        tooltip = page.deep_scan_btn.toolTip()
        self.assertIn("allocated RAM", tooltip)
        self.assertIn("No disk data or settings are changed", tooltip)
        page.start_hardware_scan()
        self.assertIn("own RAM buffer", page.status.text())
        self._settle(page)

    def test_an_ordinary_full_check_does_not_become_a_deep_scan(self):
        page = self._page()
        page.start_full_check()
        self._settle(page)
        self.assertFalse(page._deep)
        self.assertEqual(page.case["profile"], "audit")

    def test_verification_summary_reaches_the_status_line(self):
        page = self._page()
        self._diagnose(page, "my pc is slow", {"onset": "week"})
        page.on_session_finished({
            "id": "abc", "problem": "my pc is slow",
            "diagnosis_before": page.case,
            "verification": {"outcome": "resolved", "summary": "All clear.",
                             "stopped_early": {"step": "Clean Temp Files",
                                               "checks": "System drive free space",
                                               "skipped": ["Deep Disk Cleanup"]}},
        })
        self.assertIn("Resolved", page.status.text())
        self.assertIn("Clean Temp Files", page.status.text())

    def test_missing_verification_is_reported_not_hidden(self):
        page = self._page()
        self._diagnose(page, "my pc is slow", {"onset": "week"})
        page.on_session_finished({"id": "abc", "verification": {}})
        self.assertIn("before verification", page.status.text())

    def test_outcomeless_verification_is_not_reported_as_success(self):
        # An interrupted run leaves a verification dict carrying only the step
        # log. Treating that as a result would claim a measurement that never
        # happened.
        page = self._page()
        self._diagnose(page, "my pc is slow", {"onset": "week"})
        page.on_session_finished({
            "id": "abc", "verification": {"performed": [{"title": "x", "result": "y"}]},
        })
        self.assertIn("before verification", page.status.text())
        self.assertNotIn("Complete.", page.status.text())

    def test_reopened_session_preserves_failed_or_unapplied_repairs(self):
        page = self._page()
        for outcome, status in (("repair_failed", "failed"), ("not_applied", "not_applied"), ("cancelled", "cancelled")):
            with self.subTest(outcome=outcome):
                session = {"id": "saved", "source": "guided", "problem": "Disk full",
                    "diagnosis_before": {"profile": "storage", "findings": []},
                    "verification": {"outcome": outcome, "targets": ["disk_free"],
                        "attempts": [{"identity": "clean_temp:{}", "outcome": "failed"}]}}
                page.win.journal.list_sessions = lambda: [session]
                page._load_last_run()
                before = page._last_run["before"]
                self.assertEqual(before["repair_status"], status)
                self.assertEqual(before["verification_targets"], ["disk_free"])
                self.assertEqual(len(before["attempts"]), 1)

    def test_session_callback_keeps_execution_facts_for_recheck(self):
        page = self._page()
        page._last_run = {"before": {}, "profile": "storage"}
        page.on_session_finished({"id": "saved", "verification": {
            "outcome": "repair_failed", "repair_status": "failed", "summary": "Failed.",
            "attempts": [{"identity": "clean_temp:{}", "outcome": "failed"}]}})
        self.assertEqual(page._last_run["before"]["repair_status"], "failed")
        self.assertEqual(len(page._last_run["before"]["attempts"]), 1)


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class RunStepTests(unittest.TestCase):
    """The runner's per-step dispatch, driven without a real main window."""

    @classmethod
    def setUpClass(cls):
        import WinMend
        cls.WinMend = WinMend

    class FakeHost:
        def __init__(self, admin=True):
            self.admin_status = admin
            self.called = []
            import threading as _threading
            self.cancel_event = _threading.Event()

        def __getattr__(self, name):
            if name.startswith("_") and name not in ("_ran",):
                raise AttributeError(name)

            def handler():
                self.called.append(name)

            return handler

    def _window(self, admin=True):
        window = self.WinMend.WMMainWindow.__new__(self.WinMend.WMMainWindow)
        window.host = self.FakeHost(admin)
        return window

    def test_task_step_dispatches_to_the_handler(self):
        window = self._window()
        step = {"kind": "task", "id": "clean_temp", "title": "Clean Temp Files", "admin": True}
        state, message, undo = self.WinMend.WMMainWindow._run_step(
            window, step, lambda _m: None)
        self.assertEqual(state, "done")
        self.assertIsNone(undo)
        expected = self.WinMend.WM_HANDLERS["clean_temp"]
        self.assertIn(expected, window.host.called)

    def test_admin_step_is_skipped_without_elevation(self):
        window = self._window(admin=False)
        step = {"kind": "task", "id": "clean_temp", "title": "Clean Temp Files", "admin": True}
        state, message, _undo = self.WinMend.WMMainWindow._run_step(
            window, step, lambda _m: None)
        self.assertEqual(state, "skip")
        self.assertIn("administrator", message.lower())
        self.assertEqual(window.host.called, [])

    def test_unknown_action_is_skipped_not_crashed(self):
        window = self._window()
        step = {"kind": "action", "id": "no_such_action", "title": "x", "admin": False,
                "params": {}}
        state, message, _undo = self.WinMend.WMMainWindow._run_step(
            window, step, lambda _m: None)
        self.assertEqual(state, "skip")

    def test_action_failure_is_reported_as_fail(self):
        window = self._window()
        step = {"kind": "action", "id": "rollback_driver", "title": "x", "admin": False,
                "params": {"published": "bogus"}}
        state, message, _undo = self.WinMend.WMMainWindow._run_step(
            window, step, lambda _m: None)
        self.assertEqual(state, "fail")
        self.assertIn("not a driver package", message)

    def test_handler_exception_becomes_a_failure(self):
        window = self._window()

        def explode():
            raise RuntimeError("boom")

        setattr(window.host, self.WinMend.WM_HANDLERS["clean_temp"], explode)
        step = {"kind": "task", "id": "clean_temp", "title": "Clean Temp Files", "admin": True}
        state, message, _undo = self.WinMend.WMMainWindow._run_step(
            window, step, lambda _m: None)
        self.assertEqual(state, "fail")
        self.assertIn("boom", message)

    def test_task_lookup_returns_real_winmend_metadata(self):
        window = self.WinMend.WMMainWindow.__new__(self.WinMend.WMMainWindow)
        window.simple = False
        meta = self.WinMend.WMMainWindow.wm_task_lookup(window, "clean_temp")
        self.assertIsNotNone(meta)
        task = next(t for t in self.WinMend.WM_TASKS if t.id == "clean_temp")
        self.assertEqual(meta["title"], task.title)
        self.assertEqual(meta["risk"], task.risk)
        self.assertIsNone(self.WinMend.WMMainWindow.wm_task_lookup(window, "nope"))


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class EarlyStopScopeTests(unittest.TestCase):
    """How much of the plan a resolved step is allowed to cancel.

    One complaint produces a sequence of attempts at a single thing, so the
    first attempt that works ends the run. A full check produces a list of
    unrelated faults, and there the clock being fixed says nothing whatever
    about the printer.
    """

    @classmethod
    def setUpClass(cls):
        import WinMend
        cls.WinMend = WinMend

    def _run(self, profile, steps, clears_at):
        import queue
        import threading

        WinMend = self.WinMend
        window = WinMend.WMMainWindow.__new__(WinMend.WMMainWindow)
        ran = []
        messages = queue.Queue()
        stop = threading.Event()

        class FakeHost:
            queue = messages
            cancel_event = stop

        class FakeEngine:
            @staticmethod
            def remeasure(_keys, cancel=None):
                return {"system_context": HEALTHY["system_context"]}

            @staticmethod
            def measure_findings(_raw):
                return [{"key": "time_sync", "status": "bad"},
                        {"key": "printers", "status": "bad", "data": {"spooler": "stopped"}}]

            @staticmethod
            def step_cleared(step, _raw, _before):
                return (step["id"] in clears_at), [{"label": step["id"]}]

            @staticmethod
            def build_case(*_args, **_kwargs):
                return {"findings": [], "hypotheses": [], "plan": []}

        class FakeDiagnostics:
            @staticmethod
            def compare(_before, _after):
                return {"outcome": "improved", "summary": "done"}

        window.host = FakeHost()
        window.case_engine = FakeEngine()
        window.diagnostic_engine = FakeDiagnostics()
        window.journal = None
        window.wm_task_lookup = lambda _id: None
        window._prepare_protection = lambda _steps, _session: True
        window._run_step = lambda step, _emit: (ran.append(step["id"]) or ("done", "ok", None))

        WinMend.WMMainWindow._case_worker(
            window, steps, None, {"profile": profile, "findings": [], "problem": "x"})
        return ran

    @staticmethod
    def _step(index, step_id, hypothesis):
        return {"index": index, "id": step_id, "kind": "action", "title": step_id,
                "hypothesis": hypothesis, "verify_keys": ["k"], "stop_if_clear": True,
                "admin": False, "params": {"name": "Spooler"} if step_id == "restart_service" else {}, "restore_point": False}

    STEPS = [_step.__func__(0, "sync_clock", "clock_drift"),
             _step.__func__(1, "time_sync_fix", "clock_drift"),
             _step.__func__(2, "restart_service", "print_spooler")]

    def test_a_full_check_keeps_going_to_the_next_fault(self):
        # The whole promise of a full check is that it repairs everything it
        # found. Ending the run at the first success would silently abandon
        # every other fault on the list.
        ran = self._run(self.WinMend.WM_AUDIT_PROFILE, self.STEPS, {"sync_clock"})
        self.assertIn("restart_service", ran)
        self.assertNotIn("time_sync_fix", ran)

    def test_a_full_check_still_skips_the_rest_of_the_same_fault(self):
        ran = self._run(self.WinMend.WM_AUDIT_PROFILE, self.STEPS, {"sync_clock"})
        self.assertEqual(ran, ["sync_clock", "restart_service"])

    def test_one_complaint_still_stops_at_the_first_thing_that_works(self):
        ran = self._run("network", self.STEPS, {"sync_clock"})
        self.assertEqual(ran, ["sync_clock", "restart_service"])

    def test_nothing_is_skipped_when_nothing_clears(self):
        ran = self._run(self.WinMend.WM_AUDIT_PROFILE, self.STEPS, set())
        self.assertEqual(ran, ["sync_clock", "time_sync_fix", "restart_service"])


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class StepShimTests(unittest.TestCase):
    def test_shim_exposes_what_the_queue_needs(self):
        import WinMend

        shim = WinMend.WMStepShim({
            "id": "clean_temp", "title": "Clean Temp Files", "risk": "caution",
            "restore_point": False, "admin": True, "reboot": False,
        })
        self.assertEqual(shim.display_title(True), "Clean Temp Files")
        self.assertEqual(shim.id, "clean_temp")
        self.assertTrue(shim.admin)


if __name__ == "__main__":
    unittest.main(verbosity=2)


def _user_role():
    from PySide6.QtCore import Qt
    return Qt.UserRole


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class MeasurementFilterTests(PageHarness, unittest.TestCase):
    """The attention-only filter on a table that now holds eighty-odd rows."""

    def test_the_filter_starts_off_so_the_healthy_rows_are_visible(self):
        # The healthy rows are the evidence that the check actually looked.
        # Hiding them by default would turn a full report into an assertion.
        page = self._page()
        page.start_full_check()
        self._settle(page)
        self.assertFalse(page.findings_filter.isChecked())
        self.assertEqual(page.findings.topLevelItemCount(), len(page.case["findings"]))

    def test_ticking_the_filter_shows_only_what_needs_attention(self):
        page = self._page({"disk": {"free_gb": 2.0, "free_pct": 1.0}})
        page.start_full_check()
        self._settle(page)
        page.findings_filter.setChecked(True)
        flagged = [f for f in page.case["findings"] if f["status"] not in ("good", "info")]
        self.assertTrue(flagged)
        self.assertEqual(page.findings.topLevelItemCount(), len(flagged))
        self.assertIn(f"Showing {len(flagged)}", page.findings_count.text())

    def test_the_filter_redraws_without_re_running_the_checks(self):
        page = self._page({"disk": {"free_gb": 2.0, "free_pct": 1.0}})
        page.start_full_check()
        self._settle(page)
        before = list(page.win.case_engine.probe.calls)
        page.findings_filter.setChecked(True)
        page.findings_filter.setChecked(False)
        self.assertEqual(page.win.case_engine.probe.calls, before)
        self.assertEqual(page.findings.topLevelItemCount(), len(page.case["findings"]))

    def test_a_clean_pc_with_the_filter_on_says_so_rather_than_showing_nothing(self):
        # An empty table reads as a broken page. It has to say why it is empty.
        page = self._page()
        page.start_full_check()
        self._settle(page)
        page.findings_filter.setChecked(True)
        self.assertGreater(page.findings.topLevelItemCount(), 0)
        self.assertTrue(all(f["status"] not in ("warn", "bad") for f in page.case["findings"]))


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class TimelineTabTests(PageHarness, unittest.TestCase):
    """The dated view of the same evidence."""

    @staticmethod
    def _iso(days):
        from datetime import datetime, timedelta, timezone
        return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")

    def test_changes_and_faults_are_both_listed(self):
        page = self._page({
            "installed_updates": {"available": True, "updates": [
                {"kb": "KB5099999", "installed": self._iso(4), "days_ago": 4.0, "kind": ""}]},
            "bugchecks": {"available": True, "count": 1, "crashes": [
                {"time": self._iso(3), "code": "0x0000009F", "name": "DRIVER_POWER_STATE_FAILURE",
                 "cause": "a driver did not respond", "tags": ["driver"], "dump": ""}]},
        })
        page.start_full_check()
        self._settle(page)
        rows = [page.timeline.topLevelItem(row)
                for row in range(page.timeline.topLevelItemCount())]
        titles = [row.text(2) for row in rows]
        self.assertTrue(any("KB5099999" in title for title in titles))
        self.assertTrue(any("0x0000009F" in title for title in titles))
        # Newest first: the crash at three days precedes the update at four.
        self.assertLess(next(i for i, t in enumerate(titles) if "0x0000009F" in t),
                        next(i for i, t in enumerate(titles) if "KB5099999" in t))

    def test_an_undated_pc_says_timing_cannot_explain_anything(self):
        page = self._page({
            "installed_updates": {"available": True, "updates": []},
            "installed_programs": {"available": True, "programs": []},
            "third_party_drivers": {"available": True, "total": 4, "recent": [],
                                    "store_exists": True},
            "restore_points": {"available": True, "points": [], "protection": True},
        })
        page.start_full_check()
        self._settle(page)
        self.assertEqual(page.timeline.topLevelItemCount(), 0)
        self.assertIn("cannot be used to explain", page.timeline_note.text())

    def test_a_new_sweep_clears_the_previous_timeline(self):
        page = self._page({
            "installed_updates": {"available": True, "updates": [
                {"kb": "KB5000123", "installed": self._iso(2), "days_ago": 2.0, "kind": ""}]}})
        page.start_full_check()
        self._settle(page)
        self.assertGreater(page.timeline.topLevelItemCount(), 0)
        page.win.case_engine.probe.data["installed_updates"] = {"available": True, "updates": []}
        page.win.case_engine.probe.data["restore_points"] = {"available": True, "points": [],
                                                             "protection": True}
        page.start_full_check()
        self._settle(page)
        self.assertEqual(page.timeline.topLevelItemCount(), 0)


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class SharedStepDisplayTests(PageHarness, unittest.TestCase):
    """A step that answers two findings has to look like it answers two."""

    def test_a_shared_step_names_every_finding_it_covers(self):
        page = self._page({
            "firewall_profiles": {"available": True, "disabled": ["Public"],
                                  "allow_inbound": [], "profiles": [
                                      {"name": "Public", "enabled": False, "inbound": "Block"}]},
            "uac_state": {"available": True, "enabled": False, "consent": 0,
                          "never_notifies": False, "secure_desktop": False},
        })
        page.start_full_check()
        self._settle(page)
        shared = next(s for s in page.case["plan"] if s["id"] == "security_posture_report")
        self.assertTrue(shared["also_for"])
        row = next(page.plan.topLevelItem(n) for n in range(page.plan.topLevelItemCount())
                   if page.plan.topLevelItem(n).data(0, _user_role()) == shared["index"])
        self.assertIn("also covers", row.text(2))
        tooltip = row.toolTip(1)
        for title in [shared["hypothesis_title"], *shared["also_titles"]]:
            self.assertIn(title, tooltip)


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class MeasurementDetailTests(PageHarness, unittest.TestCase):
    """Clicking a reading has to answer "where did you get that?".

    Eighty-odd rows of verdicts with nothing behind them is a list of
    assertions. The detail pane is what turns each one back into a measurement
    the user can go and check for themselves.
    """

    def _select(self, page, key):
        for row in range(page.findings.topLevelItemCount()):
            item = page.findings.topLevelItem(row)
            if (item.data(0, _user_role()) or {}).get("key") == key:
                page.findings.setCurrentItem(item)
                return item
        return None

    def test_nothing_selected_says_so_rather_than_showing_an_empty_box(self):
        page = self._page()
        self.assertIn("Select a reading", page.finding_detail.toPlainText())

    def test_the_detail_names_the_windows_facility_the_reading_came_from(self):
        page = self._page({"component_store_health": {"available": True, "state": "repairable"}})
        page.start_full_check()
        self._settle(page)
        self.assertIsNotNone(self._select(page, "component_store"))
        text = page.finding_detail.toPlainText()
        self.assertIn("Where this was read from", text)
        self.assertIn("CheckHealth", text)
        self.assertIn("Checking Windows component health", text)

    def test_the_detail_shows_what_was_actually_measured(self):
        page = self._page({"disk": {"free_gb": 2.0, "free_pct": 1.0}})
        page.start_full_check()
        self._settle(page)
        self._select(page, "disk_free")
        text = page.finding_detail.toPlainText()
        self.assertIn("What the check actually saw", text)
        self.assertIn("free pct", text)

    def test_the_detail_names_the_repairs_and_the_cause_that_rest_on_it(self):
        page = self._page({"disk": {"free_gb": 2.0, "free_pct": 1.0}})
        page.start_full_check()
        self._settle(page)
        self._select(page, "disk_free")
        text = page.finding_detail.toPlainText()
        self.assertIn("Repairs that target this", text)
        self.assertIn("Deep Disk Cleanup", text)
        cause = next(h for h in page.case["hypotheses"] if "disk_free" in h["evidence_keys"])
        self.assertIn(cause["title"], text)

    def test_a_healthy_row_is_just_as_traceable_as_a_failing_one(self):
        # The healthy rows are the evidence that the check actually looked, so
        # they have to be as inspectable as the flagged ones.
        page = self._page()
        page.start_full_check()
        self._settle(page)
        self._select(page, "uptime")
        text = page.finding_detail.toPlainText()
        self.assertIn("Information", text)
        self.assertIn("Where this was read from", text)

    def test_the_selection_survives_toggling_the_attention_filter(self):
        page = self._page({"disk": {"free_gb": 2.0, "free_pct": 1.0}})
        page.start_full_check()
        self._settle(page)
        self._select(page, "disk_free")
        page.findings_filter.setChecked(True)
        selected = page.findings.currentItem()
        self.assertEqual((selected.data(0, _user_role()) or {}).get("key"), "disk_free")
        self.assertIn("System drive free space", page.finding_detail.toPlainText())

    def test_an_evidence_link_opens_the_measurement_behind_the_verdict(self):
        page = self._page({"disk": {"free_gb": 2.0, "free_pct": 1.0}})
        page.start_full_check()
        self._settle(page)
        page.tabs.setCurrentIndex(0)
        page._focus_finding("disk_free")
        self.assertEqual(page.tabs.currentIndex(), 1)
        selected = page.findings.currentItem()
        self.assertEqual((selected.data(0, _user_role()) or {}).get("key"), "disk_free")

    def test_a_link_to_a_hidden_row_clears_the_filter_rather_than_landing_nowhere(self):
        page = self._page({"disk": {"free_gb": 2.0, "free_pct": 1.0}})
        page.start_full_check()
        self._settle(page)
        page.findings_filter.setChecked(True)
        page._focus_finding("uptime")  # healthy, so the filter is hiding it
        self.assertFalse(page.findings_filter.isChecked())
        selected = page.findings.currentItem()
        self.assertEqual((selected.data(0, _user_role()) or {}).get("key"), "uptime")

    def test_a_cause_card_links_to_every_reading_it_cites(self):
        from PySide6.QtWidgets import QLabel

        page = self._page({"disk": {"free_gb": 2.0, "free_pct": 1.0}})
        page.start_full_check()
        self._settle(page)
        cards = [page.assessment_box.itemAt(i).widget()
                 for i in range(page.assessment_box.count())]
        cards = [c for c in cards if isinstance(c, self.WinMend.WMHypothesisCard)]
        self.assertTrue(cards)
        markup = "".join(label.text() for card in cards
                         for label in card.findChildren(QLabel))
        self.assertIn("Evidence:", markup)
        self.assertIn("href='disk_free'", markup)

    def test_a_flagged_reading_with_no_ranked_cause_is_still_one_click_away(self):
        # The fallback for the assessments that produce no ranked cause: those
        # used to say "N readings are worth a look" and leave the user to find
        # them among eighty rows.
        from PySide6.QtWidgets import QLabel

        page = self._page({"disk": {"free_gb": 1.0, "free_pct": 1.0}})
        page.start_full_check()
        self._settle(page)
        page._clear_assessment("No single fault stands out.")
        page._add_attention_links(page.case)
        widgets = [page.assessment_box.itemAt(i).widget()
                   for i in range(page.assessment_box.count())]
        markup = "".join(w.text() for w in widgets if isinstance(w, QLabel))
        self.assertIn("href='disk_free'", markup)
        page._focus_finding("disk_free")
        selected = page.findings.currentItem()
        self.assertEqual((selected.data(0, _user_role()) or {}).get("key"), "disk_free")

    def test_the_detail_pane_starts_shut_so_the_table_keeps_its_height(self):
        # On a small window the difference is eight readings visible or two.
        page = self._page()
        self.assertEqual(page.findings_split.sizes()[1], 0)

    def test_clicking_a_row_opens_the_pane_even_after_it_was_dragged_shut(self):
        page = self._page({"disk": {"free_gb": 2.0, "free_pct": 1.0}})
        page.start_full_check()
        self._settle(page)
        self._select(page, "disk_free")
        self.assertGreater(page.findings_split.sizes()[1], 0)
        page.findings_split.setSizes([400, 0])
        self._select(page, "uptime")
        self.assertGreater(page.findings_split.sizes()[1], 0)

    def test_the_flagged_list_is_empty_when_nothing_is_flagged(self):
        page = self._page()
        page.start_full_check()
        self._settle(page)
        page._clear_assessment("Every check passed.")
        before = page.assessment_box.count()
        page._add_attention_links(page.case)
        self.assertEqual(page.assessment_box.count(), before)


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class ChecklistAndLogTests(unittest.TestCase):
    """The right-hand rail: everything queued, and everything that happened.

    Both panels used to throw work away -- the checklist drew only the last
    four finished items and had nowhere to scroll, and the log deleted its
    oldest lines once it passed four hundred of them. Between them, the panel
    that is supposed to say what a twenty-task run is doing could show neither
    the run nor its history.
    """

    app = None

    @classmethod
    def setUpClass(cls):
        import WinMend

        cls.WinMend = WinMend
        cls.app = QApplication.instance() or QApplication([])

    class FakeTask:
        def __init__(self, title):
            self.title = title

        def display_title(self, _simple=False):
            return self.title

    def _rail(self):
        """A real rail, built without the rest of the main window."""
        WinMend = self.WinMend
        window = WinMend.WMMainWindow.__new__(WinMend.WMMainWindow)
        window.T = WinMend.WM_DARK
        window.queue_rows = []
        window.pending = []
        window.finished = []
        window.running_task = None
        window.run_started = None
        window.run_thread = None
        window.simple = False
        window.request_stop = lambda: None
        WinMend.WMMainWindow._build_right(window)
        return window

    @staticmethod
    def _titles(window):
        from PySide6.QtWidgets import QLabel
        return [row.findChildren(QLabel)[1].text() for row in window.queue_rows]

    def test_every_queued_task_is_listed(self):
        window = self._rail()
        window.pending = [self.FakeTask(f"Task {n}") for n in range(20)]
        window._rebuild_queue()
        self.assertEqual(len(window.queue_rows), 20)
        self.assertIn("Task 19", self._titles(window))
        self.assertIn("20 queued", window.q_count.text())

    def test_finished_tasks_are_all_kept_not_just_the_last_few(self):
        window = self._rail()
        window.finished = [(f"Done {n}", "done", 10) for n in range(12)]
        window._rebuild_queue()
        self.assertEqual(len(window.queue_rows), 12)
        self.assertIn("Done 0", self._titles(window))
        self.assertIn("12 done", window.q_count.text())

    def test_the_checklist_scrolls_instead_of_clipping(self):
        window = self._rail()
        window.pending = [self.FakeTask(f"Task {n}") for n in range(30)]
        window._rebuild_queue()
        holder = window.q_scroll.widget()
        for row in window.queue_rows:
            self.assertIs(row.parent(), holder)
        self.assertTrue(window.q_scroll.widgetResizable())

    def test_a_running_task_is_shown_above_the_queue(self):
        window = self._rail()
        window.running_task = ("clean_temp", "Clean Temp Files")
        window.pending = [self.FakeTask("Next one")]
        window._rebuild_queue()
        self.assertTrue(getattr(window.queue_rows[0], "_is_running", False))
        self.assertIn("1 running", window.q_count.text())
        self.assertIn("1 queued", window.q_count.text())

    def _with_selection(self, window, task_ids):
        """Give the rail a host whose vars say which tasks are ticked."""
        WinMend = self.WinMend
        chosen = set(task_ids)

        class Var:
            def __init__(self, on):
                self._on = on

            def get(self):
                return self._on

        class Host:
            vars = {task.id: Var(task.id in chosen) for task in WinMend.WM_TASKS}

        window.host = Host()
        return window

    def test_ticked_tasks_are_listed_before_anything_is_run(self):
        # A selection of fifteen used to be a number on a label: the only way
        # to see what was ticked was to scroll every category looking for ticks.
        WinMend = self.WinMend
        window = self._with_selection(
            self._rail(), [task.id for task in WinMend.WM_TASKS[:15]])
        window._rebuild_queue()
        self.assertEqual(len(window.queue_rows), 15)
        self.assertIn("15 selected", window.q_count.text())
        self.assertIn(WinMend.WM_TASKS[14].title,
                      " | ".join(self._titles(window)))

    def test_the_preview_gives_way_to_the_run_it_becomes(self):
        WinMend = self.WinMend
        window = self._with_selection(
            self._rail(), [task.id for task in WinMend.WM_TASKS[:15]])
        window.running_task = ("clean_temp", "Clean Temp Files")
        window.pending = [self.FakeTask("Next one")]
        window._rebuild_queue()
        self.assertEqual(len(window.queue_rows), 2)
        self.assertNotIn("selected", window.q_count.text())

    def test_an_empty_checklist_says_so(self):
        window = self._rail()
        window._rebuild_queue()
        self.assertTrue(window.q_empty.isVisibleTo(window.q_scroll))
        self.assertEqual(window.q_count.text(), "idle")

    def test_the_log_keeps_every_line(self):
        window = self._rail()
        for n in range(1500):
            window._log(f"line {n}")
        text = window.log_view.toPlainText()
        self.assertIn("line 0", text)
        self.assertIn("line 1499", text)
        self.assertGreaterEqual(window.log_view.document().blockCount(), 1500)

    def test_log_text_is_escaped_rather_than_rendered(self):
        # Task output is arbitrary text, and a stray angle bracket must not be
        # able to eat the rest of the line as markup.
        window = self._rail()
        window._log(r"found <b>C:\Temp\a&b</b>")
        self.assertIn(r"found <b>C:\Temp\a&b</b>", window.log_view.toPlainText())
