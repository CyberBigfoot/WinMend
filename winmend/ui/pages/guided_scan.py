"""WinMend ui: pages: guided scan."""

from __future__ import annotations

from PySide6.QtCore import Qt as QtC
from PySide6.QtWidgets import QComboBox, QFileDialog, QHBoxLayout, QLabel, QMessageBox, QWidget
from pathlib import Path
from winmend.diagnostics.reference import (
    AUDIT_PROFILE as WM_AUDIT_PROFILE,
    HARDWARE_PROFILE as WM_HARDWARE_PROFILE,
)
from winmend.reports.case import render_case_report_html
import os
import threading
import time
import webbrowser


class GuidedScanMixin:
    """WMGuidedFixPage methods grouped by responsibility."""

    # ---- stage 1: describe ----------------------------------------------

    @staticmethod
    def _execution_baseline(original, session):
        """Restore execution facts as well as measurements after reopening."""
        before = dict(original or {})
        saved = session.get("verification") or {}
        if "targets" in saved:
            before["verification_targets"] = saved["targets"]
        before["attempts"] = saved.get("attempts", before.get("attempts", []))
        status = saved.get("repair_status")
        if status not in ("failed", "complete", "not_applied", "cancelled"):
            status = {"repair_failed": "failed", "not_applied": "not_applied", "cancelled": "cancelled"}.get(saved.get("outcome"))
        if status is None and session.get("status") in ("failed", "cancelled"):
            status = session["status"]
        if status:
            before["repair_status"] = status
        return before

    def _load_last_run(self):
        """Adopt the newest guided session as the re-check baseline, so a fix
        that needed a restart can still be verified after the app reopens."""
        try:
            for session in self.win.journal.list_sessions():
                if session.get("source") == "guided" and session.get("diagnosis_before"):
                    before = self._execution_baseline(session["diagnosis_before"], session)
                    saved = session.get("verification", {})
                    if saved.get("outcome") == "restart_required":
                        before["restart_required"] = True
                    expected = set(before.get("restart_expected_ids", []))
                    if expected & {t["id"] for t in session.get("tasks", []) if t.get("state") in ("done", "interrupted")}:
                        before["restart_required"] = True
                    self._last_run = {
                        "problem": session.get("problem", ""),
                        "profile": session["diagnosis_before"].get("profile"),
                        "answers": session["diagnosis_before"].get("answers", {}),
                        "before": before,
                        "session_id": session.get("id"),
                    }
                    # The box is deliberately left empty. Filling it with the
                    # last session's problem hides the example placeholder and
                    # invites re-diagnosing something already dealt with -- and
                    # after a full check it put the words "Full system check"
                    # into a box asking what is going wrong. The previous run is
                    # still adopted above as the re-check baseline.
                    break
        except Exception:
            self._last_run = None

    def start_diagnosis(self):
        query = self.problem.text().strip()
        if len(query) < 3:
            self.status.setText("Please describe the problem in a few words first.")
            return
        if self._busy or self.win.run_thread is not None or self.win.undo_thread is not None:
            self.status.setText("Wait for the current WinMend run to finish before diagnosing again.")
            return
        try:
            prepared = self.win.case_engine.questions(query)
        except Exception as exc:
            self.status.setText(f"The triage questions could not be prepared: {exc}")
            return
        self._interview_answers = {}
        self.questions = prepared.get("questions", [])[:1]
        self._profile = prepared.get("profile", "general")
        self._show_interview(prepared)

    def start_full_check(self):
        """Check everything, with no complaint and no interview."""
        if self._busy or self.win.run_thread is not None or self.win.undo_thread is not None:
            self.status.setText("Wait for the current WinMend run to finish first.")
            return
        self.interview_card.setVisible(False)
        self.questions = []
        self.answer_widgets = {}
        self._profile = WM_AUDIT_PROFILE
        self._run_sweep({}, audit=True)

    def start_hardware_scan(self):
        """Examine the components themselves, including the two live tests."""
        if self._busy or self.win.run_thread is not None or self.win.undo_thread is not None:
            self.status.setText("Wait for the current WinMend run to finish first.")
            return
        self.interview_card.setVisible(False)
        self.questions = []
        self.answer_widgets = {}
        self._profile = WM_HARDWARE_PROFILE
        self._run_sweep({}, audit=True, deep=True)

    def _show_interview(self, prepared):
        while self.question_box.count():
            item = self.question_box.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()
        self.answer_widgets = {}

        for question in self.questions:
            row = QWidget()
            row.setStyleSheet("background:transparent;")
            layout = QHBoxLayout(row)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(9)
            label = QLabel(question["text"])
            label.setWordWrap(True)
            label.setMinimumWidth(260)
            label.setStyleSheet(f"color:{self.T['text_2']};font-size:11.5px;background:transparent;")
            if question.get("help"):
                label.setToolTip(question["help"])
            layout.addWidget(label, 1)
            combo = QComboBox()
            combo.setFixedHeight(28)
            combo.setMinimumWidth(230)
            combo.setStyleSheet(
                f"QComboBox{{background:{self.T['bg']};color:{self.T['text']};"
                f"border:1px solid {self.T['border_hi']};border-radius:6px;padding:0 8px;font-size:11px;}}"
                f"QComboBox QAbstractItemView{{background:{self.T['card']};color:{self.T['text']};"
                f"selection-background-color:{self.T['accent']};}}"
            )
            combo.addItem("— choose —", "")
            for option in question["options"]:
                combo.addItem(option["label"], option["value"])
            layout.addWidget(combo)
            self.answer_widgets[question["id"]] = combo
            saved = getattr(self, "_interview_answers", {}).get(question["id"])
            if saved:
                combo.setCurrentIndex(combo.findData(saved))
            combo.currentIndexChanged.connect(lambda _i, qid=question["id"], control=combo:
                                              self._interview_answered(qid, control.currentData()))
            self.question_box.addWidget(row)

        profile_label = str(prepared.get("profile", "general")).replace("+", " + ").title()
        if prepared.get("low_confidence"):
            self.status.setText(
                "The description does not identify a specific symptom area, so these questions are general. "
                "Answering them still narrows the diagnosis."
            )
        else:
            self.status.setText(f"Treating this as a {profile_label} problem.")
        self._stage = "interview"
        self.interview_card.setVisible(True)
        self.diagnose_btn.setEnabled(False)

    def _interview_answered(self, question_id, value):
        if not value:
            return
        from winmend.diagnostics.interview import INTERVIEW_BY_ID, Interview
        answers = getattr(self, "_interview_answers", {})
        answers[question_id] = value
        self._interview_answers = answers
        asked = [INTERVIEW_BY_ID[key].as_dict() for key in answers if key in INTERVIEW_BY_ID]
        if len(asked) < Interview.MAX_QUESTIONS:
            prepared = self.win.case_engine.questions(self.problem.text(), answers=answers)
            asked += prepared.get("questions", [])[:1]
        else:
            prepared = {"profile": self._profile}
        self.questions = asked
        self._show_interview(prepared)

    def _submit_interview(self, skip=False):
        answers = {}
        if not skip:
            answers.update(getattr(self, "_interview_answers", {}))
            for question_id, combo in self.answer_widgets.items():
                value = combo.currentData()
                if value:
                    answers[question_id] = value
        self.interview_card.setVisible(False)
        self._run_sweep(answers)

    # ---- stage 2: evidence ----------------------------------------------

    def _cancel_sweep(self):
        self._sweep_cancel = True
        self.progress_label.setText("Stopping...")

    def _run_sweep(self, answers, audit=False, deep=False):
        query = ("Hardware deep scan" if deep else
                 "Full system check" if audit else self.problem.text().strip())
        self._busy = True
        self._audit = audit
        self._deep = deep
        self._sweep_cancel = False
        self.case = None
        self._render_components({})
        self.hardware_rescan_btn.setEnabled(False)
        self.diagnose_btn.setEnabled(False)
        self.full_check_btn.setEnabled(False)
        self.deep_scan_btn.setEnabled(False)
        self.run_plan_btn.setEnabled(False)
        self.recheck_btn.setEnabled(False)
        self.report_btn.setEnabled(False)
        self._render_findings([])
        self.timeline.clear()
        self.plan.clear()
        self.withheld_label.setVisible(False)
        self._clear_assessment("Working...")
        self.progress.setRange(0, 0)
        self.progress_label.setText("Running quick checks...")
        self.progress_row.setVisible(True)
        self.status.setText(
            "Checking components and event logs. The memory test writes to its own RAM buffer; "
            "drive samples are read only. No disk data or settings are changed."
            if deep else
            "Checking everything on this PC. All of these checks are read-only."
            if audit else
            "Running read-only checks. Nothing is changed during this stage."
        )
        self._stage = "sweep"
        if audit or "network" in str(getattr(self, "_profile", "")) or "time" in str(getattr(self, "_profile", "")):
            self.status.setText(self.status.text() + " Public connectivity checks use Microsoft and Cloudflare names, and bounded TCP probes to Cloudflare and Google public resolver addresses (IPv4 and IPv6 when configured); no diagnostic report is transmitted.")

        engine = self.win.case_engine
        profile = (WM_HARDWARE_PROFILE if deep else
                   WM_AUDIT_PROFILE if audit else getattr(self, "_profile", None))

        def post(callback):
            self.win.host.root.after(0, callback)

        def work():
            try:
                history = None
                try:
                    history = self.win.journal.list_sessions()
                except Exception:
                    history = None
                triage = engine.triage(query, answers, profile, cancel=lambda: self._sweep_cancel)
                post(lambda: self._show_triage(triage))
                if self._sweep_cancel:
                    post(lambda: self._sweep_cancelled())
                    return

                def progress(done, total, label):
                    post(lambda: self._sweep_progress(done, total, label))

                case = engine.build_case(
                    query, answers=answers, profile=profile, history=history,
                    progress=progress, cancel=lambda: self._sweep_cancel,
                    task_lookup=self.win.wm_task_lookup, raw=triage.get("raw"),
                    deep=deep,
                )
            except Exception as exc:
                error = str(exc)
                post(lambda: self._sweep_failed(error))
                return
            if self._sweep_cancel:
                post(lambda: self._sweep_cancelled())
                return
            post(lambda: self._show_case(case))

        self._sweep_thread = threading.Thread(target=work, daemon=True)
        self._sweep_thread.start()

    def _sweep_progress(self, done, total, label):
        if self.progress.maximum() == 0:
            self.progress.setRange(0, total)
        self.progress.setValue(done)
        self.progress_label.setText(f"{label}  ({done}/{total})")

    def _show_triage(self, triage):
        """Paint the fast findings immediately so the panel is never empty."""
        self._render_findings(triage.get("findings", []))
        self.tabs.setCurrentIndex(1)
        engine = self.win.case_engine
        remaining = len(engine.DEEP_COLLECTORS)
        if getattr(self, "_deep", False):
            remaining += len(engine.HARDWARE_COLLECTORS)
        self.progress.setRange(0, remaining)
        self.progress.setValue(0)

    def _sweep_failed(self, error):
        self._busy = False
        self.progress_row.setVisible(False)
        self.status.setText(f"The diagnostic pass could not finish: {error}")
        self._clear_assessment("The diagnosis did not complete.")
        self._update_run_button()

    def _sweep_cancelled(self):
        self._busy = False
        self.progress_row.setVisible(False)
        self.status.setText("Diagnosis cancelled. Nothing was changed.")
        self._clear_assessment("Diagnosis cancelled.")
        self._update_run_button()

    # ---- stage 4: run -----------------------------------------------------

    def _selected_steps(self):
        if not self.case:
            return []
        by_index = {step["index"]: step for step in self.case.get("plan", [])}
        chosen = []
        for row in range(self.plan.topLevelItemCount()):
            item = self.plan.topLevelItem(row)
            if item.checkState(0) == QtC.Checked:
                step = by_index.get(item.data(0, QtC.UserRole))
                if step is not None:
                    chosen.append(step)
        return chosen

    def _update_run_button(self, *_args):
        idle = self.win.run_thread is None and self.win.undo_thread is None
        self.diagnose_btn.setEnabled(idle and not self._busy and self._stage != "interview")
        self.full_check_btn.setEnabled(idle and not self._busy)
        self.deep_scan_btn.setEnabled(idle and not self._busy)
        self.hardware_rescan_btn.setEnabled(idle and not self._busy)
        self.hardware_tool_btn.setEnabled(idle and not self._busy and self.components.currentItem() is not None)
        self.run_plan_btn.setEnabled(bool(self.case and self._selected_steps()) and idle
                                     and not self._busy)
        self.run_plan_btn.setText("Run protected plan" if self.tabs.currentIndex() == 4
                                 else "Review repair plan")
        self.recheck_btn.setEnabled(idle and not self._busy and self._last_run is not None)
        self.report_btn.setEnabled(self.case is not None and not self._busy)
        latest = getattr(self, "_latest_verification", None) or {}
        self.confirm_symptom_btn.setVisible(latest.get("condition_outcome") == "resolved"
                                            and latest.get("symptom_status") == "unknown"
                                            and (self._last_run or {}).get("profile") not in (WM_AUDIT_PROFILE, WM_HARDWARE_PROFILE))
        self.confirm_symptom_btn.setEnabled(idle and not self._busy)

    def _run_plan(self):
        if self.tabs.currentIndex() != 4:
            self.tabs.setCurrentIndex(4)
            return
        steps = self._selected_steps()
        if not steps:
            return
        # Renumber so the runner's "skip the rest" logic matches what the user
        # actually chose, not the original plan's positions.
        chosen = []
        for position, step in enumerate(steps):
            copy = dict(step)
            copy["index"] = position
            chosen.append(copy)
        if self.win._start_case(self.case, chosen):
            self._last_run = {
                "problem": self.case.get("problem", ""),
                "profile": self.case.get("profile", "general"),
                "answers": self.case.get("answers", {}),
                "before": self.case,
                "session_id": None,
            }
            self.run_plan_btn.setEnabled(False)
            self.diagnose_btn.setEnabled(False)
            self.recheck_btn.setEnabled(False)
            self.status.setText(
                "Protected repair is running, one step at a time. Verification runs afterward."
            )

    def on_session_finished(self, session):
        self.diagnose_btn.setEnabled(True)
        if session and session.get("id"):
            if self._last_run is None:
                self._last_run = {
                    "problem": session.get("problem", ""),
                    "profile": (session.get("diagnosis_before") or {}).get("profile"),
                    "answers": (session.get("diagnosis_before") or {}).get("answers", {}),
                    "before": session.get("diagnosis_before") or {},
                    "session_id": session.get("id"),
                }
            else:
                self._last_run["session_id"] = session.get("id")
            self._last_run["before"] = self._execution_baseline(self._last_run["before"], session)
        verification = (session or {}).get("verification", {})
        self._latest_verification = verification
        # A verification dict that carries no outcome is not a result -- an
        # interrupted run leaves one behind, and reporting it as "Complete"
        # would claim a measurement that never happened.
        if verification.get("outcome"):
            outcome = verification["outcome"].replace("_", " ").title()
            text = f"Verification: {outcome}. {verification.get('summary', '')}"
            early = verification.get("stopped_early")
            if early:
                text += (f" Stopped after \"{early['step']}\" because {early['checks']} "
                         f"came back healthy; {len(early['skipped'])} later step(s) were "
                         f"not needed.")
            after = verification.get("after")
            if after:
                # Keep the assessment and plan visible, but move the measurements
                # to the after-state so the result is immediately readable.
                self._render_findings(after.get("findings", []))
            self.status.setText(text)
        else:
            self.status.setText(
                "The run ended before verification completed. Review the Safety Journal for details.")
        self._update_run_button()

    # ---- delayed verification and reporting --------------------------------

    def _recheck(self):
        """Repeat the last guided run's checks against its pre-repair baseline.

        Fixes that need a restart can only be judged afterward; this also fills
        in the verification of a session the restart itself interrupted."""
        reference = self._last_run
        if (reference is None or self._busy or self.win.run_thread is not None
                or self.win.undo_thread is not None):
            return
        self._busy = True
        self.diagnose_btn.setEnabled(False)
        self.recheck_btn.setEnabled(False)
        self.status.setText("Re-running the original read-only checks to verify the earlier repair...")
        self.progress.setRange(0, 0)
        self.progress_label.setText("Re-checking...")
        self.progress_row.setVisible(True)

        def post(callback):
            self.win.host.root.after(0, callback)

        def work():
            try:
                after = self.win.case_engine.build_case(
                    reference.get("problem", ""), answers=reference.get("answers"),
                    profile=reference.get("profile"), task_lookup=self.win.wm_task_lookup,
                    history=[{"attempts": (reference.get("before") or {}).get("attempts", [])}])
                verification = self.win.diagnostic_engine.compare(
                    reference.get("before") or {}, after)
                verification["after"] = after
            except Exception as exc:
                error = str(exc)
                post(lambda: self._recheck_failed(error))
                return
            post(lambda: self._show_recheck(verification))

        self._sweep_thread = threading.Thread(target=work, daemon=True)
        self._sweep_thread.start()

    def _recheck_failed(self, error):
        self._busy = False
        self.progress_row.setVisible(False)
        self.status.setText(f"The re-check could not finish: {error}")
        self._update_run_button()

    def _show_recheck(self, verification):
        self._busy = False
        self._latest_verification = verification
        self.progress_row.setVisible(False)
        outcome = verification.get("outcome", "complete").replace("_", " ").title()
        after = verification.get("after") or {}
        if after:
            self._show_case(after)
        self.status.setText(f"Re-check: {outcome}. {verification.get('summary', '')}")
        session_id = (self._last_run or {}).get("session_id")
        if session_id:
            try:
                self.win.journal.set_verification(session_id, verification)
                if self.win.journal_page is not None:
                    self.win.journal_page.refresh(select_id=session_id)
            except Exception:
                pass
        self._update_run_button()

    def _confirm_symptom(self):
        latest = getattr(self, "_latest_verification", None) or {}
        after = latest.get("after")
        if not after or not self._last_run:
            return
        answer = QMessageBox.question(self, "Original symptom", "Has the original problem stopped under the same conditions?",
                                      QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel, QMessageBox.Cancel)
        if answer == QMessageBox.Cancel:
            return
        after["symptom_resolved"] = answer == QMessageBox.Yes
        verification = self.win.diagnostic_engine.compare(self._last_run.get("before") or {}, after)
        verification["attempts"] = latest.get("attempts", [])
        verification["performed"] = latest.get("performed", [])
        self._show_recheck(verification)

    def _export_report(self):
        if not self.case:
            return
        verification = None
        performed = ()
        session_id = (self._last_run or {}).get("session_id")
        if session_id:
            try:
                session = self.win.journal.get_session(session_id) or {}
                verification = session.get("verification") or None
                performed = (verification or {}).get("performed") or ()
            except Exception:
                verification = None
        try:
            html = render_case_report_html(self.case, verification, performed)
        except Exception as exc:
            QMessageBox.warning(self, "Report", f"The report could not be produced: {exc}")
            return
        stamp = time.strftime("%Y-%m-%d_%H%M%S")
        # The real Desktop: with OneDrive folder backup, %USERPROFILE%\Desktop
        # does not exist and the dialog opened on a folder it could not show.
        default = os.path.join(self.win.host._get_desktop_dir(), f"WinMend_case_{stamp}.html")
        path, _filter = QFileDialog.getSaveFileName(
            self, "Save case report", default, "Web page (*.html)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as stream:
                stream.write(html)
        except OSError as exc:
            QMessageBox.warning(self, "Report", f"The report could not be saved: {exc}")
            return
        self.status.setText(f"Case report saved to {path}")
        try:
            webbrowser.open(Path(path).as_uri())
        except Exception:
            pass
