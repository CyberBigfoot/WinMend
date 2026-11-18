"""WinMend ui: window workflows."""

from __future__ import annotations

from PySide6.QtWidgets import QMessageBox
from winmend.core.processes import _no_console_startupinfo, wm_run
from winmend.ui.widgets.hypothesis import WMStepShim
import threading


class WindowWorkflowsMixin:
    """WMMainWindow methods grouped by responsibility."""

    def _start_case(self, case, steps):
        """Run an adaptive guided plan: step, re-measure, stop when it clears."""
        if not steps or self.run_thread is not None or self.undo_thread is not None:
            return False

        risky = [s for s in steps if s.get("risk") == "destructive" or s.get("confirm")]
        if risky:
            lines = []
            for step in risky:
                suffix = ("" if step.get("reversible")
                          else "  (cannot be undone automatically)")
                lines.append(f"  •  {step['title']}{suffix}")
            protected = any(s.get("restore_point") for s in risky)
            message = (
                "These steps change or remove something specific:\n\n"
                + "\n".join(lines) + "\n\n"
                + ("A System Restore point will be created first, so the whole session "
                   "can be rolled back.\n\n" if protected else "")
                + "Continue?")
            if QMessageBox.question(self, "Confirm the repair plan", message,
                                    QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
                self._log("Cancelled — nothing was changed.", self.T['text_3'])
                return False

        case["verification_targets"] = list(dict.fromkeys(k for s in steps if not s.get("read_only")
                                                          for k in s.get("verify_keys", [])))
        case["selected_repair_ids"] = [s["id"] for s in steps if not s.get("read_only")]
        case["restart_expected_ids"] = [s["id"] for s in steps if s.get("reboot")]
        planned = [{
            "id": step["id"],
            "title": step["title"],
            "risk": step.get("risk", "caution"),
            "restore_point": bool(step.get("restore_point")),
        } for step in steps]
        session_id = None
        try:
            session_id = self.journal.start_session(
                "guided", planned, problem=case.get("problem", ""), diagnosis=case)
        except Exception as exc:
            self._log(f"Safety Journal is unavailable for this run: {exc}", self.T['warn'])
            if any(not s.get("read_only") for s in steps):
                self._log("Protected changes were withheld because their safety records could not be saved.", self.T['warn'])
                return False

        self.host.cancel_event.clear()
        self.pending = [WMStepShim(step) for step in steps]
        self.finished = []
        self._run_task_ids = [s["id"] for s in steps if s["kind"] == "task"]
        self.active_session_id = session_id
        self._rebuild_queue()
        self.run_btn.setEnabled(False)
        self.run_thread = threading.Thread(
            target=self._case_worker, args=(list(steps), session_id, case), daemon=True)
        self.run_thread.start()
        return True

    def _start(self, tasks, workflow=None):
        if not tasks or self.run_thread is not None or self.undo_thread is not None:
            return False
        # Destructive tasks: say plainly what happens, then let them proceed.
        risky = [t for t in tasks if t.risk == "destructive"]
        if risky:
            names = "\n".join(f"  •  {t.title}" for t in risky)
            rp = any(t.restore_point for t in risky)
            msg = (f"These remove software or reset large parts of Windows:\n\n{names}\n\n"
                   + ("A System Restore point will be created first, so this can be "
                      "rolled back.\n\n" if rp else "")
                   + "Continue?")
            if QMessageBox.question(self, "Confirm", msg,
                                    QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
                self._log("Cancelled — nothing was changed.", self.T['text_3'])
                return

        planned = [{
            "id": task.id,
            "title": task.title,
            "risk": task.risk,
            "restore_point": task.restore_point,
        } for task in tasks]
        session_id = None
        try:
            session_id = self.journal.start_session(
                "guided" if workflow else "manual",
                planned,
                problem=(workflow or {}).get("problem", ""),
                diagnosis=(workflow or {}).get("diagnosis"),
            )
        except Exception as exc:
            self._log(f"Safety Journal is unavailable for this run: {exc}", self.T['warn'])

        self.host.cancel_event.clear()
        self.pending = list(tasks)
        self.finished = []
        # Remembered so the checkboxes for exactly this run can be cleared when it
        # finishes -- not the whole current selection, which may include tasks on
        # other pages or a single-card Run that was never checked.
        self._run_task_ids = [t.id for t in tasks]
        self.active_session_id = session_id
        self._rebuild_queue()
        self.run_btn.setEnabled(False)
        self.run_thread = threading.Thread(
            target=self._worker, args=(list(tasks), session_id, workflow), daemon=True
        )
        self.run_thread.start()
        return True

    def request_stop(self):
        self.host.cancel_event.set()
        self._log("Stopping… the running process is being terminated.", self.T['warn'])

    def _undo_session(self, session_id):
        if self.run_thread is not None or self.undo_thread is not None:
            QMessageBox.information(self, "WinMend is busy", "Wait for the current operation to finish first.")
            return
        if not self.host.admin_status:
            QMessageBox.warning(
                self, "Administrator rights required",
                "Restart WinMend as administrator to roll back a protected session."
            )
            return
        session = self.journal.get_session(session_id)
        # Only a number WinMend sealed when it made the checkpoint. The journal
        # file can be edited by any program, and this rolls the machine back.
        sequence = self.journal.verified_restore_point(session_id)
        if sequence is None:
            QMessageBox.information(
                self, "Exact checkpoint unavailable",
                "WinMend does not have a restore-point number it can confirm for this session. "
                "Use Open System Restore to review the available checkpoints."
            )
            return

        covered = [task.get("title", task.get("id", "Task"))
                   for task in session.get("tasks", []) if task.get("restore_point")]
        uncovered = [task.get("title", task.get("id", "Task"))
                     for task in session.get("tasks", []) if not task.get("restore_point")]
        message = (
            f"Roll Windows back to WinMend restore point #{sequence}?\n\n"
            "Windows will reboot. System settings, drivers, system files, and installed apps "
            "covered by System Restore can be reverted.\n\n"
        )
        if covered:
            message += "Covered session task(s):\n  - " + "\n  - ".join(covered[:8]) + "\n\n"
        if uncovered:
            message += (
                "Not recoverable through System Restore:\n  - " + "\n  - ".join(uncovered[:8]) +
                "\n\nDeleted temporary/cache files and personal files cannot be restored by this action.\n\n"
            )
        message += "Save your work before continuing."
        if QMessageBox.question(
                self, "Undo WinMend session", message,
                QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return

        try:
            self.journal.mark_undo_requested(session_id)
        except Exception as exc:
            QMessageBox.critical(self, "Safety Journal", f"Could not record the undo request: {exc}")
            return
        if self.journal_page is not None:
            self.journal_page.refresh(select_id=session_id)
        self._log(f"Starting rollback to restore point #{sequence}...", self.T['warn'])

        def work():
            try:
                result = wm_run(
                    ["powershell", "-NoProfile", "-ExecutionPolicy", "RemoteSigned", "-Command",
                     f"Restore-Computer -RestorePoint {int(sequence)} -Confirm:$false"],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=90, startupinfo=_no_console_startupinfo(),
                )
                if result.returncode == 0:
                    self.host.queue.put(
                        f"UNDORESULT:{session_id}:ok:Rollback was accepted. Windows will restart."
                    )
                else:
                    detail = (result.stderr or result.stdout or f"return code {result.returncode}").strip()
                    self.host.queue.put(f"UNDORESULT:{session_id}:fail:{detail[:500]}")
            except Exception as exc:
                self.host.queue.put(f"UNDORESULT:{session_id}:fail:{str(exc)[:500]}")

        self.undo_thread = threading.Thread(target=work, daemon=True)
        self.undo_thread.start()
