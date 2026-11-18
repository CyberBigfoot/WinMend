"""WinMend ui: pages: journal."""

from __future__ import annotations

from PySide6.QtCore import Qt as QtC
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)
from datetime import datetime
from winmend.diagnostics.repairs.catalog import REPAIR_ACTIONS
from winmend.features.storage.tree import wm_duration


class WMSafetyJournalPage(QWidget):
    """Review durable run history and launch an exact protected rollback."""

    def __init__(self, window):
        super().__init__()
        self.win = window
        self.T = window.T
        self.current_session_id = None
        self.setStyleSheet("background:transparent;")
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(9)

        note = QLabel(
            "The journal stores the problem description you typed, task names, outcomes, protection checkpoints, "
            "and verification summaries. It does not store command output, passwords, or discovered file paths."
        )
        note.setWordWrap(True)
        note.setStyleSheet(f"color:{self.T['text_3']};font-size:11px;background:transparent;")
        root.addWidget(note)

        split = QSplitter(QtC.Vertical)
        split.setStyleSheet(f"QSplitter::handle{{background:{self.T['border']};height:2px;}}")
        self.sessions = QTreeWidget()
        self.sessions.setColumnCount(5)
        self.sessions.setHeaderLabels(["When", "Workflow", "Result", "Tasks", "Protection"])
        self.sessions.setRootIsDecorated(False)
        self.sessions.setStyleSheet(self._tree_style())
        self.sessions.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.sessions.header().setSectionResizeMode(1, QHeaderView.Stretch)
        self.sessions.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.sessions.header().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.sessions.header().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.sessions.itemSelectionChanged.connect(self._selection_changed)
        split.addWidget(self.sessions)

        detail = QFrame()
        detail.setObjectName("journalDetail")
        detail.setStyleSheet(
            f"#journalDetail{{background:{self.T['card']};border:1px solid {self.T['border']};border-radius:8px;}}"
        )
        dv = QVBoxLayout(detail)
        dv.setContentsMargins(12, 10, 12, 10)
        dv.setSpacing(7)
        self.detail_title = QLabel("Select a journal entry")
        self.detail_title.setStyleSheet(f"color:{self.T['text']};font-size:13px;font-weight:650;background:transparent;")
        dv.addWidget(self.detail_title)
        self.detail_summary = QLabel("Every run in the default interface appears here.")
        self.detail_summary.setWordWrap(True)
        self.detail_summary.setStyleSheet(f"color:{self.T['text_3']};font-size:11px;background:transparent;")
        dv.addWidget(self.detail_summary)
        self.task_rows = QTreeWidget()
        self.task_rows.setColumnCount(4)
        self.task_rows.setHeaderLabels(["Task", "Result", "Duration", "Protection scope"])
        self.task_rows.setRootIsDecorated(False)
        self.task_rows.setStyleSheet(self._tree_style())
        self.task_rows.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.task_rows.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.task_rows.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.task_rows.header().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        dv.addWidget(self.task_rows, 1)
        buttons = QHBoxLayout()
        self.protection_note = QLabel("")
        self.protection_note.setWordWrap(True)
        self.protection_note.setStyleSheet(f"color:{self.T['text_3']};font-size:10px;background:transparent;")
        dv.addWidget(self.protection_note)
        buttons.addStretch()
        refresh = QPushButton("Refresh")
        refresh.setCursor(QtC.PointingHandCursor)
        refresh.clicked.connect(self.refresh)
        buttons.addWidget(refresh)
        self.restore_app = QPushButton("Open System Restore")
        self.restore_app.setCursor(QtC.PointingHandCursor)
        self.restore_app.clicked.connect(self.win._open_system_restore)
        buttons.addWidget(self.restore_app)
        # Targeted repairs record what they overwrote, so they can be put back
        # precisely rather than by rolling the whole machine back.
        self.reverse_btn = QPushButton("Reverse changes")
        self.reverse_btn.setCursor(QtC.PointingHandCursor)
        self.reverse_btn.setVisible(False)
        self.reverse_btn.clicked.connect(self._reverse_selected)
        buttons.addWidget(self.reverse_btn)
        self.undo = QPushButton("Undo this session")
        self.undo.setCursor(QtC.PointingHandCursor)
        self.undo.setEnabled(False)
        self.undo.setStyleSheet(
            f"QPushButton{{background:{self.T['accent']};color:#fff;border:none;border-radius:6px;padding:6px 12px;font-weight:600;}}"
            f"QPushButton:hover{{background:{self.T['accent_hi']};}}"
            f"QPushButton:disabled{{background:{self.T['card_hi']};color:{self.T['text_3']};}}"
        )
        self.undo.clicked.connect(self._undo_selected)
        buttons.addWidget(self.undo)
        dv.addLayout(buttons)
        split.addWidget(detail)
        split.setSizes([245, 300])
        root.addWidget(split, 1)
        self.refresh()

    def _tree_style(self):
        return (
            f"QTreeWidget{{background:{self.T['card']};color:{self.T['text_2']};border:1px solid {self.T['border']};"
            "border-radius:7px;font-size:11px;outline:none;}"
            "QTreeWidget::item{height:27px;}"
            f"QTreeWidget::item:selected{{background:{self.T['accent']};color:#fff;}}"
            f"QHeaderView::section{{background:{self.T['sidebar']};color:{self.T['text_3']};border:none;"
            f"border-bottom:1px solid {self.T['border']};padding:5px;font-size:10px;font-weight:600;}}"
        )

    @staticmethod
    def _when(value):
        try:
            return datetime.fromisoformat(value).astimezone().strftime("%b %d, %Y  %I:%M %p")
        except Exception:
            return value or "Unknown"

    def refresh(self, select_id=None):
        select_id = select_id or self.current_session_id
        self.sessions.clear()
        selected_item = None
        for session in self.win.journal.list_sessions():
            protection = session.get("protection", {})
            source = {"guided": "Guided Fix",
                      "startup": "Startup Manager",
                      "winget": "App updates"}.get(session.get("source"), "Manual run")
            workflow = session.get("problem") or source
            result = session.get("verification", {}).get("outcome") or session.get("status", "unknown")
            result = str(result).replace("_", " ").title()
            protection_text = (f"Restore point #{protection.get('sequence')}"
                               if protection.get("sequence") is not None else
                               "Created; use browser" if protection.get("created") else
                               "Not requested" if not protection.get("requested") else "Unavailable")
            item = QTreeWidgetItem([
                self._when(session.get("started_at")), workflow, result,
                str(len(session.get("tasks", []))), protection_text,
            ])
            item.setData(0, QtC.UserRole, session.get("id"))
            if result in ("Resolved", "Improved", "Healthy", "Complete"):
                item.setForeground(2, QColor(self.T['ok']))
            elif result in ("Failed", "Interrupted", "Needs Attention", "Not Resolved"):
                item.setForeground(2, QColor(self.T['danger']))
            self.sessions.addTopLevelItem(item)
            if session.get("id") == select_id:
                selected_item = item
        if selected_item is not None:
            self.sessions.setCurrentItem(selected_item)
        elif self.sessions.topLevelItemCount():
            self.sessions.setCurrentItem(self.sessions.topLevelItem(0))
        else:
            self.current_session_id = None
            self.detail_title.setText("No journal entries yet")
            self.detail_summary.setText("Run a task or use Guided Fix and the protected session will appear here.")
            self.task_rows.clear()
            self.undo.setEnabled(False)

    def _selection_changed(self):
        items = self.sessions.selectedItems()
        if not items:
            return
        self.current_session_id = items[0].data(0, QtC.UserRole)
        session = self.win.journal.get_session(self.current_session_id)
        if not session:
            return
        self.detail_title.setText(session.get("problem") or {
            "guided": "Guided Fix",
            "startup": "Startup Manager",
            "winget": "App updates (winget)"}.get(session.get("source"), "Manual WinMend run"))
        verification = session.get("verification", {})
        summary = verification.get("summary") or f"Session status: {session.get('status', 'unknown').replace('_', ' ')}."
        self.detail_summary.setText(summary)
        self.task_rows.clear()
        protection = session.get("protection", {})
        # Only steps whose undo record still matches the seal WinMend wrote:
        # the journal file itself can be edited by any program.
        reversible = self.win.journal.reversible_steps(self.current_session_id)
        trusted = {t.get("id") for t in reversible}
        for task in session.get("tasks", []):
            duration = task.get("duration_seconds")
            duration_text = wm_duration(duration) if duration is not None else "-"
            scope = ("Covered by checkpoint" if task.get("restore_point") and protection.get("created")
                     else "Checkpoint unavailable" if task.get("restore_point") else "Not covered")
            state = task.get("state", "unknown")
            state_text = {
                "done": "Completed", "failed": "Failed", "skipped": "Skipped",
                "cancelled": "Cancelled", "interrupted": "Interrupted",
                "running": "Running", "queued": "Queued",
            }.get(state, state.replace("_", " ").title())
            # A targeted repair records exactly what it changed, so its own
            # undo is more precise than a whole-session restore point.
            unverified = False
            if task.get("undo_state") == "available" and task.get("id") in trusted:
                scope = "Individually reversible"
            elif task.get("undo_state") in ("available", "unsealed") and task.get("undo_payload"):
                scope = "Undo record unverified"
                unverified = True
            elif task.get("undo_state") == "reversed":
                scope = "Reversed"
            item = QTreeWidgetItem([
                task.get("title", task.get("id", "Task")),
                state_text,
                duration_text, scope,
            ])
            if task.get("note"):
                item.setToolTip(1, task["note"])
            if unverified:
                item.setToolTip(3, "WinMend could not confirm this undo record is the one it wrote "
                                   "(it may have been recorded without administrator rights, before "
                                   "this check existed, or changed since), so it will not replay it. "
                                   "The session restore point, if there is one, still applies.")
            if state == "done":
                item.setForeground(1, QColor(self.T['ok']))
            elif state in ("failed", "interrupted"):
                item.setForeground(1, QColor(self.T['danger']))
            if task.get("id") in trusted and task.get("undo_state") == "available":
                item.setForeground(3, QColor(self.T['ok']))
            self.task_rows.addTopLevelItem(item)

        self.reverse_btn.setVisible(bool(reversible))
        self.reverse_btn.setEnabled(
            bool(reversible) and self.win.run_thread is None and self.win.undo_thread is None)
        if reversible:
            self.reverse_btn.setText(
                f"Reverse {len(reversible)} change{'' if len(reversible) == 1 else 's'}")
            self.reverse_btn.setToolTip(
                "Put back exactly what these steps changed, using the values recorded "
                "at the time:\n" + "\n".join(f"  •  {t.get('title', t['id'])}" for t in reversible))

        undo = session.get("undo", {})
        if protection.get("created"):
            self.protection_note.setText(
                "System Restore can reverse covered settings, drivers, system files, and installed apps. "
                "It cannot bring back deleted temp/cache files or personal files."
            )
        elif protection.get("requested"):
            self.protection_note.setText("A restore point was requested but Windows did not provide an exact rollback checkpoint.")
        else:
            self.protection_note.setText("This run did not contain a task that Windows System Restore can roll back.")
        if (protection.get("sequence") is not None
                and self.win.journal.verified_restore_point(self.current_session_id) is None):
            self.protection_note.setText(
                "WinMend could not confirm this restore-point number is the one it recorded, so it "
                "will not roll back to it automatically. Open System Restore to choose a point yourself.")
        can_undo = bool(undo.get("available") and undo.get("status") != "requested"
                        and self.win.run_thread is None and self.win.undo_thread is None
                        and self.win.host.admin_status
                        and self.win.journal.verified_restore_point(self.current_session_id) is not None)
        self.undo.setEnabled(can_undo)
        self.undo.setText("Undo requested" if undo.get("status") == "requested" else "Undo this session")

    def _undo_selected(self):
        if self.current_session_id:
            self.win._undo_session(self.current_session_id)

    def _reverse_selected(self):
        """Put back exactly what this session's targeted repairs changed."""
        if not self.current_session_id:
            return
        if self.win.run_thread is not None or self.win.undo_thread is not None:
            QMessageBox.information(self, "WinMend is busy",
                                    "Wait for the current run to finish first.")
            return
        try:
            steps = self.win.journal.reversible_steps(self.current_session_id)
        except Exception as exc:
            QMessageBox.warning(self, "Reverse changes", f"The journal could not be read: {exc}")
            return
        if not steps:
            return
        names = "\n".join(f"  •  {step.get('title', step['id'])}" for step in steps)
        if QMessageBox.question(
            self, "Reverse these changes?",
            f"WinMend will restore what these steps changed, using the values it recorded "
            f"at the time:\n\n{names}\n\nContinue?",
            QMessageBox.Yes | QMessageBox.No,
        ) != QMessageBox.Yes:
            return

        reversed_count = 0
        problems = []
        for step in steps:
            action = REPAIR_ACTIONS.get(step["id"])
            if action is None or not action.reversible:
                problems.append(f"{step.get('title', step['id'])}: no automatic undo.")
                continue
            result = action.undo(step.get("undo_payload"))
            if result["ok"]:
                reversed_count += 1
                try:
                    self.win.journal.set_step_undo_state(
                        self.current_session_id, step["id"], "reversed")
                except Exception:
                    pass
            else:
                problems.append(f"{step.get('title', step['id'])}: {result['message']}")

        message = (f"Reversed {reversed_count} change"
                   f"{'' if reversed_count == 1 else 's'}.")
        if problems:
            message += "\n\nNot reversed:\n" + "\n".join(f"  •  {p}" for p in problems)
        QMessageBox.information(self, "Reverse changes", message)
        self.refresh(select_id=self.current_session_id)
