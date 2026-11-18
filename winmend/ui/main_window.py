"""WinMend ui: main window."""

from __future__ import annotations

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QHBoxLayout, QMainWindow, QMessageBox, QWidget
from winmend.core.paths import application_root
from winmend.core.processes import wm_kill_children
from winmend.core.task_runner import TaskRunnerMixin
from winmend.data.task_catalog import WM_TASKS
from winmend.diagnostics.engine import CaseEngine
from winmend.diagnostics.profiles import DiagnosticEngine
from winmend.safety.journal import SafetyJournal
from winmend.ui.dialogs import WMMessageBox, WMSimpleDialog
from winmend.ui.task_host import WMTaskHost
from winmend.ui.window_navigation import WindowNavigationMixin
from winmend.ui.window_queue import WindowQueueMixin
from winmend.ui.window_workflows import WindowWorkflowsMixin

import os
import sys


class WMMainWindow(
    WindowNavigationMixin,
    WindowWorkflowsMixin,
    TaskRunnerMixin,
    WindowQueueMixin,
    QMainWindow,
):
    """WinMend 2.0 shell."""

    def __init__(self, theme_tokens):
        super().__init__()
        # Pages share this dict so custom painters see session theme changes.
        self.T = dict(theme_tokens)
        self._theme_curtain = None
        self.simple = True
        self.current_cat = "dashboard"
        self.cards = []
        self.queue_rows = []
        self.run_thread = None
        self.undo_thread = None
        self.running_task = None
        self.run_started = None
        self.pending = []
        self.finished = []
        self._run_task_ids = []
        # Restart recommendations raised by tasks during the current run; asked
        # about once, when the whole run finishes.
        self._reboot_reasons = []
        self.active_session_id = None
        self.journal = SafetyJournal()
        self.journal.recover_interrupted_sessions()
        self.diagnostic_engine = DiagnosticEngine()
        # The IT Desk reasoning layer shares the classic engine's probe so both
        # agree on what they are measuring, and is told how to resolve a task id
        # to this build's real WM_TASKS metadata.
        self.case_engine = CaseEngine(engine=self.diagnostic_engine)
        self.guided_page = None
        self.journal_page = None

        self.setWindowTitle("WinMend")
        # Never open taller (or wider) than the screen's work area. Opening at a
        # fixed 850px on a laptop-height display (e.g. 1366x768) pushed the bottom
        # of the window — the selection bar with the Run button — below the
        # taskbar, so it only appeared once the window was maximised. Clamp the
        # initial size to what actually fits and centre it.
        self.setMinimumSize(1040, 600)
        screen = QApplication.primaryScreen()
        if screen is not None:
            avail = screen.availableGeometry()
            w = max(1040, min(1320, avail.width() - 60))
            h = max(600, min(850, avail.height() - 60))
            self.resize(w, h)
            self.move(avail.x() + max(0, (avail.width() - w) // 2),
                      avail.y() + max(0, (avail.height() - h) // 2))
        else:
            self.resize(1320, 850)
        try:
            base = str(application_root())
            ico = os.path.join(base, "icon.ico")
            if os.path.exists(ico):
                from PySide6.QtGui import QIcon
                self.setWindowIcon(QIcon(ico))
        except Exception:
            pass

        self.host = WMTaskHost(self)
        WMMessageBox.host = self.host
        WMSimpleDialog.host = self.host

        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._build_sidebar())
        root.addWidget(self._build_center(), 1)
        root.addWidget(self._build_right())
        self._apply_window_style()

        # Drain the task queue on the UI thread. This replaces tkinter's
        # after()-loop; the 753 self.queue.put() calls in task code are
        # untouched and feed straight into this.
        self.pump = QTimer(self)
        self.pump.timeout.connect(self._drain_queue)
        self.pump.start(120)

        self.tick = QTimer(self)
        self.tick.timeout.connect(self._tick_elapsed)
        self.tick.start(1000)

        self._show_category("dashboard")

    # ---- selection + running ----

    def _on_toggle(self, task_id, checked):
        v = self.host.vars.get(task_id)
        if v is not None:
            v.set(checked)
        self._update_selection()

    def _selected(self):
        return [t for t in WM_TASKS if self.host.vars[t.id].get()]

    def _update_selection(self):
        sel = self._selected()
        n = len(sel)
        self.sel_label.setText("Nothing selected" if not n else
                               f"{n} task{'s' if n > 1 else ''} selected")
        self.run_btn.setEnabled(bool(n) and self.run_thread is None and self.undo_thread is None)
        self.run_btn.setText(f"Run {n} task{'s' if n > 1 else ''}" if n else "Run selected")
        needs_rp = [t for t in sel if t.restore_point]
        self.rp_label.setText("⛨  Restore point will be created first" if needs_rp else "")
        # So the checklist lists what has been ticked, not just a count of it.
        self._rebuild_queue()

    def _uncheck_tasks(self, task_ids):
        """Clear the selection for the given tasks once their run has finished.

        Clears the persisted state for every id (so tasks whose category page
        isn't currently built are cleared too) and syncs any visible card
        checkbox. Signals are blocked while syncing so this doesn't re-enter
        _on_toggle for each card -- the state is already cleared."""
        ids = {tid for tid in (task_ids or [])}
        if not ids:
            return
        for tid in ids:
            v = self.host.vars.get(tid)
            if v is not None:
                v.set(False)
        for card in list(self.cards):
            try:
                if card.task.id in ids and card.cb.isChecked():
                    card.cb.blockSignals(True)
                    card.cb.setChecked(False)
                    card.cb.blockSignals(False)
            except RuntimeError:
                pass  # card was torn down (page rebuilt mid-run)
        self._update_selection()

    def _run_one(self, task):
        if self.run_thread is not None or self.undo_thread is not None:
            self._log("A task is already running — wait for it to finish or press Stop.",
                      self.T['warn'])
            return
        self._start([task])

    def _run_selected(self):
        sel = self._selected()
        if sel:
            self._start(sel)

    def wm_task_lookup(self, task_id):
        """Resolve a task id to this build's real WM_TASKS metadata.

        Injected into the case engine so its plans quote the app's own titles,
        runtimes, and risk levels rather than a guess.
        """
        task = next((t for t in WM_TASKS if t.id == task_id), None)
        if task is None:
            return None
        return {
            "title": task.display_title(self.simple),
            "duration": DiagnosticEngine.TASK_DURATIONS.get(task_id, task.duration_label()),
            "risk": task.risk,
            "restore_point": task.restore_point,
            "admin": task.admin,
            "reboot": task.reboot,
        }

    def closeEvent(self, e):
        if self.undo_thread is not None:
            QMessageBox.information(
                self, "System Restore is starting",
                "Wait for Windows to accept the rollback request before closing WinMend."
            )
            e.ignore()
            return
        if self.run_thread is not None:
            if QMessageBox.question(
                    self, "Quit WinMend",
                    "A task is still running. Stop it and quit?",
                    QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
                e.ignore()
                return
            self.host.cancel_event.set()
        panel = getattr(self, "winget_panel", None)
        if panel is not None and panel.busy():
            if QMessageBox.question(
                    self, "Quit WinMend",
                    "An app update is still running. Cancel it and quit?",
                    QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
                e.ignore()
                return
            panel._cancelled = True
        apps = getattr(self, "apps_page", None)
        if apps is not None and (apps._busy or apps.proc is not None):
            if QMessageBox.question(
                    self, "Quit WinMend",
                    "An app install is still running. Cancel it and quit?",
                    QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
                e.ignore()
                return
            apps._cancelled = True
        speed = getattr(self, "speedtest_page", None)
        if speed is not None and speed.running:
            speed.cancel_event.set()  # background test; no need to block the quit
        # The task threads are daemons, so once this window closes Python drops
        # them mid-step -- before they notice the cancel and end what they
        # started. End every tracked process tree here instead, then give the
        # task a moment to unwind (its next poll sees the cancel).
        wm_kill_children()
        if self.run_thread is not None:
            self.run_thread.join(timeout=3)
        e.accept()
