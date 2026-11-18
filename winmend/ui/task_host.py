"""WinMend ui: task host."""

from __future__ import annotations

from PySide6.QtCore import Qt as QtC
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)
from winmend.core.state import WMBoolVar
from winmend.core.activity import TaskActivityQueue
from winmend.core.task_host_base import SystemCleanerGUI
from winmend.data.task_catalog import WM_TASKS
from winmend.ui.dialogs import WMMessageBox, WMRootStub
from winmend.ui.theme import WM_FONT_MONO
from winmend.ui.widgets.controls import WMCheckBox
import re
import subprocess
import threading


class WMTaskHost(SystemCleanerGUI):
    """The Qt-side task host: every task implementation, driven from the Qt UI.

    Subclasses SystemCleanerGUI to inherit every proven task method and supplies
    what those bodies reach for -- the queue, the selection vars, the cancel
    event, and Qt versions of the seams that used to write to tk widgets
    (log_message, show_progress, the prompts).

    This is what made the migration safe, and what let the old UI be deleted
    without touching the code that talks to DISM, SFC and the registry: that
    code is inherited byte-for-byte, not rewritten.
    """

    def __init__(self, window):
        self.window = window
        self.root = WMRootStub(window)
        self._ui_thread_id = threading.get_ident()
        self.queue = TaskActivityQueue()
        self.cancel_event = threading.Event()
        self.widgets = []
        self.widget_fonts = {}
        self.font_size_factor = 1.0
        self.task_progress = {}
        self.total_tasks = 0
        self.completed_tasks = 0
        self.progress_active = False
        self._progress_tasks = []
        self._cached_task_var_map = None
        # Set by _report_failure() while a task runs; the runners reset it
        # before each handler and read it afterwards.
        self._task_failure = None
        self._task_skip = None
        self.admin_status = self.is_admin()

        # One WMBoolVar per task, named exactly as the legacy attribute so the
        # inherited _task_var_map() and run_selected_tasks() resolve unchanged.
        #
        # Two task ids -- stop_background_apps and disable_startup_apps -- are
        # also the names of the executor methods that run them. Binding the var
        # to that attribute shadows the method, and execute_tasks() then dies on
        # "'WMBoolVar' object is not callable" the moment the task runs. The
        # legacy class hit the same clash and parked those vars under
        # "<id>_var", which is what _task_var_map() already looks up, so mirror
        # that whenever the id collides with a real method.
        self.vars = {}
        for t in WM_TASKS:
            v = WMBoolVar(False)
            self.vars[t.id] = v
            attr = f"{t.id}_var" if callable(getattr(type(self), t.id, None)) else t.id
            setattr(self, attr, v)
        # legacy attribute aliases where the var name differs from the task id
        self.stop_background_apps_var = self.vars.get("stop_background_apps")
        self.disable_startup_apps_var = self.vars.get("disable_startup_apps")
        self.create_restore_point_guardrail = self.vars.get(
            "create_restore_point_guardrail") or WMBoolVar(False)

    # ---- UI seams: these wrote to tk widgets; now they feed the Qt log ----

    def log_message(self, message, task_name=None):
        safe = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', str(message))
        self.queue.put(f"LOG:{task_name or ''}:{safe}")

    def show_progress(self, show=True, tasks=None):
        self.progress_active = bool(show)

    def update_progress_info(self, task_name=None, info=None):
        if info:
            self.queue.put(f"PROGRESS:{task_name or ''}:{info}")

    def _update_overall_progress(self, task_id=None, task_pct=None, mark_done=False):
        return None

    def run_restart_windows(self):
        """Guided-plan task: restart the PC after confirmation and a 60s countdown."""
        label = "Restart Windows"
        if not WMMessageBox.askyesno(
                "Restart Windows",
                "Windows will restart after a 60-second countdown so open work can "
                "be saved.\n\nSave your documents first. The countdown can be "
                "cancelled afterwards by running 'shutdown /a'.\n\nRestart now?"):
            self._report_skip(f"PROGRESS:{label}:Restart declined — nothing was scheduled.")
            return
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        result = subprocess.run(
            ["shutdown", "/r", "/t", "60",
             "/c", "WinMend: restarting to finish the repair plan."],
            capture_output=True, text=True, creationflags=flags)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip() or f"exit code {result.returncode}"
            raise RuntimeError(f"Windows refused the restart request: {detail}")
        self.queue.put(f"PROGRESS:{label}:Restart scheduled in 60 seconds. Run 'shutdown /a' to cancel it.")

    def _ui_radio_picker(self, title, prompt, options, default=None):
        """Qt replacement for the tkinter radio picker.

        Same contract as the original: options is a list of (key, label) and the
        selected key -- or None if cancelled -- comes back. Keeping the signature
        identical means the four callers (power plan, optional features, restore
        browser, UWP reset) need no changes.

        Called from worker threads, so it is marshalled to the UI thread and
        blocks the caller for the answer, exactly as the modal tk dialog did.
        """
        def _show():
            from PySide6.QtWidgets import (QDialog, QRadioButton, QDialogButtonBox,
                                           QButtonGroup)
            T = self.window.T
            dlg = QDialog(self.window)
            dlg.setWindowTitle(title)
            dlg.setMinimumWidth(470)
            dlg.setStyleSheet(f"QDialog{{background:{T['bg']};}}"
                              f"QLabel{{color:{T['text']};font-size:13px;}}"
                              f"QRadioButton{{color:{T['text_2']};font-size:13px;"
                              f"padding:5px 0;}}")
            v = QVBoxLayout(dlg)
            v.setContentsMargins(18, 16, 18, 14)
            v.setSpacing(9)
            p = QLabel(prompt)
            p.setWordWrap(True)
            p.setStyleSheet(f"color:{T['text']};font-size:13px;font-weight:600;")
            v.addWidget(p)

            group = QButtonGroup(dlg)
            first = default or (options[0][0] if options else None)
            for key, label in options:
                rb = QRadioButton(label)
                rb.setProperty("wm_key", key)
                rb.setChecked(key == first)
                group.addButton(rb)
                v.addWidget(rb)

            box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            box.accepted.connect(dlg.accept)
            box.rejected.connect(dlg.reject)
            v.addWidget(box)

            if dlg.exec() != QDialog.Accepted:
                return None
            btn = group.checkedButton()
            return btn.property("wm_key") if btn else None

        return self._call_on_ui_thread(_show)

    def _ui_check_picker(self, title, prompt, options, ok_text="Run selected"):
        """Qt replacement for the tkinter multi-select picker.

        Same contract as the original: options is a list of {"key", "label",
        "detail", "checked"} and the chosen keys -- or None if cancelled -- come
        back. The Office repair builds its checklist with it; the tkinter shell
        keeps its own version for the frozen legacy path.

        Called from worker threads, so it is marshalled to the UI thread and
        blocks the caller for the answer, exactly as the modal tk dialog did.
        """
        def _show():
            from PySide6.QtWidgets import QDialog, QDialogButtonBox
            T = self.window.T
            dlg = QDialog(self.window)
            dlg.setWindowTitle(title)
            dlg.setMinimumWidth(640)
            dlg.setStyleSheet(f"QDialog{{background:{T['bg']};}}"
                              f"QLabel{{color:{T['text']};font-size:13px;}}"
                              f"QCheckBox{{color:{T['text']};font-size:13px;font-weight:600;"
                              f"padding:4px 0 0 0;}}"
                              f"QScrollArea{{border:none;background:transparent;}}")
            v = QVBoxLayout(dlg)
            v.setContentsMargins(18, 16, 18, 14)
            v.setSpacing(9)
            p = QLabel(prompt)
            p.setWordWrap(True)
            p.setStyleSheet(f"color:{T['text']};font-size:13px;font-weight:600;")
            v.addWidget(p)

            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            inner = QWidget()
            inner.setStyleSheet("background:transparent;")
            iv = QVBoxLayout(inner)
            iv.setContentsMargins(0, 0, 8, 0)
            iv.setSpacing(2)
            boxes = []
            for opt in options:
                cb = WMCheckBox(opt["label"], T=T, colour=T['text'])
                cb.setChecked(bool(opt.get("checked")))
                cb.setProperty("wm_key", opt["key"])
                iv.addWidget(cb)
                if opt.get("detail"):
                    d = QLabel(opt["detail"])
                    d.setWordWrap(True)
                    d.setStyleSheet(f"color:{T['text_2']};font-size:12px;font-weight:400;"
                                    f"padding:0 0 8px 26px;")
                    iv.addWidget(d)
                boxes.append(cb)
            iv.addStretch(1)
            scroll.setWidget(inner)
            scroll.setMinimumHeight(min(520, 90 + 70 * max(1, len(options))))
            v.addWidget(scroll, 1)

            box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            box.button(QDialogButtonBox.Ok).setText(ok_text)
            box.accepted.connect(dlg.accept)
            box.rejected.connect(dlg.reject)
            v.addWidget(box)

            if dlg.exec() != QDialog.Accepted:
                return None
            return [cb.property("wm_key") for cb in boxes if cb.isChecked()]

        return self._call_on_ui_thread(_show)

    def _prompt_product_key(self):
        """Qt replacement for the tkinter product-key dialog.

        Same contract as the original: returns the key, or None if cancelled.

        The tkinter version builds a tk.Toplevel and calls root.wait_window(),
        neither of which exists under the Qt shell, so without this override the
        Qt runner never had a way to ask -- run_activate_windows just reported
        "No product key provided" and stopped.

        Called from a worker thread, so it is marshalled to the UI thread and
        blocks the caller for the answer, exactly as the modal tk dialog did.
        """
        def _show():
            from PySide6.QtWidgets import QDialog, QDialogButtonBox
            T = self.window.T
            dlg = QDialog(self.window)
            dlg.setWindowTitle("Activate Windows/Change Product Key")
            dlg.setMinimumWidth(430)
            dlg.setStyleSheet(f"QDialog{{background:{T['bg']};}}"
                              f"QLabel{{color:{T['text']};font-size:13px;}}")
            v = QVBoxLayout(dlg)
            v.setContentsMargins(18, 16, 18, 14)
            v.setSpacing(9)

            title = QLabel("Enter your Windows product key:")
            title.setStyleSheet(f"color:{T['text']};font-size:13px;font-weight:600;")
            v.addWidget(title)

            hint = QLabel("25 characters, grouped 5-5-5-5-5. Hyphens are added for you.")
            hint.setWordWrap(True)
            hint.setStyleSheet(f"color:{T['text_2']};font-size:12px;")
            v.addWidget(hint)

            entry = QLineEdit()
            entry.setPlaceholderText("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX")
            entry.setMaxLength(29)
            entry.setAlignment(QtC.AlignCenter)
            entry.setStyleSheet(
                f"QLineEdit{{background:{T['card']};color:{T['text']};"
                f"border:1px solid {T['border']};border-radius:6px;"
                f"padding:8px;font-family:Consolas,monospace;"
                f"font-size:15px;letter-spacing:1px;}}")
            v.addWidget(entry)

            box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            ok = box.button(QDialogButtonBox.Ok)
            ok.setText("Activate")
            ok.setEnabled(False)
            box.accepted.connect(dlg.accept)
            box.rejected.connect(dlg.reject)
            v.addWidget(box)

            # Only enable Activate for something slmgr could plausibly accept, so
            # a typo is caught here rather than 30 seconds into the run.
            def _on_edit(text):
                ok.setEnabled(self._normalize_product_key(text) is not None)
            entry.textChanged.connect(_on_edit)
            entry.returnPressed.connect(
                lambda: dlg.accept() if ok.isEnabled() else None)
            entry.setFocus()

            if dlg.exec() != QDialog.Accepted:
                return None
            return self._normalize_product_key(entry.text())

        return self._call_on_ui_thread(_show)

    @staticmethod
    def _normalize_product_key(raw):
        """'xxxxxxxxxxxxxxxxxxxxxxxxx' or 'xxxxx-xxxxx-...' -> canonical form.

        slmgr /ipk wants the hyphenated 5-5-5-5-5 form, and people paste keys
        both ways (and in lower case), so normalize instead of rejecting.
        Returns None when the input cannot be a product key.
        """
        body = re.sub(r'[^A-Za-z0-9]', '', raw or '').upper()
        if len(body) != 25:
            return None
        return '-'.join(body[i:i + 5] for i in range(0, 25, 5))

    def open_windbg_crash_paste_window(self):
        """Paste WinDbg output, get a plain-English answer.

        Was a tk.Toplevel built against self.root. Under Qt self.root is a
        WMRootStub, so the old version died on `'WMRootStub' object has no
        attribute 'tk'` the moment the WinDbg task reached it -- the feature was
        unreachable in the Qt shell. Same layout and same buttons as before,
        built from the theme tokens, and still non-modal: the original returned
        as soon as the window appeared, so the task must not block on it.
        """
        def _show():
            from PySide6.QtWidgets import QDialog, QPlainTextEdit
            T = self.window.T
            dlg = QDialog(self.window)
            dlg.setWindowTitle("WinDbg Crash Analyzer")
            dlg.setMinimumSize(760, 620)
            dlg.setStyleSheet(f"QDialog{{background:{T['bg']};}}")
            v = QVBoxLayout(dlg)
            v.setContentsMargins(18, 16, 18, 16)
            v.setSpacing(9)

            head = QLabel("WinDbg Crash Analyzer")
            head.setStyleSheet(f"color:{T['text']};font-size:17px;font-weight:700;")
            v.addWidget(head)
            sub = QLabel("Paste WinDbg !analyze -v, BlueScreenView text, or Event ID "
                         "1001 bugcheck details.")
            sub.setWordWrap(True)
            sub.setStyleSheet(f"color:{T['text_3']};font-size:12px;")
            v.addWidget(sub)

            def _label(text):
                l = QLabel(text)
                l.setStyleSheet(f"color:{T['text_2']};font-size:12px;font-weight:600;")
                return l

            def _area(read_only=False):
                a = QPlainTextEdit()
                a.setReadOnly(read_only)
                a.setStyleSheet(
                    f"QPlainTextEdit{{background:{T['card']};color:{T['text']};"
                    f"border:1px solid {T['border']};border-radius:6px;padding:8px;"
                    f"font-family:{WM_FONT_MONO};font-size:12px;}}")
                return a

            def _btn(text, primary=False, w=112):
                b = QPushButton(text)
                b.setFixedHeight(32)
                b.setMinimumWidth(w)
                b.setCursor(QtC.PointingHandCursor)
                if primary:
                    b.setStyleSheet(
                        f"QPushButton{{background:{T['accent']};color:#fff;border:none;"
                        f"border-radius:6px;font-size:12px;font-weight:600;}}"
                        f"QPushButton:hover{{background:{T['accent_hi']};}}")
                else:
                    b.setStyleSheet(
                        f"QPushButton{{background:transparent;color:{T['text_2']};"
                        f"border:1px solid {T['border_hi']};border-radius:6px;"
                        f"font-size:12px;}}"
                        f"QPushButton:hover{{background:{T['card_hi']};color:{T['text']};}}")
                return b

            cmd_row = QHBoxLayout()
            cmd_row.setSpacing(9)
            cmd_row.addWidget(_label("WinDbg command"))
            cmd = QLineEdit("!analyze -v")
            cmd.setReadOnly(True)
            cmd.setFixedHeight(30)
            cmd.setStyleSheet(
                f"QLineEdit{{background:{T['card']};color:{T['text']};"
                f"border:1px solid {T['border']};border-radius:6px;padding-left:9px;"
                f"font-family:{WM_FONT_MONO};font-size:12px;}}")
            cmd_row.addWidget(cmd, 1)
            copy_cmd = _btn("Copy Command", w=124)
            copy_cmd.clicked.connect(
                lambda: QApplication.clipboard().setText("!analyze -v"))
            cmd_row.addWidget(copy_cmd)
            v.addLayout(cmd_row)

            v.addWidget(_label("Crash/debug info"))
            src = _area()
            v.addWidget(src, 1)

            v.addWidget(_label("Plain-English answer"))
            out = _area(read_only=True)
            out.setPlainText(
                "Paste the crash analysis above, then click Analyze. For the best "
                "answer, copy the full WinDbg !analyze -v output.")
            v.addWidget(out, 1)

            def _analyze():
                out.setPlainText(self.analyze_crash_debug_text(
                    src.toPlainText().strip()))

            row = QHBoxLayout()
            row.setSpacing(9)
            paste = _btn("Paste Clipboard", w=130)
            paste.clicked.connect(
                lambda: src.setPlainText(QApplication.clipboard().text()))
            row.addWidget(paste)
            analyze = _btn("Analyze", primary=True, w=104)
            analyze.clicked.connect(_analyze)
            row.addWidget(analyze)
            copy_ans = _btn("Copy Answer", w=118)
            copy_ans.clicked.connect(
                lambda: QApplication.clipboard().setText(out.toPlainText().strip()))
            row.addWidget(copy_ans)
            row.addStretch()
            close = _btn("Close", w=92)
            close.clicked.connect(dlg.close)
            row.addWidget(close)
            v.addLayout(row)

            QShortcut(QKeySequence("Ctrl+Return"), dlg, activated=_analyze)
            src.setFocus()

            # Non-modal, so keep a reference -- a local would be collected the
            # moment _show() returns and the window would vanish.
            dlg.setAttribute(QtC.WA_DeleteOnClose)
            dlg.destroyed.connect(lambda: setattr(self, "_windbg_dialog", None))
            self._windbg_dialog = dlg
            dlg.show()
            dlg.raise_()

        return self._call_on_ui_thread(_show)

    def _refresh_task_indicator_leds(self, force=False):
        return None

    def _update_reboot_notice(self):
        return None

    def run_storage_sence(self):
        """Open the Storage page.

        The analyzer is no longer a separate window -- it is a page in the main
        window -- so this task just navigates there.
        """
        self.queue.put("PROGRESS:Storage Analyzer:Opening the Storage page…")
        self._call_on_ui_thread(lambda: self.window._show_category("storage"))
        self.queue.put("PROGRESS:Storage Analyzer:Storage page opened. Choose a drive and press Scan to analyze it.")

    def run_startup_manager(self):
        """Open the Startup page -- the task exists so search and Simple mode
        can find it; the page itself does the work."""
        self.queue.put("PROGRESS:Startup Manager:Opening the Startup page…")
        self._call_on_ui_thread(lambda: self.window._show_category("startup"))
        self.queue.put("PROGRESS:Startup Manager:Startup page opened. Review the entries and choose which to change.")

    def run_speed_test(self):
        """Open the Speed Test page -- the task exists so search and Simple mode
        can find it; the page itself runs the test."""
        self.queue.put("PROGRESS:Speed Test:Opening the Speed Test page…")
        self._call_on_ui_thread(lambda: self.window._show_category("speedtest"))
        self.queue.put("PROGRESS:Speed Test:Speed Test page opened. Press Start to measure your connection.")

    def run_app_installer(self):
        """Open the Install Apps page -- the task exists so search and Simple
        mode can find the catalogue; the page itself installs."""
        self.queue.put("PROGRESS:App Installer:Opening the app catalogue…")
        self._call_on_ui_thread(lambda: self.window._show_category("apps"))
        self.queue.put("PROGRESS:App Installer:App catalogue opened. Select apps and press Install selected to install them.")

    def run_windows_tweaks(self):
        """Open the Windows Settings page -- the task exists so search finds
        the switches; the page itself reads and writes them."""
        self.queue.put("PROGRESS:Windows Settings:Opening the settings switches…")
        self._call_on_ui_thread(lambda: self.window._show_category("tweaks"))
        self.queue.put("PROGRESS:Windows Settings:Settings page opened. Changes run when you toggle a switch.")

    def reset_all_checkboxes(self):
        for v in self.vars.values():
            v.set(False)
