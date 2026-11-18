"""WinMend ui: dialogs."""

from __future__ import annotations

from PySide6.QtCore import QObject, QTimer, Qt as QtC, Signal
from PySide6.QtWidgets import QApplication, QMessageBox
from winmend.core.prompts import bind_prompts
import traceback


class WMRootStub(QObject):
    """Stands in for the Tk root object the task methods expect.

    Task bodies call self.root.after(...) and a few winfo_*/clipboard methods.
    Rather than rewrite 77 methods, we satisfy that small surface with Qt.

    after() is the important one: SystemCleanerGUI._call_on_ui_thread marshals
    worker-thread work onto the UI thread with root.after(0, fn) + an Event, and
    that logic works verbatim once after() schedules onto Qt's main thread.
    """

    _invoke = Signal(object)

    def __init__(self, window):
        super().__init__()
        self._win = window
        self._invoke.connect(self._run, QtC.QueuedConnection)

    @staticmethod
    def _run(fn):
        try:
            fn()
        except Exception:
            traceback.print_exc()

    def after(self, ms, func=None, *args):
        if func is None:
            return None
        call = (lambda: func(*args)) if args else func
        if ms:
            # QTimer.singleShot needs an event loop in the calling thread, and
            # the task workers are plain Python threads with none: a delayed
            # call armed from one of them never fired, which is how the reboot
            # prompts after Windows Updates and CHKDSK went missing. Arm the
            # timer on the UI thread instead -- the signal hop is thread-safe.
            delay = int(ms)
            self._invoke.emit(lambda: QTimer.singleShot(delay, lambda: self._run(call)))
        else:
            self._invoke.emit(call)  # cross-thread safe
        return None

    def after_cancel(self, _job):
        return None

    def update_idletasks(self):
        QApplication.processEvents()

    # geometry — used to centre task dialogs over the window
    def winfo_rootx(self):
        return self._win.x()

    def winfo_rooty(self):
        return self._win.y()

    def winfo_width(self):
        return self._win.width()

    def winfo_height(self):
        return self._win.height()

    def wait_window(self, _w=None):
        return None

    def clipboard_clear(self):
        QApplication.clipboard().clear()

    def clipboard_append(self, text):
        cb = QApplication.clipboard()
        cb.setText((cb.text() or "") + str(text))

    def clipboard_get(self):
        return QApplication.clipboard().text()


class WMMessageBox:
    """messagebox work-alike backed by QMessageBox.

    Rebinding the module-global `messagebox` to an instance of this redirects
    all 57 legacy call sites at once, with no edits to task code.

    Task methods run on worker threads, so every call is marshalled to the UI
    thread and blocks the worker for the answer -- matching tkinter's semantics.
    """

    host = None  # set by wm_main_qt; provides _call_on_ui_thread

    @classmethod
    def _ask(cls, kind, title, message):
        def _show():
            win = cls.host.root._win if cls.host else None
            if kind == "error":
                return QMessageBox.critical(win, title, str(message)) or True
            if kind == "warning":
                return QMessageBox.warning(win, title, str(message)) or True
            if kind == "info":
                return QMessageBox.information(win, title, str(message)) or True
            if kind == "yesno":
                return QMessageBox.question(
                    win, title, str(message),
                    QMessageBox.Yes | QMessageBox.No) == QMessageBox.Yes
            if kind == "okcancel":
                return QMessageBox.question(
                    win, title, str(message),
                    QMessageBox.Ok | QMessageBox.Cancel) == QMessageBox.Ok
            return True
        if cls.host is None:
            return True
        return cls.host._call_on_ui_thread(_show)

    @classmethod
    def showinfo(cls, title="", message="", **_kw):
        return cls._ask("info", title, message)

    @classmethod
    def showerror(cls, title="", message="", **_kw):
        return cls._ask("error", title, message)

    @classmethod
    def showwarning(cls, title="", message="", **_kw):
        return cls._ask("warning", title, message)

    @classmethod
    def askyesno(cls, title="", message="", **_kw):
        return cls._ask("yesno", title, message)

    @classmethod
    def askokcancel(cls, title="", message="", **_kw):
        return cls._ask("okcancel", title, message)

    @classmethod
    def askquestion(cls, title="", message="", **_kw):
        return "yes" if cls._ask("yesno", title, message) else "no"


class WMSimpleDialog:
    """simpledialog work-alike backed by QInputDialog.

    The one caller is the Wi-Fi export gate, which makes the user type a phrase
    before passwords are shown in plaintext. It was still calling tkinter's
    simpledialog with parent=self.root -- a WMRootStub under Qt -- so the gate
    raised instead of asking. Rebound alongside `messagebox` in wm_main_qt.

    Returns None when cancelled, exactly as simpledialog.askstring does, so the
    caller's "not the phrase -> names only" branch is unchanged.
    """

    host = None  # set by wm_main_qt; provides _call_on_ui_thread

    @classmethod
    def askstring(cls, title="", prompt="", parent=None, **_kw):
        if cls.host is None:
            return None

        def _show():
            from PySide6.QtWidgets import QInputDialog
            win = cls.host.root._win if cls.host else None
            text, ok = QInputDialog.getText(win, title, str(prompt))
            return text if ok else None

        return cls.host._call_on_ui_thread(_show)


bind_prompts(WMMessageBox, WMSimpleDialog)
