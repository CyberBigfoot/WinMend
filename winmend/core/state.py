"""WinMend core: state."""

from __future__ import annotations




# ============================================================================
# ==================== TASK-API SHIM (ex-tkinter) ============================
# ============================================================================
# The task implementations below are the proven, load-bearing part of this app
# -- they talk to DISM, SFC, netsh, winreg and friends, and they were never
# rewritten for Qt. They touched tkinter in only five mechanical ways, and
# these shims re-point each one so the task bodies keep working verbatim:
#
#   tk.BooleanVar()  -> WMBoolVar        (task selection state)
#   tk.StringVar()   -> WMStrVar
#   messagebox.*     -> WMMessageBox     (QMessageBox, marshalled to the UI thread)
#   simpledialog.*   -> WMSimpleDialog   (QInputDialog)
#   root.after(ms,f) -> WMRootStub       (QTimer)
#
# self.queue.put(...) -- the dominant task->UI channel -- needs no shim at all:
# it is stdlib queue.Queue, drained by a QTimer instead of tkinter's after()
# loop. That is why the migration was tractable, and why deleting the tkinter
# UI afterwards touched none of these bodies. tkinter itself is gone; the shim
# names stay because they are what the task code calls.

class WMBoolVar:
    """tk.BooleanVar work-alike backed by a plain Python bool.

    Carries an optional bound QCheckBox so UI and state stay in sync in both
    directions, and supports trace callbacks like the tkinter original.
    """

    __slots__ = ('_v', '_widget', '_traces')

    def __init__(self, value=False):
        self._v = bool(value)
        self._widget = None
        self._traces = []

    def get(self):
        return self._v

    def set(self, value):
        value = bool(value)
        changed = value != self._v
        self._v = value
        if self._widget is not None:
            try:
                self._widget.blockSignals(True)
                self._widget.setChecked(value)
            finally:
                self._widget.blockSignals(False)
        if changed:
            for cb in self._traces:
                try:
                    cb()
                except Exception:
                    pass

    def bind_widget(self, widget):
        """Attach a QCheckBox; user clicks flow back into this var."""
        self._widget = widget
        widget.setChecked(self._v)
        widget.toggled.connect(self._from_widget)

    def _from_widget(self, checked):
        self._v = bool(checked)
        for cb in self._traces:
            try:
                cb()
            except Exception:
                pass

    def trace_add(self, _mode, callback):
        self._traces.append(lambda *_: callback())

    # tkinter alias
    trace = trace_add


class WMStrVar:
    """tk.StringVar work-alike."""

    __slots__ = ('_v', '_traces')

    def __init__(self, value=""):
        self._v = str(value)
        self._traces = []

    def get(self):
        return self._v

    def set(self, value):
        self._v = str(value)
        for cb in self._traces:
            try:
                cb()
            except Exception:
                pass

    def trace_add(self, _mode, callback):
        self._traces.append(lambda *_: callback())

    trace = trace_add
