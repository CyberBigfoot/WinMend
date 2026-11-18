"""WinMend ui: pages: tweaks."""

from __future__ import annotations

from PySide6.QtCore import QTimer, Qt as QtC
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)
from winmend.features.explorer.helpers import restart_explorer
from winmend.features.tweaks import WM_TWEAKS, apply_tweak, read_tweak_state, tweak_groups
from winmend.ui.pages.storage import WMStoragePage
from winmend.ui.widgets.controls import WMCheckBox, WMPill, wm_hline
import time


class WMToggle(WMCheckBox):
    """Windows settings use the same slider, with their immediate-change handler."""

    def __init__(self, T, parent=None):
        super().__init__(T=T, parent=parent)
        self.setFixedSize(self.sizeHint())


class WMTweaksPage(QWidget):
    """Windows preference switches, showing the registry's actual current state.

    The honesty rule that shaped this page: every switch is READ from the
    registry each time the page opens, so it shows what Windows is really set
    to -- including changes made in Settings, by another tool, or before WinMend
    was ever installed. It never displays "what WinMend last wrote".

    Each switch has a defined on-state and off-state, so flipping it back is a
    real restoration rather than a guess, and nothing here needs an undo script.
    Values WinMend did not create are never deleted, existing values keep their
    registry type, and bitfields keep the bits the switch is not about. Every
    flip is one Safety Journal entry.
    """

    _btn = WMStoragePage._btn

    def __init__(self, window):
        super().__init__()
        self.win = window
        self.T = window.T
        self.setStyleSheet("background:transparent;")
        self.rows = {}            # tweak id -> (row widget, toggle, note label)
        self._applying = False    # guards toggled() while we set state ourselves
        self._needs_explorer = False

        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(10)
        v.addWidget(self._controls())
        v.addWidget(self._restart_bar())
        v.addWidget(self._list(), 1)
        v.addWidget(self._footer())
        QTimer.singleShot(30, self.reload)

    # ---- chrome ----

    def _controls(self):
        T = self.T
        f = QFrame()
        f.setObjectName("twc")
        f.setStyleSheet(f"#twc{{background:{T['card']};border:1px solid {T['border']};"
                        f"border-radius:8px;}}")
        h = QHBoxLayout(f)
        h.setContentsMargins(13, 10, 13, 10)
        h.setSpacing(9)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search settings…")
        self.search.setFixedHeight(31)
        self.search.setStyleSheet(
            f"QLineEdit{{background:{T['bg']};border:1px solid {T['border']};"
            f"border-radius:6px;padding-left:10px;color:{T['text']};font-size:12px;}}"
            f"QLineEdit:focus{{border:1px solid {T['accent']};}}")
        self.search.textChanged.connect(self._filter)
        h.addWidget(self.search, 1)
        self.status = QLabel("")
        self.status.setStyleSheet(f"color:{T['text_3']};font-size:12px;background:transparent;")
        self.status.setMinimumWidth(1)
        h.addWidget(self.status)
        h.addStretch()
        self.refresh_btn = self._btn("Re-read", w=88)
        self.refresh_btn.setToolTip("Read every setting from the registry again — "
                                    "picks up changes made in Settings meanwhile.")
        self.refresh_btn.clicked.connect(self.reload)
        h.addWidget(self.refresh_btn)
        return f

    def _restart_bar(self):
        T = self.T
        self.restart_bar = QFrame()
        self.restart_bar.setObjectName("twr")
        self.restart_bar.setStyleSheet(
            f"#twr{{background:{T['card']};border:1px solid {T['warn']};border-radius:8px;}}")
        self.restart_bar.setVisible(False)
        h = QHBoxLayout(self.restart_bar)
        h.setContentsMargins(13, 9, 13, 9)
        h.setSpacing(9)
        self.restart_label = QLabel("")
        self.restart_label.setWordWrap(True)
        self.restart_label.setStyleSheet(f"color:{T['text_2']};font-size:12px;"
                                         f"background:transparent;")
        h.addWidget(self.restart_label, 1)
        self.restart_btn = self._btn("Restart File Explorer", primary=True, w=160)
        self.restart_btn.setToolTip("Closes and reopens Explorer so shell changes "
                                    "take effect.\nYour open windows and files are "
                                    "not touched.")
        self.restart_btn.clicked.connect(self._restart_explorer)
        h.addWidget(self.restart_btn)
        return self.restart_bar

    def _list(self):
        T = self.T
        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setFrameShape(QFrame.NoFrame)
        area.setStyleSheet("background:transparent;")
        inner = QWidget()
        inner.setStyleSheet("background:transparent;")
        iv = QVBoxLayout(inner)
        iv.setContentsMargins(0, 0, 6, 0)
        iv.setSpacing(10)
        self.group_cards = []
        for group, tweaks in tweak_groups():
            card = QFrame()
            card.setObjectName("twg")
            card.setStyleSheet(f"#twg{{background:{T['card']};border:1px solid "
                               f"{T['border']};border-radius:8px;}}")
            cv = QVBoxLayout(card)
            cv.setContentsMargins(15, 12, 15, 12)
            cv.setSpacing(0)
            head = QLabel(group)
            head.setStyleSheet(f"color:{T['text_3']};font-size:11px;font-weight:700;"
                               f"background:transparent;")
            cv.addWidget(head)
            cv.addSpacing(6)
            for index, tweak in enumerate(tweaks):
                if index:
                    line = wm_hline(T)
                    cv.addWidget(line)
                cv.addWidget(self._row(tweak))
            self.group_cards.append((card, tweaks))
            iv.addWidget(card)
        self.empty_note = QLabel("No settings match your search.")
        self.empty_note.setStyleSheet(f"color:{T['text_3']};font-size:12px;"
                                      f"background:transparent;")
        self.empty_note.setVisible(False)
        iv.addWidget(self.empty_note)
        iv.addStretch()
        area.setWidget(inner)
        return area

    def _row(self, tweak):
        T = self.T
        row = QWidget()
        row.setStyleSheet("background:transparent;")
        h = QHBoxLayout(row)
        h.setContentsMargins(0, 9, 0, 9)
        h.setSpacing(12)

        left = QVBoxLayout()
        left.setSpacing(3)
        title = QLabel(tweak.name)
        title.setStyleSheet(f"color:{T['text']};font-size:13px;font-weight:600;"
                            f"background:transparent;")
        left.addWidget(title)
        desc = QLabel(tweak.description)
        desc.setWordWrap(True)
        desc.setStyleSheet(f"color:{T['text_3']};font-size:12px;background:transparent;")
        left.addWidget(desc)

        pills = QHBoxLayout()
        pills.setSpacing(6)
        if tweak.needs_admin():
            pills.addWidget(WMPill("Admin", T['warn']))
        label = {"explorer": "Restarts Explorer", "signout": "After sign-out",
                 "reboot": "After restart"}.get(tweak.after, "")
        if label:
            pills.addWidget(WMPill(label, T['text_3']))
        note = QLabel(tweak.note)
        note.setWordWrap(True)
        note.setStyleSheet(f"color:{T['warn']};font-size:11px;background:transparent;")
        note.setVisible(bool(tweak.note))
        pills.addWidget(note)
        pills.addStretch()
        left.addLayout(pills)
        h.addLayout(left, 1)

        toggle = WMToggle(T)
        toggle.setAccessibleName(tweak.name)
        toggle.toggled.connect(lambda checked, t=tweak: self._on_toggled(t, checked))
        h.addWidget(toggle, 0, QtC.AlignVCenter)
        self.rows[tweak.id] = (row, toggle, note)
        return row

    def _footer(self):
        hint = QLabel(
            "Each switch shows what the registry says right now, not what WinMend "
            "last did — so anything you changed in Settings shows up here too. "
            "Flipping one back restores the previous value exactly; nothing is left "
            "behind. Every change is recorded in the Safety Journal.")
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color:{self.T['text_3']};font-size:11px;background:transparent;")
        return hint

    # ---- state ----

    def on_revisit(self):
        self.reload()

    def reload(self):
        """Re-read every switch from the registry."""
        unreadable = 0
        self._applying = True
        for tweak in WM_TWEAKS:
            state = read_tweak_state(tweak)
            row, toggle, _note = self.rows[tweak.id]
            if state is None:
                unreadable += 1
                toggle.setEnabled(False)
                toggle.setToolTip("WinMend could not read this setting.")
            else:
                toggle.setChecked(bool(state))
        self._applying = False
        on = sum(1 for t in WM_TWEAKS if read_tweak_state(t))
        text = f"{len(WM_TWEAKS)} settings  ·  {on} on"
        if unreadable:
            text += f"  ·  {unreadable} unreadable"
        if not self.win.host.admin_status:
            text += "  ·  not elevated"
        self.status.setText(text)
        self._filter()

    def _on_toggled(self, tweak, checked):
        if self._applying:
            return
        row, toggle, _note = self.rows[tweak.id]
        session = None
        try:
            session = self.win.journal.start_session("tweaks", [{
                "id": f"tweak:{tweak.id}",
                "title": f"{tweak.name} — turn {'on' if checked else 'off'}",
                "risk": "caution",
                "restore_point": False,
            }])
            self.win.journal.task_started(session, f"tweak:{tweak.id}")
        except Exception:
            session = None

        started = time.time()
        error = apply_tweak(tweak, checked)
        # Trust the registry, not the click: read the setting back and show
        # whatever it actually says now.
        actual = read_tweak_state(tweak)
        self._applying = True
        if actual is not None:
            toggle.setChecked(bool(actual))
        self._applying = False

        if error:
            self.status.setText(error)
            self.win._log(f"{tweak.name}: {error}", self.T['danger'])
        elif actual is None:
            error = f"{tweak.name}: the setting could not be read back; the change is unverified."
            self.status.setText(error)
            self.win._log(error, self.T['warn'])
        elif actual is not None and bool(actual) != checked:
            message = (f"{tweak.name} did not change — Windows still reports it "
                       f"{'on' if actual else 'off'}.")
            self.status.setText(message)
            self.win._log(message, self.T['warn'])
            error = message
        else:
            word = "on" if checked else "off"
            self.status.setText(f"{tweak.name} is now {word}.")
            self.win._log(f"{tweak.name} turned {word}.", self.T['ok'])
            if tweak.after == "explorer":
                self._needs_explorer = True
            elif tweak.after in ("signout", "reboot"):
                self._show_restart_bar(tweak.after)
        if tweak.after == "explorer" and not error:
            self._show_restart_bar("explorer")

        if session:
            try:
                self.win.journal.task_finished(
                    session, f"tweak:{tweak.id}",
                    "failed" if error else "done", time.time() - started, error)
                self.win.journal.complete_session(
                    session, "failed" if error else "complete")
            except Exception:
                pass

    def _show_restart_bar(self, kind):
        if kind == "explorer":
            self.restart_label.setText(
                "One or more changes need File Explorer restarted before they show up.")
            self.restart_btn.setVisible(True)
        elif kind == "signout":
            self.restart_label.setText(
                "That change takes effect the next time you sign in.")
            self.restart_btn.setVisible(self._needs_explorer)
        else:
            self.restart_label.setText(
                "That change takes effect after you restart the PC.")
            self.restart_btn.setVisible(self._needs_explorer)
        self.restart_bar.setVisible(True)

    def _restart_explorer(self):
        if QMessageBox.question(
                self, "Restart File Explorer",
                "The taskbar and desktop will disappear for a second and come "
                "back.\n\nOpen windows, files and unsaved work are not affected.\n\n"
                "Restart Explorer now?",
                QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return
        self.restart_btn.setEnabled(False)
        error = restart_explorer()
        self.restart_btn.setEnabled(True)
        if error:
            self.status.setText(error)
            self.win._log(error, self.T['danger'])
            return
        self._needs_explorer = False
        self.restart_bar.setVisible(False)
        self.status.setText("File Explorer restarted.")
        self.win._log("File Explorer restarted.", self.T['ok'])

    def _filter(self):
        needle = self.search.text().strip().lower()
        shown = 0
        for card, tweaks in self.group_cards:
            visible = 0
            for tweak in tweaks:
                row, _toggle, _note = self.rows[tweak.id]
                ok = (not needle or needle in
                      f"{tweak.name} {tweak.description} {tweak.group}".lower())
                row.setVisible(ok)
                visible += ok
            card.setVisible(bool(visible))
            shown += visible
        self.empty_note.setVisible(shown == 0)
