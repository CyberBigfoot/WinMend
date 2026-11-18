"""WinMend ui: pages: startup."""

from __future__ import annotations

from PySide6.QtCore import QTimer, Qt as QtC
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMenu,
    QMessageBox,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)
from winmend.diagnostics.collectors.windows import WindowsProbe
from winmend.features.startup.helpers import (
    file_company,
    list_startup_entries,
    set_startup_entry_enabled,
)
from winmend.ui.pages.storage import WMStoragePage
import os
import subprocess
import threading


class WMStartupPage(QWidget):
    """Startup Manager: everything that launches with Windows, what Windows
    measured it costing at boot, and a reversible per-item switch.

    Two hard rules, both inherited from decisions elsewhere in the app:
    - Toggling writes the same Task Manager-compatible StartupApproved flags
      the bulk "Optimize Startup Apps" task writes. Nothing is ever deleted,
      so every change is reversible here, in Task Manager, or in Settings.
    - The Boot impact column only shows numbers Windows actually measured
      (Diagnostics-Performance events 101/103). Apps without a measurement
      say "Not measured" -- an invented number would be worse than none.
    """

    # Same styling helpers the Storage page uses; they only touch self.T.
    _btn = WMStoragePage._btn
    _tree_style = WMStoragePage._tree_style

    def __init__(self, window):
        super().__init__()
        self.win = window
        self.T = window.T
        self.setStyleSheet("background:transparent;")
        self.entries = []
        self._gen = 0
        self._loading = False
        self._boot_info = None
        self._boot_loading = False
        self._impact = {}

        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(10)
        v.addWidget(self._controls())
        v.addWidget(self._boot_card())
        v.addWidget(self._table(), 1)
        v.addWidget(self._footer())
        QTimer.singleShot(60, self.refresh)

    # ---- chrome ----

    def _controls(self):
        T = self.T
        f = QFrame()
        f.setObjectName("suc")
        f.setStyleSheet(f"#suc{{background:{T['card']};border:1px solid {T['border']};"
                        f"border-radius:8px;}}")
        h = QHBoxLayout(f)
        h.setContentsMargins(13, 10, 13, 10)
        h.setSpacing(9)
        self.on_btn = self._btn("Turn on", primary=True, w=96)
        self.on_btn.setEnabled(False)
        self.on_btn.clicked.connect(lambda: self._set_selected_enabled(True))
        h.addWidget(self.on_btn)
        self.off_btn = self._btn("Turn off", w=96)
        self.off_btn.setEnabled(False)
        self.off_btn.clicked.connect(lambda: self._set_selected_enabled(False))
        h.addWidget(self.off_btn)
        self.status = QLabel("Reading startup entries…")
        self.status.setStyleSheet(f"color:{T['text_3']};font-size:12px;background:transparent;")
        self.status.setMinimumWidth(1)  # long status must squeeze, not push buttons out
        h.addWidget(self.status)
        h.addStretch()
        self.refresh_btn = self._btn("Refresh", w=92)
        self.refresh_btn.clicked.connect(lambda: self.refresh(reload_boot=True))
        h.addWidget(self.refresh_btn)
        return f

    def _boot_card(self):
        T = self.T
        f = QFrame()
        f.setObjectName("sbo")
        f.setStyleSheet(f"#sbo{{background:{T['card']};border:1px solid {T['border']};"
                        f"border-radius:8px;}}")
        v = QVBoxLayout(f)
        v.setContentsMargins(15, 11, 15, 11)
        v.setSpacing(3)
        self.boot_head = QLabel("Measuring recent boots…")
        self.boot_head.setStyleSheet(f"color:{T['text']};font-size:13px;font-weight:600;"
                                     f"background:transparent;")
        v.addWidget(self.boot_head)
        self.boot_detail = QLabel("Boot times come from Windows' own boot-performance log.")
        self.boot_detail.setWordWrap(True)
        self.boot_detail.setStyleSheet(f"color:{T['text_3']};font-size:12px;background:transparent;")
        v.addWidget(self.boot_detail)
        return f

    def _table(self):
        self.tree = QTreeWidget()
        self.tree.setColumnCount(6)
        self.tree.setHeaderLabels(["Name", "Status", "Boot impact", "Publisher",
                                   "Source", "Command"])
        self.tree.setStyleSheet(self._tree_style())
        self.tree.setRootIsDecorated(False)
        self.tree.setUniformRowHeights(True)
        self.tree.setSelectionMode(QTreeWidget.ExtendedSelection)
        header = self.tree.header()
        header.setStretchLastSection(True)
        self.tree.setColumnWidth(0, 250)
        self.tree.setColumnWidth(1, 62)
        self.tree.setColumnWidth(2, 165)
        self.tree.setColumnWidth(3, 170)
        self.tree.setColumnWidth(4, 155)
        self.tree.itemSelectionChanged.connect(self._update_buttons)
        self.tree.itemDoubleClicked.connect(lambda item, _c: self._toggle_item(item))
        self.tree.setContextMenuPolicy(QtC.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._menu)
        return self.tree

    def _footer(self):
        hint = QLabel("Switching an item off stops it launching at your next sign-in. "
                      "Nothing is uninstalled or deleted — switch it back on any time, "
                      "here or in Task Manager. Double-click a row to toggle it.")
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color:{self.T['text_3']};font-size:11px;background:transparent;")
        return hint

    # ---- data ----

    def on_revisit(self):
        """Re-enumerate on navigation back: cheap, and catches changes made in
        Task Manager meanwhile. The boot history is kept -- it only changes
        after a reboot."""
        self.refresh()

    def refresh(self, reload_boot=False):
        if not self._loading:
            self._loading = True
            self._gen += 1
            gen = self._gen
            self.status.setText("Reading startup entries…")
            self.refresh_btn.setEnabled(False)

            def work():
                error = ""
                try:
                    entries = list_startup_entries()
                    for entry in entries:
                        entry["publisher"] = file_company(entry.get("exe", ""))
                except Exception as exc:
                    entries, error = [], str(exc)
                self.win.host.root.after(0, lambda: self._fill(entries, error, gen))
            threading.Thread(target=work, daemon=True).start()

        if (reload_boot or self._boot_info is None) and not self._boot_loading:
            self._boot_loading = True

            def bwork():
                info = WindowsProbe().boot_history()
                self.win.host.root.after(0, lambda: self._fill_boot(info))
            threading.Thread(target=bwork, daemon=True).start()

    def _fill(self, entries, error, gen):
        if gen != self._gen:
            return  # a newer refresh superseded this result
        self._loading = False
        try:
            self.refresh_btn.setEnabled(True)
            self.entries = entries
            self.tree.setSortingEnabled(False)
            self.tree.clear()
            for index, entry in enumerate(entries):
                item = QTreeWidgetItem(["", "", "", "", "", ""])
                item.setData(0, QtC.UserRole, index)
                self.tree.addTopLevelItem(item)
                self._paint_row(item, entry)
            self.tree.setSortingEnabled(True)
            self.tree.sortByColumn(0, QtC.AscendingOrder)
            if error:
                self.status.setText(f"Could not read startup entries: {error}")
            else:
                self._update_counts()
            self._update_buttons()
        except RuntimeError:
            pass  # page torn down while the worker was reading

    def _update_counts(self):
        off = sum(1 for entry in self.entries if not entry.get("enabled", True))
        n = len(self.entries)
        text = f"{n} startup item{'s' if n != 1 else ''}"
        if off:
            text += f"  ·  {off} turned off"
        self.status.setText(text)

    def _paint_row(self, item, entry):
        T = self.T
        enabled = entry.get("enabled", True)
        item.setText(0, entry["name"])
        item.setForeground(0, QColor(T['text'] if enabled else T['text_3']))
        item.setText(1, "On" if enabled else "Off")
        item.setForeground(1, QColor(T['ok'] if enabled else T['text_3']))
        impact = self._impact_for(entry)
        if impact is not None:
            when = impact["time"][:10]
            item.setText(2, f"+{impact['degradation_s']:.1f} s  ({when})")
            seconds = impact["degradation_s"]
            colour = (T['danger'] if seconds >= 5 else
                      T['warn'] if seconds >= 2 else T['text_2'])
            item.setForeground(2, QColor(colour))
            item.setToolTip(2, "Windows measured this app slowing a recent boot "
                               f"by {seconds:.1f} seconds ({when}).")
        else:
            item.setText(2, "Not measured")
            item.setForeground(2, QColor(T['text_3']))
            item.setToolTip(2, "Windows has not recorded this item delaying a recent boot.")
        item.setText(3, entry.get("publisher") or "—")
        item.setForeground(3, QColor(T['text_2'] if entry.get("publisher") else T['text_3']))
        item.setText(4, entry["source"])
        item.setForeground(4, QColor(T['text_3']))
        item.setText(5, entry["command"])
        item.setForeground(5, QColor(T['text_3']))
        tip = f"{entry['name']}\n{entry['command']}\n\nLocation: {entry['location']}"
        item.setToolTip(0, tip)
        item.setToolTip(5, tip)

    # ---- boot history ----

    def _fill_boot(self, info):
        self._boot_loading = False
        self._boot_info = info
        try:
            if not info.get("available"):
                self.boot_head.setText("No measured boots yet.")
                reason = (info.get("reason") or "").lower()
                denied = "denied" in reason or "access" in reason
                if denied and not self.win.host.admin_status:
                    self.boot_detail.setText(
                        "Reading Windows' boot-performance log needs administrator "
                        "rights — restart WinMend as administrator to see measured "
                        "boot times here.")
                else:
                    # The log is usually readable but empty: Windows only writes
                    # a boot record for a full restart, not a Fast Startup
                    # resume, and the log may have been cleared.
                    self.boot_detail.setText(
                        "Windows hasn't recorded a measured boot recently. "
                        "Measurements appear after a full restart of the PC.")
                return
            boots = info["boots"]
            last = boots[0]
            average = sum(b["total_s"] for b in boots) / len(boots)
            self.boot_head.setText(
                f"Last boot: {last['total_s']:.1f} s"
                f"   ·   {last['desktop_s']:.1f} s to a usable desktop")
            detail = (f"Average of the last {len(boots)} measured boot"
                      f"{'s' if len(boots) != 1 else ''}: {average:.1f} s.")
            app_delays = [s for s in info.get("slow", []) if s["kind"] == "app" and s["name"]]
            if app_delays:
                worst = max(app_delays, key=lambda s: s["degradation_s"])
                detail += (f"   Biggest recent app delay: {worst['name']} "
                           f"+{worst['degradation_s']:.1f} s ({worst['time'][:10]}).")
            self.boot_detail.setText(detail)
            self._impact = {}
            for event in info.get("slow", []):
                if event["kind"] != "app":
                    continue
                for key in self._impact_keys(event.get("path") or "", event.get("name") or ""):
                    # events arrive newest first; keep the most recent per app
                    self._impact.setdefault(key, event)
            for i in range(self.tree.topLevelItemCount()):
                item = self.tree.topLevelItem(i)
                index = item.data(0, QtC.UserRole)
                if index is not None and index < len(self.entries):
                    self._paint_row(item, self.entries[index])
        except RuntimeError:
            pass

    @staticmethod
    def _impact_keys(path, name):
        keys = set()
        for raw in (os.path.basename(path), name):
            raw = (raw or "").strip().lower()
            if not raw:
                continue
            keys.add(raw)
            if raw.endswith(".exe"):
                keys.add(raw[:-4])
            else:
                keys.add(raw + ".exe")
        return keys

    def _impact_for(self, entry):
        if not self._impact:
            return None
        for key in self._impact_keys(entry.get("exe") or "", entry.get("name") or ""):
            event = self._impact.get(key)
            if event is not None:
                return event
        return None

    # ---- toggling ----

    def _selected_entries(self):
        out = []
        for item in self.tree.selectedItems():
            index = item.data(0, QtC.UserRole)
            if index is not None and index < len(self.entries):
                out.append((item, self.entries[index]))
        return out

    def _update_buttons(self):
        selected = self._selected_entries()
        self.on_btn.setEnabled(any(not e.get("enabled", True) for _i, e in selected))
        self.off_btn.setEnabled(any(e.get("enabled", True) for _i, e in selected))

    def _toggle_item(self, item):
        index = item.data(0, QtC.UserRole)
        if index is None or index >= len(self.entries):
            return
        entry = self.entries[index]
        self._apply(item, entry, not entry.get("enabled", True))

    def _set_selected_enabled(self, enabled):
        for item, entry in self._selected_entries():
            self._apply(item, entry, enabled)

    def _apply(self, item, entry, enabled):
        if entry.get("enabled", True) == enabled:
            return
        error = set_startup_entry_enabled(entry, enabled)
        if error:
            QMessageBox.warning(self, entry["name"], error)
            return
        entry["enabled"] = enabled
        self._paint_row(item, entry)
        verb = "Turned on" if enabled else "Turned off"
        self.win._log(f"{verb} startup item: {entry['name']}",
                      self.T['ok'] if enabled else self.T['warn'])
        self._journal(entry, enabled)
        self._update_counts()
        self._update_buttons()

    def _journal(self, entry, enabled):
        """One journal session per switch, so the Safety Journal shows the
        change alongside every other thing WinMend has done to this PC."""
        def work():
            try:
                journal = self.win.journal
                verb = "Turn on" if enabled else "Turn off"
                session_id = journal.start_session("startup", [{
                    "id": "startup_toggle",
                    "title": f"{verb} startup app: {entry['name']}",
                    "risk": "caution",
                    "restore_point": False,
                }])
                journal.task_started(session_id, "startup_toggle")
                journal.task_finished(session_id, "startup_toggle", "done", 0)
                journal.complete_session(session_id, "complete")
            except Exception:
                pass
        threading.Thread(target=work, daemon=True).start()

    # ---- context menu ----

    def _menu(self, pos):
        item = self.tree.itemAt(pos)
        if item is None:
            return
        index = item.data(0, QtC.UserRole)
        if index is None or index >= len(self.entries):
            return
        entry = self.entries[index]
        T = self.T
        menu = QMenu(self)
        menu.setStyleSheet(f"QMenu{{background:{T['card']};color:{T['text']};"
                           f"border:1px solid {T['border']};}}"
                           f"QMenu::item:selected{{background:{T['accent']};color:#fff;}}")
        toggle = menu.addAction("Turn off" if entry.get("enabled", True) else "Turn on")
        toggle.triggered.connect(lambda: self._apply(item, entry, not entry.get("enabled", True)))
        show = menu.addAction("Open file location")
        show.triggered.connect(lambda: self._open_location(entry))
        copy = menu.addAction("Copy command")
        copy.triggered.connect(lambda: QApplication.clipboard().setText(entry["command"]))
        menu.exec(self.tree.viewport().mapToGlobal(pos))

    def _open_location(self, entry):
        target = entry.get("exe") or entry.get("location") or ""
        try:
            if target and os.path.exists(target):
                subprocess.Popen(["explorer", "/select,", target])
            elif entry.get("kind") == "folder":
                subprocess.Popen(["explorer", os.path.dirname(entry["location"])])
            else:
                QMessageBox.information(self, entry["name"],
                                        "The file this entry points to could not be found.")
        except Exception:
            pass
