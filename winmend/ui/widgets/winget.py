"""WinMend ui: widgets: winget."""

from __future__ import annotations

from PySide6.QtCore import QTimer, Qt as QtC
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)
from winmend.core.processes import (
    _no_console_startupinfo,
    wm_kill_tree,
    wm_track_child,
    wm_untrack_child,
)
from winmend.features.apps.winget import parse_winget_upgrade, winget_listing_error
from winmend.ui.pages.storage import WMStoragePage
from winmend.ui.theme import WM_FONT_MONO
import queue
import subprocess
import threading
import time


class WMWingetPanel(QFrame):
    """App updates via winget, embedded at the top of the Updates page.

    Complements the "Update Apps (Winget)" task (which updates everything in
    one shot): this lists what is outdated first, then updates one app, a
    selection, or all of them, with live output and a per-app result column.
    One winget process runs at a time. No timeouts anywhere -- a slow download
    finishes rather than being killed; Cancel terminates the running install.
    """

    _btn = WMStoragePage._btn
    _tree_style = WMStoragePage._tree_style

    def __init__(self, window):
        super().__init__()
        self.win = window
        self.T = window.T
        T = self.T
        self.setObjectName("wgp")
        self.setStyleSheet(f"#wgp{{background:{T['card']};border:1px solid {T['border']};"
                           f"border-radius:8px;}}")
        self.rows = []
        self.pending = []
        self.proc = None
        self._busy = False
        self._checking = False
        self._cancelled = False
        self._failures = 0
        self._updated = 0
        self._session = None
        self._task_started = None
        self.q = queue.Queue()

        v = QVBoxLayout(self)
        v.setContentsMargins(15, 12, 15, 12)
        v.setSpacing(8)

        head = QHBoxLayout()
        head.setSpacing(9)
        title = QLabel("App updates")
        title.setStyleSheet(f"color:{T['text']};font-size:14px;font-weight:700;"
                            f"background:transparent;")
        head.addWidget(title)
        self.status = QLabel("Checking for app updates…")
        self.status.setStyleSheet(f"color:{T['text_3']};font-size:12px;background:transparent;")
        self.status.setMinimumWidth(1)  # long status must squeeze, not push buttons out
        head.addWidget(self.status)
        head.addStretch()
        self.cancel_btn = self._btn("Cancel", w=76)
        self.cancel_btn.setVisible(False)
        self.cancel_btn.clicked.connect(self._cancel)
        head.addWidget(self.cancel_btn)
        self.sel_btn = self._btn("Update selected", w=124)
        self.sel_btn.setEnabled(False)
        self.sel_btn.clicked.connect(self._update_selected)
        head.addWidget(self.sel_btn)
        self.all_btn = self._btn("Update all", primary=True, w=104)
        self.all_btn.setEnabled(False)
        self.all_btn.clicked.connect(self._update_all)
        head.addWidget(self.all_btn)
        self.refresh_btn = self._btn("Refresh", w=84)
        self.refresh_btn.setEnabled(False)
        self.refresh_btn.clicked.connect(self.refresh)
        head.addWidget(self.refresh_btn)
        v.addLayout(head)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(5)
        self.tree.setHeaderLabels(["App", "Installed", "Available", "Source", "Status"])
        self.tree.setStyleSheet(self._tree_style())
        self.tree.setRootIsDecorated(False)
        self.tree.setUniformRowHeights(True)
        self.tree.setSelectionMode(QTreeWidget.ExtendedSelection)
        self.tree.setFixedHeight(238)
        self.tree.header().setStretchLastSection(True)
        self.tree.setColumnWidth(0, 250)
        self.tree.setColumnWidth(1, 118)
        self.tree.setColumnWidth(2, 118)
        self.tree.setColumnWidth(3, 82)
        self.tree.itemSelectionChanged.connect(self._update_buttons)
        v.addWidget(self.tree)

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setFixedHeight(126)
        self.output.setMaximumBlockCount(600)
        self.output.setVisible(False)
        self.output.setStyleSheet(
            f"QPlainTextEdit{{background:{T['bg']};color:{T['text_2']};"
            f"border:1px solid {T['border']};border-radius:7px;"
            f"font-family:{WM_FONT_MONO};font-size:11px;padding:4px;}}")
        v.addWidget(self.output)

        self.pump = QTimer(self)
        self.pump.timeout.connect(self._drain)
        self.pump.start(150)
        QTimer.singleShot(600, self.refresh)

    def busy(self):
        return self._busy or self.proc is not None

    # ---- listing ----

    def refresh(self):
        if self._busy or self._checking:
            return
        self._checking = True
        self.status.setText("Checking for app updates…")
        self.refresh_btn.setEnabled(False)
        self.all_btn.setEnabled(False)
        self.sel_btn.setEnabled(False)

        def work():
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            try:
                probe = subprocess.run(
                    ["winget", "--version"], capture_output=True, timeout=20,
                    creationflags=flags, startupinfo=_no_console_startupinfo())
                if probe.returncode != 0:
                    raise FileNotFoundError()
            except Exception:
                self.q.put(("nowinget",))
                return
            try:
                # Listing is read-only; no timeout -- a slow source refresh
                # completes instead of being reported as a failure.
                result = subprocess.run(
                    ["winget", "upgrade", "--include-unknown",
                     "--accept-source-agreements", "--disable-interactivity"],
                    capture_output=True, text=True, encoding="utf-8",
                    errors="replace", creationflags=flags,
                    startupinfo=_no_console_startupinfo())
                error = winget_listing_error(result, updates=True)
                if error:
                    raise RuntimeError(error)
                self.q.put(("rows", parse_winget_upgrade(result.stdout or "")))
            except Exception as exc:
                self.q.put(("listerror", str(exc)))
        threading.Thread(target=work, daemon=True).start()

    def _fill(self, rows):
        T = self.T
        self.rows = rows
        for row in self.rows:
            row["state"] = ""
        self.tree.clear()
        for index, row in enumerate(rows):
            item = QTreeWidgetItem([row["name"], row["version"], row["available"],
                                    row["source"], ""])
            item.setData(0, QtC.UserRole, index)
            item.setForeground(1, QColor(T['text_3']))
            item.setForeground(2, QColor(T['ok']))
            item.setForeground(3, QColor(T['text_3']))
            if row["truncated"]:
                # winget shortened the Id with '…'; targeting it would hit the
                # wrong package or nothing. The one-shot task below handles it.
                item.setText(4, "Use “Update Apps” task below")
                item.setForeground(4, QColor(T['text_3']))
                item.setToolTip(4, "winget truncated this app's Id in its list "
                                   "output, so it can't be targeted individually.")
            self.tree.addTopLevelItem(item)
        n = len(rows)
        self.status.setText("Everything winget tracks is up to date." if not n else
                            f"{n} update{'s' if n != 1 else ''} available")
        self._update_buttons()

    # ---- updating ----

    def _targets(self, indexes):
        return [i for i in indexes
                if not self.rows[i]["truncated"] and self.rows[i]["state"] != "ok"]

    def _update_all(self):
        self._start_batch(self._targets(range(len(self.rows))))

    def _update_selected(self):
        indexes = []
        for item in self.tree.selectedItems():
            index = item.data(0, QtC.UserRole)
            if index is not None:
                indexes.append(index)
        self._start_batch(self._targets(indexes))

    def _start_batch(self, indexes):
        if self._busy or not indexes:
            return
        self._busy = True
        self._cancelled = False
        self._failures = 0
        self._updated = 0
        self.pending = list(indexes)
        self.output.clear()
        self.output.setVisible(True)
        self.cancel_btn.setVisible(True)
        self.refresh_btn.setEnabled(False)
        self.all_btn.setEnabled(False)
        self.sel_btn.setEnabled(False)
        planned = [{
            "id": f"app:{self.rows[i]['id']}",
            "title": (f"Update {self.rows[i]['name']} "
                      f"{self.rows[i]['version']} → {self.rows[i]['available']}"),
            "risk": "caution",
            "restore_point": False,
        } for i in indexes]
        try:
            self._session = self.win.journal.start_session("winget", planned)
        except Exception:
            self._session = None
        self.win._log(f"Updating {len(indexes)} app{'s' if len(indexes) != 1 else ''} "
                      f"via winget…", self.T['text_2'])
        self._next()

    def _next(self):
        if self._cancelled or not self.pending:
            self._finish_batch()
            return
        index = self.pending.pop(0)
        row = self.rows[index]
        row["state"] = "updating"
        self._set_row_status(index, "Updating…", self.T['accent'])
        self.status.setText(f"Updating {row['name']}…")
        self._task_started = time.time()
        if self._session:
            try:
                self.win.journal.task_started(self._session, f"app:{row['id']}")
            except Exception:
                pass

        def work():
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            command = ["winget", "upgrade", "--id", row["id"], "--exact", "--silent",
                       "--include-unknown", "--accept-source-agreements",
                       "--accept-package-agreements", "--disable-interactivity"]
            try:
                proc = wm_track_child(subprocess.Popen(
                    command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
                    creationflags=flags, startupinfo=_no_console_startupinfo()))
            except Exception as exc:
                self.q.put(("line", f"Could not start winget: {exc}"))
                self.q.put(("done", index, -1))
                return
            self.proc = proc
            try:
                for raw in proc.stdout:
                    # progress redraws arrive as \r-separated frames on one
                    # line; only the final frame is worth showing
                    line = raw.split("\r")[-1].strip()
                    if line and line not in "-\\|/":
                        self.q.put(("line", line))
            except Exception:
                pass
            proc.wait()
            wm_untrack_child(proc)
            self.proc = None
            self.q.put(("done", index, proc.returncode))
        threading.Thread(target=work, daemon=True).start()

    def _on_done(self, index, code):
        row = self.rows[index]
        duration = time.time() - (self._task_started or time.time())
        if code == 0:
            row["state"] = "ok"
            self._updated += 1
            self._set_row_status(index, "Updated ✓", self.T['ok'])
        else:
            row["state"] = "fail"
            self._failures += 1
            self._set_row_status(index, f"Failed (code {code})", self.T['danger'])
        self.win._log(f"{row['name']}: " + ("updated." if code == 0 else
                      f"update failed (code {code})."),
                      self.T['ok'] if code == 0 else self.T['danger'])
        if self._session:
            try:
                self.win.journal.task_finished(
                    self._session, f"app:{row['id']}",
                    "done" if code == 0 else "failed", duration,
                    "" if code == 0 else f"winget exit code {code}")
            except Exception:
                pass
        self._next()

    def _finish_batch(self):
        self._busy = False
        self.cancel_btn.setVisible(False)
        if self._cancelled:
            for index in self.pending:
                if self.rows[index]["state"] not in ("ok", "fail"):
                    self._set_row_status(index, "Skipped", self.T['text_3'])
        self.pending = []
        summary = f"{self._updated} updated"
        if self._failures:
            summary += f", {self._failures} failed"
        if self._cancelled:
            summary += ", cancelled"
        self.status.setText(f"Done — {summary}.")
        self.win._log(f"App updates finished: {summary}.",
                      self.T['danger'] if self._failures else self.T['ok'])
        if self._session:
            try:
                self.win.journal.complete_session(
                    self._session,
                    "cancelled" if self._cancelled else
                    "failed" if self._failures else "complete")
            except Exception:
                pass
            self._session = None
        self.refresh_btn.setEnabled(True)
        self._update_buttons()
        if self._updated and not self._cancelled:
            QTimer.singleShot(900, self.refresh)  # reflect the new versions

    def _cancel(self):
        self._cancelled = True
        self.cancel_btn.setEnabled(False)
        proc = self.proc
        if proc is not None:
            # The whole tree: winget hands the real work to the package's own
            # installer, which terminate() on winget alone left running.
            # Off the UI thread, as taskkill can take a moment.
            threading.Thread(target=wm_kill_tree, args=(proc,), daemon=True).start()
        self.cancel_btn.setEnabled(True)

    # ---- plumbing ----

    def _set_row_status(self, index, text, colour):
        for i in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(i)
            if item.data(0, QtC.UserRole) == index:
                item.setText(4, text)
                item.setForeground(4, QColor(colour))
                return

    def _update_buttons(self):
        if self._busy:
            return
        available = [r for r in self.rows if not r["truncated"] and r["state"] != "ok"]
        self.all_btn.setEnabled(bool(available))
        selected_ok = False
        for item in self.tree.selectedItems():
            index = item.data(0, QtC.UserRole)
            if index is not None and not self.rows[index]["truncated"] \
                    and self.rows[index]["state"] != "ok":
                selected_ok = True
                break
        self.sel_btn.setEnabled(selected_ok)

    def _drain(self):
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "rows":
                    self._checking = False
                    self.refresh_btn.setEnabled(True)
                    self._fill(msg[1])
                elif kind == "nowinget":
                    self._checking = False
                    self.refresh_btn.setEnabled(True)
                    self.status.setText("winget isn't available — install “App Installer” "
                                        "from the Microsoft Store, then press Refresh.")
                    self.win._log(self.status.text(), self.T['warn'])
                elif kind == "listerror":
                    self._checking = False
                    self.refresh_btn.setEnabled(True)
                    self.status.setText(f"Could not list updates: {msg[1]}")
                    self.win._log(self.status.text(), self.T['danger'])
                elif kind == "line":
                    self.output.appendPlainText(msg[1])
                    self.win._log(msg[1], self.T['text_2'])
                elif kind == "done":
                    self._on_done(msg[1], msg[2])
        except queue.Empty:
            pass
        except RuntimeError:
            pass  # widgets torn down mid-drain
