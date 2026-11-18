"""WinMend ui: pages: apps."""

from __future__ import annotations

from PySide6.QtCore import QTimer, Qt as QtC
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)
from winmend.core.processes import (
    _no_console_startupinfo,
    wm_kill_tree,
    wm_track_child,
    wm_untrack_child,
)
from winmend.data.app_catalog import INSTALLABLE_APPS, get_categories
from winmend.features.apps.winget import parse_winget_list, winget_listing_error
from winmend.ui.pages.storage import WMStoragePage
from winmend.ui.theme import WM_FONT_MONO
from winmend.ui.widgets.controls import WMCheckBox, WMSwitchDelegate
import queue
import subprocess
import threading
import time


class WMAppInstallerPage(QWidget):
    """The app catalogue: pick from INSTALLABLE_APPS and install in one batch.

    Every install is `winget install --id <id> --exact`, so the bytes come from
    the publisher's own source through Microsoft's package manager. WinMend
    hosts nothing and bundles no installers -- the catalogue is just a curated
    list of winget ids with a category and a one-line description.

    Execution rules are the winget update panel's, for the same reasons: one
    install at a time, no timeouts anywhere (a slow download finishes instead of
    being reported as a failure), Cancel terminates the running install and
    skips the rest, and the whole batch is one Safety Journal session.

    The "Installed" column is a real reading from `winget list`. Packages winget
    did not install itself carry a pseudo-id (ARP\\..., MSIX\\...) that can never
    match a catalogue id, so a blank there means "not detected", NOT "not
    installed" -- which is why nothing is ever unticked or hidden on its
    strength unless the user asks for it.
    """

    # Same styling helpers the Storage page uses; they only touch self.T.
    _btn = WMStoragePage._btn
    _tree_style = WMStoragePage._tree_style

    def __init__(self, window):
        super().__init__()
        self.win = window
        self.T = window.T
        self.setStyleSheet("background:transparent;")
        self.apps = [dict(name=name, **data) for name, data
                     in sorted(INSTALLABLE_APPS.items(), key=lambda kv: kv[0].lower())]
        self.items = []          # index-aligned with self.apps
        self.selected = set()    # app names; survives filtering and rebuilds
        self.installed = {}      # winget id (lower) -> installed version
        self.pending = []
        self.proc = None
        self._busy = False
        self._checking = False
        self._cancelled = False
        self._filling = False    # guards itemChanged during programmatic writes
        self._winget = True
        self._listing = None     # batch-scoped cache of what winget reports installed
        self._notes = {}         # index -> (text, colour) for failures worth keeping
        self._session = None
        self._task_started = None
        self._ok = 0
        self._failed = 0
        self._skipped = 0
        self._total = 0
        self.q = queue.Queue()

        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(10)
        v.addWidget(self._controls())
        v.addWidget(self._table(), 1)
        v.addWidget(self._console())
        v.addWidget(self._footer())
        self._build_rows()

        self.pump = QTimer(self)
        self.pump.timeout.connect(self._drain)
        self.pump.start(150)
        QTimer.singleShot(400, self.refresh)

    # ---- chrome ----

    def _controls(self):
        T = self.T
        f = QFrame()
        f.setObjectName("aic")
        f.setStyleSheet(f"#aic{{background:{T['card']};border:1px solid {T['border']};"
                        f"border-radius:8px;}}")
        outer = QVBoxLayout(f)
        outer.setContentsMargins(13, 10, 13, 10)
        outer.setSpacing(9)

        top = QHBoxLayout()
        top.setSpacing(9)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search apps — name, category, or what it does…")
        self.search.setFixedHeight(31)
        self.search.setStyleSheet(
            f"QLineEdit{{background:{T['bg']};border:1px solid {T['border']};"
            f"border-radius:6px;padding-left:10px;color:{T['text']};font-size:12px;}}"
            f"QLineEdit:focus{{border:1px solid {T['accent']};}}")
        self.search.textChanged.connect(self._apply_filter)
        top.addWidget(self.search, 1)

        self.category = QComboBox()
        self.category.setFixedHeight(31)
        self.category.setMinimumWidth(190)
        self.category.setStyleSheet(
            f"QComboBox{{background:{T['bg']};color:{T['text']};border:1px solid {T['border']};"
            f"border-radius:6px;padding:3px 9px;font-size:12px;}}"
            f"QComboBox::drop-down{{border:none;width:18px;}}"
            f"QComboBox QAbstractItemView{{background:{T['card']};color:{T['text']};"
            f"border:1px solid {T['border']};selection-background-color:{T['accent']};}}")
        self.category.addItem(f"All categories  ({len(self.apps)})", "")
        for name in get_categories():
            count = sum(1 for a in self.apps if a["category"] == name)
            self.category.addItem(f"{name}  ({count})", name)
        self.category.currentIndexChanged.connect(self._apply_filter)
        top.addWidget(self.category)

        self.hide_installed = WMCheckBox("Hide installed", T=T)
        self.hide_installed.setToolTip(
            "Hides apps winget reports as already on this PC.\n"
            "Apps installed some other way may not be detected, so this only\n"
            "hides what was actually found.")
        self.hide_installed.setStyleSheet(
            f"QCheckBox{{color:{T['text_2']};font-size:12px;background:transparent;}}")
        self.hide_installed.toggled.connect(self._apply_filter)
        top.addWidget(self.hide_installed)
        outer.addLayout(top)

        row = QHBoxLayout()
        row.setSpacing(9)
        self.status = QLabel("Checking which of these you already have…")
        self.status.setStyleSheet(f"color:{T['text_3']};font-size:12px;background:transparent;")
        self.status.setMinimumWidth(1)  # long status must squeeze, not push buttons out
        row.addWidget(self.status)
        row.addStretch()
        self.visible_btn = self._btn("Select shown", w=104)
        self.visible_btn.clicked.connect(self._select_visible)
        row.addWidget(self.visible_btn)
        self.clear_btn = self._btn("Clear", w=72)
        self.clear_btn.setEnabled(False)
        self.clear_btn.clicked.connect(self._clear_selection)
        row.addWidget(self.clear_btn)
        self.cancel_btn = self._btn("Cancel", w=76)
        self.cancel_btn.setVisible(False)
        self.cancel_btn.clicked.connect(self._cancel)
        row.addWidget(self.cancel_btn)
        self.install_btn = self._btn("Install selected", primary=True, w=132)
        self.install_btn.setEnabled(False)
        self.install_btn.clicked.connect(self._install_selected)
        row.addWidget(self.install_btn)
        outer.addLayout(row)
        return f

    def _table(self):
        self.tree = QTreeWidget()
        self.tree.setColumnCount(4)
        self.tree.setHeaderLabels(["App", "Category", "What it does", "Installed"])
        self.tree.setStyleSheet(self._tree_style() + "QTreeWidget::item{height:32px;}")
        self.tree.setItemDelegateForColumn(0, WMSwitchDelegate(self.tree))
        self.tree.setRootIsDecorated(False)
        self.tree.setUniformRowHeights(True)
        self.tree.setSelectionMode(QTreeWidget.NoSelection)
        self.tree.setFocusPolicy(QtC.StrongFocus)
        self.tree.header().setStretchLastSection(False)
        self.tree.setColumnWidth(0, 270)
        self.tree.setColumnWidth(1, 130)
        self.tree.header().setSectionResizeMode(2, QHeaderView.Stretch)
        self.tree.setColumnWidth(3, 150)
        # The slider delegate handles column 0; the other columns toggle here.
        self.tree.itemClicked.connect(self._row_clicked)
        self.tree.itemChanged.connect(self._item_changed)
        return self.tree

    def _console(self):
        T = self.T
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setFixedHeight(132)
        self.output.setMaximumBlockCount(800)
        self.output.setVisible(False)
        self.output.setStyleSheet(
            f"QPlainTextEdit{{background:{T['bg']};color:{T['text_2']};"
            f"border:1px solid {T['border']};border-radius:7px;"
            f"font-family:{WM_FONT_MONO};font-size:11px;padding:4px;}}")
        return self.output

    def _footer(self):
        hint = QLabel(
            "Apps install through winget, Microsoft's package manager, from each "
            "publisher's own source — WinMend hosts nothing and bundles no installers. "
            "They install one at a time, silently where the publisher supports it; a few "
            "ask Windows for permission first. Nothing is uninstalled here.")
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color:{self.T['text_3']};font-size:11px;background:transparent;")
        return hint

    # ---- rows ----

    def _build_rows(self):
        T = self.T
        self._filling = True
        self.tree.clear()
        self.items = []
        for index, app in enumerate(self.apps):
            item = QTreeWidgetItem([app["name"], app["category"], app["description"], ""])
            item.setData(0, QtC.UserRole, index)
            item.setFlags(item.flags() | QtC.ItemIsUserCheckable)
            item.setCheckState(0, QtC.Checked if app["name"] in self.selected
                               else QtC.Unchecked)
            item.setForeground(1, QColor(T['text_3']))
            item.setForeground(2, QColor(T['text_3']))
            item.setToolTip(0, f"winget id: {app['winget']}")
            item.setToolTip(2, app["description"])
            self.tree.addTopLevelItem(item)
            self.items.append(item)
        self._filling = False
        self._apply_filter()

    def _row_clicked(self, item, column):
        # Column 0 already toggles via the indicator; toggling again here would
        # cancel it out.
        if column != 0 and not self._busy:
            item.setCheckState(0, QtC.Unchecked
                               if item.checkState(0) == QtC.Checked else QtC.Checked)

    def _item_changed(self, item, column):
        if self._filling or column != 0:
            return
        index = item.data(0, QtC.UserRole)
        if index is None:
            return
        name = self.apps[index]["name"]
        if item.checkState(0) == QtC.Checked:
            self.selected.add(name)
        else:
            self.selected.discard(name)
            if self._busy and index in self.pending:
                # Unticking something still queued takes it out of the batch --
                # otherwise the tick says "no" while the app installs anyway.
                self.pending.remove(index)
                self._total -= 1
                self._set_status(index, "Removed from the batch",
                                 self.T['text_3'], scroll=False)
        self._update_summary()

    def _apply_filter(self):
        needle = self.search.text().strip().lower()
        wanted = self.category.currentData() or ""
        hide = self.hide_installed.isChecked()
        shown = 0
        for index, app in enumerate(self.apps):
            ok = (not wanted) or app["category"] == wanted
            if ok and hide and self._is_known_installed(app):
                ok = False
            if ok and needle:
                ok = needle in (f"{app['name']} {app['category']} "
                                f"{app['description']} {app['winget']}").lower()
            self.items[index].setHidden(not ok)
            shown += ok
        self._shown = shown
        self._update_summary()

    def _visible_indexes(self):
        return [i for i in range(len(self.apps)) if not self.items[i].isHidden()]

    def _select_visible(self):
        self._set_checked(self._visible_indexes(), True)

    def _clear_selection(self):
        self._set_checked(range(len(self.apps)), False)

    def _set_checked(self, indexes, checked):
        self._filling = True
        state = QtC.Checked if checked else QtC.Unchecked
        for index in indexes:
            self.items[index].setCheckState(0, state)
            name = self.apps[index]["name"]
            if checked:
                self.selected.add(name)
            else:
                self.selected.discard(name)
        self._filling = False
        self._update_summary()

    def _update_summary(self):
        count = len(self.selected)
        self.install_btn.setText(f"Install {count}" if count else "Install selected")
        if self._busy:
            # A run owns the status line and the buttons until it finishes.
            return
        shown = getattr(self, "_shown", len(self.apps))
        bits = [f"{shown} of {len(self.apps)} apps shown"]
        if self._checking:
            bits.append("checking what you already have…")
        elif self.installed:
            found = sum(1 for a in self.apps if self._is_known_installed(a))
            bits.append(f"{found} already installed")
        bits.append(f"{count} selected" if count else "none selected")
        self.status.setText("  ·  ".join(bits))
        self.clear_btn.setEnabled(bool(count))
        self.install_btn.setEnabled(bool(count) and self._winget)

    # ---- installed detection ----

    def _is_known_installed(self, app):
        """Whether winget reported this app installed at the last reading.

        Membership, not the version string: a freshly installed app is recorded
        before its version is known, and an empty version must not read as
        "not installed".
        """
        return app["winget"].lower() in self.installed

    def _installed_version(self, app):
        return self.installed.get(app["winget"].lower(), "")

    def on_revisit(self):
        """Re-read what is installed on navigation back -- an app installed
        elsewhere meanwhile should stop showing as missing."""
        if not self._busy:
            self.refresh()

    def refresh(self):
        if self._checking or self._busy:
            return
        self._checking = True

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
                # Read-only listing; no timeout -- a slow source refresh should
                # complete rather than be reported as a failure.
                result = subprocess.run(
                    ["winget", "list", "--accept-source-agreements",
                     "--disable-interactivity"],
                    capture_output=True, text=True, encoding="utf-8",
                    errors="replace", creationflags=flags,
                    startupinfo=_no_console_startupinfo())
                error = winget_listing_error(result)
                if error:
                    raise RuntimeError(error)
                self.q.put(("installed", parse_winget_list(result.stdout or "")))
            except Exception as exc:
                self.q.put(("listerror", str(exc)))
        threading.Thread(target=work, daemon=True).start()

    def _fill_installed(self, installed):
        self._checking = False
        self.installed = installed
        self._filling = True
        for index, app in enumerate(self.apps):
            known = self._is_known_installed(app)
            version = self._installed_version(app)
            item = self.items[index]
            item.setText(3, ("Yes  ·  " + version) if version else
                            "Yes" if known else "")
            item.setForeground(3, QColor(self.T['ok'] if known else self.T['text_3']))
            item.setToolTip(3, (f"winget reports {app['winget']} installed, so it "
                                f"will be skipped.") if known else
                               ("Not found in what winget reports installed. Apps "
                                "installed some other way may not show up here."))
        # A failure from the last run outlives this repaint: replacing "Failed"
        # with a blank cell would quietly erase the only record the user has.
        for index, (text, colour) in self._notes.items():
            self.items[index].setText(3, text)
            self.items[index].setForeground(3, QColor(colour))
        self._filling = False
        self._apply_filter()

    # ---- installing ----

    def _install_selected(self):
        if self._busy:
            return
        chosen = [i for i, app in enumerate(self.apps) if app["name"] in self.selected]
        already = [i for i in chosen if self._is_known_installed(self.apps[i])]
        targets = [i for i in chosen if i not in set(already)]
        if not targets:
            QMessageBox.information(
                self, "Nothing to install",
                "Everything you picked is already installed on this PC.\n\n"
                "Use Updates & Drivers to bring installed apps up to date.")
            return

        names = [self.apps[i]["name"] for i in targets]
        preview = ", ".join(names[:12]) + ("…" if len(names) > 12 else "")
        note = ""
        if already:
            note = (f"\n\n{len(already)} of your picks "
                    f"{'is' if len(already) == 1 else 'are'} already installed and "
                    f"will be skipped.")
        if QMessageBox.question(
                self, "Install apps",
                f"Install {len(targets)} app{'s' if len(targets) != 1 else ''} with "
                f"winget?\n\n{preview}{note}\n\nThey download from each publisher's "
                f"own source and install one at a time. Some installers will ask "
                f"Windows for permission.",
                QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return

        self._busy = True
        self._cancelled = False
        self._listing = None
        self._notes = {}
        self._ok = 0
        self._failed = 0
        self._skipped = len(already)
        self.pending = list(targets)
        self.output.clear()
        self.output.setVisible(True)
        self.cancel_btn.setVisible(True)
        self.install_btn.setEnabled(False)
        self.visible_btn.setEnabled(False)
        self.clear_btn.setEnabled(False)
        for index in already:
            self._set_status(index, "Skipped — already installed", self.T['text_3'])
        planned = [{
            "id": f"install:{self.apps[i]['winget']}",
            "title": f"Install {self.apps[i]['name']}",
            "risk": "caution",
            "restore_point": False,
        } for i in targets]
        try:
            self._session = self.win.journal.start_session("appinstall", planned)
        except Exception:
            self._session = None
        self.win._log(f"Installing {len(targets)} app{'s' if len(targets) != 1 else ''} "
                      f"via winget…", self.T['text_2'])
        self._total = len(targets)
        self._next()

    def _next(self):
        if self._cancelled or not self.pending:
            self._finish()
            return
        index = self.pending.pop(0)
        app = self.apps[index]
        done = self._total - len(self.pending)
        self.status.setText(f"Installing {app['name']} — {done} of {self._total}…")
        self._set_status(index, "Installing…", self.T['accent'])
        self._task_started = time.time()
        if self._session:
            try:
                self.win.journal.task_started(self._session, f"install:{app['winget']}")
            except Exception:
                pass

        def work():
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            command = ["winget", "install", "--id", app["winget"], "--exact",
                       "--silent", "--accept-package-agreements",
                       "--accept-source-agreements", "--disable-interactivity"]
            try:
                proc = wm_track_child(subprocess.Popen(
                    command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
                    creationflags=flags, startupinfo=_no_console_startupinfo()))
            except Exception as exc:
                self.q.put(("line", f"Could not start winget: {exc}"))
                self.q.put(("done", index, None, False))
                return
            self.proc = proc
            try:
                for raw in proc.stdout:
                    # progress redraws arrive as \r-separated frames on one line;
                    # only the final frame is worth showing
                    line = raw.split("\r")[-1].strip()
                    if line and line not in "-\\|/":
                        self.q.put(("line", line))
            except Exception:
                pass
            proc.wait()
            wm_untrack_child(proc)
            self.proc = None
            code = proc.returncode
            # A non-zero exit is not proof of failure -- winget also returns one
            # when the package was already present. Rather than hard-code its
            # error constants (Windows hands them back as unsigned ints, and the
            # set has changed between winget releases), ask whether the package
            # is actually there now.
            present = (False if (code == 0 or self._cancelled)
                       else self._is_installed(app["winget"]))
            self.q.put(("done", index, code, present))
        threading.Thread(target=work, daemon=True).start()

    @staticmethod
    def _code_text(code):
        """winget's failures are documented as hex constants (0x8A15...) and
        Windows hands them back as large unsigned ints, so show the form the
        user can actually look up."""
        if code is None:
            return "winget would not start"
        if isinstance(code, int) and code > 0xFFFF:
            return f"code 0x{code:08X}"
        return f"code {code}"

    def _is_installed(self, pkg_id):
        """Whether winget can see this exact package installed, right now.

        Deliberately reads the UNFILTERED listing. `winget list --id X --exact`
        looks like the right question but is not: when nothing installed
        matches, winget quietly falls back to the package as it exists in the
        remote source and prints a row identical in shape to an installed one
        (verified here -- an uninstalled Vivaldi came back looking exactly like
        an installed 7-Zip, both exit 0). Only the unfiltered listing is
        installed-only, so that is what gets asked.

        The listing is cached for the batch and thrown away after any successful
        install, so a run of failures costs one listing, not one per app.
        """
        if self._listing is None:
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            try:
                # Bounded, unlike an install: a hung lookup must not strand the
                # rest of the batch.
                result = subprocess.run(
                    ["winget", "list", "--accept-source-agreements",
                     "--disable-interactivity"],
                    capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=180, creationflags=flags,
                    startupinfo=_no_console_startupinfo())
                error = winget_listing_error(result)
                if error:
                    self.q.put(("line", f"Could not verify installed apps: {error}"))
                    return False
                self._listing = parse_winget_list(result.stdout or "")
            except Exception:
                self._listing = {}
        return pkg_id.lower() in self._listing

    def _on_done(self, index, code, present):
        app = self.apps[index]
        duration = time.time() - (self._task_started or time.time())
        if code == 0:
            self._ok += 1
            self._set_status(index, "Installed ✓", self.T['ok'])
            state, error = "done", ""
        elif present:
            self._skipped += 1
            self._set_status(index, "Already installed", self.T['text_3'])
            state, error = "done", ""
        else:
            self._failed += 1
            note = f"Failed — {self._code_text(code)}"
            self._set_status(index, note, self.T['danger'])
            self._notes[index] = (note, self.T['danger'])
            state, error = "failed", f"winget {self._code_text(code)}"
        self.win._log(f"{app['name']}: " + ("installed" if code == 0 else
                      "already installed" if present else error) + ".",
                      self.T['danger'] if state == "failed" else self.T['ok'])
        if code == 0:
            self._listing = None  # this install changed what is installed
        if code == 0 or present:
            # Reflect the new reality without re-running the whole listing.
            self.installed.setdefault(app["winget"].lower(), "")
            self._filling = True
            self.items[index].setCheckState(0, QtC.Unchecked)
            self._filling = False
            self.selected.discard(app["name"])
        if self._session:
            try:
                self.win.journal.task_finished(
                    self._session, f"install:{app['winget']}", state, duration, error)
            except Exception:
                pass
        self._next()

    def _finish(self):
        self._busy = False
        self.cancel_btn.setVisible(False)
        if self._cancelled:
            for index in self.pending:
                self._set_status(index, "Skipped", self.T['text_3'])
        self.pending = []
        summary = f"{self._ok} installed"
        if self._failed:
            summary += f", {self._failed} failed"
        if self._skipped:
            summary += f", {self._skipped} skipped"
        if self._cancelled:
            summary += ", cancelled"
        self.win._log(f"App installs finished: {summary}.",
                      self.T['danger'] if self._failed else self.T['ok'])
        if self._session:
            try:
                self.win.journal.complete_session(
                    self._session,
                    "cancelled" if self._cancelled else
                    "failed" if self._failed else "complete")
            except Exception:
                pass
            self._session = None
        self.visible_btn.setEnabled(True)
        self._update_summary()
        self.status.setText(f"Done — {summary}.")
        if self._ok and not self._cancelled:
            QTimer.singleShot(1200, self.refresh)  # pick up the new versions

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

    def _set_status(self, index, text, colour, scroll=True):
        self._filling = True
        item = self.items[index]
        item.setText(3, text)
        item.setForeground(3, QColor(colour))
        self._filling = False
        if scroll:
            self.tree.scrollToItem(item)

    def _drain(self):
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "installed":
                    self._fill_installed(msg[1])
                elif kind == "nowinget":
                    self._checking = False
                    self._winget = False
                    self.install_btn.setEnabled(False)
                    self.status.setText(
                        "winget isn't available — install “App Installer” from the "
                        "Microsoft Store, then reopen this page.")
                    self.win._log(self.status.text(), self.T['warn'])
                elif kind == "listerror":
                    self._checking = False
                    self.status.setText(
                        f"Could not read installed apps: {msg[1]}. You can still install.")
                    self.win._log(self.status.text(), self.T['danger'])
                elif kind == "line":
                    self.output.appendPlainText(msg[1])
                    self.win._log(msg[1], self.T['text_2'])
                elif kind == "done":
                    self._on_done(msg[1], msg[2], msg[3])
        except queue.Empty:
            pass
        except RuntimeError:
            pass  # widgets torn down mid-drain
