"""WinMend ui: pages: storage."""

from __future__ import annotations

from PySide6.QtCore import QTimer, Qt as QtC
from PySide6.QtGui import QColor, QFont, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QTreeWidgetItemIterator,
    QVBoxLayout,
    QWidget,
)
from datetime import datetime
from winmend.features.storage.duplicates import wm_find_duplicates
from winmend.features.storage.scanner import (
    SSSafetyRules,
    SSScanner,
    SS_COLOR_CORE,
    SS_COLOR_LARGE,
    SS_COLOR_MEDIUM,
    SS_THRESHOLD_GB,
    SS_THRESHOLD_MB,
    ss_format_size,
    ss_get_drive_health_info,
    ss_get_file_hint,
    ss_send_to_recycle_bin,
)
from winmend.features.storage.tree import SSNode, wm_build_tree, wm_duration
from winmend.ui.theme import WM_FONT, WM_ICON_FONT
import os
import queue
import threading
import time


class WMStoragePage(QWidget):
    """Storage Analyzer, rebuilt as a page in the main window.

    Borrows the entire safety classifier from SSSafetyRules rather than
    reimplementing it -- those rules encode which paths must never be
    auto-deleted (OS files, documents, cloud-synced folders, game libraries,
    source trees, fresh downloads) and are the most valuable part of the old
    window. They are pure functions, so they transfer verbatim.
    """

    # --- borrowed, unmodified, from the legacy window ---
    _HIGH_RISK_EXTS = SSSafetyRules._HIGH_RISK_EXTS
    _is_system_path = SSSafetyRules._is_system_path
    _is_critical_system_path = SSSafetyRules._is_critical_system_path
    _is_protected_cleanup_path = SSSafetyRules._is_protected_cleanup_path
    _is_windows_search_db = SSSafetyRules._is_windows_search_db
    _is_user_data_path = SSSafetyRules._is_user_data_path
    _is_cloud_sync_path = SSSafetyRules._is_cloud_sync_path
    _is_high_risk_extension = SSSafetyRules._is_high_risk_extension
    _is_game_library_path = SSSafetyRules._is_game_library_path
    _is_repo_or_project_path = SSSafetyRules._is_repo_or_project_path
    _is_recent_download = SSSafetyRules._is_recent_download
    _is_unsafe_to_auto_delete = SSSafetyRules._is_unsafe_to_auto_delete
    _classify_safety = SSSafetyRules._classify_safety
    _is_excluded_from_top_hogs = SSSafetyRules._is_excluded_from_top_hogs

    def __init__(self, window):
        super().__init__()
        self.win = window
        self.T = window.T
        self.setStyleSheet("background:transparent;")
        self.scanner = None
        self.scan_thread = None
        self.results = {}
        self._scan_error = None
        self.q = queue.Queue()
        self.root_node = None
        self.view_node = None
        self.started = None
        self.dupe_thread = None

        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(10)
        v.addWidget(self._controls())
        v.addWidget(self._statusbar())
        v.addWidget(self._trees(), 1)
        v.addWidget(self._legend())
        v.addWidget(self._bottom())

        self.pump = QTimer(self)
        self.pump.timeout.connect(self._drain)
        self.pump.start(150)
        QTimer.singleShot(50, self._load_drives)

        # Keyboard: Backspace goes up a folder, Delete recycles the selection.
        # Scoped to this page's trees so they don't fire elsewhere in the app.
        up = QShortcut(QKeySequence(QtC.Key_Backspace), self.tree_left)
        up.activated.connect(self._go_up)
        for tree in (self.tree_left, self.tree_right):
            sc = QShortcut(QKeySequence(QtC.Key_Delete), tree)
            sc.activated.connect(
                lambda t=tree: self._delete_nodes(
                    [it.data(0, QtC.UserRole) for it in t.selectedItems()
                     if it.data(0, QtC.UserRole) is not None]))

    # ---- chrome ----

    def _btn(self, text, primary=False, w=112):
        T = self.T
        b = QPushButton(text)
        b.setFixedHeight(32)
        b.setMinimumWidth(w)
        b.setCursor(QtC.PointingHandCursor)
        if primary:
            b.setStyleSheet(f"QPushButton{{background:{T['accent']};color:#fff;border:none;"
                            f"border-radius:6px;font-size:12px;font-weight:600;}}"
                            f"QPushButton:hover{{background:{T['accent_hi']};}}"
                            f"QPushButton:disabled{{background:{T['card_hi']};color:{T['text_3']};}}")
        else:
            b.setStyleSheet(f"QPushButton{{background:transparent;color:{T['text_2']};"
                            f"border:1px solid {T['border_hi']};border-radius:6px;font-size:12px;}}"
                            f"QPushButton:hover{{background:{T['card_hi']};color:{T['text']};}}"
                            f"QPushButton:disabled{{color:{T['text_3']};border-color:{T['border']};}}")
        return b

    def _controls(self):
        T = self.T
        f = QFrame()
        f.setObjectName("sc")
        f.setStyleSheet(f"#sc{{background:{T['card']};border:1px solid {T['border']};"
                        f"border-radius:8px;}}")
        h = QHBoxLayout(f)
        h.setContentsMargins(13, 10, 13, 10)
        h.setSpacing(9)

        lbl = QLabel("Drive")
        lbl.setStyleSheet(f"color:{T['text_3']};font-size:12px;background:transparent;")
        h.addWidget(lbl)
        self.drive = QComboBox()
        self.drive.setFixedHeight(31)
        self.drive.setMinimumWidth(230)
        self.drive.setStyleSheet(
            f"QComboBox{{background:{T['bg']};color:{T['text']};border:1px solid {T['border']};"
            f"border-radius:6px;padding:3px 9px;font-size:12px;}}"
            f"QComboBox::drop-down{{border:none;width:18px;}}"
            f"QComboBox QAbstractItemView{{background:{T['card']};color:{T['text']};"
            f"border:1px solid {T['border']};selection-background-color:{T['accent']};}}")
        h.addWidget(self.drive)

        ml = QLabel("Show files over")
        ml.setStyleSheet(f"color:{T['text_3']};font-size:12px;background:transparent;")
        h.addWidget(ml)
        self.minmb = QComboBox()
        self.minmb.addItems(["1 MB", "10 MB", "50 MB", "100 MB", "500 MB"])
        self.minmb.setCurrentText("10 MB")
        self.minmb.setFixedHeight(31)
        self.minmb.setStyleSheet(self.drive.styleSheet())
        h.addWidget(self.minmb)

        h.addStretch()
        self.scan_btn = self._btn("Scan drive", primary=True)
        self.scan_btn.clicked.connect(self._start_scan)
        h.addWidget(self.scan_btn)
        self.stop_btn = self._btn("Stop", w=74)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_scan)
        h.addWidget(self.stop_btn)
        return f

    def _statusbar(self):
        T = self.T
        f = QFrame()
        f.setObjectName("sb")
        f.setStyleSheet(f"#sb{{background:transparent;}}")
        h = QHBoxLayout(f)
        h.setContentsMargins(2, 0, 2, 0)
        h.setSpacing(11)
        self.status = QLabel("Ready.")
        self.status.setStyleSheet(f"color:{T['text_2']};font-size:12px;background:transparent;")
        h.addWidget(self.status)
        h.addStretch()
        self.health = QLabel("")
        self.health.setStyleSheet(f"color:{T['text_3']};font-size:12px;background:transparent;")
        h.addWidget(self.health)
        self.bar = QProgressBar()
        self.bar.setFixedSize(150, 5)
        self.bar.setTextVisible(False)
        self.bar.setRange(0, 0)   # indeterminate: a full walk has no real percentage
        self.bar.setVisible(False)
        self.bar.setStyleSheet(
            f"QProgressBar{{background:{T['card_hi']};border:none;border-radius:2px;}}"
            f"QProgressBar::chunk{{background:{T['accent']};border-radius:2px;}}")
        h.addWidget(self.bar)
        return f

    def _tree_style(self):
        T = self.T
        return (
            f"QTreeWidget{{background:{T['card']};color:{T['text_2']};"
            f"border:1px solid {T['border']};border-radius:8px;font-size:12px;"
            f"outline:none;}}"
            f"QTreeWidget::item{{height:25px;border:none;}}"
            f"QTreeWidget::item:hover{{background:{T['card_hi']};}}"
            f"QTreeWidget::item:selected{{background:{T['accent']};color:#fff;}}"
            f"QHeaderView::section{{background:{T['sidebar']};color:{T['text_3']};"
            f"border:none;border-bottom:1px solid {T['border']};padding:6px 8px;"
            f"font-size:11px;font-weight:600;}}"
            f"QTreeWidget::branch{{background:transparent;}}"
            # The window-wide rule hides horizontal scrollbars; the details pane
            # has more columns than fit, so restore one here.
            f"QScrollBar:horizontal{{background:transparent;height:9px;margin:0;}}"
            f"QScrollBar::handle:horizontal{{background:{T['border_hi']};"
            f"border-radius:4px;min-width:30px;}}"
            f"QScrollBar::handle:horizontal:hover{{background:{T['text_3']};}}"
            f"QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal{{width:0;}}"
            f"QScrollBar::add-page:horizontal,QScrollBar::sub-page:horizontal"
            f"{{background:none;}}")

    def _trees(self):
        """The original two-pane layout: folder tree on the left, details of the
        selected folder on the right."""
        T = self.T
        split = QSplitter(QtC.Horizontal)
        split.setStyleSheet(f"QSplitter::handle{{background:{T['border']};width:2px;}}")

        left = QWidget()
        left.setStyleSheet("background:transparent;")
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 0, 0)
        lv.setSpacing(5)

        lhead = QHBoxLayout()
        lhead.setContentsMargins(0, 0, 0, 0)
        lhead.setSpacing(7)
        # Back arrow: go up to the parent folder. Segoe MDL2 U+E72B is the "Back"
        # chevron used across Windows.
        self.back_btn = QPushButton("")
        self.back_btn.setCursor(QtC.PointingHandCursor)
        self.back_btn.setFixedSize(26, 22)
        self.back_btn.setToolTip("Go up to the parent folder  (Backspace)")
        self.back_btn.setEnabled(False)
        self.back_btn.setStyleSheet(
            f"QPushButton{{background:transparent;color:{T['text_2']};border:1px solid "
            f"{T['border_hi']};border-radius:5px;font-family:{WM_ICON_FONT};font-size:11px;}}"
            f"QPushButton:hover{{background:{T['card_hi']};color:{T['text']};}}"
            f"QPushButton:disabled{{color:{T['text_3']};border-color:{T['border']};}}")
        self.back_btn.clicked.connect(self._go_up)
        lhead.addWidget(self.back_btn)
        lt = QLabel("Directory Tree")
        lt.setStyleSheet(f"color:{T['text_3']};font-size:11px;font-weight:600;"
                         f"background:transparent;")
        lhead.addWidget(lt)
        lhead.addStretch()
        lv.addLayout(lhead)

        self.tree_left = QTreeWidget()
        self.tree_left.setColumnCount(2)
        self.tree_left.setHeaderLabels(["Folder", "Size"])
        self.tree_left.setStyleSheet(self._tree_style())
        self.tree_left.setRootIsDecorated(True)
        self.tree_left.setUniformRowHeights(True)
        self.tree_left.header().setStretchLastSection(False)
        self.tree_left.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.tree_left.header().setSectionResizeMode(1, QHeaderView.Fixed)
        self.tree_left.setColumnWidth(1, 88)
        self.tree_left.itemSelectionChanged.connect(self._on_left_select)
        self.tree_left.itemExpanded.connect(self._on_expand)
        self.tree_left.setContextMenuPolicy(QtC.CustomContextMenu)
        self.tree_left.customContextMenuRequested.connect(
            lambda pos: self._tree_menu(self.tree_left, pos))
        lv.addWidget(self.tree_left, 1)
        split.addWidget(left)

        right = QWidget()
        right.setStyleSheet("background:transparent;")
        rv = QVBoxLayout(right)
        rv.setContentsMargins(0, 0, 0, 0)
        rv.setSpacing(5)
        head = QHBoxLayout()
        head.setContentsMargins(0, 0, 0, 0)
        head.setSpacing(8)
        self.right_title = QLabel("Contents")
        self.right_title.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.right_title.setStyleSheet(f"color:{T['text_3']};font-size:11px;"
                                       f"font-weight:600;background:transparent;")
        head.addWidget(self.right_title, 1)
        # Contents / Largest files toggle — the flat "biggest things on the whole
        # drive" list is what answers "where is my space going", and the folder
        # tree alone cannot show it.
        self.view_btns = {}
        seg = QFrame()
        seg.setStyleSheet(f"background:{T['bg']};border:1px solid {T['border']};"
                          f"border-radius:6px;")
        sl = QHBoxLayout(seg)
        sl.setContentsMargins(2, 2, 2, 2)
        sl.setSpacing(2)
        for name in ("Contents", "Largest files"):
            b = QPushButton(name)
            b.setCursor(QtC.PointingHandCursor)
            b.setFixedHeight(22)
            b.setMinimumWidth(84)
            b.clicked.connect(lambda _=False, n=name: self._set_right_view(n))
            self.view_btns[name] = b
            sl.addWidget(b)
        head.addWidget(seg)
        rv.addLayout(head)
        self.right_view = "Contents"
        self.tree_right = QTreeWidget()
        cols = ["Name", "Size", "Files", "Folders", "% of Parent", "Modified", "Hint"]
        self.tree_right.setColumnCount(len(cols))
        self.tree_right.setHeaderLabels(cols)
        self.tree_right.setStyleSheet(self._tree_style())
        self.tree_right.setRootIsDecorated(False)
        self.tree_right.setUniformRowHeights(True)
        self.tree_right.setSelectionMode(QTreeWidget.ExtendedSelection)  # multi-select
        self.tree_right.setSortingEnabled(False)
        # Every column resizable, none stretched: with 7 columns in an embedded
        # pane a stretched Name gets squeezed to nothing. Fixed widths + a
        # horizontal scrollbar keeps every column readable instead.
        self.tree_right.header().setStretchLastSection(True)
        for i, w in ((0, 168), (1, 84), (2, 58), (3, 62), (4, 72), (5, 112), (6, 150)):
            self.tree_right.header().setSectionResizeMode(i, QHeaderView.Interactive)
            self.tree_right.setColumnWidth(i, w)
        self.tree_right.itemSelectionChanged.connect(self._on_right_select)
        self.tree_right.itemDoubleClicked.connect(self._on_right_double)
        self.tree_right.setContextMenuPolicy(QtC.CustomContextMenu)
        self.tree_right.customContextMenuRequested.connect(
            lambda pos: self._tree_menu(self.tree_right, pos))
        rv.addWidget(self.tree_right, 1)
        split.addWidget(right)

        # The folder tree needs less room than the 7-column details pane.
        split.setSizes([250, 470])
        split.setStretchFactor(0, 0)
        split.setStretchFactor(1, 1)
        self._restyle_view_btns()
        return split

    def _legend(self):
        T = self.T
        f = QFrame()
        f.setStyleSheet("background:transparent;")
        h = QHBoxLayout(f)
        h.setContentsMargins(2, 0, 2, 0)
        h.setSpacing(6)
        self.sel_lbl = QLabel("Select a folder on the left to see what is inside it.")
        self.sel_lbl.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.sel_lbl.setStyleSheet(f"color:{T['text_3']};font-size:12px;background:transparent;")
        h.addWidget(self.sel_lbl, 1)
        h.addSpacing(12)
        # The original size legend: red over 1 GB, orange over 100 MB, blue for
        # Windows core files.
        for colour, text in ((SS_COLOR_LARGE, "Over 1 GB"),
                             (SS_COLOR_MEDIUM, "Over 100 MB"),
                             (SS_COLOR_CORE, "Windows core file")):
            d = QLabel("■")
            d.setStyleSheet(f"color:{colour};font-size:11px;background:transparent;")
            h.addWidget(d)
            t = QLabel(text)
            t.setStyleSheet(f"color:{T['text_3']};font-size:11px;background:transparent;")
            h.addWidget(t)
            h.addSpacing(5)
        return f

    def _bottom(self):
        f = QFrame()
        f.setStyleSheet("background:transparent;")
        h = QHBoxLayout(f)
        h.setContentsMargins(2, 0, 2, 0)
        h.setSpacing(9)
        h.addStretch()
        self.dupe_btn = self._btn("Find duplicates", w=132)
        self.dupe_btn.clicked.connect(self._find_dupes)
        self.dupe_btn.setEnabled(False)
        h.addWidget(self.dupe_btn)
        self.open_btn = self._btn("Open in Explorer", w=136)
        self.open_btn.clicked.connect(self._open_selected)
        self.open_btn.setEnabled(False)
        h.addWidget(self.open_btn)
        self.del_btn = self._btn("Move to Recycle Bin", w=156)
        self.del_btn.clicked.connect(self._delete_selected)
        self.del_btn.setEnabled(False)
        h.addWidget(self.del_btn)
        return f

    # ---- drives ----

    def _load_drives(self):
        def work():
            out = []
            try:
                import psutil
                for p in psutil.disk_partitions(all=False):
                    try:
                        u = psutil.disk_usage(p.mountpoint)
                        out.append((p.mountpoint,
                                    f"{p.mountpoint}  —  {ss_format_size(u.free)} free "
                                    f"of {ss_format_size(u.total)}"))
                    except Exception:
                        continue
            except Exception:
                out.append(("C:\\", "C:\\"))
            self.win.host.root.after(0, lambda: self._fill_drives(out))
        threading.Thread(target=work, daemon=True).start()

    def _fill_drives(self, out):
        try:
            self.drive.clear()
            for path, label in out:
                self.drive.addItem(label, path)
        except RuntimeError:
            pass

    # ---- scanning ----

    def _start_scan(self):
        if self.scan_thread is not None:
            return
        path = self.drive.currentData() or "C:\\"
        mb = int(self.minmb.currentText().split()[0])
        # The result belongs to the drive that was scanned, whatever the combo
        # says by the time it ends: _finish_scan used to re-read the combo, so
        # changing it mid-scan built the tree for the wrong root -- "104,064
        # files · 0B" and an empty tree. The combos are also locked meanwhile.
        self.scan_path = path
        self.drive.setEnabled(False)
        self.minmb.setEnabled(False)
        self.results = {}
        self._scan_error = None
        self.q = queue.Queue()
        self.root_node = self.view_node = None
        self.back_btn.setEnabled(False)
        self.tree_left.clear()
        self.tree_right.clear()
        self.started = time.time()
        self.status.setText(f"Scanning {path} — this has no time limit and will finish.")
        self.win._log(f"Storage scan started: {path}.", self.T['text_2'])
        self.bar.setVisible(True)
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.dupe_btn.setEnabled(False)

        self.scanner = SSScanner(path, mb, self._on_entry, self.q)

        def work():
            try:
                self.scanner.scan()
            except Exception as e:
                self.q.put(("error", str(e)))
            finally:
                self.q.put(("done", None))

        self.scan_thread = threading.Thread(target=work, daemon=True)
        self.scan_thread.start()
        self._refresh_health(path)

    def _on_entry(self, path, meta):
        # called from the scanner thread — just queue it
        self.q.put(("entry", (path, meta)))

    def _stop_scan(self):
        if self.scanner is not None:
            self.scanner.stop()
        self.status.setText("Stopping…")

    def _drain(self):
        n = 0
        while n < 4000:   # bounded: a scan can emit tens of thousands of entries
            try:
                kind, payload = self.q.get_nowait()
            except queue.Empty:
                break
            n += 1
            if kind == "entry":
                path, meta = payload
                self.results[os.path.normpath(path)] = meta
            elif kind == "error":
                self._scan_error = str(payload)
                self.status.setText(f"Scan error: {payload}")
                self.win._log(f"Storage scan failed: {payload}", self.T['danger'])
            elif kind == "done":
                self._finish_scan()
        if n and self.scan_thread is not None:
            el = int(time.time() - (self.started or time.time()))
            sc = self.scanner
            self.status.setText(
                f"Scanning… {sc.total_files:,} files · {sc.total_folders:,} folders · "
                f"{ss_format_size(sc.scanned_bytes)} · {el // 60:02d}:{el % 60:02d} elapsed"
                + (f" · {sc.total_errors:,} unreadable" if sc.total_errors else ""))

    def _finish_scan(self):
        self.scan_thread = None
        self.bar.setVisible(False)
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.drive.setEnabled(True)
        self.minmb.setEnabled(True)
        path = getattr(self, "scan_path", None) or self.drive.currentData() or "C:\\"
        self.root_node = wm_build_tree(self.results, path)
        self._populate_left(self.root_node)
        if self.right_view == "Largest files":
            self._populate_largest()
        self.dupe_btn.setEnabled(True)
        el = time.time() - (self.started or time.time())
        sc = self.scanner
        stopped = sc is not None and not sc.is_running
        error = getattr(self, "_scan_error", None)
        self.status.setText(
            (f"Scan failed: {error}. Showing partial results. " if error else
             "Scan stopped — showing partial results. " if stopped else "Scan complete. ")
            + f"{sc.total_files:,} files · {ss_format_size(self.root_node.size)} · "
              f"took {wm_duration(el)}"
            + (f" · {sc.total_errors:,} unreadable (normal for system paths)"
               if sc.total_errors else ""))
        self.win._log("Storage: " + self.status.text(),
                      self.T['danger'] if error else self.T['warn'] if stopped else self.T['ok'])

    def _refresh_health(self, path):
        def work():
            try:
                info = ss_get_drive_health_info(path)
                st = info.get("status", "Unknown")
            except Exception:
                st = "Unknown"
            self.win.host.root.after(0, lambda: self._set_health(st))
        threading.Thread(target=work, daemon=True).start()

    def _set_health(self, st):
        T = self.T
        col = T['ok'] if st == "Healthy" else T['warn'] if st == "Unknown" else T['danger']
        try:
            self.health.setText(f"Drive health: {st}")
            self.health.setStyleSheet(f"color:{col};font-size:12px;background:transparent;")
        except RuntimeError:
            pass

    # ---- navigation ----

    # ---- populating the trees ----

    def _size_tag(self, node):
        """The original size-based classification: core / large / medium / ''.

        Same rules and thresholds as the legacy window -- blue for Windows core
        files, red over 1 GB, orange over 100 MB -- so the colours mean exactly
        what they always did.
        """
        lpath = node.path.lower()
        name = os.path.basename(lpath)
        if (":\\windows" in lpath
                or name in ("pagefile.sys", "hiberfil.sys", "swapfile.sys")):
            return "core"
        if node.size > SS_THRESHOLD_GB * 1024 ** 3:
            return "large"
        if node.size > SS_THRESHOLD_MB * 1024 ** 2:
            return "medium"
        return ""

    def _paint_row(self, item, node, cols=(0,)):
        """Colour a row by size, and bold it, exactly like the old trees."""
        tag = self._size_tag(node)
        colour = {"core": SS_COLOR_CORE, "large": SS_COLOR_LARGE,
                  "medium": SS_COLOR_MEDIUM}.get(tag)
        if colour is None:
            return tag
        f = QFont(WM_FONT.split(",")[0])
        f.setBold(True)
        for c in cols:
            item.setForeground(c, QColor(colour))
            item.setFont(c, f)
        return tag

    def _populate_left(self, root):
        """Fill the folder tree. Children are added lazily on expand -- building
        every level up front on a real drive would be tens of thousands of rows."""
        self.tree_left.clear()
        self._items = {}
        if root is None:
            return
        top = QTreeWidgetItem([root.path, ss_format_size(root.size)])
        top.setData(0, QtC.UserRole, root)
        self._paint_row(top, root, cols=(0, 1))
        self.tree_left.addTopLevelItem(top)
        self._add_children(top, root)
        top.setExpanded(True)
        self.tree_left.setCurrentItem(top)

    def _add_children(self, item, node):
        """Add one level of folders, with a placeholder so they show an arrow."""
        item.takeChildren()
        for child in node.sorted_children():
            if not child.is_dir or child.size <= 0:
                continue
            ci = QTreeWidgetItem([child.name, ss_format_size(child.size)])
            ci.setData(0, QtC.UserRole, child)
            self._paint_row(ci, child, cols=(0, 1))
            ci.setToolTip(0, child.path)
            item.addChild(ci)
            if any(g.is_dir for g in child.children):
                ci.addChild(QTreeWidgetItem(["", ""]))  # expand arrow placeholder
        item.setData(1, QtC.UserRole, True)  # marked as populated

    def _on_expand(self, item):
        node = item.data(0, QtC.UserRole)
        if node is None or item.data(1, QtC.UserRole):
            return
        self._add_children(item, node)

    def _on_left_select(self):
        items = self.tree_left.selectedItems()
        if not items:
            return
        node = items[0].data(0, QtC.UserRole)
        if node is None:
            return
        self.view_node = node
        self.back_btn.setEnabled(node.parent is not None)
        # Clicking a folder means "show me this folder", so leave the
        # Largest-files view rather than silently ignoring the click.
        if self.right_view != "Contents":
            self._set_right_view("Contents")
        else:
            self._populate_right(node)

    def _go_up(self):
        """Back arrow / Backspace: select the parent of the current folder."""
        node = self.view_node
        if node is None or node.parent is None:
            return
        item = self._find_left_item(node.parent)
        if item is not None:
            self.tree_left.setCurrentItem(item)
            self.tree_left.scrollToItem(item)
        else:
            # parent not materialised in the tree (shouldn't happen) -- show it anyway
            self.view_node = node.parent
            self.back_btn.setEnabled(node.parent.parent is not None)
            self._populate_right(node.parent)

    def _build_tree_menu(self, tree, pos):
        """Build the right-click menu for the row under `pos`. Returns the QMenu,
        or None if there is nothing to act on. Kept separate from showing it so
        the actions can be exercised in tests without a modal exec()."""
        item = tree.itemAt(pos)
        if item is None:
            return None
        # If the clicked row is not part of the current selection, act on just
        # that row -- matching how Explorer behaves.
        if not item.isSelected():
            tree.clearSelection()
            item.setSelected(True)
        nodes = [it.data(0, QtC.UserRole) for it in tree.selectedItems()]
        nodes = [n for n in nodes if n is not None]
        if not nodes:
            node = item.data(0, QtC.UserRole)
            if node is None:
                return None
            nodes = [node]

        T = self.T
        menu = QMenu(self)
        menu.setStyleSheet(
            f"QMenu{{background:{T['card']};color:{T['text']};border:1px solid "
            f"{T['border']};border-radius:6px;padding:4px;}}"
            f"QMenu::item{{padding:6px 22px 6px 14px;border-radius:4px;}}"
            f"QMenu::item:selected{{background:{T['accent']};color:#fff;}}"
            f"QMenu::separator{{height:1px;background:{T['border']};margin:4px 6px;}}")

        one = nodes[0] if len(nodes) == 1 else None
        if one is not None:
            act_open = menu.addAction("Open" if one.is_dir else "Open containing folder")
            act_open.triggered.connect(lambda: self._open_path(one.path))
            if one.is_dir:
                act_loc = menu.addAction("Open location in Explorer")
                act_loc.triggered.connect(
                    lambda: self._open_path(os.path.dirname(one.path)))
            menu.addSeparator()

        total = sum(n.size for n in nodes)
        label = (f"Move to Recycle Bin ({ss_format_size(total)})" if len(nodes) == 1
                 else f"Move {len(nodes)} items to Recycle Bin ({ss_format_size(total)})")
        act_del = menu.addAction(label)
        act_del.triggered.connect(lambda: self._delete_nodes(nodes))
        return menu

    def _tree_menu(self, tree, pos):
        """Right-click menu on either tree: open, open location, delete."""
        menu = self._build_tree_menu(tree, pos)
        if menu is not None:
            menu.exec(tree.viewport().mapToGlobal(pos))

    def _open_path(self, path):
        try:
            os.startfile(path if os.path.isdir(path) else os.path.dirname(path))
        except Exception as e:
            QMessageBox.warning(self, "Could not open", str(e))

    def _populate_right(self, node):
        """Details of the selected folder's contents -- the original right pane."""
        self.tree_right.clear()
        self.right_title.setText(f"Contents of {node.path}")
        self.right_title.setToolTip(node.path)
        total = float(node.size) or 1.0
        for child in node.sorted_children():
            if child.size <= 0:
                continue
            pct = child.size / total * 100.0
            when = (datetime.fromtimestamp(child.mtime).strftime("%Y-%m-%d %H:%M")
                    if child.mtime else "")
            files = folders = ""
            if child.is_dir:
                meta = self.results.get(child.path, {})
                files = f"{meta.get('files', 0):,}"
                folders = f"{meta.get('folders', 0):,}"
            hint = ss_get_file_hint(child.path)
            tag = self._size_tag(child)
            if tag == "core":
                hint = f"Windows Core File - {hint}" if hint else "Windows Core File"
            # The safety reason is more useful than a generic hint when there is one.
            sev, reason = self._classify_safety(child.path, child.mtime)
            if reason and not hint:
                hint = reason
            it = QTreeWidgetItem([
                child.name, ss_format_size(child.size), files, folders,
                f"{pct:.1f}%", when, hint,
            ])
            it.setData(0, QtC.UserRole, child)
            self._paint_row(it, child, cols=(0, 1))
            it.setToolTip(0, child.path)
            if reason:
                it.setToolTip(6, reason)
            for c in (2, 3, 4):
                it.setTextAlignment(c, QtC.AlignCenter)
            self.tree_right.addTopLevelItem(it)
        self._on_right_select()

    def _set_right_view(self, name):
        self.right_view = name
        self._restyle_view_btns()
        if name == "Largest files":
            self._populate_largest()
        elif self.view_node is not None:
            self._populate_right(self.view_node)

    def _restyle_view_btns(self):
        T = self.T
        for name, b in self.view_btns.items():
            on = name == self.right_view
            b.setStyleSheet(
                f"background:{T['accent']};color:#fff;border:none;border-radius:4px;"
                f"font-size:11px;font-weight:600;" if on else
                f"QPushButton{{background:transparent;color:{T['text_3']};border:none;"
                f"border-radius:4px;font-size:11px;}}"
                f"QPushButton:hover{{color:{T['text']};}}")

    def _populate_largest(self):
        """Every file in the scan, biggest first — the old Top Space Hogs list.

        Files only: listing folders here would just repeat their parents. Nothing
        is hidden, but anything the safety engine flags says so in Hint, and
        critical paths are still refused at delete time.
        """
        self.tree_right.clear()
        if self.root_node is None:
            return
        files = []
        for path, meta in self.results.items():
            if meta.get("is_dir") or meta.get("size", 0) <= 0:
                continue
            files.append((meta["size"], path, meta))
        files.sort(reverse=True, key=lambda x: x[0])
        files = files[:400]   # beyond this the list stops being useful
        self.right_title.setText(f"Largest files on {getattr(self, 'scan_path', None) or self.drive.currentData() or ''} "
                                 f"— {len(files)} biggest")
        total = float(self.root_node.size) or 1.0
        index = {}

        def find(p):
            n = index.get(p)
            if n is not None:
                return n
            return None

        # map path -> node so selection/delete reuses the same objects as the tree
        stack = [self.root_node]
        while stack:
            n = stack.pop()
            index[n.path] = n
            stack.extend(n.children)

        for size, path, meta in files:
            node = index.get(os.path.normpath(path))
            if node is None:
                node = SSNode(path, size, False, meta.get("mtime", 0))
            hint = ss_get_file_hint(path)
            tag = self._size_tag(node)
            if tag == "core":
                hint = f"Windows Core File - {hint}" if hint else "Windows Core File"
            sev, reason = self._classify_safety(path, node.mtime)
            if reason and not hint:
                hint = reason
            when = (datetime.fromtimestamp(node.mtime).strftime("%Y-%m-%d %H:%M")
                    if node.mtime else "")
            it = QTreeWidgetItem([
                os.path.basename(path) or path, ss_format_size(size), "", "",
                f"{size / total * 100:.1f}%", when, hint,
            ])
            it.setData(0, QtC.UserRole, node)
            self._paint_row(it, node, cols=(0, 1))
            it.setToolTip(0, path)
            if reason:
                it.setToolTip(6, reason)
            it.setTextAlignment(4, QtC.AlignCenter)
            self.tree_right.addTopLevelItem(it)
        self._on_right_select()

    def _on_right_double(self, item, _col):
        """Double-click a folder to drill into it, like the old window."""
        node = item.data(0, QtC.UserRole)
        if node is None or not node.is_dir:
            return
        match = self._find_left_item(node)
        if match is not None:
            self.tree_left.setCurrentItem(match)
            match.setExpanded(True)
        else:
            self.view_node = node
            self._populate_right(node)

    def _find_left_item(self, node):
        it = QTreeWidgetItemIterator(self.tree_left)
        while it.value():
            item = it.value()
            if item.data(0, QtC.UserRole) is node:
                return item
            it += 1
        return None

    def _selected_nodes(self):
        out = []
        for item in self.tree_right.selectedItems():
            n = item.data(0, QtC.UserRole)
            if n is not None:
                out.append(n)
        return out

    def _on_right_select(self):
        nodes = self._selected_nodes()
        self.open_btn.setEnabled(len(nodes) == 1)
        self.del_btn.setEnabled(bool(nodes))
        if not nodes:
            self.sel_lbl.setText("Select a folder on the left to see what is inside it.")
            self.sel_lbl.setStyleSheet(
                f"color:{self.T['text_3']};font-size:12px;background:transparent;")
            return
        T = self.T
        if len(nodes) == 1:
            node = nodes[0]
            sev, reason = self._classify_safety(node.path, node.mtime)
            col = {'critical': T['danger'], 'user': T['warn'], 'risky': T['warn'],
                   'recent': T['accent'], 'safe': T['ok']}.get(sev, T['text_2'])
            note = reason or "Nothing flagged — likely safe to remove"
            txt = f"{node.name}  ·  {ss_format_size(node.size)}  ·  {note}"
            self.sel_lbl.setToolTip(f"{node.path}\n{ss_format_size(node.size)}\n{note}")
        else:
            total = sum(n.size for n in nodes)
            risky = [n for n in nodes
                     if self._classify_safety(n.path, n.mtime)[0] != 'safe']
            col = T['warn'] if risky else T['ok']
            txt = f"{len(nodes)} items selected  ·  {ss_format_size(total)}"
            if risky:
                txt += f"  ·  {len(risky)} flagged — check before deleting"
            self.sel_lbl.setToolTip("\n".join(n.path for n in nodes[:20]))
        fm = self.sel_lbl.fontMetrics()
        self.sel_lbl.setText(fm.elidedText(txt, QtC.ElideRight,
                                           max(120, self.sel_lbl.width() - 4)))
        self.sel_lbl.setStyleSheet(f"color:{col};font-size:12px;background:transparent;")

    def _open_selected(self):
        nodes = self._selected_nodes()
        if not nodes:
            return
        p = nodes[0].path
        try:
            os.startfile(p if os.path.isdir(p) else os.path.dirname(p))
        except Exception as e:
            QMessageBox.warning(self, "Could not open", str(e))

    def _delete_selected(self):
        """Move the checked items to the Recycle Bin, refusing critical paths."""
        self._delete_nodes(self._selected_nodes())

    def _delete_nodes(self, nodes):
        """Shared delete path used by the button, the right-click menu and the
        Delete key. Refuses critical system paths, confirms once, recycles the
        rest, then refreshes whichever panes are affected."""
        if not nodes:
            return

        blocked = [(n, self._classify_safety(n.path, n.mtime)[1])
                   for n in nodes if self._classify_safety(n.path, n.mtime)[0] == 'critical']
        nodes = [n for n in nodes
                 if self._classify_safety(n.path, n.mtime)[0] != 'critical']
        if blocked:
            names = "\n".join(f"  •  {n.name} — {why}" for n, why in blocked[:8])
            QMessageBox.critical(
                self, "Protected",
                f"{len(blocked)} item(s) are critical system paths and will not be "
                f"deleted:\n\n{names}\n\nRemoving these can stop Windows booting.")
        if not nodes:
            return

        flagged = [(n, self._classify_safety(n.path, n.mtime)[1])
                   for n in nodes if self._classify_safety(n.path, n.mtime)[0] != 'safe']
        total = sum(n.size for n in nodes)
        detail = "\n".join(f"  •  {n.name}  ({ss_format_size(n.size)})" for n in nodes[:10])
        if len(nodes) > 10:
            detail += f"\n  …and {len(nodes) - 10} more"
        warn = ""
        if flagged:
            warn = "\n\nFlagged:\n" + "\n".join(
                f"  •  {n.name} — {why}" for n, why in flagged[:6])
        if QMessageBox.question(
                self, "Move to Recycle Bin",
                f"Move {len(nodes)} item(s) — {ss_format_size(total)} — to the "
                f"Recycle Bin?\n\n{detail}{warn}\n\n"
                f"They go to the Recycle Bin, so you can restore them.",
                QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return

        done = failed = 0
        freed = 0
        touched_dir = False
        for n in nodes:
            if ss_send_to_recycle_bin(n.path):
                done += 1
                freed += n.size
                touched_dir = touched_dir or n.is_dir
                if n.parent is not None and n in n.parent.children:
                    n.parent.children.remove(n)
                self.results.pop(n.path, None)
            else:
                failed += 1
        if done:
            self.win._log(f"Storage: moved {done} item(s) to the Recycle Bin — "
                          f"{ss_format_size(freed)} freed", self.T['ok'])
        if failed:
            QMessageBox.warning(
                self, "Some items could not be deleted",
                f"{failed} of {len(nodes)} could not be moved. They may be in use "
                f"or protected by Windows.")
        # Deleting a folder changes the left tree too; rebuild it so the removed
        # node disappears there as well, then restore the current view.
        if touched_dir and self.root_node is not None:
            keep = self.view_node
            self._populate_left(self.root_node)
            if keep is not None and keep.parent is not None or keep is self.root_node:
                item = self._find_left_item(keep)
                if item is not None:
                    self.tree_left.setCurrentItem(item)
        if self.right_view == "Largest files":
            self._populate_largest()
        elif self.view_node is not None:
            self._populate_right(self.view_node)
        self.status.setText(f"Moved {done} item(s) to the Recycle Bin · "
                            f"{ss_format_size(freed)} freed")

    # ---- duplicates ----

    def _find_dupes(self):
        if self.dupe_thread is not None:
            return
        files = [(p, m) for p, m in self.results.items()
                 if not m.get("is_dir") and m.get("size", 0) > 1024 * 1024]
        if not files:
            QMessageBox.information(self, "Duplicates", "Scan a drive first.")
            return
        self.dupe_btn.setEnabled(False)
        self.bar.setVisible(True)
        self.status.setText(f"Looking for duplicates among {len(files):,} files…")

        def work():
            try:
                groups = wm_find_duplicates(files, lambda s: self.win.host.root.after(
                    0, lambda: self.status.setText(s)))
            except Exception as exc:
                groups = []
                # Bind the text now: Python deletes the `except` variable when the
                # block ends, and this lambda runs later on the UI thread.
                msg = f"Duplicate scan failed: {exc}"
                self.win.host.root.after(0, lambda: self.status.setText(msg))
            self.win.host.root.after(0, lambda: self._show_dupes(groups))

        self.dupe_thread = threading.Thread(target=work, daemon=True)
        self.dupe_thread.start()

    def _show_dupes(self, groups):
        self.dupe_thread = None
        self.dupe_btn.setEnabled(True)
        self.bar.setVisible(False)
        if not groups:
            self.status.setText("No duplicate files found.")
            QMessageBox.information(self, "Duplicates",
                                    "No duplicates found in the scanned results.")
            return
        wasted = sum(g[0] * (len(g[1]) - 1) for g in groups)
        self.status.setText(f"{len(groups):,} sets of duplicates · "
                            f"{ss_format_size(wasted)} recoverable")
        lines = []
        for size, paths in groups[:14]:
            lines.append(f"{ss_format_size(size)} × {len(paths)} copies")
            for p in paths[:3]:
                lines.append(f"      {p}")
            if len(paths) > 3:
                lines.append(f"      …and {len(paths) - 3} more")
        more = f"\n\n…and {len(groups) - 14} more sets." if len(groups) > 14 else ""
        QMessageBox.information(
            self, "Duplicate files",
            f"Found {len(groups):,} sets of identical files.\n"
            f"Deleting all but one copy of each would free "
            f"{ss_format_size(wasted)}.\n\n" + "\n".join(lines) + more +
            "\n\nWinMend lists duplicates but will not auto-delete them — "
            "pick the copy you want to keep and remove the others yourself.")
        self.win._log(f"Storage: {len(groups)} duplicate sets, "
                      f"{ss_format_size(wasted)} recoverable", self.T['ok'])
