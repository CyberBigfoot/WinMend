"""WinMend ui: window navigation."""

from __future__ import annotations

from PySide6.QtCore import QTimer, Qt as QtC
from PySide6.QtGui import QColor, QPalette, QTextCursor
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QStackedWidget,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItemIterator,
    QVBoxLayout,
    QWidget,
)
from winmend.core.search import wm_normalize_query
from winmend.data.task_catalog import WM_CATEGORIES, WM_TASKS
from winmend.ui.pages.apps import WMAppInstallerPage
from winmend.ui.pages.guided_fix import WMGuidedFixPage
from winmend.ui.pages.journal import WMSafetyJournalPage
from winmend.ui.pages.speedtest import WMSpeedTestPage
from winmend.ui.pages.startup import WMStartupPage
from winmend.ui.pages.storage import WMStoragePage
from winmend.ui.pages.tweaks import WMTweaksPage
from winmend.ui.theme import (
    WM_DARK,
    WM_FONT,
    WM_FONT_MONO,
    WM_GLYPH,
    WM_ICON_FONT,
    WM_LIGHT,
    wm_windows_name,
)
from winmend.ui.widgets.controls import (
    WMCheckBox,
    WMTaskCard,
    WMThemeCurtain,
    WMThemeSwitch,
    wm_hline,
)
from winmend.ui.widgets.winget import WMWingetPanel
import platform
import re
import threading
import time


class WindowNavigationMixin:
    """WMMainWindow methods grouped by responsibility."""

    # ---- chrome ----

    def _apply_window_style(self):
        T = self.T
        palette = self.palette()
        for group in (QPalette.Active, QPalette.Inactive, QPalette.Disabled):
            for role, key in ((QPalette.Window, 'bg'), (QPalette.WindowText, 'text'),
                              (QPalette.Base, 'card'), (QPalette.AlternateBase, 'card_hi'),
                              (QPalette.Text, 'text_2'), (QPalette.Button, 'card_hi'),
                              (QPalette.ButtonText, 'text_2'), (QPalette.Highlight, 'accent'),
                              (QPalette.Link, 'accent_hi'), (QPalette.ToolTipBase, 'card'),
                              (QPalette.ToolTipText, 'text')):
                palette.setColor(group, role, QColor(T[key]))
            palette.setColor(group, QPalette.HighlightedText, QColor('#ffffff'))
        palette.setColor(QPalette.Disabled, QPalette.Text, QColor(T['text_3']))
        palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(T['text_3']))
        self.setPalette(palette)
        self.setStyleSheet(
            f"QMainWindow{{background:{T['bg']};}}"
            f"QWidget{{font-family:{WM_FONT};color:{T['text']};}}"
            f"QToolTip{{background:{T['card']};color:{T['text']};"
            f"border:1px solid {T['border']};padding:5px;}}"
            # Message boxes need their SURFACE painted here too, not just their
            # text. The QWidget rule above sets colour and nothing else, so the
            # box kept whatever background Windows painted it -- and the moment
            # the app's tokens and the OS colour scheme disagree (light tokens,
            # dark Windows, e.g. after a theme switch while WinMend is open) the
            # result was #1A1A1A text on a near-black surface: a dialog that
            # reads as completely black. Both halves now come from the tokens,
            # so the box always matches the window it opened from.
            f"QMessageBox{{background:{T['bg']};}}"
            f"QMessageBox QLabel{{background:transparent;color:{T['text']};font-size:13px;}}"
            f"QMessageBox QPushButton{{background:transparent;color:{T['text_2']};"
            f"border:1px solid {T['border_hi']};border-radius:6px;font-size:12px;"
            f"min-width:86px;min-height:28px;padding:0 13px;}}"
            f"QMessageBox QPushButton:hover{{background:{T['card_hi']};color:{T['text']};}}"
            f"QMessageBox QPushButton:default{{background:{T['accent']};color:#fff;"
            f"border:1px solid {T['accent']};}}"
            f"QMessageBox QPushButton:default:hover{{background:{T['accent_hi']};"
            f"border:1px solid {T['accent_hi']};}}"
            # thin, unobtrusive scrollbars — the OS default looks alien in a dark shell
            f"QScrollBar:vertical{{background:transparent;width:10px;margin:0;}}"
            f"QScrollBar::handle:vertical{{background:{T['border_hi']};border-radius:5px;"
            f"min-height:28px;}}"
            f"QScrollBar::handle:vertical:hover{{background:{T['text_3']};}}"
            f"QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{{height:0;}}"
            f"QScrollBar::add-page:vertical,QScrollBar::sub-page:vertical{{background:none;}}"
            f"QScrollBar:horizontal{{height:0;}}")

    def _build_sidebar(self):
        T = self.T
        s = QWidget()
        s.setStyleSheet(f"background:{T['sidebar']};")
        v = QVBoxLayout(s)
        v.setContentsMargins(13, 17, 13, 13)
        v.setSpacing(0)

        brand = QLabel("WinMend")
        brand.setStyleSheet(f"color:{T['text']};font-size:19px;font-weight:700;"
                            f"padding-left:8px;background:transparent;")
        v.addWidget(brand)
        sub = QLabel("Windows maintenance")
        sub.setStyleSheet(f"color:{T['text_3']};font-size:11px;padding-left:8px;background:transparent;")
        v.addWidget(sub)
        v.addSpacing(16)

        seg = QFrame()
        seg.setStyleSheet(f"background:{T['bg']};border:1px solid {T['border']};border-radius:7px;")
        sl = QHBoxLayout(seg)
        sl.setContentsMargins(3, 3, 3, 3)
        sl.setSpacing(3)
        self.mode_btns = {}
        for name in ("Simple", "Advanced"):
            b = QPushButton(name)
            b.setCursor(QtC.PointingHandCursor)
            b.setFixedHeight(26)
            b.clicked.connect(lambda _=False, n=name: self._set_mode(n == "Simple"))
            self.mode_btns[name] = b
            sl.addWidget(b)
        v.addWidget(seg)
        v.addSpacing(15)

        self.nav_items = {}
        for key, label, _desc in WM_CATEGORIES:
            item = QFrame()
            item.setObjectName("nav")  # scope the style; unscoped rules cascade
            item.setCursor(QtC.PointingHandCursor)      # to children and give every
            item.setFixedHeight(37)                     # child label a left border
            il = QHBoxLayout(item)
            il.setContentsMargins(11, 0, 8, 0)
            il.setSpacing(11)
            g = QLabel(WM_GLYPH.get(key, ""))
            g.setFixedWidth(17)
            t = QLabel(label)
            n = QLabel("")
            n.setStyleSheet(f"color:{T['text_3']};font-size:10px;background:transparent;")
            il.addWidget(g)
            il.addWidget(t)
            il.addStretch()
            il.addWidget(n)
            item.mousePressEvent = (lambda _e, k=key: self._show_category(k))
            self.nav_items[key] = (item, g, t, n)
            v.addWidget(item)
            v.addSpacing(1)

        v.addStretch()
        v.addWidget(wm_hline(T))
        v.addSpacing(9)
        theme_row = QHBoxLayout()
        theme_label = QLabel("Dark mode")
        theme_label.setStyleSheet(f"color:{T['text_2']};font-size:12px;background:transparent;")
        theme_row.addWidget(theme_label)
        theme_row.addStretch()
        self.theme_switch = WMThemeSwitch(T)
        self.theme_switch.setChecked(T['name'] == 'dark')
        self.theme_switch.toggled.connect(self._set_theme)
        theme_row.addWidget(self.theme_switch)
        v.addLayout(theme_row)
        theme_hint = QLabel("Startup follows Windows theme")
        theme_hint.setStyleSheet(f"color:{T['text_3']};font-size:10px;background:transparent;")
        v.addWidget(theme_hint)
        v.addSpacing(10)
        adm = QHBoxLayout()
        is_admin = self.host.admin_status
        dot = QLabel("●")
        dot.setStyleSheet(f"color:{T['ok'] if is_admin else T['warn']};"
                          f"font-size:11px;background:transparent;")
        adm.addWidget(dot)
        al = QLabel("Administrator" if is_admin else "Not elevated")
        al.setStyleSheet(f"color:{T['text_2']};font-size:12px;background:transparent;")
        adm.addWidget(al)
        adm.addStretch()
        v.addLayout(adm)
        v.addSpacing(7)

        self._restyle_nav()
        self._restyle_mode()

        # Wrap the sidebar in a scroll area so its ~14 fixed-height nav rows can
        # never force the whole window taller than the screen. Previously that
        # tall minimum height, on laptop-height displays, pushed the center
        # column's action bar (Run selected) off the bottom of the screen; the
        # button only appeared when the window was maximised. When the window is
        # tall enough the stretch keeps the footer pinned to the bottom exactly
        # as before; when it's short, the sidebar scrolls instead of overflowing.
        rail = QScrollArea()
        rail.setObjectName("rail")  # scoped: unscoped border-right would draw a
        rail.setFixedWidth(228)     # line down the left of every child label
        rail.setWidgetResizable(True)
        rail.setFrameShape(QFrame.NoFrame)
        rail.setStyleSheet(f"#rail{{background:{T['sidebar']};"
                           f"border-right:1px solid {T['border']};}}")
        rail.setWidget(s)
        return rail

    def _set_theme(self, dark):
        """Change appearance in place, preserving task and cached page state."""
        tokens = WM_DARK if dark else WM_LIGHT
        if self.T['name'] == tokens['name']:
            return
        if self._theme_curtain is not None:
            self._theme_curtain.finish()
        surface = self.centralWidget()
        # Capture the window backdrop too: the central widget is transparent.
        snapshot = self.grab(surface.geometry()) if self.isVisible() else None
        old = dict(self.T)
        self.T.update(tokens)
        self._recolour_widgets(old)
        self._apply_window_style()
        self._restyle_nav()
        self._restyle_mode()
        blocked = self.theme_switch.blockSignals(True)
        self.theme_switch.setChecked(dark)
        self.theme_switch.blockSignals(blocked)
        if snapshot is not None:
            curtain = WMThemeCurtain(surface, snapshot)
            self._theme_curtain = curtain
            curtain.finished.connect(lambda: self._clear_theme_curtain(curtain))
        self.update()

    def _clear_theme_curtain(self, curtain):
        if self._theme_curtain is curtain:
            self._theme_curtain = None

    def _recolour_widgets(self, old):
        # Replace each old token in one pass; sequential replacement would
        # confuse light card white with dark text white on the return trip.
        colours = {value: self.T[key] for key, value in old.items() if key != 'name'}
        css_colour = re.compile(r'#[0-9a-fA-F]{6}\b|rgba\([^)]*\)')
        brush_colours = {QColor(value).rgba(): QColor(self.T[key])
                         for key, value in old.items() if value.startswith('#')}

        def replace(text):
            return css_colour.sub(lambda match: colours.get(match[0], match[0]), text)

        widgets = [self, *self.findChildren(QWidget)]
        # Navigation detaches cached pages; recolour them before the next visit.
        for name in ('storage_page', 'guided_page', 'journal_page', 'startup_page',
                     'speedtest_page', 'apps_page', 'tweaks_page', 'winget_panel'):
            page = getattr(self, name, None)
            if page is not None:
                widgets.extend([page, *page.findChildren(QWidget)])
        seen = set()
        for widget in widgets:
            if widget in seen:
                continue
            seen.add(widget)
            stylesheet = widget.styleSheet()
            updated = replace(stylesheet)
            if updated != stylesheet:
                widget.setStyleSheet(updated)
            if isinstance(widget, WMCheckBox) and widget._colour in colours:
                widget._colour = colours[widget._colour]
            if isinstance(widget, QLabel) and '<' in widget.text():
                widget.setText(replace(widget.text()))
            if widget is not self and widget.testAttribute(QtC.WA_SetPalette):
                palette = widget.palette()
                for group in (QPalette.Active, QPalette.Inactive, QPalette.Disabled):
                    colour = brush_colours.get(palette.color(group, QPalette.Link).rgba())
                    if colour is not None:
                        palette.setColor(group, QPalette.Link, colour)
                widget.setPalette(palette)
            if isinstance(widget, QTreeWidget):
                iterator = QTreeWidgetItemIterator(widget)
                while iterator.value() is not None:
                    item = iterator.value()
                    for column in range(widget.columnCount()):
                        for get_brush, set_brush in ((item.foreground, item.setForeground),
                                                     (item.background, item.setBackground)):
                            brush = get_brush(column)
                            colour = brush_colours.get(brush.color().rgba())
                            if brush.style() != QtC.NoBrush and colour is not None:
                                brush.setColor(colour)
                                set_brush(column, brush)
                    iterator += 1
            if isinstance(widget, QTextBrowser):
                # Edit formatting only, keeping log text, selection and scroll.
                document = widget.document()
                block = document.begin()
                while block.isValid():
                    fragments = block.begin()
                    while not fragments.atEnd():
                        fragment = fragments.fragment()
                        if fragment.isValid():
                            fmt = fragment.charFormat()
                            changed = False
                            for get_brush, set_brush in ((fmt.foreground, fmt.setForeground),
                                                         (fmt.background, fmt.setBackground)):
                                brush = get_brush()
                                colour = brush_colours.get(brush.color().rgba())
                                if brush.style() != QtC.NoBrush and colour is not None:
                                    brush.setColor(colour)
                                    set_brush(brush)
                                    changed = True
                            if changed:
                                cursor = QTextCursor(document)
                                cursor.setPosition(fragment.position())
                                cursor.setPosition(fragment.position() + fragment.length(),
                                                   QTextCursor.KeepAnchor)
                                cursor.setCharFormat(fmt)
                        fragments += 1
                    block = block.next()
            if isinstance(widget, WMAppInstallerPage):
                widget._notes = {index: (text, colours.get(colour, colour))
                                 for index, (text, colour) in widget._notes.items()}
            widget.update()

    def _build_center(self):
        T = self.T
        c = QWidget()
        c.setStyleSheet("background:transparent;")
        v = QVBoxLayout(c)
        v.setContentsMargins(28, 22, 28, 20)
        v.setSpacing(0)

        self.search = QLineEdit()
        self.search.setPlaceholderText(
            "Search tasks — or describe a problem: “PC is slow”, “no internet”, “blue screen”…")
        self.search.setFixedHeight(38)
        self.search.setStyleSheet(f"""
            QLineEdit {{ background:{T['card']};border:1px solid {T['border']};
                border-radius:8px;padding-left:12px;color:{T['text']};font-size:13px; }}
            QLineEdit:focus {{ border:1px solid {T['accent']}; }}
        """)
        self.search.textChanged.connect(self._filter)
        v.addWidget(self.search)
        v.addSpacing(20)

        self.page_title = QLabel("")
        self.page_title.setStyleSheet(f"color:{T['text']};font-size:25px;font-weight:700;background:transparent;")
        v.addWidget(self.page_title)
        self.page_sub = QLabel("")
        self.page_sub.setWordWrap(True)
        self.page_sub.setStyleSheet(f"color:{T['text_3']};font-size:13px;background:transparent;")
        v.addWidget(self.page_sub)
        v.addSpacing(15)

        self.stack = QStackedWidget()
        self.stack.setStyleSheet("background:transparent;")
        v.addWidget(self.stack, 1)

        v.addSpacing(13)
        self.selection_bar = QWidget()
        self.selection_bar.setStyleSheet("background:transparent;")
        bar = QHBoxLayout(self.selection_bar)
        bar.setContentsMargins(0, 0, 0, 0)
        self.sel_label = QLabel("Nothing selected")
        self.sel_label.setStyleSheet(f"color:{T['text_3']};font-size:12px;background:transparent;")
        bar.addWidget(self.sel_label)
        bar.addStretch()
        self.rp_label = QLabel("")
        self.rp_label.setStyleSheet(f"color:{T['ok']};font-size:12px;background:transparent;")
        bar.addWidget(self.rp_label)
        bar.addSpacing(13)
        self.run_btn = QPushButton("Run selected")
        self.run_btn.setFixedSize(132, 37)
        self.run_btn.setCursor(QtC.PointingHandCursor)
        self.run_btn.setEnabled(False)
        self.run_btn.setStyleSheet(f"""
            QPushButton {{ background:{T['accent']};color:#fff;border:none;
                border-radius:7px;font-size:13px;font-weight:600; }}
            QPushButton:hover {{ background:{T['accent_hi']}; }}
            QPushButton:disabled {{ background:{T['card_hi']};color:{T['text_3']}; }}
        """)
        self.run_btn.clicked.connect(self._run_selected)
        bar.addWidget(self.run_btn)
        v.addWidget(self.selection_bar)
        return c

    def _build_right(self):
        T = self.T
        self.right = QWidget()
        self.right.setObjectName("rail")
        self.right.setFixedWidth(340)
        self.right.setStyleSheet(f"#rail{{background:{T['sidebar']};"
                                 f"border-left:1px solid {T['border']};}}")
        v = QVBoxLayout(self.right)
        v.setContentsMargins(17, 18, 17, 15)
        v.setSpacing(0)

        # Checklist above, log below, both scrolling and both splittable. The
        # checklist used to be a plain stack of rows with nowhere to go: select
        # a dozen tasks and the ones past the fold simply were not drawn, so
        # the panel that is supposed to say what is about to run could not.
        split = QSplitter(QtC.Vertical)
        split.setChildrenCollapsible(False)
        split.setHandleWidth(9)
        split.setStyleSheet(
            f"QSplitter::handle{{background:transparent;}}"
            f"QSplitter::handle:hover{{background:{T['border']};}}")

        queue_pane = QWidget()
        queue_pane.setStyleSheet("background:transparent;")
        qv = QVBoxLayout(queue_pane)
        qv.setContentsMargins(0, 0, 0, 0)
        qv.setSpacing(0)
        hd = QHBoxLayout()
        q = QLabel("Checklist")
        q.setStyleSheet(f"color:{T['text']};font-size:14px;font-weight:700;background:transparent;")
        q.setToolTip("Everything this run will do, in order: what is running now, "
                     "what is still queued, and what has already finished.")
        hd.addWidget(q)
        hd.addStretch()
        self.q_count = QLabel("idle")
        self.q_count.setStyleSheet(f"color:{T['text_3']};font-size:11px;background:transparent;")
        hd.addWidget(self.q_count)
        qv.addLayout(hd)
        qv.addSpacing(8)

        self.q_scroll = QScrollArea()
        self.q_scroll.setWidgetResizable(True)
        self.q_scroll.setFrameShape(QFrame.NoFrame)
        self.q_scroll.setHorizontalScrollBarPolicy(QtC.ScrollBarAlwaysOff)
        self.q_scroll.setStyleSheet(
            "QScrollArea{background:transparent;border:none;}"
            f"QScrollBar:vertical{{background:transparent;width:9px;margin:0;}}"
            f"QScrollBar::handle:vertical{{background:{T['border_hi']};min-height:24px;"
            "border-radius:4px;}"
            "QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0;}"
            "QScrollBar::add-page:vertical,QScrollBar::sub-page:vertical{background:transparent;}")
        q_inner = QWidget()
        q_inner.setStyleSheet("background:transparent;")
        self.q_box = QVBoxLayout(q_inner)
        self.q_box.setContentsMargins(0, 0, 6, 0)
        self.q_box.setSpacing(0)
        self.q_empty = QLabel("No tasks running.")
        self.q_empty.setStyleSheet(f"color:{T['text_3']};font-size:11px;background:transparent;")
        self.q_box.addWidget(self.q_empty)
        self.q_box.addStretch()
        self.q_scroll.setWidget(q_inner)
        qv.addWidget(self.q_scroll, 1)
        split.addWidget(queue_pane)

        log_pane = QWidget()
        log_pane.setStyleSheet("background:transparent;")
        lv = QVBoxLayout(log_pane)
        lv.setContentsMargins(0, 0, 0, 0)
        lv.setSpacing(0)
        lt = QLabel("Activity log")
        lt.setStyleSheet(f"color:{T['text']};font-size:14px;font-weight:700;background:transparent;")
        lt.setToolTip("Every line this session has produced, oldest first. "
                      "Select text to copy it.")
        lv.addWidget(lt)
        lv.addSpacing(7)

        # A document rather than a stack of labels. The old panel built one
        # QLabel per line and threw away everything past 400 of them, which is
        # a few minutes of a chatty repair -- so the history the user wanted to
        # scroll back through was the part that had already been deleted.
        # This keeps the whole session, and the text can be selected and copied.
        self.log_view = QTextBrowser()
        self.log_view.setFrameShape(QFrame.NoFrame)
        self.log_view.setOpenExternalLinks(False)
        self.log_view.setLineWrapMode(QTextBrowser.WidgetWidth)
        self.log_view.document().setMaximumBlockCount(0)
        self.log_view.setStyleSheet(
            f"QTextBrowser{{background:{T['bg']};color:{T['text_2']};"
            f"border:1px solid {T['border']};border-radius:7px;padding:8px;"
            f"font-family:{WM_FONT_MONO};font-size:10.5px;}}"
            f"QScrollBar:vertical{{background:{T['bg']};width:9px;margin:0;}}"
            f"QScrollBar::handle:vertical{{background:{T['border_hi']};min-height:24px;"
            "border-radius:4px;}"
            "QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0;}")
        lv.addWidget(self.log_view, 1)
        split.addWidget(log_pane)

        split.setSizes([300, 380])
        split.setStretchFactor(0, 0)
        split.setStretchFactor(1, 1)
        v.addWidget(split, 1)
        self._log("Ready. Nothing has been changed.", T['text_3'])
        return self.right

    # ---- pages ----

    def _page_for(self, key):
        T = self.T
        if key == "guide":
            if self.guided_page is None:
                self.guided_page = WMGuidedFixPage(self)
            return self.guided_page
        if key == "journal":
            if self.journal_page is None:
                self.journal_page = WMSafetyJournalPage(self)
            else:
                self.journal_page.refresh()
            return self.journal_page
        if key == "storage":
            # Built once and cached: a scan takes minutes, and it must survive
            # navigating away and back. Also returned bare rather than wrapped in
            # a QScrollArea -- the treemap fills the available space instead of
            # scrolling.
            if getattr(self, "storage_page", None) is None:
                self.storage_page = WMStoragePage(self)
            return self.storage_page
        if key == "startup":
            # Cached like the storage page: enumeration is cheap but the boot
            # history probe is not, and toggles-in-progress must survive
            # navigation.
            if getattr(self, "startup_page", None) is None:
                self.startup_page = WMStartupPage(self)
            else:
                self.startup_page.on_revisit()
            return self.startup_page
        if key == "speedtest":
            # Cached so a test in progress survives navigating away and back.
            if getattr(self, "speedtest_page", None) is None:
                self.speedtest_page = WMSpeedTestPage(self)
            return self.speedtest_page
        if key == "apps":
            # Cached: hundreds of rows, a winget listing behind them, and a
            # running batch install that must survive navigating away and back.
            if getattr(self, "apps_page", None) is None:
                self.apps_page = WMAppInstallerPage(self)
            else:
                self.apps_page.on_revisit()
            return self.apps_page
        if key == "tweaks":
            # Cached, and re-read on every visit: another tool (or Settings)
            # may have changed something since we last looked.
            if getattr(self, "tweaks_page", None) is None:
                self.tweaks_page = WMTweaksPage(self)
            else:
                self.tweaks_page.on_revisit()
            return self.tweaks_page
        sa = QScrollArea()
        sa.setWidgetResizable(True)
        sa.setFrameShape(QFrame.NoFrame)
        sa.setStyleSheet("background:transparent;")
        inner = QWidget()
        inner.setStyleSheet("background:transparent;")
        iv = QVBoxLayout(inner)
        iv.setContentsMargins(0, 0, 6, 0)
        iv.setSpacing(8)

        if key == "dashboard":
            iv.addWidget(self._dashboard())
        else:
            if key == "updates":
                # Cached across rebuilds: a winget listing takes many seconds
                # and a running update must survive navigating away.
                if getattr(self, "winget_panel", None) is None:
                    self.winget_panel = WMWingetPanel(self)
                iv.addWidget(self.winget_panel)
            for t in [x for x in WM_TASKS if x.category == key]:
                card = WMTaskCard(t, T, self.simple, self._run_one, self._on_toggle,
                                  self.host.vars[t.id].get())
                self.cards.append(card)
                iv.addWidget(card)
            self.empty_note = QLabel("Nothing here in Simple mode — switch to Advanced to see every task.")
            self.empty_note.setStyleSheet(f"color:{T['text_3']};font-size:12px;background:transparent;")
            self.empty_note.setVisible(False)
            iv.addWidget(self.empty_note)
        iv.addStretch()
        sa.setWidget(inner)
        return sa

    def _dashboard(self):
        """System info at a glance — read live, changes nothing."""
        T = self.T
        w = QWidget()
        w.setStyleSheet("background:transparent;")
        v = QVBoxLayout(w)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(8)
        # Bumped every time the page is rebuilt. The background probe below
        # captures the value and drops its result if the page has since been
        # torn down -- otherwise it writes to deleted QLabels and Qt aborts with
        # "Internal C++ object already deleted".
        self._dash_gen = getattr(self, "_dash_gen", 0) + 1
        self.dash_rows = {}
        for label in ("Windows", "Device", "CPU", "Memory", "Storage", "Uptime", "Elevation"):
            card = QFrame()
            card.setObjectName("dcard")  # scoped: an unscoped rule would draw a
            card.setStyleSheet(         # border around every child label too
                f"#dcard{{background:{T['card']};border:1px solid {T['border']};"
                f"border-radius:8px;}}")
            h = QHBoxLayout(card)
            h.setContentsMargins(15, 12, 15, 12)
            k = QLabel(label)
            k.setStyleSheet(f"color:{T['text_3']};font-size:12px;background:transparent;")
            k.setFixedWidth(96)
            val = QLabel("reading…")
            val.setWordWrap(True)
            val.setStyleSheet(f"color:{T['text']};font-size:13px;font-weight:600;background:transparent;")
            h.addWidget(k)
            h.addWidget(val, 1)
            self.dash_rows[label] = val
            v.addWidget(card)
        QTimer.singleShot(60, self._load_dashboard)
        return w

    def _load_dashboard(self):
        """Populate the dashboard off-thread; WMI/psutil calls can be slow."""
        gen = self._dash_gen

        def work():
            out = {}
            try:
                import psutil
                out["CPU"] = f"{platform.processor() or 'Unknown'}  ·  {psutil.cpu_count(logical=True)} threads"
                m = psutil.virtual_memory()
                out["Memory"] = (f"{m.total / 1024**3:.1f} GB total  ·  "
                                 f"{m.percent:.0f}% in use")
                d = psutil.disk_usage("C:\\")
                out["Storage"] = (f"C:  {d.free / 1024**3:.0f} GB free of "
                                  f"{d.total / 1024**3:.0f} GB  ·  {d.percent:.0f}% used")
                up = time.time() - psutil.boot_time()
                out["Uptime"] = f"{int(up // 86400)}d {int(up % 86400 // 3600)}h {int(up % 3600 // 60)}m"
            except Exception as e:
                out.setdefault("CPU", f"unavailable ({e})")
            try:
                out["Windows"] = wm_windows_name()
                out["Device"] = platform.node()
            except Exception:
                pass
            out["Elevation"] = ("Administrator — everything available"
                                if self.host.admin_status else
                                "Standard user — some tasks need elevation")
            self.host.root.after(0, lambda: self._fill_dashboard(out, gen))
        threading.Thread(target=work, daemon=True).start()

    def _fill_dashboard(self, out, gen):
        # The page was rebuilt (or navigated away from) while we were probing:
        # the labels this result belongs to no longer exist. Drop it.
        if gen != self._dash_gen:
            return
        try:
            for k, val in out.items():
                if k in self.dash_rows:
                    self.dash_rows[k].setText(str(val))
            for k, lbl in self.dash_rows.items():
                if lbl.text() == "reading…":
                    lbl.setText("unavailable")
        except RuntimeError:
            pass  # widgets torn down between the check and the write

    # Pages that are not task lists, and those among them with their own search
    # (or no need of one) -- the task search box is hidden on the latter.
    _NON_TASK_PAGES = ("dashboard", "guide", "journal", "storage", "startup",
                       "speedtest", "apps", "tweaks")

    _SEARCHLESS_PAGES = ("guide", "journal", "storage", "startup", "speedtest",
                         "apps", "tweaks")

    def _show_category(self, key):
        self.current_cat = key
        # Choosing a page ends a search: its results span every page, so they
        # cannot stay on screen once one page has been picked.
        self._showing_results = False
        if self.search.text():
            self.search.blockSignals(True)
            self.search.clear()
            self.search.blockSignals(False)
        title = next((c for c in WM_CATEGORIES if c[0] == key), None)
        if title:
            self.page_title.setText(title[1])
            self.page_sub.setText(title[2])
        self._clear_stack()
        self.stack.addWidget(self._page_for(key))
        is_task_page = key not in self._NON_TASK_PAGES
        self.search.setVisible(key not in self._SEARCHLESS_PAGES)
        self.selection_bar.setVisible(is_task_page)
        self._restyle_nav()
        self._filter()
        self._update_selection()

    def _clear_stack(self):
        """Empty the page stack, keeping the cached pages alive."""
        # Rebuild the page so Simple/Advanced changes take effect. The storage
        # page is cached and must survive this -- detach it first, or
        # deleteLater() destroys it along with an in-progress scan.
        preserved = tuple(
            page for page in (
                getattr(self, "storage_page", None),
                getattr(self, "guided_page", None),
                getattr(self, "journal_page", None),
                getattr(self, "startup_page", None),
                getattr(self, "speedtest_page", None),
                getattr(self, "apps_page", None),
                getattr(self, "tweaks_page", None),
            ) if page is not None
        )
        # The winget panel is nested inside the Updates page, so it would be
        # destroyed with it -- detach it first, like the cached pages.
        if getattr(self, "winget_panel", None) is not None:
            self.winget_panel.setParent(None)
        while self.stack.count():
            w = self.stack.widget(0)
            self.stack.removeWidget(w)
            if w in preserved:
                w.setParent(None)
            else:
                w.deleteLater()
        self.cards = []
        self.empty_note = None

    def _search_task_ids(self, text):
        """(task ids, one-line explanation) for what was typed in the search box.

        Names first -- someone typing "cpu stress" wants that task -- then the
        tasks the symptom matcher suggests for a described problem."""
        q = wm_normalize_query(text)
        in_title = [t.id for t in WM_TASKS
                    if q and q in wm_normalize_query(f"{t.title} {t.plain or ''}")]
        # A description only mentioning the words ranks below the suggestions:
        # "restore point" should not put Debloat second because its text
        # explains that a restore point cannot bring apps back.
        in_desc = [t.id for t in WM_TASKS
                   if q and t.id not in in_title
                   and q in wm_normalize_query(f"{t.desc} {t.id.replace('_', ' ')}")]
        suggested, reason = self.host._recommend_tasks_for_query(text)
        known = {t.id for t in WM_TASKS}
        suggested = [i for i in suggested if i in known and i not in in_title]
        shown = f"“{text.strip()}”"
        if reason == "General triage pack":
            # The matcher's catch-all: only worth showing when nothing else is.
            if in_title or in_desc:
                return in_title + in_desc, f"Tasks matching {shown}."
            return suggested, (f"Nothing matches {shown} directly, so these are general "
                               f"check-up tasks. Guided Fix can also ask about the problem "
                               f"step by step.")
        ids = in_title + suggested + [i for i in in_desc if i not in suggested]
        if in_title and suggested:
            related = f"the tasks suggested for it ({reason})" if reason else "related tasks"
            return ids, f"Tasks named {shown} first, then {related}."
        if suggested:
            return ids, (f"Suggested for {shown}: {reason}." if reason
                         else f"Tasks related to {shown}.")
        return ids, f"Tasks matching {shown}."

    def _show_search_results(self, text):
        """Every task the search finds, from every page.

        The box used to filter only the page on screen, by exact text, so the
        problems its own placeholder suggests ("PC is slow", "no internet")
        found nothing -- and the symptom matcher that could answer them was
        called only by a test."""
        T = self.T
        ids, explanation = self._search_task_ids(text)
        by_id = {t.id: t for t in WM_TASKS}
        tasks = [by_id[i] for i in ids if i in by_id]
        hidden = 0
        if self.simple:
            # Simple mode keeps to its own tasks -- unless none of them fit,
            # when an Advanced answer beats an empty page.
            simple = [t for t in tasks if t.simple]
            if simple:
                hidden = len(tasks) - len(simple)
                tasks = simple

        self._clear_stack()
        sa = QScrollArea()
        sa.setWidgetResizable(True)
        sa.setFrameShape(QFrame.NoFrame)
        sa.setStyleSheet("background:transparent;")
        inner = QWidget()
        inner.setStyleSheet("background:transparent;")
        iv = QVBoxLayout(inner)
        iv.setContentsMargins(0, 0, 6, 0)
        iv.setSpacing(8)
        for t in tasks:
            card = WMTaskCard(t, T, self.simple, self._run_one, self._on_toggle,
                              self.host.vars[t.id].get())
            self.cards.append(card)
            iv.addWidget(card)
        if hidden:
            more = QLabel(f"{hidden} more in Advanced mode.")
            more.setStyleSheet(f"color:{T['text_3']};font-size:12px;background:transparent;")
            iv.addWidget(more)
        iv.addStretch()
        sa.setWidget(inner)
        self.stack.addWidget(sa)

        self._showing_results = True
        self.page_title.setText("Search results")
        self.page_sub.setText(explanation)
        self.selection_bar.setVisible(True)
        self._update_selection()

    def _set_mode(self, simple):
        if simple == self.simple:
            return
        self.simple = simple
        self._restyle_mode()
        if getattr(self, "_showing_results", False) and self.search.text().strip():
            self._restyle_nav()
            self._filter()  # the same search, in the new mode
        else:
            self._show_category(self.current_cat)

    def _restyle_mode(self):
        T = self.T
        for name, b in self.mode_btns.items():
            on = (name == "Simple") == self.simple
            b.setStyleSheet(
                f"background:{T['accent']};color:#fff;border:none;border-radius:5px;"
                f"font-size:12px;font-weight:600;" if on else
                f"QPushButton{{background:transparent;color:{T['text_3']};border:none;"
                f"border-radius:5px;font-size:12px;}}"
                f"QPushButton:hover{{color:{T['text']};}}")

    def _restyle_nav(self):
        T = self.T
        for key, (item, g, t, n) in self.nav_items.items():
            on = key == self.current_cat
            item.setStyleSheet(
                (f"#nav{{background:{T['card_hi']};border:none;"
                 f"border-left:3px solid {T['accent']};border-radius:6px;}}") if on else
                (f"#nav{{background:transparent;border:none;"
                 f"border-left:3px solid transparent;border-radius:6px;}}"
                 f"#nav:hover{{background:{T['card']};}}"))
            g.setStyleSheet(f"color:{T['accent'] if on else T['text_3']};"
                            f"font-family:{WM_ICON_FONT};font-size:14px;background:transparent;")
            t.setStyleSheet(f"color:{T['text'] if on else T['text_2']};font-size:13px;"
                            f"font-weight:{600 if on else 400};background:transparent;")
            if key != "dashboard":
                total = [x for x in WM_TASKS if x.category == key]
                shown = [x for x in total if x.simple] if self.simple else total
                n.setText(str(len(shown)) if shown else "")
            n.setStyleSheet(f"color:{T['text_3']};font-size:10px;background:transparent;")

    def _filter(self):
        text = self.search.text().strip()
        if text and self.current_cat not in self._SEARCHLESS_PAGES:
            self._show_search_results(text)
            return
        if getattr(self, "_showing_results", False):
            # The search was cleared: put the page back.
            self._show_category(self.current_cat)
            return
        visible = 0
        for c in self.cards:
            ok = (not self.simple) or c.task.simple
            c.setVisible(ok)
            visible += ok
        note = getattr(self, "empty_note", None)
        if note is not None:
            try:
                note.setVisible(visible == 0 and self.current_cat != "dashboard")
            except RuntimeError:
                pass
