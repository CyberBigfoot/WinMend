"""WinMend ui: pages: guided fix."""

from __future__ import annotations

from PySide6.QtCore import Qt as QtC
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTabWidget,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)
from winmend.ui.pages.guided_results import GuidedResultsMixin
from winmend.ui.pages.guided_scan import GuidedScanMixin
from winmend.ui.widgets.controls import WMCheckBox, WMSwitchDelegate
import html as _html
import os
import subprocess


class WMGuidedFixPage(
    GuidedScanMixin,
    GuidedResultsMixin,
    QWidget,
):
    """The IT desk: triage interview, evidence, ranked causes, adaptive repair.

    The flow deliberately mirrors how a technician actually works. Questions the
    PC cannot answer are asked first, because "it started after Tuesday's
    update" decides where to look and no probe can measure it. Evidence arrives
    in two passes so the obvious problems surface in seconds. Causes are ranked
    and explained rather than listed. Repairs run one at a time and stop as soon
    as the measurement they targeted comes back clean.
    """

    def __init__(self, window):
        super().__init__()
        self.win = window
        self.T = window.T
        self.case = None
        self.questions = []
        self.answer_widgets = {}
        self._busy = False
        self._stage = "describe"
        self._last_run = None
        self._latest_verification = None
        self._sweep_cancel = False
        # Kept so the diagnostic pass can be waited on -- the offscreen test
        # drives this page for real, and a fire-and-forget thread cannot be.
        self._sweep_thread = None
        self._profile = None
        self._audit = False
        self._deep = False
        self.setObjectName("guidedFixPage")
        self.setStyleSheet(
            "#guidedFixPage{background:transparent;}"
            f"QScrollBar:vertical{{background:{self.T['bg']};width:8px;margin:0;}}"
            f"QScrollBar::handle:vertical{{background:{self.T['border_hi']};min-height:24px;border-radius:4px;}}"
            "QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0;}"
            "QScrollBar::add-page:vertical,QScrollBar::sub-page:vertical{background:transparent;}")

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(9)

        root.addWidget(self._build_prompt())

        self.status = QLabel(
            "Describe the problem in your own words. WinMend will ask a few follow-up "
            "questions, then run read-only checks that change nothing."
        )
        self.status.setWordWrap(True)
        self.status.setTextFormat(QtC.PlainText)
        self.status.setStyleSheet(f"color:{self.T['text_3']};font-size:12px;background:transparent;")
        root.addWidget(self.status)

        self.interview_card = self._build_interview()
        self.interview_card.setVisible(False)
        root.addWidget(self.interview_card)

        self.progress_row = self._build_progress()
        self.progress_row.setVisible(False)
        root.addWidget(self.progress_row)

        root.addWidget(self._build_upper(), 1)
        self.hardware_tab = self._build_hardware()
        self.tabs.addTab(self.hardware_tab, "Hardware")
        self.tabs.addTab(self._build_plan(), "Repair plan")
        root.addWidget(self.plan_actions)
        self.tabs.setTabVisible(3, False)
        self.tabs.currentChanged.connect(self._update_run_button)
        self._load_last_run()

    # ---- construction ---------------------------------------------------

    def _build_prompt(self):
        frame = QFrame()
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(0, 0, 0, 8)
        layout.setSpacing(12)
        # No title here: the window header above the page already says "Guided
        # Fix" and describes it, so a second copy was pure duplication.
        intro = QLabel("Describe a problem or choose a scan. Review the evidence before making changes.")
        intro.setWordWrap(True)
        intro.setStyleSheet(f"color:{self.T['text_2']};font-size:12px;")
        layout.addWidget(intro)
        row = QHBoxLayout()
        row.setSpacing(10)
        self.problem = QLineEdit()
        self.problem.setPlaceholderText("For example: Wi-Fi connects but websites will not load")
        self.problem.setFixedHeight(42)
        self.problem.setStyleSheet(
            f"QLineEdit{{background:{self.T['card']};color:{self.T['text']};"
            f"border:1px solid {self.T['border_hi']};border-radius:7px;padding:0 12px;font-size:13px;}}"
            f"QLineEdit:focus{{border-color:{self.T['accent']};}}")
        self.problem.returnPressed.connect(self.start_diagnosis)
        row.addWidget(self.problem, 1)
        self.diagnose_btn = QPushButton("Find a fix")
        self.diagnose_btn.setFixedSize(112, 42)
        self.diagnose_btn.setStyleSheet(self._primary_style())
        self.diagnose_btn.setCursor(QtC.PointingHandCursor)
        self.diagnose_btn.clicked.connect(self.start_diagnosis)
        row.addWidget(self.diagnose_btn)
        layout.addLayout(row)
        scans = QHBoxLayout()
        scans.setSpacing(10)
        self.full_check_btn = QPushButton("Check for issues")
        self.deep_scan_btn = QPushButton("Deep Hardware Check")
        for button, callback in ((self.full_check_btn, self.start_full_check),
                                 (self.deep_scan_btn, self.start_hardware_scan)):
            button.setMinimumHeight(36)
            button.setStyleSheet(self._ghost_style() + "QPushButton{padding:0 14px;}")
            button.setCursor(QtC.PointingHandCursor)
            button.clicked.connect(callback)
            scans.addWidget(button)
        self.full_check_btn.setToolTip("Check Windows, apps and system settings without changing them.")
        self.deep_scan_btn.setToolTip(
            "Several minutes. Checks components, device status and error logs. "
            "Tests its own allocated RAM and reads sampled drive blocks. "
            "No disk data or settings are changed. Some checks require administrator access.")
        scans.addStretch()
        self.examples = QComboBox()
        self.examples.addItem("Try an example…")
        self.examples.addItems(["My PC is slow", "Wi-Fi keeps dropping", "Windows Update is stuck",
                                "I keep getting blue screens", "I think I have a virus"])
        self.examples.setMinimumHeight(36)
        self.examples.setMaximumWidth(210)
        self.examples.setStyleSheet(
            f"QComboBox{{background:{self.T['card']};color:{self.T['text_2']};"
            f"border:1px solid {self.T['border']};border-radius:7px;padding:0 9px;}}"
            f"QComboBox QAbstractItemView{{background:{self.T['card']};color:{self.T['text']};"
            f"selection-background-color:{self.T['accent']};}}")
        self.examples.activated.connect(
            lambda index: self.problem.setText(self.examples.itemText(index)) if index else None)
        scans.addWidget(self.examples)
        layout.addLayout(scans)
        return frame

    def _build_hardware(self):
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)
        self.hardware_note = QLabel("Select a component to see evidence, coverage and next steps.")
        self.hardware_note.setWordWrap(True)
        self.hardware_note.setStyleSheet(f"color:{self.T['text_2']};font-size:12px;")
        layout.addWidget(self.hardware_note)
        split = QSplitter(QtC.Vertical)
        split.setChildrenCollapsible(False)
        self.components = QTreeWidget()
        self.components.setColumnCount(3)
        self.components.setHeaderLabels(["Component", "Status", "Scan coverage"])
        self.components.setRootIsDecorated(False)
        self.components.setStyleSheet(self._tree_style())
        self.components.setMinimumHeight(120)
        self.components.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.components.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.components.header().setSectionResizeMode(2, QHeaderView.Stretch)
        self.components.currentItemChanged.connect(self._show_component)
        split.addWidget(self.components)
        self.component_detail = QTextBrowser()
        self.component_detail.setOpenExternalLinks(False)
        self.component_detail.setMinimumHeight(130)
        self.component_detail.setStyleSheet(
            f"QTextBrowser{{background:{self.T['bg']};color:{self.T['text_2']};"
            f"border:none;border-radius:6px;padding:10px;font-size:12px;}}")
        split.addWidget(self.component_detail)
        split.setSizes([270, 220])
        layout.addWidget(split, 1)
        row = QHBoxLayout()
        self.hardware_tool_btn = QPushButton("Open diagnostic tool")
        self.hardware_tool_btn.setMinimumHeight(34)
        self.hardware_tool_btn.setStyleSheet(self._ghost_style() + "QPushButton{padding:0 14px;}")
        self.hardware_tool_btn.clicked.connect(self._open_component_tool)
        row.addWidget(self.hardware_tool_btn)
        row.addStretch()
        self.hardware_rescan_btn = QPushButton("Re-scan hardware")
        self.hardware_rescan_btn.setMinimumSize(150, 34)
        self.hardware_rescan_btn.setStyleSheet(self._primary_style())
        self.hardware_rescan_btn.clicked.connect(self.start_hardware_scan)
        row.addWidget(self.hardware_rescan_btn)
        layout.addLayout(row)
        return panel

    def _render_components(self, case):
        rows = case.get("components") or []
        self.components.clear()
        self.component_detail.clear()
        self.tabs.setTabVisible(3, bool(rows))
        self.hardware_tool_btn.setEnabled(False)
        for component in rows:
            item = QTreeWidgetItem([component['name'], component['status_label'], component['summary']])
            item.setData(0, QtC.UserRole, component)
            colour = 'warn' if component['status'] == 'attention' else 'text_3'
            item.setForeground(1, QColor(self.T[colour]))
            for column in range(3):
                item.setToolTip(column, item.text(column))
            self.components.addTopLevelItem(item)
        if rows:
            attention = sum(c['status'] == 'attention' for c in rows)
            limited = sum(c['status'] in ('limited', 'unavailable') for c in rows)
            self.hardware_note.setText(
                f"{len(rows)} component groups · {attention} need attention · {limited} have limited or missing readings. "
                "Select a row for repair steps.")
            selected = next((i for i, c in enumerate(rows) if c['status'] == 'attention'), 0)
            self.components.setCurrentItem(self.components.topLevelItem(selected))

    def _show_component(self, item, previous=None):
        if item is None:
            self.component_detail.clear()
            self.hardware_tool_btn.setEnabled(False)
            return
        c = item.data(0, QtC.UserRole)
        esc = _html.escape
        parts = [f"<h3>{esc(c['name'])}</h3>"]
        for heading, lines in (("What to do", c['next_steps']), ("Evidence", c['evidence']),
                               ("Missing checks", c['missing'])):
            if lines:
                parts.append(f"<h4>{heading}</h4><ul>" + ''.join(f"<li>{esc(line)}</li>" for line in lines) + "</ul>")
        parts.append(f"<h4>Limits of this check</h4><p>{esc(c['limitation'])}</p>")
        if c['devices']:
            parts.append("<h4>Connected devices</h4><ul>" + ''.join(
                f"<li>{esc(d['name'])} — {esc('Code ' + str(d['code']) if d['code'] is not None else 'Status unavailable')}</li>"
                for d in c['devices']) + "</ul>")
        self.component_detail.setHtml(''.join(parts))
        labels = {"device_manager": "Open Device Manager", "memory_diagnostic": "Open Memory Diagnostic",
                  "system_information": "Open System Information"}
        self.hardware_tool_btn.setText(labels.get(c['tool'], "Open diagnostic tool"))
        self.hardware_tool_btn.setEnabled(not self._busy and c['tool'] in labels)

    def _open_component_tool(self):
        item = self.components.currentItem()
        if self._busy or item is None:
            return
        # Fixed local entry points only; no device names or probe text become commands.
        tool = item.data(0, QtC.UserRole).get('tool')
        system = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32')
        commands = {'device_manager': [os.path.join(system, 'mmc.exe'), os.path.join(system, 'devmgmt.msc')],
                    'memory_diagnostic': [os.path.join(system, 'mdsched.exe')],
                    'system_information': [os.path.join(system, 'msinfo32.exe')]}
        if tool not in commands:
            return
        try:
            subprocess.Popen(commands[tool])
        except OSError as exc:
            self.status.setText(f"The diagnostic tool could not open: {exc}")

    def _primary_style(self):
        return (
            f"QPushButton{{background:{self.T['accent']};color:#fff;border:none;border-radius:7px;"
            "font-size:12px;font-weight:650;}"
            f"QPushButton:hover{{background:{self.T['accent_hi']};}}"
            f"QPushButton:disabled{{background:{self.T['card_hi']};color:{self.T['text_3']};}}"
        )

    def _ghost_style(self):
        return (
            f"QPushButton{{background:transparent;color:{self.T['text_2']};"
            f"border:1px solid {self.T['border_hi']};border-radius:7px;font-size:12px;font-weight:600;}}"
            f"QPushButton:hover{{border-color:{self.T['accent']};color:{self.T['text']};}}"
            f"QPushButton:disabled{{color:{self.T['text_3']};border-color:{self.T['border']};}}"
        )

    def _build_interview(self):
        card = QFrame()
        card.setObjectName("interviewCard")
        card.setStyleSheet(
            f"#interviewCard{{background:{self.T['card']};border:1px solid {self.T['accent']};"
            "border-radius:9px;}"
        )
        layout = QVBoxLayout(card)
        layout.setContentsMargins(15, 12, 15, 12)
        layout.setSpacing(9)
        heading = QLabel("A few questions first")
        heading.setStyleSheet(f"color:{self.T['text']};font-size:13px;font-weight:650;background:transparent;")
        layout.addWidget(heading)
        note = QLabel(
            "These are the things this PC cannot work out for itself, and they change "
            "what the checks look for. Answer what you can — \"not sure\" is fine."
        )
        note.setWordWrap(True)
        note.setStyleSheet(f"color:{self.T['text_3']};font-size:11px;background:transparent;")
        layout.addWidget(note)

        self.question_box = QVBoxLayout()
        self.question_box.setSpacing(7)
        layout.addLayout(self.question_box)

        buttons = QHBoxLayout()
        buttons.addStretch()
        self.skip_btn = QPushButton("Skip questions")
        self.skip_btn.setFixedSize(126, 32)
        self.skip_btn.setCursor(QtC.PointingHandCursor)
        self.skip_btn.setStyleSheet(self._ghost_style())
        self.skip_btn.clicked.connect(lambda: self._submit_interview(skip=True))
        buttons.addWidget(self.skip_btn)
        self.answers_btn = QPushButton("Run the checks")
        self.answers_btn.setFixedSize(136, 32)
        self.answers_btn.setCursor(QtC.PointingHandCursor)
        self.answers_btn.setStyleSheet(self._primary_style())
        self.answers_btn.clicked.connect(lambda: self._submit_interview(skip=False))
        buttons.addWidget(self.answers_btn)
        layout.addLayout(buttons)
        return card

    def _build_progress(self):
        row = QWidget()
        row.setStyleSheet("background:transparent;")
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(9)
        self.progress = QProgressBar()
        self.progress.setFixedHeight(6)
        self.progress.setTextVisible(False)
        self.progress.setStyleSheet(
            f"QProgressBar{{background:{self.T['card_hi']};border:none;border-radius:3px;}}"
            f"QProgressBar::chunk{{background:{self.T['accent']};border-radius:3px;}}"
        )
        layout.addWidget(self.progress, 1)
        self.progress_label = QLabel("")
        self.progress_label.setFixedWidth(230)
        self.progress_label.setStyleSheet(f"color:{self.T['text_3']};font-size:10.5px;background:transparent;")
        layout.addWidget(self.progress_label)
        self.cancel_sweep_btn = QPushButton("Cancel")
        self.cancel_sweep_btn.setFixedSize(74, 26)
        self.cancel_sweep_btn.setCursor(QtC.PointingHandCursor)
        self.cancel_sweep_btn.setStyleSheet(self._ghost_style())
        self.cancel_sweep_btn.clicked.connect(self._cancel_sweep)
        layout.addWidget(self.cancel_sweep_btn)
        return row

    def _tree_style(self):
        return (
            f"QTreeWidget{{background:{self.T['bg']};color:{self.T['text_2']};"
            f"border:1px solid {self.T['border']};border-radius:6px;font-size:11px;outline:none;}}"
            "QTreeWidget::item{height:34px;padding:2px 6px;}"
            f"QTreeWidget::item:selected{{background:{self.T['accent']};color:#fff;}}"
            f"QHeaderView::section{{background:{self.T['sidebar']};color:{self.T['text_3']};"
            f"border:none;border-bottom:1px solid {self.T['border']};padding:5px;"
            "font-size:10px;font-weight:600;}"
        )

    def _build_upper(self):
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(
            f"QTabWidget::pane{{background:{self.T['card']};border:1px solid {self.T['border']};"
            "border-radius:8px;}"
            f"QTabBar::tab{{background:transparent;color:{self.T['text_3']};padding:10px 16px;"
            "font-size:12px;font-weight:600;border:none;}"
            f"QTabBar::tab:selected{{color:{self.T['text']};border-bottom:2px solid {self.T['accent']};}}"
        )

        assessment = QWidget()
        assessment.setStyleSheet("background:transparent;")
        outer = QVBoxLayout(assessment)
        outer.setContentsMargins(9, 9, 9, 9)
        self.assessment_scroll = QScrollArea()
        self.assessment_scroll.setWidgetResizable(True)
        self.assessment_scroll.setFrameShape(QFrame.NoFrame)
        self.assessment_scroll.setStyleSheet("background:transparent;")
        holder = QWidget()
        holder.setStyleSheet("background:transparent;")
        self.assessment_box = QVBoxLayout(holder)
        self.assessment_box.setContentsMargins(0, 0, 0, 0)
        self.assessment_box.setSpacing(8)
        self.assessment_empty = QLabel(
            "Your results will appear here.\n\nStart with a problem description, check Windows for issues, "
            "or run Deep Hardware Check to review components and repair options."
        )
        self.assessment_empty.setWordWrap(True)
        self.assessment_empty.setStyleSheet(
            f"color:{self.T['text_3']};font-size:11.5px;background:transparent;")
        self.assessment_box.addWidget(self.assessment_empty)
        self.assessment_box.addStretch()
        self.assessment_scroll.setWidget(holder)
        outer.addWidget(self.assessment_scroll)
        self.tabs.addTab(assessment, "Assessment")

        evidence = QWidget()
        evidence.setStyleSheet("background:transparent;")
        inner = QVBoxLayout(evidence)
        inner.setContentsMargins(9, 9, 9, 9)
        inner.setSpacing(7)

        # Eighty-odd readings is a lot to scroll when four of them are the
        # point. The filter is off by default because the healthy rows are the
        # evidence that the check actually looked -- but once a user has seen
        # that, they want the short list.
        filter_row = QHBoxLayout()
        filter_row.setSpacing(9)
        self.findings_filter = WMCheckBox("Only what needs attention", T=self.T)
        self.findings_filter.setStyleSheet(
            f"QCheckBox{{color:{self.T['text_2']};font-size:11px;background:transparent;}}")
        self.findings_filter.toggled.connect(lambda _on: self._render_findings())
        filter_row.addWidget(self.findings_filter)
        self.findings_count = QLabel("")
        self.findings_count.setStyleSheet(
            f"color:{self.T['text_3']};font-size:11px;background:transparent;")
        filter_row.addWidget(self.findings_count, 1)
        inner.addLayout(filter_row)

        self.findings = QTreeWidget()
        self.findings.setColumnCount(3)
        self.findings.setHeaderLabels(["Check", "Result", "What it means"])
        self.findings.setRootIsDecorated(False)
        self.findings.setStyleSheet(self._tree_style())
        self.findings.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.findings.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.findings.header().setSectionResizeMode(2, QHeaderView.Stretch)
        self.findings.currentItemChanged.connect(self._show_finding)

        # Every row is a claim about this PC, and a claim the user cannot trace
        # is just an assertion. Selecting one opens what was actually measured,
        # which Windows facility it was read from, and what follows from it.
        self.finding_detail = QTextBrowser()
        self.finding_detail.setOpenExternalLinks(False)
        # On a short window the table is what matters, so it keeps the larger
        # share as space runs out, and the detail pane can be dragged shut
        # entirely. Selecting a row reopens it -- see _show_finding.
        self.findings.setMinimumHeight(80)
        self.finding_detail.setMinimumHeight(0)
        self.finding_detail.setStyleSheet(
            f"QTextBrowser{{background:{self.T['bg']};color:{self.T['text_2']};"
            f"border:1px solid {self.T['border']};border-radius:6px;padding:10px;font-size:11.5px;}}")
        self._clear_finding_detail()

        self.findings_split = QSplitter(QtC.Vertical)
        self.findings_split.setChildrenCollapsible(True)
        self.findings_split.addWidget(self.findings)
        self.findings_split.addWidget(self.finding_detail)
        self.findings_split.setStretchFactor(0, 2)
        self.findings_split.setStretchFactor(1, 1)
        # Starts shut, so the table is exactly as tall as it was before this
        # pane existed -- on a small window that is the difference between
        # eight readings visible and two. Clicking a row opens it.
        self.findings_split.setSizes([1, 0])
        inner.addWidget(self.findings_split, 1)
        self.tabs.addTab(evidence, "Measurements")

        # The same evidence on a date axis. Two questions the other tabs cannot
        # answer live here: when did this PC start going wrong, and what
        # happened to it just before that.
        history = QWidget()
        history.setStyleSheet("background:transparent;")
        stack = QVBoxLayout(history)
        stack.setContentsMargins(9, 9, 9, 9)
        stack.setSpacing(7)
        self.timeline_note = QLabel(
            "Changes and faults on one date axis. Nothing here is a diagnosis on its own -- "
            "it is the record a diagnosis gets checked against."
        )
        self.timeline_note.setWordWrap(True)
        self.timeline_note.setStyleSheet(
            f"color:{self.T['text_3']};font-size:11px;background:transparent;")
        stack.addWidget(self.timeline_note)
        self.timeline = QTreeWidget()
        self.timeline.setColumnCount(4)
        self.timeline.setHeaderLabels(["When", "", "What happened", "Detail"])
        self.timeline.setRootIsDecorated(False)
        self.timeline.setStyleSheet(self._tree_style())
        self.timeline.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.timeline.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.timeline.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.timeline.header().setSectionResizeMode(3, QHeaderView.Stretch)
        stack.addWidget(self.timeline)
        self.tabs.addTab(history, "Timeline")
        return self.tabs

    def _build_plan(self):
        frame = QFrame()
        frame.setObjectName("guidedPanel")
        frame.setStyleSheet(
            f"#guidedPanel{{background:{self.T['card']};border:1px solid {self.T['border']};"
            "border-radius:8px;}"
        )
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(7)
        heading = QLabel("Repair plan")
        heading.setStyleSheet(f"color:{self.T['text']};font-size:13px;font-weight:650;background:transparent;")
        layout.addWidget(heading)

        self.plan = QTreeWidget()
        self.plan.setColumnCount(5)
        self.plan.setHeaderLabels(["Run", "Step", "Why", "Time", "Undo"])
        self.plan.setRootIsDecorated(False)
        self.plan.setStyleSheet(self._tree_style())
        self.plan.setItemDelegateForColumn(0, WMSwitchDelegate(self.plan))
        self.plan.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.plan.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.plan.header().setSectionResizeMode(2, QHeaderView.Stretch)
        self.plan.header().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.plan.header().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.plan.itemChanged.connect(self._update_run_button)
        layout.addWidget(self.plan, 1)

        self.withheld_label = QLabel("")
        self.withheld_label.setWordWrap(True)
        self.withheld_label.setVisible(False)
        self.withheld_label.setStyleSheet(
            f"color:{self.T['text_2']};font-size:11px;background:{self.T['bg']};"
            f"border-left:2px solid {self.T['danger']};border-radius:0 5px 5px 0;padding:7px 9px;"
        )
        layout.addWidget(self.withheld_label)

        bottom = QHBoxLayout()
        self.plan_note = QLabel("No plan yet.")
        self.plan_note.setWordWrap(True)
        self.plan_note.setStyleSheet(f"color:{self.T['text_3']};font-size:11px;background:transparent;")
        layout.addWidget(self.plan_note)
        bottom.addStretch()

        self.report_btn = QPushButton("Save report")
        self.report_btn.setFixedSize(104, 34)
        self.report_btn.setCursor(QtC.PointingHandCursor)
        self.report_btn.setEnabled(False)
        self.report_btn.setToolTip(
            "Save a self-contained case report: what was reported, what was measured, "
            "what it was judged to be, and what was deliberately not done."
        )
        self.report_btn.setStyleSheet(self._ghost_style())
        self.report_btn.clicked.connect(self._export_report)
        bottom.addWidget(self.report_btn)

        self.recheck_btn = QPushButton("Re-check now")
        self.recheck_btn.setFixedSize(112, 34)
        self.recheck_btn.setCursor(QtC.PointingHandCursor)
        self.recheck_btn.setEnabled(False)
        self.recheck_btn.setToolTip(
            "Repeat the original read-only checks and compare against the state before "
            "the last guided repair — useful after the restart a fix needed."
        )
        self.recheck_btn.setStyleSheet(self._ghost_style())
        self.recheck_btn.clicked.connect(self._recheck)
        bottom.addWidget(self.recheck_btn)
        self.confirm_symptom_btn = QPushButton("Confirm symptom")
        self.confirm_symptom_btn.setMinimumHeight(34)
        self.confirm_symptom_btn.setStyleSheet(self._ghost_style())
        self.confirm_symptom_btn.setVisible(False)
        self.confirm_symptom_btn.clicked.connect(self._confirm_symptom)
        bottom.addWidget(self.confirm_symptom_btn)

        self.run_plan_btn = QPushButton("Run protected plan")
        self.run_plan_btn.setFixedSize(156, 34)
        self.run_plan_btn.setCursor(QtC.PointingHandCursor)
        self.run_plan_btn.setEnabled(False)
        self.run_plan_btn.setStyleSheet(self._primary_style())
        self.run_plan_btn.clicked.connect(self._run_plan)
        bottom.addWidget(self.run_plan_btn)
        self.plan_actions = QWidget()
        self.plan_actions.setLayout(bottom)
        bottom.setContentsMargins(0, 6, 0, 0)
        return frame
