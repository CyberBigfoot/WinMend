"""WinMend ui: widgets: hypothesis."""

from __future__ import annotations

from PySide6.QtCore import Qt as QtC
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout
import html as _html


class WMStepShim:
    """Adapts a plan step to the little interface the run queue expects."""

    __slots__ = ("id", "title", "risk", "restore_point", "admin", "reboot", "step")

    def __init__(self, step):
        self.id = step["id"]
        self.title = step["title"]
        self.risk = step.get("risk", "caution")
        self.restore_point = bool(step.get("restore_point"))
        self.admin = bool(step.get("admin"))
        self.reboot = bool(step.get("reboot"))
        self.step = step

    def display_title(self, simple_mode=False):
        return self.title


class WMHypothesisCard(QFrame):
    """One ranked explanation: what it is, why, and what to do about it."""

    COLOURS = {"critical": "danger", "high": "warn", "medium": "warn", "low": "text_3"}

    def __init__(self, hypothesis, theme, evidence=None, on_evidence=None):
        super().__init__()
        T = theme
        self.setObjectName("hypCard")
        severity = hypothesis.get("severity", "medium")
        accent = T[self.COLOURS.get(severity, "text_3")]
        self.setStyleSheet(
            f"#hypCard{{background:{T['card']};border:1px solid {T['border']};"
            f"border-left:3px solid {accent};border-radius:7px;}}"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 9, 12, 10)
        layout.setSpacing(5)

        header = QHBoxLayout()
        header.setSpacing(7)
        pill = QLabel(severity.upper())
        pill.setStyleSheet(
            f"background:{accent};color:{T['bg']};border-radius:8px;padding:1px 8px;"
            "font-size:9px;font-weight:700;"
        )
        header.addWidget(pill)
        title = QLabel(hypothesis.get("title", ""))
        title.setWordWrap(True)
        title.setStyleSheet(f"color:{T['text']};font-size:13px;font-weight:650;background:transparent;")
        header.addWidget(title, 1)
        confidence = QLabel(f"{hypothesis.get('evidence_strength', 'uncalibrated').title()} evidence")
        confidence.setStyleSheet(f"color:{T['text_3']};font-size:10px;background:transparent;")
        header.addWidget(confidence)
        layout.addLayout(header)

        explanation = QLabel(hypothesis.get("explanation", ""))
        title.setTextFormat(QtC.PlainText)
        explanation.setTextFormat(QtC.PlainText)
        explanation.setWordWrap(True)
        explanation.setStyleSheet(f"color:{T['text_2']};font-size:11.5px;background:transparent;")
        layout.addWidget(explanation)

        if hypothesis.get("advice"):
            advice = QLabel("What to do:  " + hypothesis["advice"])
            advice.setTextFormat(QtC.PlainText)
            advice.setWordWrap(True)
            advice.setStyleSheet(
                f"color:{T['text_2']};font-size:11px;background:{T['bg']};"
                f"border-left:2px solid {T['accent']};border-radius:0 5px 5px 0;padding:6px 9px;"
            )
            layout.addWidget(advice)
        for field, label in (("supporting", "Supports"), ("contradictory", "Against"), ("missing", "Missing")):
            if hypothesis.get(field):
                detail = QLabel(label + ": " + ", ".join(hypothesis[field]))
                detail.setTextFormat(QtC.PlainText)
                detail.setWordWrap(True)
                detail.setStyleSheet(f"color:{T['text_3']};font-size:10px;")
                layout.addWidget(detail)

        # The readings this verdict rests on, as links. A conclusion the user
        # cannot follow back to the measurement behind it is just an assertion,
        # and these cards used to end without naming one.
        cited = [key for key in (hypothesis.get("evidence_keys") or [])
                 if key in (evidence or {})]
        if cited and on_evidence is not None:
            links = QLabel("Evidence:  " + " · ".join(
                f"<a style='color:{T['accent_hi']}' href='{_html.escape(key)}'>{_html.escape(evidence[key])}</a>"
                for key in cited))
            links.setWordWrap(True)
            links.setTextFormat(QtC.RichText)
            links.setStyleSheet(f"color:{T['text_3']};font-size:11px;background:transparent;")
            palette = links.palette()
            palette.setColor(QPalette.Link, QColor(T['accent_hi']))
            links.setPalette(palette)
            links.setCursor(QtC.PointingHandCursor)
            links.setToolTip("Opens the measurement this explanation rests on.")
            links.linkActivated.connect(on_evidence)
            layout.addWidget(links)
