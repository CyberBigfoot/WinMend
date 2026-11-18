"""WinMend ui: widgets: queue."""

from __future__ import annotations

from PySide6.QtCore import Qt as QtC
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QVBoxLayout


class WMQueueRow(QFrame):
    """One entry in the queue: pending, running (with elapsed), or finished."""

    def __init__(self, title, state, detail, T, on_cancel=None):
        super().__init__()
        col = {"run": T['accent'], "done": T['ok'], "wait": T['text_3'],
               "fail": T['danger'], "cancel": T['text_3']}[state]
        glyph = {"run": "▶", "done": "✓", "wait": "○", "fail": "✕", "cancel": "—"}[state]
        self.setStyleSheet("background:transparent;")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 6, 0, 6)
        lay.setSpacing(9)
        g = QLabel(glyph)
        g.setStyleSheet(f"color:{col};font-size:12px;background:transparent;")
        g.setFixedWidth(13)
        lay.addWidget(g, 0, QtC.AlignTop)
        v = QVBoxLayout()
        v.setSpacing(2)
        t = QLabel(title)
        t.setWordWrap(True)
        t.setStyleSheet(f"color:{T['text'] if state == 'run' else T['text_2']};"
                        f"font-size:12px;font-weight:{600 if state == 'run' else 400};"
                        f"background:transparent;")
        v.addWidget(t)
        self.detail = QLabel(detail)
        # Wraps so the row can be narrower than its longest line: the checklist
        # now lives in a scroll area, which would otherwise widen itself to fit
        # "Running - 00:00 elapsed - no time limit" and push the titles off.
        self.detail.setWordWrap(True)
        self.detail.setStyleSheet(f"color:{col if state == 'run' else T['text_3']};"
                                  f"font-size:11px;background:transparent;")
        v.addWidget(self.detail)
        lay.addLayout(v, 1)
        if state == "run" and on_cancel:
            x = QPushButton("Stop")
            x.setFixedSize(52, 23)
            x.setCursor(QtC.PointingHandCursor)
            x.setStyleSheet(f"""
                QPushButton {{ background:transparent;color:{T['text_3']};
                    border:1px solid {T['border_hi']};border-radius:4px;font-size:10px; }}
                QPushButton:hover {{ color:{T['danger']};border:1px solid {T['danger']}; }}
            """)
            x.clicked.connect(on_cancel)
            lay.addWidget(x, 0, QtC.AlignVCenter)
