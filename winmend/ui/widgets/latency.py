"""WinMend ui: widgets: latency."""

from __future__ import annotations

from PySide6.QtCore import QPointF, Qt as QtC
from PySide6.QtGui import QColor, QPainter, QPen, QPolygonF
from PySide6.QtWidgets import QWidget


class WMLatencyGraph(QWidget):
    """A live line chart of latency samples during a speed test. The rise while
    the link is saturated *is* the bufferbloat, made visible -- a single 'avg'
    number can't show a spike, and the spike is what glitches a call."""

    def __init__(self, theme):
        super().__init__()
        self.T = theme
        self.samples = []          # list of (ms, loaded: bool)
        self.setMinimumHeight(84)
        self.setStyleSheet("background:transparent;")

    def reset(self):
        self.samples = []
        self.update()

    def add(self, ms, loaded):
        self.samples.append((float(ms), bool(loaded)))
        if len(self.samples) > 400:
            self.samples = self.samples[-400:]
        self.update()

    def paintEvent(self, _event):
        T = self.T
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        p.fillRect(0, 0, w, h, QColor(T['card']))
        pad = 8
        if len(self.samples) < 2:
            p.setPen(QColor(T['text_3']))
            p.drawText(self.rect(), QtC.AlignCenter, "Latency graph appears during the test")
            p.end()
            return
        values = [s[0] for s in self.samples]
        lo, hi = min(values), max(values)
        span = max(1.0, hi - lo)
        n = len(self.samples)
        plot_w = w - 2 * pad
        plot_h = h - 2 * pad

        def point(i):
            x = pad + plot_w * (i / (n - 1))
            y = pad + plot_h * (1 - (self.samples[i][0] - lo) / span)
            return QPointF(x, y)

        # faint baseline at the idle minimum
        p.setPen(QPen(QColor(T['border']), 1, QtC.DashLine))
        base_y = pad + plot_h * (1 - (0.0) / span) if lo == hi else \
            pad + plot_h * (1 - (min(values) - lo) / span)
        p.drawLine(pad, int(base_y), w - pad, int(base_y))
        # the line itself
        p.setPen(QPen(QColor(T['accent']), 2))
        p.drawPolyline(QPolygonF([point(i) for i in range(n)]))
        # mark the loaded (under-saturation) samples in a warning tint
        p.setPen(QPen(QColor(T['warn']), 2))
        seg = []
        for i in range(n):
            if self.samples[i][1]:
                seg.append(point(i))
            elif seg:
                if len(seg) > 1:
                    p.drawPolyline(QPolygonF(seg))
                seg = []
        if len(seg) > 1:
            p.drawPolyline(QPolygonF(seg))
        # min / max labels
        p.setPen(QColor(T['text_3']))
        p.drawText(pad, pad + 10, f"{hi:.0f} ms")
        p.drawText(pad, h - pad, f"{lo:.0f} ms")
        p.end()
