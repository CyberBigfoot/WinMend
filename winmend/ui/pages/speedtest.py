"""WinMend ui: pages: speedtest."""

from __future__ import annotations

from PySide6.QtCore import QTimer, Qt as QtC
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QScrollArea,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)
from winmend.core.preferences import _get_pref_path
from winmend.data.task_catalog import WM_TASKS
from winmend.features.speedtest.connection import wifi_bottleneck_verdict
from winmend.features.speedtest.history import SpeedTestHistory, summarize_result_for_history
from winmend.features.speedtest.runner import SpeedTest
from winmend.features.speedtest.verdicts import usage_verdicts
from winmend.reports.speedtest import render_speedtest_report_html
from winmend.ui.pages.storage import WMStoragePage
from winmend.ui.widgets.latency import WMLatencyGraph
import json
import os
import queue
import threading
import time


class WMSpeedTestPage(QWidget):
    """Internet speed test with connection-quality insights.

    Quick test: download, upload, latency, jitter. Advanced test adds
    latency-under-load (a bufferbloat grade for download and upload
    separately), DNS response time and IPv6 reachability. All figures are real
    measurements against Cloudflare's public speed-test servers; nothing is
    invented, in keeping with the honesty rule the diagnostics follow.

    The engine (SpeedTest, in winmend_safety.py) runs on a worker thread and
    streams progress through a queue the UI drains -- the same pattern the
    Storage and winget panels use, so a test survives navigating away.
    """

    _btn = WMStoragePage._btn

    GRADE_HELP = {
        "A+": "Excellent — video calls and gaming stay smooth even mid-download.",
        "A": "Great — barely any lag added when the connection is busy.",
        "B": "Good — a little lag under load, rarely noticeable.",
        "C": "Fair — calls and games may stutter during big downloads.",
        "D": "Poor — expect lag whenever the connection is busy.",
        "F": "Bad — heavy lag under load; a router with SQM/QoS would help.",
    }

    def __init__(self, window):
        super().__init__()
        self.win = window
        self.T = window.T
        self.setStyleSheet("background:transparent;")
        self.running = False
        self.thread = None
        self.cancel_event = threading.Event()
        self.q = queue.Queue()
        self.result = None
        self._advanced = False
        self._max_seen = {"download": 1.0, "upload": 1.0}
        self.history = SpeedTestHistory()
        self._plan = self._load_plan()

        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(11)
        v.addWidget(self._controls())
        v.addWidget(self._plan_row())
        v.addWidget(self._gauges())
        v.addWidget(self._graph_card())
        v.addWidget(self._phase_row())
        self._insights_scroll = QScrollArea()
        self._insights_scroll.setWidgetResizable(True)
        self._insights_scroll.setFrameShape(QFrame.NoFrame)
        self._insights_scroll.setStyleSheet("background:transparent;")
        self._insights_host = QWidget()
        self._insights_host.setStyleSheet("background:transparent;")
        self._insights_layout = QVBoxLayout(self._insights_host)
        self._insights_layout.setContentsMargins(0, 0, 6, 0)
        self._insights_layout.setSpacing(11)
        self._insights_scroll.setWidget(self._insights_host)
        v.addWidget(self._insights_scroll, 1)
        v.addWidget(self._footer())

        self.pump = QTimer(self)
        self.pump.timeout.connect(self._drain)
        self.pump.start(90)
        self._render_idle()

    # ---- chrome ----

    def _controls(self):
        T = self.T
        f = QFrame()
        f.setObjectName("stc")
        f.setStyleSheet(f"#stc{{background:{T['card']};border:1px solid {T['border']};"
                        f"border-radius:8px;}}")
        h = QHBoxLayout(f)
        h.setContentsMargins(13, 10, 13, 10)
        h.setSpacing(9)
        self.start_btn = self._btn("Start speed test", primary=True, w=150)
        self.start_btn.clicked.connect(lambda: self._start(advanced=False))
        h.addWidget(self.start_btn)
        self.adv_btn = self._btn("Advanced test", w=128)
        self.adv_btn.setToolTip("Also grades bufferbloat (latency under load), "
                                "DNS response time and IPv6. Takes a little longer.")
        self.adv_btn.clicked.connect(lambda: self._start(advanced=True))
        h.addWidget(self.adv_btn)
        self.cancel_btn = self._btn("Cancel", w=84)
        self.cancel_btn.setVisible(False)
        self.cancel_btn.clicked.connect(self._cancel)
        h.addWidget(self.cancel_btn)
        h.addStretch()
        self.server_lbl = QLabel("")
        self.server_lbl.setStyleSheet(f"color:{T['text_3']};font-size:12px;background:transparent;")
        self.server_lbl.setMinimumWidth(1)
        h.addWidget(self.server_lbl)
        return f

    def _plan_row(self):
        T = self.T
        f = QFrame()
        f.setStyleSheet("background:transparent;")
        h = QHBoxLayout(f)
        h.setContentsMargins(2, 0, 2, 0)
        h.setSpacing(7)
        lbl = QLabel("Your plan (optional):")
        lbl.setStyleSheet(f"color:{T['text_3']};font-size:12px;background:transparent;")
        h.addWidget(lbl)
        edit_css = (f"QLineEdit{{background:{T['card']};border:1px solid {T['border']};"
                    f"border-radius:6px;padding:4px 7px;color:{T['text']};font-size:12px;}}"
                    f"QLineEdit:focus{{border:1px solid {T['accent']};}}")
        self.plan_down = QLineEdit()
        self.plan_down.setFixedWidth(64)
        self.plan_down.setPlaceholderText("down")
        self.plan_down.setStyleSheet(edit_css)
        h.addWidget(self.plan_down)
        slash = QLabel("/")
        slash.setStyleSheet(f"color:{T['text_3']};background:transparent;")
        h.addWidget(slash)
        self.plan_up = QLineEdit()
        self.plan_up.setFixedWidth(64)
        self.plan_up.setPlaceholderText("up")
        self.plan_up.setStyleSheet(edit_css)
        h.addWidget(self.plan_up)
        unit = QLabel("Mbps")
        unit.setStyleSheet(f"color:{T['text_3']};font-size:12px;background:transparent;")
        h.addWidget(unit)
        save = self._btn("Save", w=64)
        save.clicked.connect(self._save_plan)
        h.addWidget(save)
        if self._plan.get("down"):
            self.plan_down.setText(f"{self._plan['down']:g}")
        if self._plan.get("up"):
            self.plan_up.setText(f"{self._plan['up']:g}")
        h.addStretch()
        self.export_btn = self._btn("Export report", w=124)
        self.export_btn.setEnabled(False)
        self.export_btn.setToolTip("Save a timestamped HTML report you can send to your ISP.")
        self.export_btn.clicked.connect(self._export_report)
        h.addWidget(self.export_btn)
        return f

    def _graph_card(self):
        T = self.T
        card = QFrame()
        card.setObjectName("grc")
        card.setStyleSheet(f"#grc{{background:{T['card']};border:1px solid {T['border']};"
                           f"border-radius:9px;}}")
        v = QVBoxLayout(card)
        v.setContentsMargins(12, 9, 12, 10)
        v.setSpacing(5)
        head = QHBoxLayout()
        title = QLabel("Latency over the test")
        title.setStyleSheet(f"color:{T['text_3']};font-size:11px;font-weight:600;"
                            f"letter-spacing:0.4px;background:transparent;")
        head.addWidget(title)
        head.addStretch()
        key = QLabel("● idle    ● under load")
        key.setStyleSheet(f"color:{T['text_3']};font-size:10px;background:transparent;")
        head.addWidget(key)
        v.addLayout(head)
        self.graph = WMLatencyGraph(T)
        v.addWidget(self.graph)
        return card

    def _gauge_card(self, key, title, unit):
        T = self.T
        card = QFrame()
        card.setObjectName("gcard")
        card.setStyleSheet(f"#gcard{{background:{T['card']};border:1px solid {T['border']};"
                           f"border-radius:10px;}}")
        v = QVBoxLayout(card)
        v.setContentsMargins(18, 15, 18, 15)
        v.setSpacing(2)
        cap = QLabel(title)
        cap.setStyleSheet(f"color:{T['text_3']};font-size:12px;font-weight:600;"
                          f"letter-spacing:0.4px;background:transparent;")
        v.addWidget(cap)
        row = QHBoxLayout()
        row.setSpacing(6)
        row.setContentsMargins(0, 0, 0, 0)
        value = QLabel("—")
        value.setStyleSheet(f"color:{T['text']};font-size:33px;font-weight:700;"
                            f"background:transparent;")
        row.addWidget(value)
        u = QLabel(unit)
        u.setStyleSheet(f"color:{T['text_3']};font-size:13px;background:transparent;")
        u.setAlignment(QtC.AlignBottom | QtC.AlignLeft)
        row.addWidget(u)
        row.addStretch()
        v.addLayout(row)
        bar = QProgressBar()
        bar.setFixedHeight(4)
        bar.setTextVisible(False)
        bar.setRange(0, 1000)
        bar.setValue(0)
        bar.setStyleSheet(
            f"QProgressBar{{background:{T['card_hi']};border:none;border-radius:2px;}}"
            f"QProgressBar::chunk{{background:{T['accent']};border-radius:2px;}}")
        v.addWidget(bar)
        self._gauge_widgets[key] = (value, bar)
        return card

    def _gauges(self):
        self._gauge_widgets = {}
        row = QWidget()
        row.setStyleSheet("background:transparent;")
        h = QHBoxLayout(row)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(11)
        h.addWidget(self._gauge_card("download", "DOWNLOAD", "Mbps"), 1)
        h.addWidget(self._gauge_card("upload", "UPLOAD", "Mbps"), 1)
        h.addWidget(self._gauge_card("ping", "PING", "ms"), 1)
        return row

    def _phase_row(self):
        T = self.T
        row = QWidget()
        row.setStyleSheet("background:transparent;")
        h = QHBoxLayout(row)
        h.setContentsMargins(2, 0, 2, 0)
        h.setSpacing(10)
        self.phase_lbl = QLabel("Ready when you are.")
        self.phase_lbl.setStyleSheet(f"color:{T['text_2']};font-size:12px;background:transparent;")
        h.addWidget(self.phase_lbl)
        h.addStretch()
        self.phase_bar = QProgressBar()
        self.phase_bar.setFixedSize(160, 5)
        self.phase_bar.setTextVisible(False)
        self.phase_bar.setRange(0, 0)
        self.phase_bar.setVisible(False)
        self.phase_bar.setStyleSheet(
            f"QProgressBar{{background:{T['card_hi']};border:none;border-radius:2px;}}"
            f"QProgressBar::chunk{{background:{T['accent']};border-radius:2px;}}")
        h.addWidget(self.phase_bar)
        return row

    def _footer(self):
        note = QLabel("Measures your connection by transferring data to and from "
                      "Cloudflare's public speed-test servers (speed.cloudflare.com). "
                      "No information about this PC is sent, and nothing is changed. "
                      "Moving enough data for an accurate result can use several hundred "
                      "MB — or ~1 GB on very fast links — so mind metered connections.")
        note.setWordWrap(True)
        note.setStyleSheet(f"color:{self.T['text_3']};font-size:11px;background:transparent;")
        return note

    # ---- run control ----

    def _start(self, advanced):
        if self.running:
            return
        self.running = True
        self._advanced = advanced
        self.cancel_event = threading.Event()
        self.result = None
        self._max_seen = {"download": 1.0, "upload": 1.0}
        self.graph.reset()
        self.export_btn.setEnabled(False)
        for key in ("download", "upload", "ping"):
            value, bar = self._gauge_widgets[key]
            value.setText("—")
            value.setStyleSheet(f"color:{self.T['text']};font-size:33px;font-weight:700;"
                                f"background:transparent;")
            bar.setValue(0)
        self._clear_insights()
        self.start_btn.setEnabled(False)
        self.adv_btn.setEnabled(False)
        self.cancel_btn.setVisible(True)
        self.cancel_btn.setEnabled(True)
        self.phase_bar.setVisible(True)
        self.phase_lbl.setText("Starting…")
        self.win._log("Speed test started" + (" (advanced)" if advanced else "") + "…",
                      self.T['text_2'])

        def work():
            engine = SpeedTest(progress=lambda e: self.q.put(e),
                               cancel=self.cancel_event.is_set)
            try:
                engine.run(advanced=advanced)
            except Exception as exc:
                self.q.put({"type": "error", "error": str(exc)})
        self.thread = threading.Thread(target=work, daemon=True)
        self.thread.start()

    def _cancel(self):
        self.cancel_event.set()
        self.cancel_btn.setEnabled(False)
        self.phase_lbl.setText("Stopping…")

    # ---- live updates ----

    def _drain(self):
        try:
            while True:
                event = self.q.get_nowait()
                self._handle(event)
        except queue.Empty:
            pass
        except RuntimeError:
            pass  # page torn down mid-drain

    def _handle(self, event):
        kind = event.get("type")
        if kind == "phase":
            self.phase_lbl.setText(event.get("label", ""))
            if event.get("phase") == "server":
                pass
        elif kind == "throughput":
            self._on_throughput(event)
        elif kind == "latency":
            self.graph.add(event["ms"], event.get("loaded", False))
            if not event.get("loaded"):
                # live idle-latency read-out on the ping gauge
                value, _bar = self._gauge_widgets["ping"]
                value.setText(f"{event['ms']:.0f}")
        elif kind == "error":
            self._finish_error(event.get("error", "The speed test failed."))
        elif kind == "done":
            self._finish(event.get("result") or {})

    def _on_throughput(self, event):
        phase = event.get("phase")
        if phase not in ("download", "upload"):
            return
        mbps = float(event.get("mbps", 0.0))
        value, bar = self._gauge_widgets[phase]
        value.setText(f"{mbps:.1f}")
        self._max_seen[phase] = max(self._max_seen[phase], mbps)
        # fill the bar relative to the fastest sample seen this run
        bar.setValue(int(1000 * mbps / self._max_seen[phase]) if self._max_seen[phase] else 0)

    # ---- completion ----

    def _finish(self, result):
        self.result = result
        self.running = False
        self.thread = None
        self.cancel_btn.setVisible(False)
        self.start_btn.setEnabled(True)
        self.adv_btn.setEnabled(True)
        self.phase_bar.setVisible(False)

        server = result.get("server") or {}
        if server.get("available"):
            bits = ["Cloudflare"]
            if server.get("colo"):
                bits.append(str(server["colo"]))
            if server.get("isp"):
                bits.append(str(server["isp"]))
            self.server_lbl.setText("  ·  ".join(bits))

        down = result.get("download") or {}
        up = result.get("upload") or {}
        idle = result.get("idle_latency") or {}
        # A phase that moved almost no data failed; show "—", not a bogus 0.0.
        down_ok = down.get("ok", True)
        up_ok = up.get("ok", True)
        self._set_final_gauge("download", down.get("mbps") if down_ok else None)
        self._set_final_gauge("upload", up.get("mbps") if up_ok else None)
        ping_value, _bar = self._gauge_widgets["ping"]
        ping_value.setText(f"{idle['min_ms']:.0f}" if idle.get("min_ms") is not None else "—")

        failed = [name for name, ok in (("download", down_ok), ("upload", up_ok)) if not ok]
        if result.get("status") == "cancelled":
            self.phase_lbl.setText("Test cancelled.")
        elif failed:
            # Don't record a misleading run; tell the user why and let them retry.
            self.phase_lbl.setText(
                "Couldn't measure " + " and ".join(failed) +
                " — the speed-test server was busy or unreachable. Try again in a moment.")
            self.win._log("Speed test: " + "/".join(failed) +
                          " could not be measured (server busy or offline).", self.T['warn'])
        else:
            self.phase_lbl.setText("Done.")
            self.export_btn.setEnabled(True)
            self._log_result(result)
            try:
                self.history.add(summarize_result_for_history(result))
            except Exception:
                pass
        self._render_insights(result)

    def _finish_error(self, message):
        self.running = False
        self.thread = None
        self.cancel_btn.setVisible(False)
        self.start_btn.setEnabled(True)
        self.adv_btn.setEnabled(True)
        self.phase_bar.setVisible(False)
        self.phase_lbl.setText(message)
        self.win._log(f"Speed test: {message}", self.T['danger'])

    def _set_final_gauge(self, key, mbps):
        value, bar = self._gauge_widgets[key]
        if mbps is None:
            value.setText("—")
            return
        value.setText(f"{mbps:.1f}")
        bar.setValue(1000)

    def _log_result(self, result):
        down = (result.get("download") or {}).get("mbps")
        up = (result.get("upload") or {}).get("mbps")
        ping = (result.get("idle_latency") or {}).get("min_ms")
        parts = []
        if down is not None:
            parts.append(f"{down:.1f} Mbps down")
        if up is not None:
            parts.append(f"{up:.1f} up")
        if ping is not None:
            parts.append(f"{ping:.0f} ms ping")
        self.win._log("Speed test: " + ", ".join(parts) + ".", self.T['ok'])

    # ---- insights + history ----

    def _clear_insights(self):
        while self._insights_layout.count():
            item = self._insights_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.setParent(None)

    def _render_idle(self):
        self._clear_insights()
        T = self.T
        card = QFrame()
        card.setObjectName("hint")
        card.setStyleSheet(f"#hint{{background:{T['card']};border:1px solid {T['border']};"
                           f"border-radius:9px;}}")
        v = QVBoxLayout(card)
        v.setContentsMargins(16, 14, 16, 14)
        v.setSpacing(4)
        title = QLabel("Two tests in one")
        title.setStyleSheet(f"color:{T['text']};font-size:14px;font-weight:700;background:transparent;")
        v.addWidget(title)
        body = QLabel(
            "• <b>Start speed test</b> — download, upload, ping and jitter.<br>"
            "• <b>Advanced test</b> — adds a bufferbloat grade (how much lag a busy "
            "connection adds — the real reason calls stutter during downloads), plus "
            "DNS response time and IPv6 reachability.")
        body.setWordWrap(True)
        body.setTextFormat(QtC.RichText)
        body.setStyleSheet(f"color:{T['text_2']};font-size:12px;background:transparent;")
        v.addWidget(body)
        self._insights_layout.addWidget(card)
        self._render_history()
        self._insights_layout.addStretch()

    def _render_insights(self, result):
        self._clear_insights()
        # Most user-facing first: what the connection is actually good for.
        verdict_card = self._verdict_card(result)
        if verdict_card:
            self._insights_layout.addWidget(verdict_card)
        conn_card = self._connection_card(result)
        if conn_card:
            self._insights_layout.addWidget(conn_card)
        grades = self._grade_rows(result)
        if grades:
            self._insights_layout.addWidget(self._grade_card(grades))
        rows = self._insight_rows(result)
        if rows:
            self._insights_layout.addWidget(self._insight_card("Connection insights", rows))
        fixes = self._fixes_card(result)
        if fixes:
            self._insights_layout.addWidget(fixes)
        self._render_history()
        self._insights_layout.addStretch()

    def _insight_rows(self, result):
        rows = []
        idle = result.get("idle_latency") or {}
        down = result.get("download") or {}
        up = result.get("upload") or {}
        server = result.get("server") or {}
        if idle.get("min_ms") is not None:
            rows.append(("Latency (idle)", f"{idle['min_ms']:.0f} ms min  ·  "
                                           f"{idle.get('avg_ms', 0):.0f} ms avg"))
        if idle.get("jitter_ms") is not None:
            rows.append(("Jitter", f"{idle['jitter_ms']:.1f} ms"))
        # plan comparison — the 'am I getting what I pay for?' answer
        if self._plan.get("down") and down.get("mbps") is not None:
            pct = down["mbps"] / self._plan["down"] * 100
            rows.append(("Download vs plan",
                         f"{pct:.0f}% of your {self._plan['down']:g} Mbps plan"))
        if self._plan.get("up") and up.get("mbps") is not None:
            pct = up["mbps"] / self._plan["up"] * 100
            rows.append(("Upload vs plan",
                         f"{pct:.0f}% of your {self._plan['up']:g} Mbps plan"))
        if down.get("peak_mbps"):
            rows.append(("Download peak", f"{down['peak_mbps']:.1f} Mbps"))
        if up.get("peak_mbps"):
            rows.append(("Upload peak", f"{up['peak_mbps']:.1f} Mbps"))
        if result.get("rpm"):
            rows.append(("Responsiveness", f"{result['rpm']} RPM"))
        # latency tail under load — the part an average hides
        for key, label in (("download", "Latency p95 (down load)"),
                           ("upload", "Latency p95 (up load)")):
            loaded = (result.get(key) or {}).get("loaded_latency") or {}
            if loaded.get("p95_ms") is not None:
                rows.append((label, f"{loaded['p95_ms']:.0f} ms"))
        # multi-target latency — router vs internet
        for target in result.get("multi_latency") or []:
            if target.get("rtt_ms") is not None:
                rows.append((target["label"], f"{target['rtt_ms']:.0f} ms"))
            elif not target.get("reachable"):
                rows.append((target["label"], "unreachable"))
        dns = result.get("dns") or {}
        if dns.get("avg_ms") is not None:
            rows.append(("DNS lookup", f"{dns['avg_ms']:.0f} ms average"))
        ipv6 = result.get("ipv6")
        if ipv6 is not None:
            if ipv6.get("available"):
                rows.append(("IPv6", f"Available  ·  {ipv6.get('latency_ms', 0):.0f} ms"))
            else:
                rows.append(("IPv6", "Not available"))
        if server.get("ip"):
            rows.append(("Your IP", str(server["ip"])))
        loc = "  ·  ".join(str(x) for x in (server.get("city"), server.get("country")) if x)
        if server.get("colo"):
            rows.append(("Server", f"{server['colo']}" + (f"  ·  {loc}" if loc else "")))
        return rows

    # ---- 'good for…' verdict card ----

    def _verdict_card(self, result):
        down = (result.get("download") or {}).get("mbps")
        up = (result.get("upload") or {}).get("mbps")
        if down is None and up is None:
            return None
        idle = (result.get("idle_latency") or {}).get("min_ms")
        loaded = None
        for key in ("download", "upload"):
            lv = (result.get(key) or {}).get("loaded_latency") or {}
            if lv.get("avg_ms") is not None:
                loaded = max(loaded or 0, lv["avg_ms"])
        grade = (result.get("bufferbloat_download") or {}).get("grade")
        verdicts = usage_verdicts(down, up, idle, loaded, grade)
        T = self.T
        colours = {"good": T['ok'], "ok": T['warn'], "bad": T['danger']}
        marks = {"good": "✓", "ok": "●", "bad": "✗"}
        card = QFrame()
        card.setObjectName("vc")
        card.setStyleSheet(f"#vc{{background:{T['card']};border:1px solid {T['border']};"
                           f"border-radius:9px;}}")
        v = QVBoxLayout(card)
        v.setContentsMargins(16, 13, 16, 13)
        v.setSpacing(6)
        head = QLabel("What this connection is good for")
        head.setStyleSheet(f"color:{T['text']};font-size:14px;font-weight:700;"
                           f"background:transparent;")
        v.addWidget(head)
        for item in verdicts:
            row = QHBoxLayout()
            row.setSpacing(9)
            colour = colours.get(item["rating"], T['text_3'])
            mark = QLabel(marks.get(item["rating"], "•"))
            mark.setFixedWidth(16)
            mark.setStyleSheet(f"color:{colour};font-size:14px;font-weight:800;"
                               f"background:transparent;")
            row.addWidget(mark)
            name = QLabel(item["activity"])
            name.setStyleSheet(f"color:{T['text']};font-size:12px;background:transparent;")
            name.setFixedWidth(210)
            row.addWidget(name)
            note = QLabel(item["note"])
            note.setStyleSheet(f"color:{T['text_3']};font-size:12px;background:transparent;")
            row.addWidget(note, 1)
            holder = QWidget()
            holder.setStyleSheet("background:transparent;")
            holder.setLayout(row)
            v.addWidget(holder)
        return card

    # ---- connection / Wi-Fi card ----

    def _connection_card(self, result):
        conn = result.get("connection") or {}
        if not conn.get("available"):
            return None
        T = self.T
        card = QFrame()
        card.setObjectName("cc")
        card.setStyleSheet(f"#cc{{background:{T['card']};border:1px solid {T['border']};"
                           f"border-radius:9px;}}")
        v = QVBoxLayout(card)
        v.setContentsMargins(16, 13, 16, 13)
        v.setSpacing(4)
        head = QLabel("Connection")
        head.setStyleSheet(f"color:{T['text']};font-size:14px;font-weight:700;"
                           f"background:transparent;")
        v.addWidget(head)
        if conn.get("type") == "wifi":
            bits = ["Wi-Fi"]
            if conn.get("radio"):
                bits.append(conn["radio"])
            if conn.get("link_mbps"):
                bits.append(f"{conn['link_mbps']:.0f} Mbps link")
            if conn.get("signal_pct") is not None:
                bits.append(f"{conn['signal_pct']}% signal")
            if conn.get("band"):
                bits.append(f"{conn['band']} ch {conn.get('channel', '?')}")
        elif conn.get("type") == "ethernet":
            bits = ["Ethernet (wired)"]
            if conn.get("link_mbps"):
                bits.append(f"{conn['link_mbps']:.0f} Mbps link")
        else:
            bits = ["Unknown adapter"]
        summary = QLabel("  ·  ".join(bits))
        summary.setStyleSheet(f"color:{T['text_2']};font-size:12px;font-weight:600;"
                              f"background:transparent;")
        v.addWidget(summary)
        verdict = wifi_bottleneck_verdict(conn, (result.get("download") or {}).get("mbps"))
        if verdict:
            severity, text = verdict
            colour = {"warn": T['warn'], "info": T['text_3']}.get(severity, T['text_3'])
            note = QLabel(text)
            note.setWordWrap(True)
            note.setStyleSheet(f"color:{colour};font-size:12px;background:transparent;")
            v.addWidget(note)
        return card

    # ---- suggested fixes ----

    def _suggested_fixes(self, result):
        fixes = []
        seen = set()

        def add(text, task_id):
            if task_id not in seen:
                seen.add(task_id)
                fixes.append((text, task_id))

        dns = result.get("dns") or {}
        if dns.get("avg_ms") is not None and dns["avg_ms"] > 40:
            add("DNS lookups are slow — switch to a faster DNS provider", "change_dns")
            add("…or turn on encrypted DNS (DNS-over-HTTPS)", "dns_over_https")
        for key in ("bufferbloat_download", "bufferbloat_upload"):
            grade = result.get(key)
            if grade and grade.get("grade") in ("D", "F"):
                add("High bufferbloat under load — check Wi-Fi channels/interference",
                    "wifi_channel_analyzer")
                break
        conn = result.get("connection") or {}
        if conn.get("type") == "wifi" and (conn.get("signal_pct") or 100) < 55:
            add("Weak Wi-Fi signal — analyze your Wi-Fi channel and neighbours",
                "wifi_channel_analyzer")
        down = (result.get("download") or {}).get("mbps")
        if down is not None and down < 5:
            add("Speeds are very low — flush DNS and renew your IP", "flush_dns")
            add("…or run the full network diagnostic bundle", "network_diagnostic_bundle")
        return fixes

    def _fixes_card(self, result):
        fixes = self._suggested_fixes(result)
        if not fixes:
            return None
        T = self.T
        card = QFrame()
        card.setObjectName("fc")
        card.setStyleSheet(f"#fc{{background:{T['card']};border:1px solid {T['border']};"
                           f"border-radius:9px;}}")
        v = QVBoxLayout(card)
        v.setContentsMargins(16, 13, 16, 13)
        v.setSpacing(8)
        head = QLabel("Your results suggest")
        head.setStyleSheet(f"color:{T['text']};font-size:14px;font-weight:700;"
                           f"background:transparent;")
        v.addWidget(head)
        for text, task_id in fixes:
            row = QHBoxLayout()
            row.setSpacing(10)
            lbl = QLabel(text)
            lbl.setWordWrap(True)
            lbl.setStyleSheet(f"color:{T['text_2']};font-size:12px;background:transparent;")
            row.addWidget(lbl, 1)
            btn = self._btn("Open", w=72)
            btn.clicked.connect(lambda _=False, t=task_id: self._go_to_task(t))
            row.addWidget(btn)
            holder = QWidget()
            holder.setStyleSheet("background:transparent;")
            holder.setLayout(row)
            v.addWidget(holder)
        return card

    def _go_to_task(self, task_id):
        task = next((t for t in WM_TASKS if t.id == task_id), None)
        if task is None:
            return
        # Advanced tools may be hidden in Simple mode; make sure the target shows.
        if not task.simple and self.win.simple:
            self.win._set_mode(False)
        self.win._show_category(task.category)
        try:
            self.win.search.setText(task.title)
        except Exception:
            pass

    # ---- plan + export ----

    def _load_plan(self):
        try:
            with open(_get_pref_path("speedtest_plan.json"), "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return {"down": data.get("down"), "up": data.get("up")}
        except Exception:
            return {}

    def _save_plan(self):
        def num(edit):
            try:
                val = float(edit.text().strip())
                return val if val > 0 else None
            except ValueError:
                return None
        self._plan = {"down": num(self.plan_down), "up": num(self.plan_up)}
        try:
            with open(_get_pref_path("speedtest_plan.json"), "w", encoding="utf-8") as fh:
                json.dump(self._plan, fh)
        except Exception:
            pass
        self.win._log("Saved your plan speed for comparison.", self.T['text_2'])
        if self.result:
            self._render_insights(self.result)  # refresh the plan-% rows

    def _export_report(self):
        if not self.result:
            return
        try:
            html_text = render_speedtest_report_html(self.result, self._plan)
            # The real Documents folder -- OneDrive redirects it, and then
            # %USERPROFILE%\Documents is an empty leftover nobody looks in.
            out_dir = os.path.join(self.win.host._get_documents_dir(), "WinMend")
            os.makedirs(out_dir, exist_ok=True)
            stamp = time.strftime("%Y-%m-%d_%H%M%S")
            path = os.path.join(out_dir, f"speedtest_{stamp}.html")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(html_text)
            self.win._log(f"Speed-test report saved: {path}", self.T['ok'])
            try:
                os.startfile(path)  # noqa: open in the default browser
            except Exception:
                pass
        except Exception as exc:
            self.win._log(f"Could not export the report: {exc}", self.T['danger'])

    def _grade_rows(self, result):
        rows = []
        for key, label in (("bufferbloat_download", "Under download load"),
                           ("bufferbloat_upload", "Under upload load")):
            grade = result.get(key)
            if grade and grade.get("grade") and grade.get("grade") != "—":
                rows.append((label, grade))
        return rows

    def _insight_card(self, title, rows):
        T = self.T
        card = QFrame()
        card.setObjectName("ic")
        card.setStyleSheet(f"#ic{{background:{T['card']};border:1px solid {T['border']};"
                           f"border-radius:9px;}}")
        v = QVBoxLayout(card)
        v.setContentsMargins(16, 13, 16, 13)
        v.setSpacing(0)
        head = QLabel(title)
        head.setStyleSheet(f"color:{T['text']};font-size:14px;font-weight:700;"
                           f"background:transparent;")
        v.addWidget(head)
        v.addSpacing(6)
        grid = QWidget()
        grid.setStyleSheet("background:transparent;")
        g = QVBoxLayout(grid)
        g.setContentsMargins(0, 0, 0, 0)
        g.setSpacing(0)
        for i, (key, val) in enumerate(rows):
            line = QHBoxLayout()
            line.setContentsMargins(0, 5, 0, 5)
            k = QLabel(key)
            k.setStyleSheet(f"color:{T['text_3']};font-size:12px;background:transparent;")
            k.setFixedWidth(150)
            vl = QLabel(str(val))
            vl.setWordWrap(True)
            vl.setStyleSheet(f"color:{T['text']};font-size:12px;font-weight:600;"
                             f"background:transparent;")
            line.addWidget(k)
            line.addWidget(vl, 1)
            row_w = QWidget()
            row_w.setStyleSheet(
                "background:transparent;" if i == 0 else
                f"background:transparent;border-top:1px solid {T['border']};")
            row_w.setLayout(line)
            g.addWidget(row_w)
        v.addWidget(grid)
        return card

    def _grade_card(self, grades):
        T = self.T
        colours = {"A+": T['ok'], "A": T['ok'], "B": T['ok'],
                   "C": T['warn'], "D": T['danger'], "F": T['danger']}
        card = QFrame()
        card.setObjectName("gc")
        card.setStyleSheet(f"#gc{{background:{T['card']};border:1px solid {T['border']};"
                           f"border-radius:9px;}}")
        v = QVBoxLayout(card)
        v.setContentsMargins(16, 13, 16, 13)
        v.setSpacing(8)
        head = QLabel("Bufferbloat (latency under load)")
        head.setStyleSheet(f"color:{T['text']};font-size:14px;font-weight:700;"
                           f"background:transparent;")
        v.addWidget(head)
        for label, grade in grades:
            letter = grade["grade"]
            colour = colours.get(letter, T['text_3'])
            row = QHBoxLayout()
            row.setSpacing(11)
            pill = QLabel(letter)
            pill.setFixedSize(40, 30)
            pill.setAlignment(QtC.AlignCenter)
            pill.setStyleSheet(f"background:{colour};color:#fff;border-radius:7px;"
                               f"font-size:16px;font-weight:800;")
            row.addWidget(pill)
            text = QLabel(f"<b>{label}</b> — +{grade['increase_ms']:.0f} ms added.  "
                          f"{self.GRADE_HELP.get(letter, '')}")
            text.setWordWrap(True)
            text.setTextFormat(QtC.RichText)
            text.setStyleSheet(f"color:{T['text_2']};font-size:12px;background:transparent;")
            row.addWidget(text, 1)
            holder = QWidget()
            holder.setStyleSheet("background:transparent;")
            holder.setLayout(row)
            v.addWidget(holder)
        return card

    def _render_history(self):
        try:
            entries = self.history.list()
        except Exception:
            entries = []
        if not entries:
            return
        T = self.T
        card = QFrame()
        card.setObjectName("hc")
        card.setStyleSheet(f"#hc{{background:{T['card']};border:1px solid {T['border']};"
                           f"border-radius:9px;}}")
        v = QVBoxLayout(card)
        v.setContentsMargins(16, 13, 16, 13)
        v.setSpacing(6)
        head = QLabel("Recent results")
        head.setStyleSheet(f"color:{T['text']};font-size:14px;font-weight:700;"
                           f"background:transparent;")
        v.addWidget(head)
        tree = QTreeWidget()
        tree.setColumnCount(4)
        tree.setHeaderLabels(["When", "Download", "Upload", "Ping"])
        tree.setRootIsDecorated(False)
        tree.setUniformRowHeights(True)
        tree.setFixedHeight(min(190, 34 + 25 * min(len(entries), 6)))
        tree.setStyleSheet(WMStoragePage._tree_style(self))
        tree.setFocusPolicy(QtC.NoFocus)
        for entry in entries[:6]:
            when = str(entry.get("at") or "")[:16].replace("T", "  ")
            down = entry.get("download_mbps")
            up = entry.get("upload_mbps")
            ping = entry.get("ping_ms")
            item = QTreeWidgetItem([
                when,
                f"{down:.1f} Mbps" if down is not None else "—",
                f"{up:.1f} Mbps" if up is not None else "—",
                f"{ping:.0f} ms" if ping is not None else "—",
            ])
            item.setForeground(1, QColor(T['text_2']))
            item.setForeground(2, QColor(T['text_2']))
            item.setForeground(3, QColor(T['text_2']))
            tree.addTopLevelItem(item)
        tree.setColumnWidth(0, 150)
        tree.setColumnWidth(1, 110)
        tree.setColumnWidth(2, 110)
        v.addWidget(tree)
        self._insights_layout.addWidget(card)
