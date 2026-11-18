"""Tests for the offline logic behind the Speed Test page: latency/jitter
summarising, bufferbloat grading, the history store, and result flattening.
The network measurements themselves are exercised by a live smoke test, not
here, so this suite stays fast and offline."""

import tempfile
import unittest
from pathlib import Path

from winmend_safety import (
    SpeedTest,
    SpeedTestHistory,
    aggregate_throughput,
    bufferbloat_grade,
    parse_link_speed,
    parse_netsh_wifi,
    render_speedtest_report_html,
    responsiveness_rpm,
    summarize_latency,
    summarize_result_for_history,
    usage_verdicts,
    wifi_bottleneck_verdict,
)


class ParseTraceTests(unittest.TestCase):
    SAMPLE = ("fl=354f173\nh=speed.cloudflare.com\nip=173.73.173.71\n"
              "ts=1784314920.000\ncolo=IAD\nhttp=http/1.1\nloc=US\nwarp=off\n")

    def test_extracts_key_fields(self):
        fields = SpeedTest.parse_trace(self.SAMPLE)
        self.assertEqual(fields["ip"], "173.73.173.71")
        self.assertEqual(fields["colo"], "IAD")
        self.assertEqual(fields["loc"], "US")
        self.assertEqual(fields["warp"], "off")

    def test_empty_and_malformed(self):
        self.assertEqual(SpeedTest.parse_trace(""), {})
        self.assertEqual(SpeedTest.parse_trace(None), {})
        self.assertNotIn("garbage", SpeedTest.parse_trace("garbage-no-equals"))


class SummarizeLatencyTests(unittest.TestCase):
    def test_basic_stats(self):
        out = summarize_latency([10, 20, 30])
        self.assertEqual(out["samples"], 3)
        self.assertEqual(out["min_ms"], 10)
        self.assertAlmostEqual(out["avg_ms"], 20.0)
        # consecutive diffs are 10 and 10 -> jitter 10
        self.assertAlmostEqual(out["jitter_ms"], 10.0)

    def test_single_sample_has_zero_jitter(self):
        out = summarize_latency([42])
        self.assertEqual(out["min_ms"], 42)
        self.assertEqual(out["jitter_ms"], 0.0)

    def test_none_values_are_ignored(self):
        out = summarize_latency([None, 15, None, 25])
        self.assertEqual(out["samples"], 2)
        self.assertEqual(out["min_ms"], 15)

    def test_empty(self):
        out = summarize_latency([])
        self.assertEqual(out["samples"], 0)
        self.assertIsNone(out["min_ms"])
        self.assertIsNone(out["jitter_ms"])


class BufferbloatGradeTests(unittest.TestCase):
    def test_grade_boundaries(self):
        # increase = loaded - idle
        self.assertEqual(bufferbloat_grade(20, 22)["grade"], "A+")   # +2 ms
        self.assertEqual(bufferbloat_grade(20, 40)["grade"], "A")    # +20 ms
        self.assertEqual(bufferbloat_grade(20, 70)["grade"], "B")    # +50 ms
        self.assertEqual(bufferbloat_grade(20, 170)["grade"], "C")   # +150 ms
        self.assertEqual(bufferbloat_grade(20, 320)["grade"], "D")   # +300 ms
        self.assertEqual(bufferbloat_grade(20, 620)["grade"], "F")   # +600 ms

    def test_increase_is_reported_and_never_negative(self):
        out = bufferbloat_grade(50, 30)  # loaded faster than idle -> clamp to 0
        self.assertEqual(out["increase_ms"], 0.0)
        self.assertEqual(out["grade"], "A+")

    def test_missing_inputs(self):
        self.assertEqual(bufferbloat_grade(None, 40)["grade"], "—")
        self.assertEqual(bufferbloat_grade(20, None)["grade"], "—")


class SummarizeResultTests(unittest.TestCase):
    def test_flattens_full_result(self):
        result = {
            "started_at": "2026-07-17T10:00:00+00:00",
            "advanced": True,
            "download": {"mbps": 240.5, "peak_mbps": 300.0},
            "upload": {"mbps": 12.3},
            "idle_latency": {"min_ms": 8.0, "jitter_ms": 1.2},
            "server": {"isp": "Example ISP", "colo": "SEA"},
            "bufferbloat_download": {"grade": "A"},
            "bufferbloat_upload": {"grade": "B"},
        }
        row = summarize_result_for_history(result)
        self.assertEqual(row["download_mbps"], 240.5)
        self.assertEqual(row["upload_mbps"], 12.3)
        self.assertEqual(row["ping_ms"], 8.0)
        self.assertEqual(row["isp"], "Example ISP")
        self.assertEqual(row["grade_down"], "A")
        self.assertEqual(row["grade_up"], "B")
        self.assertTrue(row["advanced"])

    def test_tolerates_missing_sections(self):
        row = summarize_result_for_history({"started_at": "x"})
        self.assertIsNone(row["download_mbps"])
        self.assertIsNone(row["grade_down"])


class HistoryStoreTests(unittest.TestCase):
    def test_add_prepends_and_trims(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hist.json"
            store = SpeedTestHistory(path=path, max_entries=5)
            for i in range(8):
                store.add({"at": f"t{i}", "download_mbps": float(i)})
            entries = store.list()
            self.assertEqual(len(entries), 5)              # trimmed to max
            self.assertEqual(entries[0]["at"], "t7")       # newest first
            self.assertEqual(entries[-1]["at"], "t3")

    def test_survives_missing_and_corrupt_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hist.json"
            store = SpeedTestHistory(path=path)
            self.assertEqual(store.list(), [])             # missing file
            path.write_text("{ not json", encoding="utf-8")
            self.assertEqual(store.list(), [])             # corrupt file
            store.add({"at": "ok"})
            self.assertEqual(store.list()[0]["at"], "ok")  # recovers on write


class PercentileTests(unittest.TestCase):
    def test_percentiles_present_and_ordered(self):
        out = summarize_latency(list(range(1, 101)))  # 1..100
        self.assertAlmostEqual(out["p50_ms"], 50.5)
        self.assertGreater(out["p95_ms"], out["p50_ms"])
        self.assertGreater(out["p99_ms"], out["p95_ms"])

    def test_single_sample(self):
        out = summarize_latency([12])
        self.assertEqual(out["p95_ms"], 12)


class AggregateThroughputTests(unittest.TestCase):
    @staticmethod
    def _series(mbps, warmup=2.0, duration=8.0, step=0.1, gaps=()):
        """Build a (elapsed, cumulative_bytes) series growing at `mbps`, with
        optional flat 'gap' intervals (indices where no bytes arrive)."""
        bps = mbps * 1e6 / 8.0
        series = [(0.0, 0)]
        elapsed, total = 0.0, 0
        i = 0
        while elapsed < warmup + duration:
            elapsed += step
            if i not in gaps:
                total += int(bps * step)
            series.append((round(elapsed, 3), total))
            i += 1
        return series

    def test_steady_link_reports_true_rate(self):
        out = aggregate_throughput(self._series(200.0), warmup=2.0)
        self.assertAlmostEqual(out["mbps"], 200.0, delta=2.0)
        self.assertGreater(out["intervals"], 40)

    def test_request_gaps_do_not_drag_the_number_down(self):
        # a steady 300 Mbps link with a handful of boundary gaps; trimming the
        # slow tail should keep the reported figure near the true rate
        series = self._series(300.0, gaps={25, 40, 55, 70})
        out = aggregate_throughput(series, warmup=2.0)
        self.assertGreater(out["mbps"], 285.0)

    def test_warmup_is_excluded(self):
        # slow-start: first 2s at 10 Mbps, then 100 Mbps. Warmup must be dropped.
        slow = self._series(10.0, warmup=0.0, duration=2.0)
        fast = self._series(100.0, warmup=0.0, duration=8.0)
        base = slow[-1][1]
        merged = slow + [(2.0 + t, base + b) for t, b in fast[1:]]
        out = aggregate_throughput(merged, warmup=2.0)
        self.assertAlmostEqual(out["mbps"], 100.0, delta=3.0)

    def test_too_short_falls_back_to_total(self):
        out = aggregate_throughput([(0.0, 0), (1.0, 12_500_000)], warmup=2.0)
        self.assertAlmostEqual(out["mbps"], 100.0, delta=1.0)  # 12.5 MB in 1s

    def test_peak_window_smooths_single_interval_bursts(self):
        # steady 200 Mbps, with one 100 ms interval that bursts to ~1000 Mbps
        series = self._series(200.0)
        # inflate one steady interval's cumulative jump (index ~50)
        burst_at = 50
        extra = int(1000e6 / 8 * 0.1)  # ~1000 Mbps worth over 0.1s
        series = [(t, b + (extra if i >= burst_at else 0))
                  for i, (t, b) in enumerate(series)]
        out = aggregate_throughput(series, warmup=2.0)
        self.assertAlmostEqual(out["mbps"], 200.0, delta=6.0)   # burst trimmed out
        self.assertLess(out["peak_mbps"], 400.0)                # 1s window, not the spike
        self.assertGreaterEqual(out["peak_mbps"], out["mbps"] - 1)

    def test_empty(self):
        out = aggregate_throughput([], warmup=2.0)
        self.assertEqual(out["mbps"], 0.0)


class ResponsivenessTests(unittest.TestCase):
    def test_rpm(self):
        self.assertEqual(responsiveness_rpm(60), 1000)   # 60ms -> 1000 rpm
        self.assertEqual(responsiveness_rpm(20), 3000)

    def test_rpm_guards(self):
        self.assertIsNone(responsiveness_rpm(None))
        self.assertIsNone(responsiveness_rpm(0))


class UsageVerdictTests(unittest.TestCase):
    def test_fast_clean_link_is_good_across_the_board(self):
        verdicts = {v["activity"]: v["rating"]
                    for v in usage_verdicts(500, 500, 6, 8, "A")}
        self.assertEqual(verdicts["4K / UHD streaming"], "good")
        self.assertEqual(verdicts["Competitive online gaming"], "good")

    def test_bufferbloat_downgrades_calls_and_gaming(self):
        verdicts = {v["activity"]: v["rating"]
                    for v in usage_verdicts(500, 500, 8, 500, "F")}
        # plenty of bandwidth, but F-grade bufferbloat ruins realtime use
        self.assertIn(verdicts["Competitive online gaming"], ("bad",))
        self.assertIn(verdicts["Video calls (Zoom/Teams)"], ("ok", "bad"))

    def test_slow_link_fails_heavy_activities(self):
        verdicts = {v["activity"]: v["rating"]
                    for v in usage_verdicts(3, 1, 80, None, None)}
        self.assertEqual(verdicts["4K / UHD streaming"], "bad")


class LinkSpeedParseTests(unittest.TestCase):
    def test_units(self):
        self.assertEqual(parse_link_speed("1 Gbps"), 1000.0)
        self.assertAlmostEqual(parse_link_speed("866.7 Mbps"), 866.7)
        self.assertEqual(parse_link_speed("100 Mbps"), 100.0)

    def test_none_and_garbage(self):
        self.assertIsNone(parse_link_speed(""))
        self.assertIsNone(parse_link_speed("unknown"))


class NetshWifiParseTests(unittest.TestCase):
    SAMPLE = ("    Name                   : Wi-Fi\n"
              "    State                  : connected\n"
              "    SSID                   : MyNetwork\n"
              "    Radio type             : 802.11ax\n"
              "    Signal                 : 82%\n"
              "    Channel                : 36\n"
              "    Receive rate (Mbps)    : 866.7\n"
              "    Transmit rate (Mbps)   : 780\n")

    def test_extracts_wifi_fields(self):
        info = parse_netsh_wifi(self.SAMPLE)
        self.assertEqual(info["signal_pct"], 82)
        self.assertEqual(info["link_mbps"], 866.7)     # max of rx/tx
        self.assertEqual(info["radio"], "802.11ax")
        self.assertEqual(info["channel"], 36)
        self.assertEqual(info["band"], "5 GHz")

    def test_empty(self):
        self.assertEqual(parse_netsh_wifi(""), {})


class BottleneckVerdictTests(unittest.TestCase):
    def test_wifi_is_the_ceiling(self):
        conn = {"type": "wifi", "link_mbps": 300, "signal_pct": 80}
        sev, text = wifi_bottleneck_verdict(conn, 220)  # >= 50% of link
        self.assertEqual(sev, "warn")
        self.assertIn("Wi-Fi", text)

    def test_wifi_has_headroom_blames_isp(self):
        conn = {"type": "wifi", "link_mbps": 1200, "signal_pct": 90}
        sev, text = wifi_bottleneck_verdict(conn, 90)  # link >> measured*2.5
        self.assertEqual(sev, "info")
        self.assertIn("upstream", text)

    def test_weak_signal_flagged(self):
        conn = {"type": "wifi", "link_mbps": 400, "signal_pct": 30}
        sev, text = wifi_bottleneck_verdict(conn, 50)
        self.assertEqual(sev, "warn")
        self.assertIn("signal", text.lower())

    def test_ethernet_message(self):
        conn = {"type": "ethernet", "link_mbps": 1000}
        sev, text = wifi_bottleneck_verdict(conn, 300)
        self.assertEqual(sev, "info")
        self.assertIn("wired", text.lower())

    def test_no_data(self):
        self.assertIsNone(wifi_bottleneck_verdict({}, 0))


class ReportRenderTests(unittest.TestCase):
    def test_report_includes_key_values_and_plan(self):
        result = {
            "started_at": "2026-07-17T10:00:00+00:00",
            "download": {"mbps": 94.0}, "upload": {"mbps": 11.0},
            "idle_latency": {"min_ms": 9.0, "jitter_ms": 1.0},
            "server": {"ip": "203.0.113.7", "colo": "SEA"},
            "connection": {"type": "ethernet", "link_mbps": 1000},
        }
        html_text = render_speedtest_report_html(result, {"down": 500, "up": 50})
        self.assertIn("94.0 Mbps", html_text)
        self.assertIn("getting 19%", html_text)   # 94 / 500
        self.assertIn("Ethernet", html_text)
        self.assertIn("203.0.113.7", html_text)
        self.assertTrue(html_text.strip().startswith("<!doctype html>"))

    def test_escapes_html(self):
        result = {"server": {"ip": "<script>"}, "download": {"mbps": 1.0}}
        html_text = render_speedtest_report_html(result)
        self.assertNotIn("<script>", html_text)
        self.assertIn("&lt;script&gt;", html_text)


if __name__ == "__main__":
    unittest.main()
