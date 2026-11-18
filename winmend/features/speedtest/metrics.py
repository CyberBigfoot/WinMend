"""WinMend features: speedtest: metrics."""

from __future__ import annotations

import math


# ---------------------------------------------------------------------------
# Internet speed test
#
# Measures throughput, latency and connection quality against Cloudflare's
# public speed-test endpoints (speed.cloudflare.com). No account or key, and no
# bundled binary -- it uses `requests`, already a WinMend dependency.
#
# Nothing about the PC is transmitted: uploaded bytes are filler the server
# discards, downloaded bytes are discarded locally, and the only identifying
# value involved is the public IP the endpoint reports back, which is shown to
# the user, not sent anywhere.
#
# A speed test is duration-bounded by design; the per-request socket timeouts
# exist only so one dead connection can't stall the whole run, and a cancel
# callback stops it early. This is not the "timeout kills a finished scan" bug
# the maintenance tasks were freed from -- the test genuinely runs for a fixed
# number of seconds and then reports.
# ---------------------------------------------------------------------------

# Added latency under load, in ms, mapped to a grade. Thresholds follow the
# widely-used Waveform/DSLReports bufferbloat scale.
BUFFERBLOAT_GRADES = ((5, "A+"), (30, "A"), (60, "B"), (200, "C"), (400, "D"))


def _percentile(sorted_values, pct):
    """Linear-interpolated percentile of an already-sorted list."""
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (len(sorted_values) - 1) * (pct / 100.0)
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return sorted_values[int(rank)]
    return sorted_values[low] + (sorted_values[high] - sorted_values[low]) * (rank - low)


def summarize_latency(samples):
    """min / average / jitter / percentiles for round-trip times in ms.

    Jitter is the mean absolute difference between consecutive samples
    (the RFC 3550 interarrival-jitter idea), which reflects how *steady* the
    latency is rather than merely its spread. p95/p99 expose the tail that a
    single average hides -- the tail is what actually causes a call to glitch."""
    clean = [float(s) for s in samples if s is not None]
    if not clean:
        return {"samples": 0, "min_ms": None, "avg_ms": None, "jitter_ms": None,
                "p50_ms": None, "p95_ms": None, "p99_ms": None}
    diffs = [abs(clean[i] - clean[i - 1]) for i in range(1, len(clean))]
    ordered = sorted(clean)
    return {
        "samples": len(clean),
        "min_ms": min(clean),
        "avg_ms": sum(clean) / len(clean),
        "jitter_ms": (sum(diffs) / len(diffs)) if diffs else 0.0,
        "p50_ms": _percentile(ordered, 50),
        "p95_ms": _percentile(ordered, 95),
        "p99_ms": _percentile(ordered, 99),
    }


def responsiveness_rpm(loaded_latency_ms):
    """Apple's Responsiveness metric: round-trips per minute under load.
    Higher is better; > 1000 is excellent, < 300 is poor."""
    if not loaded_latency_ms or loaded_latency_ms <= 0:
        return None
    return int(round(60000.0 / loaded_latency_ms))


def aggregate_throughput(series, warmup, trim_low=0.15, trim_high=0.05, peak_window=1.0):
    """Turn a series of (elapsed_seconds, cumulative_bytes) samples into a
    steady-state throughput in Mbps.

    Method (close to how Ookla/Cloudflare report a stable figure): take the
    per-interval rate of every ~100 ms sample after the warmup, drop the slowest
    `trim_low` and fastest `trim_high` fraction, and average the rest. Trimming
    the slow tail removes our own request-boundary gaps (which otherwise drag the
    average *below* the real link speed); trimming the fast tail removes a burst
    from buffered data. `peak_mbps` is the best throughput over any
    `peak_window`-second span -- a meaningful 'best sustained' figure, not a
    single-interval TCP burst."""
    rates = []
    for i in range(1, len(series)):
        t0, b0 = series[i - 1]
        t1, b1 = series[i]
        dt = t1 - t0
        if dt <= 0 or t0 < warmup:
            continue
        rates.append((b1 - b0) * 8 / dt / 1e6)
    if not rates:
        # too short to have steady samples: fall back to total bytes / total time
        if len(series) >= 2 and series[-1][0] > 0:
            return {"mbps": series[-1][1] * 8 / series[-1][0] / 1e6,
                    "peak_mbps": series[-1][1] * 8 / series[-1][0] / 1e6, "intervals": 0}
        return {"mbps": 0.0, "peak_mbps": 0.0, "intervals": 0}
    ordered = sorted(rates)
    lo = int(len(ordered) * trim_low)
    hi = len(ordered) - int(len(ordered) * trim_high)
    core = ordered[lo:hi] if hi > lo else ordered
    mbps = sum(core) / len(core)
    # peak over any peak_window-second span (rolling), which averages out the
    # 100 ms bursts a single-interval max would over-report.
    steady = [(t, b) for t, b in series if t >= warmup]
    peak = 0.0
    j = 0
    for i in range(len(steady)):
        if j < i:
            j = i
        while j < len(steady) and steady[j][0] - steady[i][0] < peak_window:
            j += 1
        if j < len(steady):
            dt = steady[j][0] - steady[i][0]
            if dt > 0:
                peak = max(peak, (steady[j][1] - steady[i][1]) * 8 / dt / 1e6)
    return {"mbps": mbps, "peak_mbps": peak or max(rates), "intervals": len(rates)}
