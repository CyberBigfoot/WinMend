"""WinMend features: speedtest: runner."""

from __future__ import annotations

from winmend.core.findings import utc_now
from winmend.core.paths import application_root
from winmend.features.speedtest.connection import (
    active_connection,
    bufferbloat_grade,
    ipv6_connectivity,
    measure_dns,
    multi_target_latency,
)
from winmend.features.speedtest.metrics import (
    aggregate_throughput,
    responsiveness_rpm,
    summarize_latency,
)

import os
import sys
import tempfile
import threading
import time


class _ByteCounter:
    """Thread-safe running total of bytes moved by the worker threads."""

    def __init__(self):
        self._n = 0
        self._lock = threading.Lock()

    def add(self, n):
        with self._lock:
            self._n += n

    def value(self):
        with self._lock:
            return self._n


_CA_BUNDLE_CACHE = None


_CA_BUNDLE_RESOLVED = False


def resolve_ca_bundle():
    """Return a path to a valid CA bundle for TLS verification, or None.

    requests defaults its ``verify`` to ``certifi.where()``. In a frozen build
    (PyInstaller) that path often points at a file that was never extracted, and
    a stale ``REQUESTS_CA_BUNDLE`` env var can point at a deleted file too. Either
    way requests raises ``Could not find a suitable TLS CA certificate bundle,
    invalid path`` before a single byte is sent -- which is exactly the Speed Test
    failure users hit. We resolve a bundle that actually exists on disk here and
    hand it to requests explicitly, so verification never depends on requests'
    fragile default resolution.

    The result is cached: resolution touches the filesystem and, in the frozen
    fallback, writes a temp file, neither of which should repeat per request.
    """
    global _CA_BUNDLE_CACHE, _CA_BUNDLE_RESOLVED
    if _CA_BUNDLE_RESOLVED:
        return _CA_BUNDLE_CACHE

    candidates = []
    # 1. Explicit environment overrides -- but only trusted when they exist. A
    #    stale REQUESTS_CA_BUNDLE pointing at a deleted path is itself a cause of
    #    the error, so we ignore it rather than pass it straight through.
    for var in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSL_CERT_FILE"):
        val = os.environ.get(var)
        if val:
            candidates.append(val)

    # 2. certifi's bundled cacert.pem (the normal source of truth).
    certifi = None
    try:
        import certifi  # type: ignore
        candidates.append(certifi.where())
    except Exception:
        certifi = None

    # 3. A cacert.pem shipped alongside a frozen build / this module.
    base = str(application_root())
    candidates.append(os.path.join(base, "cacert.pem"))
    candidates.append(os.path.join(base, "certifi", "cacert.pem"))

    bundle = None
    for path in candidates:
        try:
            if path and os.path.isfile(path):
                bundle = path
                break
        except Exception:
            continue

    # Last resort: certifi is importable but its file was never unpacked to disk
    # (common with onefile builds). Materialise the bundled PEM into a temp file
    # so verification can still happen.
    if bundle is None:
        try:
            if certifi is not None:
                pem = certifi.contents()
                tmp = os.path.join(tempfile.gettempdir(), "winmend_cacert.pem")
                with open(tmp, "w", encoding="ascii") as handle:
                    handle.write(pem)
                if os.path.isfile(tmp):
                    bundle = tmp
        except Exception:
            pass

    # Repair broken CA-bundle env vars. requests lets REQUESTS_CA_BUNDLE /
    # CURL_CA_BUNDLE override an explicit session.verify, so a stale one pointing
    # at a deleted file re-triggers the exact 'invalid path' error even after we
    # set session.verify. A path that doesn't exist is broken for every HTTPS
    # call in this process, so pointing it at our known-good bundle is a repair,
    # never a downgrade. Only touch ones that are actually missing.
    if bundle is not None:
        for var in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
            val = os.environ.get(var)
            try:
                if val and not os.path.isfile(val):
                    os.environ[var] = bundle
            except Exception:
                pass

    _CA_BUNDLE_CACHE = bundle
    _CA_BUNDLE_RESOLVED = True
    return bundle


class SpeedTest:
    DOWN_URL = "https://speed.cloudflare.com/__down"
    UP_URL = "https://speed.cloudflare.com/__up"
    # cdn-cgi/trace is the endpoint that answers non-browser clients (the JSON
    # /meta endpoint 403s them). It returns key=value lines: ip, colo (the
    # Cloudflare datacenter), loc (country), http. It carries no ISP/ASN name,
    # so that field is simply omitted rather than pulling in a second service.
    TRACE_URL = "https://speed.cloudflare.com/cdn-cgi/trace"

    def __init__(self, progress=None, cancel=None, streams=6):
        # progress(event: dict) receives live phase/throughput updates;
        # cancel() -> bool is polled so the UI's Cancel button can stop the run.
        self._progress = progress or (lambda _event: None)
        self._cancel = cancel or (lambda: False)
        self.streams = max(1, int(streams))

    # ---- plumbing ----

    def _emit(self, **event):
        try:
            self._progress(event)
        except Exception:
            pass

    def _stop(self):
        try:
            return bool(self._cancel())
        except Exception:
            return False

    @staticmethod
    def _requests():
        import requests  # imported lazily so the module loads without it
        return requests

    def _session(self):
        """A requests.Session with TLS verification wired to a CA bundle that
        actually exists, so the test never dies on 'Could not find a suitable
        TLS CA certificate bundle, invalid path'.

        Passing an explicit ``verify`` path (rather than leaving it True) also
        stops requests from silently substituting a stale REQUESTS_CA_BUNDLE
        env var, since that override only applies when verify is True/None."""
        requests = self._requests()
        session = requests.Session()
        bundle = resolve_ca_bundle()
        if bundle:
            session.verify = bundle
        else:
            # No usable bundle anywhere -- verifying is impossible on this
            # machine. Rather than fail the whole test, fall back to an
            # unverified transfer: these endpoints carry only throughput filler
            # to Cloudflare, never user data. Silence urllib3's warning so the
            # activity log isn't spammed on every request.
            session.verify = False
            try:
                requests.packages.urllib3.disable_warnings()
            except Exception:
                pass
        return session

    # ---- individual measurements ----

    @staticmethod
    def parse_trace(text):
        fields = {}
        for line in (text or "").splitlines():
            key, sep, value = line.partition("=")
            if sep:
                fields[key.strip()] = value.strip()
        return fields

    def server_info(self, timeout=8):
        try:
            session = self._session()
            try:
                fields = self.parse_trace(session.get(self.TRACE_URL, timeout=timeout).text)
            finally:
                session.close()
            return {
                "available": bool(fields.get("ip") or fields.get("colo")),
                "ip": fields.get("ip"),
                "colo": fields.get("colo"),
                "country": fields.get("loc"),
                "http": fields.get("http"),
                "warp": fields.get("warp"),
            }
        except Exception as exc:
            return {"available": False, "error": str(exc)}

    def measure_latency(self, count=20, timeout=5):
        """Idle round-trip time via tiny (0-byte) downloads on a kept-alive
        connection, so the numbers reflect the network, not TLS setup."""
        requests = self._requests()
        session = self._session()
        samples = []
        try:
            for index in range(count):
                if self._stop():
                    break
                start = time.perf_counter()
                try:
                    resp = session.get(self.DOWN_URL, params={"bytes": 0}, timeout=timeout)
                    _ = resp.content
                    if resp.status_code < 400:
                        rtt = (time.perf_counter() - start) * 1000
                        samples.append(rtt)
                        # skip the first sample from the live read-out: it still
                        # carries connection setup
                        if index > 0:
                            self._emit(type="latency", ms=rtt, loaded=False, phase="idle")
                except requests.RequestException:
                    continue
                time.sleep(0.02)
        finally:
            session.close()
        # the first sample includes handshake; drop it if we have enough
        useful = samples[1:] if len(samples) > 3 else samples
        return summarize_latency(useful)

    # Cloudflare's __down rejects requests over ~100 MB (10^8 bytes) with 403, so
    # 90 MB is the largest safe chunk. Bigger chunks (was 25 MB) mean each request
    # lasts longer, so the gaps between them -- when no bytes flow -- are rarer;
    # with more parallel streams this keeps the link saturated and the number honest.
    def _download_worker(self, counter, stop_flag, chunk_bytes=90000000, timeout=25):
        requests = self._requests()
        session = self._session()
        try:
            while not stop_flag.is_set() and not self._stop():
                try:
                    with session.get(self.DOWN_URL, params={"bytes": chunk_bytes},
                                     stream=True, timeout=timeout) as resp:
                        if resp.status_code >= 400:
                            time.sleep(1.0)   # back off (e.g. 429) -- fast retries would
                            continue          # only sustain a rate limit
                        for block in resp.iter_content(262144):
                            counter.add(len(block))
                            if stop_flag.is_set() or self._stop():
                                break
                except requests.RequestException:
                    time.sleep(0.1)
        finally:
            session.close()

    def _upload_worker(self, counter, stop_flag, chunk_bytes=52428800, timeout=25):
        requests = self._requests()
        filler = b"0" * 131072

        def body():
            sent = 0
            while sent < chunk_bytes:
                if stop_flag.is_set() or self._stop():
                    return
                block = filler if (chunk_bytes - sent) >= len(filler) else filler[:chunk_bytes - sent]
                sent += len(block)
                counter.add(len(block))
                yield block

        session = self._session()
        try:
            while not stop_flag.is_set() and not self._stop():
                try:
                    resp = session.post(self.UP_URL, data=body(),
                                        headers={"Content-Type": "application/octet-stream"},
                                        timeout=timeout)
                    if resp.status_code >= 400:
                        time.sleep(1.0)   # back off instead of hammering
                except requests.RequestException:
                    time.sleep(0.1)
        finally:
            session.close()

    def _sample_throughput(self, counter, duration, warmup, phase):
        """Sample the shared byte counter, emit a *smoothed* live figure for the
        gauge, and return an accurate steady-state throughput.

        Two separate streams on purpose: the live number is an exponential
        moving average so the gauge glides instead of flickering, while the
        returned figure comes from aggregate_throughput() over fine-grained
        samples -- so smoothing the display never distorts the result."""
        start = time.perf_counter()
        series = [(0.0, 0)]                 # (elapsed, cumulative bytes) for the result
        last_emit_t, last_emit_bytes = start, 0
        ema = None
        while True:
            if self._stop():
                break
            now = time.perf_counter()
            elapsed = now - start
            total = counter.value()
            # measurement sample every ~100 ms
            if elapsed - series[-1][0] >= 0.1:
                series.append((elapsed, total))
            # smoothed live read-out every ~150 ms
            dt = now - last_emit_t
            if dt >= 0.15:
                inst = (total - last_emit_bytes) * 8 / dt / 1e6
                ema = inst if ema is None else (0.35 * inst + 0.65 * ema)
                self._emit(type="throughput", phase=phase, mbps=max(0.0, ema),
                           elapsed=elapsed)
                last_emit_t, last_emit_bytes = now, total
            if elapsed >= warmup + duration:
                break
            time.sleep(0.03)
        series.append((time.perf_counter() - start, counter.value()))
        result = aggregate_throughput(series, warmup)
        result["bytes"] = counter.value()
        # Almost no data moved -> the transfer failed (server busy / rate-limited /
        # offline), not a genuinely 0 Mbps link. Flag it so the UI can say so
        # honestly instead of reporting a bogus 0.0.
        result["ok"] = result["bytes"] > 3_000_000
        # settle the gauge exactly on the accurate final figure
        self._emit(type="throughput", phase=phase, mbps=result["mbps"],
                   elapsed=warmup + duration, final=True)
        return result

    def _run_saturation(self, worker, duration, warmup, phase, collect_latency):
        """Saturate the link with `self.streams` workers while sampling
        throughput, optionally pinging in parallel to measure latency-under-load
        (the basis of the bufferbloat grade)."""
        counter = _ByteCounter()
        stop_flag = threading.Event()
        workers = [threading.Thread(target=worker, args=(counter, stop_flag), daemon=True)
                   for _ in range(self.streams)]
        for thread in workers:
            thread.start()

        loaded_latency = []
        pinger = None
        if collect_latency:
            def ping_under_load():
                requests = self._requests()
                session = self._session()
                time.sleep(warmup)  # only sample once the pipe is actually full
                try:
                    while not stop_flag.is_set() and not self._stop():
                        start = time.perf_counter()
                        try:
                            resp = session.get(self.DOWN_URL, params={"bytes": 0}, timeout=5)
                            _ = resp.content
                            if resp.status_code < 400:
                                rtt = (time.perf_counter() - start) * 1000
                                loaded_latency.append(rtt)
                                self._emit(type="latency", ms=rtt, loaded=True, phase=phase)
                        except requests.RequestException:
                            pass
                        time.sleep(0.1)
                finally:
                    session.close()
            pinger = threading.Thread(target=ping_under_load, daemon=True)
            pinger.start()

        throughput = self._sample_throughput(counter, duration, warmup, phase)
        stop_flag.set()
        for thread in workers:
            thread.join(timeout=3)
        if pinger:
            pinger.join(timeout=3)
        throughput["loaded_latency"] = summarize_latency(loaded_latency)
        return throughput

    # ---- orchestration ----

    def _finalize(self, result, cancelled):
        result["completed_at"] = utc_now()
        result["status"] = "cancelled" if cancelled else "complete"
        self._emit(type="done", result=result)
        return result

    def run(self, advanced=False):
        result = {"started_at": utc_now(), "advanced": bool(advanced)}
        try:
            self._requests()
        except Exception:
            result["status"] = "error"
            result["error"] = ("The 'requests' library isn't available, so the speed "
                               "test can't run.")
            self._emit(type="error", error=result["error"])
            return result

        self._emit(type="phase", phase="server", label="Finding your nearest server…")
        result["server"] = self.server_info()
        # Which adapter/Wi-Fi link is carrying this test -- cheap, and the basis
        # of the 'is it Wi-Fi or the ISP?' verdict. Best-effort; never fatal.
        try:
            result["connection"] = active_connection()
        except Exception:
            result["connection"] = {"available": False}
        if self._stop():
            return self._finalize(result, cancelled=True)

        self._emit(type="phase", phase="idle_latency", label="Measuring latency…")
        result["idle_latency"] = self.measure_latency(count=20)
        if self._stop():
            return self._finalize(result, cancelled=True)

        self._emit(type="phase", phase="download", label="Testing download speed…")
        result["download"] = self._run_saturation(
            self._download_worker, duration=(12 if advanced else 10), warmup=2.5,
            phase="download", collect_latency=advanced)
        if self._stop():
            return self._finalize(result, cancelled=True)

        self._emit(type="phase", phase="upload", label="Testing upload speed…")
        result["upload"] = self._run_saturation(
            self._upload_worker, duration=(10 if advanced else 8), warmup=2.5,
            phase="upload", collect_latency=advanced)

        if advanced and not self._stop():
            idle = (result["idle_latency"] or {}).get("avg_ms")
            down_loaded = result["download"]["loaded_latency"]
            up_loaded = result["upload"]["loaded_latency"]
            result["bufferbloat_download"] = bufferbloat_grade(idle, down_loaded.get("avg_ms"))
            result["bufferbloat_upload"] = bufferbloat_grade(idle, up_loaded.get("avg_ms"))
            # Responsiveness (RPM) from the worse of the two loaded directions.
            worst_loaded = max((v for v in (down_loaded.get("avg_ms"),
                                            up_loaded.get("avg_ms")) if v), default=None)
            result["rpm"] = responsiveness_rpm(worst_loaded)
            self._emit(type="phase", phase="quality", label="Checking DNS, IPv6 and routing…")
            result["dns"] = measure_dns()
            result["ipv6"] = ipv6_connectivity()
            gateway = (result.get("connection") or {}).get("gateway")
            result["multi_latency"] = multi_target_latency(gateway)

        return self._finalize(result, cancelled=self._stop())
