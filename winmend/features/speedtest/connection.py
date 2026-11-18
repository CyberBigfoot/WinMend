"""WinMend features: speedtest: connection."""

from __future__ import annotations

from winmend.features.speedtest.metrics import BUFFERBLOAT_GRADES
import re
import socket
import subprocess
import time


# ---- connection (adapter / Wi-Fi) awareness -------------------------------
# The native-app advantage a browser speed test can never have: seeing whether
# the bottleneck is the Wi-Fi link, not the ISP.

def _run_command(command, timeout=8):
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        result = subprocess.run(command, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=timeout,
                                creationflags=flags)
        return result.returncode, (result.stdout or ""), (result.stderr or "")
    except Exception as exc:
        return -1, "", str(exc)


def parse_link_speed(text):
    """'1 Gbps' -> 1000.0, '866.7 Mbps' -> 866.7. Unit-based, so localized
    labels around it don't matter."""
    if not text:
        return None
    match = re.search(r"([\d.]+)\s*(G|M|K)?bps", text, re.IGNORECASE)
    if not match:
        return None
    value = float(match.group(1))
    unit = (match.group(2) or "M").upper()
    return value * {"G": 1000.0, "M": 1.0, "K": 0.001}[unit]


def parse_netsh_wifi(text):
    """Best-effort Wi-Fi details from `netsh wlan show interfaces`. Parses by
    units/patterns (Mbps, %, 802.11x) rather than localized field labels, so it
    survives non-English Windows; anything it can't find is simply omitted."""
    info = {}
    # netsh prints the unit in the label ("Receive rate (Mbps) : 866.7"), so
    # match "Mbps...: value"; also accept the value-then-unit form as a fallback.
    rates = [float(m) for m in re.findall(r"[Mm]bps[^\n:]*:\s*([\d.]+)", text)]
    rates += [float(m) for m in re.findall(r"([\d.]+)\s*Mbps", text)]
    if rates:
        info["link_mbps"] = max(rates)          # the negotiated PHY rate
    signal = re.search(r"(\d+)\s*%", text)
    if signal:
        info["signal_pct"] = int(signal.group(1))
    radio = re.search(r"802\.11[a-z]+", text, re.IGNORECASE)
    if radio:
        info["radio"] = radio.group(0)
    channel = re.search(r"(?im)^\s*\S*[Cc]hannel\S*\s*:\s*(\d+)\s*$", text)
    if channel:
        ch = int(channel.group(1))
        info["channel"] = ch
        info["band"] = ("2.4 GHz" if ch <= 14 else "6 GHz" if ch > 165 else "5 GHz")
    return info


def active_connection():
    """The interface carrying the default route, its type and negotiated link
    speed, plus Wi-Fi radio details when applicable. Uses adapter *property*
    values (802.3 / Native 802.11), not display text, so it is locale-proof."""
    script = (
        "$r=Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |"
        " Sort-Object RouteMetric,ifMetric | Select-Object -First 1;"
        "if($r){$a=Get-NetAdapter -InterfaceIndex $r.ifIndex -ErrorAction SilentlyContinue;"
        "if($a){Write-Output ('NAME|'+$a.Name);Write-Output ('MEDIA|'+$a.PhysicalMediaType);"
        "Write-Output ('LINK|'+$a.LinkSpeed)};Write-Output ('GW|'+$r.NextHop)}"
    )
    rc, out, _ = _run_command(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "RemoteSigned", "-Command", script],
        timeout=12)
    fields = {}
    for line in out.splitlines():
        key, sep, value = line.strip().partition("|")
        if sep:
            fields[key] = value.strip()
    media = fields.get("MEDIA", "")
    is_wifi = "802.11" in media or "wireless" in media.lower()
    conn = {
        "available": bool(fields),
        "name": fields.get("NAME"),
        "gateway": fields.get("GW") or None,
        "type": "wifi" if is_wifi else "ethernet" if fields.get("MEDIA") else "unknown",
        "link_mbps": parse_link_speed(fields.get("LINK", "")),
    }
    if is_wifi:
        wrc, wout, _ = _run_command(["netsh", "wlan", "show", "interfaces"], timeout=10)
        if wrc == 0:
            wifi = parse_netsh_wifi(wout)
            conn.update(wifi)
            if wifi.get("link_mbps"):  # the Wi-Fi PHY rate beats the generic adapter one
                conn["link_mbps"] = wifi["link_mbps"]
    return conn


def wifi_bottleneck_verdict(conn, measured_down_mbps):
    """Honest, hedged read on whether Wi-Fi or the ISP is the ceiling. Real
    Wi-Fi throughput tops out around half the PHY link rate, which is the basis
    for the thresholds here."""
    if not conn or not measured_down_mbps or measured_down_mbps <= 0:
        return None
    if conn.get("type") == "ethernet":
        link = conn.get("link_mbps")
        if link and measured_down_mbps >= link * 0.9:
            return ("info", f"You're near this wired adapter's {link:.0f} Mbps link — "
                            f"a faster network port would be needed to go higher.")
        return ("info", "You're on a wired connection, so Wi-Fi isn't limiting you. "
                        "Any shortfall from your plan is upstream (ISP or router).")
    if conn.get("type") != "wifi":
        return None
    signal = conn.get("signal_pct")
    link = conn.get("link_mbps")
    if signal is not None and signal < 45:
        return ("warn", f"Weak Wi-Fi signal ({signal}%) is likely capping your speed — "
                        f"move closer to the router or use Ethernet.")
    if link:
        if measured_down_mbps >= link * 0.5:
            return ("warn", f"You're near what this Wi-Fi link ({link:.0f} Mbps) can "
                            f"realistically deliver — Wi-Fi is the bottleneck, not your "
                            f"ISP. Ethernet or a newer standard/band would help.")
        if link >= measured_down_mbps * 2.5:
            return ("info", f"Your Wi-Fi link ({link:.0f} Mbps) has plenty of headroom "
                            f"over the measured {measured_down_mbps:.0f} Mbps — the limit "
                            f"is upstream (your ISP or plan), not Wi-Fi.")
    return ("info", "Connected over Wi-Fi. If this is far below your plan, try Ethernet "
                    "to rule out Wi-Fi before contacting your ISP.")


def _tcp_rtt(host, ports=(443, 80, 53), attempts=3, timeout=2.0):
    """Round-trip time to a host via TCP connect timing. A refused connection
    (RST) still proves reachability and yields a valid RTT, so routers with no
    open port are still measured."""
    if not host:
        return {"reachable": False, "rtt_ms": None}
    best = None
    reachable = False
    for _ in range(max(1, attempts)):
        for port in ports:
            start = time.perf_counter()
            try:
                with socket.create_connection((host, port), timeout=timeout):
                    pass
                elapsed = (time.perf_counter() - start) * 1000
            except ConnectionRefusedError:
                elapsed = (time.perf_counter() - start) * 1000  # RST = reachable
            except OSError:
                continue
            reachable = True
            best = elapsed if best is None else min(best, elapsed)
            break
    return {"reachable": reachable, "rtt_ms": best}


def multi_target_latency(gateway=None):
    """Latency to the router (first hop) and public anchors, so a slow result
    can be pinned to the local network, the ISP, or a single distant server."""
    targets = []
    if gateway:
        targets.append(("Router (first hop)", gateway))
    targets.extend([("Cloudflare (1.1.1.1)", "1.1.1.1"),
                    ("Google DNS (8.8.8.8)", "8.8.8.8")])
    out = []
    for label, host in targets:
        result = _tcp_rtt(host, ports=(443, 80, 53) if "Router" in label else (443, 80))
        out.append({"label": label, "host": host, **result})
    return out


def bufferbloat_grade(idle_ms, loaded_ms):
    """Grade the latency increase a saturated link adds. Bufferbloat is why a
    download can make video calls stutter even on a 'fast' connection."""
    if idle_ms is None or loaded_ms is None:
        return {"increase_ms": None, "grade": "—"}
    increase = max(0.0, float(loaded_ms) - float(idle_ms))
    grade = "F"
    for threshold, letter in BUFFERBLOAT_GRADES:
        if increase < threshold:
            grade = letter
            break
    return {"increase_ms": increase, "grade": grade}


def measure_dns(hosts=None, timeout=3.0):
    """Average resolution time for a handful of popular domains. Slow DNS makes
    the whole web feel sluggish even when raw throughput is fine."""
    hosts = hosts or ["www.google.com", "www.microsoft.com", "www.cloudflare.com",
                      "www.amazon.com", "en.wikipedia.org"]
    times = []
    failures = 0
    for host in hosts:
        start = time.perf_counter()
        try:
            socket.getaddrinfo(host, 443)
            times.append((time.perf_counter() - start) * 1000)
        except OSError:
            failures += 1
    return {
        "tested": len(hosts),
        "failures": failures,
        "avg_ms": (sum(times) / len(times)) if times else None,
    }


def ipv6_connectivity(host="speed.cloudflare.com", timeout=4.0):
    """Whether IPv6 actually works end-to-end, and its connect latency."""
    try:
        infos = socket.getaddrinfo(host, 443, socket.AF_INET6, socket.SOCK_STREAM)
    except OSError:
        return {"available": False, "reason": "no AAAA record / no IPv6 stack"}
    for _family, _type, _proto, _canon, sockaddr in infos:
        start = time.perf_counter()
        try:
            with socket.create_connection((sockaddr[0], sockaddr[1]), timeout=timeout):
                return {"available": True,
                        "latency_ms": (time.perf_counter() - start) * 1000,
                        "address": sockaddr[0]}
        except OSError:
            continue
    return {"available": False, "reason": "IPv6 address unreachable"}
