"""Interpret measurements without selecting repairs or inferring physical damage."""
from __future__ import annotations
from winmend.diagnostics.helpers import _evidence
import math

THRESHOLDS = {"cpu_pct": 85, "available_pct": 8, "commit_pct": 90,
              "pages_input_per_second": 20, "latency_ms": 50, "min_samples": 3}


def numbers(values):
    return [v for v in values if isinstance(v, (int, float)) and math.isfinite(v)]


def repeated(values, threshold, below=False):
    values = numbers(values)
    return len(values) >= 3 and sum((v <= threshold if below else v >= threshold)
                                   for v in values) / len(values) >= .75


def resource_findings(payload):
    if not payload.get("available"):
        return []
    samples = payload.get("samples") or []
    cpu = [s.get("cpu_pct") for s in samples]
    cpu = numbers(cpu)
    pressure = repeated(cpu, THRESHOLDS["cpu_pct"]) and not payload.get("update_active")
    avg = sum(cpu)/len(cpu) if cpu else None
    rows = [_evidence("resource_cpu", "Repeated processor utilization",
                      "bad" if pressure else "info" if payload.get("update_active") else "good" if len(cpu) >= 3 else "inconclusive",
                      f"{avg:.0f}% average over {len(cpu)} samples" if avg is not None else "Not measured",
                      "Update work is active; repeat after it finishes." if payload.get("update_active") else
                      "Repeated in a short window after other collectors finished. This cannot establish long-term persistence.",
                      data={"samples": cpu, "processes": payload.get("processes", []), "update_active": payload.get("update_active", False)})]
    available = numbers(s.get("available_pct") for s in samples)
    commits = numbers(s.get("commit_pct") for s in samples)
    paging = payload.get("paging", {})
    pages = paging.get("pages_input_per_second") if paging.get("available") else None
    low = repeated(available, THRESHOLDS["available_pct"], below=True)
    exhausted = repeated(commits, THRESHOLDS["commit_pct"])
    pressured = low and (exhausted or (pages is not None and pages >= THRESHOLDS["pages_input_per_second"]))
    coverage = len(available) >= 3 and len(commits) >= 3
    rows.append(_evidence("resource_memory", "Available and committed memory",
                "bad" if pressured else "inconclusive" if low or not coverage else "warn" if exhausted else "good",
                f"{min(v for v in available if v is not None):.1f}% minimum available" if any(v is not None for v in available) else "Not measured",
                "Pressure requires repeated low availability plus high commit or page-input activity. RAM utilization alone is insufficient.",
                data={"available_samples": available, "commit_samples": commits, "pages_input_per_second": pages,
                      "processes": payload.get("processes", [])}))
    by_device = {}
    for sample in samples:
        for disk in sample.get("disks", []):
            if disk.get("latency_ms") is not None:
                by_device.setdefault(disk["device"], []).append(disk["latency_ms"])
    slow = {d: values for d, values in by_device.items() if repeated(values, THRESHOLDS["latency_ms"])}
    adequate = any(len(values) >= 3 for values in by_device.values())
    rows.append(_evidence("resource_storage", "Repeated storage I/O latency",
                "bad" if slow else "good" if adequate else "inconclusive",
                "; ".join(f"{d}: {sum(v)/len(v):.1f} ms average" for d, v in by_device.items()) or "Insufficient I/O to measure latency",
                "Per-device counter deltas with at least 50 operations per sample. Contention can cause high latency without drive failure.",
                data={"devices": by_device, "slow": list(slow)}))
    for row in rows:
        row["repeatable"] = len(samples) >= 3
    return rows


def network_findings(payload):
    if not payload.get("available"):
        return []
    rows = []
    tcp = payload.get("tcp", [])
    success = sum(r.get("ok") is True for r in tcp)
    rows.append(_evidence("tcp_connectivity", "Direct public TCP connections",
                "good" if success >= 2 else "warn" if len(tcp) >= 4 and not success else "inconclusive",
                f"{success}/{len(tcp)} successful connections",
                "Two public destinations on TCP 443. Filtered probes do not prove all internet access is unavailable.",
                data={"results": tcp}))
    for field, key, label in (("dns", "resolver_queries", "Repeated Windows DNS queries"),
                              ("https", "https_connectivity", "Public HTTPS responses")):
        part = payload.get(field, {})
        samples = part.get("results", [])
        count = sum(s.get("ok") is True for s in samples)
        adequate = len(samples) >= (4 if field == "dns" else 2)
        status = "good" if adequate and count == len(samples) else "bad" if adequate and not count else "warn" if adequate and count else "inconclusive"
        if not part.get("available"):
            status = part.get("diagnostic_state", "inconclusive")
        rows.append(_evidence(key, label, status,
                    f"{count}/{len(samples)} successful" if part.get("available") else "Not measured",
                    ("Uses Windows' resolver policy for two public domains; private split-DNS domains remain untested."
                     if field == "dns" else "Uses Windows' web request path. This cannot verify the affected browser or a private site."),
                    data={"results": samples, "reason": part.get("reason")}))
        rows[-1]["repeatable"] = adequate
    rows[0]["repeatable"] = len(tcp) >= 4
    for family, field in (("IPv4", "tcp_ipv4"), ("IPv6", "tcp_ipv6")):
        attempts = [r for r in tcp if r.get("family") == family]
        capability = payload.get("address_families", {}).get(family.lower())
        successes = sum(r.get("ok") is True for r in attempts)
        state = ("not_applicable" if capability is False else "good" if successes >= 2 else
                 "warn" if len(attempts) >= 4 else "inconclusive")
        rows.append(_evidence(field, family + " public TCP path", state,
                    f"{successes}/{len(attempts)} successful" if attempts else "Not tested",
                    "Address-family-specific probes. Endpoint filtering remains a limitation.",
                    data={"results": attempts, "configured": capability}))
    return rows


def conservative_legacy(rows, raw):
    """Correct known misleading legacy interpretations before rules see them."""
    for row in rows:
        key, data = row["key"], row.get("data", {})
        if key in ("temp_size", "uptime", "startup", "proxy", "dns_config", "mtu", "link_health"):
            row["status"] = "info"
        if key == "proxy":
            row["detail"] = "Proxy and PAC configuration may be required by the network. Their presence alone does not establish interference; compare the web request path and policy."
        if key == "dns_config":
            row["detail"] = "Configured resolvers can be private, enterprise or ISP addresses. An unfamiliar address is not a fault; resolution and policy must be checked."
        if key == "thermal":
            row["detail"] = "Firmware reported processor performance restrictions. Heat, power limits and firmware policy remain alternatives; current temperature was not measured by this event check."
        if key == "memory_config":
            row["status"] = "info"
            row["detail"] += " Module count and nominal speed alone do not prove a performance fault or the actual channel topology."
        if key == "component_devices" and not any(d.get("code") in (1, 3, 10, 18, 19, 31, 39, 43, 52, 54) for d in data.get("problems", [])):
            row["status"] = "info"
        if key == "startup" and any(s.get("degradation_s", 0) >= 2 for s in (raw.get("boot_history", {}) or {}).get("slow", [])):
            row["status"] = "warn"
        if key == "memory":
            row["status"] = "info"
            row["detail"] = "RAM utilization snapshot. Confirm low available memory and commit or paging pressure over repeated samples."
        if key == "defender" and (not isinstance(data.get("enabled"), bool) or not isinstance(data.get("realtime"), bool)):
            row["status"] = "inconclusive"
        if key == "defender" and row["status"] == "bad" and data.get("running_mode") != "Normal":
            row["status"] = "inconclusive"
            row["detail"] = "Defender's primary active protection mode was not established. Another protection provider or policy may explain this state."
        if key == "defender" and str(data.get("running_mode") or "").lower() in ("passive mode", "sxs passive mode", "edr block mode"):
            row["status"] = "info"
            row["detail"] = "Defender reports a passive or managed protection mode. This is not evidence of a disabled primary antivirus."
        if key == "disk_latency":
            row["status"] = "info" if data.get("avg_ms") is not None else "inconclusive"
        if key == "smart" and not data.get("disks") and not data.get("unhealthy"):
            row.update(status="inconclusive", value="No drive health data returned")
        if key == "drive_wear" and not data.get("counters_readable"):
            if row["status"] != "bad":
                row["status"] = "inconclusive"
        if key == "wifi_link" and data.get("signal_pct") is None:
            row["status"] = "inconclusive"
        if key == "winsock" and not data.get("total"):
            row["status"] = "inconclusive"
            row["detail"] = "No catalog entries could be interpreted. Unsupported or localized output cannot prove a healthy stack."
        if key == "mtu" and not data.get("interfaces"):
            row["status"] = "inconclusive"
        if key == "threats" and not data.get("unresolved"):
            row["status"] = "info"
        if key == "system_files":
            row["historical"] = True
            if not data.get("ever_run"):
                row["status"] = "not_tested"
            elif not data.get("corrupt"):
                row["status"] = "info"
        if key == "filesystem":
            if not data.get("dirty"):
                if data.get("scheduled"):
                    row["status"] = "info"
                    row["detail"] = "A scheduled check alone does not prove file-system damage."
                elif not raw.get("volumes", {}).get("available") or not raw.get("volumes", {}).get("volumes") or any(v.get("dirty") is None for v in raw.get("volumes", {}).get("volumes", [])):
                    row["status"] = "inconclusive"
                    row["detail"] = "No scheduled check was found, but the per-volume dirty flags could not all be verified."
        if key == "firewall" and "profiles" in data and (not data.get("profiles") or any(p.get("enabled") is None for p in data.get("profiles", []))):
            row["status"] = "inconclusive"
        if key == "windows_version" and data.get("supported") is False:
            row["status"] = "inconclusive"
            row["detail"] = "This release is past the recorded standard servicing window. ESU and edition entitlements were not verified, so this device's update eligibility is unknown."
        if key == "drive_wear" and row["status"] == "bad":
            disks = data.get("disks", [])
            if not any((d.get("read_errors") or d.get("write_errors")) or str(d.get("health", "Healthy")).lower() not in ("healthy", "") for d in disks):
                row["status"] = "warn"
                row["detail"] = "Reported endurance consumption is a maintenance concern, not proof that the drive is failing. Monitor trend and maintain a backup."
        if key == "evt_shutdowns":
            row["detail"] = "Kernel-Power 41 records an unclean shutdown. It does not identify the cause or prove a faulty power supply."
        if key == "evt_hardware":
            detailed = raw.get("whea_errors", {})
            if not detailed.get("uncorrected") and detailed.get("corrected", 0) < 5:
                row["status"] = "info"
        if key == "bluetooth" and not data.get("faulty"):
            row["status"] = "info"
        if key == "audio":
            row["detail"] += " This check covers services and PnP status; default playback routing and audible output were not tested."
        if key == "bluetooth":
            row["detail"] += " Radio and service status do not verify a particular headset's link or audio quality."
        if key == "cpu_clock" and not data.get("load_pct", 0) >= 70:
            row["status"] = "info"
        if key == "dns" and (raw.get("network") or {}).get("dns") is None:
            row["status"] = "inconclusive"
        if key == "dns_resolution" and data.get("slow") and not data.get("hijacked") and not data.get("failed"):
            row["status"] = "info"
            row["detail"] = "Query latency was measured in one short pass. Cache warm-up, resolver load and routing remain alternatives; this alone does not establish persistent DNS slowness."
        if key == "adapters" and (raw.get("network") or {}).get("adapters") is None:
            row["status"] = "inconclusive"
        if key == "ip_config" and not data.get("interfaces"):
            row.update(status="inconclusive", value="No usable IP interface returned")
        if key == "ip_config" and row["status"] == "bad" and sum(r.get("ok") is True for r in raw.get("layered_network", {}).get("tcp", [])) >= 2:
            row["status"] = "inconclusive"
            row["detail"] = "Direct TCP connections succeeded despite this configuration flag. VPN, policy routing or incomplete interface coverage needs review before blaming routing."
        if key == "drive_wear" and any((d.get("read_errors") or d.get("write_errors")) for d in data.get("disks", [])):
            row["detail"] += " Error counters may cover the drive's lifetime; a rising count or matching recent events is needed to establish ongoing errors."
        if key == "reachability" and (raw.get("network") or {}).get("reachable") is False:
            row["status"] = "inconclusive"
            row["detail"] = "One public TCP probe failed. Filtering or a remote endpoint may explain it; this is not proof of an internet outage."
        if key == "net_quality":
            row["status"] = "info"
            row["detail"] = "TCP timings to one fixed IPv4 endpoint. Failed attempts can reflect filtering, address-family limits or that endpoint; they do not measure overall connection loss."
    return rows
