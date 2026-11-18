"""A shared evidence differential; legacy rules propose, this layer evaluates.

Scores are ordinal, inspectable weights, never calibrated probabilities. One
provider/failure family contributes once even if it produced many finding rows.
"""
from __future__ import annotations
from winmend.diagnostics.models import Hypothesis, repair_action, task_action
from winmend.diagnostics.observations import UNKNOWN, age_seconds

AREAS = {
    "network": {"adapters", "dns", "dns_config", "dns_resolution", "reachability", "net_quality", "proxy", "hosts", "ip_config", "link_health", "wifi_link", "connection_profile", "winsock", "mtu", "tcp_connectivity", "resolver_queries", "https_connectivity"},
    "performance": {"resource_cpu", "resource_memory", "resource_storage", "memory", "disk_latency", "disk_activity", "top_memory", "startup", "boot_time", "thermal", "cpu_clock", "power_plan", "pagefile", "disk_free", "smart", "drive_wear", "evt_disk", "storage_faults", "pending_reboot"},
    "storage": {"disk_free", "volumes", "smart", "drive_wear", "filesystem", "evt_disk", "storage_faults", "storage_events", "smart_detail", "disk_surface", "disk_optimization"},
    "crashes": {"evt_shutdowns", "bugchecks", "app_crashes", "gpu_resets", "crash_dumps", "hardware_errors", "evt_hardware", "storage_events", "live_kernel", "crash_reports", "memory_test", "memory_pattern", "power_loss", "evt_disk", "storage_faults", "smart", "drive_wear"},
    "updates": {"update_failures", "update_state", "update_policy", "update_cache", "component_store", "pending_reboot", "system_files", "hosts", "resolver_queries", "tcp_connectivity", "https_connectivity"},
    "security": {"defender", "threats", "firewall", "uac", "defender_exclusions", "platform", "hosts"},
    "audio": {"audio", "problem_devices"}, "bluetooth": {"bluetooth", "problem_devices"},
    "devices": {"problem_devices", "display", "component_devices", "monitors", "gpu_resets"},
    "printer": {"printers"}, "shell": {"shell", "search_index", "path", "policies", "known_folders"},
    "apps": {"app_crashes", "store_apps"}, "browser": {"app_crashes", "https_connectivity", "resolver_queries"},
    "battery": {"battery_wear", "power_loss"}, "time": {"time_sync"},
}
FAULT_FAMILIES = {
    "smart": "storage_health", "drive_wear": "storage_health", "smart_detail": "storage_health",
    "evt_disk": "storage_events", "storage_events": "storage_events", "storage_faults": "storage_events",
    "evt_hardware": "hardware_events", "hardware_errors": "hardware_events",
    "evt_shutdowns": "shutdown_events", "power_loss": "shutdown_events",
    "cpu_load": "cpu_samples", "resource_cpu": "cpu_samples",
    "memory": "memory_samples", "resource_memory": "memory_samples", "top_memory": "memory_samples",
    "dns": "dns_queries", "dns_resolution": "dns_queries", "resolver_queries": "dns_queries",
    "reachability": "tcp_probes", "tcp_connectivity": "tcp_probes",
    "disk_latency": "disk_samples", "resource_storage": "disk_samples",
}
# Healthy measurements contradict these particular faults. Ancillary healthy
# keys (SMART for a latency bottleneck) must not falsely disprove another fault.
PRIMARY = {
    "dns_dead": ("resolver_queries", "dns_resolution"),
    "no_route": ("ip_config",), "cpu_hog": ("resource_cpu",),
    "memory_pressure": ("resource_memory",), "storage_bottleneck": ("resource_storage",),
    "disk_full": ("disk_free",), "rogue_proxy": ("https_connectivity",),
    "problem_devices": ("problem_devices",), "update_error": ("update_failures",),
    "component_corruption": ("component_store",),
    "app_crash_module": ("app_crashes",), "problem_devices": ("problem_devices",),
}
DEFERRED = {"recent_update", "recent_driver", "recent_program", "stability_drop", "rogue_dns", "odd_mtu",
            "single_channel_memory", "firmware_stale", "safe_mode_clean", "reboot_relief"}


def direct_candidates(ctx):
    rows = []
    if ctx.status("adapters") == "bad":
        rows.append(Hypothesis("no_link", "No active network link was observed",
            "No non-loopback adapter was active during the link check. This does not establish a driver fault.",
            evidence_keys=("adapters",), actions=[task_action("pc_report")],
            advice="Check the cable, wireless association or airplane mode before changing Windows networking."))
    if ctx.status("resolver_queries") == "bad" and ctx.status("tcp_connectivity") == "good":
        rows.append(Hypothesis("dns_dead", "DNS resolution is the leading suspected cause",
            "Queries for two public names repeatedly failed while direct TCP connections succeeded. This isolates name resolution from basic connectivity.",
            evidence_keys=("resolver_queries", "tcp_connectivity", "ip_config"), severity="high",
            actions=[repair_action("flush_dns_cache", reason="Clear cached answers, then repeat resolver and HTTPS checks.")],
            advice="Inspect the configured resolvers and VPN split-DNS policy. Public tests do not verify private domains."))
    if ctx.status("resource_cpu") == "bad":
        data = ctx.evidence["resource_cpu"]["data"]
        hogs = [p for p in data.get("processes", []) if len(p.get("cpu_samples", [])) >= 3
                and sum(v >= 50 for v in p["cpu_samples"])/len(p["cpu_samples"]) >= .75]
        hog = hogs[0] if hogs else None
        rows.append(Hypothesis("cpu_hog", (f"{hog['name']} repeatedly consumed most of the processor" if hog else "Repeated CPU saturation"),
            "CPU saturation persisted across the short sampling window. This supports a load bottleneck; it does not prove the process is malfunctioning.",
            evidence_keys=("resource_cpu",),
            actions=[task_action("pc_report", "Review the process workload before closing anything.")],
            advice="Repeat while the slowdown is present; save work before closing a program."))
    if ctx.status("resource_memory") == "bad":
        rows.append(Hypothesis("memory_pressure", "Memory pressure is limiting available resources",
            "Repeated low available memory is corroborated by high commit or page-input activity. Cached RAM usage alone did not trigger this assessment.",
            evidence_keys=("resource_memory",), actions=[task_action("pc_report")],
            advice="Review the measured processes and workload before closing applications. This is separate from faulty RAM."))
    if ctx.status("resource_storage") == "bad":
        rows.append(Hypothesis("storage_bottleneck", "Repeated storage latency may explain the slowdown",
            "One device had high I/O latency in at least three samples. Contention, a controller issue and media errors remain different explanations.",
            evidence_keys=("resource_storage",), actions=[task_action("pc_report")],
            advice="Compare the affected device and workload with storage errors. High activity alone does not establish drive failure."))
    proxy = ctx.get("proxy_settings", {})
    if proxy.get("pac_or_proxy") and ctx.status("https_connectivity") == "bad" and ctx.status("tcp_connectivity") == "good":
        rows.append(Hypothesis("proxy_path", "The web request path needs investigation",
            "Direct TCP works but HTTPS requests fail while a proxy is configured. Proxy authentication, TLS, filtering and the remote services remain alternatives.",
            evidence_keys=("https_connectivity", "tcp_connectivity", "proxy"),
            actions=[task_action("network_diagnostic_bundle")],
            advice="Confirm the required proxy and any VPN with your administrator before changing settings."))
    return rows


def evaluate(ctx, proposals):
    direct = direct_candidates(ctx)
    replaced = {h.id for h in direct}
    candidates = direct + [h for h in proposals if h.id not in replaced]
    # An explicit differential also records explanations that do NOT fit.
    # Threshold-triggered rules alone cannot explain what has been ruled out.
    alternatives = []
    if ctx.audit or ctx.parts & {"performance", "crashes", "general"}:
        alternatives += [
            ("cpu_hog", "CPU saturation", ("resource_cpu",)),
            ("memory_pressure", "Memory pressure", ("resource_memory",)),
            ("storage_bottleneck", "Storage I/O bottleneck", ("resource_storage",)),
            ("failing_drive", "Possible storage hardware or controller fault", ("smart", "drive_wear", "storage_faults")),
            ("app_crash_module", "Application-level crash", ("app_crashes",)),
            ("problem_devices", "Device failure", ("problem_devices",)),
        ]
    if ctx.audit or ctx.parts & {"network", "browser", "updates", "general"}:
        alternatives += [
            ("dns_dead", "Name resolution failure", ("resolver_queries", "tcp_connectivity", "ip_config")),
            ("no_route", "IP configuration or default route failure", ("ip_config",)),
            ("proxy_path", "Proxy, filtering or TLS path problem", ("https_connectivity", "proxy")),
            ("application_connectivity", "Application or individual service failure", ("affected_application",)),
        ]
    existing = {h.id for h in candidates}
    for identifier, title, keys in alternatives:
        if identifier not in existing:
            candidates.append(Hypothesis(identifier, title,
                "Compare this explanation with the measured condition. Missing coverage cannot rule out an intermittent fault.",
                evidence_keys=keys, actions=[]))
    kept, trace = [], []
    relevant = set().union(*(AREAS.get(part, set()) for part in ctx.parts))
    for h in candidates:
        support, contradiction, missing, groups = [], [], [], {}
        for key in h.evidence_keys:
            row = ctx.evidence.get(key)
            if not row or row.get("status") in UNKNOWN:
                missing.append(key)
                continue
            if row.get("status") in ("warn", "bad"):
                if (h.id == "dns_dead" and key in ("resolver_queries", "dns_resolution") and row.get("status") != "bad") or (
                        h.id == "proxy_path" and key == "https_connectivity" and row.get("status") != "bad"):
                    contradiction.append(key)
                    continue
                age = age_seconds(row.get("collected_at"))
                # Current data expires; historical records are explicitly limited.
                if age is not None and age > 300 and not row.get("historical"):
                    missing.append(key)
                    continue
                support.append(key)
                family = FAULT_FAMILIES.get(key, key)
                weight = 2 if row.get("historical") else 4 if row.get("repeatable") else 3
                groups[family] = max(groups.get(family, 0), weight)
            elif key in PRIMARY.get(h.id, ()) and row.get("status") == "good":
                contradiction.append(key)
        affected = set(ctx.interpretation.applications) - {"game", "games"}
        if "app_crashes" in support and affected:
            faults = ctx.get("app_crashes", {}).get("crashes", [])
            matching = [f for f in faults if str(f.get("app", "")).lower().removesuffix(".exe") in affected]
            if not matching:
                support.remove("app_crashes")
                groups.pop("app_crashes", None)
                missing.append("affected_application")
                h.explanation += " The recorded crash concerns a different application from the one reported."
        if h.id == "dns_dead" and ctx.status("tcp_connectivity") == "good":
            groups["tcp_probes"] = 3
            support.append("tcp_connectivity")
        if h.id == "dns_dead" and ctx.status("ip_config") == "bad":
            contradiction.append("ip_config")
        if h.id == "dns_dead" and ctx.status("tcp_connectivity") in ("bad", "warn"):
            contradiction.append("tcp_connectivity")
        if h.id == "captive_portal" and ctx.status("https_connectivity") == "good":
            contradiction.append("https_connectivity")
        if h.id in DEFERRED:
            h.actions = [a for a in h.actions if a.get("task") in ("pc_report", "reliability_monitor")]
            h.explanation += " Timing or configuration alone does not establish a cause."
        if h.id == "rogue_proxy":
            h.actions = []
        score = sum(groups.values()) - 4*len(set(contradiction)) - min(2, .5*len(missing))
        relevance = bool(set(h.evidence_keys) & relevant) or ctx.audit or "general" in ctx.parts
        h.rank_score = round(score + (2 if relevance and support else 0), 2)
        h.supporting, h.contradictory, h.missing = sorted(set(support)), sorted(set(contradiction)), sorted(set(missing))
        h.evidence_strength = ("strong" if score >= 7 and not contradiction and not missing else
                               "moderate" if score >= 3 and not contradiction else "limited")
        if support and all(ctx.evidence.get(key, {}).get("historical") for key in support):
            h.evidence_strength = "limited"
            h.title = "Recorded evidence: " + h.title
            h.explanation += " These records describe past events; the current cause and repair outcome require a fresh, targeted check."
        h.confidence = max(1, min(99, int(max(0, score)*10)))  # compatibility only; UI never shows a percentage
        h.decision = "supported_suspicion" if support and score > 0 else "investigation_lead"
        disposition = "included" if support and score > 0 else "insufficient_evidence"
        if support and score > 0 and not relevance:
            disposition = "incidental_observation"
        # Keep context/timeline leads in the trace, not as unsupported diagnoses.
        if h.id.startswith("baseline_"):
            disposition = "investigation_lead"
        elif support and score > 0 and relevance and h.id not in DEFERRED:
            kept.append(h)
        trace.append({**h.as_dict(), "disposition": disposition,
                      "independent_groups": groups, "symptom_relevant": relevance,
                      "score_formula": "sum(max weight per failure family) - 4 per contradiction - missing coverage penalty"})
    kept.sort(key=lambda h: (-h.rank_score, -{"critical": 3, "high": 2, "medium": 1, "low": 0}.get(h.severity, 1), h.id))
    return kept, trace
