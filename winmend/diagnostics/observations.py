"""Provider results and measured findings, with explicit coverage and provenance.

Legacy payloads remain readable. A failed provider is removed before legacy
rules run, then represented by an unknown finding; it is never filled with 0.
"""
from __future__ import annotations

from datetime import datetime, timezone
import math
import uuid

from winmend.core.findings import utc_now
from winmend.diagnostics.catalog import COLLECTOR_ORIGINS, FINDING_SOURCES

STATES = frozenset(("healthy", "problem_detected", "warning", "inconclusive",
                    "not_tested", "not_applicable", "unsupported", "permission_denied",
                    "collection_failed", "cancelled"))
UNKNOWN = STATES - {"healthy", "problem_detected", "warning"}
STATUS_STATE = {"good": "healthy", "bad": "problem_detected", "warn": "warning",
                "info": "inconclusive"}
# Minimum contracts for older providers that return dictionaries without available.
REQUIRED = {"disk": ("free_pct", "free_gb"), "memory": ("used_pct", "available_gb"),
            "temp_size": ("bytes",), "network": ("adapters", "dns", "reachable"),
            "cpu_load": ("used_pct",), "dns_resolution": ("resolved", "attempted"),
            "time_sync": ("offset_seconds",)}
SCALARS = {"startup_count": (int,), "uptime_days": (int, float),
           "pending_reboot": (bool,), "firewall_enabled": (bool,)}
HISTORICAL = frozenset(("event_log_errors", "bugchecks", "app_crashes", "gpu_resets",
                       "storage_removals", "whea_errors", "update_failures", "thermal_events",
                       "installed_updates", "third_party_drivers", "installed_programs",
                       "reliability_history", "integrity_history", "boot_history", "dump_files",
                       "power_events", "storage_bus_errors", "event_log_sweep", "wer_reports",
                       "minidump_details", "memory_diagnostic", "live_kernel_events"))


def failure_state(reason):
    text = str(reason or "").lower()
    if any(s in text for s in ("denied", "unauthorized", "administrator", "winerror 5", "0x80041003")):
        return "permission_denied"
    if "cancel" in text:
        return "cancelled"
    if any(s in text for s in ("unsupported", "not supported", "commandnotfound", "command not found")):
        return "unsupported"
    if "not applicable" in text:
        return "not_applicable"
    if "timeout" in text or "timed out" in text:
        return "collection_failed"
    return "collection_failed" if reason else "inconclusive"


def usable(name, value):
    if value is None:
        return False
    if isinstance(value, dict):
        if value.get("available") is False or value.get("diagnostic_state") in UNKNOWN:
            return False
        if not value:
            return False
        for field in REQUIRED.get(name, ()):
            if field not in value:
                return False
            v = value.get(field)
            if (v is None and name != "network") or (isinstance(v, float) and not math.isfinite(v)):
                return False
        if name == "disk" and (not isinstance(value["free_pct"], (int, float)) or not 0 <= value["free_pct"] <= 100 or not isinstance(value["free_gb"], (int, float))):
            return False
        return True
    if name in SCALARS:
        if isinstance(value, bool) and bool not in SCALARS[name]:
            return False
        return isinstance(value, SCALARS[name]) and (not isinstance(value, (int, float))
               or isinstance(value, bool) or math.isfinite(value))
    return isinstance(value, (list, int, float, bool))


def split_results(raw):
    return ({name: value for name, value in (raw or {}).items() if usable(name, value)},
            {name: value for name, value in (raw or {}).items() if not usable(name, value)})


def unknown_findings(raw, findings):
    """Add rows for attempted, unusable sources, including sources with no mapping."""
    clean, unavailable = split_results(raw)
    present = {f["key"] for f in findings}
    rows = []
    for name, value in unavailable.items():
        keys = [key for key, sources in FINDING_SOURCES.items() if name in sources]
        keys = keys or ["provider_" + name]
        reason = (value.get("reason") or value.get("error") or "No usable measurement returned") \
                 if isinstance(value, dict) else "No usable measurement returned"
        state = value.get("diagnostic_state") if isinstance(value, dict) else None
        explicit_reason = (value.get("reason") or value.get("error")) if isinstance(value, dict) else None
        if isinstance(value, dict) and value.get("exposes_nothing"):
            explicit_reason = reason = "Unsupported: this board exposes no sensors through the available providers."
        if isinstance(value, dict) and value.get("unreadable"):
            explicit_reason = str(explicit_reason or "") + " " + "; ".join(str(item.get("reason", "")) for item in value["unreadable"])
            reason = explicit_reason
        state = state if state in UNKNOWN else failure_state(explicit_reason)
        for key in keys:
            # A working alternative (e.g. detailed restart instead of scalar) is valid.
            if key in present or any(source in clean for source in FINDING_SOURCES.get(key, ())):
                continue
            rows.append({"key": key, "label": key.replace("_", " ").title(),
                         "status": state, "value": "Not measured", "detail": str(reason)[:200],
                         "data": {}, "task_ids": []})
            present.add(key)
    return rows


def attach_provenance(findings, raw, session_id, metadata=None, symptom=""):
    from winmend.diagnostics.measurements import THRESHOLDS
    specifications = {
        "disk_free": ("GB and percent", "At least 18% free; below 8% is critically constrained"),
        "resource_cpu": ("percent", {"saturation_threshold": THRESHOLDS["cpu_pct"], "minimum_samples": 3}),
        "resource_memory": ("percent and pages/second", {"low_available_threshold": THRESHOLDS["available_pct"],
                    "high_commit_threshold": THRESHOLDS["commit_pct"], "page_input_threshold": THRESHOLDS["pages_input_per_second"]}),
        "resource_storage": ("ms/operation", {"latency_threshold": THRESHOLDS["latency_ms"], "minimum_samples": 3}),
        "resolver_queries": ("successful queries / attempts", "Two public names queried repeatedly"),
        "tcp_connectivity": ("successful connections / attempts", "Two public TCP destinations; filtering is a limitation"),
    }
    records = []
    metadata = metadata or {}
    context = raw.get("system_context") if isinstance(raw.get("system_context"), dict) else {}
    for finding in findings:
        sources = FINDING_SOURCES.get(finding["key"], ())
        metas = [metadata[s] for s in sources if s in metadata]
        # Loaded legacy cases have unknown collection duration, not invented timing.
        collected_at = max((m["collected_at"] for m in metas), default=None)
        duration = sum(m.get("duration_ms", 0) for m in metas) if metas else None
        historical = any(s in HISTORICAL for s in sources)
        unit, expected = specifications.get(finding["key"], (finding.get("unit"), finding.get("expected_range")))
        state = STATUS_STATE.get(finding["status"], finding["status"])
        if state not in STATES:
            state = "inconclusive"
        record = {"id": uuid.uuid4().hex, "session_id": session_id,
                  "check_id": finding["key"], "providers": list(sources),
                  "source": [COLLECTOR_ORIGINS.get(s, s) for s in sources],
                  "collected_at": collected_at, "duration_ms": duration,
                  "value": finding.get("data") or None, "display_value": finding.get("value"),
                  "unit": unit, "expected_range": expected,
                  "state": state, "historical": historical, "direct": not historical,
                  "repeatable": finding.get("repeatable", False),
                  "reliability": "limited" if historical or state in UNKNOWN else "direct",
                  "freshness": "historical" if historical else "current" if collected_at else "unknown",
                  "windows": {key: context.get(key) for key in ("build", "version", "architecture")},
                  "permissions": "administrator" if state == "permission_denied" else "provider dependent",
                  "symptom": symptom, "supports": [], "contradicts": [],
                  "error": finding.get("detail") if finding["status"] in UNKNOWN else None}
        data = finding.get("data", {})
        record["device_ids"] = sorted({str(d.get("instance_id") or d.get("drive") or d.get("device"))
                                      for d in data.get("devices", []) if isinstance(d, dict)
                                      and (d.get("instance_id") or d.get("drive") or d.get("device"))}) if isinstance(data.get("devices"), list) else []
        finding.update(observation_id=record["id"], collected_at=collected_at,
                       duration_ms=duration, diagnostic_state=state,
                       historical=historical, source=record["source"])
        records.append(record)
    return records


def age_seconds(text):
    try:
        moment = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - moment).total_seconds())
    except (ValueError, TypeError):
        return None
