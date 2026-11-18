"""Compare the original targeted faults, independently of command exit codes."""
from __future__ import annotations
from winmend.core.findings import SEVERITY
from winmend.diagnostics.catalog import FINDING_SOURCES
from winmend.diagnostics.observations import HISTORICAL

NUMERIC = {"disk_free": ("free_pct", 1), "disk_latency": ("avg_ms", -1)}


def historical(row):
    return row.get("historical", False) or any(s in HISTORICAL for s in FINDING_SOURCES.get(row["key"], ()))


def comparable(old, new):
    if not new or new.get("status") not in ("good", "warn", "bad") or historical(new):
        return False
    if old["key"].startswith("resource_") or old["key"] == "resolver_queries":
        return bool(new.get("repeatable"))
    return True


def update_confirmation(old, new):
    """Newer successful events for the exact failed update(s), not any update.

    Event record IDs avoid inferring sequence from a clock that may be wrong.
    A later failure of that same update prevents crediting an earlier success.
    """
    if not new or old.get("key") != "update_failures":
        return False, False
    baseline = old.get("data", {})
    original = {f.get("identity") for f in baseline.get("failures", []) if f.get("identity")}
    record_id = baseline.get("max_record_id") or 0
    if not original or record_id <= 0:
        return False, False
    fresh = new.get("data", {})
    remaining = {f.get("identity") for f in fresh.get("failures", [])}
    confirmed = {s.get("identity") for s in fresh.get("successes", [])
                 if (s.get("record_id") or 0) > record_id and s.get("identity") not in remaining}
    covered = original & confirmed
    return original <= covered, bool(covered)


def compare(before, after):
    old_map = {f["key"]: f for f in before.get("findings", [])}
    new_map = {f["key"]: f for f in after.get("findings", [])}
    keys = before.get("verification_targets")
    if keys is None:
        keys = [key for key, row in old_map.items() if row.get("status") in ("warn", "bad")]
        if before.get("schema_version") == 2 and before.get("profile") not in ("general", "audit", "hardware"):
            from winmend.diagnostics.reasoning import AREAS
            relevant = set().union(*(AREAS.get(part, set()) for part in str(before.get("profile", "")).split("+")))
            keys = [key for key in keys if key in relevant]
    broken = [key for key in dict.fromkeys(keys) if old_map.get(key, {}).get("status") in ("warn", "bad")]
    resolved, improved, worsened, unknown, persistent, changes = [], [], [], [], [], []
    for key in broken:
        old, new = old_map[key], new_map.get(key)
        result = "inconclusive"
        all_updates, some_updates = update_confirmation(old, new)
        if some_updates:
            if all_updates and new.get("status") == "good":
                resolved.append(key)
                result = "resolved"
            else:
                improved.append(key)
                result = "improved"
        elif not comparable(old, new) or historical(old):
            unknown.append(key)
        elif new["status"] == "good":
            resolved.append(key)
            result = "resolved"
        else:
            old_rank, new_rank = SEVERITY.get(old["status"], 0), SEVERITY.get(new["status"], 0)
            if new_rank < old_rank:
                improved.append(key)
                result = "improved"
            elif new_rank > old_rank:
                worsened.append(key)
                result = "worse"
            else:
                metric, direction = NUMERIC.get(key, (None, 1))
                a, b = old.get("data", {}).get(metric), new.get("data", {}).get(metric)
                if isinstance(a, (int, float)) and isinstance(b, (int, float)) and abs(b-a) >= max(.5, abs(a)*.2):
                    if (b-a)*direction > 0:
                        improved.append(key)
                        result = "improved"
                    else:
                        worsened.append(key)
                        result = "worse"
                else:
                    persistent.append(key)
                    result = "persists"
        changes.append({"key": key, "label": old.get("label", key), "before": old.get("value"),
                        "after": new.get("value") if new else "Not measured", "result": result,
                        "before_status": old.get("status"), "after_status": new.get("status") if new else "not_tested"})
    if worsened:
        condition = "needs_attention"
    elif broken and len(resolved) == len(broken):
        condition = "resolved"
    elif resolved or improved:
        condition = "improved"
    elif persistent:
        condition = "not_resolved"
    else:
        condition = "inconclusive"
    symptom = after.get("symptom_resolved")
    symptom_status = "resolved" if symptom is True else "persists" if symptom is False else "unknown"
    outcome = condition
    if condition == "resolved" and before.get("problem") and before.get("profile") not in ("audit", "hardware") and symptom is not True:
        outcome = "improved" if symptom is False else "symptom_unverified"
    requested = before.get("restart_required", False)
    old_context, new_context = before.get("system_context") or {}, after.get("system_context") or {}
    old_event, new_event = old_context.get("boot_event_record_id"), new_context.get("boot_event_record_id")
    old_ticks, new_ticks = old_context.get("boot_uptime_ms"), new_context.get("boot_uptime_ms")
    restarted = bool(old_event and new_event and new_event > old_event)
    if old_ticks is not None and new_ticks is not None and new_ticks + 5000 < old_ticks:
        restarted = True
    if requested and not restarted:
        outcome = "restart_required"
    if before.get("repair_status") == "failed":
        outcome = "repair_failed"
    elif before.get("repair_status") == "not_applied":
        outcome = "not_applied"
    elif before.get("repair_status") == "cancelled":
        outcome = "cancelled"
    summaries = {
        "resolved": "All targeted measurable faults were verified clear. This result is limited to those checks.",
        "improved": "Some targeted conditions improved, but the original problem is not fully verified resolved.",
        "symptom_unverified": "The targeted measurements cleared. Repair completed; the original symptom still needs confirmation.",
        "not_resolved": "The targeted fault remains. Reassess the other explanations before attempting another repair.",
        "needs_attention": "A targeted condition worsened. Review the evidence and recovery options before further repairs.",
        "inconclusive": "Verification lacks comparable measurements of the targeted fault. No resolution is claimed.",
        "restart_required": "This repair requires a restart before its effect can be verified. Re-check after restarting.",
        "repair_failed": "At least one repair failed. Review the recorded execution result; measurements alone do not make that command successful.",
        "not_applied": "No system repair was applied. The new measurements describe the current condition; no repair success is claimed.",
        "cancelled": "The repair run was cancelled. These readings describe the current condition; they do not establish a completed repair.",
    }
    return {"outcome": outcome, "condition_outcome": condition, "symptom_status": symptom_status,
            "summary": summaries[outcome], "before_score": before.get("severity_score", 0),
            "after_score": after.get("severity_score", 0), "improved_checks": len(improved)+len(resolved),
            "worsened_checks": len(worsened), "unverified_keys": unknown,
            "unresolved_keys": persistent + improved + worsened, "resolved_keys": resolved,
            "targets": broken, "changes": changes, "after": after}
