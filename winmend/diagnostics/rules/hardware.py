"""WinMend diagnostics: rules: hardware."""

from __future__ import annotations

from winmend.diagnostics.helpers import _plural
from winmend.diagnostics.models import Hypothesis, task_action
from winmend.diagnostics.rules.registry import rule


# -- hardware: the ones that must outrank everything else --------------------

@rule
def rule_failing_drive(ctx):
    """A drive that is failing explains slowness, freezes, and crashes at once --
    and makes several otherwise-reasonable repairs actively dangerous."""
    smart = ctx.get("smart_health", {})
    unhealthy = smart.get("unhealthy") or []
    events = ctx.get("event_log_errors", {})
    disk_errors = events.get("disk_errors", 0) if events.get("available") else 0
    removals = ctx.get("storage_removals", {})
    removal_count = removals.get("events", 0) if removals.get("available") else 0
    bugcheck_disk = [c for c in (ctx.get("bugchecks", {}).get("crashes") or [])
                     if "disk" in (c.get("tags") or [])]

    signals = []
    confidence = 0
    if unhealthy:
        signals.append(f"the drive reports itself as {unhealthy[0]}")
        confidence += 55
    if disk_errors:
        signals.append(f"{_plural(disk_errors, 'disk error')} logged by the storage driver")
        confidence += 25 if disk_errors < 5 else 35
    if removal_count:
        signals.append(f"{_plural(removal_count, 'device reset or surprise removal')}")
        confidence += 15
    if bugcheck_disk:
        signals.append(f"a {bugcheck_disk[0]['name']} stop code, which is a disk-read failure")
        confidence += 30
    if not signals or confidence < 30:
        return None

    return Hypothesis(
        "failing_drive",
        "Storage faults require investigation" if not unhealthy else "A drive reports degraded health",
        "Storage evidence: " + "; ".join(signals) + ". Media damage, controller faults, loose connections and power interruptions require different follow-up checks.",
        confidence=confidence,
        severity="critical",
        evidence_keys=["smart", "evt_disk", "storage_faults"],
        actions=[task_action("disk_smart_check",
                             "Read the drive's own health data to confirm before anything else.")],
        advice=("Back up anything irreplaceable now, before running any repair. "
                "Repairs that rewrite the disk can finish off a drive that is already failing."),
        # This is the correlation that a checklist cannot make: every one of
        # these is the standard answer to "disk errors", and every one of them is
        # the wrong move on a drive that is physically dying. ``check_disk``
        # belongs here for the same reason as the chkdsk task -- a repair that
        # is targeted rather than generic is not therefore gentler.
        suppress=["chk_dsk", "check_disk", "defrag_optimize"],
        suppress_reason=("Withheld while the drive looks unhealthy: chkdsk and defragmentation "
                         "both rewrite the disk heavily, which is how a failing drive is pushed "
                         "over the edge. Confirm the drive's health, and back up, first."),
    )


@rule
def rule_bad_memory(ctx):
    events = ctx.get("event_log_errors", {})
    whea = ctx.get("whea_errors", {})
    hardware = whea.get("uncorrected", 0) if whea.get("worst_area") == "memory" else 0
    crashes = ctx.get("bugchecks", {}).get("crashes") or []
    memory_codes = [c for c in crashes if "memory" in (c.get("tags") or [])]
    hardware_codes = [c for c in crashes if "hardware" in (c.get("tags") or [])]

    confidence = 0
    signals = []
    if hardware:
        signals.append(f"{_plural(hardware, 'hardware error event')} reported by the machine itself (WHEA)")
        confidence += 50
    if hardware_codes:
        signals.append(f"a {hardware_codes[0]['name']} stop code")
        confidence += 40
    if len(memory_codes) >= 2:
        signals.append(f"repeated memory-related stop codes ({memory_codes[0]['name']})")
        confidence += 35
    elif memory_codes:
        signals.append(f"a {memory_codes[0]['name']} stop code")
        confidence += 20
    if ctx.answer("safe_mode") == "yes" and confidence:
        signals.append("the problem persists in Safe Mode, which rules out most software")
        confidence += 15
    if not signals or confidence < 30:
        return None
    return Hypothesis(
        "bad_memory",
        "Possible memory instability requires confirmation",
        "Memory-related evidence: " + "; ".join(signals) + ". Stop codes alone do not identify faulty RAM.",
        confidence=confidence,
        severity="critical" if hardware else "high",
        evidence_keys=["evt_hardware", "bugchecks"],
        actions=[task_action("ram_quick_test", "Run a quick memory sanity test first."),
                 task_action("memory_diagnostic",
                             "Schedule the full Windows Memory Diagnostic for the next restart.")],
        advice=("If the memory test fails, reseat the modules and test one at a time. "
                "WHEA errors that survive a memory swap usually mean the CPU, board, or power supply."),
    )


@rule
def rule_thermal_throttle(ctx):
    thermal = ctx.get("thermal_events", {})
    if not thermal.get("available"):
        return None
    count = thermal.get("throttle_events", 0)
    if count < 3:
        return None
    hot = ctx.answer("perf_signs") == "fans"
    return Hypothesis(
        "thermal_throttle",
        "Firmware has limited CPU performance",
        f"Windows logged {_plural(count, 'thermal throttling event')} in the last two weeks"
        + (", and you noticed the fans working hard" if hot else "")
        + ". Heat, power limits and firmware settings remain competing explanations; temperature data is needed to identify heat.",
        confidence=75 if hot else 60,
        severity="high",
        evidence_keys=["thermal"],
        actions=[task_action("pc_report", "Capture the full hardware report for the record.")],
        advice=("This is physical, not software: clear dust from the fans and vents, "
                "make sure air can reach the intakes, and on a laptop consider having the "
                "thermal paste redone. No software repair will help."),
    )


@rule
def rule_battery_worn(ctx):
    wear = ctx.get("battery_wear", {})
    if not wear.get("available"):
        return None
    pct = wear.get("wear_pct", 0)
    if pct < 25:
        return None
    return Hypothesis(
        "battery_worn",
        "The battery is worn out",
        f"The battery now holds {100 - pct:.0f}% of its original capacity "
        f"({wear['full_mwh']:,} mWh of a designed {wear['design_mwh']:,} mWh), "
        f"so it has lost {pct:.0f}%.",
        confidence=90,
        severity="high" if pct >= 40 else "medium",
        evidence_keys=["battery_wear"],
        actions=[task_action("battery_health_report",
                             "Produce the full Windows battery report to confirm and keep.")],
        advice=("Battery wear is not repairable in software. Above about 30% loss, "
                "replacement is the only real fix."),
    )
