"""WinMend diagnostics: rules: context."""

from __future__ import annotations

from winmend.core.findings import SEVERITY
from winmend.diagnostics.helpers import _plural
from winmend.diagnostics.models import Hypothesis, repair_action, task_action
from winmend.diagnostics.repairs.power import _BALANCED_SCHEME
from winmend.diagnostics.rules.registry import rule
from winmend.diagnostics.timeline import ChangeTimeline


# The standard first moves for each kind of complaint, and the findings that
# say whether that area is measurably unwell. Without this, a complaint about a
# printer on a PC whose spooler happens to be running would get a plan about
# startup programs -- technically true, entirely beside the point.
PROFILE_BASELINE = {
    "network": (
        ("flush_dns", "network_diagnostic_bundle", "wlan_report"),
        ("adapters", "dns", "reachability", "net_quality", "wifi_link", "dns_config", "proxy"),
        "internet connection",
    ),
    "performance": (
        ("disable_startup_apps", "clean_temp", "pc_report"),
        ("memory", "startup", "disk_free", "boot_time", "disk_latency", "thermal"),
        "speed",
    ),
    "storage": (
        ("clean_temp", "disk_cleanup", "component_cleanup"),
        ("disk_free", "temp_size"),
        "disk space",
    ),
    "updates": (
        ("windows_updates", "windows_update_forensic"),
        ("update_failures", "component_store", "pending_reboot"),
        "Windows Update",
    ),
    "crashes": (
        ("bsod_triage", "minidump_analyzer", "reliability_monitor", "repair_system"),
        ("bugchecks", "evt_shutdowns", "evt_hardware", "evt_disk", "gpu_resets"),
        "crashes",
    ),
    "security": (
        ("defender_scan", "msrt_scan", "scheduled_task_audit", "security_posture_report"),
        ("defender", "firewall", "defender_exclusions", "hosts"),
        "security",
    ),
    "battery": (
        ("battery_health_report", "power_plan_switcher"),
        ("battery_wear",),
        "battery",
    ),
    "audio": (("audio_repair",), (), "sound"),
    "printer": (("clear_print_spooler",), (), "printing"),
    "bluetooth": (("bluetooth_repair",), (), "Bluetooth"),
    "apps": (("uwp_app_reset",), ("app_crashes",), "Store apps"),
    "time": (("time_sync_fix",), (), "clock"),
    "browser": (("clear_browser_cache",), ("app_crashes",), "browser"),
    "shell": (("rebuild_icon_cache", "reset_search_index", "start_menu_reset"), (),
              "Start menu and Explorer"),
}


@rule
def rule_profile_baseline(ctx):
    """Always address the thing the user actually complained about.

    Evidence-driven rules outrank this (it is deliberately low severity), but
    without it a plan can end up entirely about something the user never
    mentioned just because that is what happened to measure badly.

    A full check has no complaint to address, so this stays silent there: every
    area would contribute its first steps, burying the things that are actually
    wrong under a forty-step plan of speculative maintenance.
    """
    if ctx.audit:
        return None
    produced = []
    for part in sorted(ctx.parts):
        entry = PROFILE_BASELINE.get(part)
        if entry is None:
            continue
        task_ids, keys, area = entry
        unwell = [k for k in keys if SEVERITY.get(ctx.status(k), 0) > 0]

        # Tailor the shell repairs to what was actually described, rather than
        # resetting three unrelated parts of Explorer.
        if part == "shell":
            wanted = []
            if ctx.mentions("search", "index"):
                wanted.append("reset_search_index")
            if ctx.mentions("start", "taskbar"):
                wanted.append("start_menu_reset")
            if ctx.mentions("icon", "thumbnail"):
                wanted.append("rebuild_icon_cache")
            task_ids = tuple(wanted) or ("rebuild_icon_cache",)
        if part == "network" and not ctx.mentions("wifi", "wi-fi", "wireless", "drop"):
            task_ids = tuple(t for t in task_ids if t != "wlan_report")
        if part == "browser" and ctx.mentions("edge"):
            task_ids = task_ids + ("edge_performance",)

        if unwell:
            explanation = (f"The {area} checks show something wrong right now, and these are "
                           f"the standard repairs for it.")
            confidence = 60
        else:
            explanation = (f"Nothing in the {area} checks is failing at this moment. For a "
                           f"problem that comes and goes, the useful next step is to capture "
                           f"evidence while it is happening rather than to change settings "
                           f"blindly.")
            confidence = 35
        produced.append(Hypothesis(
            f"baseline_{part}",
            f"Standard first steps for {area}",
            explanation,
            confidence=confidence,
            severity="low",
            evidence_keys=list(keys),
            actions=[task_action(task_id) for task_id in task_ids],
            advice=("" if unwell else
                    "If the symptom returns, run this again while it is happening -- the "
                    "checks measure the PC as it is at that moment."),
        ))
    return produced


@rule
def rule_pending_restart(ctx):
    if ctx.status("pending_reboot") != "warn" and ctx.status("uptime") != "warn":
        return None
    uptime = ctx.evidence.get("uptime", {}).get("value", "")
    pending = ctx.status("pending_reboot") == "warn"
    return Hypothesis(
        "needs_restart",
        "Windows is waiting for a restart",
        ("Windows reports pending work that requires a restart. This does not by itself establish an update failure or explain the reported symptom."
         if pending else f"It has been {uptime} since a full restart."),
        confidence=90 if pending else 60,
        severity="medium" if pending else "low",
        evidence_keys=["pending_reboot", "uptime"],
        actions=[task_action("restart_windows", "Restart so pending work can complete.")],
        advice=("Shutting down from the Start menu is not enough when Fast Startup is on -- "
                "use Restart, which always performs a full shutdown."),
    )


# -- hardware the machine reports on itself ----------------------------------

@rule
def rule_hardware_error(ctx):
    """The machine's own error reporting, read properly rather than counted.

    ``rule_bad_memory`` already uses the WHEA *count* as one signal among
    several. This reads the events themselves, because a corrected PCIe blip and
    an uncorrected memory-controller fault are the same number and opposite
    diagnoses.
    """
    whea = ctx.get("whea_errors", {})
    if not whea.get("available") or not whea.get("count"):
        return None
    uncorrected = whea.get("uncorrected", 0)
    total = whea.get("count", 0)
    corrected = whea.get("corrected", max(0, total - uncorrected - whea.get("unknown_severity", 0)))
    area = whea.get("worst_area", "unknown")
    # Corrected errors are the hardware doing its job. A handful over a month is
    # normal on any machine with ECC-adjacent reporting, so only a sustained
    # stream is worth raising on its own.
    if not uncorrected and corrected < 5:
        return None
    where = {
        "memory": "the memory or its controller",
        "pcie": "a PCI Express device or slot",
        "processor": "the processor",
        "bus": "a system bus",
    }.get(area, "a hardware component")
    if uncorrected:
        title = f"Hardware fault reported by {where}"
        explanation = (
            f"{_plural(uncorrected, 'uncorrected hardware error')} of {total} recorded. "
            f"An uncorrected error means {where} failed and could not recover. This comes "
            f"from hardware error reporting. Firmware, tuning, power and physical defects "
            f"can all be involved; the report alone does not identify the part to replace."
        )
        confidence, severity = 90, "critical"
    else:
        title = f"{where[0].upper() + where[1:]} is correcting repeated errors"
        explanation = (
            f"{_plural(corrected, 'corrected hardware error')} recorded. The hardware caught each "
            f"one and carried on. Repetition warrants investigation of settings, firmware "
            f"and hardware, but does not prove that a component is wearing out."
        )
        confidence, severity = 70, "high"
    actions = [task_action("pc_report", "Capture the full report to take to a repair shop.")]
    if area == "memory":
        actions.insert(0, task_action(
            "memory_diagnostic", "Confirm it with Windows' own memory test at the next restart."))
    return Hypothesis(
        "hardware_error", title, explanation,
        confidence=confidence, severity=severity,
        evidence_keys=["hardware_errors", "evt_hardware"],
        actions=actions,
        advice=("Back up important data. Return CPU and memory tuning to stock settings and "
                "review the PC maker's firmware guidance. For memory errors, run an offline "
                "memory test. For PCIe errors, isolate the device, slot and power connection. "
                "Shut down and disconnect power before following the service manual to reseat "
                "parts; persistent errors at stock settings need manufacturer diagnostics or service."),
        # A long chkdsk pass on hardware that is already reporting faults is how
        # a recoverable machine becomes an unrecoverable one.
        suppress=["chk_dsk", "check_disk", "defrag_optimize", "optimize_volume"],
        suppress_reason=("The hardware is reporting errors. A long full-surface pass on a "
                         "component that is already failing risks making it worse, so it is "
                         "being held back until the hardware is checked."),
    )


@rule
def rule_memory_test_failed(ctx):
    """Windows' own memory test already found bad RAM.

    This outranks every inference in the engine. Everything else about memory is
    deduced from crash patterns; this is a direct test result.
    """
    result = ctx.get("memory_diagnostic", {})
    if not result.get("available") or not result.get("failed"):
        return None
    last = result.get("last") or {}
    when = last.get("time", "")
    return Hypothesis(
        "memory_test_failed",
        "Windows' memory test found faulty memory",
        (f"The Windows Memory Diagnostic reported hardware problems"
         + (f" when it ran on {when[:10]}" if when else "") + ". That is a direct test "
         "result rather than an inference, and faulty memory explains crashes, corruption, "
         "and freezes all at once. Memory that fails this test has to be replaced."),
        confidence=95, severity="critical",
        evidence_keys=["memory_test"],
        actions=[task_action("ram_quick_test", "Confirm which module before buying anything."),
                 task_action("pc_report", "Capture the report for the shop or the warranty claim.")],
        advice=("Test one module at a time to find the bad one. Until it is replaced, treat "
                "anything this PC writes as unreliable -- do not run repairs that rewrite "
                "large amounts of disk, and back up to another machine."),
        suppress=["chk_dsk", "check_disk", "repair_system", "component_cleanup"],
        suppress_reason=("Memory that fails its own test corrupts what it writes. Running a "
                         "repair that rewrites system files through faulty memory can turn a "
                         "bad-RAM problem into a broken Windows install."),
    )


@rule
def rule_cpu_throttled(ctx):
    """The processor is being held far below its rated speed while it is busy."""
    throttle = ctx.get("cpu_throttle", {})
    if not throttle.get("available") or not throttle.get("low_clock"):
        return None
    load = throttle.get("load_pct") or 0
    ratio = throttle.get("ratio") or 0
    # Idling low is what every modern CPU does. Only a machine that is being
    # asked to work and still cannot reach its clock is throttled.
    if load < 40:
        return None
    thermal = ctx.get("thermal_events", {})
    hot = thermal.get("throttle_events", 0) if thermal.get("available") else 0
    battery = ctx.get("battery_wear", {})
    on_battery = bool(battery.get("available") and battery.get("on_battery"))
    reasons = []
    if hot:
        reasons.append(f"{_plural(hot, 'thermal throttling event')} recorded")
    if on_battery:
        reasons.append("the PC is running on battery, where Windows caps the clock deliberately")
    plan = ctx.get("power_config", {})
    if plan.get("available") and plan.get("power_saver"):
        reasons.append("the power plan is set to Power saver")
    return Hypothesis(
        "cpu_throttled",
        "The processor is running far below its rated speed",
        (f"The processor is at {ratio * 100:.0f}% of its rated clock while {load}% busy. "
         + ("Something is holding it back: " + "; ".join(reasons) + "."
            if reasons else
            "Nothing in the readings explains why -- heat, a power limit, or a firmware "
            "setting are the usual causes.")
         + " A processor pinned low makes the whole PC feel broken while every load "
           "measurement still looks healthy."),
        confidence=75 if reasons else 55,
        severity="high" if hot else "medium",
        evidence_keys=["cpu_clock", "thermal", "power_plan"],
        actions=([repair_action("set_power_plan", {"scheme": _BALANCED_SCHEME},
                                title="Switch to the Balanced power plan",
                                reason="Power saver caps the processor clock.")]
                 if plan.get("available") and plan.get("power_saver") else [])
                + [task_action("cpu_stress_test",
                               "Load the processor and watch whether the clock recovers.")],
        advice=("If it is heat, cleaning the fans and vents is the fix. On a laptop, check it "
                "is on mains power and that the charger is the right one -- an underpowered "
                "charger makes Windows cap the clock without saying so."),
    )


@rule
def rule_stability_drop(ctx):
    """Windows' own stability record fell, and something changed when it did.

    This is the correlation the engine could not make before. Rather than
    guessing from recency, it takes the date Windows itself recorded the machine
    getting worse and asks what was installed around then -- a claim that can be
    checked rather than asserted.
    """
    stability = ctx.get("reliability_history", {})
    if not stability.get("available") or not stability.get("degraded"):
        return None
    timeline = ctx.timeline
    suspects = timeline.suspects(ctx.onset_days())
    if not suspects:
        # The score fell and nothing was installed near it. That names no cause
        # and offers no repair, so it stays out of the plan rather than becoming
        # a shrug with a progress bar attached.
        return None
    onset = timeline.onset(ctx.onset_days()) or {}
    when = {
        "stated": "when you said the trouble started",
        "stability": "when Windows recorded this PC getting less stable",
        "first_symptom": "when the first fault was recorded",
    }.get(onset.get("source", ""), "when the trouble started")

    # What actually knocked the score down, which is the part the user can act
    # on. The score is a consequence of recorded failures, so naming those
    # first is the difference between a diagnosis and a coincidence.
    limit = float(onset.get("days_ago", 0))
    nearby = [item for item in timeline.symptoms
              if limit - 1.0 <= item["days_ago"] <= limit + ChangeTimeline.WINDOW_DAYS]
    kinds = {}
    for item in nearby:
        kinds[item["kind"]] = kinds.get(item["kind"], 0) + 1
    recorded = ", ".join(
        f"{count} {name.replace('_', ' ')}" + ("" if count == 1 else "s")
        for name, count in sorted(kinds.items(), key=lambda pair: -pair[1])
        if name != "stability_drop")

    lead = suspects[0]
    others = len(suspects) - 1
    data = lead.get("data") or {}
    # Confidence falls as the field widens. Eight things installed in the same
    # week makes the nearest one a coincidence, not a suspect -- treating a
    # crowded window as strong evidence is the same mistake as blaming whatever
    # was newest, wearing a timestamp.
    narrow = len(suspects) <= 2
    confidence = max(35, 70 - 9 * others)

    actions = []
    if narrow and lead["kind"] == "update" and data.get("kb"):
        actions.append(repair_action(
            "uninstall_update", {"kb": data["kb"]},
            title=f"Uninstall {data['kb']}",
            reason=f"It installed {abs(lead['gap_days']):.1f} days from {when}, "
                   f"and nothing else did."))
    elif narrow and lead["kind"] == "driver" and data.get("published"):
        actions.append(repair_action(
            "rollback_driver",
            {"published": data["published"], "name": data.get("original", "")},
            title=f"Remove the {data.get('provider', '')} driver package".strip(),
            reason=f"It was staged {abs(lead['gap_days']):.1f} days from {when}, "
                   f"and nothing else was."))
    checkpoints = timeline.suspects(ctx.onset_days(), kinds=("restore",))
    actions.append(task_action(
        "system_restore_browser",
        ("There is a restore point from within a day of the drop, so rolling back undoes "
         "every change in that window at once rather than guessing which one mattered."
         if checkpoints else
         "Roll the whole PC back to a checkpoint from before the score fell, which undoes "
         "every change in the window at once rather than guessing which one mattered.")))
    actions.append(task_action("reliability_monitor",
                               "See the day-by-day timeline Windows itself keeps."))

    if narrow:
        blame = (f"The only change close to that date is: {lead['title']}"
                 + (f" ({lead['detail']})" if lead.get("detail") else "")
                 + f", {abs(lead['gap_days']):.1f} days away.")
    else:
        listing = "; ".join(item["title"] for item in suspects[:4])
        blame = (f"{_plural(len(suspects), 'change')} landed in that window -- {listing}"
                 + (", and more" if len(suspects) > 4 else "")
                 + ". With that many, the closest one is not evidence against it, so none of "
                   "them is being singled out.")

    return Hypothesis(
        "stability_drop",
        f"Something changed around {stability.get('drop_date')} and the PC got worse",
        (f"Windows keeps its own stability score, and it fell from "
         f"{stability.get('drop_from')} to {stability.get('drop_to')} out of 10 on "
         f"{stability.get('drop_date')}, averaging {stability.get('recent_avg')} since against "
         f"{stability.get('baseline_avg')} before."
         + (f" What it recorded around then: {recorded}." if recorded else "")
         + " " + blame),
        confidence=confidence,
        severity="medium" if narrow else "low",
        evidence_keys=["stability"],
        actions=actions,
        advice=("This is a correlation drawn from a date Windows measured rather than one "
                "anyone remembered, which is what makes it worth acting on. It is still a "
                "correlation: if undoing the change makes no difference, put it back."
                if narrow else
                "Too much changed at once for any single item to be blamed. A restore point "
                "from before the drop undoes all of it together, which is the only way to test "
                "the window as a whole."),
    )
