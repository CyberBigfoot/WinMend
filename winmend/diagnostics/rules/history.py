"""WinMend diagnostics: rules: history."""

from __future__ import annotations

from winmend.diagnostics.helpers import _plural
from winmend.diagnostics.models import Hypothesis, repair_action, task_action
from winmend.diagnostics.reference import module_vendor
from winmend.diagnostics.rules.registry import rule


# -- change correlation: what a technician asks about first ------------------

@rule
def rule_recent_update(ctx):
    """A quality update installed close to when the symptom began."""
    updates = ctx.get("installed_updates", {})
    if not updates.get("available"):
        return None
    window = ctx.onset_days()
    if window is None:
        return None
    suspects = [u for u in updates.get("updates", []) if ctx.near_onset(u.get("days_ago"))]
    if not suspects:
        return None
    blamed = ctx.answer("trigger") == "update"
    top = suspects[0]
    confidence = 45 + (30 if blamed else 0) + (10 if len(suspects) == 1 else 0)
    return Hypothesis(
        "recent_update",
        f"A recent Windows update ({top['kb']}) lines up with the symptom",
        f"{top['kb']} installed {top['days_ago']:.0f} day(s) ago, which falls inside the "
        f"window you described"
        + (", and you said an update went in just before the trouble started" if blamed else "")
        + f". {_plural(len(suspects), 'update')} installed in that window.",
        confidence=confidence,
        severity="high" if blamed else "medium",
        evidence_keys=["recent_updates"],
        actions=[repair_action(
            "uninstall_update", {"kb": top["kb"]},
            title=f"Uninstall {top['kb']}",
            reason="Remove the update that lines up with when the problem started.")],
        advice=("If removing it fixes the problem, pause updates for a few weeks and let "
                "Microsoft supersede it, rather than leaving the PC permanently unpatched."),
    )


# Which driver classes can plausibly produce which symptom. Recency alone is a
# weak signal: a virtualisation driver installed yesterday is not why the PC has
# been slow, and blaming it because it sorted first is exactly the wrong answer.
# Driver classes that can produce each kind of corroborating failure. This maps
# "something is measurably broken" to "which recently-installed driver could
# actually be responsible for it".
DRIVER_CLASS_AREAS = {
    "display": ("display",),
    "storage": ("diskdrive", "hdc", "scsiadapter", "volume", "storage"),
    "network": ("net", "netclient", "netservice", "nettrans"),
    "audio": ("media", "audioendpoint", "sound"),
    "bluetooth": ("bluetooth",),
    "usb": ("usb", "usbdevice"),
    "system": ("system", "computer", "processor"),
}


@rule
def rule_recent_driver(ctx):
    """A recently installed driver, but only when something corroborates it.

    Recency on its own is not evidence. Dozens of driver packages are staged by
    routine updates, so "this one was newest" would name an innocent driver on
    most PCs. A driver is only accused here when either a measurement points at
    its area, or the user says they changed software or hardware themselves.
    """
    drivers = ctx.get("third_party_drivers", {})
    if not drivers.get("available"):
        return None
    if ctx.onset_days() is None:
        return None
    suspects = [d for d in drivers.get("recent", []) if ctx.near_onset(d.get("days_ago"))]
    if not suspects:
        return None

    # What is actually failing right now, expressed as driver areas.
    failing = set()
    devices = ctx.get("problem_devices", {})
    if devices.get("available"):
        for device in devices.get("devices", []):
            if device.get("problem_code") in (10, 31, 43, 39, 19, 1, 3, 18, 52, 54):
                area = str(device.get("class", "")).strip().lower()
                for name, classes in DRIVER_CLASS_AREAS.items():
                    if area in classes:
                        failing.add(name)
    if (ctx.get("gpu_resets", {}) or {}).get("count", 0) >= 1:
        failing.add("display")
    events = ctx.get("event_log_errors", {})
    if events.get("available") and events.get("disk_errors"):
        failing.add("storage")
    for crash in (ctx.get("bugchecks", {}) or {}).get("crashes", []):
        tags = crash.get("tags") or []
        if "gpu" in tags:
            failing.add("display")
        if "disk" in tags:
            failing.add("storage")
        if "driver" in tags:
            failing.add("system")
    net = ctx.get("network") or {}
    if "network" in ctx.parts and net and not net.get("reachable"):
        failing.add("network")

    allowed = set()
    for area in failing:
        allowed.update(DRIVER_CLASS_AREAS.get(area, ()))

    corroborated = [d for d in suspects
                    if str(d.get("class", "")).strip().lower() in allowed]
    blamed = ctx.answer("trigger") in ("software", "hardware")
    if not corroborated and not blamed:
        # Nothing measured points at a driver, and the user did not report
        # installing one. Naming the newest package here would be a guess.
        return None

    pool = corroborated or suspects
    pool = sorted(pool, key=lambda d: d.get("days_ago") or 0)
    top = pool[0]
    safe_mode_clean = ctx.answer("safe_mode") == "no"
    confidence = (45 if corroborated else 25) + (25 if blamed else 0) + (15 if safe_mode_clean else 0)

    name = top.get("original") or top.get("published")
    provider = top.get("provider", "")
    device_class = top.get("class", "")
    return Hypothesis(
        "recent_driver",
        f"A recently installed driver ({name}) lines up with the symptom",
        f"The driver package {name}"
        + (f" from {provider}" if provider else "")
        + (f", a {device_class} driver," if device_class else "")
        + f" was installed {top['days_ago']:.0f} day(s) ago, inside the window you described"
        + (f", and something in that same area is currently failing"
           if corroborated else "")
        + (", you said software or hardware changed just before" if blamed else "")
        + (", and the problem disappears in Safe Mode, where third-party drivers do not load"
           if safe_mode_clean else "")
        + ("" if corroborated else
           ". No measurement points at this driver specifically, so treat it as a lead")
        + ".",
        confidence=confidence,
        severity="high" if corroborated else "medium",
        evidence_keys=["recent_drivers", "problem_devices", "gpu_resets"],
        actions=[repair_action(
            "rollback_driver",
            {"published": top["published"], "name": name, "provider": provider,
             "class": device_class},
            title=f"Remove the {name} driver package",
            reason="Revert to the driver Windows shipped, which was working before.")],
        advice="If this is the fix, get a newer driver from the manufacturer rather than the one just removed.",
    )


@rule
def rule_recent_program(ctx):
    programs = ctx.get("installed_programs", {})
    if not programs.get("available"):
        return None
    if ctx.answer("trigger") != "software":
        return None
    suspects = [p for p in programs.get("programs", []) if ctx.near_onset(p.get("days_ago"))]
    if not suspects:
        return None
    names = ", ".join(p["name"] for p in suspects[:4])
    return Hypothesis(
        "recent_program",
        "Software installed just before the problem started",
        f"You said a program went in right before the trouble began. "
        f"{_plural(len(suspects), 'program')} installed in that window: {names}.",
        confidence=55,
        severity="medium",
        evidence_keys=["recent_programs"],
        actions=[task_action("pc_report", "Record the full software inventory for comparison.")],
        advice=("Uninstall the one you recognise as new, from Settings > Apps, and re-test. "
                "WinMend does not remove programs for you here because only you know which "
                "of these you still want."),
    )


# -- drivers and devices -----------------------------------------------------

@rule
def rule_gpu_driver(ctx):
    resets = ctx.get("gpu_resets", {})
    reset_count = resets.get("count", 0) if resets.get("available") else 0
    crashes = ctx.get("bugchecks", {}).get("crashes") or []
    gpu_codes = [c for c in crashes if "gpu" in (c.get("tags") or [])]
    app_gpu = [c for c in (ctx.get("app_crashes", {}).get("crashes") or [])
               if c.get("area") == "gpu"]

    confidence = 0
    signals = []
    driver_name = ""
    if reset_count >= 2:
        signals.append(f"the display driver reset {_plural(reset_count, 'time')} without a full crash")
        confidence += 45
        driver_name = next((e.get("driver") for e in resets.get("events", []) if e.get("driver")), "")
    if gpu_codes:
        signals.append(f"a {gpu_codes[0]['name']} stop code")
        confidence += 40
    if app_gpu:
        signals.append(f"apps crashing inside {app_gpu[0]['vendor'] or app_gpu[0]['module']}")
        confidence += 25
    if not signals or confidence < 35:
        return None
    vendor, _area = module_vendor(driver_name)
    return Hypothesis(
        "gpu_driver",
        f"The graphics driver is failing{f' ({vendor})' if vendor else ''}",
        "The graphics stack is misbehaving: " + "; ".join(signals) + ".",
        confidence=confidence,
        severity="high",
        evidence_keys=["gpu_resets", "bugchecks", "app_crashes"],
        actions=[task_action("gpu_diagnostic", "Check the graphics driver and recent display failures.")],
        advice=("Install the current driver directly from NVIDIA, AMD, or Intel rather than "
                "letting Windows Update pick one. If the resets continue on a clean driver, "
                "suspect the card's power delivery or heat."),
    )


@rule
def rule_problem_devices(ctx):
    devices = ctx.get("problem_devices", {})
    if not devices.get("available"):
        return None
    broken = devices.get("devices") or []
    if not broken:
        return None
    # Devices with no driver at all are noise on most PCs; a device Windows
    # actively stopped is not.
    serious = [d for d in broken if d.get("problem_code") in (10, 31, 43, 39, 19, 1, 3, 18, 52, 54)]
    if not ctx.audit and not ctx.parts & {"general", "devices", "crashes"}:
        classes = set()
        for area in ctx.parts:
            classes.update(DRIVER_CLASS_AREAS.get({"audio": "audio", "network": "network",
                           "bluetooth": "bluetooth", "storage": "storage"}.get(area, ""), ()))
        serious = [d for d in serious if str(d.get("class", "")).lower() in classes]
    if not serious:
        return None
    top = serious[0]
    return Hypothesis(
        "problem_devices",
        f"Windows has flagged a device: {top['name']}",
        f"{top['name']} is in a {top['status']} state with problem code {top['problem_code']} -- "
        f"{top['meaning']}"
        + (f" {_plural(len(serious) - 1, 'other device')} also flagged." if len(serious) > 1 else ""),
        confidence=85,
        severity="high" if top["problem_code"] in (43, 10, 54) else "medium",
        evidence_keys=["problem_devices"],
        actions=[task_action("pc_report", "Capture device status and driver evidence before changing this device."), repair_action(
            "reinstall_device",
            {"instance_id": top["instance_id"], "name": top["name"], "class": top.get("class", "")},
            title=f"Reinstall the driver for {top['name']}",
            reason=top["remedy"])],
        advice=("For device-reported faults, check the connection, power and a different port first. "
                "A persistent code does not identify the failed component; use the manufacturer's diagnostics. "
                "Driver-loading codes need package or signature investigation before reinstalling."),
    )


@rule
def rule_app_crash_module(ctx):
    """Name the component an app is actually dying inside."""
    crashes = ctx.get("app_crashes", {})
    if not crashes.get("available"):
        return None
    ranked = [c for c in crashes.get("crashes", []) if c.get("count", 0) >= 2 and c.get("module")]
    affected = set(ctx.interpretation.applications) - {"game", "games"}
    if affected:
        ranked = [c for c in ranked if str(c.get("app", "")).lower().removesuffix(".exe") in affected]
    if not ranked:
        return None
    top = ranked[0]
    module = top["module"]
    vendor = top.get("vendor") or ""
    own_fault = module.split(".")[0] == top["app"].split(".")[0]
    meaning = top.get("exception_meaning") or ""
    if own_fault:
        explanation = (f"{top['app']} has crashed {_plural(top['count'], 'time')} inside its own "
                       f"code ({module}).")
        advice = "Review that program's version, extensions and crash details. The recorded module is the failure location; it does not prove the underlying cause."
    else:
        explanation = (f"{top['app']} has crashed {_plural(top['count'], 'time')}, and each time "
                       f"the failure was inside {module}"
                       + (f" -- the {vendor}" if vendor else "") + ".")
        advice = (f"Inspect {vendor or 'the component that owns ' + module} and compare other crashes before updating it. "
                  "A shared failure module is an investigation lead; application inputs, dependencies and hardware remain alternatives.")
    if meaning:
        explanation += f" {meaning}"
    return Hypothesis(
        "app_crash_module",
        f"{top['app']} is crashing inside {module}",
        explanation,
        confidence=80,
        severity="medium",
        evidence_keys=["app_crashes"],
        actions=[task_action("reliability_monitor", "Review Windows' own timeline of these failures.")],
        advice=advice,
    )
