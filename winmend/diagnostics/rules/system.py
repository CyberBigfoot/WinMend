"""WinMend diagnostics: rules: system."""

from __future__ import annotations

from winmend.diagnostics.helpers import _plural
from winmend.diagnostics.models import Hypothesis, repair_action, task_action
from winmend.diagnostics.rules.registry import rule
import os


# -- Windows state -----------------------------------------------------------

def _volume_named(ctx, drive):
    """One volume's row from the volumes collector, or None."""
    wanted = str(drive).rstrip("\\").upper()
    for volume in (ctx.get("volumes", {}).get("volumes") or []):
        if str(volume.get("drive", "")).rstrip("\\").upper() == wanted:
            return volume
    return None


@rule
def rule_disk_full(ctx):
    item = ctx.evidence.get("disk_free")
    if item is None or item.get("status") not in ("warn", "bad"):
        return None
    data = item.get("data") or {}
    free_pct = data.get("free_pct", 0)
    critical = item.get("status") == "bad"
    system = _volume_named(ctx, os.environ.get("SystemDrive", "C:"))
    reclaimable = (system or {}).get("recycle_gb") or 0
    return Hypothesis(
        "disk_full",
        "The system drive is running out of room",
        f"Only {item.get('value', '')} is free on the Windows drive. Below about 10%, Windows "
        "cannot stage updates, grow the page file, or write crash dumps, which shows up as "
        "slowness, failed updates, and apps refusing to start."
        + (f" {reclaimable:.1f} GB of that is deleted files still sitting in the Recycle Bin."
           if reclaimable >= 1 else ""),
        confidence=95,
        severity="critical" if critical else "medium",
        evidence_keys=["disk_free", "temp_size"],
        actions=([repair_action("empty_recycle_bin", {"drive": system["drive"]},
                                title=f"Empty the Recycle Bin on {system['drive']}",
                                reason=f"Reclaim the {reclaimable:.1f} GB of deleted files "
                                       f"still held there.")]
                 if reclaimable >= 1 else []
                 ) + [task_action("clean_temp", "Clear accumulated temporary data.")]
                 + ([task_action("disk_cleanup", "Let Windows remove update leftovers and caches."),
                     task_action("component_cleanup", "Compact the component store, often several GB."),
                     task_action("windows_old_cleanup", "Remove the previous Windows installation.")]
                    if critical else
                    [task_action("disk_cleanup", "Let Windows remove update leftovers and caches.")]),
        advice=("If cleanup does not free enough, use the Storage page to find what is actually "
                "using the drive -- it is usually a handful of very large folders."),
    )


@rule
def rule_component_corruption(ctx):
    store = ctx.get("component_store_health", {})
    if not store.get("available"):
        return None
    state = store.get("state")
    if state not in ("repairable", "unrepairable"):
        return None
    return Hypothesis(
        "component_corruption",
        "Windows' component store is damaged",
        "DISM reports the component store as "
        + ("repairable -- Windows can rebuild it from its own sources."
           if state == "repairable" else
           "damaged in a way its quick check cannot repair."),
        confidence=90,
        severity="high",
        evidence_keys=["component_store"],
        actions=[task_action("repair_system",
                             "Run the full DISM restore and system file check.")],
        advice=("Component corruption is the usual reason updates fail repeatedly and features "
                "vanish. Expect this repair to take a while."
                + (" If it cannot repair itself, an in-place upgrade install of Windows is the "
                   "next step -- it keeps files and programs." if state == "unrepairable" else "")),
    )


@rule
def rule_windows_eol(ctx):
    version = ctx.get("windows_version", {})
    if not version.get("available") or version.get("supported") is not False:
        return None
    return Hypothesis(
        "windows_eol",
        f"{version['label']} no longer receives updates",
        f"This PC runs {version['label']}, which stopped receiving security updates on "
        f"{version.get('eol', 'its end-of-service date')}. Every flaw found since then is "
        "unpatched, and new software increasingly will not run on it.",
        confidence=95,
        severity="high",
        evidence_keys=["windows_version"],
        actions=[task_action("windows_updates", "Check what Windows will offer to install.")],
        advice=("Upgrading to a supported version is the fix. This is worth doing even if it is "
                "not the cause of today's symptom."),
    )


@rule
def rule_pagefile_disabled(ctx):
    pagefile = ctx.get("pagefile", {})
    if not pagefile.get("available") or not pagefile.get("disabled"):
        return None
    return Hypothesis(
        "pagefile_disabled",
        "The page file is turned off",
        "Windows has no page file. This is usually done deliberately as a misguided "
        "'optimisation'; the effect is that programs fail to allocate memory, apps close "
        "without warning, and Windows cannot write a crash dump when it does fail.",
        confidence=90,
        severity="high",
        evidence_keys=["pagefile"],
        actions=[repair_action(
            "enable_pagefile", {},
            title="Let Windows manage the page file again",
            reason="Restore normal virtual-memory behaviour. Takes effect after a restart.")],
        advice="Even with plenty of RAM, Windows expects a page file to exist.",
    )


@rule
def rule_update_error(ctx):
    failures = ctx.get("update_failures", {})
    if not failures.get("available"):
        return None
    coded = [f for f in failures.get("failures", []) if f.get("code") and f.get("meaning")]
    if not coded:
        return None
    top = coded[0]
    actions = []
    if top.get("remedy") and top["remedy"] != "driver_rollback_hint":
        actions.append(task_action(top["remedy"], top["meaning"]))
    return Hypothesis(
        "update_error",
        f"Windows Update is failing with {top['code']}",
        f"The update log records {top['code']}: {top['meaning']}"
        + (f" ({_plural(len(coded), 'failure')} recorded.)" if len(coded) > 1 else ""),
        confidence=88,
        severity="high",
        evidence_keys=["update_failures"],
        actions=actions or [task_action("windows_update_forensic",
                                        "Inspect and repair the update service state.")],
        advice=("Error codes are the shortcut here: this one has a specific remedy, which is "
                "why it is listed ahead of the generic update repairs."),
    )


def match_startup_entry(name, entries):
    """Find the startup entry a boot-performance event refers to, if any.

    The Diagnostics-Performance log names whatever process was slow, which is
    frequently something Windows launches itself (WWAHost.exe hosts Store apps,
    for instance). Those are not startup entries and cannot be disabled as one,
    so an unmatched name means "do not offer to disable this", not "try anyway".
    """
    wanted = str(name or "").strip().lower()
    if not wanted:
        return None
    stem = wanted[:-4] if wanted.endswith(".exe") else wanted
    for entry in entries or ():
        if not entry.get("enabled"):
            continue
        entry_name = str(entry.get("name", "")).strip().lower()
        exe = os.path.basename(str(entry.get("exe", ""))).strip().lower()
        exe_stem = exe[:-4] if exe.endswith(".exe") else exe
        if wanted in (entry_name, exe) or stem in (entry_name, exe_stem):
            return entry
    return None


@rule
def rule_startup_bloat(ctx):
    item = ctx.evidence.get("startup")
    if item is None or item.get("status") not in ("warn", "bad"):
        return None
    boot = ctx.get("boot_history", {})
    slow = []
    if boot.get("available"):
        # Only apps (event 101). Services (103) are not startup entries, and
        # offering to disable one as if it were cannot work.
        slow = sorted((s for s in boot.get("slow", []) if s.get("kind") == "app"),
                      key=lambda s: s.get("degradation_s", 0), reverse=True)
    entries = (ctx.get("startup_entries", {}) or {}).get("entries") or []
    count = (item.get("data") or {}).get("count", 0)

    actions = []
    named = ""
    delay = 0.0
    matched = None
    for candidate in slow:
        if candidate.get("degradation_s", 0) < 2:
            break
        named = named or candidate.get("name", "")
        delay = delay or candidate.get("degradation_s", 0)
        found = match_startup_entry(candidate.get("name"), entries)
        if found is not None:
            matched = found
            named = candidate.get("name", "")
            delay = candidate.get("degradation_s", 0)
            break

    if matched is not None:
        actions.append(repair_action(
            "disable_startup_entry", {"name": matched["name"]},
            title=f"Stop {matched['name']} from starting with Windows",
            reason=f"Windows measured it delaying startup by {delay:.0f} seconds."))
    actions.append(task_action("disable_startup_apps",
                               "Review everything that launches at sign-in."))

    explanation = f"{_plural(count, 'program')} start automatically with Windows."
    if matched is not None:
        explanation += (f" Windows itself measured {matched['name']} as the worst offender it "
                        f"can act on, delaying startup by {delay:.0f} seconds.")
    elif named:
        # Still worth saying: it explains the slow boot even though this is not
        # something WinMend can switch off.
        explanation += (f" Windows measured {named} delaying startup by {delay:.0f} seconds, "
                        f"but that is a process Windows starts itself rather than a startup "
                        f"entry, so it cannot be switched off here.")
    return Hypothesis(
        "startup_bloat",
        "Too much starts automatically with Windows",
        explanation,
        confidence=70 if matched is not None else 55,
        severity="medium",
        evidence_keys=["startup", "boot_time"],
        actions=actions,
        advice=("Disabling a startup entry does not uninstall anything -- the program still "
                "runs when you open it."
                + ("" if matched is not None or not named else
                   f" If {named} is the real cost, it is Store apps loading at sign-in; "
                   f"reducing those is done from Settings > Apps > Startup.")),
    )


@rule
def rule_memory_pressure(ctx):
    item = ctx.evidence.get("memory")
    if item is None or item.get("status") not in ("warn", "bad"):
        return None
    top = ctx.get("top_memory_processes") or []
    if not top:
        return None
    worst = top[0]
    total_gb = (ctx.get("memory_config", {}) or {}).get("total_gb") or 0
    share = (worst["mb"] / 1024 / total_gb * 100) if total_gb else 0
    if share < 25:
        return None
    return Hypothesis(
        "memory_pressure",
        f"{worst['name']} is using most of the memory",
        f"Memory is at {item.get('value', 'high usage')}, and {worst['name']} alone holds "
        f"{worst['mb'] / 1024:.1f} GB -- about {share:.0f}% of the {total_gb:.0f} GB installed.",
        confidence=80,
        severity="medium",
        evidence_keys=["memory", "top_memory"],
        actions=[repair_action(
            "stop_process", {"name": worst["name"]},
            title=f"Close {worst['name']}",
            reason="Release the memory it is holding, so the effect can be measured directly.")],
        advice=("If this program is one you need, closing it is only a test. A browser with many "
                "tabs is the usual answer; if it is a background service, it may be leaking."),
    )


@rule
def rule_single_channel_memory(ctx):
    config = ctx.get("memory_config", {})
    if not config.get("available") or "performance" not in ctx.parts:
        return None
    if not config.get("single_channel") and not config.get("underclocked"):
        return None
    if config.get("single_channel"):
        return Hypothesis(
            "single_channel_memory",
            "Memory is running in single-channel mode",
            f"Only one memory module is installed ({config['total_gb']:.0f} GB in "
            f"{config['sticks'][0]['slot']}). A second matching module roughly doubles memory "
            "bandwidth, which is one of the largest cheap gains available on this PC.",
            confidence=90, severity="low", evidence_keys=["memory_config"],
            actions=[],
            advice="This is a hardware upgrade, not a repair -- nothing here is broken.",
        )
    return Hypothesis(
        "underclocked_memory",
        "Memory is running below its rated speed",
        f"The modules are rated for {config['rated_mhz']} MHz but are running at "
        f"{config['actual_mhz']} MHz, which is the default until the XMP/EXPO profile is "
        "enabled in the firmware.",
        confidence=85, severity="low", evidence_keys=["memory_config"],
        actions=[],
        advice="Enabling the memory profile in BIOS/UEFI recovers the speed you paid for.",
    )
