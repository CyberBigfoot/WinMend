"""WinMend diagnostics: rules: storage."""

from __future__ import annotations

from winmend.diagnostics.helpers import _plural
from winmend.diagnostics.models import Hypothesis, repair_action, task_action
from winmend.diagnostics.rules.registry import rule


# -- the wider sweep: faults a full check must be able to explain -------------
#
# Every rule below rests on one of the measurements added for the full check.
# Without them those measurements would still be reported, but only as bare
# "something is wrong here" rows with no account of what it means or what to do,
# which is the shape of finding the engine was written to avoid.

@rule
def rule_dirty_filesystem(ctx):
    """Windows has marked a volume as damaged and not yet repaired it."""
    filesystem = ctx.evidence.get("filesystem")
    if not filesystem or filesystem.get("status") != "bad":
        return None
    data = filesystem.get("data") or {}
    flagged = sorted(set(data.get("scheduled") or []) | set(data.get("dirty") or []))
    if not flagged:
        return None
    drives = ", ".join(flagged)
    scheduled = bool(data.get("scheduled"))
    return Hypothesis(
        "dirty_filesystem",
        f"The file system on {drives} needs a consistency review",
        (f"Windows has set the dirty bit on {drives}"
         + (" and already queued a disk check for the next restart" if scheduled else "")
         + ". A dirty flag can follow an unclean shutdown or an inconsistency; it is not proof of structural damage or a failing drive."),
        confidence=90,
        severity="high",
        evidence_keys=["filesystem"],
        actions=[repair_action("check_disk", {"drive": flagged[0]},
                               title=f"Repair the file system on {flagged[0]}",
                               reason=("Try the online repair first, and only schedule the "
                                       "boot-time check if that is not enough.")),
                 task_action("chk_dsk",
                             "Run the disk check that clears the flag and repairs the damage.")],
        advice=("The online scan needs no restart. If it cannot finish the repair, the "
                "boot-time check can take a long time on a large drive -- do not interrupt it "
                "once it starts."),
    )


@rule
def rule_secondary_volume_full(ctx):
    """A data drive filling up breaks saves and installs while C: looks fine."""
    finding = ctx.evidence.get("volumes")
    if not finding or finding.get("status") not in ("warn", "bad"):
        return None
    others = (finding.get("data") or {}).get("others") or []
    tight = sorted((v for v in others if v["free_pct"] < 12),
                   key=lambda v: v["free_pct"])
    if not tight:
        return None
    worst = tight[0]
    name = f"{worst['drive']} {worst['label']}".strip()
    # The bin was measured on this drive precisely because it is short of room.
    # Offering to empty an empty bin is the kind of advice that teaches people
    # to stop reading the plan.
    reclaimable = worst.get("recycle_gb")
    return Hypothesis(
        "secondary_volume_full",
        f"{name} is nearly full",
        (f"{name} has {worst['free_gb']:.0f} GB free of {worst['total_gb']:.0f} GB "
         f"({worst['free_pct']:.0f}%)"
         + (f", and {_plural(len(tight) - 1, 'other drive')} in the same state"
            if len(tight) > 1 else "")
         + ". The system drive is measured separately, so this is the one thing on this PC "
           "that is short of room."
         + (f" {reclaimable:.1f} GB of it is deleted files still sitting in that drive's "
            f"Recycle Bin." if reclaimable and reclaimable >= 1 else
            " Its Recycle Bin is already empty, so the space is going on real files."
            if reclaimable is not None else "")),
        confidence=95,
        severity="medium" if worst["free_pct"] >= 5 else "high",
        evidence_keys=["volumes"],
        actions=([repair_action("empty_recycle_bin", {"drive": worst["drive"]},
                                title=f"Empty the Recycle Bin on {worst['drive']}",
                                reason=(f"Reclaim the {reclaimable:.1f} GB of deleted files "
                                        f"still held on that drive."))]
                 if reclaimable and reclaimable >= 1 else []
                 ) + [task_action("storage_sence",
                                  f"See what is actually using {worst['drive']}."),
                      task_action("disk_cleanup", f"Free space, then check {worst['drive']} again.")],
        advice=("Windows keeps a separate Recycle Bin per drive, so emptying it from the "
                "desktop does not necessarily touch this one. The Storage Analyzer shows what "
                "is taking the rest of the room, which is faster than guessing."),
    )


@rule
def rule_drive_wear(ctx):
    """A drive can be worn out or logging errors while SMART still says healthy."""
    reliability = ctx.get("disk_reliability", {})
    if not reliability.get("available") or not reliability.get("counters_readable"):
        return None
    signals = []
    confidence = 0
    for disk in reliability.get("disks") or []:
        wear = disk.get("wear_pct")
        errors = (disk.get("read_errors") or 0) + (disk.get("write_errors") or 0)
        if wear is not None and wear >= 80:
            signals.append(f"{disk['name']} has used {wear}% of its rated write life")
            confidence += 50 if wear >= 90 else 35
        if errors:
            signals.append(f"{disk['name']} reports {_plural(errors, 'uncorrected error')}")
            confidence += 45
        health = (disk.get("health") or "").lower()
        if health and health not in ("healthy", ""):
            signals.append(f"{disk['name']} reports itself as {disk['health']}")
            confidence += 40
    if not signals:
        return None
    return Hypothesis(
        "drive_wear",
        "A drive is wearing out or logging errors",
        "Read from the drive's own counters: " + "; ".join(signals) + ".",
        confidence=confidence,
        severity="high",
        evidence_keys=["drive_wear", "smart"],
        actions=[task_action("disk_smart_check", "Read the full health data for that drive.")],
        advice=("Wear and uncorrected errors do not repair themselves. Make sure anything "
                "irreplaceable on that drive is backed up somewhere else."),
        suppress=["defrag_optimize"],
        suppress_reason=("Withheld on a worn drive: defragmentation rewrites a large part of the "
                         "disk, which spends write life the drive has little of left."),
    )
