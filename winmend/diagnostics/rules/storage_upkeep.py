"""WinMend diagnostics: rules: storage upkeep."""

from __future__ import annotations

from winmend.diagnostics.models import Hypothesis, repair_action, task_action
from winmend.diagnostics.reference import _EXPECTED_DISK_USERS
from winmend.diagnostics.rules.registry import rule


# -- storage upkeep ----------------------------------------------------------

@rule
def rule_trim_off(ctx):
    """An SSD that is not being told which blocks are free."""
    optimize = ctx.get("disk_optimization", {})
    if not optimize.get("available") or optimize.get("trim") is not False:
        return None
    reliability = ctx.get("disk_reliability", {})
    disks = reliability.get("disks") or []
    ssds = [d for d in disks if str(d.get("media", "")).upper() == "SSD"]
    if reliability.get("available") and disks and not ssds:
        # TRIM does nothing for a mechanical disk, so switching it off there is
        # not a fault and reporting it would be noise.
        return None
    return Hypothesis(
        "trim_off",
        "TRIM is switched off, so the SSD is getting slower",
        ("With TRIM disabled, Windows never tells the drive which blocks have been freed, so "
         "the drive keeps treating deleted data as live and has to shuffle it on every write. "
         "The effect is gradual: an SSD that felt fast when it was new gets slower over months "
         "for no reason any other check would show."),
        confidence=80, severity="medium",
        evidence_keys=["disk_optimization"],
        actions=[repair_action("enable_trim", {}, reason="Turn the free-block notifications on."),
                 repair_action("optimize_volume", {"drive": "C:"},
                               title="Retrim the system drive",
                               reason="Clear the backlog that built up while TRIM was off.")],
        advice="Turning it on stops the problem getting worse; the retrim clears the backlog.",
    )


@rule
def rule_volume_unhealthy(ctx):
    """Windows reports a volume as not healthy."""
    optimize = ctx.get("disk_optimization", {})
    unhealthy = optimize.get("unhealthy") or []
    if not optimize.get("available") or not unhealthy:
        return None
    listing = ", ".join(f"{v['drive']} ({v['health']}/{v['operational']})" for v in unhealthy)
    return Hypothesis(
        "volume_unhealthy",
        "Windows reports a volume as not healthy",
        (f"{listing}. This is Windows' own storage stack reporting the volume as damaged or "
         f"degraded, which is a different thing from a full disk -- it means the structure "
         f"itself has a problem."),
        confidence=85, severity="high",
        evidence_keys=["disk_optimization", "filesystem", "smart"],
        actions=[repair_action("check_disk", {"drive": unhealthy[0]["drive"]},
                               reason="Schedule a structural check of the volume."),
                 task_action("disk_smart_check", "Read the drive's own health report.")],
        advice=("Back up anything on that volume before repairing it. A volume Windows already "
                "calls unhealthy can get worse under a long repair pass."),
    )


@rule
def rule_bitlocker_suspended(ctx):
    """Encrypted, but with the key sitting in the clear."""
    locker = ctx.get("bitlocker_state", {})
    suspended = locker.get("suspended") or []
    if not locker.get("available") or not suspended:
        return None
    drives = ", ".join(volume["drive"] for volume in suspended)
    return Hypothesis(
        "bitlocker_suspended",
        f"Drive encryption is suspended on {drives}",
        (f"{drives} is still encrypted, but protection is suspended, which means the key is "
         f"stored unencrypted on the disk so Windows can start without asking for it. Anyone "
         f"who takes the drive can read everything on it -- the encryption is providing no "
         f"protection at all. A failed feature update or a firmware change is the usual reason "
         f"a PC is left like this, and nothing tells the user it happened."),
        confidence=90, severity="high",
        evidence_keys=["encryption"],
        actions=[repair_action("resume_bitlocker", {"drive": suspended[0]["drive"]},
                               title=f"Turn protection back on for {suspended[0]['drive']}",
                               reason="Stop the key being stored in the clear.")],
        advice=("Make sure you have the recovery key saved before resuming -- if the PC ever "
                "asks for it and you do not have it, the data is gone. It is in your Microsoft "
                "account at aka.ms/myrecoverykey if it was backed up there."),
    )


@rule
def rule_disk_hog(ctx):
    """One program is holding the disk at full tilt."""
    busy = ctx.get("top_disk_processes", {})
    busiest = busy.get("busiest") if busy.get("available") else None
    if not busiest:
        return None
    # Silent in a full check, for the same reason cpu_load is informational
    # there: a one-second sample taken while this sweep is itself reading the
    # disk measures the sweep as much as the machine. With no complaint to
    # explain, whatever happened to be busiest is not a finding.
    if ctx.audit:
        return None
    if "performance" not in ctx.parts and not ctx.mentions("disk", "100%", "freez", "slow"):
        return None
    latency = ctx.get("disk_latency", {})
    slow = bool(latency.get("available") and latency.get("avg_ms", 0) >= 25)
    rate = busiest.get("mb_per_sec", 0)
    if rate < 5 and not slow:
        return None
    name = busiest.get("name", "a program")
    if name.lower() in _EXPECTED_DISK_USERS:
        # Windows' own indexer, update stack, and antivirus are supposed to read
        # the disk hard, and they stop on their own. Naming one as the fault
        # sends the user to kill a service that will restart itself.
        return Hypothesis(
            "disk_busy_maintenance",
            f"Windows maintenance is using the disk ({name})",
            (f"{name} is reading and writing at {rate:.1f} MB/s"
             + (f", and disk responses are averaging {latency.get('avg_ms'):.0f} ms."
                if slow else ".")
             + " This is Windows' own upkeep -- indexing, scanning, or update work. It is "
               "meant to run when the PC is idle and it stops on its own, but on a mechanical "
               "disk it can make everything else crawl while it does."),
            confidence=65, severity="low",
            evidence_keys=["disk_activity", "disk_latency"],
            actions=[task_action("defrag_optimize", "Optimise the drive so upkeep costs less."),
                     task_action("pc_report", "Capture what is running if it never settles.")],
            advice=("Leave the PC on and idle for an hour or two after a big update -- this "
                    "work finishes and does not come back."),
        )
    return Hypothesis(
        "disk_hog",
        f"{name} is using the disk heavily",
        (f"{name} moved {rate:.1f} MB/s during a one-second sample"
         + (f", and disk responses are averaging {latency.get('avg_ms'):.0f} ms, which is slow "
            f"enough for the whole PC to feel stuck." if slow else ".")),
        confidence=60 if slow else 45, severity="medium" if slow else "low",
        evidence_keys=["disk_activity", "disk_latency"],
        actions=[repair_action("stop_process", {"name": name},
                               title=f"Close {name}",
                               reason="Stop it and see whether the PC frees up."),
                 task_action("pc_report", "Capture the full picture before changing anything.")],
        advice=("A single sample names a candidate, not a culprit. If closing it does not "
                "help, or it comes straight back, it was not the cause."),
    )
