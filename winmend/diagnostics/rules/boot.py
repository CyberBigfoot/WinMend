"""WinMend diagnostics: rules: boot."""

from __future__ import annotations

from winmend.diagnostics.helpers import _plural
from winmend.diagnostics.models import Hypothesis, repair_action, task_action
from winmend.diagnostics.rules.registry import rule


# -- boot, power, and sleep --------------------------------------------------

@rule
def rule_safe_mode_stuck(ctx):
    """The PC is set to boot into Safe Mode every time.

    Almost always msconfig: the user ticked "Safe boot" to troubleshoot
    something, and the box that unticks it is inside the Windows they can no
    longer start normally.
    """
    boot = ctx.get("boot_config", {})
    if not boot.get("available") or not boot.get("safe_mode_forced"):
        return None
    return Hypothesis(
        "safe_mode_stuck",
        "This PC is set to start in Safe Mode every time",
        (f"The boot configuration carries safeboot={boot.get('safeboot')}. Windows will start "
         f"in Safe Mode on every restart until that is removed -- no amount of restarting "
         f"clears it. Almost everything looks broken in Safe Mode because almost nothing is "
         f"loaded: no sound, no networking on the minimal setting, and the wrong screen "
         f"resolution."),
        confidence=95, severity="critical",
        evidence_keys=["boot_config"],
        actions=[repair_action("clear_safe_boot", {},
                               reason="Remove the setting and restart normally.")],
        advice="After the restart, everything that appeared broken in Safe Mode comes back.",
    )


@rule
def rule_unsigned_drivers(ctx):
    """Driver signature enforcement is switched off."""
    boot = ctx.get("boot_config", {})
    if not boot.get("available"):
        return None
    if not (boot.get("test_signing") or boot.get("integrity_checks_off")):
        return None
    which = []
    if boot.get("test_signing"):
        which.append("test signing is on")
    if boot.get("integrity_checks_off"):
        which.append("integrity checks are off")
    return Hypothesis(
        "unsigned_drivers",
        "Unsigned drivers are allowed to load",
        (f"The boot configuration says {' and '.join(which)}. Windows will load kernel drivers "
         f"that nobody has signed. That is a deliberate developer setting on a development "
         f"machine; anywhere else it means something needed the check turned off to install "
         f"itself, and a kernel driver has complete control of the PC."),
        confidence=80, severity="high",
        evidence_keys=["boot_config"],
        actions=[task_action("sysinternals_autoruns",
                             "List what is loading at boot, including unsigned drivers."),
                 task_action("defender_scan", "Scan, since this state is what malware wants.")],
        advice=("If you turned this on yourself to install a driver, that is the explanation. "
                "If you did not, find out what needed it before turning it back on."),
    )


@rule
def rule_fast_startup_masking(ctx):
    """Fast startup is hiding the effect of shutting down.

    Only raised against a symptom. Fast startup is on by default on most PCs
    that shipped with Windows, so on its own it is a setting, not a fault -- it
    becomes one when the user describes exactly what it does.
    """
    fast = ctx.get("fast_startup", {})
    if not fast.get("available") or not fast.get("enabled"):
        return None
    # Silent in a full check. Fast startup is on by default on most PCs that
    # shipped with Windows, so with no complaint to explain it is a setting and
    # not a fault -- and in an audit ``ctx.parts`` holds every profile, so the
    # device-area test below would match on every healthy machine.
    if ctx.audit:
        return None
    reasons = []
    if ctx.answer("reboot_helps") == "yes":
        reasons.append("you said a restart helps for a while")
    if ctx.mentions("shut down", "shutdown", "shuts down", "wont turn off", "won't turn off",
                    "turn off", "start up", "startup", "boot"):
        reasons.append("the complaint is about shutting down or starting up")
    devices = ctx.get("problem_devices", {})
    if devices.get("available") and devices.get("devices"):
        reasons.append("a device is in a fault state, which a real shutdown often clears")
    if "usb" in ctx.query or "printer" in ctx.parts or "audio" in ctx.parts \
            or "bluetooth" in ctx.parts:
        reasons.append("device problems are exactly what a hibernated kernel carries over")
    if not reasons:
        return None
    return Hypothesis(
        "fast_startup_masking",
        "Shutting down is not actually clearing anything",
        ("Fast startup is on, so \"Shut down\" hibernates the Windows kernel instead of "
         "stopping it. Drivers and devices keep whatever state they were in, which is why a "
         "restart can fix something that a shutdown does not. "
         + "This matters here because " + ", and ".join(reasons) + "."),
        confidence=65, severity="medium",
        evidence_keys=["fast_startup"],
        actions=[repair_action("disable_fast_startup", {},
                               reason="Make shutting down really stop Windows.")],
        advice=("The cost is a few seconds longer to start. In exchange, shutting down becomes "
                "a real reset again, which is what most troubleshooting advice assumes."),
    )


@rule
def rule_wakes_itself(ctx):
    """The PC wakes itself up when nobody asked it to."""
    wake = ctx.get("wake_history", {})
    if not wake.get("available"):
        return None
    complained = ctx.mentions("wake", "wakes", "woke", "sleep", "sleeps", "hibernate",
                              "turns itself on", "turns on by itself")
    if not complained:
        return None
    last = wake.get("last_wake") or {}
    source = last.get("source", "")
    armed = wake.get("armed", 0) if wake.get("timers_readable") else 0
    if not source and not armed:
        return None
    parts = []
    if source:
        parts.append(f"the last thing to wake this PC was {source}")
    if armed:
        parts.append(f"{_plural(armed, 'scheduled wake timer')} armed")
    elif not wake.get("timers_readable"):
        parts.append("scheduled wake timers could not be listed without administrator rights")
    actions = []
    if armed:
        actions.append(repair_action(
            "disable_wake_timers", {},
            reason="Stop scheduled maintenance from waking the PC."))
    actions.append(task_action("power_plan_switcher", "Review the sleep settings."))
    return Hypothesis(
        "wakes_itself",
        "Something is waking this PC on its own",
        ("You described a PC that wakes up by itself, and " + "; ".join(parts) + ". "
         "A wake timer is scheduled maintenance -- usually Windows Update or a backup -- "
         "asking the PC to start up in the night. A device wake source is usually a mouse, "
         "a keyboard, or a network adapter set to wake the machine."),
        confidence=70 if armed else 50, severity="medium",
        evidence_keys=["wake_sources"],
        actions=actions,
        advice=("If a device is waking it, Device Manager > that device > Power Management > "
                "\"Allow this device to wake the computer\" is the switch. A mouse on a desk "
                "that gets knocked is the single most common cause."),
    )
