"""WinMend diagnostics: rules: upkeep."""

from __future__ import annotations

from winmend.diagnostics.helpers import _plural
from winmend.diagnostics.models import Hypothesis, repair_action, task_action
from winmend.diagnostics.repairs.power import _BALANCED_SCHEME
from winmend.diagnostics.rules.registry import rule


@rule
def rule_critical_service_stopped(ctx):
    """A service that is supposed to always be running, is not."""
    services = ctx.get("service_health", {})
    if not services.get("available"):
        return None
    broken = services.get("critical_stopped") or []
    if not broken:
        return None
    disabled = [s for s in broken if s.get("disabled")]
    listing = "; ".join(f"{s['display']} ({s['why'].split('--')[-1].strip()})"
                        for s in broken[:3])
    return Hypothesis(
        "critical_service_stopped",
        f"{_plural(len(broken), 'essential service')} not running",
        (f"{listing}."
         + (f" {_plural(len(disabled), 'one of them is')} set to Disabled, so it will not start "
            f"on its own -- that is a change someone or something made, not a crash."
            if disabled else " These are meant to run continuously.")),
        confidence=90,
        severity="high",
        evidence_keys=["services"],
        # A disabled service and a stopped one are the same symptom and
        # different repairs: starting a disabled service works exactly once,
        # until the next restart puts it back where someone left it.
        actions=[repair_action(
            "set_service_startup" if service.get("disabled") else "restart_service",
            ({"name": service["name"], "start": "auto"} if service.get("disabled")
             else {"name": service["name"]}),
            title=(f"Re-enable and start {service['display']}" if service.get("disabled")
                   else f"Start {service['display']}"),
            reason=("It is set to Disabled, so it has to be set back to starting on its own "
                    "before starting it means anything." if service.get("disabled")
                    else "Start the service and see whether it stays up."),
        ) for service in broken[:3]] + [
            task_action("service_dependency_repair",
                        "Repair the service configuration and its dependencies.")],
    )


@rule
def rule_maintenance_task_failing(ctx):
    """Windows' own upkeep has quietly stopped running."""
    tasks = ctx.get("scheduled_tasks", {})
    if not tasks.get("available"):
        return None
    failing = tasks.get("maintenance_failures") or []
    if not failing:
        return None
    leaves = [t["task"].rsplit("\\", 1)[-1] for t in failing]
    names = ", ".join(leaves[:3])
    # Say what each failure costs, rather than a general sentence about upkeep.
    # These tasks do quite different jobs, and "restore points are not being
    # created" is a different problem from "SSDs are never retrimmed".
    effects = [t.get("consequence") for t in failing[:3] if t.get("consequence")]
    # Only the tasks Windows can start without its own arguments are worth
    # offering to run. The rest are reported and explained.
    startable = [(t, leaf) for t, leaf in zip(failing, leaves) if t.get("runnable")]
    return Hypothesis(
        "maintenance_task_failing",
        f"{_plural(len(failing), 'Windows maintenance task')} failing",
        (f"{names} failed at the last run ({failing[0]['code']}). "
         + ("While that lasts, " + "; ".join(effects) + "." if effects else
            "These are the tasks that keep the PC maintained on its own.")
         + " Nothing reports this at the time -- it shows up weeks later as something else."),
        confidence=80,
        severity="medium",
        evidence_keys=["scheduled_tasks"],
        actions=([repair_action("run_scheduled_task", {"task": startable[0][0]["task"]},
                                title=f"Run {startable[0][1]} now",
                                reason=("Running it now separates a one-off failure from one "
                                        "that repeats, and the second is the one worth chasing."))]
                 if startable else []
                 ) + [task_action("scheduled_task_audit",
                                  "List the failing tasks and what they were supposed to do.")],
    )


@rule
def rule_active_threat(ctx):
    """Defender found something and did not finish dealing with it."""
    threats = ctx.get("defender_threats", {})
    if not threats.get("available"):
        return None
    unresolved = threats.get("unresolved") or []
    if not unresolved:
        return None
    worst = unresolved[0]
    return Hypothesis(
        "active_threat",
        "Malware Defender found but did not remove",
        (f"{worst['name']} is recorded as {worst['state']}"
         + (f", {worst['days_ago']:.0f} days ago" if worst.get("days_ago") is not None else "")
         + (f", along with {_plural(len(unresolved) - 1, 'other detection')}"
            if len(unresolved) > 1 else "")
         + ". A detection in that state is still present on this PC."),
        confidence=90,
        severity="critical",
        evidence_keys=["threats"],
        actions=[repair_action("remove_threats", title="Finish removing what Defender found",
                               reason=("Defender already knows what these are; this asks it to "
                                       "complete the removal it stopped part-way through.")),
                 task_action("defender_scan", "Run a full scan and let it complete the removal."),
                 task_action("msrt_scan", "Follow with the Malicious Software Removal Tool.")],
        advice=("If the same item keeps coming back after removal, something is putting it "
                "there again -- check startup entries and scheduled tasks next."),
    )


@rule
def rule_uac_disabled(ctx):
    """UAC off is the setting that most changes what a mistake can cost."""
    uac = ctx.get("uac_state", {})
    if not uac.get("available"):
        return None
    if uac.get("enabled") and not uac.get("never_notifies"):
        return None
    off = not uac.get("enabled")
    return Hypothesis(
        "uac_disabled",
        "User Account Control is turned off" if off else "User Account Control never asks",
        ("Every program started on this PC runs with full administrator rights and nothing "
         "asks first." if off else
         "UAC is switched on but set to elevate silently, so administrator rights are granted "
         "without a prompt. The effect is close to having it off."),
        confidence=95,
        severity="high" if off else "medium",
        evidence_keys=["uac"],
        actions=[task_action("security_posture_report",
                             "Record the current security settings before changing them."),
                 repair_action("enable_uac", title="Turn User Account Control back on",
                               reason=("Set it back to the Windows default: ask before a "
                                       "program is given administrator rights."))],
        advice=("This takes effect after a restart. If a program then starts prompting every "
                "time you open it, that program was relying on running as administrator "
                "silently -- which is the thing UAC exists to tell you about."),
    )


@rule
def rule_firewall_off(ctx):
    """A firewall profile that is off, named rather than counted.

    ``_unexplained`` used to cover this, which meant the offer was a report on
    the firewall rather than a way to turn it back on.
    """
    profiles = ctx.get("firewall_profiles", {})
    if not profiles.get("available"):
        return None
    off = profiles.get("disabled") or []
    allow = profiles.get("allow_inbound") or []
    if not off and not allow:
        return None
    affected = sorted(set(off) | set(allow))
    public = "Public" in affected
    return Hypothesis(
        "firewall_off",
        f"The {', '.join(affected)} firewall profile"
        + ("s are" if len(affected) > 1 else " is") + " not protecting this PC",
        ((f"{', '.join(off)} is switched off. " if off else "")
         + (f"{', '.join(allow)} is switched on but set to allow every inbound connection, "
            f"which looks healthy in Windows Security and is not. " if allow else "")
         + ("The Public profile is the one that applies on cafe, hotel, and airport networks, "
            "so this is the profile that matters most." if public else
            "Windows applies one profile at a time, depending on the network this PC is on.")),
        confidence=95,
        severity="high" if public else "medium",
        evidence_keys=["firewall"],
        actions=[repair_action("enable_firewall", {"profiles": affected},
                               title=f"Turn the {', '.join(affected)} profile"
                                     + ("s" if len(affected) > 1 else "") + " back on",
                               reason=("Enable the profile and block unrequested inbound "
                                       "connections. Outbound traffic is left exactly as it is.")),
                 task_action("security_posture_report",
                             "Record the full security configuration afterwards.")],
        advice=("If a third-party security suite is installed, it normally turns the Windows "
                "firewall off on purpose and this is expected."),
    )


@rule
def rule_no_protection(ctx):
    """Nothing to roll back to -- including from WinMend's own repairs."""
    points = ctx.get("restore_points", {})
    if not points.get("available"):
        return None
    items = points.get("points") or []
    protection = points.get("protection")
    if items and protection is not False:
        return None
    if not items and protection is None:
        # Protection state could not be read and there are simply no points.
        # That is worth offering, not worth asserting anything about.
        return None
    return Hypothesis(
        "no_protection",
        ("System Protection is turned off" if protection is False
         else "There is no restore point to go back to"),
        (("System Restore is disabled, so Windows is not keeping checkpoints. Nothing on this "
          "PC -- including WinMend's own repairs -- has a one-click way back."
          if protection is False else
          "System Protection is on but has never produced a restore point, so there is still "
          "nothing to roll back to.")
         + (f" There {'is' if len(items) == 1 else 'are'} {_plural(len(items), 'point')} on disk."
            if items else "")),
        confidence=90,
        severity="medium",
        evidence_keys=["restore_points"],
        actions=[repair_action("enable_system_restore",
                               title="Turn System Protection back on",
                               reason=("Enable it and take a first checkpoint, so there is "
                                       "something to return to before anything else changes.")),
                 task_action("create_restore_point_guardrail",
                             "Keep a named checkpoint of the current state.")],
        advice=("This is worth doing before the rest of a repair plan rather than after it. "
                "Restore points cost disk space and nothing else."),
    )


@rule
def rule_power_saver(ctx):
    """The invisible reason a PC 'got slow'."""
    power = ctx.get("power_config", {})
    if not power.get("available") or not power.get("power_saver"):
        return None
    # On battery this is the correct setting and none of WinMend's business.
    if power.get("on_battery"):
        return None
    laptop = power.get("has_battery")
    return Hypothesis(
        "power_saver",
        "The Power saver plan is capping this PC",
        (f"The active power plan is {power.get('name', 'Power saver')}, which holds the "
         f"processor well below its rated speed"
         + (" even though this laptop is plugged in" if laptop else " on a desktop")
         + ". Nothing in Windows reports this as a problem, and it is one of the few settings "
           "that slows everything down at once."),
        confidence=85,
        severity="medium",
        evidence_keys=["power_plan"],
        actions=[repair_action("set_power_plan", {"scheme": _BALANCED_SCHEME},
                               title="Switch back to the Balanced plan",
                               reason="Let the processor run at its normal speed again.")],
        advice=("Balanced is the Windows default and still steps the processor down when the "
                "PC is idle -- it is not the same as forcing full speed all the time."),
    )


@rule
def rule_update_blocked(ctx):
    """Updates cannot run at all -- usually left behind by a debloat script."""
    state = ctx.get("update_state", {})
    if not state.get("available") or not state.get("blocked"):
        return None
    policies = state.get("policies") or []
    disabled = [name for name, entry in (state.get("services") or {}).items()
                if entry.get("disabled")]
    if not policies and not disabled:
        return None
    reason = (policies[0]["meaning"] if policies
              else f"the {disabled[0]} service is set to Disabled")
    return Hypothesis(
        "update_blocked",
        "Windows Update cannot run",
        (f"This PC will not receive updates because {reason}. Windows does not report this "
         f"as an error -- the update page simply never finds anything, which looks the same "
         f"as being up to date."),
        confidence=90,
        severity="high",
        evidence_keys=["update_state"],
        actions=[repair_action("unblock_updates", title="Let Windows Update run again",
                               reason=("Remove the policy values, the pause, and the disabled "
                                       "services that are stopping it -- and record them so "
                                       "the block can be put back.")),
                 task_action("reset_win_update",
                             "Reset the update components if it still finds nothing."),
                 task_action("windows_updates", "Then check for updates.")],
        advice=("Tools that 'debloat' or 'de-telemetry' Windows commonly do this. If that was "
                "deliberate, nothing here needs fixing -- but the security fixes stop too."),
    )


@rule
def rule_clock_drift(ctx):
    """A wrong clock presents as half a dozen unrelated-looking failures."""
    clock = ctx.get("time_sync", {})
    if not clock.get("available"):
        return None
    offset = clock.get("offset_seconds")
    if offset is None or abs(offset) < 60:
        return None
    drift = abs(offset)
    return Hypothesis(
        "clock_drift",
        "The system clock is wrong",
        (f"This PC's clock is {'ahead of' if offset < 0 else 'behind'} real time by "
         f"{drift / 60:.0f} minutes, measured against {clock.get('source', 'an internet time server')}"
         + (f", and the Windows Time service is {clock['service']}"
            if clock.get("service") in ("stopped", "unknown") else "")
         + ". Secure websites, Windows Update, and sign-in all reject a clock this far out, "
           "which is why the symptom is usually 'the internet is broken'."),
        confidence=95,
        severity="high" if drift >= 300 else "medium",
        evidence_keys=["time_sync"],
        actions=[repair_action("sync_clock", title="Correct the clock",
                               reason=("Start the Windows Time service and resynchronise "
                                       "against an internet time server.")),
                 task_action("time_sync_fix", "Resynchronise the clock and start the time service.")],
        advice=("A clock that drifts again within days is usually a dead CMOS battery on the "
                "motherboard."),
    )


@rule
def rule_temporary_profile(ctx):
    """The user's files look deleted, and are not."""
    profile = ctx.get("user_profile", {})
    if not profile.get("available") or not profile.get("temporary"):
        return None
    return Hypothesis(
        "temporary_profile",
        "You are signed in to a temporary profile",
        ("Windows could not load the normal user profile at sign-in and created an empty one "
         "instead. The desktop, documents, and settings look wiped, and anything saved during "
         "this session is thrown away at sign-out. The real profile is still on the disk."),
        confidence=95,
        severity="critical",
        evidence_keys=["user_profile"],
        actions=[task_action("pc_report", "Capture the profile state before making any changes."),
                 repair_action("restore_profile",
                               title="Point this account back at its real profile",
                               reason=("Swap the profile list entry back to the real profile. "
                                       "It checks the real folder is still on the disk first, "
                                       "and keeps a copy of the temporary entry."))],
        advice=("Do not save anything new until this is fixed. Restart first on its own -- "
                "Windows often loads the real profile at the next attempt without any of this. "
                "If it does not, the repair above is the same swap done by hand, with the "
                "before state kept so it can be undone."),
    )


@rule
def rule_no_route(ctx):
    """Nothing can be reached because nothing has a way out."""
    if ctx.status("tcp_connectivity") == "good":
        return None
    config = ctx.get("network_config", {})
    if not config.get("available"):
        return None
    interfaces = config.get("interfaces") or []
    if not interfaces or config.get("has_route"):
        return None
    self_assigned = config.get("self_assigned_only")
    return Hypothesis(
        "no_route",
        ("This PC never got an address from the router" if self_assigned
         else "This PC has no way out of the local network"),
        (("Every network adapter is on a 169.254 self-assigned address, which is what Windows "
          "falls back to when no DHCP server answers. The PC can see the cable or the Wi-Fi, "
          "and nothing beyond it." if self_assigned else
          "The adapters have addresses but there is no default gateway, so nothing outside "
          "this network can be reached.")),
        confidence=90,
        severity="high",
        evidence_keys=["ip_config", "reachability"],
        actions=[repair_action("renew_lease", title="Ask the router for an address again",
                               reason=("Renew the lease, and release it first only if the "
                                       "renewal on its own gets the same answer back.")),
                 task_action("network_adapter_reset", "Reset the adapter and request a new address."),
                 task_action("ipconfig_all", "Record the full addressing state for comparison.")],
        advice=("If a restart of the router fixes it, DHCP on the router is the thing at fault, "
                "not this PC."),
    )


@rule
def rule_link_errors(ctx):
    """A bad cable or port, which nothing else in Windows reports."""
    link = ctx.get("adapter_health", {})
    if not link.get("available"):
        return None
    degraded = link.get("degraded") or []
    if not degraded:
        return None
    worst = max(degraded, key=lambda a: a["error_pct"])
    return Hypothesis(
        "link_errors",
        f"{worst['name']} is losing packets at the adapter",
        (f"{worst['error_pct']}% of the {worst['packets']:,} packets through {worst['name']} "
         f"since the last restart were dropped or errored. That is counted by the adapter "
         f"itself, so it is below anything a speed test or a ping measures."),
        confidence=75,
        severity="medium",
        evidence_keys=["link_health"],
        actions=[repair_action("reset_adapter", {"name": worst["name"]},
                               title=f"Restart the {worst['name']} adapter",
                               reason=("Renegotiate the link. The error counters restart from "
                                       "zero, so the next reading measures the link from now "
                                       "rather than since the last boot.")),
                 task_action("network_adapter_reset", "Reset the adapter and re-measure.")],
        advice=("If the rate stays high after a reset, swap the cable and then the port. On "
                "Wi-Fi, this is usually distance or interference rather than hardware."),
    )


@rule
def rule_print_spooler(ctx):
    """Printing is broken in one of the two ways it is ever broken."""
    printers = ctx.get("printers", {})
    if not printers.get("available"):
        return None
    installed = printers.get("printers") or []
    if not installed:
        return None
    stopped = printers.get("spooler") == "stopped"
    offline = printers.get("default_offline") or []
    if not stopped and not offline:
        return None
    return Hypothesis(
        "print_spooler",
        "The print spooler is stopped" if stopped else "The default printer is offline",
        ("The Print Spooler service is not running, so nothing can be printed and no printer "
         "will appear as available." if stopped else
         f"{offline[0]['name']} is set as the default printer and reports itself offline. "
         f"Jobs sent to it queue up and never print."),
        confidence=90 if stopped else 75,
        severity="medium",
        evidence_keys=["printers"],
        actions=([repair_action("restart_service", {"name": "Spooler"},
                                title="Start the Print Spooler service",
                                reason="Start the service that queues print jobs.")]
                 if stopped else []
                 ) + [task_action("clear_print_spooler",
                                  "Clear the stuck queue and restart the spooler.")],
    )


@rule
def rule_search_broken(ctx):
    """Search is measurable now, so a search complaint can finally be verified."""
    search = ctx.get("search_index", {})
    if not search.get("available") or search.get("healthy"):
        return None
    if search.get("disabled"):
        if ctx.audit:
            # Switched off, not broken -- WinMend's RAM Optimizations does it on
            # purpose. With no one complaining about search, a deliberate
            # setting is not a fault; the full check used to call it "broken"
            # at 85% and offer a start that cannot work on a disabled service.
            return None
        return Hypothesis(
            "search_broken",
            "Windows Search is switched off",
            "The Windows Search service is set to Disabled, so it never starts, and the Start "
            "menu and File Explorer search have nothing to read from. Tools that save memory "
            "switch it off on purpose -- WinMend's RAM Optimizations among them.",
            confidence=90,
            severity="medium",
            evidence_keys=["search_index"],
            actions=[repair_action("set_service_startup", {"name": "WSearch", "start": "auto"},
                                   title="Turn Windows Search back on",
                                   reason="Set it back to starting on its own and start it; "
                                          "the index then catches up by itself.")],
            advice="The index takes a while to catch up; search is incomplete until it does.",
        )
    stopped = search.get("service") != "running"
    return Hypothesis(
        "search_broken",
        "Windows Search is not working",
        ("The Windows Search service is not running, so the Start menu and File Explorer "
         "search have nothing to read from and return nothing." if stopped else
         "The search index was never built successfully, so searches return nothing or miss "
         "most of what is on the PC."),
        confidence=85,
        severity="medium",
        evidence_keys=["search_index"],
        actions=([repair_action("restart_service", {"name": "WSearch"},
                                title="Start the Windows Search service",
                                reason="Start the service the Start menu searches through.")]
                 if stopped else []
                 ) + [task_action("reset_search_index", "Rebuild the search index from scratch.")],
        advice="Rebuilding the index takes a while, and search is incomplete until it finishes.",
    )


@rule
def rule_cpu_hog(ctx):
    """One program is holding the machine down.

    Only offered when the user came in complaining about speed. In a full check
    there is no complaint to explain, and a one-second sample cannot tell a
    program that is working hard from one that is stuck -- so a proactive
    "something is using your CPU" would be a guess wearing a verdict's clothes.
    """
    if ctx.audit or "performance" not in ctx.parts or ctx.status("resource_cpu") != "bad":
        return None
    cpu = ctx.get("cpu_load", {})
    if not cpu.get("available"):
        return None
    hog = cpu.get("hog")
    if not hog or cpu.get("used_pct", 0) < 80:
        return None
    return Hypothesis(
        "cpu_hog",
        f"{hog['name']} is using most of the processor",
        (f"{hog['name']} was holding {hog['pct']:.0f}% of the whole processor while the PC "
         f"was at {cpu.get('used_pct', 0):.0f}%. Everything else has to wait for what is left, "
         f"which is what a PC that has 'got slow' usually is."),
        confidence=70,
        severity="medium",
        evidence_keys=["cpu_load"],
        actions=[repair_action("stop_process", {"name": hog["name"]},
                               title=f"Stop {hog['name']}",
                               reason="Stop it and see whether the PC responds normally again.")],
        advice=("If it comes straight back, it is being restarted by something -- a startup "
                "entry, a service, or a scheduled task."),
    )
