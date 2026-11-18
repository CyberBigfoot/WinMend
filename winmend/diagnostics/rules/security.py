"""WinMend diagnostics: rules: security."""

from __future__ import annotations

from winmend.diagnostics.models import Hypothesis, repair_action, task_action
from winmend.diagnostics.rules.registry import rule


# -- security ----------------------------------------------------------------

@rule
def rule_defender_off(ctx):
    item = ctx.evidence.get("defender")
    if item is None or item.get("status") != "bad":
        return None
    return Hypothesis(
        "defender_off",
        "Real-time protection is not running",
        f"Microsoft Defender reports: {item.get('value', 'protection disabled')}. "
        "Review the active protection provider and policy. This reading does not establish a malware infection.",
        confidence=85,
        severity="critical",
        evidence_keys=["defender"],
        actions=[repair_action("enable_realtime_protection",
                               title="Turn real-time protection back on",
                               reason=("Put live scanning back on before anything else, so a "
                                       "scan is not the only thing standing between this PC "
                                       "and whatever turned it off.")),
                 task_action("defender_scan", "Run a full malware scan."),
                 task_action("msrt_scan", "Run Microsoft's removal tool as a second opinion.")],
        advice=("If you installed a different antivirus, this is expected and fine. "
                "If you did not, treat it as a compromise until a scan says otherwise."),
    )


@rule
def rule_defender_exclusions(ctx):
    exclusions = ctx.get("defender_exclusions", {})
    if not exclusions.get("available"):
        return None
    broad = exclusions.get("overly_broad") or []
    if not broad:
        return None
    return Hypothesis(
        "defender_exclusions",
        "Defender has been told to ignore entire drives or folders",
        f"These scan exclusions are wide enough to hide anything inside them: "
        f"{', '.join(broad[:4])}. Adding a broad exclusion is a standard step for malware "
        "that wants to survive a scan.",
        confidence=75,
        severity="critical",
        evidence_keys=["defender_exclusions"],
        actions=[task_action("security_posture_report", "Record the full security configuration."),
                 task_action("defender_scan", "Run a full scan once the exclusions are removed.")],
        advice=("Remove these in Windows Security > Virus & threat protection > Exclusions, "
                "unless you added them deliberately for a game or development tool."),
    )


@rule
def rule_malware_symptoms(ctx):
    signs = ctx.answer("security_signs")
    if signs not in ("popups", "browser", "files"):
        return None
    if signs == "files":
        return Hypothesis(
            "ransomware_suspected",
            "Files renamed or encrypted -- treat as ransomware until proven otherwise",
            "You reported files being renamed, encrypted, or disappearing. That is the "
            "signature of ransomware, and it changes what should happen next.",
            confidence=70,
            severity="critical",
            evidence_keys=[],
            actions=[task_action("defender_scan", "Run a full scan.")],
            advice=("Disconnect this PC from the network and from any backup drive now, before "
                    "anything else. Do not pay. Do not overwrite the encrypted files -- a free "
                    "decryptor may exist later. Restore from a backup that was offline."),
            suppress=["clean_temp", "disk_cleanup", "component_cleanup", "windows_old_cleanup",
                      "defrag_optimize"],
            suppress_reason=("Withheld while ransomware is suspected: every one of these deletes "
                             "or overwrites data, which can destroy both evidence and any chance "
                             "of recovering the encrypted files."),
        )
    return Hypothesis(
        "adware_suspected",
        "The symptoms describe adware or a browser hijack",
        ("Pop-ups appearing on their own" if signs == "popups"
         else "A changed home page or search engine")
        + " is characteristic of adware rather than a Windows fault.",
        confidence=70,
        severity="high",
        evidence_keys=[],
        actions=[task_action("defender_scan", "Run a full malware scan."),
                 task_action("msrt_scan", "Run Microsoft's removal tool as a second opinion."),
                 task_action("scheduled_task_audit", "Look for scheduled tasks re-installing it."),
                 task_action("clear_browser_cache", "Clear the browser data it left behind.")],
        advice=("Also check the browser's own extension list -- most hijacks live there, and no "
                "system scan will remove an extension you approved."),
    )


# -- interview-only inferences ----------------------------------------------

@rule
def rule_safe_mode_clean(ctx):
    """Safe Mode is the cleanest software-vs-hardware split available."""
    if ctx.answer("safe_mode") != "no":
        return None
    return Hypothesis(
        "software_cause",
        "The cause is software, not hardware",
        "You said the problem does not happen in Safe Mode. Safe Mode loads only Microsoft's "
        "own core drivers and no startup programs, so a fault that disappears there is caused "
        "by a third-party driver, a startup program, or a service -- not by the hardware.",
        confidence=80,
        severity="medium",
        evidence_keys=[],
        actions=[task_action("disable_startup_apps",
                             "Narrow it down by removing startup programs from the picture.")],
        advice=("The standard way to find the culprit is to disable half the startup items and "
                "services, re-test, and halve again."),
    )


@rule
def rule_reboot_relief(ctx):
    if ctx.answer("reboot_helps") != "yes":
        return None
    if ctx.status("uptime") not in ("warn", "bad") and not ctx.evidence.get("memory"):
        return None
    return Hypothesis(
        "resource_leak",
        "Something is leaking resources while the PC runs",
        "A restart helps for a while and then the problem returns. That pattern means a "
        "program or service is accumulating memory, handles, or temporary files over time "
        "rather than a setting being wrong.",
        confidence=65,
        severity="medium",
        evidence_keys=["memory", "uptime", "top_memory"],
        actions=[task_action("pc_report", "Capture a full report while the symptom is present.")],
        advice=("The next time it slows down -- before restarting -- open Task Manager and sort "
                "by memory. Whatever sits at the top is the leak."),
    )
