"""WinMend diagnostics: rules: updates."""

from __future__ import annotations

from winmend.diagnostics.helpers import _plural
from winmend.diagnostics.models import Hypothesis, repair_action, task_action
from winmend.diagnostics.rules.registry import rule


# -- Windows servicing -------------------------------------------------------

@rule
def rule_update_redirected(ctx):
    """Windows Update is pointed at a server instead of Microsoft."""
    policy = ctx.get("update_policy", {})
    if not policy.get("available") or not policy.get("redirected"):
        return None
    server = policy.get("wsus", "")
    failures = ctx.get("update_failures", {})
    failed = failures.get("count", 0) if failures.get("available") else 0
    return Hypothesis(
        "update_redirected",
        "Updates are being fetched from another server, not from Microsoft",
        (f"A policy points this PC at {server} for updates. On a managed work PC that is "
         f"correct. Anywhere else -- a laptop that has left a company, or a PC a script was run "
         f"on -- that server cannot be reached, and Windows reports being up to date while "
         f"receiving nothing at all."
         + (f" {_plural(failed, 'update failure')} recorded, which fits."
            if failed else "")),
        confidence=85, severity="high",
        evidence_keys=["update_policy", "update_state", "update_failures"],
        actions=[repair_action("clear_update_policy", {},
                               reason="Point Windows Update back at Microsoft."),
                 task_action("windows_updates", "Check for updates to confirm it works.")],
        advice=("If this is a work PC that is still managed, do not remove the policy -- ask "
                "IT. If it used to be a work PC and no longer is, removing it is the fix."),
    )


@rule
def rule_update_pinned(ctx):
    """Pinned to a Windows version it will never leave."""
    policy = ctx.get("update_policy", {})
    pinned = policy.get("pinned_version") if policy.get("available") else ""
    if not pinned:
        return None
    version = ctx.get("windows_version", {})
    eol = bool(version.get("available") and not version.get("supported", True))
    return Hypothesis(
        "update_pinned",
        f"This PC is pinned to Windows {pinned}",
        (f"A policy holds this PC on version {pinned}. It will take security updates for that "
         f"release and will never move past it"
         + (", and that release has already stopped receiving them." if eol else
            ", including past the day it stops being supported.")),
        confidence=85, severity="high" if eol else "medium",
        evidence_keys=["update_policy", "windows_version"],
        actions=[repair_action("clear_update_policy", {},
                               reason="Remove the version pin."),
                 task_action("windows_updates", "Let Windows offer the newer release.")],
    )


@rule
def rule_update_cache_stale(ctx):
    """Updates keep retrying against the same broken downloads."""
    cache = ctx.get("update_cache", {})
    if not cache.get("available") or not cache.get("stale"):
        return None
    failures = ctx.get("update_failures", {})
    failed = failures.get("count", 0) if failures.get("available") else 0
    state = ctx.get("update_state", {})
    if state.get("available") and state.get("blocked"):
        # Updates are switched off outright, so a stale cache is the consequence
        # of that rather than a separate fault. rule_update_blocked owns it.
        return None
    return Hypothesis(
        "update_cache_stale",
        "Windows Update is retrying against files that are already broken",
        (f"The download folder holds {cache.get('gb', 0):.1f} GB, and the oldest file in it is "
         f"{cache.get('oldest_days', 0):.0f} days old. Windows keeps resuming against those "
         f"same partial files, which is why a stuck update stays stuck no matter how many "
         f"times it is retried."
         + (f" {_plural(failed, 'install failure')} recorded in the update history."
            if failed else "")),
        confidence=75 if failed else 60, severity="medium",
        evidence_keys=["update_cache", "update_failures"],
        actions=[repair_action("clear_update_cache", {},
                              reason="Set the folder aside so Windows downloads fresh copies."),
                 task_action("windows_updates", "Retry the update afterwards.")],
        advice=("The old folder is renamed rather than deleted, so nothing is lost. You can "
                "delete it once updates are working again."),
    )


@rule
def rule_not_activated(ctx):
    """Windows is not activated."""
    licence = ctx.get("activation_state", {})
    if not licence.get("available") or not licence.get("known"):
        return None
    if licence.get("licensed"):
        return None
    return Hypothesis(
        "not_activated",
        "Windows is not activated",
        (f"Windows reports itself as {licence.get('state', 'not activated')}. Security updates "
         f"still install and the PC keeps working, but personalisation settings are locked and "
         f"a watermark sits over the desktop."),
        confidence=90, severity="low",
        evidence_keys=["activation"],
        actions=[task_action("activate_windows", "Open the activation troubleshooter.")],
        advice=("If this PC was activated before and stopped, a hardware change is the usual "
                "reason -- signing in with the Microsoft account the licence is linked to "
                "reactivates it."),
    )
