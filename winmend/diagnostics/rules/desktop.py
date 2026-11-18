"""WinMend diagnostics: rules: desktop."""

from __future__ import annotations

from winmend.diagnostics.helpers import _plural
from winmend.diagnostics.models import Hypothesis, repair_action, task_action
from winmend.diagnostics.rules.registry import rule


# -- apps, shell, and devices ------------------------------------------------

@rule
def rule_broken_store_apps(ctx):
    """Store apps Windows itself reports as damaged."""
    appx = ctx.get("appx_health", {})
    if not appx.get("available"):
        return None
    broken = appx.get("broken") or []
    missing = appx.get("missing") or []
    if not broken and not missing:
        return None
    if broken:
        names = ", ".join(entry["name"] for entry in broken[:3])
        return Hypothesis(
            "broken_store_apps",
            f"{_plural(len(broken), 'Store app')} damaged",
            (f"Windows reports {names} as not being in a good state. A damaged package cannot "
             f"start -- it bounces once and closes with no message -- and the Store cannot "
             f"repair it, because as far as the Store is concerned it is already installed."),
            confidence=85, severity="medium",
            evidence_keys=["store_apps"],
            actions=[repair_action("reregister_app", {"name": broken[0]["name"]},
                                   title=f"Repair {broken[0]['name']}",
                                   reason="Register it again against the files it has.")]
                    + [task_action("uwp_app_reset", "Re-register every Store app if more than "
                                                    "one is affected.")],
        )
    return Hypothesis(
        "store_removed",
        f"{', '.join(missing)} is not installed",
        (f"{', '.join(missing)} is part of Windows and is missing from this PC. It is almost "
         f"always a \"debloat\" script that removed it -- and once the Store itself is gone, "
         f"nothing can be installed from it and some Windows features stop working."),
        confidence=80, severity="medium",
        evidence_keys=["store_apps"],
        actions=[task_action("uwp_app_reset", "Re-register the built-in packages.")],
        advice=("If you ran a debloat script and meant to remove these, this is working as you "
                "asked. If you did not, re-registering usually brings them back."),
    )


@rule
def rule_shell_stopped(ctx):
    """Explorer is not running, so there is no desktop."""
    shell = ctx.get("shell_health", {})
    if not shell.get("available"):
        return None
    if shell.get("explorer_running"):
        if not shell.get("icon_cache_large"):
            return None
        return Hypothesis(
            "icon_cache_bloated",
            "The icon cache has grown large enough to misbehave",
            (f"The icon and thumbnail cache is {shell.get('icon_cache_mb', 0):.0f} MB. Past a "
             f"few hundred megabytes it starts returning the wrong picture or none at all, "
             f"which is why icons go blank or show another program's logo."),
            confidence=70, severity="low",
            evidence_keys=["shell"],
            actions=[task_action("rebuild_icon_cache", "Clear the cache and restart Explorer.")],
        )
    return Hypothesis(
        "shell_stopped",
        "Explorer is not running",
        ("The desktop, the taskbar, and the Start menu are all drawn by Explorer, and it is "
         "not running. Programs already open keep working; there is just nothing to launch "
         "anything new from."),
        confidence=85, severity="high",
        evidence_keys=["shell"],
        actions=[repair_action("restart_explorer", {},
                               reason="Bring the desktop and taskbar back.")],
        advice=("If it stops again straight away, a shell extension from another program is "
                "usually the cause -- start the PC in Safe Mode and it will stay up."),
    )


@rule
def rule_audio_dead(ctx):
    """No sound, with a measurement behind it rather than the user's word."""
    audio = ctx.get("audio_health", {})
    if not audio.get("available"):
        return None
    stopped = audio.get("service_stopped") or []
    faulty = audio.get("faulty") or []
    if not stopped and not faulty:
        return None
    if stopped and audio.get("any_device"):
        return Hypothesis(
            "audio_service_stopped",
            "The audio service is stopped",
            (f"{' and '.join(stopped)} is not running. Nothing on this PC can play sound while "
             f"that is the case, whatever the volume is set to and whichever device is "
             f"selected."),
            confidence=90, severity="high",
            evidence_keys=["audio", "services"],
            actions=[repair_action("restart_audio", {},
                                   reason="Start the audio stack in dependency order."),
                     repair_action("set_service_startup",
                                   {"name": "Audiosrv", "start": "auto"},
                                   title="Set Windows Audio to start automatically",
                                   reason="Stop it staying down after the next restart.")],
        )
    names = "; ".join(f"{d['name']} ({d['problem'] or d['status']})" for d in faulty[:2])
    return Hypothesis(
        "audio_device_fault",
        "An audio device is in a fault state",
        (f"{names}. Windows knows the hardware is there but the driver is not working, so the "
         f"device will not appear as something you can play sound through."),
        confidence=75, severity="medium",
        evidence_keys=["audio", "problem_devices"],
        actions=[task_action("audio_repair", "Run the full audio repair sequence."),
                 task_action("install_system_drivers", "Let Windows fetch the right driver.")],
    )


@rule
def rule_bluetooth_broken(ctx):
    """Bluetooth hardware is present but not usable."""
    bluetooth = ctx.get("bluetooth_health", {})
    if not bluetooth.get("available") or not bluetooth.get("present"):
        return None
    if bluetooth.get("healthy"):
        return None
    stopped = bluetooth.get("service") == "stopped"
    faulty = bluetooth.get("faulty") or []
    return Hypothesis(
        "bluetooth_broken",
        "Bluetooth is not working",
        ("The Bluetooth Support Service is stopped, so no device can pair or connect even "
         "though the radio is there."
         if stopped else
         "; ".join(f"{d['name']}: {d['problem'] or d['status']}" for d in faulty[:2])
         + ". Windows can see the radio but the driver is not working."),
        confidence=85 if stopped else 70, severity="medium",
        evidence_keys=["bluetooth"],
        actions=([repair_action("set_service_startup",
                                {"name": "bthserv", "start": "demand"},
                                title="Set the Bluetooth service back to on-demand",
                                reason="Windows starts it on demand; disabled it never runs."),
                  repair_action("restart_service", {"name": "bthserv"},
                                title="Start the Bluetooth Support Service",
                                reason="Nothing can pair while it is stopped.")]
                 if stopped else [])
                + [task_action("bluetooth_repair", "Run the full Bluetooth repair sequence.")],
    )


@rule
def rule_basic_display_driver(ctx):
    """Windows is drawing the screen in software because the real driver failed."""
    display = ctx.get("display_config", {})
    basic = display.get("basic_driver") or [] if display.get("available") else []
    faulty = display.get("faulty") or [] if display.get("available") else []
    if not basic and not faulty:
        return None
    if basic:
        return Hypothesis(
            "basic_display_driver",
            "The graphics driver is not loaded",
            ("The screen is being driven by Microsoft's fallback display adapter, which means "
             "the real graphics driver either failed to install or is not starting. Everything "
             "is drawn in software: the picture is oversized, nothing animates smoothly, video "
             "stutters, and games will not start at all."),
            confidence=90, severity="high",
            evidence_keys=["display", "problem_devices", "gpu_resets"],
            actions=[task_action("install_system_drivers",
                                 "Let Windows fetch the proper display driver."),
                     task_action("gpu_diagnostic", "Read what the adapter reports about itself.")],
            advice=("If Windows cannot find one, download it from the graphics card maker "
                    "directly -- AMD, NVIDIA, or Intel -- rather than from the PC maker's site, "
                    "which is often years out of date."),
        )
    names = "; ".join(f"{a['name']}: {a['problem'] or 'fault'}" for a in faulty[:2])
    return Hypothesis(
        "display_adapter_fault",
        "A display adapter is in a fault state",
        f"{names}. The adapter is present but Windows cannot use it properly.",
        confidence=75, severity="medium",
        evidence_keys=["display", "problem_devices"],
        actions=[task_action("gpu_diagnostic", "Read the adapter's own status."),
                 task_action("install_system_drivers", "Reinstall the driver.")],
    )


# -- integrity, policy, and where the files are ------------------------------

@rule
def rule_system_files_corrupt(ctx):
    """The last integrity check found damage it could not repair."""
    integrity = ctx.get("integrity_history", {})
    if not integrity.get("available") or not integrity.get("corrupt"):
        return None
    store = ctx.get("component_store_health", {})
    store_bad = bool(store.get("available") and not store.get("healthy", True))
    return Hypothesis(
        "system_files_corrupt",
        "Windows files are damaged and could not be repaired",
        (f"System File Checker has already run on this PC and found "
         f"{_plural(integrity.get('unrepairable', 0), 'file')} it could not repair. That "
         f"specific failure means the component store -- the copy Windows repairs *from* -- is "
         f"damaged too"
         + (", which the component health check confirms." if store_bad else ". ")
         + " Running sfc again will fail the same way; the store has to be repaired first."),
        confidence=85, severity="high",
        evidence_keys=["system_files", "component_store"],
        actions=[task_action("repair_system",
                             "Repair the component store with DISM, then re-run sfc.")],
        advice=("This needs a working internet connection: DISM fetches replacement files from "
                "Windows Update. If it fails offline, that is why."),
    )


@rule
def rule_policy_restrictions(ctx):
    """Windows features switched off behind the Settings app."""
    policies = ctx.get("policy_health", {})
    found = policies.get("restrictions") or [] if policies.get("available") else []
    if not found:
        return None
    # Security restrictions are the ones worth interrupting for. The rest are a
    # tidy-up, and grading them the same way would make the whole section noise.
    security = [entry for entry in found if entry["area"] == "security"]
    lead = (security or found)[0]
    listing = "; ".join(entry["meaning"] for entry in (security or found)[:3])
    return Hypothesis(
        "policy_restrictions",
        ("Protection has been switched off by policy" if security else
         f"{_plural(len(found), 'Windows feature')} switched off by policy"),
        (f"{listing}. These are set in a place the Settings app never shows, so the switch for "
         f"them looks stuck or missing. On a work PC they are set deliberately by IT; on a "
         f"home PC they are almost always left over from a \"debloat\" or \"privacy\" script."),
        confidence=85, severity="high" if security else "low",
        evidence_keys=["policies", "defender", "uac"],
        actions=[repair_action("remove_policy",
                               {"hive": lead["hive"], "path": lead["path"],
                                "value": lead["value"]},
                               title=f"Remove the {lead['value']} restriction",
                               reason=lead["meaning"])]
                + [task_action("windows_tweaks", "Review every setting of this kind.")],
        advice=("If this is a managed work PC, leave these alone and ask IT -- the policy will "
                "be reapplied anyway at the next refresh."),
    )


@rule
def rule_path_broken(ctx):
    """The system PATH is missing something Windows needs."""
    env = ctx.get("environment_health", {})
    if not env.get("available"):
        return None
    if env.get("has_system32") and not env.get("truncation_risk"):
        return None
    if not env.get("has_system32"):
        return Hypothesis(
            "path_broken",
            "System32 is missing from the system PATH",
            ("The system PATH does not include System32. That single omission breaks a great "
             "deal of Windows in ways that point nowhere near the real cause: commands report "
             "\"not recognised\", installers fail, and scripts that worked yesterday stop. It "
             "is almost always a program's installer that overwrote the value instead of "
             "adding to it."),
            confidence=95, severity="critical",
            evidence_keys=["path"],
            actions=[repair_action("repair_path", {},
                                   reason="Put the standard Windows folders back on the PATH.")],
            advice=("Nothing existing is removed or reordered -- the missing folders are added "
                    "to the front and everything else is left exactly as it was."),
        )
    return Hypothesis(
        "path_truncation",
        "The system PATH is close to the length limit",
        (f"The PATH is {env.get('length')} characters. Past about 2,047 the value is truncated "
         f"when it is read in the classic format, and everything after the cut silently stops "
         f"working -- with no error that mentions the PATH."),
        confidence=70, severity="medium",
        evidence_keys=["path"],
        actions=[task_action("pc_report", "Capture the current PATH before editing it.")],
        advice=("Removing entries for programs that are no longer installed is the safe way to "
                "shorten it. WinMend does not edit the PATH except to add missing Windows "
                "folders back, because a wrong edit here breaks every program at once."),
    )


@rule
def rule_files_stranded(ctx):
    """Desktop and Documents point somewhere that is not working."""
    folders = ctx.get("known_folders", {})
    if not folders.get("available"):
        return None
    missing = folders.get("missing") or []
    if missing:
        names = ", ".join(entry["label"] for entry in missing)
        return Hypothesis(
            "folders_missing",
            f"{names} point at a folder that does not exist",
            (f"Windows is looking for {names} at a path that is not there. That is why the "
             f"files appear to have vanished -- the originals are usually still on the disk "
             f"under the old location, and nothing has been deleted."),
            confidence=85, severity="high",
            evidence_keys=["known_folders"],
            actions=[task_action("account_audit", "Check the account and its folder settings."),
                     task_action("pc_report", "Record the current paths before changing them.")],
            advice=("The paths are under Explorer's User Shell Folders. Do not create empty "
                    "folders at the new location first -- Windows will start using them and "
                    "the originals get harder to find."),
        )
    if not folders.get("stranded"):
        return None
    names = ", ".join(entry["label"] for entry in (folders.get("redirected") or []))
    return Hypothesis(
        "files_not_syncing",
        f"{names} are in OneDrive, and OneDrive is not running",
        (f"{names} are stored in OneDrive rather than on this PC, and the OneDrive client is "
         f"not running. The files are still reachable, but nothing is syncing: anything saved "
         f"there now exists only on this machine, and changes made on another device will not "
         f"arrive."),
        confidence=80, severity="medium",
        evidence_keys=["known_folders"],
        actions=[repair_action("start_onedrive", {},
                               reason="Start syncing again and upload anything waiting.")],
        advice=("If you meant to stop using OneDrive, move these folders back to this PC first "
                "-- otherwise the files stay in the cloud folder and are easy to lose track of."),
    )
