"""WinMend diagnostics: profiles."""

from __future__ import annotations

from datetime import datetime, timezone
from winmend.core.findings import SEVERITY, _finding, utc_now
from winmend.diagnostics.collectors.windows import WindowsProbe
import uuid


class DiagnosticEngine:
    """Turns a plain-language complaint into checks and a conservative plan."""

    PROFILE_TERMS = {
        "network": ("internet", "wifi", "wi-fi", "network", "dns", "online", "disconnect", "latency"),
        "performance": ("slow", "lag", "performance", "freez", "startup", "boot", "sluggish"),
        "storage": ("storage", "disk full", "space", "drive full", "cleanup", "junk", "temporary"),
        "updates": ("update", "windows update", "stuck update", "driver update"),
        "crashes": ("crash", "blue screen", "bsod", "restart", "bugcheck", "display driver"),
        "security": ("virus", "malware", "security", "defender", "hacked", "suspicious"),
        "battery": ("battery", "charge", "laptop dies", "power drain"),
        "audio": ("audio", "sound", "speaker", "microphone", "no sound"),
        "printer": ("printer", "printing", "print queue", "spooler"),
        "shell": ("start menu", "taskbar", "search", "icons", "thumbnail", "file association"),
        "bluetooth": ("bluetooth", "bt headset", "pairing", "paired"),
        "apps": ("microsoft store", "store app", "app crash", "apps crash", "app will not open",
                 "app won't open", "apps won't open", "uwp"),
        "time": ("wrong time", "clock is wrong", "date is wrong", "time sync", "certificate error",
                 "certificate warning"),
        "browser": ("browser", "chrome", "edge", "firefox", "web pages slow", "tabs"),
    }

    PROFILE_LABELS = (
        ("performance", "Slow PC"), ("network", "Internet / Wi-Fi"), ("storage", "Disk space"),
        ("updates", "Windows Update"), ("crashes", "Crashes / blue screens"), ("security", "Security"),
        ("battery", "Battery"), ("audio", "Sound"), ("printer", "Printing"),
        ("shell", "Start menu / icons / search"), ("bluetooth", "Bluetooth"),
        ("apps", "Store apps"), ("time", "Clock / certificates"), ("browser", "Browser"),
    )

    TASK_REASONS = {
        "clean_temp": "Remove accumulated temporary data that is consuming system-drive space.",
        "disk_cleanup": "Let Windows safely remove update leftovers and system caches.",
        "disable_startup_apps": "Reduce the number of programs competing during sign-in.",
        "pc_report": "Capture a broader read-only health report for anything the quick checks cannot explain.",
        "flush_dns": "Refresh cached name lookups and renew the current IP configuration.",
        "network_adapter_reset": "Reinitialize active network adapters after a connectivity failure.",
        "network_diagnostic_bundle": "Collect routing, adapter, DNS, and reachability evidence.",
        "wlan_report": "Collect Windows' Wi-Fi connection and disconnect history.",
        "windows_updates": "Retry the normal Windows Update path.",
        "windows_update_forensic": "Repair the update service state before retrying updates.",
        "bsod_triage": "Collect crash dumps and event evidence without changing the PC.",
        "gpu_diagnostic": "Check the graphics driver and recent display-related failures.",
        "repair_system": "Verify and repair damaged Windows component and system files.",
        "defender_scan": "Run a full Microsoft Defender malware scan.",
        "scheduled_task_audit": "Review non-Microsoft scheduled tasks for suspicious persistence.",
        "firewall_audit": "Review inbound firewall rules for unsafe program entries.",
        "battery_health_report": "Measure battery capacity and wear using Windows' battery report.",
        "power_plan_switcher": "Choose a suitable Windows power plan after reviewing battery health.",
        "service_dependency_repair": "Repair and restart critical Windows service dependencies.",
        "clear_print_spooler": "Remove stuck print jobs and restart the print service.",
        "reset_search_index": "Rebuild Windows Search when indexing is the likely cause.",
        "start_menu_reset": "Reset corrupted Start and taskbar layout data.",
        "rebuild_icon_cache": "Rebuild corrupted icon and thumbnail caches.",
        "file_assoc_reset": "Clear broken per-user default-app associations.",
        "disk_smart_check": "Read the drive's own SMART health data to rule out failing hardware.",
        "chk_dsk": "Scan the file system for the disk errors Windows has been logging.",
        "component_cleanup": "Compact the Windows component store, often worth several GB.",
        "windows_old_cleanup": "Remove the previous Windows installation to reclaim major disk space.",
        "minidump_analyzer": "Analyze the recorded crash dumps to name the failing driver.",
        "ram_quick_test": "Run a quick memory sanity test, a common blue-screen cause.",
        "memory_diagnostic": "Schedule the full Windows Memory Diagnostic on the next restart.",
        "reliability_monitor": "Open Windows' own timeline of recent errors and failures.",
        "device_firmware": "Check the board and device firmware against what the vendor ships.",
        "event_log_viewer": "Open the event logs to read the repeating errors in full.",
        "reset_win_update": "Fully reset the Windows Update engine and its download cache.",
        "msrt_scan": "Run Microsoft's Malicious Software Removal Tool as a second opinion.",
        "security_posture_report": "Summarize this PC's security settings in one read-only report.",
        "camera_mic_audit": "List which apps can use the camera and microphone.",
        "account_audit": "Review local accounts, admins, and sign-in settings.",
        "smart_malware_remediation": "Run the deep malware remediation with a restore point first.",
        "audio_repair": "Restart the audio engine and re-register its components.",
        "bluetooth_repair": "Restart Bluetooth services and clear stale pairing state.",
        "uwp_app_reset": "Re-register broken Microsoft Store apps for this user.",
        "time_sync_fix": "Resync the clock; a wrong clock breaks secure websites.",
        "clear_browser_cache": "Clear bloated browser caches that slow page loads.",
        "edge_performance": "Apply Edge's efficiency settings to cut its background load.",
        "reset_network": "Reset the full Windows network stack (Winsock, TCP/IP).",
        "deep_network_remediation": "Run the deep multi-step network remediation.",
        "stop_background_apps": "Stop background apps that keep consuming CPU and memory.",
        "defrag_optimize": "Optimize the drive (retrim SSDs, defragment hard disks).",
        "restart_windows": "Restart the PC to apply pending changes and clear stuck state.",
        "ipconfig_all": "Record the full addressing state so a later reading can be compared to it.",
        "storage_sence": "Show what is actually taking the room on a drive that is short of space.",
        "create_restore_point_guardrail": "Take a named checkpoint to return to if a repair goes wrong.",
        "boot_time_analyzer": "Break a slow sign-in down into the stages Windows records for it.",
        # Referenced by the IT Desk rules. A task id missing from this table is
        # dropped by _default_task_lookup without a word, so a hypothesis can
        # end up on screen with nothing underneath it to run.
        "system_restore_browser": "Roll the whole PC back to a checkpoint from before the trouble started.",
        "install_system_drivers": "Let Windows fetch and install the proper device drivers.",
        "change_dns": "Switch name lookups to a resolver that is known to work.",
        "windows_tweaks": "Review the Windows settings that a script may have changed.",
        "sysinternals_autoruns": "List everything that loads at startup, including drivers.",
        "cpu_stress_test": "Load the processor and watch whether it reaches its rated speed.",
        "activate_windows": "Open the activation troubleshooter.",
    }

    # Rough expectations shown in the plan so nobody starts an hours-long scan
    # thinking it is a two-minute fix.
    TASK_DURATIONS = {
        "clean_temp": "2-5 min", "disk_cleanup": "3-10 min", "disable_startup_apps": "1 min",
        "pc_report": "1-2 min", "flush_dns": "under 1 min", "network_adapter_reset": "1-2 min",
        "network_diagnostic_bundle": "1-3 min", "wlan_report": "1 min", "windows_updates": "5-30 min",
        "windows_update_forensic": "2-5 min", "bsod_triage": "1-3 min", "gpu_diagnostic": "1-2 min",
        "repair_system": "10-45 min", "defender_scan": "1-4 hours", "scheduled_task_audit": "1 min",
        "firewall_audit": "1 min", "battery_health_report": "1-2 min", "power_plan_switcher": "under 1 min",
        "service_dependency_repair": "1-3 min", "clear_print_spooler": "1 min",
        "reset_search_index": "2-5 min (rebuilds over hours)", "start_menu_reset": "1-2 min",
        "rebuild_icon_cache": "1-2 min", "file_assoc_reset": "under 1 min",
        "disk_smart_check": "under 1 min", "chk_dsk": "5-60 min", "component_cleanup": "5-20 min",
        "windows_old_cleanup": "5-15 min", "minidump_analyzer": "1-3 min", "ram_quick_test": "1-2 min",
        "memory_diagnostic": "next restart", "reliability_monitor": "opens a viewer",
        "device_firmware": "1-2 min", "event_log_viewer": "opens a viewer",
        "reset_win_update": "3-10 min", "msrt_scan": "5-20 min", "security_posture_report": "1-2 min",
        "camera_mic_audit": "under 1 min", "account_audit": "under 1 min",
        "smart_malware_remediation": "10-60 min", "audio_repair": "1-2 min",
        "bluetooth_repair": "1-2 min", "uwp_app_reset": "2-10 min", "time_sync_fix": "under 1 min",
        "clear_browser_cache": "1-3 min", "edge_performance": "under 1 min",
        "reset_network": "1-2 min + restart", "deep_network_remediation": "3-10 min",
        "stop_background_apps": "under 1 min", "defrag_optimize": "5-60 min",
        "restart_windows": "60-second countdown", "ipconfig_all": "under 1 min",
        "storage_sence": "under 1 min",
        "create_restore_point_guardrail": "1-3 min", "boot_time_analyzer": "1-2 min",
        "system_restore_browser": "10-45 min", "install_system_drivers": "5-30 min",
        "change_dns": "under 1 min", "windows_tweaks": "1-2 min",
        "sysinternals_autoruns": "1-2 min", "cpu_stress_test": "1-2 min",
        "gpu_stress_test": "1-2 min",
        "activate_windows": "1-2 min",
    }

    # Deeper second-pass repairs, recommended only when the journal shows the
    # same category of problem was already treated recently.
    ESCALATION_TASKS = {
        "network": ("reset_network", "deep_network_remediation"),
        "updates": ("reset_win_update",),
        "performance": ("stop_background_apps", "defrag_optimize"),
        "security": ("smart_malware_remediation",),
        "crashes": ("memory_diagnostic",),
    }
    ESCALATION_WINDOW_DAYS = 14

    def __init__(self, probe=None):
        self.probe = probe or WindowsProbe()

    def classify(self, problem):
        profile, _score = self.classify_detail(problem)
        return profile

    def classify_detail(self, problem):
        """Return (profile, top_score). Two close-scoring profiles blend as 'a+b',
        because people describe compound problems ('slow and wifi drops')."""
        from winmend.diagnostics.symptoms import classify
        return classify(problem)

    @staticmethod
    def _plan(task_ids):
        seen = set()
        result = []
        for task_id in task_ids:
            if task_id in seen:
                continue
            seen.add(task_id)
            result.append({
                "id": task_id,
                "reason": DiagnosticEngine.TASK_REASONS.get(task_id, "Recommended by the diagnostic checks."),
                "duration": DiagnosticEngine.TASK_DURATIONS.get(task_id, "varies"),
            })
        return result

    @classmethod
    def _recent_treated_profiles(cls, history):
        """Profile parts of guided sessions that already ran a plan recently."""
        cutoff = datetime.now(timezone.utc).timestamp() - cls.ESCALATION_WINDOW_DAYS * 86400
        treated = set()
        for session in history or []:
            if session.get("source") != "guided":
                continue
            try:
                started = datetime.fromisoformat(session.get("started_at", "")).timestamp()
            except (TypeError, ValueError):
                continue
            if started < cutoff:
                continue
            profile = (session.get("diagnosis_before") or {}).get("profile", "")
            treated.update(part for part in profile.split("+") if part)
        return treated

    def diagnose(self, problem, profile=None, history=None):
        """Historical API, now routed through the same evidence and safety engine.

        Keeps findings/recommended_tasks/profile/severity_score for saved callers;
        a repeated complaint no longer authorizes speculative escalation.
        """
        from winmend.diagnostics.engine import CaseEngine
        return CaseEngine(probe=self.probe, engine=self).build_case(
            problem, profile=profile, history=history)

    @staticmethod
    def compare(before, after):
        from winmend.diagnostics.verification import compare
        return compare(before, after)
