"""Shared planning and execution preconditions. Unknown requirements fail closed."""
from __future__ import annotations
import json

READ_ONLY = frozenset(("pc_report", "network_diagnostic_bundle", "wlan_report", "bsod_triage",
                      "gpu_diagnostic", "disk_smart_check", "minidump_analyzer", "reliability_monitor",
                      "event_log_viewer", "ipconfig_all", "storage_sence", "boot_time_analyzer",
                      "battery_health_report", "security_posture_report", "firewall_audit",
                      "scheduled_task_audit", "account_audit", "camera_mic_audit", "sysinternals_autoruns"))
REQUIREMENTS = {
    "clean_temp": ("disk_free",), "disk_cleanup": ("disk_free", "volumes"),
    "component_cleanup": ("disk_free",), "empty_recycle_bin": ("disk_free", "volumes"),
    "flush_dns_cache": ("resolver_queries", "dns_resolution"), "flush_dns": ("resolver_queries", "dns_resolution"),
    "reset_dns_servers": ("resolver_queries",), "change_dns": ("resolver_queries",),
    "clear_proxy": ("https_connectivity",), "restore_hosts": ("hosts",),
    "renew_lease": ("ip_config",), "reset_adapter": ("ip_config",), "network_adapter_reset": ("ip_config",),
    "reset_winsock": ("winsock",), "reset_network": ("winsock",),
    "enable_pagefile": ("pagefile",), "reinstall_device": ("problem_devices",),
    "restart_audio": ("audio",), "audio_repair": ("audio",), "bluetooth_repair": ("bluetooth",),
    "clear_print_spooler": ("printers",), "reset_search_index": ("search_index",),
    "restart_explorer": ("shell",), "reregister_app": ("store_apps",), "uwp_app_reset": ("store_apps",),
    "repair_path": ("path",), "remove_policy": ("policies",), "start_onedrive": ("known_folders",),
    "restore_profile": ("user_profile",), "clear_safe_boot": ("boot_config",),
    "enable_trim": ("disk_optimization",), "optimize_volume": ("disk_optimization",),
    "defrag_optimize": ("disk_optimization",), "check_disk": ("filesystem",), "chk_dsk": ("filesystem",),
    "set_power_plan": ("power_plan",), "disable_pcie_power_saving": ("storage_events",),
    "resume_bitlocker": ("encryption",), "reset_tdr": ("gpu_hardware",),
    "set_gpu_scheduling": ("gpu_hardware",), "schedule_memory_test": ("memory_test", "memory_pattern"),
    "memory_diagnostic": ("memory_test", "memory_pattern", "hardware_errors", "bugchecks"),
    "ram_quick_test": ("memory_test", "memory_pattern", "hardware_errors", "bugchecks"),
    "enable_uac": ("uac",), "enable_realtime": ("defender",), "enable_realtime_protection": ("defender",), "enable_firewall": ("firewall",),
    "remove_threats": ("threats",), "defender_scan": ("threats", "hosts"), "msrt_scan": ("threats",),
    "unblock_updates": ("update_state",), "clear_update_policy": ("update_policy",),
    "clear_update_cache": ("update_cache",), "reset_win_update": ("update_failures",),
    "windows_updates": ("update_failures", "update_state", "pending_reboot"),
    "windows_update_forensic": ("update_failures",), "repair_system": ("component_store",),
    "restart_service": ("services", "audio", "printers", "search_index"), "set_service_startup": ("services",),
    "service_dependency_repair": ("services",), "run_scheduled_task": ("scheduled_tasks",),
    "disable_startup_entry": ("startup",), "disable_startup_apps": ("startup",),
    "sync_clock": ("time_sync",), "time_sync_fix": ("time_sync",),
    "restart_windows": ("pending_reboot",), "enable_system_restore": ("restore_points",),
    "create_restore_point_guardrail": ("restore_points",),
}
POLICY_SENSITIVE = frozenset(("reset_dns_servers", "change_dns", "clear_proxy", "restore_hosts", "renew_lease",
    "reset_adapter", "network_adapter_reset", "reset_winsock", "reset_network", "flush_dns",
    "set_network_private", "set_mtu", "rollback_driver", "reinstall_device", "uninstall_update",
    "clear_update_policy", "remove_policy", "set_service_startup", "service_dependency_repair",
    "enable_realtime", "enable_realtime_protection", "enable_firewall", "enable_uac", "unblock_updates", "resume_bitlocker"))
POLICY_SENSITIVE = POLICY_SENSITIVE | frozenset(("enable_pagefile", "repair_path", "restore_profile",
    "set_power_plan", "reset_tdr", "set_gpu_scheduling", "clear_safe_boot"))
DISK_MUTATIONS = frozenset(("chk_dsk", "check_disk", "defrag_optimize", "optimize_volume", "component_cleanup",
                           "disk_cleanup", "clean_temp", "empty_recycle_bin", "repair_system"))
FATAL_STORAGE = ("smart", "drive_wear", "smart_detail", "disk_surface")
VERIFY_OVERRIDE = {
    "flush_dns_cache": ("resolver_queries", "https_connectivity"),
    "reset_dns_servers": ("resolver_queries", "https_connectivity"),
    "change_dns": ("resolver_queries", "https_connectivity"),
    "clear_proxy": ("https_connectivity",), "renew_lease": ("ip_config", "tcp_connectivity"),
}


def repair_identity(step):
    return step.get("id", "") + ":" + json.dumps(step.get("params", {}), sort_keys=True)


def eligible(step, findings, context=None, attempts=()):
    identifier = step.get("id", "")
    if any(a.get("identity") == repair_identity(step) and a.get("outcome") in
           ("failed", "not_resolved", "inconclusive", "symptom_unverified", "improved", "needs_attention") for a in attempts):
        return False, "This repair was already attempted without verified resolution. Collect different evidence first."
    if step.get("kind") == "task" and identifier in READ_ONLY:
        return True, "Read-only investigation"
    if identifier in ("rollback_driver", "uninstall_update", "system_restore_browser"):
        return False, "Recency does not establish causation; a matching fault and a verified recovery path are required."
    required = REQUIREMENTS.get(identifier)
    if not required:
        return False, "No validated evidence precondition exists for this repair. Further investigation is required."
    by_key = {f["key"]: f for f in findings}
    supporting = [key for key in required if by_key.get(key, {}).get("status") in ("warn", "bad")]
    if not supporting:
        return False, "The specific fault this repair addresses was not measured."
    if identifier in ("restart_audio", "audio_repair") and not by_key.get("audio", {}).get("data", {}).get("service_stopped"):
        return False, "The audio services are not confirmed stopped. Device absence or output routing needs a different investigation."
    params = step.get("params", {})
    if identifier == "reinstall_device":
        target = str(params.get("instance_id", "")).lower()
        devices = by_key.get("problem_devices", {}).get("data", {}).get("devices", [])
        if not target or not any(str(d.get("instance_id", "")).lower() == target and
                                 d.get("problem_code") in (10, 31, 43, 39, 19, 1, 3, 18, 52, 54) for d in devices):
            return False, "This exact device is not currently confirmed faulty."
        if not any(str(d.get("instance_id", "")).lower() == target and d.get("problem_code") in
                   (1, 3, 18, 19, 31, 39, 52) for d in devices):
            return False, "This device code does not establish a driver-loading fault. Check its connection, power and vendor diagnostics before removing it."
    if identifier == "disable_startup_entry" and params.get("name") not in by_key.get("startup", {}).get("data", {}).get("names", []):
        return False, "This exact startup entry is not confirmed enabled."
    if identifier == "remove_policy":
        restrictions = by_key.get("policies", {}).get("data", {}).get("restrictions", [])
        if not any(all(str(entry.get(k, "")).lower() == str(params.get(k, "")).lower()
                       for k in ("hive", "path", "value")) for entry in restrictions):
            return False, "The exact policy value is no longer present in the evidence."
    if identifier == "empty_recycle_bin":
        data = by_key.get("volumes", {}).get("data", {})
        volumes = data.get("volumes", []) + data.get("others", [])
        if not any(str(v.get("drive", "")).lower() == str(params.get("drive", "")).lower()
                   and (v.get("recycle_gb") or 0) >= 1 for v in volumes):
            return False, "Reclaimable deleted files on this exact drive could not be confirmed."
    if identifier in DISK_MUTATIONS and any(by_key.get(k, {}).get("status") == "bad" for k in FATAL_STORAGE):
        return False, "Possible drive damage: back up first. Write-heavy software repairs are withheld."
    if identifier in POLICY_SENSITIVE:
        context = context or {}
        if context.get("available") is not True or any(context.get(k) is None for k in
                ("domain_joined", "mdm_managed", "vpn_present", "remote_session")):
            return False, "Management, VPN and remote-session safety could not be established."
        if any(context.get(k) for k in ("domain_joined", "mdm_managed", "vpn_present", "remote_session", "split_dns", "virtual_network")):
            return False, "Managed, VPN, split-DNS or remote configuration requires administrator review; this change could interrupt access."
    if identifier in ("reset_dns_servers", "change_dns"):
        return False, "Public resolver failures do not justify replacing configured DNS. Review the exact resolver and private-domain requirements first."
    if identifier == "clear_proxy":
        return False, "HTTPS failure does not prove the proxy is incorrect. Confirm its requirement and failure before removal."
    if identifier == "restart_service":
        target = step.get("params", {}).get("name", "").lower()
        services = by_key.get("services", {}).get("data", {}).get("critical_stopped", [])
        audio = by_key.get("audio", {}).get("data", {}).get("service_stopped", [])
        specific = (target == "spooler" and by_key.get("printers", {}).get("data", {}).get("spooler") == "stopped") or (
                    target == "wsearch" and by_key.get("search_index", {}).get("data", {}).get("service") == "stopped")
        if not specific and not any(str(s.get("name", "")).lower() == target for s in services) and target not in [str(s).lower() for s in audio]:
            return False, "The target service is not confirmed faulty. Stopped trigger-start services are normal."
    return True, "Measured prerequisite: " + ", ".join(supporting)


def decorate_step(step, findings):
    required = REQUIREMENTS.get(step["id"], ())
    step["required_evidence"] = list(required)
    if step["id"] in VERIFY_OVERRIDE:
        keys = [k for k in VERIFY_OVERRIDE[step["id"]] if any(f["key"] == k for f in findings)]
        if keys:
            step["verify_keys"] = keys
    step["read_only"] = step.get("kind") == "task" and step["id"] in READ_ONLY
    step["recovery_required"] = bool(step.get("restore_point") and step.get("risk") == "destructive")
    step["expected_effect"] = "Repeat the targeted measurements; command completion does not verify symptom resolution."
    step["verification_scope"] = "targeted_fault"
    step["side_effects"] = {
        "flush_dns_cache": "Name queries may take longer while the cache rebuilds.",
        "renew_lease": "The network connection may briefly disconnect.",
        "reinstall_device": "The device may disconnect until Windows redetects it; its manufacturer driver may be needed.",
        "check_disk": "An offline check may require a restart and extend boot time.",
        "restart_windows": "Open work must be saved before restarting.",
    }.get(step["id"], "Review this step's explanation and undo coverage before running it.")
    return step
