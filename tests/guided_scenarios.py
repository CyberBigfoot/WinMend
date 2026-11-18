"""Human-labeled regression cases. Values describe observations, not engine rules.

These are development fixtures. The separate JSON evaluation set is not used
for threshold tuning, and neither set represents a fleet accuracy study.
"""
from copy import deepcopy

BASE = {
    "system_context": {"available": True, "domain_joined": False, "mdm_managed": False,
                       "vpn_present": False, "remote_session": False, "split_dns": False, "boot_time": 100, "boot_event_record_id": 42},
    "disk": {"free_gb": 120, "free_pct": 40}, "memory": {"used_pct": 40, "available_gb": 8},
    "network": {"adapters": 1, "dns": True, "reachable": True},
    "network_config": {"available": True, "has_route": True, "self_assigned_only": False,
                       "interfaces": [{"address": "192.0.2.2", "gateway": "192.0.2.1", "self_assigned": False}]},
    "dns_resolution": {"available": True, "resolved": 2, "attempted": 2, "failed": 0, "slowest_ms": 20, "hijacked": False},
    "smart_health": {"available": True, "disks": 1, "unhealthy": []},
    "problem_devices": {"available": True, "devices": []},
    "restart_pending": {"available": True, "pending": False, "reasons": [], "queued_renames": 0},
    "event_log_errors": {"available": True, "unexpected_shutdowns": 0, "hardware_errors": 0, "disk_errors": 0, "service_crashes": 0},
    "bugchecks": {"available": True, "crashes": []}, "gpu_resets": {"available": True, "count": 0},
    "update_failures": {"available": True, "failures": []},
    "proxy_settings": {"available": True, "pac_or_proxy": False},
    "service_health": {"available": True, "critical_stopped": [], "total": 100},
    "app_crashes": {"available": True, "crashes": []},
}


def load(cpu=(20, 30, 15, 25), available=(50, 48, 49, 51), commit=(40, 42, 41, 44),
         latency=(2, 3, 2, 4), process=None, update=False, paging=0):
    return {"available": True, "samples": [
        {"cpu_pct": c, "available_pct": a, "commit_pct": m,
         "disks": [{"device": "disk0", "latency_ms": d, "ops": 200}]} for c, a, m, d in zip(cpu, available, commit, latency)],
        "processes": [process] if process else [], "update_active": update,
        "paging": {"available": True, "pages_input_per_second": paging}}


def internet(dns=True, tcp=True, https=True):
    return {"available": True, "repeated": True,
            "tcp": [{"endpoint": h, "ok": tcp, "attempt": a} for a in range(2) for h in ("1.1.1.1", "8.8.8.8")],
            "dns": {"available": True, "results": [{"name": h, "ok": dns, "attempt": a} for a in range(2) for h in ("www.microsoft.com", "cloudflare.com")]},
            "https": {"available": True, "results": [{"endpoint": h, "ok": https} for h in ("www.microsoft.com", "cloudflare.com")]}}


class RecordedProbe:
    def __init__(self, overrides=None):
        self.data = deepcopy(BASE)
        self.data.update({"performance_samples": load(), "layered_network": internet()})
        self.data.update(deepcopy(overrides or {}))
        self.calls = []

    def __getattr__(self, name):
        def collect():
            self.calls.append(name)
            value = self.data.get(name, {"available": False, "diagnostic_state": "unsupported", "reason": "Fixture provider not exposed"})
            if isinstance(value, Exception):
                raise value
            return deepcopy(value)
        return collect


DEVICE = {"available": True, "devices": [{"name": "USB device", "class": "USB", "status": "Error",
          "problem_code": 43, "instance_id": "USB\\TEST", "meaning": "Device reported a fault", "remedy": "Inspect device"}]}
DNS_FAILURE = {"layered_network": internet(dns=False, https=False),
               "dns_resolution": {"available": True, "resolved": 0, "attempted": 2}}
NO_ROUTE = {"network_config": {"available": True, "has_route": False, "self_assigned_only": False,
            "interfaces": [{"address": "192.0.2.2", "gateway": "", "self_assigned": False}]},
            "layered_network": internet(tcp=False, https=False)}

# name, complaint, overrides, acceptable cause(s), repairs forbidden in this case
SCENARIOS = [
    ("wifi_dns", "Wi-Fi connected but websites do not load", DNS_FAILURE, ["dns_dead"], ["reinstall_device", "reset_network"]),
    ("lan_no_route", "Connected to network but no internet", NO_ROUTE, ["no_route"], ["change_dns"]),
    ("icmp_blocked", "Internet works but ping is blocked", {"icmp": False}, [], ["reset_network"]),
    ("unfamiliar_dns", "Wi-Fi is working", {"dns_servers": {"available": True, "unrecognised": ["203.0.113.5"], "interfaces": []}}, [], ["reset_dns_servers"]),
    ("one_website", "Only one website fails", {}, [], ["reset_network", "change_dns"]),
    ("vpn_split_dns", "Work sites fail over VPN", {**DNS_FAILURE, "system_context": {**BASE["system_context"], "vpn_present": True, "split_dns": True}}, ["dns_dead"], ["reset_dns_servers", "reset_adapter"]),
    ("dhcp_apipa", "Wi-Fi has no internet", {**NO_ROUTE, "network_config": {"available": True, "has_route": False, "self_assigned_only": True,
        "interfaces": [{"address": "169.254.1.2", "gateway": "", "self_assigned": True}]}}, ["no_route"], ["change_dns"]),
    ("proxy_path", "Websites do not load", {"proxy_settings": {"available": True, "pac_or_proxy": True, "enabled": True, "server": "proxy.example:8080"},
        "layered_network": internet(https=False)}, ["proxy_path"], ["clear_proxy"]),
    ("intermittent_network", "My laptop keeps disconnecting from Wi-Fi", {}, [], ["reset_network", "reinstall_device"]),
    ("cpu_process", "The PC is slow", {"performance_samples": load(cpu=(96, 92, 98, 95), process={"name": "worker.exe", "cpu_samples": [80]*4})}, ["cpu_hog"], ["stop_process"]),
    ("temporary_cpu", "PC was slow for a second", {"performance_samples": load(cpu=(98, 20, 10, 15))}, [], ["stop_process"]),
    ("memory_paging", "Everything freezes", {"performance_samples": load(available=(3, 4, 3, 2), commit=(96, 97, 95, 96), paging=70)}, ["memory_pressure"], ["ram_quick_test"]),
    ("ram_caching", "My PC is slow", {"memory": {"used_pct": 95, "available_gb": 6}}, [], ["stop_process", "memory_diagnostic"]),
    ("io_latency", "Applications freeze and the SSD is busy", {"performance_samples": load(latency=(100, 80, 95, 110))}, ["storage_bottleneck"], ["chk_dsk"]),
    ("normal_disk", "My SSD is at 100% during a copy", {}, [], ["chk_dsk", "defrag_optimize"]),
    ("update_load", "PC slow during Windows Update", {"performance_samples": load(cpu=(98, 95, 96, 99), update=True)}, [], ["stop_process"]),
    ("unconfirmed_slowness", "My computer is running really slow", {}, [], ["repair_system", "disable_startup_apps"]),
    ("critical_space", "Disk full", {"disk": {"free_gb": 1, "free_pct": 1}}, ["disk_full"], ["windows_old_cleanup"]),
    ("storage_errors", "Freezes while saving files", {"disk_reliability": {"available": True, "counters_readable": True, "disks": [{"name": "SSD", "read_errors": 20, "write_errors": 2, "health": "Healthy"}]}}, ["drive_wear"], ["chk_dsk", "defrag_optimize"]),
    ("smart_missing", "Disk feels slow", {"smart_health": {"available": False}}, [], ["chk_dsk"]),
    ("sampled_reads", "Check hardware", {"disk_read_sweep": {"available": True, "disks": [{"disk": 0, "blocks_read": 48, "error_count": 0, "gb_span": 256, "slow_reads": 0}], "failing": [], "sluggish": []}}, [], ["check_disk"]),
    ("allocated_memory", "Check hardware", {"memory_pattern_test": {"available": True, "tested_mb": 128, "failures": [], "passed": True, "passes": 5}}, [], ["schedule_memory_test"]),
    ("hardware_denied", "Check hardware", {"smart_attributes": PermissionError("Access denied")}, [], ["check_disk"]),
    ("backup_first", "Disk full and freezes", {"disk": {"free_gb": 1, "free_pct": 1}, "smart_health": {"available": True, "disks": 1, "unhealthy": ["SSD Warning"]}}, ["failing_drive", "disk_full"], ["clean_temp", "disk_cleanup", "chk_dsk"]),
    ("update_code", "Windows Update fails every time", {"update_failures": {"available": True, "failures": [{"code": "0x80070070", "meaning": "Insufficient space", "remedy": "disk_cleanup"}]}}, ["update_error"], ["repair_system"]),
    ("pending_restart", "Windows update waiting", {"restart_pending": {"available": True, "pending": True, "reasons": ["Update pending"]}}, ["needs_restart"], ["reset_win_update"]),
    ("trigger_service", "Windows update checking", {"service_health": {"available": True, "critical_stopped": [], "stopped_auto": [{"name": "wuauserv"}], "total": 100}}, [], ["set_service_startup"]),
    ("device_code", "USB device not working", {"problem_devices": DEVICE}, ["problem_devices"], ["rollback_driver"]),
    ("recent_driver_only", "Slow after a driver update", {"third_party_drivers": {"available": True, "recent": [{"published": "oem1.inf", "days_ago": 1, "class": "Display"}]}}, [], ["rollback_driver"]),
    ("repeated_display", "Games crash and screen goes black", {"gpu_resets": {"available": True, "count": 5, "events": []}}, ["gpu_driver"], ["rollback_driver"]),
    ("unrelated_update", "PC slow after yesterday's update", {"installed_updates": {"available": True, "updates": [{"kb": "KB12345", "days_ago": 1}]}}, [], ["uninstall_update"]),
    ("kernel_power", "Randomly shuts off", {"event_log_errors": {**BASE["event_log_errors"], "unexpected_shutdowns": 1}}, [], ["stop_process", "repair_system"]),
    ("app_fault", "Only Chrome crashes", {"app_crashes": {"available": True, "crashes": [{"app": "chrome.exe", "module": "chrome.dll", "count": 4, "exception": "c0000005", "vendor": "", "exception_meaning": "Access violation"}]}}, ["app_crash_module"], ["repair_system"]),
    ("bugcheck", "Blue screens", {"bugchecks": {"available": True, "crashes": [{"code": "0x00000116", "name": "VIDEO_TDR_FAILURE", "tags": ["gpu"], "cause": "Display timeout"}]}}, ["gpu_driver"], ["memory_diagnostic"]),
    ("storage_timeouts", "Freezes while loading", {"event_log_errors": {**BASE["event_log_errors"], "disk_errors": 10}, "storage_removals": {"available": True, "events": 4}}, ["failing_drive"], ["chk_dsk"]),
    ("missing_crash_logs", "PC keeps crashing", {"bugchecks": {"available": False}, "event_log_errors": {"available": False}}, [], ["repair_system"]),
    ("competing_pressure", "PC slow and freezes", {"performance_samples": load(cpu=(96,95,97,98), available=(2,3,2,4), commit=(96,95,98,97))}, ["cpu_hog", "memory_pressure"], ["stop_process"]),
    ("dns_contradiction", "Wi-Fi connected but names fail", {**DNS_FAILURE, "network_config": NO_ROUTE["network_config"]}, ["dns_dead"], ["change_dns"]),
    ("missing_coverage", "PC is slow", {"performance_samples": {"available": False}}, [], ["stop_process"]),
    ("timeout", "Wi-Fi slow", {"layered_network": TimeoutError("Timed out")}, [], ["reset_network"]),
    ("permission", "PC slow", {"performance_samples": PermissionError("Access denied")}, [], ["stop_process"]),
    ("compound", "My PC is slow and Wi-Fi keeps dropping", {}, [], ["reset_network"]),
    ("negation", "My PC isn't slow but crashes when opening games", {}, [], ["disable_startup_apps"]),
    ("skip_questions", "Everything was fine until yesterday", {}, [], ["repair_system"]),
    ("command_success_fault_remains", "Disk full", {"disk": {"free_gb": 1, "free_pct": 1}}, ["disk_full"], []),
    ("partial_improvement", "Disk full", {"disk": {"free_gb": 1, "free_pct": 1}}, ["disk_full"], []),
    ("fault_clears", "Disk full", {"disk": {"free_gb": 1, "free_pct": 1}}, ["disk_full"], []),
    ("restart_verification", "Windows update pending restart", {"restart_pending": {"available": True, "pending": True, "reasons": ["Update"]}}, ["needs_restart"], []),
    ("changed_second_scan", "PC slow", {}, [], ["stop_process"]),
    ("healthy_audit", "Full system check", {}, [], ["repair_system", "reset_network", "stop_process"]),
]
