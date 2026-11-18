"""Compatibility imports for the modular WinMend package."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from winmend.core.findings import SEVERITY, _finding, utc_now
from winmend.diagnostics.catalog import (
    COLLECTOR_ORIGINS,
    Cancelled,
    FINDING_SOURCES,
    PROTECTION_FIRST,
    collectors_for,
)
from winmend.diagnostics.collectors.deep import DeepProbe
from winmend.diagnostics.collectors.windows import WindowsProbe
from winmend.diagnostics.components import build_component_report, device_guidance
from winmend.diagnostics.context import Context
from winmend.diagnostics.engine import CaseEngine
from winmend.diagnostics.evidence import finding_evidence
from winmend.diagnostics.hardware.probe import HardwareProbe
from winmend.diagnostics.helpers import (
    _days_ago,
    _evidence,
    _is_private_address,
    _iso_to_dt,
    _plural,
    _scan_age,
    _tri_state,
)
from winmend.diagnostics.interview import (
    INTERVIEW_BY_ID,
    INTERVIEW_QUESTIONS,
    Interview,
    Question,
    _in_parts,
    _mentions,
)
from winmend.diagnostics.models import (
    Hypothesis,
    _default_task_lookup,
    _profile_names,
    repair_action,
    task_action,
)
from winmend.diagnostics.reference import (
    AUDIT_PROFILE,
    BENIGN_TASK_RESULTS,
    BUGCHECK_CODES,
    CRITICAL_SERVICES,
    DEVICE_PROBLEM_CODES,
    EXCEPTION_CODES,
    HARDWARE_PROFILE,
    KNOWN_DNS,
    MAINTENANCE_TASKS,
    POWER_SCHEMES,
    PRINTER_STATUS,
    PROTECTED_HOSTS,
    SEVERITY_RANK,
    UNRESOLVED_THREAT_STATUS,
    VENDOR_MODULES,
    WHEA_EVENTS,
    WHEA_SOURCES,
    WINDOWS_BUILDS,
    WU_ERROR_CODES,
    _EXPECTED_DISK_USERS,
    _LICENSE_STATUS,
    _POLICY_WATCHLIST,
    _VIRTUAL_ADAPTERS,
    _WINSOCK_STOCK,
    _maintenance_task,
    _policy_watchlist,
    describe_bugcheck,
    describe_whea,
    describe_wu_error,
    module_vendor,
)
from winmend.diagnostics.repairs.base import RepairAction, _result, _run_command
from winmend.diagnostics.repairs.boot import (
    _POWER_KEY,
    _do_clear_safe_boot,
    _do_disable_fast_startup,
    _do_disable_wake_timers,
    _undo_clear_safe_boot,
    _undo_disable_fast_startup,
    _undo_disable_wake_timers,
)
from winmend.diagnostics.repairs.catalog import REPAIR_ACTIONS
from winmend.diagnostics.repairs.common import (
    _SERVICES_KEY,
    _START_VALUES,
    _START_WORDS,
    _ps_run,
    _registry_apply,
    _registry_restore,
    _registry_snapshot,
    _service_start,
    _valid_drive,
    _valid_service_name,
)
from winmend.diagnostics.repairs.desktop import (
    _ENVIRONMENT_KEY,
    _do_remove_policy,
    _do_repair_path,
    _do_reregister_app,
    _do_restart_audio,
    _do_restart_explorer,
    _do_start_onedrive,
    _undo_remove_policy,
    _undo_repair_path,
)
from winmend.diagnostics.repairs.drivers import (
    _do_reinstall_device,
    _do_rollback_driver,
    _do_uninstall_update,
    _find_update_package,
    _undo_rollback_driver,
    _undo_uninstall_update,
)
from winmend.diagnostics.repairs.graphics import (
    _GRAPHICS_KEY,
    _SHADER_CACHES,
    _do_clear_shader_cache,
    _do_reset_tdr,
    _do_set_gpu_scheduling,
    _undo_reset_tdr,
    _undo_set_gpu_scheduling,
)
from winmend.diagnostics.repairs.maintenance import _do_run_scheduled_task
from winmend.diagnostics.repairs.memory import (
    _MEMORY_KEY,
    _do_enable_pagefile,
    _do_schedule_memory_test,
    _undo_enable_pagefile,
    _undo_schedule_memory_test,
)
from winmend.diagnostics.repairs.network import (
    _do_flush_dns,
    _do_renew_lease,
    _do_reset_adapter,
    _do_reset_winsock,
    _do_set_mtu,
    _do_set_network_private,
    _do_sync_clock,
    _undo_set_mtu,
    _undo_set_network_private,
    _undo_sync_clock,
)
from winmend.diagnostics.repairs.network_config import (
    _DEFAULT_HOSTS,
    _PROXY_KEY,
    _do_clear_proxy,
    _do_reset_dns,
    _do_restore_hosts,
    _hosts_path,
    _undo_clear_proxy,
    _undo_reset_dns,
    _undo_restore_hosts,
)
from winmend.diagnostics.repairs.power import (
    _BALANCED_SCHEME,
    _do_disable_pcie_power_saving,
    _do_set_power_plan,
    _undo_disable_pcie_power_saving,
    _undo_set_power_plan,
)
from winmend.diagnostics.repairs.profile import (
    _PROFILE_LIST,
    _do_restore_profile,
    _profile_path_of,
    _read_key_values,
    _undo_restore_profile,
    _write_key_values,
)
from winmend.diagnostics.repairs.protection import _do_enable_system_restore
from winmend.diagnostics.repairs.security import (
    _FIREWALL_NAMES,
    _UAC_KEY,
    _do_enable_firewall,
    _do_enable_realtime,
    _do_enable_uac,
    _do_remove_threats,
    _undo_enable_firewall,
    _undo_enable_uac,
)
from winmend.diagnostics.repairs.services import (
    _do_restart_service,
    _do_set_service_startup,
    _do_stop_process,
    _undo_set_service_startup,
)
from winmend.diagnostics.repairs.startup import (
    _do_disable_startup_entry,
    _undo_disable_startup_entry,
)
from winmend.diagnostics.repairs.storage import (
    _do_check_disk,
    _do_empty_recycle_bin,
    _do_enable_trim,
    _do_optimize_volume,
    _do_resume_bitlocker,
    _undo_check_disk,
    _undo_enable_trim,
    recycle_bin_bytes,
)
from winmend.diagnostics.repairs.updates import (
    _WU_AU_KEY,
    _WU_POLICY_KEY,
    _WU_REDIRECT_VALUES,
    _WU_SERVICES,
    _WU_UX_KEY,
    _do_clear_update_cache,
    _do_clear_update_policy,
    _do_unblock_updates,
    _undo_clear_update_policy,
    _undo_unblock_updates,
)
from winmend.diagnostics.rules import RULES
from winmend.diagnostics.rules.boot import (
    rule_fast_startup_masking,
    rule_safe_mode_stuck,
    rule_unsigned_drivers,
    rule_wakes_itself,
)
from winmend.diagnostics.rules.components import (
    rule_component_device_status,
    rule_cooling_fault,
    rule_drive_failing_smart,
    rule_drive_link_faults,
    rule_drive_read_failures,
    rule_firmware_stale,
    rule_gpu_hardware_fault,
    rule_gpu_link_degraded,
    rule_gpu_memory_errors,
    rule_gpu_recovery_disabled,
    rule_kernel_pool_leak,
    rule_log_storm,
    rule_memory_proven_faulty,
    rule_motherboard_firmware_errors,
    rule_partitions_misaligned,
    rule_power_delivery,
    rule_repeating_bugcheck,
    rule_shared_crash_module,
    rule_tpm_not_ready,
)
from winmend.diagnostics.rules.context import (
    PROFILE_BASELINE,
    rule_cpu_throttled,
    rule_hardware_error,
    rule_memory_test_failed,
    rule_pending_restart,
    rule_profile_baseline,
    rule_stability_drop,
)
from winmend.diagnostics.rules.desktop import (
    rule_audio_dead,
    rule_basic_display_driver,
    rule_bluetooth_broken,
    rule_broken_store_apps,
    rule_files_stranded,
    rule_path_broken,
    rule_policy_restrictions,
    rule_shell_stopped,
    rule_system_files_corrupt,
)
from winmend.diagnostics.rules.hardware import (
    rule_bad_memory,
    rule_battery_worn,
    rule_failing_drive,
    rule_thermal_throttle,
)
from winmend.diagnostics.rules.history import (
    DRIVER_CLASS_AREAS,
    rule_app_crash_module,
    rule_gpu_driver,
    rule_problem_devices,
    rule_recent_driver,
    rule_recent_program,
    rule_recent_update,
)
from winmend.diagnostics.rules.network import (
    rule_hosts_hijack,
    rule_rogue_dns,
    rule_rogue_proxy,
    rule_upstream_network,
    rule_weak_wifi,
)
from winmend.diagnostics.rules.network_stack import (
    rule_broken_winsock,
    rule_captive_portal,
    rule_dns_dead,
    rule_dns_hijacked,
    rule_metered_connection,
    rule_odd_mtu,
    rule_public_profile,
)
from winmend.diagnostics.rules.registry import rule
from winmend.diagnostics.rules.security import (
    rule_defender_exclusions,
    rule_defender_off,
    rule_malware_symptoms,
    rule_reboot_relief,
    rule_safe_mode_clean,
)
from winmend.diagnostics.rules.storage import (
    rule_dirty_filesystem,
    rule_drive_wear,
    rule_secondary_volume_full,
)
from winmend.diagnostics.rules.storage_upkeep import (
    rule_bitlocker_suspended,
    rule_disk_hog,
    rule_trim_off,
    rule_volume_unhealthy,
)
from winmend.diagnostics.rules.system import (
    _volume_named,
    match_startup_entry,
    rule_component_corruption,
    rule_disk_full,
    rule_memory_pressure,
    rule_pagefile_disabled,
    rule_single_channel_memory,
    rule_startup_bloat,
    rule_update_error,
    rule_windows_eol,
)
from winmend.diagnostics.rules.updates import (
    rule_not_activated,
    rule_update_cache_stale,
    rule_update_pinned,
    rule_update_redirected,
)
from winmend.diagnostics.rules.upkeep import (
    rule_active_threat,
    rule_clock_drift,
    rule_cpu_hog,
    rule_critical_service_stopped,
    rule_firewall_off,
    rule_link_errors,
    rule_maintenance_task_failing,
    rule_no_protection,
    rule_no_route,
    rule_power_saver,
    rule_print_spooler,
    rule_search_broken,
    rule_temporary_profile,
    rule_uac_disabled,
    rule_update_blocked,
)
from winmend.diagnostics.timeline import ChangeTimeline
from winmend.reports.case import render_case_report_html
import json
import os
import re
import shutil
import socket
import subprocess
import time
import uuid
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


__all__ = [
    "DeepProbe", "Interview", "INTERVIEW_QUESTIONS", "CaseEngine",
    "RepairAction", "REPAIR_ACTIONS", "Hypothesis", "RULES",
    "BUGCHECK_CODES", "WU_ERROR_CODES", "EXCEPTION_CODES", "DEVICE_PROBLEM_CODES",
    "WINDOWS_BUILDS", "VENDOR_MODULES", "describe_bugcheck", "describe_wu_error",
    "render_case_report_html",
]
