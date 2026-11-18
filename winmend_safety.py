"""Compatibility imports for the modular WinMend package."""

from datetime import datetime, timezone
from pathlib import Path
from winmend.core.findings import JOURNAL_SCHEMA, SEVERITY, _finding, utc_now
from winmend.core.registry_values import _ROOTS, _hive
from winmend.core.windows import (
    PROGRESS_BAR_CLASS,
    _user32,
    bring_window_to_front,
    classify_prompt,
    pids_with_visible_windows,
    process_prompts,
    visible_windows,
    window_children,
)
from winmend.diagnostics.collectors.windows import WindowsProbe
from winmend.diagnostics.profiles import DiagnosticEngine
from winmend.features.apps.winget import (
    _parse_winget_row,
    _winget_columns,
    _winget_table_rows,
    parse_winget_list,
    parse_winget_upgrade,
)
from winmend.features.cleanup_helpers import (
    CLEANMGR_EXCLUDED,
    CLEANMGR_LEGACY_PROFILE,
    CLEANMGR_STAGES,
    CLEANMGR_STAGE_SERVICES,
    CLEANMGR_WORKER_NAMES,
    IdleWatch,
    VOLUME_CACHES_KEY,
    cleanmgr_activity_signature,
    cleanmgr_profile_value,
    configure_cleanmgr_profile,
    disarm_legacy_profile,
    format_bytes_freed,
    format_elapsed,
    plan_cleanmgr_stages,
    processes_named,
    service_pids,
)
from winmend.features.debloat.helpers import (
    DEBLOAT_BREAKS,
    DEBLOAT_EXTREME_EXTRA,
    DEBLOAT_STANDARD,
    ONEDRIVE_DEBLOAT_KEY,
    _DEBLOAT_COMMONLY_USED,
    build_debloat_options,
    debloat_candidates,
    match_debloat_packages,
)
from winmend.features.explorer.helpers import (
    DRIVE_KINDS,
    EXPLORER_HISTORY_KEYS,
    EXPLORER_JUMP_LISTS,
    KNOWN_FOLDER_ALIASES,
    MAPPED_DRIVES_KEY,
    OVERLAY_HANDLER_LIMIT,
    QUICK_ACCESS_APPID,
    _BLOCKED_ROOT,
    _CLSID_RE,
    _CONTEXT_MENU_ROOTS,
    _DESTLIST_ENTRY_FIXED,
    _DESTLIST_HEADER,
    _DESTLIST_MIN_VERSION,
    _OVERLAY_ROOT,
    _clsid_dll,
    _clsid_is_packaged,
    _default_value,
    _subkeys,
    delete_registry_tree,
    drive_kind,
    host_answers,
    is_microsoft_company,
    jump_list_kind,
    jump_list_path,
    known_folder_path,
    mapped_drive_target,
    network_shortcuts,
    network_shortcuts_dir,
    network_target_host,
    network_target_port,
    parse_destlist,
    persistent_mapped_drives,
    quick_access_pins,
    read_destlist,
    read_jump_list,
    recent_items_dir,
    restart_explorer,
    shell_extension_inventory,
    start_explorer,
    stop_explorer,
)
from winmend.features.network_dns import DNS_PROVIDERS, dns_provider
from winmend.features.office.helpers import (
    APPX_REPOSITORY_KEY,
    C2R_VIRTUAL_CLASSES,
    CLICKTORUN_SERVICE,
    GPU_MODULE_PREFIXES,
    LOAD_BEHAVIOR,
    NEW_OUTLOOK_PACKAGE,
    NEW_OUTLOOK_STORE_ID,
    OFFICE_APPS,
    OFFICE_APP_PATHS_KEY,
    OFFICE_AUTH_WATCHLIST,
    OFFICE_BACKGROUND_OK,
    OFFICE_C2R_CONFIG_KEY,
    OFFICE_C2R_KEY,
    OFFICE_COMMON_KEY,
    OFFICE_CREDENTIAL_PREFIXES,
    OFFICE_IDENTITY_KEYS,
    OFFICE_LICENSE_FOLDERS,
    OFFICE_PROCESS_NAMES,
    OUTLOOK_ADDIN_ROOTS,
    OUTLOOK_DEFAULT_SIZE_LIMIT_MB,
    OUTLOOK_KEY,
    OUTLOOK_STORE_PATH_VALUES,
    WINDOWS_CORE_MODULES,
    _addin_path,
    _clsid_code_path,
    _file_url_to_path,
    _progid_clsid,
    _reg_value,
    _walk_values,
    addin_for_module,
    appx_package_installed,
    build_office_repair_options,
    classify_office_crash,
    data_file_verdict,
    decode_utf16_path,
    default_mail_client,
    office_addins,
    office_auth_findings,
    office_c2r_repair_command,
    office_c2r_update_command,
    office_client_paths,
    office_crash_events,
    office_credential_targets,
    office_hardware_acceleration_disabled,
    office_installation,
    office_subscription_accounts,
    outlook_data_files,
    outlook_minimizes_to_tray,
    outlook_profiles,
    outlook_size_limit_mb,
    outlook_store_paths,
    parse_cmdkey_list,
    parse_office_crash_output,
    parse_ospp_status,
    service_state,
    summarize_office_crashes,
    windowless_processes,
)
from winmend.features.shell_helpers import (
    FILE_EXTS_KEY,
    URL_ASSOCIATIONS_KEY,
    USER_CHOICE_KEYS,
    _delete_key_tree,
    reset_user_choices,
)
from winmend.features.speedtest.connection import (
    _run_command,
    _tcp_rtt,
    active_connection,
    bufferbloat_grade,
    ipv6_connectivity,
    measure_dns,
    multi_target_latency,
    parse_link_speed,
    parse_netsh_wifi,
    wifi_bottleneck_verdict,
)
from winmend.features.speedtest.history import SpeedTestHistory, summarize_result_for_history
from winmend.features.speedtest.metrics import (
    BUFFERBLOAT_GRADES,
    _percentile,
    aggregate_throughput,
    responsiveness_rpm,
    summarize_latency,
)
from winmend.features.speedtest.runner import (
    SpeedTest,
    _ByteCounter,
    _CA_BUNDLE_CACHE,
    _CA_BUNDLE_RESOLVED,
    resolve_ca_bundle,
)
from winmend.features.speedtest.verdicts import usage_verdicts
from winmend.features.startup.helpers import (
    _FILETIME_EPOCH_OFFSET,
    _STARTUP_APPROVED_BASE,
    _STARTUP_RUN_KEY,
    _STARTUP_RUN_KEY_WOW,
    _resolve_lnk,
    _startup_entry_enabled,
    exe_from_command,
    file_company,
    list_startup_entries,
    set_startup_entry_enabled,
    startup_blob_is_disabled,
    startup_disable_blob,
    startup_enable_blob,
)
from winmend.features.tweaks import (
    CLASSIC_MENU_KEY,
    REMOVE,
    TweakValue,
    WM_TWEAKS,
    WindowsTweak,
    _EXPLORER_ADV,
    _SEARCH,
    _masked_write,
    _matches,
    _read_typed,
    _read_value,
    _v,
    apply_tweak,
    read_classic_context_menu,
    read_tweak_state,
    set_classic_context_menu,
    tweak_groups,
)
from winmend.reports.speedtest import render_speedtest_report_html
from winmend.safety.journal import SafetyJournal
import html
import json
import math
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None
