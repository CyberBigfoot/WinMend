"""Compatibility imports for the modular WinMend package."""

from PySide6.QtCore import (
    QEasingCurve,
    QEvent,
    QObject,
    QPersistentModelIndex,
    QPointF,
    QRectF,
    QSize,
    QTimer,
    QVariantAnimation,
    Qt as QtC,
    Signal,
)
from PySide6.QtGui import (
    QColor,
    QFont,
    QIcon,
    QKeySequence,
    QPainter,
    QPainterPath,
    QPalette,
    QPen,
    QPixmap,
    QPolygonF,
    QShortcut,
    QTextCursor,
)
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QStackedWidget,
    QStyle,
    QStyleOptionViewItem,
    QStyledItemDelegate,
    QTabWidget,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItem,
    QTreeWidgetItemIterator,
    QVBoxLayout,
    QWidget,
)
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from winmend.bootstrap import (
    _startup_alert,
    check_dependencies,
    is_frozen,
    main,
    restart_as_admin,
    startup_log,
    wm_main_qt,
)
from winmend.core.models import WMTask
from winmend.core.preferences import _get_pref_path
from winmend.core.processes import (
    WMCompleted,
    WM_STALL_NOTICE_SECS,
    _WM_CHILDREN,
    _WM_CHILDREN_LOCK,
    _no_console_startupinfo,
    wm_kill_children,
    wm_kill_tree,
    wm_run,
    wm_track_child,
    wm_untrack_child,
)
from winmend.core.registry import create_reg_key, open_reg_key
from winmend.core.search import _wm_last_line, wm_normalize_query, wm_query_has
from winmend.core.security import SecurityUtils
from winmend.core.state import WMBoolVar, WMStrVar
from winmend.core.task_host_base import SystemCleanerGUI
from winmend.core.windows import bring_window_to_front, process_prompts, visible_windows
from winmend.data.app_catalog import INSTALLABLE_APPS, get_apps_by_category, get_categories
from winmend.data.task_catalog import WM_CATEGORIES, WM_HANDLERS, WM_TASKS
from winmend.data.tools import WINDBG_DIRECT_DOWNLOAD_URL, WINDBG_LEARN_URL, WINDBG_WINGET_ID
from winmend.diagnostics.collectors.windows import WindowsProbe
from winmend.diagnostics.engine import CaseEngine
from winmend.diagnostics.profiles import DiagnosticEngine
from winmend.diagnostics.reference import (
    AUDIT_PROFILE as WM_AUDIT_PROFILE,
    HARDWARE_PROFILE as WM_HARDWARE_PROFILE,
)
from winmend.diagnostics.repairs.catalog import REPAIR_ACTIONS
from winmend.features.apps.winget import parse_winget_list, parse_winget_upgrade
from winmend.features.cleanup_helpers import (
    CLEANMGR_EXCLUDED,
    CLEANMGR_STAGE_SERVICES,
    IdleWatch,
    VOLUME_CACHES_KEY,
    cleanmgr_activity_signature,
    configure_cleanmgr_profile,
    disarm_legacy_profile,
    format_bytes_freed,
    format_elapsed,
    plan_cleanmgr_stages,
    processes_named,
    service_pids,
)
from winmend.features.debloat.helpers import ONEDRIVE_DEBLOAT_KEY, build_debloat_options
from winmend.features.explorer.helpers import (
    EXPLORER_HISTORY_KEYS,
    EXPLORER_JUMP_LISTS,
    KNOWN_FOLDER_ALIASES,
    OVERLAY_HANDLER_LIMIT,
    QUICK_ACCESS_APPID,
    delete_registry_tree,
    drive_kind,
    host_answers,
    jump_list_kind,
    jump_list_path,
    known_folder_path,
    mapped_drive_target,
    network_shortcuts,
    network_target_host,
    persistent_mapped_drives,
    quick_access_pins,
    read_jump_list,
    recent_items_dir,
    restart_explorer,
    shell_extension_inventory,
    start_explorer,
    stop_explorer,
)
from winmend.features.network_dns import DNS_PROVIDERS, dns_provider
from winmend.features.office.helpers import (
    CLICKTORUN_SERVICE,
    NEW_OUTLOOK_STORE_ID,
    OFFICE_BACKGROUND_OK,
    OFFICE_COMMON_KEY,
    OFFICE_IDENTITY_KEYS,
    OFFICE_LICENSE_FOLDERS,
    OFFICE_PROCESS_NAMES,
    build_office_repair_options,
    data_file_verdict,
    default_mail_client,
    office_addins,
    office_auth_findings,
    office_c2r_repair_command,
    office_c2r_update_command,
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
    parse_ospp_status,
    service_state,
    summarize_office_crashes,
    windowless_processes,
)
from winmend.features.shell_helpers import reset_user_choices
from winmend.features.speedtest.connection import wifi_bottleneck_verdict
from winmend.features.speedtest.history import SpeedTestHistory, summarize_result_for_history
from winmend.features.speedtest.metrics import responsiveness_rpm
from winmend.features.speedtest.runner import SpeedTest
from winmend.features.speedtest.verdicts import usage_verdicts
from winmend.features.startup.helpers import (
    file_company,
    list_startup_entries,
    set_startup_entry_enabled,
)
from winmend.features.storage.duplicates import wm_find_duplicates
from winmend.features.storage.scanner import (
    SSSafetyRules,
    SSScanner,
    SS_COLOR_CORE,
    SS_COLOR_LARGE,
    SS_COLOR_MEDIUM,
    SS_HINTS,
    SS_THRESHOLD_GB,
    SS_THRESHOLD_MB,
    ss_format_size,
    ss_get_drive_details,
    ss_get_drive_health_info,
    ss_get_file_hint,
    ss_send_to_recycle_bin,
)
from winmend.features.storage.tree import SSNode, wm_build_tree, wm_duration
from winmend.features.tweaks import WM_TWEAKS, apply_tweak, read_tweak_state, tweak_groups
from winmend.reports.case import render_case_report_html
from winmend.reports.speedtest import render_speedtest_report_html
from winmend.reports.system import PCReporter
from winmend.safety.journal import SafetyJournal
from winmend.safety.restore_points import wm_find_restore_point
from winmend.ui.dialogs import (
    WMMessageBox,
    WMMessageBox as messagebox,
    WMRootStub,
    WMSimpleDialog,
    WMSimpleDialog as simpledialog,
)
from winmend.ui.main_window import WMMainWindow
from winmend.ui.pages.apps import WMAppInstallerPage
from winmend.ui.pages.guided_fix import WMGuidedFixPage
from winmend.ui.pages.journal import WMSafetyJournalPage
from winmend.ui.pages.speedtest import WMSpeedTestPage
from winmend.ui.pages.startup import WMStartupPage
from winmend.ui.pages.storage import WMStoragePage
from winmend.ui.pages.tweaks import WMToggle, WMTweaksPage
from winmend.ui.task_host import WMTaskHost
from winmend.ui.theme import (
    WM_DARK,
    WM_FONT,
    WM_FONT_MONO,
    WM_GLYPH,
    WM_ICON_FONT,
    WM_LIGHT,
    wm_detect_windows_theme,
    wm_load_theme_pref,
    wm_windows_name,
)
from winmend.ui.widgets.controls import (
    WMCheckBox,
    WMPill,
    WMSwitchDelegate,
    WMTaskCard,
    WMThemeCurtain,
    WMThemeSwitch,
    WM_SWITCH_DURATION,
    WM_SWITCH_HEIGHT,
    WM_SWITCH_WIDTH,
    _wm_paint_switch,
    wm_hline,
)
from winmend.ui.widgets.hypothesis import WMHypothesisCard, WMStepShim
from winmend.ui.widgets.latency import WMLatencyGraph
from winmend.ui.widgets.queue import WMQueueRow
from winmend.ui.widgets.winget import WMWingetPanel
import ctypes
import hashlib
import html as _html
import json
import math
import os
import platform
import queue
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import traceback
import uuid
import webbrowser
import winreg


__all__ = tuple(name for name in globals() if not name.startswith("__"))
