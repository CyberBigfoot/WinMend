"""WinMend diagnostics: repairs: catalog."""

from __future__ import annotations

from winmend.diagnostics.repairs.base import RepairAction
from winmend.diagnostics.repairs.boot import (
    _do_clear_safe_boot,
    _do_disable_fast_startup,
    _do_disable_wake_timers,
    _undo_clear_safe_boot,
    _undo_disable_fast_startup,
    _undo_disable_wake_timers,
)
from winmend.diagnostics.repairs.desktop import (
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
    _undo_rollback_driver,
    _undo_uninstall_update,
)
from winmend.diagnostics.repairs.graphics import (
    _do_clear_shader_cache,
    _do_reset_tdr,
    _do_set_gpu_scheduling,
    _undo_reset_tdr,
    _undo_set_gpu_scheduling,
)
from winmend.diagnostics.repairs.maintenance import _do_run_scheduled_task
from winmend.diagnostics.repairs.memory import (
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
    _do_clear_proxy,
    _do_reset_dns,
    _do_restore_hosts,
    _undo_clear_proxy,
    _undo_reset_dns,
    _undo_restore_hosts,
)
from winmend.diagnostics.repairs.power import (
    _do_disable_pcie_power_saving,
    _do_set_power_plan,
    _undo_disable_pcie_power_saving,
    _undo_set_power_plan,
)
from winmend.diagnostics.repairs.profile import _do_restore_profile, _undo_restore_profile
from winmend.diagnostics.repairs.protection import _do_enable_system_restore
from winmend.diagnostics.repairs.security import (
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
)
from winmend.diagnostics.repairs.updates import (
    _do_clear_update_cache,
    _do_clear_update_policy,
    _do_unblock_updates,
    _undo_clear_update_policy,
    _undo_unblock_updates,
)


REPAIR_ACTIONS = {
    action.id: action for action in (
        RepairAction(
            "reset_tdr", "Restore graphics crash recovery",
            "Puts the graphics timeout settings back to the Windows default so a hung "
            "driver is reset instead of locking the machine.",
            _do_reset_tdr, _undo_reset_tdr,
            risk="safe", admin=True, restore_point=False, duration="under a minute",
            reboot=True, verify_keys=("gpu_hardware",),
        ),
        RepairAction(
            "set_gpu_scheduling", "Turn off hardware GPU scheduling",
            "Switches off hardware-accelerated GPU scheduling, a common cause of stutter "
            "and driver resets on older cards.",
            _do_set_gpu_scheduling, _undo_set_gpu_scheduling,
            risk="safe", admin=True, restore_point=False, duration="under a minute",
            reboot=True, verify_keys=("gpu_hardware", "gpu_resets"),
        ),
        RepairAction(
            "clear_shader_cache", "Clear the graphics shader cache",
            "Deletes the compiled shader caches so the graphics drivers rebuild them. A "
            "corrupted cache produces the same artefacts as a failing card.",
            _do_clear_shader_cache,
            risk="safe", admin=False, restore_point=False, duration="under a minute",
            reboot=False, verify_keys=("gpu_resets", "live_kernel"),
            # Rebuilt automatically by the drivers, so there is nothing to undo
            # and nothing lost -- only a slower first launch.
            reversible=False,
        ),
        RepairAction(
            "schedule_memory_test", "Schedule the Windows memory test",
            "Queues the Windows Memory Diagnostic to run at the next restart, which tests "
            "all of the memory rather than only the part a running system can borrow.",
            _do_schedule_memory_test, _undo_schedule_memory_test,
            risk="safe", admin=True, restore_point=False, duration="under a minute",
            reboot=True, verify_keys=("memory_pattern", "memory_test"), confirm=True,
        ),
        RepairAction(
            "disable_pcie_power_saving", "Stop PCIe links powering down",
            "Turns off PCI Express link power management, a documented cause of NVMe "
            "drives dropping off the bus and of storage controller resets.",
            _do_disable_pcie_power_saving, _undo_disable_pcie_power_saving,
            risk="safe", admin=True, restore_point=False, duration="under a minute",
            reboot=False, verify_keys=("storage_events",),
        ),
        RepairAction(
            "rollback_driver", "Remove a driver package",
            "Removes one third-party driver package so Windows reverts to its own driver.",
            _do_rollback_driver, _undo_rollback_driver,
            risk="destructive", admin=True, restore_point=True, duration="2-5 min",
            reboot=True, verify_keys=("problem_devices", "gpu_resets", "bugchecks"),
            confirm=True, reversible=False,
        ),
        RepairAction(
            "uninstall_update", "Uninstall a Windows update",
            "Removes one specific update by KB number.",
            _do_uninstall_update, _undo_uninstall_update,
            risk="destructive", admin=True, restore_point=True, duration="5-20 min",
            reboot=True, verify_keys=("recent_updates",), confirm=True, reversible=False,
        ),
        RepairAction(
            "reinstall_device", "Reinstall a device driver",
            "Removes one device and lets Windows redetect and reinstall it.",
            _do_reinstall_device, None,
            risk="destructive", admin=True, restore_point=True, duration="1-3 min",
            verify_keys=("problem_devices",), confirm=True,
        ),
        RepairAction(
            "clear_proxy", "Clear the proxy configuration",
            "Turns off the configured proxy and automatic configuration script.",
            _do_clear_proxy, _undo_clear_proxy,
            risk="caution", admin=False, restore_point=False, duration="under 1 min",
            verify_keys=("proxy", "reachability", "dns"),
        ),
        RepairAction(
            "restore_hosts", "Restore the default hosts file",
            "Backs up the current hosts file and replaces it with the Windows default.",
            _do_restore_hosts, _undo_restore_hosts,
            risk="caution", admin=True, restore_point=False, duration="under 1 min",
            verify_keys=("hosts", "reachability", "dns"),
        ),
        RepairAction(
            "reset_dns_servers", "Return DNS to automatic",
            "Clears static DNS servers so the router's are used again.",
            _do_reset_dns, _undo_reset_dns,
            risk="caution", admin=True, restore_point=False, duration="under 1 min",
            verify_keys=("dns_config", "dns", "reachability"),
        ),
        RepairAction(
            "enable_pagefile", "Let Windows manage the page file",
            "Restores system-managed virtual memory.",
            _do_enable_pagefile, _undo_enable_pagefile,
            risk="caution", admin=True, restore_point=True, duration="under 1 min",
            reboot=True, verify_keys=("pagefile",),
        ),
        RepairAction(
            "disable_startup_entry", "Stop one program starting with Windows",
            "Flags a single startup entry as disabled. Nothing is deleted.",
            _do_disable_startup_entry, _undo_disable_startup_entry,
            risk="caution", admin=False, restore_point=False, duration="under 1 min",
            verify_keys=("startup",),
        ),
        RepairAction(
            "restart_service", "Restart a Windows service",
            "Stops and starts one named service.",
            _do_restart_service, None,
            risk="caution", admin=True, restore_point=False, duration="under 1 min",
            # Left empty so the step inherits the evidence keys of whichever
            # rule proposed it: the services, search, and printing findings each
            # measure a different service, and a fixed list here could only ever
            # be right for one of them.
            verify_keys=(),
        ),
        RepairAction(
            "stop_process", "Close a running program",
            "Ends one program so the memory it holds is released.",
            _do_stop_process, None,
            risk="caution", admin=False, restore_point=False, duration="under 1 min",
            verify_keys=("memory", "top_memory"),
        ),
        RepairAction(
            "enable_uac", "Turn User Account Control back on",
            "Restores the prompt before a program is given administrator rights.",
            _do_enable_uac, _undo_enable_uac,
            risk="caution", admin=True, restore_point=False, duration="under 1 min",
            reboot=True, verify_keys=("uac",),
        ),
        RepairAction(
            "enable_realtime_protection", "Turn real-time protection back on",
            "Re-enables Microsoft Defender's live scanning.",
            _do_enable_realtime, None,
            risk="caution", admin=True, restore_point=False, duration="under 1 min",
            verify_keys=("defender",),
        ),
        RepairAction(
            "remove_threats", "Finish removing what Defender found",
            "Completes the removal of detections Defender left outstanding.",
            _do_remove_threats, None,
            risk="caution", admin=True, restore_point=False, duration="1-3 min",
            verify_keys=("threats",),
        ),
        RepairAction(
            "enable_firewall", "Turn the firewall back on",
            "Enables the named firewall profiles and blocks unrequested inbound traffic.",
            _do_enable_firewall, _undo_enable_firewall,
            risk="caution", admin=True, restore_point=False, duration="under 1 min",
            verify_keys=("firewall",),
        ),
        RepairAction(
            "set_service_startup", "Set a service back to starting on its own",
            "Restores one service's start type and starts it.",
            _do_set_service_startup, _undo_set_service_startup,
            risk="caution", admin=True, restore_point=False, duration="under 1 min",
            # Left empty for the same reason as restart_service: the services,
            # search, printing, and update findings each measure a different
            # service, so the proposing hypothesis names what to re-check.
            verify_keys=(),
        ),
        RepairAction(
            "unblock_updates", "Let Windows Update run again",
            "Removes the policies, pause, and disabled services that stop updates.",
            _do_unblock_updates, _undo_unblock_updates,
            risk="caution", admin=True, restore_point=False, duration="under 1 min",
            verify_keys=("update_state",),
        ),
        RepairAction(
            "run_scheduled_task", "Run a Windows maintenance task now",
            "Runs one of Windows' own maintenance tasks and reports what it returns.",
            _do_run_scheduled_task, None,
            risk="caution", admin=True, restore_point=False, duration="2-5 min",
            verify_keys=("scheduled_tasks",),
        ),
        RepairAction(
            "sync_clock", "Correct the system clock",
            "Starts the Windows Time service and resynchronises against an internet time server.",
            _do_sync_clock, _undo_sync_clock,
            risk="caution", admin=True, restore_point=False, duration="under 1 min",
            verify_keys=("time_sync",),
        ),
        RepairAction(
            "renew_lease", "Ask the router for an address again",
            "Renews the DHCP lease, releasing it first if the renewal alone does not work.",
            _do_renew_lease, None,
            risk="caution", admin=True, restore_point=False, duration="1-2 min",
            verify_keys=("ip_config", "reachability", "dns"),
        ),
        RepairAction(
            "reset_adapter", "Restart one network adapter",
            "Disables and re-enables a single adapter so its link is renegotiated.",
            _do_reset_adapter, None,
            risk="caution", admin=True, restore_point=False, duration="under 1 min",
            verify_keys=("link_health", "ip_config"),
        ),
        RepairAction(
            "check_disk", "Repair the file system on a drive",
            "Runs the online scan, and schedules the boot-time repair only if that is not enough.",
            _do_check_disk, _undo_check_disk,
            risk="caution", admin=True, restore_point=False, duration="10-60 min",
            verify_keys=("filesystem",),
        ),
        RepairAction(
            "empty_recycle_bin", "Empty the Recycle Bin on one drive",
            "Permanently deletes what is in that drive's Recycle Bin.",
            _do_empty_recycle_bin, None,
            risk="destructive", admin=False, restore_point=False, duration="1-2 min",
            verify_keys=("volumes", "disk_free"), confirm=True,
        ),
        RepairAction(
            "set_power_plan", "Switch back to the Balanced power plan",
            "Makes Balanced the active plan so the processor is no longer capped.",
            _do_set_power_plan, _undo_set_power_plan,
            risk="caution", admin=True, restore_point=False, duration="under 1 min",
            verify_keys=("power_plan",),
        ),
        RepairAction(
            "enable_system_restore", "Turn System Protection back on",
            "Re-enables System Restore and creates a first point to roll back to.",
            _do_enable_system_restore, None,
            risk="caution", admin=True, restore_point=False, duration="1-3 min",
            verify_keys=("restore_points",),
        ),
        RepairAction(
            "restore_profile", "Point this account back at its real profile",
            "Swaps the temporary profile list entry back for the real one. Nothing is deleted.",
            _do_restore_profile, _undo_restore_profile,
            risk="destructive", admin=True, restore_point=True, duration="under 1 min",
            reboot=True, verify_keys=("user_profile",), confirm=True,
        ),
        RepairAction(
            "clear_safe_boot", "Stop booting into Safe Mode",
            "Removes the boot setting that forces Windows to start in Safe Mode every time.",
            _do_clear_safe_boot, _undo_clear_safe_boot,
            risk="caution", admin=True, restore_point=False, duration="under 1 min",
            reboot=True, verify_keys=("boot_config",),
        ),
        RepairAction(
            "disable_fast_startup", "Turn fast startup off",
            "Makes \"Shut down\" fully stop Windows instead of hibernating the kernel.",
            _do_disable_fast_startup, _undo_disable_fast_startup,
            risk="safe", admin=True, restore_point=False, duration="under 1 min",
            verify_keys=("fast_startup",),
        ),
        RepairAction(
            "disable_wake_timers", "Stop scheduled tasks waking this PC",
            "Switches wake timers off for the current power plan.",
            _do_disable_wake_timers, _undo_disable_wake_timers,
            risk="safe", admin=True, restore_point=False, duration="under 1 min",
            verify_keys=("wake_sources",),
        ),
        RepairAction(
            "enable_trim", "Turn TRIM back on",
            "Lets Windows tell an SSD which blocks are free, which it needs to stay fast.",
            _do_enable_trim, _undo_enable_trim,
            risk="safe", admin=True, restore_point=False, duration="under 1 min",
            verify_keys=("disk_optimization",),
        ),
        RepairAction(
            "optimize_volume", "Optimise a drive",
            "Retrims an SSD or defragments a mechanical disk.",
            _do_optimize_volume, None,
            risk="safe", admin=True, restore_point=False, duration="5-30 min",
            verify_keys=("disk_optimization",), reversible=False,
        ),
        RepairAction(
            "resume_bitlocker", "Turn drive protection back on",
            "Re-enables BitLocker protection on a volume left suspended.",
            _do_resume_bitlocker, None,
            risk="caution", admin=True, restore_point=False, duration="1-2 min",
            verify_keys=("encryption",), reversible=False,
        ),
        RepairAction(
            "reset_winsock", "Reset the network stack",
            "Puts the Winsock catalog back to the layers Windows ships with.",
            _do_reset_winsock, None,
            risk="destructive", admin=True, restore_point=True, duration="1-2 min",
            reboot=True, verify_keys=("winsock", "reachability"), confirm=True, reversible=False,
        ),
        RepairAction(
            "flush_dns_cache", "Clear the DNS cache",
            "Throws away remembered name lookups so the next one asks the server again.",
            _do_flush_dns, None,
            risk="safe", admin=False, restore_point=False, duration="under 1 min",
            verify_keys=("dns_resolution",), reversible=False,
        ),
        RepairAction(
            "set_network_private", "Set this connection to Private",
            "Moves the connection off the Public profile so sharing and discovery work.",
            _do_set_network_private, _undo_set_network_private,
            risk="caution", admin=True, restore_point=False, duration="under 1 min",
            verify_keys=("connection_profile",),
        ),
        RepairAction(
            "set_mtu", "Put the packet size back to standard",
            "Sets an adapter's MTU back to 1500 bytes.",
            _do_set_mtu, _undo_set_mtu,
            risk="caution", admin=True, restore_point=False, duration="under 1 min",
            verify_keys=("mtu",),
        ),
        RepairAction(
            "clear_update_policy", "Point Windows Update back at Microsoft",
            "Removes the policies redirecting updates to another server or pinning a version.",
            _do_clear_update_policy, _undo_clear_update_policy,
            risk="caution", admin=True, restore_point=False, duration="1-2 min",
            verify_keys=("update_policy", "update_state"),
        ),
        RepairAction(
            "clear_update_cache", "Clear the update download folder",
            "Sets aside the half-downloaded update files so Windows fetches them again.",
            _do_clear_update_cache, None,
            risk="caution", admin=True, restore_point=False, duration="2-5 min",
            verify_keys=("update_cache", "update_failures"), reversible=False,
        ),
        RepairAction(
            "reregister_app", "Repair a Store app",
            "Registers one app again against the files it already has.",
            _do_reregister_app, None,
            risk="caution", admin=False, restore_point=False, duration="1-2 min",
            verify_keys=("store_apps",), reversible=False,
        ),
        RepairAction(
            "restart_explorer", "Restart the desktop",
            "Restarts Explorer, which draws the desktop, taskbar, and Start menu.",
            _do_restart_explorer, None,
            risk="caution", admin=False, restore_point=False, duration="under 1 min",
            verify_keys=("shell",), reversible=False,
        ),
        RepairAction(
            "restart_audio", "Restart the audio services",
            "Stops and starts the audio stack in dependency order, rebuilding playback devices.",
            _do_restart_audio, None,
            risk="caution", admin=True, restore_point=False, duration="under 1 min",
            verify_keys=("audio",), reversible=False,
        ),
        RepairAction(
            "start_onedrive", "Start OneDrive",
            "Starts the OneDrive client so redirected folders sync again.",
            _do_start_onedrive, None,
            risk="safe", admin=False, restore_point=False, duration="under 1 min",
            verify_keys=("known_folders",), reversible=False,
        ),
        RepairAction(
            "repair_path", "Repair the system PATH",
            "Adds the standard Windows folders back to the PATH without touching anything else.",
            _do_repair_path, _undo_repair_path,
            risk="caution", admin=True, restore_point=True, duration="under 1 min",
            reboot=True, verify_keys=("path",),
        ),
        RepairAction(
            "remove_policy", "Remove a restriction",
            "Removes one policy value that is switching a Windows feature off.",
            _do_remove_policy, _undo_remove_policy,
            risk="caution", admin=True, restore_point=False, duration="under 1 min",
            verify_keys=("policies",),
        ),
    )
}
