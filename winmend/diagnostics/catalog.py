"""WinMend diagnostics: catalog."""

from __future__ import annotations




# ---------------------------------------------------------------------------
# The case engine
# ---------------------------------------------------------------------------

class Cancelled(Exception):
    """Raised inside a sweep when the caller asked it to stop."""


# Steps that exist to make the rest of the plan reversible. A restore point
# taken after the repairs records the broken state, which is worse than useless.
PROTECTION_FIRST = ("enable_system_restore", "create_restore_point_guardrail")


# Which collector produces each finding row.
#
# Two namespaces meet here: findings are what the user sees and what
# verification compares, collectors are the code that measures them. Re-running
# one step's checks means going from the first to the second, so the mapping has
# to be explicit -- keeping them implicitly parallel is how a "verify" silently
# measures nothing at all.
FINDING_SOURCES = {
    "system_context": ("system_context",),
    "tcp_connectivity": ("layered_network",),
    "tcp_ipv4": ("layered_network",),
    "tcp_ipv6": ("layered_network",),
    "resolver_queries": ("layered_network",),
    "https_connectivity": ("layered_network",),
    "resource_cpu": ("performance_samples",),
    "resource_memory": ("performance_samples",),
    "resource_storage": ("performance_samples",),
    "disk_free": ("disk",),
    "volumes": ("volumes",),
    # The dirty bit lives on the volume record, so re-checking the file system
    # means re-reading both sources.
    "filesystem": ("filesystem_health", "volumes"),
    "temp_size": ("temp_size",),
    "memory": ("memory",),
    "cpu_load": ("cpu_load",),
    # Both, so a re-check after disabling startup apps re-reads the enabled
    # state rather than the raw registry count.
    "startup": ("startup_entries", "startup_count"),
    "uptime": ("uptime_days",),
    "pending_reboot": ("pending_reboot", "restart_pending"),
    "windows_version": ("windows_version",),
    "smart": ("smart_health",),
    "drive_wear": ("disk_reliability",),
    "storage_faults": ("storage_removals",),
    "evt_shutdowns": ("event_log_errors",),
    "evt_hardware": ("event_log_errors",),
    "evt_disk": ("event_log_errors",),
    "evt_services": ("event_log_errors",),
    "bugchecks": ("bugchecks",),
    "crash_dumps": ("dump_files",),
    "services": ("service_health",),
    "scheduled_tasks": ("scheduled_tasks",),
    "gpu_resets": ("gpu_resets",),
    "app_crashes": ("app_crashes",),
    "problem_devices": ("problem_devices",),
    "thermal": ("thermal_events",),
    "update_failures": ("update_failures",),
    "update_state": ("update_state",),
    "recent_updates": ("installed_updates",),
    "recent_drivers": ("third_party_drivers",),
    "recent_programs": ("installed_programs",),
    "component_store": ("component_store_health",),
    "pagefile": ("pagefile",),
    "proxy": ("proxy_settings",),
    "hosts": ("hosts_file",),
    "dns_config": ("dns_servers",),
    "adapters": ("network",),
    "dns": ("network",),
    "reachability": ("network",),
    "net_quality": ("ping_quality",),
    "ip_config": ("network_config",),
    "link_health": ("adapter_health",),
    "time_sync": ("time_sync",),
    "wifi_link": ("wifi_link",),
    "defender": ("defender",),
    "threats": ("defender_threats",),
    "firewall": ("firewall_enabled", "firewall_profiles"),
    "uac": ("uac_state",),
    "defender_exclusions": ("defender_exclusions",),
    "platform": ("platform_security",),
    "battery_wear": ("battery_wear",),
    "memory_config": ("memory_config",),
    "top_memory": ("top_memory_processes",),
    "boot_time": ("boot_history",),
    "power_plan": ("power_config",),
    "disk_latency": ("disk_latency",),
    "restore_points": ("restore_points",),
    "search_index": ("search_index",),
    "printers": ("printers",),
    "user_profile": ("user_profile",),
    # -- added with the wider evidence sweep -------------------------------
    "hardware_errors": ("whea_errors",),
    "memory_test": ("memory_diagnostic",),
    "cpu_clock": ("cpu_throttle",),
    "stability": ("reliability_history",),
    "boot_config": ("boot_config",),
    "fast_startup": ("fast_startup",),
    "wake_sources": ("wake_history",),
    "disk_optimization": ("disk_optimization",),
    "encryption": ("bitlocker_state",),
    "disk_activity": ("top_disk_processes",),
    "dns_resolution": ("dns_resolution",),
    "connection_profile": ("network_profile",),
    "winsock": ("winsock_health",),
    "mtu": ("interface_mtu",),
    "update_policy": ("update_policy",),
    "update_cache": ("update_cache",),
    "activation": ("activation_state",),
    "store_apps": ("appx_health",),
    "shell": ("shell_health",),
    "audio": ("audio_health",),
    "bluetooth": ("bluetooth_health",),
    "display": ("display_config",),
    "system_files": ("integrity_history",),
    "policies": ("policy_health",),
    "path": ("environment_health",),
    "known_folders": ("known_folders",),
    # -- the component-level hardware scan ---------------------------------
    "firmware": ("firmware_info", "cpu_details"),
    "component_devices": ("component_devices",),
    "cpu_hardware": ("cpu_details",),
    "memory_modules": ("memory_modules",),
    "sensors": ("sensor_readings",),
    "power_loss": ("power_events",),
    "firmware_errors": ("firmware_errors",),
    "tpm": ("tpm_state",),
    "gpu_hardware": ("gpu_hardware",),
    "live_kernel": ("live_kernel_events",),
    "gpu_telemetry": ("gpu_vendor_telemetry",),
    "monitors": ("display_links",),
    "smart_detail": ("smart_attributes",),
    "storage_events": ("storage_bus_errors",),
    "disk_geometry": ("disk_geometry",),
    "disk_surface": ("disk_read_sweep",),
    "memory_pattern": ("memory_pattern_test",),
    "kernel_pool": ("pool_usage",),
    "log_sweep": ("event_log_sweep",),
    "crash_reports": ("wer_reports",),
    "crash_dumps_detail": ("minidump_details",),
}


def collectors_for(finding_keys):
    """Collector names needed to re-measure the given finding keys."""
    names = []
    for key in finding_keys or ():
        for collector in FINDING_SOURCES.get(key, ()):
            if collector not in names:
                names.append(collector)
    return names


# Where each collector actually looked.
#
# FINDING_SOURCES answers "which code measured this"; this answers the question
# the user asks next, which is "where did you get that from". A verdict the user
# cannot trace back to a registry value, an event ID or a command is an
# assertion, and this app is not in the business of those. Each line names the
# real facility, so a sceptical user can go and read the same thing themselves.
COLLECTOR_ORIGINS = {
    "system_context": "CIM operating-system and management state, NetAdapter, NRPT, boot time and power source; no machine or account names.",
    "layered_network": "Two attempts to 1.1.1.1 and 8.8.8.8 on TCP 443; repeated Resolve-DnsName and HTTPS HEAD to Microsoft and Cloudflare, with timeouts.",
    "performance_samples": "Repeated psutil counters and GetPerformanceInfo commit usage, after subprocess diagnostics finish; per-device I/O deltas.",
    # -- fast pass ---------------------------------------------------------
    "disk": "Free and total space on the Windows drive, read from the file system itself.",
    "memory": "The live memory counters behind Task Manager's Memory tab.",
    "uptime_days": "The boot time Windows records, measured against the current clock.",
    "startup_count": r"The HKCU and HKLM ...\CurrentVersion\Run keys, plus both Start menu Startup folders.",
    "startup_entries": r"Everything Task Manager's Startup tab shows: the Run keys, the Startup folders, "
                       r"and the StartupApproved flags that record which entries are disabled.",
    "pending_reboot": r"HKLM\...\WindowsUpdate\Auto Update\RebootRequired and "
                      r"HKLM\...\Component Based Servicing\RebootPending.",
    "restart_pending": r"The same two restart keys, plus PendingFileRenameOperations under "
                       r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager.",
    "windows_version": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion (build, edition), checked "
                       r"against Microsoft's published servicing end dates.",
    "proxy_settings": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings -- the proxy "
                      r"and auto-config URL Windows applies.",
    "hosts_file": r"C:\Windows\System32\drivers\etc\hosts, read line by line.",
    "network": "Adapter link states, a DNS lookup of www.microsoft.com, and a TCP connection to 1.1.1.1:443.",
    "uac_state": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System "
                 r"(EnableLUA and the consent prompt values).",
    "update_state": r"HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings and the WindowsUpdate policy keys.",
    "power_config": r"HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes -- the active plan's GUID.",
    "user_profile": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList -- whether this session "
                    r"is on the real profile or a temporary stand-in.",
    "filesystem_health": r"The per-volume dirty bit, and the BootExecute value under "
                         r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager.",
    "dump_files": r"Crash dump files on disk: C:\Windows\Minidump\*.dmp and C:\Windows\MEMORY.DMP, by file date.",
    "adapter_health": "Per-adapter link speed and the cumulative error and drop counters Windows keeps.",
    "boot_config": "bcdedit /enum -- the boot loader's own settings.",
    "fast_startup": r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power (HiberbootEnabled).",
    "wake_history": "powercfg /lastwake and powercfg /waketimers.",
    "update_policy": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -- WSUS redirection, "
                     r"deferrals and version pinning.",
    "update_cache": r"The size and file dates of C:\Windows\SoftwareDistribution\Download.",
    "policy_health": r"A watchlist of values under the HKLM and HKCU ...\Policies keys that switch "
                     r"Windows features off where the Settings app will never show it.",
    "environment_health": r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment -- "
                          r"the system PATH value.",
    "known_folders": "The Shell Folders registry values -- where Desktop, Documents, Downloads and "
                     "Pictures actually point, and whether those folders exist.",
    "integrity_history": r"The tail of C:\Windows\Logs\CBS\CBS.log -- what the last System File Checker "
                         r"run concluded.",
    "shell_health": "The running explorer.exe processes and the size of the icon and thumbnail caches.",
    "dns_resolution": "Live name lookups, timed -- including one name that cannot exist, which must fail.",
    "winsock_health": "netsh winsock show catalog -- the layers spliced into every socket this PC opens.",
    "interface_mtu": "netsh interface ipv4 show subinterfaces -- the packet size set on each interface.",
    # -- deep pass ---------------------------------------------------------
    "temp_size": r"A walk of %TEMP% and C:\Windows\Temp, adding up file sizes.",
    "smart_health": "Get-PhysicalDisk -- the pass/fail health flag each drive reports about itself.",
    "event_log_errors": "The System event log, last 7 days: Kernel-Power 41, disk and storage events "
                        "7/51/153, service events 7031/7034, and the WHEA-Logger provider.",
    "bugchecks": "The System log, event 1001 from BugCheck -- the stop code recorded after each blue screen.",
    "app_crashes": "The Application log, events 1000 and 1002 -- application crashes and hangs, with the "
                   "faulting module named.",
    "update_failures": "Microsoft-Windows-WindowsUpdateClient/Operational -- failed installs with their "
                       "error codes.",
    "installed_updates": "Get-HotFix -- the updates Windows records as installed, newest first.",
    "installed_programs": r"The three Uninstall registry keys (HKLM, HKLM\WOW6432Node and HKCU), using "
                          r"each entry's recorded install date.",
    "third_party_drivers": "pnputil /enum-drivers, with the DriverStore file dates as the install time.",
    "problem_devices": "Get-PnpDevice -- devices carrying a Device Manager problem code.",
    "gpu_resets": "The System log, Display event 4101 -- the display driver stopped responding and "
                  "Windows restarted it.",
    "thermal_events": "The System log, Kernel-Processor-Power event 37 -- the processor was slowed by heat.",
    "storage_removals": "The System log -- surprise-removal and device-reset events raised by the "
                        "storage stack.",
    "memory_config": "Win32_PhysicalMemory -- each installed stick, its slot, and its rated speed.",
    "top_memory_processes": "Per-process working set, grouped by program name.",
    "pagefile": "Win32_PageFileUsage -- whether a page file exists and how large Windows let it grow.",
    "dns_servers": "Get-DnsClientServerAddress -- the resolvers each active interface is using.",
    "battery_wear": r"BatteryStaticData and BatteryFullChargedCapacity in root\wmi -- design capacity "
                    r"against what the pack now holds.",
    "wifi_link": "netsh wlan show interfaces -- signal, band and radio type for the live link.",
    "defender": "Get-MpComputerStatus -- Defender's own report on itself.",
    "firewall_enabled": "netsh advfirewall show allprofiles state.",
    "defender_exclusions": "Get-MpPreference -- the paths, extensions and processes excluded from scanning.",
    "platform_security": "Secure Boot state, Win32_Tpm, Get-BitLockerVolume and the licensing status, "
                         "in one pass.",
    "component_store_health": "DISM /Online /Cleanup-Image /CheckHealth -- the corruption flags Windows "
                              "has already recorded against its component store.",
    "boot_history": "Microsoft-Windows-Diagnostics-Performance/Operational events 100, 101 and 103 -- "
                    "boot durations and the per-app delays inside them.",
    "restore_points": "Get-ComputerRestorePoint, plus the System Restore registry settings that say "
                      "whether protection is on at all.",
    "disk_latency": "Two disk IO counter samples taken a second apart -- average service time per operation.",
    "ping_quality": "Repeated TCP connects, timed. Deliberately not ping.exe, whose output is localised.",
    "volumes": "Win32_Volume -- space, file system and dirty state on every fixed drive.",
    "disk_reliability": "Get-StorageReliabilityCounter -- wear, temperature and uncorrected error counts "
                        "from the drive's own firmware. The counters need administrator rights.",
    "service_health": "Win32_Service -- start type and current state for every installed service.",
    "scheduled_tasks": "Get-ScheduledTask and Get-ScheduledTaskInfo -- each task's last result code.",
    "search_index": r"The WSearch service state and HKLM\SOFTWARE\Microsoft\Windows Search.",
    "defender_threats": "Get-MpThreat and Get-MpComputerStatus -- what Defender found, and whether it "
                        "finished dealing with it.",
    "firewall_profiles": "Get-NetFirewallProfile -- the domain, private and public profiles separately.",
    "network_config": "Get-NetIPConfiguration, Get-NetIPAddress and Get-NetRoute -- addresses and whether "
                      "a default gateway exists.",
    "time_sync": "A direct SNTP query to a public time server, compared with this PC's clock.",
    "printers": "Win32_Printer and Win32_PrintJob -- printers in an error state and jobs stuck in the queue.",
    "cpu_load": "A one-second sample across every running process.",
    "whea_errors": "The System log, Microsoft-Windows-WHEA-Logger -- hardware errors the hardware itself "
                   "reported to Windows.",
    "memory_diagnostic": "The System log, Microsoft-Windows-MemoryDiagnostics-Results -- the verdict of "
                         "Windows' own memory test, if it has ever run.",
    "cpu_throttle": "Win32_Processor -- current clock speed against the rated maximum.",
    "reliability_history": "Win32_ReliabilityStabilityMetrics -- Windows' own stability score, by day.",
    "disk_optimization": "Get-Volume and fsutil behavior query DisableDeleteNotify -- TRIM, and when each "
                         "volume was last maintained.",
    "bitlocker_state": "Win32_EncryptableVolume -- protection status and conversion state per drive.",
    "top_disk_processes": "Per-process disk read and write counters, sampled live.",
    "network_profile": "Get-NetConnectionProfile, plus the DefaultMediaCost registry values that mark a "
                       "connection metered.",
    "activation_state": "SoftwareLicensingProduct -- licence status and any grace period remaining.",
    "appx_health": "Get-AppxPackage -- Store apps Windows itself reports as damaged.",
    "audio_health": "The Audiosrv and AudioEndpointBuilder services, plus Win32_SoundDevice.",
    "bluetooth_health": "The bthserv service and the Win32_PnPEntity devices in the Bluetooth class.",
    "display_config": "Win32_VideoController -- adapters, driver dates, and whether Windows has fallen "
                      "back to the basic display driver.",
    # -- component-level hardware scan -------------------------------------
    "component_devices": "Win32_PnPEntity -- every present device, with its status and problem code.",
    "firmware_info": "Win32_BIOS, Win32_BaseBoard and Win32_ComputerSystem -- the board and the firmware "
                     "running on it.",
    "cpu_details": r"HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0 -- processor identity and both "
                   r"microcode revisions, the firmware's and the one Windows loaded.",
    "memory_modules": "Win32_PhysicalMemory and Win32_PhysicalMemoryArray -- every DIMM by slot, with its "
                      "rated and running speed.",
    "gpu_hardware": r"Win32_VideoController, plus the TDR crash-recovery values under "
                    r"HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers.",
    "display_links": r"WmiMonitorID and WmiMonitorConnectionParams in root\wmi -- the monitors themselves "
                     r"and how each one is connected.",
    "tpm_state": "Get-Tpm -- whether the security chip is present, owned and ready. Needs administrator rights.",
    "pool_usage": "Win32_PerfRawData_PerfOS_Memory -- paged and non-paged kernel pool, where a leaking "
                  "driver shows up.",
    "disk_geometry": "Get-PhysicalDisk and Get-Partition -- firmware revision, bus type, sector size and "
                     "partition alignment.",
    "minidump_details": r"The bugcheck header read directly out of each C:\Windows\Minidump\*.dmp. "
                        r"No debugger involved -- the code and its four parameters sit at fixed offsets.",
    "wer_reports": r"Windows Error Reporting's own archive under "
                   r"C:\ProgramData\Microsoft\Windows\WER -- every crash, with the faulting module.",
    "live_kernel_events": r"C:\Windows\LiveKernelReports and the WER events behind them -- faults Windows "
                          r"captured without bluescreening.",
    "gpu_vendor_telemetry": "nvidia-smi, when an NVIDIA card is present -- ECC error counts and the "
                            "negotiated PCIe link width.",
    "sensor_readings": r"MSAcpi_ThermalZoneTemperature in root\wmi, Win32_Fan, Win32_TemperatureProbe and "
                       r"Win32_VoltageProbe -- whatever this board actually exposes.",
    "smart_attributes": r"MSStorageDriver_FailurePredictData in root\wmi -- the raw SMART attribute table, "
                        r"straight off each ATA drive.",
    "power_events": "The System log, Kernel-Power 41 and event 6008 -- power lost without a clean shutdown.",
    "firmware_errors": "The System log, filtered to the ACPI and firmware providers at error level.",
    "storage_bus_errors": "The System log, storage fault events grouped by the driver that raised them.",
    "event_log_sweep": "Every enabled event log on this PC, errors and criticals only, grouped by "
                       "provider and event ID.",
    "memory_pattern_test": "WinMend's own allocated memory, written with known patterns and read back. "
                           "It can only reach memory Windows lets it allocate.",
    "disk_read_sweep": "Timed, read-only reads of blocks spread across each physical drive. "
                       "Nothing is written.",
}
