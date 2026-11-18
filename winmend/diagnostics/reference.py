"""WinMend diagnostics: reference."""

from __future__ import annotations

try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


# ---------------------------------------------------------------------------
# Knowledge bases
#
# These are the tables a technician carries in their head. Keeping them as data
# means a new code is one row, not a new branch.
# ---------------------------------------------------------------------------

# Bugcheck code -> (name, plain-language probable cause, hypothesis hints)
BUGCHECK_CODES = {
    0x0A: ("IRQL_NOT_LESS_OR_EQUAL", "A driver touched memory it was not allowed to.", ("driver",)),
    0x1A: ("MEMORY_MANAGEMENT", "Windows' memory manager found an inconsistency. Often faulty RAM.", ("memory", "driver")),
    0x1E: ("KMODE_EXCEPTION_NOT_HANDLED", "A driver raised an error it did not handle.", ("driver",)),
    0x3B: ("SYSTEM_SERVICE_EXCEPTION", "A driver or system service failed during a kernel call.", ("driver",)),
    0x4E: ("PFN_LIST_CORRUPT", "The page-frame list was corrupted. Usually faulty RAM or a storage driver.", ("memory", "driver")),
    0x50: ("PAGE_FAULT_IN_NONPAGED_AREA", "Invalid memory was referenced. Commonly faulty RAM or antivirus drivers.", ("memory", "driver")),
    0x7A: ("KERNEL_DATA_INPAGE_ERROR", "Windows could not read a page from disk. Strongly suggests a failing drive.", ("disk",)),
    0x7B: ("INACCESSIBLE_BOOT_DEVICE", "Windows could not reach the boot drive. Storage driver or controller mode.", ("disk",)),
    0x7E: ("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "A system thread hit an error a driver failed to handle.", ("driver",)),
    0x9F: ("DRIVER_POWER_STATE_FAILURE", "A driver did not complete a sleep or wake transition.", ("driver", "power")),
    0xC2: ("BAD_POOL_CALLER", "A driver misused a kernel memory pool.", ("driver",)),
    0xC4: ("DRIVER_VERIFIER_DETECTED_VIOLATION", "Driver Verifier caught a driver breaking the rules.", ("driver",)),
    0xC5: ("DRIVER_CORRUPTED_EXPOOL", "A driver corrupted the kernel pool. Also seen with faulty RAM.", ("driver", "memory")),
    0xD1: ("DRIVER_IRQL_NOT_LESS_OR_EQUAL", "A driver accessed pageable memory at too high an IRQL.", ("driver",)),
    0xEF: ("CRITICAL_PROCESS_DIED", "A process Windows cannot run without terminated. Often corrupted system files.", ("corruption",)),
    0xF4: ("CRITICAL_OBJECT_TERMINATION", "A critical system process ended unexpectedly. Often a failing drive.", ("disk", "corruption")),
    0x116: ("VIDEO_TDR_ERROR", "The graphics driver failed to reset and could not recover.", ("gpu",)),
    0x117: ("VIDEO_TDR_TIMEOUT_DETECTED", "The graphics driver stopped responding.", ("gpu",)),
    0x119: ("VIDEO_SCHEDULER_INTERNAL_ERROR", "The video scheduler hit an unrecoverable error.", ("gpu",)),
    0x124: ("WHEA_UNCORRECTABLE_ERROR", "The hardware itself reported an uncorrectable fault: CPU, memory, or bus.", ("hardware",)),
    0x133: ("DPC_WATCHDOG_VIOLATION", "A driver ran too long without yielding. Often a storage or chipset driver.", ("driver", "disk")),
    0x139: ("KERNEL_SECURITY_CHECK_FAILURE", "A kernel structure was corrupted. Driver or memory fault.", ("driver", "memory")),
    0x144: ("BUGCODE_USB3_DRIVER", "The USB 3 stack hit a fatal error.", ("driver",)),
    0x154: ("UNEXPECTED_STORE_EXCEPTION", "The compressed-memory store failed. Often a failing drive.", ("disk", "memory")),
    0x1E7: ("WORKER_THREAD_INVALID_STATE", "A kernel worker thread was left in a bad state by a driver.", ("driver",)),
}


# Windows Update failure codes -> (short meaning, what actually fixes it)
WU_ERROR_CODES = {
    "0x80070002": ("A required update file was missing.", "reset_win_update"),
    "0x80070003": ("A required update path was missing.", "reset_win_update"),
    "0x8007000D": ("Update data was invalid or corrupt.", "reset_win_update"),
    "0x80070020": ("Another program held an update file open.", "restart_windows"),
    "0x80070070": ("Not enough disk space to stage the update.", "disk_cleanup"),
    "0x800705B4": ("The update timed out.", "windows_update_forensic"),
    "0x8007000E": ("Windows ran out of memory staging the update.", "restart_windows"),
    "0x80073712": ("The component store is missing or damaged.", "repair_system"),
    "0x800F0831": ("A required servicing package is missing from the component store.", "repair_system"),
    "0x800F081F": ("Repair source files could not be found.", "repair_system"),
    "0x800F0922": ("The update could not install; often too little System Reserved space or a VPN blocking it.", "windows_update_forensic"),
    "0x80240034": ("The update failed to download.", "reset_win_update"),
    "0x8024402C": ("Windows could not reach the update servers. Usually a proxy or DNS problem.", "flush_dns"),
    "0x80244019": ("The update server returned 'not found'.", "reset_win_update"),
    "0x80248007": ("The update database is missing or damaged.", "reset_win_update"),
    "0x80D02002": ("The update download timed out.", "reset_win_update"),
    "0xC1900101": ("A driver blocked a Windows feature update.", "driver_rollback_hint"),
    "0xC1900208": ("An installed program is incompatible with this feature update.", "windows_update_forensic"),
    "0x80070643": ("The update installer failed. Common on the WinRE servicing update.", "windows_update_forensic"),
}


# Application-crash exception codes seen in Application log event 1000
EXCEPTION_CODES = {
    "c0000005": "Access violation -- the program read or wrote memory it does not own.",
    "c0000374": "Heap corruption -- memory was damaged before the crash.",
    "c0000409": "Stack buffer overrun -- a security check tripped.",
    "c000041d": "An unhandled exception in a callback.",
    "e0434352": "An unhandled .NET exception.",
    "e06d7363": "An unhandled C++ exception.",
    "c0000006": "In-page error -- the program could not be read from disk. Suspect the drive.",
    "80000003": "A debug breakpoint was hit.",
    "c0000017": "The program could not get the memory it asked for.",
}


# Device Manager problem codes -> (meaning, what a technician does about it)
DEVICE_PROBLEM_CODES = {
    1: ("The device is not configured correctly.", "Reinstall the driver."),
    3: ("The driver may be corrupted, or the system is low on memory.", "Reinstall the driver."),
    10: ("The device cannot start.", "Update or reinstall the driver; check the hardware connection."),
    12: ("The device cannot find enough free resources.", "A hardware resource conflict -- usually a BIOS/UEFI matter."),
    14: ("The device needs a restart to work.", "Restart Windows."),
    16: ("Windows cannot identify all the resources the device uses.", "Update the driver."),
    18: ("The drivers need to be reinstalled.", "Reinstall the driver."),
    19: ("The registry entry for this device is damaged.", "Reinstall the driver."),
    21: ("Windows is removing the device.", "Restart Windows."),
    22: ("The device is disabled.", "Re-enable it in Device Manager."),
    24: ("The device is not present, not working, or missing a driver.", "Check the connection, then reinstall the driver."),
    28: ("No driver is installed for this device.", "Install the driver."),
    29: ("The device is disabled in firmware.", "Enable it in BIOS/UEFI."),
    31: ("Windows cannot load the drivers for this device.", "Reinstall the driver."),
    32: ("The driver's start type is disabled.", "Reinstall the driver."),
    33: ("Windows cannot determine which resources the device needs.", "A hardware fault -- the device may be failing."),
    35: ("The firmware is missing information this device needs.", "A BIOS/UEFI update is needed."),
    38: ("An earlier instance of the driver is still in memory.", "Restart Windows."),
    39: ("The driver is corrupted or missing.", "Reinstall the driver."),
    40: ("The registry service key is invalid.", "Reinstall the driver."),
    41: ("A driver loaded but Windows cannot find the device.", "Check the connection, then reinstall the driver."),
    42: ("A duplicate device is already running.", "Restart Windows."),
    43: ("The device reported a problem and Windows stopped it.", "A hardware fault or a bad driver. Reinstall the driver; if it recurs, the device is failing."),
    44: ("An application or service shut this device down.", "Restart Windows."),
    45: ("The device is not currently connected.", "Reconnect it, or clear the stale entry."),
    46: ("The device is unavailable because Windows is shutting down.", "Restart Windows."),
    47: ("The device is prepared for safe removal but was not unplugged.", "Unplug and reconnect it."),
    48: ("The driver is blocked because it is known to cause problems.", "Get a newer driver from the manufacturer."),
    49: ("The registry hive exceeded its size limit.", "Remove unused devices from Device Manager."),
    52: ("Windows cannot verify the driver's digital signature.", "Get a properly signed driver from the manufacturer."),
    54: ("The device failed and is being reset.", "A hardware or driver fault -- reinstall the driver."),
}


# Kernel/user modules whose vendor a technician recognises on sight.
VENDOR_MODULES = {
    "nvlddmkm": ("NVIDIA display driver", "gpu"),
    "nvoglv64": ("NVIDIA OpenGL driver", "gpu"),
    "nvwgf2umx": ("NVIDIA Direct3D driver", "gpu"),
    "nvd3dumx": ("NVIDIA Direct3D driver", "gpu"),
    "amdkmdag": ("AMD display driver", "gpu"),
    "amdkmdap": ("AMD display driver", "gpu"),
    "atikmdag": ("AMD display driver", "gpu"),
    "atio6axx": ("AMD OpenGL driver", "gpu"),
    "igdkmd64": ("Intel graphics driver", "gpu"),
    "igd10iumd64": ("Intel graphics driver", "gpu"),
    "igdumdim64": ("Intel graphics driver", "gpu"),
    "iastora": ("Intel Rapid Storage driver", "storage"),
    "iastorac": ("Intel Rapid Storage driver", "storage"),
    "stornvme": ("Windows NVMe storage driver", "storage"),
    "storahci": ("Windows AHCI storage driver", "storage"),
    "rtwlane": ("Realtek Wi-Fi driver", "network"),
    "netwtw": ("Intel Wi-Fi driver", "network"),
    "netwlv64": ("Intel Wi-Fi driver", "network"),
    "athw8x": ("Qualcomm Atheros Wi-Fi driver", "network"),
    "bcmwl63a": ("Broadcom Wi-Fi driver", "network"),
    "rt640x64": ("Realtek Ethernet driver", "network"),
    "e1d68x64": ("Intel Ethernet driver", "network"),
    "ndu": ("Windows Network Data Usage driver", "network"),
    "tcpip": ("Windows TCP/IP stack", "network"),
    "ntfs": ("Windows NTFS file system", "storage"),
    "volsnap": ("Windows volume shadow copy", "storage"),
    "dxgmms2": ("Windows DirectX graphics scheduler", "gpu"),
    "dxgkrnl": ("Windows DirectX kernel", "gpu"),
    "win32kfull": ("Windows kernel graphics subsystem", "os"),
    "ntoskrnl": ("The Windows kernel itself -- the real cause is usually another driver", "os"),
    "wdfilter": ("Microsoft Defender filter driver", "security"),
    "mbamchameleon": ("Malwarebytes driver", "security"),
    "klif": ("Kaspersky driver", "security"),
    "aswsp": ("Avast driver", "security"),
    "symefasi": ("Norton/Symantec driver", "security"),
    "bdfwfpf": ("Bitdefender driver", "security"),
    "rzudd": ("Razer device driver", "peripheral"),
    "lgcoretemp": ("Logitech driver", "peripheral"),
    "asussaio": ("ASUS utility driver", "peripheral"),
    "ene": ("ENE/ASUS RGB driver", "peripheral"),
    "cpuz": ("CPU-Z monitoring driver", "peripheral"),
    "rtcore64": ("MSI Afterburner / RivaTuner driver", "peripheral"),
    "vgk": ("Riot Vanguard anti-cheat driver", "anticheat"),
    "easyanticheat": ("EasyAntiCheat driver", "anticheat"),
    "bedaisy": ("BattlEye anti-cheat driver", "anticheat"),
    "faceit": ("FACEIT anti-cheat driver", "anticheat"),
}


# Windows 10/11 servicing end dates for Home/Pro. Used to warn when a PC has
# simply stopped receiving fixes -- an extremely common invisible root cause.
WINDOWS_BUILDS = {
    19044: ("Windows 10 21H2", "2023-06-13"),
    19045: ("Windows 10 22H2", "2025-10-14"),
    22000: ("Windows 11 21H2", "2023-10-10"),
    22621: ("Windows 11 22H2", "2024-10-08"),
    22631: ("Windows 11 23H2", "2025-11-11"),
    26100: ("Windows 11 24H2", "2026-10-13"),
    26200: ("Windows 11 25H2", "2027-10-12"),
}


# Hostnames malware most often black-holes in the hosts file.
PROTECTED_HOSTS = (
    "windowsupdate.com", "update.microsoft.com", "microsoft.com", "windows.com",
    "defender.microsoft.com", "malwarebytes.com", "avast.com", "avg.com",
    "kaspersky.com", "bitdefender.com", "norton.com", "mcafee.com",
    "eset.com", "sophos.com", "trendmicro.com", "virustotal.com",
)


# DNS servers that are normal to see. Anything else on a consumer PC is worth
# reporting -- it is how DNS hijacks and leftover VPN state show up.
KNOWN_DNS = {
    "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare",
    "8.8.8.8": "Google", "8.8.4.4": "Google",
    "9.9.9.9": "Quad9", "149.112.112.112": "Quad9",
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
    "94.140.14.14": "AdGuard", "94.140.15.15": "AdGuard",
    "76.76.2.0": "Control D", "185.228.168.9": "CleanBrowsing",
}


# Services that are supposed to be running on any healthy Windows PC, with what
# breaks when they are not.
#
# This list is short on purpose. "Automatic services that are not running" is a
# tempting check and a useless one: Windows marks a great many services
# Automatic and then starts them only on a trigger, so wuauserv, sppsvc, and
# MapsBroker sit stopped on a perfectly healthy machine. Only services that are
# genuinely meant to be up all the time can carry a warning.
CRITICAL_SERVICES = {
    "EventLog": "Windows Event Log -- without it nothing on this page can be measured",
    "Dnscache": "DNS Client -- name lookups fall back to a slow, uncached path",
    "Dhcp": "DHCP Client -- the PC cannot get an address from the router",
    "nsi": "Network Store Interface -- networking configuration stops working",
    "mpssvc": "Windows Firewall -- inbound protection is off while it is stopped",
    "Winmgmt": "WMI -- a great deal of Windows management stops responding",
    "Schedule": "Task Scheduler -- maintenance, updates, and backups stop running",
    "ProfSvc": "User Profile Service -- sign-in can fall back to a temporary profile",
    "RpcSs": "Remote Procedure Call -- most of Windows depends on it",
    "PlugPlay": "Plug and Play -- new hardware is not detected",
    "CryptSvc": "Cryptographic Services -- updates and signature checks fail",
    "BFE": "Base Filtering Engine -- the firewall and VPNs cannot run without it",
    "Themes": "Themes -- the desktop falls back to a basic appearance",
    "AudioSrv": "Windows Audio -- no sound",
    "AudioEndpointBuilder": "Windows Audio Endpoint Builder -- no playback devices",
    "SamSs": "Security Accounts Manager -- sign-in and permissions",
    "LanmanWorkstation": "Workstation -- network drives and shares stop working",
}


# Scheduled tasks that keep the PC healthy. A failure in one of these is worth
# reporting; a failure in some leftover third-party updater is not, which is why
# the two are graded differently.
# Windows' own upkeep, by exact task path: what stops happening when it fails,
# and whether starting it by hand means anything.
#
# Whole folders were matched here at first (``\Microsoft\Windows\UpdateOrchestrator\``
# and friends) and that was wrong twice over. Those folders are mostly broker
# and helper tasks that the update stack launches with arguments: they report
# odd result codes on a perfectly healthy PC, and running one by hand returns
# 0x80070002 every time because the arguments are missing. So the folder form
# invented a fault and then invented a failure to repair it. Only tasks that are
# meaningful on their own are listed, and each is named in full.
MAINTENANCE_TASKS = {
    r"\Microsoft\Windows\Defrag\ScheduledDefrag": (
        "drives are never optimised, and SSDs are never retrimmed", True),
    r"\Microsoft\Windows\SystemRestore\SR": (
        "no new restore points are being created, so there is nothing to roll back to", True),
    r"\Microsoft\Windows\Chkdsk\ProactiveScan": (
        "file-system damage is never caught early, only when something breaks", True),
    r"\Microsoft\Windows\DiskCleanup\SilentCleanup": (
        "temporary files are never cleared on their own", True),
    r"\Microsoft\Windows\Servicing\StartComponentCleanup": (
        "superseded update files are never removed, so the component store keeps growing", True),
    r"\Microsoft\Windows\Registry\RegIdleBackup": (
        "the registry hives are never backed up", True),
    r"\Microsoft\Windows\WindowsUpdate\Scheduled Start": (
        "update checks are not being started on a schedule", True),
    r"\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance": (
        "Defender's scan cache is never tidied, which slows every scan", True),
    r"\Microsoft\Windows\Windows Defender\Windows Defender Cleanup": (
        "Defender's old quarantine entries are never cleared", True),
    r"\Microsoft\Windows\Windows Defender\Windows Defender Verification": (
        "Defender's own integrity check is not running", True),
    # Starting a full malware scan takes hours and has its own task on the
    # Security page. Reporting it is useful; launching it from here is not.
    r"\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan": (
        "the scheduled malware scan is not running", False),
    r"\Microsoft\Windows\WindowsBackup\ConfigNotification": (
        "you are never told when backup has stopped running", False),
}


# Task Scheduler result codes that mean "this has not failed": never run, still
# running, queued, stopped by the user, or declined because its conditions were
# not met. Treating these as failures would flag most of the 150-odd tasks
# Windows ships with -- SilentCleanup returns 0x800710E0 on a healthy PC every
# time the machine stops being idle part-way through.
BENIGN_TASK_RESULTS = {
    0x00000000, 0x00041300, 0x00041301, 0x00041302, 0x00041303,
    0x00041304, 0x00041306, 0x00041325, 0x00041326, 0x0004131B,
    0x800710E0,  # the operator or administrator refused the request
    0x8004131F,  # an instance of this task is already running
    0x800704DD,  # needs an interactive session and nobody is signed in
}


# Power scheme GUIDs. OEMs ship their own, so an unrecognised GUID is looked up
# by name rather than assumed to be anything.
POWER_SCHEMES = {
    "381b4222-f694-41f0-9685-ff5bb260df2e": ("Balanced", False),
    "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c": ("High performance", False),
    "a1841308-3541-4fab-bc81-f71556f20b4a": ("Power saver", True),
    "e9a42b02-d5df-448d-aa00-03f14749eb61": ("Ultimate performance", False),
    "ded574b5-45a0-4f42-8737-46345c09c238": ("Power saver (OEM)", True),
}


# Defender threat status ids that mean the threat is still there. Anything not
# listed here has been cleaned, quarantined, removed, or blocked.
UNRESOLVED_THREAT_STATUS = {
    1: "detected but not yet acted on",
    5: "allowed by an exclusion or by the user",
    102: "quarantine failed",
    103: "removal failed",
    104: "allow failed",
    105: "abandoned",
    107: "block failed",
}


# Win32_Printer.PrinterStatus -- 3 (idle) and 4 (printing) are the healthy pair.
PRINTER_STATUS = {
    1: "other", 2: "unknown", 3: "idle", 4: "printing", 5: "warming up",
    6: "stopped printing", 7: "offline",
}


def _maintenance_task(path):
    """(consequence, runnable) for a known maintenance task, else None.

    Matched in full and case-insensitively. Prefix matching is what let a
    broker task in a maintenance folder be treated as maintenance.
    """
    wanted = str(path).strip().lower()
    for known, entry in MAINTENANCE_TASKS.items():
        if known.lower() == wanted:
            return entry
    return None


def describe_bugcheck(code):
    """(name, cause, tags) for a bugcheck code, or a safe unknown triple."""
    try:
        numeric = int(code, 16) if isinstance(code, str) else int(code)
    except (TypeError, ValueError):
        return ("UNKNOWN", "An unrecognised stop code.", ())
    entry = BUGCHECK_CODES.get(numeric)
    if entry is None:
        return (f"0x{numeric:08X}", "An uncommon stop code; the dump file names the component.", ())
    return entry


def describe_wu_error(code):
    """(meaning, remedy task id) for a Windows Update error code."""
    if not code:
        return (None, None)
    key = str(code).strip().upper()
    if not key.startswith("0X"):
        try:
            key = f"0X{int(key) & 0xFFFFFFFF:08X}"
        except ValueError:
            return (None, None)
    key = "0x" + key[2:]
    for known, value in WU_ERROR_CODES.items():
        if known.upper() == key.upper():
            return value
    return (None, None)


def module_vendor(name):
    """('NVIDIA display driver', 'gpu') for a module file name, or (None, None)."""
    if not name:
        return (None, None)
    stem = str(name).lower().rsplit("\\", 1)[-1]
    for suffix in (".sys", ".dll", ".exe"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    if stem in VENDOR_MODULES:
        return VENDOR_MODULES[stem]
    for key, value in VENDOR_MODULES.items():
        if stem.startswith(key):
            return value
    return (None, None)


# What a WHEA hardware-error event is actually telling you. The event id gives
# the severity and the message names the source; together they decide whether
# this is a component that recovered or one that is failing.
WHEA_SOURCES = (
    ("memory", ("memory", "dimm", "memory controller"),
     "the memory or its controller reported an error"),
    ("pcie", ("pci express", "pcie", "root port", "endpoint"),
     "a PCI Express device or slot reported an error"),
    ("processor", ("processor", "cpu", "machine check", "cache"),
     "the processor reported an internal error"),
    ("bus", ("bus", "interconnect", "platform"),
     "a system bus or the platform reported an error"),
)


WHEA_EVENTS = {
    17: ("corrected", "a hardware error occurred and the hardware corrected it"),
    18: ("fatal", "an uncorrected hardware error stopped the PC"),
    19: ("corrected", "a corrected hardware error was recorded"),
    46: ("fatal", "a fatal hardware error was recorded"),
    47: ("corrected", "a corrected memory error was recorded"),
}


def describe_whea(event_id, message=""):
    """(area, meaning) for one WHEA event.

    Event 47 reports a corrected memory error, not proof of page retirement.
    """
    text = str(message or "").lower()
    if event_id == 47:
        return "memory", WHEA_EVENTS[47][1]
    for area, needles, meaning in WHEA_SOURCES:
        if any(needle in text for needle in needles):
            return area, meaning
    kind, meaning = WHEA_EVENTS.get(int(event_id or 0), ("unknown", "a hardware error was recorded"))
    return ("memory" if kind == "memory" else "unknown"), meaning


# Winsock providers that ship with Windows. Anything else in the catalog was
# spliced in by something the user installed, which is the only part worth
# reporting -- the stock entries are present on every PC that has ever worked.
_WINSOCK_STOCK = {
    "mswsock.dll", "winrnr.dll", "napinsp.dll", "pnrpnsp.dll", "nlaapi.dll",
    "wshbth.dll", "rnr20.dll", "%systemroot%\\system32\\mswsock.dll",
}


# Interfaces that are *meant* to run a non-standard packet size: VPN tunnels,
# hypervisor switches, and container bridges all legitimately sit below 1500.
_VIRTUAL_ADAPTERS = (
    "tailscale", "wireguard", "openvpn", "tap-", "tun", "vethernet", "hyper-v",
    "vmware", "virtualbox", "docker", "wsl", "bluetooth", "teredo", "isatap",
    "loopback", "npcap", "zerotier", "nordlynx", "proton", "mullvad",
)


_LICENSE_STATUS = {
    0: "unlicensed",
    1: "licensed",
    2: "in the initial grace period",
    3: "in the additional grace period",
    4: "in a non-genuine grace period",
    5: "not activated -- notification mode",
    6: "in the extended grace period",
}


# Policy values that switch a working feature off. Every one of these is set by
# something other than the Settings app -- a management policy on a work PC, or
# far more often on a home PC, the residue of a "debloat" or "privacy" script
# the user ran once and no longer remembers.
#
# Two rules keep this list honest. Only policies with a user-visible cost are
# listed, because a policy that merely changes a default is not a fault. And
# every entry has to be one whose *enabled* state is the damage: a value like
# ``EnableFirewall`` reads 1 on a healthy PC, so listing it here would report
# working protection as a restriction.
def _policy_watchlist():
    if winreg is None:
        return ()
    hklm, hkcu = winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER
    return (
        (hklm, r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware",
         "Microsoft Defender is switched off by policy", "security"),
        (hklm, r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
         "DisableRealtimeMonitoring",
         "Defender's real-time protection is switched off by policy", "security"),
        (hklm, r"SOFTWARE\Policies\Microsoft\Windows\System", "DisableCMD",
         "the Command Prompt is blocked by policy", "shell"),
        (hkcu, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
         "DisableTaskMgr", "Task Manager is blocked by policy", "shell"),
        (hkcu, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
         "DisableRegistryTools", "the Registry Editor is blocked by policy", "shell"),
        (hklm, r"SOFTWARE\Policies\Microsoft\Windows\Explorer", "DisableSearchBoxSuggestions",
         "search suggestions are blocked by policy", "shell"),
        (hklm, r"SOFTWARE\Policies\Microsoft\Windows\WindowsStore", "RemoveWindowsStore",
         "the Microsoft Store is removed by policy", "apps"),
        (hklm, r"SOFTWARE\Policies\Microsoft\Windows\CloudContent",
         "DisableWindowsConsumerFeatures",
         "Store app auto-installation is blocked by policy", "apps"),
        (hklm, r"SOFTWARE\Policies\Microsoft\Windows\SystemRestore", "DisableSR",
         "System Restore is switched off by policy", "recovery"),
        (hklm, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate",
         "automatic updates are switched off by policy", "updates"),
        (hkcu, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
         "NoRun", "the Run dialog is blocked by policy", "shell"),
        (hkcu, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
         "NoControlPanel", "Settings and Control Panel are blocked by policy", "shell"),
    )


_POLICY_WATCHLIST = tuple(_policy_watchlist())


# ---------------------------------------------------------------------------
# Hypotheses and the rule engine
# ---------------------------------------------------------------------------

# Processes that are supposed to read the disk hard and that stop on their own.
# Naming one of these as the cause sends a user off to kill a Windows service
# that restarts itself thirty seconds later, so they get their own, gentler
# verdict rather than being convicted alongside a runaway program.
_EXPECTED_DISK_USERS = {
    "msmpeng.exe", "searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
    "tiworker.exe", "trustedinstaller.exe", "wuauclt.exe", "usoclient.exe",
    "compattelrunner.exe", "defrag.exe", "sihclient.exe", "mssense.exe",
    "backgroundtaskhost.exe", "svchost.exe", "system", "memory compression",
}


SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


# The profile used by a proactive full check, where there is no complaint to
# classify. It is a real profile string rather than a flag so that it survives
# the journal round-trip and the verification re-run unchanged.
AUDIT_PROFILE = "audit"


# The profile used by the component-level hardware scan. Like the audit profile
# it opens every rule area, because a failing drive is not "a storage problem"
# until someone has decided that is what they are looking for.
HARDWARE_PROFILE = "hardware"
