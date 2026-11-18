"""WinMend data: task catalog."""

from __future__ import annotations

from winmend.core.models import WMTask
from winmend.data.app_catalog import INSTALLABLE_APPS
from winmend.features.network_dns import DNS_PROVIDERS


WM_CATEGORIES = [
    ("dashboard",   "Dashboard",         "This PC at a glance."),
    ("guide",       "Guided Fix",        "Diagnose a problem, build a protected repair plan, and verify the result."),
    ("journal",     "Safety Journal",    "Review every WinMend run, its protection checkpoint, results, and undo path."),
    ("cleanup",     "Cleanup",           "Reclaim disk space by removing files Windows no longer needs."),
    ("storage",     "Storage",           "See exactly what is using this drive, and clear it safely."),
    ("repair",      "Repair & Recovery", "Fix corrupted system files, crashes, and broken components."),
    ("performance", "Performance",       "Speed up boot, cut background load, and remove bloat."),
    ("startup",     "Startup",           "Choose which apps launch with Windows — and see what each one costs at boot."),
    ("network",     "Network",           "Diagnose and repair internet and connectivity problems."),
    ("speedtest",   "Speed Test",        "Measure your internet speed, latency, and connection quality — with a deeper test for advanced users."),
    ("security",    "Security",          "Scan for threats and audit what is running on this PC."),
    ("diagnostics", "Diagnostics",       "Test hardware and investigate crashes. Stress tests raise hardware load; memory diagnostics can restart Windows."),
    ("updates",     "Updates & Drivers", "Keep Windows, drivers, and installed apps current."),
    ("apps",        "Install Apps",      f"{len(INSTALLABLE_APPS)} apps, sorted by category. Tick the ones you want and "
                                         f"WinMend installs them in one batch through winget — straight from each "
                                         f"publisher, nothing bundled."),
    ("tweaks",      "Windows Settings",  "Switches for the Windows behaviour that has no obvious setting. Each one "
                                         "shows what your registry actually says right now, and flipping it back "
                                         "restores exactly what was there before."),
    ("advanced",    "Advanced",          "Expert tools. Know what these do before running them."),
]


# Generated from the legacy create_widgets() body — titles, descriptions, admin
# flags and runtimes are the app's own, carried over verbatim. Order within a
# category is the original screen order.
WM_TASKS = [

    # ── CLEANUP ──
    WMTask("clean_temp", "Clean Temp Files (System-wide)", "cleanup",
           "Cleans the Windows and user Temp folders. Anything changed in the last 24 "
           "hours is left alone, because installers and running apps (WinMend "
           "included) are still using it. Prefetch is kept: Windows uses it to start "
           "your apps faster. (Use 'Clear Browser Cache' for browser data.)",
           admin=True, secs=150, risk="caution", simple=True, plain="Free up disk space"),
    WMTask("disk_cleanup", "Deep Disk Cleanup", "cleanup",
           "Runs Windows Disk Cleanup in four stages — temporary files and caches, "
           "Delivery Optimization and old driver packages, Windows Update Cleanup, "
           "previous-installation leftovers — then empties the Recycle Bin. Progress "
           "is measured (free space, CPU and disk activity), so a slow stage is "
           "reported and a stuck one is skipped rather than sitting at 95%. Never "
           "touches your Downloads folder, File History versions, or the files "
           "'Reset this PC' needs. Windows Update Cleanup alone can take 10-40 minutes "
           "the first time.",
           admin=True, secs=300, risk="caution", simple=True, plain="Deep clean disk"),
    WMTask("clear_browser_cache", "Clear Browser Cache (All Browsers)", "cleanup",
           "Deletes the cache folders of every profile in Edge, Chrome, Brave, Vivaldi, "
           "Opera and Firefox. Only cached web data -- never passwords, history, "
           "bookmarks or cookies. Close browsers first for best results.",
           secs=140, risk="caution", simple=True, plain="Clear browser cache"),
    WMTask("component_cleanup", "Component Store Cleanup (DISM)", "cleanup",
           "DISM /StartComponentCleanup -- removes old update backups and frees disk "
           "space from the component store.",
           admin=True, secs=120, risk="caution"),
    WMTask("rebuild_icon_cache", "Rebuild Icon & Thumbnail Cache", "cleanup",
           "Clears icon and thumbnail caches and restarts Explorer. Fixes blank, "
           "black, or corrupted icons on desktop, taskbar, and File Explorer.",
           admin=True, secs=90, risk="caution"),
    WMTask("rebuild_font_cache", "Rebuild Font Cache", "cleanup",
           "Stops the Font Cache service, deletes font cache files, and restarts the "
           "service. Fixes corrupted or missing fonts.",
           admin=True, secs=95, risk="caution"),
    WMTask("storage_sence", "WinMend Storage Analyzer", "cleanup",
           "Custom Storage Analyzer Created By EAWTECH",
           admin=True, secs=35, risk="caution", simple=True, plain="See what's using my disk"),
    WMTask("windows_old_cleanup", "Remove Windows.old (Previous Windows)", "cleanup",
           "Deletes the previous Windows installation folder left behind by a feature "
           "update — often 20-30 GB. After this you can no longer roll back to the "
           "previous version of Windows.",
           admin=True, secs=300, risk="destructive"),
    WMTask("restore_point_cleanup", "Delete Old Restore Points", "cleanup",
           "Deletes every System Restore point except the newest one. Frees "
           "shadow-copy storage while keeping your most recent rollback.",
           admin=True, secs=60, risk="caution"),

    # ── REPAIR ──
    WMTask("restart_windows", "Restart Windows (60-second countdown)", "repair",
           "Asks for confirmation, then restarts the PC after a 60-second countdown "
           "so open work can be saved. The countdown can be cancelled with "
           "'shutdown /a'. Clears stuck services and finishes pending updates.",
           secs=70, risk="caution", simple=True, plain="Restart my PC", reboot=True),
    WMTask("repair_system", "Repair System (SFC/DISM)", "repair",
           "Repairs Windows system files using SFC and DISM",
           admin=True, secs=420, risk="caution", simple=True, plain="Repair damaged Windows files", restore_point=True),
    WMTask("chk_dsk", "Check Disk (choose a drive)", "repair",
           "Asks which drive to check and how thoroughly, then repairs file-system "
           "errors. A drive that is not in use is checked straight away; the Windows "
           "drive (or any drive in use) is booked in for the next restart, and the "
           "run ends by offering that restart.",
           admin=True, secs=450, risk="caution", reboot_after=True),
    WMTask("reset_win_update", "Reset Windows Update Components", "repair",
           "Stops update services, renames SoftwareDistribution & catroot2, restarts "
           "services. Fixes stuck or failing Windows Updates.",
           admin=True, secs=305, risk="caution", restore_point=True),
    WMTask("clear_print_spooler", "Clear Print Spooler Queue", "repair",
           "Stops the print spooler, deletes all stuck print jobs, and restarts the "
           "service.",
           admin=True, secs=40, risk="caution"),
    WMTask("toggle_safe_mode", "Safe Mode Boot Toggle", "repair",
           "Turns Safe Mode with Networking on or off. While it is on, EVERY restart "
           "goes into Safe Mode until you run this again to turn it off.",
           admin=True, secs=600, risk="caution", restore_point=True, reboot_after=True),
    WMTask("boot_advanced_options", "Boot to Advanced Options / BIOS", "repair",
           "Forces the PC to reboot directly into the BIOS/UEFI or Advanced Startup "
           "Options menu.",
           admin=True, secs=650, risk="caution", reboot=True),
    WMTask("reset_search_index", "Reset Windows Search Index", "repair",
           "Stops Windows Search, deletes the search index database, and restarts the "
           "service. Fixes broken search and Cortana.",
           admin=True, secs=100, risk="destructive", restore_point=True),
    WMTask("service_dependency_repair", "Service Dependency Repair", "repair",
           "Checks nine core Windows services and their dependencies: any that were "
           "switched off are set back to their Windows default start type, and any "
           "that should be running are started. Services Windows starts only on "
           "demand are left on demand.",
           admin=True, secs=110, risk="caution", restore_point=True),
    WMTask("ssd_saver", "SSD Saver", "repair",
           "On a PC with an AMD processor or graphics card, stops the AMD External "
           "Events Utility service and then sets it to Disabled. Excessive SSD writes: "
           "affected systems see ongoing background writes (from a fraction of a MB/s "
           "to several MB/s, or hundreds of GB a day in severe reports), tied to how "
           "the External Events Utility interacts with Windows and PCIe behaviour. "
           "Drive wear: SSDs have a finite write endurance (TBW), so constant "
           "background writes can wear out the system drive faster. Changes nothing "
           "on other PCs. If FreeSync or Radeon's hotkeys misbehave afterwards, "
           "'Reset Windows Defaults' turns the service back on.",
           admin=True, secs=20, risk="caution", restore_point=True),
    WMTask("reset_to_defaults", "Reset Windows Defaults (Undo Tweaks)", "repair",
           "Reverts WinMend tweaks: visual effects and animations back to 'Let Windows "
           "choose'; Focus Assist, Transparency, Game Bar, Game DVR and Game Mode back "
           "on (including the Game DVR policy); every Edge policy WinMend set removed; "
           "Fast Startup and hibernation back on; RAM Optimizations undone (SysMain, "
           "Telemetry, Windows Search and Diagnostic Policy back to Automatic, memory "
           "compression and peer downloads on); background apps allowed again; the "
           "page file back to how it was (or Windows-managed); Memory Integrity back "
           "on if WinMend turned it off; the graphics preferences WinMend added "
           "removed; the AMD External Events Utility back to its old start type if "
           "SSD Saver disabled it. Network profile is left unchanged.",
           admin=True, secs=118, risk="destructive", restore_point=True),
    WMTask("system_restore_browser", "System Restore Browser (List & Rollback)", "repair",
           "Opens a list of every System Restore checkpoint on this PC. Pick one and "
           "confirm to roll back. Reboots Windows to begin restore.",
           admin=True, secs=700, risk="caution", reboot=True),
    WMTask("file_assoc_reset", "Reset File Associations (Default Apps)", "repair",
           "Clears your chosen default app for common file types (.txt .html .pdf .jpg "
           ".png .gif .mp4 .mp3 .zip) and web links, so Windows asks which app to use "
           "next time. Windows protects some of these (web links and PDFs) from being "
           "changed by any program; for those, the run opens Settings > Default apps "
           "and says which ones to reset there.",
           admin=True, secs=78, risk="destructive", restore_point=True),
    WMTask("start_menu_reset", "Reset Start Menu & Taskbar Layout", "repair",
           "Clears the Start Menu (Start2.bin) and Taskbar layout files, then restarts "
           "Explorer. Fixes broken/frozen Start menu, missing tiles, or corrupted "
           "pinned items.",
           admin=True, secs=92, risk="destructive", restore_point=True),
    WMTask("uwp_app_reset", "Reset UWP App (Mail/Photos/etc.)", "repair",
           "Picker to fully reset a UWP/Store app to defaults via Get-AppxPackage | "
           "Reset-AppxPackage. Fixes Mail, Photos, Camera, Calculator, Store, etc. "
           "when they won't launch.",
           admin=True, secs=58, risk="destructive", restore_point=True),
    WMTask("audio_repair", "Repair Audio (Restart Sound Services)", "repair",
           "Restarts the Windows Audio and Audio Endpoint Builder services and makes "
           "sure they start automatically. The standard fix for 'no sound' after an "
           "update or a crashed audio driver.",
           admin=True, secs=30, risk="caution", simple=True, plain="Fix sound problems"),
    WMTask("explorer_repair", "Repair File Explorer (Reset Quick Access)", "repair",
           "For File Explorer that opens slowly, sits at 'Working on it...', or "
           "hangs on Quick Access. Rebuilds the Quick Access list (a corrupted or "
           "overloaded one is the most common cause) and puts your pinned folders "
           "back, minus any on a server, NAS, or mapped drive that no longer "
           "answers. Clears Recent Items and Explorer's address-bar, search and "
           "recent-documents history. Lists mapped network drives and network "
           "locations that do not answer and asks before disconnecting them. Reports "
           "third-party context-menu and icon-overlay extensions without changing "
           "them. Everything removed is copied to a backup folder first; Explorer "
           "restarts.",
           secs=60, risk="caution", simple=True, plain="Fix slow File Explorer"),
    WMTask("office_repair", "Repair Microsoft Office & Outlook", "repair",
           "For Outlook or Office that will not open, crashes, keeps asking for a "
           "password, or says 'Unlicensed Product'. Measures first: the Click-to-Run "
           "service, Office processes stuck without a window, licence state, the "
           "Outlook profile and data-file size, add-ins, sign-in registry overrides, "
           "and two weeks of crash events with each crash traced to the add-in, "
           "driver or Office file it landed in. Then shows a checklist; only "
           "repairs the measurements point at are pre-ticked: end the stuck process, "
           "fix the service, turn off the crashing add-in, Office's own Quick or "
           "Online Repair, reset the navigation pane, rebuild the offline cache, "
           "reset the sign-in/licence cache (backed up first), check for Office "
           "updates. Reversible steps log their undo.",
           admin=True, secs=240, risk="caution", simple=True, plain="Fix Outlook / Office",
           restore_point=True),

    # ── PERFORMANCE ──
    WMTask("disable_fast_startup", "Disable Fast Startup", "performance",
           "Disables Fast Startup (Hybrid shutdown). Fixes issues with dual-boot, "
           "drivers, and ensures clean shutdowns. Hibernate stays available -- only "
           "the hybrid shutdown is turned off.",
           admin=True, secs=70, risk="caution", restore_point=True),
    WMTask("adjust_virtual_memory", "Optimize Virtual Memory", "performance",
           "Detects your RAM (e.g. 16GB) \u2192 sets the page file to start at that size and "
           "grow to 2x RAM (32GB). Checks the Windows drive has room first and refuses "
           "if it would leave the drive nearly full. Shows current vs new settings. "
           "'Reset Windows Defaults' puts the previous setting back.",
           admin=True, secs=88, risk="caution", restore_point=True, reboot_after=True),
    WMTask("ram_optimizations", "RAM Optimizations (Trim Background Services)", "performance",
           "Reclaims the RAM four background services hold onto, by stopping each one "
           "and setting it to Disabled: SysMain (Superfetch), Connected User "
           "Experiences and Telemetry, Windows Search, and the Diagnostic Policy "
           "Service. Also turns off optional diagnostic data, stops Delivery "
           "Optimization downloading updates from other PCs, and turns off memory "
           "compression when Get-MMAgent reports it on. Costs you search indexing and "
           "the built-in Windows troubleshooters; 'Reset Windows Defaults' puts every "
           "part of it back.",
           admin=True, secs=95, risk="caution", restore_point=True, reboot_after=True),
    WMTask("windows_adjustments", "Performance Adjustments", "performance",
           "Sets Performance Options to Custom and trims visual effects (menu fades, "
           "animations, transparency), and turns off Focus Assist, Game Bar, Game DVR "
           "and Game Mode. Asks separately before marking your networks as Private.",
           admin=True, secs=80, risk="caution", restore_point=True),
    WMTask("defrag_optimize", "Optimize Drives (SSD-Safe)", "performance",
           "Optimizes all drives: TRIM for SSDs, Defrag for HDDs. Automatically "
           "detects drive type -- will NEVER defrag an SSD.",
           admin=True, secs=140, risk="caution"),
    WMTask("disable_gaming_features", "Turn Off All Gaming Features", "performance",
           "Turns OFF: Game Bar overlay, Game DVR recording, Game Mode optimizations, "
           "Background recording, Xbox Game Monitoring. May improve performance on "
           "non-gaming PCs.",
           admin=True, secs=85, risk="caution", restore_point=True),
    WMTask("enable_gaming_features", "Turn On All Gaming Features", "performance",
           "Turns ON: Game Bar + Guide button, Game Mode, optimizations for windowed "
           "games, HAGS, VRR, and adds detected game executables to Graphics "
           "high-performance app preferences. Also turns OFF Memory Integrity (Core "
           "Isolation) -- a security feature that costs frames -- and clears the "
           "Locked value when the switch is greyed out as managed by your "
           "administrator. 'Reset Windows Defaults' undoes all of it.",
           admin=True, secs=90, risk="caution", restore_point=True, reboot_after=True),
    WMTask("edge_performance", "Edge Performance Adjustments", "performance",
           "Disables: Startup Boost (runs Edge at boot), Background Apps. Changes "
           "default search to Google instead of Bing. Applied as Edge policy, so "
           "Edge will show these as managed settings.",
           admin=True, secs=75, risk="caution", restore_point=True),
    WMTask("windows_tweaks", "Windows Settings & Tweaks", "performance",
           "Opens the switch panel for Windows behaviour that has no obvious "
           "setting: dark theme, file extensions, taskbar layout, mouse "
           "acceleration, Start menu web results, and more. Each switch reads "
           "its real current state and flips back exactly as it was.",
           secs=1, risk="caution", simple=True, plain="Change Windows settings"),
    WMTask("power_plan_switcher", "Power Plan Switcher", "performance",
           "Choose a power plan: Balanced, High Performance, Power Saver, or Ultimate "
           "Performance (unlocked on demand). Applied via powercfg /setactive.",
           admin=True, secs=48, risk="caution"),
    WMTask("debloat_windows", "Debloat Windows", "performance",
           "Finds which of 91 common preinstalled apps are actually on this PC and "
           "shows them as a checklist. Games, trials and promotional apps are ticked; "
           "apps people commonly use (Teams, Spotify, To Do, Sticky Notes...) are "
           "listed but left unticked. Removes only what you tick, for every user, and "
           "logs exactly what was removed. Removed apps come back from the Store, not "
           "from a restore point.",
           admin=True, secs=520, risk="destructive"),
    WMTask("debloat_extreme", "Debloat Windows Extreme", "performance",
           "WARNING: the same checklist, extended to Windows' own apps and OEM tools "
           "(Store, Calculator, Notepad, Photos, Xbox sign-in, OneDrive...). Anything "
           "whose removal breaks something is unticked and says what it breaks. "
           "Removes only what you tick and logs exactly what was removed.",
           admin=True, secs=125, risk="destructive"),
    WMTask("stop_background_apps", "Stop Background Apps", "performance",
           "Disables background activity for UWP/Store apps via registry "
           "(GlobalUserDisabled=1). Already-running processes are not terminated; "
           "takes effect on next launch.",
           secs=60, risk="caution", restore_point=True),
    WMTask("disable_startup_apps", "Optimize Startup Apps", "performance",
           "Disables all Task Manager startup items (Run keys + Startup folders) "
           "except OneDrive. Entries are preserved and can be re-enabled from Task "
           "Manager.",
           secs=65, risk="caution", simple=True, plain="Make my PC start faster", restore_point=True),
    WMTask("startup_manager", "Startup Manager", "performance",
           "Opens the Startup page: every app that launches with Windows, the boot delay "
           "Windows actually measured for it, and a reversible on/off switch per app "
           "(Task Manager-compatible — nothing is deleted).",
           secs=2, risk="caution", simple=True, plain="Choose which apps start with Windows"),

    # ── NETWORK ──
    WMTask("speed_test", "Internet Speed Test", "network",
           "Measures download and upload speed, latency and jitter against Cloudflare's "
           "public speed-test servers. The Advanced test also grades bufferbloat (latency "
           "under load), DNS response time and IPv6. Read-only — it transfers test data "
           "but changes nothing on this PC.",
           secs=45, risk="safe", simple=True, plain="Test my internet speed"),
    WMTask("flush_dns", "Flush DNS & Renew IP", "network",
           "Flushes DNS cache and renews your IP address",
           admin=True, secs=50, risk="caution", simple=True, plain="Fix internet connection"),
    WMTask("ipconfig_all", "Display Network Config", "network",
           "Displays detailed network configuration information",
           secs=15, risk="safe"),
    WMTask("change_dns", "Change DNS Servers", "network",
           f"Pick from {len(DNS_PROVIDERS)} public DNS providers — Cloudflare, Google, "
           f"Quad9, OpenDNS and AdGuard, including the malware- and adult-filtering "
           f"variants — and apply it (IPv4 and IPv6) to every active physical network "
           f"adapter. VPN and virtual adapters keep their own DNS. The same picker "
           f"puts DNS back to automatic.",
           admin=True, secs=55, risk="caution", simple=True, plain="Change my DNS",
           restore_point=True),
    WMTask("reset_hosts", "Reset / Flush Hosts File", "network",
           "Resets the Windows Hosts file to default, fixing connection issues caused "
           "by malware or bad ad-blockers.",
           admin=True, secs=45, risk="caution", restore_point=True),
    WMTask("reset_network", "Reset Network Stack (Winsock/TCP)", "network",
           "Resets Winsock catalog and TCP/IP stack. Fixes 'No Internet Access' and "
           "deep connectivity issues. Requires reboot.",
           admin=True, secs=260, risk="destructive", restore_point=True, reboot_after=True),
    WMTask("deep_network_remediation", "Deep Network Stack Remediation", "network",
           "Runs aggressive network stack resets (IP release/renew, Winsock, TCP/IP, "
           "IPv4/IPv6 interfaces, ARP, NBT, BranchCache) and reports each one's result. "
           "Asks separately before resetting the firewall, because that deletes every "
           "rule your apps added. Requires reboot.",
           admin=True, secs=280, risk="destructive", restore_point=True, reboot_after=True),
    WMTask("export_wifi_passwords", "View / Export Saved Wi-Fi Passwords", "network",
           "Extracts all saved Wi-Fi networks and plain-text passwords and saves them "
           "to a file on the Desktop -- or, when the Desktop is synced to OneDrive, to "
           "your user folder instead, so the passwords never upload to the cloud.",
           admin=True, secs=40, risk="safe"),
    WMTask("network_adapter_reset", "Reset Network Adapters", "network",
           "Disables and re-enables every connected physical network adapter (Ethernet, "
           "Wi-Fi). Adapters you had switched off stay off, and VPN adapters are left "
           "to their own apps. Quick fix for connectivity glitches.",
           admin=True, secs=45, risk="caution", restore_point=True),
    WMTask("ping_test", "Ping Test (Connectivity Check)", "network",
           "Pings default gateway, Google DNS (8.8.8.8), Cloudflare (1.1.1.1), and "
           "google.com to check connectivity.",
           secs=15, risk="safe"),
    WMTask("network_diagnostic_bundle", "Network Deep Diagnosis Bundle", "network",
           "Builds a deep connectivity report (adapter state, routing, DNS, ping "
           "tests, and error signals).",
           admin=True, secs=30, risk="safe", simple=True, plain="Diagnose internet problems"),
    WMTask("dns_over_https", "DNS-over-HTTPS (On / Off)", "network",
           "Turns encrypted DNS (DoH) on or off. On: Cloudflare 1.1.1.1 and Google "
           "8.8.8.8 over HTTPS on every active physical adapter (VPN adapters keep "
           "their own DNS), strict mode with no fallback to unencrypted DNS, then "
           "checks that Windows is really sending lookups over HTTPS -- and undoes it "
           "if lookups stop working. Off: back to automatic DNS.",
           admin=True, secs=62, risk="caution", restore_point=True),
    WMTask("wifi_channel_analyzer", "Wi-Fi Channel Analyzer", "network",
           "Scans nearby Wi-Fi networks with netsh wlan show networks mode=bssid. "
           "Shows SSID, channel, signal strength, and band. Use to pick a less-crowded "
           "channel for your router.",
           secs=32, risk="safe"),
    WMTask("wlan_report", "Wireless Network Report (WlanReport)", "network",
           "Builds Windows' own wireless diagnostics report (netsh wlan show "
           "wlanreport): connection history, disconnect reasons, signal and adapter "
           "events from the last few days. Opens in your browser when done.",
           admin=True, secs=25, risk="safe", simple=True, plain="Wi-Fi problem report"),
    WMTask("open_ports_viewer", "Open Ports & Listening Services", "network",
           "Lists every TCP/UDP port currently bound and the process that owns it "
           "(netstat -ano joined with Get-Process). Useful to spot suspicious "
           "listeners or port conflicts.",
           secs=18, risk="safe"),
    WMTask("bluetooth_repair", "Repair Bluetooth (Restart Stack)", "network",
           "Restarts the Bluetooth support services and power-cycles the Bluetooth "
           "radio. Fixes 'Bluetooth disappeared' and devices that refuse to pair.",
           admin=True, secs=45, risk="caution", simple=True, plain="Fix Bluetooth"),
    WMTask("time_sync_fix", "Fix System Clock (Time Sync)", "network",
           "Starts the Windows Time service and forces a resync (w32tm /resync). A "
           "wrong clock silently breaks HTTPS, sign-ins, and updates.",
           admin=True, secs=20, risk="caution", simple=True, plain="Fix wrong clock"),

    # ── SECURITY ──
    WMTask("defender_scan", "Windows Defender Full Scan", "security",
           "Launches a full system scan using Windows Defender (MpCmdRun.exe). This "
           "may take a long time.",
           admin=True, secs=210, risk="caution", simple=True, plain="Scan for viruses"),
    WMTask("msrt_scan", "MSRT Quick Malware Scan", "security",
           "Runs the Microsoft Malicious Software Removal Tool (MRT.exe) in quiet mode "
           "for a quick scan.",
           admin=True, secs=230, risk="caution"),
    WMTask("smart_malware_remediation", "Smart Malware Remediation Mode", "security",
           "Runs Defender signature update + scan, MSRT, startup persistence "
           "inventory, and saves a remediation report.",
           admin=True, secs=250, risk="caution", restore_point=True),
    WMTask("telemetry_hard_disable", "Telemetry & Tracking Hard-Disable", "security",
           "Disables DiagTrack service + CompatTelRunner task, sets Telemetry policy "
           "to 0, clears Advertising ID, disables app-launch tracking, tailored "
           "experiences, feedback prompts, and inking/typing data collection.",
           admin=True, secs=115, risk="destructive", restore_point=True),
    WMTask("scheduled_task_audit", "Audit Scheduled Tasks (Persistence)", "security",
           "Inventories non-Microsoft scheduled tasks. Flags any task that runs from "
           "%TEMP%, %APPDATA%, or unsigned executables. Common malware persistence "
           "vector. Saves report to Desktop.",
           admin=True, secs=42, risk="safe"),
    WMTask("firewall_audit", "Firewall Rules Audit", "security",
           "Inventories enabled inbound firewall rules and flags any that allow "
           "unsigned binaries. Saves a Desktop report with profile, action, and "
           "program path for each rule.",
           admin=True, secs=38, risk="safe"),
    WMTask("sysinternals_autoruns", "Sysinternals Autoruns", "security",
           "Downloads and launches Sysinternals Autoruns to manage startup programs.",
           admin=True, secs=550, risk="caution"),
    WMTask("sysinternals_procexp", "Sysinternals Process Explorer", "security",
           "Downloads and launches Sysinternals Process Explorer for advanced process "
           "management.",
           admin=True, secs=560, risk="caution"),
    WMTask("security_posture_report", "Security Posture Report", "security",
           "Builds an HTML report of Defender status, UAC level, SmartScreen, "
           "BitLocker, firewall profiles, and how recent your last update is. Opens "
           "in your browser when done.",
           admin=True, secs=35, risk="safe", simple=True, plain="Security check-up"),
    WMTask("camera_mic_audit", "Camera & Microphone Access Audit", "security",
           "Lists every app that is allowed to use the camera or microphone and when "
           "it last did. Read-only.",
           secs=15, risk="safe"),
    WMTask("account_audit", "Local Account Audit", "security",
           "Lists local accounts and administrators; flags accounts that require no "
           "password, extra admins, and an enabled built-in Administrator or Guest. "
           "Read-only.",
           secs=20, risk="safe"),

    # ── DIAGNOSTICS ──
    WMTask("minidump_analyzer", "MiniDump Analyzer (BlueScreenView)", "diagnostics",
           "Downloads and launches NirSoft BlueScreenView to analyze BSOD minidump "
           "files.",
           admin=True, secs=540, risk="safe"),
    WMTask("windbg_crash_analyzer", "WinDbg Crash Analyzer", "diagnostics",
           "Installs/launches Microsoft's WinDbg, then opens a paste box that explains "
           "copied crash analysis in plain English.",
           admin=True, secs=570, risk="safe"),
    WMTask("bsod_triage", "One-Click BSOD Triage", "diagnostics",
           "Collects crash dumps, bugcheck events, driver context, and builds a "
           "Desktop triage report.",
           admin=True, secs=580, risk="safe"),
    WMTask("event_log_viewer", "View Recent Event Log Errors", "diagnostics",
           "Shows the 25 most recent Error and Warning events from the Windows System "
           "and Application logs.",
           secs=20, risk="safe"),
    WMTask("pc_report", "Generate PC Report", "diagnostics",
           "Generates a detailed system report",
           secs=25, risk="safe", simple=True, plain="Full PC health report"),
    WMTask("battery_health_report", "Battery Health Report", "diagnostics",
           "Runs powercfg /batteryreport on Desktop and opens the HTML. Shows design "
           "vs. full-charge capacity, recent usage, and wear (%). Skipped "
           "automatically on desktops.",
           secs=22, risk="safe"),
    WMTask("reliability_monitor", "Open Reliability Monitor", "diagnostics",
           "Launches Windows Reliability Monitor (perfmon /rel). Shows a day-by-day "
           "stability timeline with crashes, freezes, and failed updates.",
           secs=12, risk="safe"),
    WMTask("memory_diagnostic", "Schedule Memory Diagnostic (Restart)", "diagnostics",
           "Launches Windows Memory Diagnostic (mdsched.exe). On confirmation, reboots "
           "immediately and tests RAM for errors before Windows loads.",
           admin=True, secs=660, risk="caution", reboot=True),
    WMTask("cpu_stress_test", "CPU Stress Test (60s) & Health Check", "diagnostics",
           "Starts a workload on every CPU thread for 60 seconds while sampling load and clock "
           "speed, then checks the System event log for new WHEA hardware errors. "
           "Reports low load, reduced clock speed and new hardware errors; unavailable "
           "measurements are reported as incomplete. Save your work and "
           "plug laptops in first.",
           admin=True, secs=95, risk="caution"),
    WMTask("gpu_stress_test", "GPU Stress Test (60s)", "diagnostics",
           "Runs a hardware OpenGL shader workload for 60 seconds in a cancellable child "
           "process. Names the adapter tested and checks for new display-driver errors. "
           "Tests the GPU chosen by your graphics driver; other GPUs, VRAM integrity and "
           "temperature are not tested. Save your work and plug laptops in first.",
           admin=True, secs=80, risk="caution"),
    WMTask("ram_quick_test", "RAM Quick Test (Pattern Check)", "diagnostics",
           "Writes and verifies test patterns (0x55, 0xAA, random) across up to 1 GB "
           "of free RAM, lists installed memory sticks, and checks the event log for "
           "memory diagnostic results and WHEA errors. For a deeper boot-time scan use "
           "'Schedule Memory Diagnostic'.",
           admin=True, secs=85, risk="safe"),
    WMTask("gpu_diagnostic", "GPU Diagnostic & Driver Check", "diagnostics",
           "Inventories every graphics adapter (driver version, device status, error "
           "codes), scans the event log for display-driver crashes (TDR events), reads "
           "temperature/utilization via nvidia-smi when available, and runs a dxdiag "
           "scan for reported problems.",
           admin=True, secs=70, risk="safe"),
    WMTask("usb_enumerate", "USB Devices: List & Safely Eject", "diagnostics",
           "Lists all attached USB devices (mass storage, HID, audio, etc.) and offers "
           "a one-click safe-eject for every removable drive \u2014 useful before "
           "unplugging.",
           secs=28, risk="caution"),
    WMTask("disk_smart_check", "Disk Health Check (SMART)", "diagnostics",
           "Reads SMART reliability data for every drive: health status, temperature, "
           "wear, power-on hours, and read/write errors. Early warning before a drive "
           "fails.",
           admin=True, secs=25, risk="safe", simple=True, plain="Check drive health"),
    WMTask("boot_time_analyzer", "Boot Time Analyzer", "diagnostics",
           "Reads Windows' boot-performance event log: how long recent boots took and "
           "which driver, service, or app slowed them down.",
           admin=True, secs=20, risk="safe"),

    # ── UPDATES ──
    WMTask("windows_updates", "Check & Install Windows Updates", "updates",
           "Checks for and installs the Windows updates Windows itself would install "
           "(not optional previews or updates you have hidden). Offers a restart at "
           "the end if one is needed.",
           admin=True, secs=390, risk="caution", simple=True, plain="Check for Windows updates"),
    WMTask("device_firmware", "OEM Firmware Updates", "updates",
           "Finds missing OEM driver/firmware updates on Windows Update and shows them "
           "as a checklist first. Graphics drivers start unticked -- Windows Update "
           "often offers an older one than your GPU maker's. Then reports OEM support "
           "guidance.",
           admin=True, secs=340, risk="caution", restore_point=True),
    WMTask("install_system_drivers", "Install System Drivers", "updates",
           "Finds missing drivers on Windows Update and shows them as a checklist "
           "first (graphics drivers start unticked), then shows detailed driver "
           "inventory output.",
           admin=True, secs=320, risk="caution", restore_point=True),
    WMTask("windows_update_forensic", "Windows Update Forensic Fixer", "updates",
           "Diagnoses first: update services, a pending restart, and recent Windows "
           "Update errors. Only resets the update components when there is evidence "
           "they are broken, and asks for a restart instead when one is pending. "
           "Then checks for updates.",
           admin=True, secs=360, risk="caution", restore_point=True),
    WMTask("driver_rollback_center", "Driver Rollback Center (Snapshot + Guide)", "updates",
           "Exports a copy of every third-party driver installed now, with a driver "
           "inventory and a step-by-step guide to put any of them back later. Saved "
           "on this PC under your user folder (not OneDrive).",
           admin=True, secs=300, risk="caution", restore_point=True),
    WMTask("update_apps", "Update Apps (Winget)", "updates",
           "Lists every app winget can update, then updates them all in one pass "
           "with live progress. Stop ends winget and whatever installer it started.",
           admin=True, secs=180, risk="caution", simple=True, plain="Update my apps"),
    WMTask("app_installer", "Install Apps", "updates",
           f"Opens the app catalogue: {len(INSTALLABLE_APPS)} apps across browsers, "
           f"utilities, media, development and games. Pick any number and install "
           f"them in one batch via winget, each from its publisher's own source.",
           secs=1, risk="caution", simple=True, plain="Install apps"),

    # ── ADVANCED ──
    WMTask("chris_titus_utility", "Chris Titus Windows Utility", "advanced",
           "Runs the Chris Titus Windows Utility script",
           admin=True, secs=500, risk="caution", restore_point=True),
    WMTask("open_msconfig", "Open MSCONFIG", "advanced",
           "Launches Windows System Configuration (msconfig).",
           secs=25, risk="caution"),
    WMTask("activate_windows", "Activate Windows/Change Product Key", "advanced",
           "Activates Windows using a product key via slmgr.vbs",
           admin=True, secs=35, risk="caution"),
    WMTask("autopilot_csv", "Create AutoPilot CSV", "advanced",
           "Creates an AutoPilot CSV for deployment",
           admin=True, secs=40, risk="caution"),
    WMTask("create_restore_point_guardrail", "Create Restore Point (Guardrail)", "advanced",
           "Creates a manual System Restore checkpoint to use as a recovery guardrail.",
           admin=True, secs=10, risk="caution"),
    WMTask("optional_features_toggle", "Windows Optional Features", "advanced",
           "Pop-up picker to enable or disable WSL, Hyper-V, Windows Sandbox, Virtual "
           "Machine Platform, Containers, .NET Framework 3.5, legacy media "
           "(Windows Media Player, DirectPlay) and the NFS client, via DISM. "
           "Requires reboot after toggling.",
           admin=True, secs=105, risk="destructive", restore_point=True, reboot_after=True),
    WMTask("legacy_boot_menu", "Legacy F8 Boot Menu", "advanced",
           "Restores the F8 Advanced Boot Options screen Microsoft turned off by "
           "default — the one that offers Safe Mode when Windows will not start. "
           "Costs a slightly slower boot; the same picker turns it back off.",
           admin=True, secs=20, risk="caution"),
]


# task id -> the SystemCleanerGUI method that performs it. Extracted from the
# legacy execute_tasks() dispatch chain, so the Qt UI calls exactly the same
# proven implementations the tkinter UI has always called.
WM_HANDLERS = {
    # cleanup
    "clean_temp": "clean_temp_files",
    "disk_cleanup": "run_disk_cleanup",
    "clear_browser_cache": "run_clear_browser_cache",
    "component_cleanup": "run_component_store_cleanup",
    "rebuild_icon_cache": "rebuild_icon_and_thumb_cache",
    "rebuild_font_cache": "run_rebuild_font_cache",
    "storage_sence": "run_storage_sence",
    "windows_old_cleanup": "run_windows_old_cleanup",
    "restore_point_cleanup": "run_restore_point_cleanup",
    # repair
    "restart_windows": "run_restart_windows",
    "repair_system": "repair_system_files",
    "chk_dsk": "run_chk_dsk",
    "reset_win_update": "reset_windows_update",
    "clear_print_spooler": "run_clear_print_spooler",
    "toggle_safe_mode": "run_toggle_safe_mode",
    "boot_advanced_options": "run_boot_advanced_options",
    "reset_search_index": "run_reset_search_index",
    "service_dependency_repair": "run_service_dependency_repair",
    "ssd_saver": "run_ssd_saver",
    "reset_to_defaults": "run_reset_to_defaults",
    "system_restore_browser": "run_system_restore_browser",
    "file_assoc_reset": "run_file_assoc_reset",
    "start_menu_reset": "run_start_menu_reset",
    "uwp_app_reset": "run_uwp_app_reset",
    "audio_repair": "run_audio_repair",
    "explorer_repair": "run_explorer_repair",
    "office_repair": "run_office_repair",
    # performance
    "disable_fast_startup": "perform_disable_fast_startup",
    "adjust_virtual_memory": "optimize_virtual_memory",
    "windows_adjustments": "perform_windows_adjustments",
    "defrag_optimize": "run_defrag_optimize",
    "disable_gaming_features": "disable_all_gaming_features",
    "enable_gaming_features": "enable_all_gaming_features",
    "edge_performance": "apply_edge_performance_adjustments",
    "power_plan_switcher": "run_power_plan_switcher",
    "debloat_windows": "run_win11_debloat",
    "debloat_extreme": "run_win11_debloat_extreme",
    "stop_background_apps": "stop_background_apps",
    "disable_startup_apps": "disable_startup_apps",
    "startup_manager": "run_startup_manager",
    "windows_tweaks": "run_windows_tweaks",
    "ram_optimizations": "run_ram_optimizations",
    # network
    "flush_dns": "flush_dns_and_renew_ip",
    "ipconfig_all": "display_ip_config",
    "change_dns": "change_dns_servers",
    "reset_hosts": "run_reset_hosts",
    "reset_network": "reset_network_stack",
    "deep_network_remediation": "run_deep_network_remediation",
    "export_wifi_passwords": "run_export_wifi_passwords",
    "network_adapter_reset": "run_network_adapter_reset",
    "ping_test": "run_ping_test",
    "network_diagnostic_bundle": "run_network_diagnostic_bundle",
    "dns_over_https": "run_dns_over_https",
    "wifi_channel_analyzer": "run_wifi_channel_analyzer",
    "wlan_report": "run_wlan_report",
    "speed_test": "run_speed_test",
    "open_ports_viewer": "run_open_ports_viewer",
    "bluetooth_repair": "run_bluetooth_repair",
    "time_sync_fix": "run_time_sync_fix",
    # security
    "defender_scan": "run_defender_scan",
    "msrt_scan": "run_msrt_scan",
    "smart_malware_remediation": "run_smart_malware_remediation",
    "telemetry_hard_disable": "run_telemetry_hard_disable",
    "scheduled_task_audit": "run_scheduled_task_audit",
    "firewall_audit": "run_firewall_audit",
    "sysinternals_autoruns": "run_sysinternals_autoruns",
    "sysinternals_procexp": "run_sysinternals_procexp",
    "security_posture_report": "run_security_posture_report",
    "camera_mic_audit": "run_camera_mic_audit",
    "account_audit": "run_account_audit",
    # diagnostics
    "minidump_analyzer": "run_minidump_analyzer",
    "windbg_crash_analyzer": "run_windbg_crash_analyzer",
    "bsod_triage": "run_bsod_triage",
    "event_log_viewer": "run_event_log_viewer",
    "pc_report": "generate_pc_report",
    "battery_health_report": "run_battery_health_report",
    "reliability_monitor": "run_reliability_monitor",
    "memory_diagnostic": "run_memory_diagnostic",
    "cpu_stress_test": "run_cpu_stress_test",
    "gpu_stress_test": "run_gpu_stress_test",
    "ram_quick_test": "run_ram_quick_test",
    "gpu_diagnostic": "run_gpu_diagnostic_test",
    "usb_enumerate": "run_usb_enumerate",
    "disk_smart_check": "run_disk_smart_check",
    "boot_time_analyzer": "run_boot_time_analyzer",
    # updates
    "windows_updates": "check_and_install_windows_updates",
    "device_firmware": "check_and_install_device_firmware",
    "install_system_drivers": "install_system_drivers_info",
    "windows_update_forensic": "run_windows_update_forensic_fixer",
    "driver_rollback_center": "run_driver_rollback_center",
    "update_apps": "update_installed_apps",
    "app_installer": "run_app_installer",
    # advanced
    "chris_titus_utility": "run_chris_titus_utility",
    "open_msconfig": "run_open_msconfig",
    "activate_windows": "run_activate_windows",
    "autopilot_csv": "create_autopilot_csv",
    "create_restore_point_guardrail": "run_create_restore_point_guardrail",
    "optional_features_toggle": "run_optional_features_toggle",
    "legacy_boot_menu": "run_legacy_boot_menu",
}
