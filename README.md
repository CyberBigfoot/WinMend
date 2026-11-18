<div align="center">

# WinMend

## Overview

**WinMend** is a desktop application for IT professionals, power users, and everyday users who want a single, reliable tool to maintain, repair, and diagnose their Windows machines.

**99 maintenance tools** across 12 categories — from one-click junk removal to BSOD triage, network stack remediation, CPU and GPU stress tests, a full internet speed test, a startup manager, 27 reversible Windows registry switches, and a 392-app installer — all in one native Windows app, without ever opening a command prompt.

Three things separate WinMend from a folder of batch scripts:

- **Guided Fix** — describe the problem in plain English. WinMend asks up to five relevant optional questions, gathers measurements and change history, compares supporting and contradictory evidence, and ranks suspected causes. Repairs require measured prerequisites and safety checks; remaining repairs for the same fault stop when its targeted measurements clear.
- **Safety Journal** — every run is recorded locally, with the exact restore point number where Windows exposes one, so a session can be rolled back precisely.
- **Nothing is killed on a timer.** Long scans (SFC, DISM, CHKDSK, full-drive analysis) run to completion with live output and a Cancel button. A slow scan is never reported as a failed one.

> **Requires Administrator privileges** for full functionality. The standalone `.exe` automatically prompts for elevation via UAC.

---

## Table of Contents

- [What's New in WinMend 3.7](#whats-new-in-winmend-37)
- [Features](#features)
  - [Guided Fix](#guided-fix)
  - [Safety Journal](#safety-journal)
  - [Dashboard](#dashboard)
  - [Cleanup](#cleanup)
  - [Storage Analyzer](#storage-analyzer)
  - [Repair & Recovery](#repair--recovery)
  - [Performance](#performance)
  - [Startup Manager](#startup-manager)
  - [Network](#network)
  - [Speed Test](#speed-test)
  - [Security](#security)
  - [Diagnostics](#diagnostics)
  - [Updates & Drivers](#updates--drivers)
  - [Install Apps](#install-apps)
  - [Windows Settings](#windows-settings)
  - [Advanced](#advanced)
- [UI & Design](#ui--design)
- [Usage Guide](#usage-guide)
- [Security & Safety](#security--safety)
- [Requirements](#requirements)
- [Source Layout](#source-layout)
- [Older Releases](#older-releases)
- [License](#license)
- [Antivirus False Positive Notice](#antivirus-false-positive-notice)
- [Disclaimer](#disclaimer)

---

## What's New in WinMend 3.7

### Cleanup that cannot be redirected

WinMend runs elevated, and `C:\Windows\Temp` lets every standard account create folders. The temp cleaner used a path-based recursive delete there: swap a folder it had just listed for a junction, and it followed the junction and deleted files outside the folder with administrator rights. That was reproduced, and it is fixed.

- **Clean Temp Files**, **Clear Browser Cache**, and the Guided Fix shader-cache repair now delete **by handle** (`winmend/core/safe_delete.py`). Every entry is opened with `FILE_FLAG_OPEN_REPARSE_POINT`, so a link is opened and removed as itself; checked against its expected location with `GetFinalPathNameByHandle`; held without `FILE_SHARE_DELETE` while its contents go, so it cannot be swapped out; and removed with delete-on-close, never looked up by name a second time.
- A cache folder that is itself a link, or is reached through one, is reported as **"was not cleared"** and left alone. If you have junctioned a browser profile to another drive, its cache is now skipped on purpose.

### Undo records that cannot be forged

The Safety Journal lives in `%APPDATA%`, which any program running as you can rewrite, and **Reverse changes** and **Undo this session** replay it with administrator rights. A program could have written an "undo" of its own (switching UAC prompts off, or prepending a folder to the system PATH) and had WinMend apply it.

- Every undo record and restore-point number is now **sealed**: a SHA-256 of exactly what WinMend recorded, bound to its session and step, stored in `HKLM\SOFTWARE\WinMend\UndoSeals`. That key is owned by Administrators with a protected DACL (SYSTEM and Administrators write, Users read), and its security is re-checked every time it is opened (`winmend/safety/seals.py`).
- Nothing is replayed unless it still matches its seal. An entry that does not (edited, forged, recorded without administrator rights, or **written by 3.6 or earlier**) shows as **"Undo record unverified"** and is not offered for automatic reversal. The System Restore browser still lets you pick a checkpoint by hand.

### Every option is a slider

Every on/off choice in the app is now an animated slider, red when off and green when on, instead of a checkbox: task cards, the Install Apps catalogue, Windows Settings switches, Guided Fix repair-plan steps, and the pickers a task opens before it runs. They are still real checkboxes and checkable list items underneath, so Tab, Space, and screen readers behave as before.

### Dark mode switch

A **Dark mode** switch at the foot of the sidebar changes the theme for the current session, in place. Widgets are recoloured rather than rebuilt, so selections, scan results, cached pages, and a running task are untouched, and the new theme sweeps across the window from left to right. WinMend still starts in whichever theme Windows is set to; the session choice is not saved.

### Honest results for every option

All 99 options go through one reporting contract. A task that finishes without reporting any activity is marked **failed** ("this option's result could not be confirmed") instead of completed. A failure outranks a skip, and a cancellation outranks both.

### Cleanup, corrected

- **Clean Temp Files** keeps Prefetch, which Windows reads to start apps faster, and leaves anything changed in the last 24 hours, which installers and running apps (including WinMend's own unpacked files) are still using.
- **Clear Browser Cache** covers every profile of Edge, Chrome, Brave, Vivaldi, Opera, Opera GX, and Firefox, and touches only cache folders. Firefox's cache used to be looked for in the roaming profile, where it does not exist, so it was never actually cleared.

### New: SSD Saver

**SSD Saver** (Repair & Recovery) stops the AMD External Events Utility service and sets it to Disabled, on PCs with an AMD processor or graphics card. Affected systems see ongoing background writes from that service, which wear an SSD's finite write endurance. It changes nothing on other PCs or where the service is not installed, and **Reset Windows Defaults** puts back the start type it had.

### Options that now do what they say

Every option was run through the real window with each command recorded, and these were fixed:

- **Create AutoPilot CSV** used to write a script into `C:\PowerShell` (a folder every account on the PC can change) and run it as administrator. It now reads the hardware hash in memory and saves the CSV to your Desktop.
- **Windows Update Forensic Fixer** reset the update components over any error in the last 14 days, even one a later install of the same update had already fixed. It now leaves Windows Update alone unless an error is still unresolved.
- **Windows Updates** reported a partly successful install as a failure. It now names each update that did and did not install, and offers the restart the installed ones need.
- **Rebuild Icon & Thumbnail Cache** deleted nothing (Windows restarted Explorer before the files were reached) yet said it had succeeded, then opened a stray Explorer window. It now closes Explorer cleanly, reports any file still in use, and starts Explorer only if Windows has not.
- **Reliability Monitor**, **Memory Diagnostic**, Office's **Quick and Online Repair**, **WinDbg** and the edition-change dialog were started with their window hidden. They now open normally.
- **Windows Optional Features** enables DirectPlay and the NFS client themselves rather than their empty parent features, and confirms the result with Windows.
- **Boot Time Analyzer** explains when the Diagnostic Policy Service is off (RAM Optimizations turns it off), instead of showing old boots as if they were recent.
- PowerShell failures now show their message ("The requested operation requires elevation.") instead of an error id.
- Cancelling **Activate Windows**, or running **Battery Health Report** or **Wi-Fi Channel Analyzer** on a PC without a battery or Wi-Fi, now reports Skipped rather than Completed.
- **PC Report** shows the real system UUID; it used to show the network adapter's MAC address under that name.

### Under the hood

`WinMend.py` is now a small launcher; the application lives in the `winmend/` package, organised by responsibility. See [Source Layout](#source-layout).

---

## Features

### Guided Fix

1. Open **Guided Fix** from the sidebar.
2. Either select **Check for issues** to scan everything and skip to step 4, or describe the symptom — such as `Wi-Fi connects but websites will not load` — and select **Start**.
3. Answer the follow-up questions, or select **Skip questions**.
4. Watch the checks run. **Assessment** ranks the likely causes with the evidence for each; **Measurements** lists every reading.
5. Review the plan. Anything deliberately withheld is shown beneath it with the reason.
6. Switch off any step you do not want, then select **Run protected plan**.
7. Use **Save report** for a shareable case file, or **Re-check now** after a restart to verify a fix that needed one.

Assessments show qualitative evidence strength, support, contradictions, and missing coverage. Performance checks repeat CPU, available memory, commit, and per-device I/O readings; high cached RAM usage, startup counts, and recent changes alone do not establish a cause. Failed, unavailable, and unsupported measurements remain visible as unknown.

Public connectivity probes use fixed Microsoft and Cloudflare names, Cloudflare and Google TCP endpoints, and a reserved `.invalid` DNS control, with timeouts. No diagnostic report is sent. Public probes cannot verify private VPN domains or the affected browser. The case-engine API also allows external probes to be disabled.

Verification compares the original targeted faults with fresh comparable readings. Command completion, missing measurements, and a lower overall severity score cannot establish success. **Confirm symptom** records whether the original user problem cleared; until then, cleared readings are reported as symptom unverified. See the [implementation and validation report](artifacts/guided-intelligence/engineering-summary.md) for scope, test results, and remaining limitations.

### Safety Journal

Open **Safety Journal** to inspect manual and guided runs. Each entry shows task-level status, duration, checkpoint coverage, and verification results. **Undo this session** is available only when WinMend recorded an exact Windows restore point. **Open System Restore** remains available for reviewing other checkpoints manually.

When a guided run made a targeted change — clearing a proxy, replacing the hosts file, disabling one startup entry, returning DNS to automatic — that step records exactly what it overwrote, and **Reverse changes** puts those values back individually without rolling the whole machine back.

Both buttons act only on records WinMend has sealed. The journal file can be edited by any program running as you, so each undo record and restore-point number is fingerprinted into an administrator-only registry key when it is written, and checked against it before anything is replayed. A record that does not match, or that was written by WinMend 3.6 or earlier, is shown as **Undo record unverified** and is not reversed automatically.

> System Restore does not recover deleted junk, temporary files, browser caches, or personal files. WinMend labels tasks that fall outside a checkpoint's protection scope rather than implying they are reversible.

### Smart Fix Search

The search bar at the top of the app matches your plain-English problem against every one of the 99 tools and ranks the best candidates, with the reason for each match. Type `my pc is slow`, `no sound`, `blue screen`, or `wifi not working` and jump straight to the relevant tool.

---

### Dashboard

System information at a glance: CPU, RAM, motherboard, OS build and install date, every drive with free space, network adapters, and whether WinMend is running elevated.

---

### Cleanup

*9 tools*

| Task | Description |
|---|---|
| Clean Temp Files (System-wide) | Windows Temp and User Temp. Leaves anything changed in the last 24 hours and keeps Prefetch, which Windows uses to start apps faster. Never follows a link out of the folder |
| Deep Disk Cleanup | Windows Disk Cleanup in four measured stages (temp files and caches, Delivery Optimization and old drivers, Windows Update Cleanup, previous-installation leftovers), then the Recycle Bin. Progress is measured from free space, CPU and disk activity, so a slow stage is reported and a provably stuck one is skipped instead of sitting at 95%. Never touches your Downloads folder, File History versions or the files Reset this PC needs |
| Clear Browser Cache | Cache folders only, for every profile of Edge, Chrome, Brave, Vivaldi, Opera, Opera GX, and Firefox — never passwords, history, bookmarks, or cookies |
| Component Store Cleanup (DISM) | Removes superseded Windows Update backups from the component store |
| Rebuild Icon & Thumbnail Cache | Fixes blank, black, or corrupted icons on the desktop, taskbar, and Explorer |
| Rebuild Font Cache | Fixes corrupted or missing fonts |
| WinMend Storage Analyzer | Opens the Storage page |
| Remove Windows.old | Deletes the previous Windows installation — often 20-30 GB. Ends the rollback window |
| Delete Old Restore Points | Frees shadow-copy storage while keeping your newest rollback point |

---

### Storage Analyzer

Its own page in the sidebar (**Storage**) — a two-pane disk analyzer with a hierarchical folder tree on the left and details on the right.

- **Directory tree** — expand any folder; children load on demand so huge drives stay responsive
- **Contents / Largest files toggle** — the right pane shows either the selected folder's contents (Name, Size, Files, Folders, % of Parent, Modified, Hint) or a flat biggest-first list of every file in the scan
- **Size-coded rows** — blue for Windows core files, red over 1 GB, orange over 100 MB
- **Safety classifier** — 13 rules identify what must never be casually deleted: critical OS paths, documents and media, cloud-synced folders, high-risk extensions (`.pst`, `.vhd`, `.kdbx`…), game libraries, source trees, recent downloads, and the Search index. This drives the Hint column, the confirmation dialog, and a hard refusal to delete critical paths
- **Duplicate finder** — groups by size, then a 64 KB head hash, then a full BLAKE2b hash so same-size lookalikes are never mistaken for duplicates. It lists duplicates and deliberately refuses to auto-delete them
- **Multi-select recycling** — send several items to the Recycle Bin at once, or open a file's location

Drive health (SMART) lives in **Diagnostics → Disk Health Check**.

---

### Repair & Recovery

*18 tools*

| Task | Description |
|---|---|
| Repair System (SFC/DISM) | Scans and restores corrupted Windows system files |
| Schedule Check Disk | Repairs filesystem errors and bad sectors on next reboot |
| Reset Windows Update Components | Renames SoftwareDistribution and catroot2 to fix stuck or failing updates |
| Clear Print Spooler Queue | Removes stuck print jobs and restarts the spooler |
| Reset Windows Search Index | Fixes broken search and Cortana |
| Service Dependency Repair | Repairs critical service dependency chains |
| SSD Saver | On a PC with an AMD processor or graphics card, stops the AMD External Events Utility service and sets it to Disabled. **Excessive SSD writes:** affected systems see ongoing background writes (from a fraction of a MB/s to several MB/s, or hundreds of GB a day in severe reports), tied to how the External Events Utility interacts with Windows and PCIe behaviour. **Drive wear:** SSDs have a finite write endurance (TBW), so constant background writes can wear out the system drive faster. Does nothing on other PCs; Reset Windows Defaults turns the service back on |
| Reset File Associations | Clears UserChoice keys for common extensions |
| Reset Start Menu & Taskbar Layout | Fixes a broken, frozen, or corrupted Start menu |
| Reset UWP App | Fully resets Mail, Photos, Camera, Calculator, Store, etc. |
| Repair Audio | Restarts the audio services — the standard "no sound after an update" fix |
| Repair File Explorer (Reset Quick Access) | For Explorer that opens slowly or sits at "Working on it...": rebuilds the Quick Access jump list and puts your pins back (minus any on a server or drive that no longer answers), clears Explorer history, finds mapped drives and network locations that don't answer and asks before removing them, and lists third-party shell extensions. Backs everything up first |
| Repair Microsoft Office & Outlook | For Outlook or Office that won't open, crashes, keeps asking for a password or says "Unlicensed Product". Measures first — the Click-to-Run service, Office processes stuck without a window, licence state, the Outlook profile and data-file size, add-ins, sign-in registry overrides, and two weeks of crash events traced to the add-in, driver or Office file each landed in — then shows a checklist with only the evidence-backed repairs pre-ticked: end the stuck process, fix the service, turn off the crashing add-in, Office's own Quick or Online Repair, reset the navigation pane, rebuild the offline cache, reset the sign-in/licence cache (backed up first), check for Office updates. Reversible steps log their undo |
| Reset Windows Defaults (Undo Tweaks) | Reverts WinMend's own performance and gaming tweaks |
| System Restore Browser | Lists every restore point on the PC and rolls back to the one you pick |
| Safe Mode Boot Toggle | Boots into Safe Mode with Networking on the next restart |
| Boot to Advanced Options / BIOS | Reboots straight into UEFI / Advanced Startup |
| Restart Windows | Confirmed restart with a 60-second cancellable countdown |

---

### Performance

*15 tools*

| Task | Description |
|---|---|
| Disable Fast Startup | Forces clean shutdowns — fixes dual-boot and driver oddities |
| Optimize Virtual Memory | Sizes the page file from installed RAM, showing current vs recommended |
| RAM Optimizations | Stops/disables SysMain, Search, DiagTrack, DPS; turns off memory compression and DO peer downloads; recommends a restart only if one is needed |
| Performance Adjustments | Applies a custom visual-effects and background-activity profile |
| Optimize Drives (SSD-Safe) | TRIM for SSDs, defrag for HDDs — never defrags an SSD |
| Turn Off All Gaming Features | Game Bar, DVR, Game Mode, background recording, Xbox monitoring |
| Turn On All Gaming Features | Game Bar, Game Mode, HAGS, VRR, and per-executable GPU preferences |
| Edge Performance Adjustments | Disables Startup Boost and background apps |
| Power Plan Switcher | Balanced, High Performance, Power Saver, or Ultimate Performance |
| Debloat Windows | Removes 91 default bloatware apps silently — no download, no tweaks |
| Debloat Windows Extreme | Adds optional, unsafe, and OEM apps to the removal list — use with caution |
| Stop Background Apps | Disables background activity for Store apps |
| Optimize Startup Apps | Disables all Task Manager startup items except OneDrive, reversibly |
| Startup Manager | Opens the Startup page |
| Windows Settings & Tweaks | Opens the Windows Settings page |

---

### Startup Manager

Its own sidebar page. Enumerates every autostart entry from the `Run` keys (HKCU, HKLM, and the 32-bit view) and both Startup folders.

- **Reversible on/off per app** — WinMend writes the same Task Manager-compatible `StartupApproved` flags Windows uses. **Nothing is ever deleted**, so anything you disable can be re-enabled here or in Task Manager
- **Real measured boot impact** — the delay column shows only what Windows' own Diagnostics-Performance log actually recorded for that app. If there is no measurement, it says **"Not measured"** rather than inventing a rating
- **Journalled** — every toggle is a Safety Journal entry

---

### Network

*17 tools*

| Task | Description |
|---|---|
| Internet Speed Test | Opens the Speed Test page |
| Flush DNS & Renew IP | Clears the resolver cache and renews adapter leases |
| Display Network Config | Full `ipconfig /all` for every adapter |
| Change DNS Servers | 8 public resolvers — Cloudflare, Google, Quad9, OpenDNS, AdGuard, plus malware- and adult-filtering variants — or hand DNS back to your router |
| DNS-over-HTTPS Toggle | Enables encrypted DNS on every active adapter |
| Reset / Flush Hosts File | Restores the default Hosts file after malware or a bad ad-blocker |
| Reset Network Stack (Winsock/TCP) | Fixes "No Internet Access" and deep connectivity faults |
| Deep Network Stack Remediation | Aggressive reset — Winsock, TCP/IP, firewall, ARP, NBT |
| Reset Network Adapters | Disables and re-enables every adapter |
| Ping Test | Gateway, 8.8.8.8, 1.1.1.1, and google.com |
| Network Deep Diagnosis Bundle | Adapter state, routing, DNS, ping tests, and error signals in one report |
| Wi-Fi Channel Analyzer | Nearby networks with channel, signal, and band — pick a clearer channel |
| Wireless Network Report | Windows' own WlanReport: connection history and disconnect reasons |
| View / Export Saved Wi-Fi Passwords | Gated — you must type `EXPORT WIFI PASSWORDS` to authorize plaintext extraction |
| Open Ports & Listening Services | Every bound TCP/UDP port joined to the owning process |
| Repair Bluetooth | Restarts the Bluetooth stack and power-cycles the radio |
| Fix System Clock | Forces a time resync — a wrong clock silently breaks HTTPS, sign-ins, and updates |

---

### Speed Test

Its own sidebar page, measured against **Cloudflare's public speed-test endpoints**. Nothing is bundled and no licensed binary is shipped.

**Quick test** — download, upload, ping, and jitter, with a live gauge and a latency graph drawn as the test runs.

**Advanced test** adds the things a browser tab cannot see:

- **Bufferbloat grade** (A+ to F, Waveform scale) from latency measured *under load* — the spike is visible on the graph
- **Responsiveness (RPM)** plus p50/p95/p99 latency
- **Wi-Fi and adapter bottleneck detection** — reads your actual link speed, radio type, signal, and PHY rate to tell you whether **your Wi-Fi is the ceiling or your ISP is**
- **First-hop latency** — times your own router separately from 1.1.1.1 and 8.8.8.8, so a bad local network is distinguishable from a bad connection
- **DNS timing and IPv6 availability**
- **"Good for…" verdicts** — 4K, HD, video calls, gaming, upload, and multi-device, weighting latency and bufferbloat rather than raw Mbps
- **Exportable ISP evidence report** — a self-contained HTML report comparing your measured speed against your plan, saved to `Documents\WinMend\`
- **Suggested fixes** — findings link straight to the tool that addresses them

Results are trended over time in `speedtest_history.json`. A speed test changes nothing on your PC, so it gets no Safety Journal entry.

> A full advanced test on a gigabit link can move up to ~1 GB of data. The page warns you before it starts.

---

### Security

*11 tools*

| Task | Description |
|---|---|
| Windows Defender Full Scan | Full system scan via `MpCmdRun.exe` |
| MSRT Quick Malware Scan | Microsoft Malicious Software Removal Tool, quiet mode |
| Smart Malware Remediation Mode | Signature update, scan, persistence inventory, and a saved report |
| Telemetry & Tracking Hard-Disable | DiagTrack, CompatTelRunner, telemetry policy, advertising ID, app-launch tracking |
| Audit Scheduled Tasks | Flags non-Microsoft tasks running from `%TEMP%`, `%APPDATA%`, or unsigned binaries |
| Firewall Rules Audit | Inbound rules that allow unsigned binaries, with a saved report |
| Security Posture Report | Defender, UAC, SmartScreen, BitLocker, firewall profiles, update recency |
| Camera & Microphone Access Audit | Every app allowed to use the camera or mic, and when it last did — read-only |
| Local Account Audit | Flags passwordless accounts, extra admins, and enabled Administrator/Guest — read-only |
| Sysinternals Autoruns | Every Windows autostart location in one place |
| Sysinternals Process Explorer | Advanced process inspection |

---

### Diagnostics

*15 tools — diagnostics and bounded hardware workloads. Stress tests raise load and temperature; memory diagnostics can restart Windows.*

| Task | Description |
|---|---|
| MiniDump Analyzer | BSOD dumps via NirSoft BlueScreenView |
| WinDbg Crash Analyzer | Microsoft WinDbg, plus a paste box that explains crash analysis in plain English |
| One-Click BSOD Triage | Dumps, bugcheck events, and driver context in one Desktop report |
| View Recent Event Log Errors | The 25 most recent System and Application errors and warnings |
| Generate PC Report | Detailed HTML report — hardware, networking, and security |
| Disk Health Check (SMART) | Health, temperature, wear, power-on hours, read/write errors per drive |
| Battery Health Report | `powercfg /batteryreport` — design vs full-charge capacity and wear % |
| Boot Time Analyzer | How long recent boots took and which driver, service, or app slowed them |
| Open Reliability Monitor | Day-by-day stability timeline |
| Schedule Memory Diagnostic | Windows Memory Diagnostic on next boot |
| RAM Quick Test | Pattern check across up to 1 GB of free RAM, plus installed stick inventory |
| CPU Stress Test (60s) | Workloads on every CPU thread, with load and clock samples and a check for new WHEA errors; unavailable measurements produce an incomplete result |
| GPU Stress Test (60s) | Hardware OpenGL shader workload in a cancellable child process; names the tested GPU and checks for new display-driver errors. Tests one selected GPU, without a VRAM or temperature check |
| GPU Diagnostic & Driver Check | Adapter inventory, TDR crash events, driver versions, temperature |
| USB Devices: List & Safely Eject | Every attached USB device, with one-click safe eject for removable drives |

---

### Updates & Drivers

*7 tools*

| Task | Description |
|---|---|
| Check & Install Windows Updates | Full Windows Update cycle |
| OEM Firmware Updates | Driver and firmware updates from Windows Update, plus OEM guidance |
| Install System Drivers | Installs missing drivers and shows the full inventory |
| Windows Update Forensic Fixer | Diagnoses stuck, broken, or looping update components |
| Driver Rollback Center | Snapshots drivers and builds a guided rollback workbook by device class |
| Update Apps (Winget) | Opens the app-update panel |
| Install Apps | Opens the Install Apps page |

**The winget update panel** sits at the top of this page:

- Lists every app with an available update, parsed directly from `winget upgrade`
- Updates run **one at a time** with live output on screen, no timeouts, and Cancel stops the run
- The whole batch is recorded as a single Safety Journal session

---

### Install Apps

A curated software catalogue built into WinMend — its own sidebar page.

- **392 curated applications** across 9 categories: Browsers · Utilities · Development · Multimedia Tools · Communications · Document · Games · Microsoft Tools · Pro Tools
- **Category filter and search** — matches names, categories, descriptions, and winget IDs
- **Already-installed detection** — WinMend marks what winget reports installed. Apps installed outside winget may not be detected, so a blank row means *not detected*, not *not installed*
- **Batch install** — switch on any number of apps across categories; they install one at a time with winget's live output, and **Cancel** stops the run
- **Winget backend** — Microsoft's Windows Package Manager fetches each app from the publisher's own source. WinMend hosts nothing and bundles no installers
- **Journalled** — every batch is recorded in the Safety Journal

---

### Windows Settings

A page of switches for the Windows behaviour that has no obvious setting.

- **27 switches** across Appearance, File Explorer, Taskbar & Start, Input, and System — dark theme, file extensions, hidden files, the classic right-click menu, taskbar alignment and buttons, Start menu web results, mouse acceleration, Num Lock at startup, long path support, detailed blue screens, and more
- **Shows the truth, not a memory** — every switch is read from the registry each time the page opens, so changes made in Settings or by another tool appear here too. It never displays "what WinMend last wrote"
- **Reversible by construction** — each switch has a defined on-state *and* off-state, so flipping it back restores exactly what was there. Values WinMend did not create are never deleted, existing values keep their registry type, and bitfields keep the bits the switch is not about
- **Honest about what is needed** — switches requiring admin, an Explorer restart, a sign-out, or a reboot say so on the row, and Explorer is only ever restarted when you ask
- **Journalled** — every flip is a Safety Journal entry

Registry paths and values are taken from Chris Titus's WinUtil, where they have been exercised on real machines, rather than invented.

---

### Advanced

*7 tools — know what these do before running them.*

| Task | Description |
|---|---|
| Create Restore Point (Guardrail) | A manual System Restore checkpoint to use as a recovery guardrail |
| Activate Windows / Change Product Key | Installs the key, activates against Microsoft, and verifies status via `slmgr` |
| Windows Optional Features | Enable or disable WSL, Hyper-V, Sandbox, Virtual Machine Platform, Containers, .NET Framework 3.5, legacy media, and the NFS client via DISM |
| Legacy F8 Boot Menu | Restores the F8 Advanced Boot Options screen — the one that offers Safe Mode when Windows will not start |
| Chris Titus Windows Utility | Downloads to a local temp file, computes SHA256, prompts, then runs locally |
| Create AutoPilot CSV | Exports a hardware hash for AutoPilot enrollment |
| Open MSCONFIG | Launches Windows System Configuration |

---

## UI & Design

### Layout

A **sidebar of 16 pages**, not a single scrolling wall of checkboxes:

`Dashboard` · `Guided Fix` · `Safety Journal` · `Cleanup` · `Storage` · `Repair & Recovery` · `Performance` · `Startup` · `Network` · `Speed Test` · `Security` · `Diagnostics` · `Updates & Drivers` · `Install Apps` · `Windows Settings` · `Advanced`

Each task is a card with its own **Run** button, a plain-English description, an estimated runtime, and badges that say up front if it needs admin, restarts the PC, removes software, makes a restore point first, or is read-only.

### Sliders

Every on/off choice is an animated slider — red when off, green when on — whether it selects tasks, apps to install, a Windows Settings switch, a step of a Guided Fix repair plan, or an option in a task's pre-run picker. Underneath they are ordinary checkboxes, so Tab, Space, and screen readers work as they always did.

### Simple and Advanced modes

| Mode | Shows |
|---|---|
| **Simple** | 26 plain-English actions — "Free up disk space", "Fix my internet", "Check my drive's health" |
| **Advanced** | All 99 tools with their real names and full descriptions |

### Checklist and Activity log

The right-hand panel is split in two. The **Checklist** lists everything selected before you start, then what is running (with elapsed time and no time limit), what is queued, and every finished task with how long it took — nothing is trimmed, so a long run can be reviewed in full while it is still going. The **Activity log** beneath it keeps the whole session's output, timestamped. A task that finishes without reporting anything is shown as failed, not completed. Nothing is ever terminated on a timer.

### Theme

A clean, Fluent-influenced look in **both light and dark**. WinMend starts in whichever theme Windows is set to; the **Dark mode** switch at the foot of the sidebar changes it for the session, recolouring the window in place with a left-to-right sweep so nothing you have selected or started is lost. Typography is **Segoe UI Variable**, the Windows 11 system font — the six bundled display fonts from v1.x were removed in 2.0.

---

## Usage Guide

### Running your first task

1. Launch WinMend as Administrator.
2. The **Dashboard** opens with a summary of this PC.
3. Pick a category from the sidebar, or type your problem into the search bar.
4. Press **Run** on any task. It joins the queue and streams its output live.
5. If a task requires a reboot, its card says so before you start it.

### Fixing something when you don't know the cause

1. Open **Guided Fix**.
2. Describe the symptom in your own words.
3. Read the findings — these are measurements, not guesses.
4. Switch off anything you would rather not run, then **Run protected plan**.
5. Check the verification result. If WinMend could not confirm an improvement, it says so.

### Undoing a session

Open **Safety Journal**, select the run, and choose **Undo this session**. This is offered only when WinMend recorded an exact restore point for that run and its sealed record still matches. Deleted temp files, caches, and personal files are not recoverable this way.

---

## Security & Safety

- **Administrator required** — system-level tasks need elevation, requested automatically in the `.exe` build. Tasks that need admin say so on their card
- **Auto restore point before risky tasks** — WinMend creates one clearly named checkpoint before a run containing restore-compatible changes
- **Change history** — registry, startup, and network changes are recorded so they can be reversed
- **Input sanitization** — commands are sanitized against injection and path traversal
- **Link-safe deletion** — temp, browser-cache, and shader-cache cleaning delete by handle and never follow a junction or symlink out of the folder being cleaned, even one swapped in mid-run. A cache folder that is itself a link is skipped and reported, not followed
- **Sealed undo records** — the journal in `%APPDATA%` is not trusted on its own. Every undo record and restore-point number is fingerprinted into `HKLM\SOFTWARE\WinMend\UndoSeals`, which only administrators can change, and nothing is replayed unless it still matches
- **Confirmation prompts** — destructive or irreversible actions require explicit confirmation. Exporting Wi-Fi passwords requires typing a confirmation phrase
- **Diagnostics describe their effects** — stress tests raise hardware load; scheduling a memory diagnostic can restart Windows
- **Honest reporting** — a task that ran is not treated as a task that worked, and a task that reports nothing is marked failed rather than completed; unmeasured values are labelled "Not measured" rather than filled in
- **No data collection** — WinMend collects, transmits, and stores nothing. The journal, speed-test history, and reports are local files on your own machine, and the undo seals are fingerprints in the local registry

---

## Requirements

| Requirement | Minimum |
|---|---|
| Operating System | Windows 10 (1903+) or Windows 11 |
| Architecture | 64-bit |
| Permissions | Administrator |
| Python (source only) | 3.10+ |
| RAM | 256 MB |
| Disk Space | 50 MB |

**Python dependencies (source only)** — see [`requirements.txt`](requirements.txt):

```
PySide6         # the WinMend interface
psutil          # process and system metrics
pywin32         # Windows API access
requests        # speed test and tool downloads
```

---

## Source Layout

`WinMend.py` is the launcher. Application code lives in the `winmend/` package,
organized by responsibility:

| Location | Responsibility |
|---|---|
| `winmend/bootstrap.py` | Startup checks, elevation, and the Qt application entry point |
| `winmend/core/` | Background task runners, command execution, cancellation, process tracking, link-safe deletion, preferences, and shared models |
| `winmend/data/` | Task definitions and handler IDs, app catalogue, and external-tool identifiers |
| `winmend/features/` | Maintenance handlers and their helpers, grouped by feature such as cleanup, network, Office, and Explorer |
| `winmend/ui/` | Main window, navigation, dialogs, reusable widgets, and individual pages |
| `winmend/diagnostics/` | Interview, evidence collection, assessment, planning, rules, hardware probes, and targeted repairs |
| `winmend/safety/` | Durable safety journal, undo seals, and restore-point lookup |
| `winmend/reports/` | System, Guided Fix, and speed-test HTML reports |
| `tests/` | Headless logic tests and offscreen Qt regression tests |

The task host, diagnostic probes, report collector, and main window compose
small groups of methods. Their existing method names and execution context
are preserved so the maintenance commands, progress reporting, cancellation,
and rollback contracts stay consistent. Feature code and background task
runners import no Qt; the UI binds the confirmation-dialog adapters.

The root `winmend_safety.py`, `winmend_diagnostics.py`, `winmend_hardware.py`,
and `winmend_components.py` files, plus `winmend/compat.py`, preserve historical
imports. New code should import the implementation module directly. Tests
mock dependencies where they are used, rather than patching a compatibility
re-export. Import order in `winmend/diagnostics/rules/__init__.py` preserves
the original rule evaluation order and must remain intentional.

Run from source with `python WinMend.py` or `python -m winmend`. For a UI-only
review without an elevation prompt, append `--no-elevate`. Run the test suite
with `python -m unittest discover -s tests`. Build with
`python -m PyInstaller --clean WinMend.spec`; `WINMEND_BUILD_MODE` still selects
`onefile` or `onedir`.

The pre-refactor source snapshot and relocation audit are in
`artifacts/refactor/`. `verify.py` checks moved definitions, embedded commands,
data tables, and rule order against that snapshot. `migrate.py` is one-time
migration tooling and should not be rerun after subsequent application edits.

---

## Older Releases

<details>
<summary><strong>v3.6 — Qt interface, Guided Fix, Safety Journal</strong></summary>

### A completely new interface

WinMend 3.6 replaces the single 82-checkbox scrolling window with a native **PySide6 (Qt)** application:

- **Sidebar navigation** — 16 pages instead of one wall of checkboxes
- **Simple and Advanced modes** — Simple shows 25 plain-English actions ("Free up disk space", "Fix my internet"); Advanced exposes all 96 tools
- **Per-task Run buttons** with a visible **queue tray** — start what you want, watch what is running, cancel anything
- **Light and dark themes** that follow your Windows personalisation setting
- **Segoe UI Variable** system typography — the six bundled display fonts of v1.x are gone

The Qt interface is the only interface: the original tkinter shell and its `--legacy` switch have been removed.

### Guided Fix: triage, diagnose, repair, verify

Guided Fix works the way a support technician does, not the way a checklist does.

**No specific problem? Select "Check for issues".** One click runs every check on the PC — 83 collectors producing over 75 readings in about 15 seconds, depending on what this machine exposes — and reports anything measurably wrong, ranked by severity, with a repair plan for whatever it finds. No description and no questions needed, because there is no symptom to place in time. If everything passes it says so plainly and offers no work: "all 77 checks are healthy, nothing on this PC is measurably wrong." Every flagged reading gets something offered against it; a warning with no action beside it would not be a complete answer. A filter above the table narrows 77 rows to the handful that need attention, but it starts switched off — the healthy rows are the evidence that the check actually looked.

It means *every* drive, not just the one Windows is on; the services and scheduled tasks that keep the PC maintained; whether Windows Update can still run at all; what Defender found and whether it finished dealing with it; the file-system dirty bit, drive wear counters, UAC, the firewall profile by name, the addressing and the default gateway, the adapter's own error counters, the system clock, printing, search, and the user profile. Several of those are faults nothing in Windows reports plainly — a data drive at 4%, updates switched off by a leftover policy, a threat detected but never removed, a clock wrong by ten minutes, a temporary profile that makes a PC look wiped.

It also reads the faults that have no error message anywhere: the hardware's own error reports split by which component raised them, a memory test Windows already failed, a PC set to boot into Safe Mode forever, drive encryption left suspended with the key in the clear, a network stack routing every socket through a DLL that was uninstalled, a resolver answering for domains that cannot exist, updates pointed at a company server the laptop left two jobs ago, a connection quietly marked metered so nothing ever downloads, System32 missing from the PATH, and Desktop and Documents pointing into a OneDrive that is not running.

The rules that depend on your account of events stay silent during a full check, by design. With no reported symptom and no stated onset, nothing gets blamed on last Tuesday's update — everything reported rests purely on measurement.

If you *do* have a specific symptom, describe it instead and the full workflow runs:

**1. It asks first.** Describe the problem in normal language and WinMend asks up to five follow-up questions chosen from what you typed — when it started, whether anything changed just before, whether it still happens in Safe Mode, whether other devices on the network are affected. These are the things a PC cannot work out about itself, and they decide where everything else looks. You can skip them.

**2. It gathers evidence in two passes.** A fast pass shows findings within a few seconds; a deep sweep then runs ~52 further checks concurrently with a progress bar and a Cancel button. Alongside the classic health probes it reads:

- **Change history** — updates, drivers, and programs installed recently, correlated against when you said the problem began
- **Hardware's own account of itself** — the machine-check and PCI Express errors Windows recorded, split into corrected and uncorrected and attributed to the component that raised them; whether Windows' memory test has ever run and what it found; whether the processor is reaching its rated clock while it is being asked to work
- **Boot, power, and sleep** — the boot loader's own settings, including the msconfig flag that strands a PC in Safe Mode and the two that let unsigned drivers load; whether "Shut down" really shuts down; what last woke the PC and what is still allowed to
- **Storage upkeep and encryption** — whether TRIM is switched off, whether Windows calls each volume healthy, and whether any drive is encrypted but left with protection suspended
- **The network as it actually behaves** — third-party layers spliced into the socket stack and whether their files still exist, name resolution timed and tested against a domain that cannot exist, packet size per adapter, Windows' own internet verdict, and whether the connection is marked metered
- **Where updates come from** — a redirection to another update server, a pin to a Windows version this PC will now never leave, and how big and how old the stuck download folder is
- **Apps, shell, and devices** — Store packages Windows reports as damaged, whether Explorer is running, the audio services and endpoints, Bluetooth, and whether the screen is being drawn by the real graphics driver or Microsoft's fallback
- **Integrity, policy, and your files** — what the last System File Checker run concluded, read from its log rather than by starting a half-hour repair; features switched off by policy behind the Settings app; the system PATH; and whether Desktop and Documents point somewhere that works
- **Device and driver health** — Device Manager problem codes, display-driver resets, thermal throttling, memory configuration, disk service times
- **Error codes** — blue-screen stop codes, Windows Update `0x8007…` failures, and the faulting module inside application crashes, each decoded to a probable cause
- **Storage, drive by drive** — free space and file system on every fixed volume, the dirty bit, a scheduled disk check, crash dumps on disk, and the drive's own wear, temperature, and uncorrected-error counters, which change long before SMART's pass/fail flag does
- **Upkeep** — essential services that are stopped, Windows maintenance tasks that are failing, and whether Windows Update has been switched off by policy or a disabled service
- **Security posture** — Defender's detection history including anything detected but never removed, UAC, each firewall profile by name, Defender exclusions, Secure Boot/TPM
- **Connection and clock** — addressing and default gateway, the adapter's own error and drop counters, Wi-Fi signal, DNS and proxy configuration, and the system clock measured against an internet time server
- **Integrity and policy state** — component-store health, servicing support status, page file, hosts file, search index, printing, power plan, and whether this is the real user profile or a temporary stand-in

**3. It reasons, then explains.** Findings are correlated into ranked *hypotheses*, each with a confidence, the evidence it rests on, and what a technician would tell you to do. "Probably a driver" is not a diagnosis; "the NVIDIA package installed three days ago, and the display driver has reset six times since" is.

**A Timeline tab puts changes and faults on one date axis.** Windows keeps its own stability score, and the day it fell is a *measured* answer to "when did this PC get worse" — one that does not depend on anyone remembering. Changes are correlated against that date, or against what you said, whichever is more authoritative. The point of the correlation is that it can refuse: a change that landed *after* the trouble began is never a suspect, and when eight things were installed in the same week the nearest one is a coincidence, so nothing is singled out and the confidence falls to say so. Recency dressed up with a timestamp is still recency.

**4. It refuses the wrong repair.** When the evidence makes a normally-sensible fix dangerous, that fix is withheld *and named*, with the reason. A drive reporting itself unhealthy withholds chkdsk and defragmentation — both rewrite the disk heavily, which is how a failing drive is pushed over the edge, and the targeted file-system repair is withheld on exactly the same grounds, because being precise does not make it gentle. Suspected ransomware withholds every cleanup task, because they destroy evidence and any chance of recovery.

**5. It can act on the exact culprit.** Beyond the 94 general tasks, Guided Fix carries **43 targeted repairs** that act on the object it identified rather than on a whole category — and every fault the full check can report has one, or an explicit statement that it cannot be fixed from software.

It can roll back *that* driver package, uninstall *that* KB, disable *that* startup entry, re-enable *that* disabled service, run *that* failing maintenance task, restart *that* adapter, empty the Recycle Bin on *the drive that is actually full*. It can turn User Account Control back on, turn a named firewall profile back on, turn Defender's real-time protection back on and finish the removal it abandoned, strip out the policies and disabled services that stop Windows Update, correct the clock, ask the router for an address again, repair a file system online before resorting to a boot-time check, switch a Power-saver desktop back to Balanced, turn System Protection back on — and point an account that was handed a temporary profile back at its real one, which is the difference between a user's files looking deleted and being there.

It can also remove the setting that forces Safe Mode, make "Shut down" really shut down, stop scheduled tasks waking the PC at night, turn TRIM back on and retrim the drive, resume suspended encryption, reset a network stack that routes through a missing file, put a mangled packet size back to standard, point Windows Update back at Microsoft and clear the stuck downloads, re-register *that* damaged Store app, bring back a desktop whose Explorer has stopped, restart the audio stack in dependency order, start OneDrive so redirected folders sync again, put the standard Windows folders back on a broken PATH without touching anything else, and remove one named policy that is switching a feature off — while refusing to remove a registry value it was not built to know about.

**When one step answers two findings, it is only run once — and says so.** Deduplicating the plan is right; crediting the step to whichever rule spoke first is not, because the other diagnosis then appears on screen with nothing underneath it. The shared step carries every finding it covers, verifies against all of them, and clears all of them together.

Reversible actions record exactly what they overwrote — including the difference between a setting that was zero and one that was never there — and the Safety Journal can put them back individually. Where nothing can honestly be reversed (removing malware, correcting a clock) the action says so rather than offering an undo that would harm you. Where nothing can honestly be repaired — a drive wearing out, failing memory, a swollen battery — it reports the measurement and says plainly that this is hardware.

**6. It stops as soon as it is fixed — but only for that fault.** Repairs run one at a time. After each step the handful of checks that step targeted are re-measured, and if they come back healthy the rest of that fault's steps are skipped — so a DNS flush that solves the problem does not drag you through a 45-minute component repair. In a full check the plan is a list of unrelated faults, so a resolved clock ends the clock's steps and the printer still gets its turn.

**7. It verifies, and it can be handed over.** After the run the full checks repeat and report whether the measured condition was resolved, improved, unchanged, or worsened. **Save report** produces a self-contained HTML case file: what was reported, what was measured, what it was judged to be, what was done, and what was deliberately not done.

Guided profiles cover performance, storage, network and Wi-Fi, Windows Update, crashes and BSODs, security, battery, audio, printing, Bluetooth, Store apps, clock and certificates, browsers, Start/Search/taskbar problems, and general PC health. Every complaint gets its area's standard first steps even when nothing measures badly — and says so honestly rather than inventing a fault.

Guided Fix never treats a task merely returning as proof the problem was solved.

### Safety Journal and exact rollback

Every run from the WinMend interface gets a durable local record containing:

- The tasks planned and completed, their duration, and their outcome
- The problem description and read-only diagnostic summary for Guided Fix sessions
- Whether a session restore point was requested and successfully created
- The exact restore-point number when Windows exposes it
- Before/after verification results
- Interrupted-session recovery after a reboot, crash, or forced exit

For a run containing System Restore-compatible changes, WinMend creates one clearly named session checkpoint before changes begin. The journal can launch an exact rollback after a separate confirmation.

The journal is stored locally at `%APPDATA%\WinMend\safety_journal.json`. Command output, passwords, and discovered file paths are deliberately excluded.

### No timeout kills

Every task in v1.x ran under a watchdog that reported long-but-successful scans as failures. That watchdog is gone. Tasks now stream live output, offer **Cancel**, and show an advisory notice if a task looks stalled — but WinMend never terminates your SFC or CHKDSK run on your behalf.

### New pages in 3.6

| Page | What it adds |
|---|---|
| **Dashboard** | This PC at a glance — hardware, OS, disks, network |
| **Storage** | The Storage Analyzer, now a full page instead of a separate window, with a duplicate finder |
| **Startup** | Per-app startup control with real, measured boot impact |
| **Speed Test** | Download/upload/latency plus bufferbloat grading, Wi-Fi bottleneck detection, and an exportable ISP evidence report |
| **Install Apps** | The 392-app catalogue with already-installed detection and batch installs |
| **Windows Settings** | 27 reversible registry switches, each read live from your registry |

</details>

<details>
<summary><strong>v1.7 — AV hardening and dependency cleanup</strong></summary>

### AV hardening & false positive reduction
- Replaced PowerShell `ExecutionPolicy Bypass` with `RemoteSigned` across the entire application
- Replaced the raw `CREATE_NO_WINDOW` hex constant with the standard `subprocess.STARTUPINFO` Windows API approach
- Added a folder (`onedir`) build mode to sidestep heuristics aimed at single packed binaries

### Debloat system rewrite
- Removed the remote Win11Debloat script fetch (`debloat.raphi.re`) entirely
- **Standard Debloat:** fully embedded locally. Silently removes 91 pre-installed bloatware apps, no extra tweaks or tracking changes
- **Extreme Debloat:** embedded locally. Removes 139 apps including OEM bloatware (HP, Lenovo, Dell) and heavily integrated Windows apps

### External dependency cleanup
- Removed the O&O ShutUp10 external download
- Hardened the Chris Titus Tech Tool path: downloads to a local temp file, computes SHA256, sanity-checks, prompts, then executes locally
- Gated Wi-Fi password export behind typing the phrase `EXPORT WIFI PASSWORDS`

</details>

<details>
<summary><strong>v1.5 — Rebrand, activation, holographic theme</strong></summary>

- Application rebranded from **Windows System Cleaner** to **WinMend**
- New task: **Activate Windows / Change Product Key** — installs the key, activates, and verifies expiry via `slmgr`
- Introduced the Holographic theme (deep cosmic navy `#030611`, cyan `#7FE4FF`, emerald admin indicator) — replaced in 3.0 by the light/dark Fluent theme
- Expanded the bundled font library — removed entirely in 3.0 in favour of the Windows system font

</details>

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Antivirus False Positive Notice

> [!WARNING]
> **WinMend may be flagged as malware or a potentially unwanted program (PUP) by antivirus software. This is a known false positive.**

### Why does this happen?

WinMend is a legitimate Windows maintenance tool. Antivirus engines use behavioral heuristics — they flag *what a program does*, not *what it intends to do*. WinMend performs many of the same low-level operations malware uses, by design:

| Operation | Why WinMend does it | Why AV flags it |
|---|---|---|
| Registry modification | Windows Settings switches, startup entries, performance tweaks | Malware modifies the registry for persistence |
| Mass file deletion | Remove temp files, browser cache, bloatware | Ransomware deletes or encrypts files |
| PowerShell execution | Run system repair and diagnostic commands | Malware uses PowerShell for execution |
| UAC elevation request | Admin rights are required for system-level tasks | Privilege escalation is a malware technique |
| Removing AppX packages | Uninstall bloatware via `Remove-AppxPackage` | Malware may remove security software |
| Download & run tools | Sysinternals, BlueScreenView, WinDbg, Chris Titus Utility | Classic trojan dropper pattern |
| PyInstaller packaging | Single-file executable distribution | Many malware samples use PyInstaller |

### Known detections (false positives)

These vendors have flagged WinMend. These are **incorrect detections**:

| Vendor | Detection Name |
|---|---|
| Microsoft Defender | `Trojan:Win32/Wacatac.C!ml` |
| CrowdStrike Falcon | `Win/malicious_confidence_90% (D)` |
| Elastic | Malicious (moderate confidence) |
| Arctic Wolf | Unsafe |
| Bkav Pro | `W64.AIDetectMalware` |
| SecureAge | Malicious |

> These are ML/heuristic classifiers reacting to system-level behavior — not actual malicious code.

### What has been done to reduce detections

- `ExecutionPolicy Bypass` replaced with `RemoteSigned` throughout
- Raw `CREATE_NO_WINDOW` hex flag (`0x08000000`) replaced with the standard `subprocess.STARTUPINFO` Windows API approach
- UPX compression disabled in the PyInstaller build
- An `onedir` build mode available for distributions that trip single-binary heuristics
- All debloat functionality embedded locally — no remote script execution
- User confirmation shown before any external tool is downloaded, with a SHA256 computed for the Chris Titus utility
- No telemetry, no data collection, no remote connections except user-initiated tool downloads and the speed test you start yourself

### How to resolve the false positive

**Option 1 — Add an exclusion in your AV software**

Add `WinMend.exe` or its folder to your antivirus exclusion list. Refer to your vendor's documentation.

**Option 2 — Submit a false positive report**

Most vendors accept submissions. Provide:
- The `WinMend.exe` file
- Its SHA256 hash (`certutil -hashfile WinMend.exe SHA256`)
- A brief description: *"WinMend is an open-source Windows maintenance tool. Source available at [GitHub URL]. This detection is a false positive triggered by legitimate system maintenance operations."*

**Common submission portals:**
- Microsoft: [Microsoft Security Intelligence](https://www.microsoft.com/en-us/wdsi/filesubmission)
- CrowdStrike: contact via your Falcon console
- Elastic: [Elastic false positive form](https://discuss.elastic.co/c/security/)

**Option 3 — Build from source**

Building yourself gives full transparency and a unique binary hash less likely to carry prior detections. See [Building from Source](#building-from-source).

### Source code transparency

WinMend is fully open source. Every operation is visible in the `winmend/` package: maintenance handlers in `features/`, diagnostic collectors and targeted repairs in `diagnostics/`, and the journal in `safety/`. There are no obfuscated commands, no encoded payloads, no network beaconing, and no data exfiltration. If you or your security team want to audit the code before running it, the full source is in this repository.

---

## Disclaimer

WinMend provides powerful, low-level access to Windows system components. While every effort has been made to ensure safe operation:

- Always **back up important data** before running disk repairs, system file operations, or large-scale deletions
- Use **Create Restore Point (Guardrail)**, or let WinMend create its own session checkpoint, before batch operations
- Some tasks (CHKDSK, SFC, DISM, full-drive analysis) take a long time depending on drive size and system state. WinMend will not cut them short — let them finish
- **Debloat Windows Extreme** and **Remove Windows.old** remove things that cannot be easily restored — read the warnings before using them
- The developer is not responsible for data loss or system instability resulting from use of this software

**Use at your own risk.**

---

<div align="center">

Made with care for the Windows community.

[![Support on Buy Me a Coffee](https://img.shields.io/badge/Support-Buy%20Me%20a%20Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/onlycyber)

</div>
