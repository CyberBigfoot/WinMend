<div align="center">

# WinMend

### A professional all-in-one Windows maintenance, repair, and diagnostic toolkit

[![Version](https://img.shields.io/badge/Version-1.5-0078D4?style=for-the-badge)](https://github.com/GrantEawood/WinMend/releases)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D4?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/GrantEawood/WinMend)
[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Support](https://img.shields.io/badge/Support-Buy%20Me%20a%20Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/onlycyber)

</div>

---

## Overview

**WinMend** is a feature-rich desktop application built for IT professionals, power users, and everyday users who need a single, reliable tool to maintain, repair, and optimize their Windows machines.

From one-click junk file removal to advanced BSOD analysis, network stack remediation, Windows activation, and a 350+ app installer — WinMend brings everything under one polished, holographic dark-themed dashboard without ever needing to open a command prompt.

> **Requires Administrator privileges** for full functionality. The standalone `.exe` will automatically prompt for elevation via UAC.

---

## Screenshots

<img width="1368" height="720" alt="Screenshot 2026-03-23 134144" src="https://github.com/user-attachments/assets/89f3e0d2-8f59-4afd-a3ad-774566d81183" />

<img width="1331" height="676" alt="Screenshot 2026-03-23 134236" src="https://github.com/user-attachments/assets/db48eff0-f472-49e8-a199-a70c13c3e730" />

<img width="1169" height="548" alt="Screenshot 2026-03-23 134505" src="https://github.com/user-attachments/assets/16bc041c-bf4b-446c-8450-3d4df5a76ce6" />

---

## Table of Contents

- [What's New in v1.5](#whats-new-in-v15)
- [Features](#features)
  - [Smart Fix Search](#smart-fix-search)
  - [Core System Tasks](#core-system-tasks)
  - [Additional Tasks](#additional-tasks)
  - [App Settings](#app-settings)
  - [Storage Analyzer](#storage-analyzer)
  - [App Installer](#app-installer)
- [UI & Design](#ui--design)
- [Installation](#installation)
- [Building from Source](#building-from-source)
- [Usage Guide](#usage-guide)
- [Security & Safety](#security--safety)
- [Requirements](#requirements)
- [License](#license)
- [Antivirus False Positive Notice](#antivirus-false-positive-notice)
- [Disclaimer](#disclaimer)

---

## What's New in v1.5

<details>
<summary><strong>Click to expand v1.5 changelog</strong></summary>

### Rebranding
- Application fully rebranded from **Windows System Cleaner** to **WinMend**
- Executable, window title, and Storage Analyzer all updated to reflect the new name

### New Task — Activate Windows / Change Product Key
- Enter a product key via dialog and WinMend will run the full activation sequence automatically:
  1. Install the product key (`slmgr /ipk`)
  2. Activate against Microsoft's servers (`slmgr /ato`)
  3. Verify activation status and expiry (`slmgr /xpr`)

### Holographic Theme
- Replaced the previous multi-theme system with a single, refined **Holographic** theme:
  - Deep cosmic navy (`#030611`) base
  - Cyan (`#7FE4FF`) accent
  - Emerald (`#19F1A2`) admin indicator
  - Frosted glass panel aesthetic optimized for OLED and HDR displays

### Expanded Font Library
Four new fonts bundled alongside the existing set:

| Font | Usage |
|---|---|
| Chopsic | Title, section headers, buttons |
| Evogria | Task option labels |
| Exo 2 | Activity log body text |
| Codec Cold Bold | UI accents |
| Microsport Bold | Numeric displays |
| TT Lakes Neue | Secondary labels |
| NIKEA | Decorative headings |
| ThisAppeal | Supporting display text |

</details>

---

## Features

### Smart Fix Search

The Smart Fix search bar lets you describe a Windows problem in plain English and instantly receive a prioritised, curated list of the best tools to fix it.

**How it works:**
1. Type your problem — e.g. `my pc is slow`, `no sound`, `blue screen`, `wifi not working`
2. WinMend scores and ranks every available tool against your query in real time
3. Matching tools appear below the search bar with a reason for each recommendation
4. Click **Apply Recommended Tasks** to pre-select them all, then **Run Selected Tasks** to execute

**Supported categories include:**
`Performance` · `Network` · `Security` · `Malware` · `Blue Screen / BSOD` · `Audio` · `Display` · `USB / Peripherals` · `Disk Health` · `Overheating` · `Browser` · `Startup` · `Shell / Explorer` · `Updates` · `Safe Mode / BIOS` · `App Updates` · `General Diagnostics`

---

### Core System Tasks

> Located in the **left column** of the dashboard.

#### Cleanup & Repair
| Task | Description |
|---|---|
| Clean Temporary Files | Removes junk from all system and user temp directories |
| Deep Disk Cleanup | Automates Windows Disk Cleanup with all categories enabled |
| Repair System (SFC + DISM) | Scans and restores corrupted Windows system files |
| Check Disk (CHKDSK) | Scans the active drive for filesystem errors and bad sectors |
| Defrag & Optimize | Defragments HDDs and issues TRIM commands on SSDs |
| Component Cleanup | Removes superseded Windows Update component store entries |

#### Performance
| Task | Description |
|---|---|
| Windows Performance Adjustments | Disables animations, telemetry, and unnecessary background features |
| Optimize Virtual Memory | Calculates and sets the ideal Page File size based on installed RAM |
| Disable Fast Startup | Forces complete shutdowns to prevent uptime-related corruption |
| Adjust Virtual Memory | Manual Page File configuration tool |

#### Updates
| Task | Description |
|---|---|
| Windows Updates | Triggers a full Windows Update cycle |
| Device & Firmware Updates | Scans and installs driver and firmware updates |
| Update Installed Apps (Winget) | Batch-updates all installed applications via the Windows Package Manager |

---

### Additional Tasks

> Located in the **right column** of the dashboard.

#### Network & Connectivity
| Task | Description |
|---|---|
| Flush DNS | Clears the DNS resolver cache |
| Renew IP Address | Releases and renews all network adapter leases |
| Deep Network Stack Remediation | Full one-click reset — winsock, IP config, DNS, and adapter states |
| Fast DNS Switcher | Switch to Cloudflare (1.1.1.1) or Google (8.8.8.8) DNS instantly |
| Reset Network Adapters | Re-initializes all network adapters |
| Export Wi-Fi Passwords | Exports all saved wireless credentials to a text file |
| View Network Adapter Details | Full `ipconfig /all` output for all adapters |
| Ping Test | Verifies basic internet connectivity |
| Network Diagnostic Bundle | Runs a comprehensive suite of automated network diagnostics |

#### Security & Diagnostics
| Task | Description |
|---|---|
| Windows Defender Scan | Triggers a full Microsoft Defender malware scan |
| MSRT Scan | Runs the Microsoft Malicious Software Removal Tool |
| Smart Malware Remediation | Targeted removal of common persistent and stubborn threats |
| MiniDump Analyzer | Opens BSOD crash dump files using NirSoft BlueScreenView |
| BSOD Triage | Collects and organizes crash data for in-depth analysis |
| Event Log Viewer | Surfaces critical errors and warnings from Windows Event Log |
| PC Reporter | Generates a detailed HTML report covering hardware, networking, and security |

#### Updates & Drivers
| Task | Description |
|---|---|
| Windows Updates | Full Windows Update trigger |
| Device & Firmware Updates | Driver and firmware scan |
| Install System Drivers | Installs missing or outdated device drivers |
| Windows Update Forensic | Diagnoses stuck, broken, or looping Windows Update components |
| Driver Rollback Center | Reverts recently installed drivers causing instability |

#### Activation
| Task | Description |
|---|---|
| Activate Windows / Change Product Key | Enter a product key to install, activate, and verify Windows licensing in one step |

#### Utilities
| Task | Description |
|---|---|
| Chris Titus Windows Utility | Integrated launcher for the popular WinUtil all-in-one toolkit |
| Debloat Windows | Silently removes 91 pre-installed bloatware apps (no download, no system tweaks) |
| Debloat Windows Extreme | Removes 139 apps including optional, unsafe, and OEM software — use with caution |
| Sysinternals Autoruns | Manage every Windows autostart location in one place |
| Sysinternals Process Explorer | Advanced task manager for identifying rogue processes |
| Storage Analyzer | Launches the built-in professional disk and drive scanner |
| Create AutoPilot CSV | Exports a Windows AutoPilot hardware hash for device enrollment |
| Create Restore Point (Guardrail) | Creates a manual System Restore checkpoint before making changes |

#### Boot & Recovery
| Task | Description |
|---|---|
| Toggle Safe Mode Boot | Configures the system to boot into Safe Mode on next restart |
| Boot to Advanced Options / BIOS | Restarts directly into the Windows Recovery / UEFI firmware menu |

---

### App Settings

| Setting | Description |
|---|---|
| Stop Background Apps | Terminates non-essential background processes to free up resources |
| Disable Startup Apps | Manages the startup application list to speed up boot times |
| Edge Performance Mode | Applies browser-level performance and efficiency optimizations |
| Clear Browser Cache | Wipes cached data across Chrome, Firefox, and Edge |
| Rebuild Icon Cache | Fixes broken or missing desktop, taskbar, and Start Menu icons |

---

### Storage Analyzer

A standalone professional disk analysis window accessible from the Utilities section or the main toolbar.

**Features:**
- **Interactive Directory Tree** — browse your entire drive with expandable folder nodes
- **Detailed File List** — view Name, Size, Allocated Size, File Count, and Folder Count for any selected directory
- **Drive Health Monitoring** — real-time S.M.A.R.T. data:
  - Health status (Healthy / Warning / Critical)
  - Temperature and wearout percentage
  - Performance stats — IOPS and latency
- **Large File Finder** — color-coded size highlights make it easy to spot space hogs
- **Filter Options** — filter by file extension, minimum size, and age
- **Integrated Actions** — open file locations or delete files directly from the analyzer window

---

### App Installer

A high-performance application installer built directly into WinMend.

- **350+ curated applications** across categories:
  - Browsers · Development Tools · Gaming · Multimedia · Communications · Document Software · Security · Utilities
- **Categorized sidebar navigation** for fast browsing
- **Integrated search** to find any app instantly
- **Batch install** — select multiple apps across categories and install them all at once
- **Winget backend** — uses Microsoft's official Windows Package Manager for secure, verified installs

---

## UI & Design

### Holographic Theme

WinMend uses a refined **Holographic** theme — a deep cosmic navy and cyan aesthetic optimized for OLED and HDR displays:

| Element | Color |
|---|---|
| Background | Deep cosmic navy `#030611` |
| Accent | Cyan `#7FE4FF` |
| Admin indicator | Emerald `#19F1A2` |
| Panels | Frosted glass surfaces |

### Font Size

Adjustable via the **Change Font Size** menu to support any monitor resolution or display scaling:
`Small` · `Medium` · `Large` · `Extra Large`

### Layout

The main dashboard uses a **two-column equal-width layout**:
- **Left column** — Core system maintenance, optimization, and update tasks
- **Right column** — Advanced network, security, diagnostic, driver, and utility tasks

A persistent **Activity Log** runs at the bottom of the screen, logging every action in real time with timestamps and color-coded status indicators.

---

## Installation

### Option 1 — Standalone Executable (Recommended)

Download the latest `WinMend.exe` from the [Releases](https://github.com/GrantEawood/WinMend/releases) page.

> Right-click → **Run as Administrator**, or the app will automatically request UAC elevation.

No Python installation or additional dependencies required.

---

### Option 2 — Run from Source

**Prerequisites**
- Windows 10 or Windows 11 (64-bit)
- Python 3.8 or higher

**1. Clone the repository**
```bash
git clone https://github.com/GrantEawood/WinMend.git
cd WinMend
```

**2. Install dependencies**
```bash
pip install wmi requests beautifulsoup4 psutil customtkinter
```

**3. Run as Administrator**
```bash
python WinMend.py
```

---

## Building from Source

### Basic build (single file)
```bash
pyinstaller --onefile --noconsole --icon="icon.ico" WinMend.py
```

### Recommended build with UAC elevation

**Step 1 — Generate the spec file**
```bash
pyinstaller --onefile --noconsole --icon="icon.ico" WinMend.py
```

**Step 2 — Edit `WinMend.spec`**

Find the `EXE(` block and add `uac_admin=True`:
```python
exe = EXE(
    ...
    name='WinMend',
    uac_admin=True,       # Forces UAC elevation prompt on launch
    console=False,
)
```

**Step 3 — Build from the spec**
```bash
pyinstaller WinMend.spec
```

The final executable will be in the `dist/` folder.

> **Antivirus note:** See the [Antivirus False Positive Notice](#antivirus-false-positive-notice) section below for a full explanation of why WinMend may be flagged and how to resolve it.

---

## Usage Guide

### Running your first scan

1. Launch WinMend as Administrator
2. The dashboard will open with all tasks deselected
3. Tick the tasks you want to run from either column, or use the **Smart Fix Search** to get automatic recommendations
4. Click **Run Selected Tasks**
5. Monitor progress in the **Activity Log**
6. If any selected task requires a reboot, a banner will appear and you will be prompted automatically

### Smart Fix Search — Quick Start

| You type | WinMend recommends |
|---|---|
| `my pc is slow` | Clean Temp, Disk Cleanup, Virtual Memory, Startup Apps, Defrag |
| `no sound` | Driver Install, Device Firmware, Service Repair, Event Log |
| `wifi not working` | Flush DNS, Deep Network Reset, DNS Switch, Network Diagnostics |
| `blue screen` | MiniDump Analyzer, BSOD Triage, Driver Rollback, Repair System |
| `100% disk` | CHKDSK, Defrag & Optimize, Storage Sense, Disk Cleanup |
| `virus` | Defender Scan, MSRT, Smart Malware Remediation, Autoruns |
| `not activated` | Activate Windows / Change Product Key |

### Reboot-required tasks

The following tasks will display a **"A Reboot Will Be Required"** notice when selected:
`Repair System` · `Windows Updates` · `Device & Firmware Updates` · `Check Disk` · `Reset Windows Update` · `Toggle Safe Mode` · `Boot to Advanced Options`

---

## Security & Safety

- **Administrator required** — system-level tasks require elevated permissions. UAC elevation is requested automatically in the `.exe` build
- **Input sanitization** — all commands are sanitized to prevent injection or path traversal attacks
- **Confirmation prompts** — destructive or irreversible actions (disk repair, network reset, debloat) require explicit user confirmation before executing
- **Restore Point Guardrail** — run the **Create Restore Point** task before any batch operation to create a recovery fallback
- **No data collection** — WinMend does not collect, transmit, or store any personal or system data

---

## Requirements

| Requirement | Minimum |
|---|---|
| Operating System | Windows 10 (1903+) or Windows 11 |
| Architecture | 64-bit |
| Permissions | Administrator |
| Python (source only) | 3.8+ |
| RAM | 256 MB |
| Disk Space | 50 MB |

**Python dependencies (source only):**
```
wmi
requests
beautifulsoup4
psutil
customtkinter
```

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Antivirus False Positive Notice

> [!WARNING]
> **WinMend may be flagged as malware or a potentially unwanted program (PUP) by antivirus software. This is a known false positive.**

### Why does this happen?

WinMend is a legitimate Windows maintenance tool. However, antivirus engines use behavioral heuristics — they flag *what a program does*, not *what it intends to do*. WinMend performs many of the same low-level operations that malware uses, by design:

| Operation | Why WinMend does it | Why AV flags it |
|---|---|---|
| Registry modification | Disable gaming overlays, manage startup items, apply performance tweaks | Malware modifies registry for persistence |
| Mass file deletion | Remove temp files, browser cache, bloatware | Ransomware deletes or encrypts files |
| PowerShell execution | Run system repair and diagnostic commands | Malware uses PowerShell for execution |
| UAC elevation request | Requires admin rights for system-level tasks | Privilege escalation is a malware technique |
| Removing AppX packages | Uninstall bloatware via `Remove-AppxPackage` | Malware may remove security software |
| Download & run tools | Sysinternals, BlueScreenView, Chris Titus Utility | Classic trojan dropper pattern |
| PyInstaller packaging | Single-file executable distribution | Many malware samples use PyInstaller |

### Known detections (false positives)

The following vendors have flagged WinMend as a false positive. These are **incorrect detections**:

| Vendor | Detection Name |
|---|---|
| Microsoft Defender | `Trojan:Win32/Wacatac.C!ml` |
| CrowdStrike Falcon | `Win/malicious_confidence_90% (D)` |
| Elastic | Malicious (moderate confidence) |
| Arctic Wolf | Unsafe |
| Bkav Pro | `W64.AIDetectMalware` |
| SecureAge | Malicious |

> These detections are driven by ML/heuristic classifiers reacting to system-level behavior — not actual malicious code.

### What has been done to reduce detections

- `ExecutionPolicy Bypass` replaced with `RemoteSigned` throughout
- Raw `CREATE_NO_WINDOW` hex flag (`0x08000000`) replaced with the standard `subprocess.STARTUPINFO` Windows API approach
- UPX compression disabled in PyInstaller build
- All debloat functionality is embedded locally — no remote script execution
- User confirmation dialogs shown before any external tool is downloaded
- No telemetry, no data collection, no remote connections except user-initiated tool downloads

### How to resolve the false positive

**Option 1 — Add an exclusion in your AV software**

Add the `WinMend.exe` file or its folder to your antivirus exclusion/whitelist list. Refer to your AV vendor's documentation for steps.

**Option 2 — Submit a false positive report**

Most vendors accept false positive submissions. Use your AV vendor's portal and provide:
- The `WinMend.exe` file
- The SHA256 hash of the file (`certutil -hashfile WinMend.exe SHA256`)
- A brief description: *"WinMend is an open-source Windows maintenance tool. Source available at [GitHub URL]. This detection is a false positive triggered by legitimate system maintenance operations."*

**Common submission portals:**
- Microsoft: [Microsoft Security Intelligence](https://www.microsoft.com/en-us/wdsi/filesubmission)
- CrowdStrike: Contact via your Falcon console
- Elastic: [Elastic false positive form](https://discuss.elastic.co/c/security/)

**Option 3 — Build from source**

Building from source yourself gives you full transparency and a unique binary hash less likely to carry prior detections. See [Building from Source](#building-from-source).

### Source code transparency

WinMend is fully open source. Every operation the tool performs is visible in `WinMend.py`. There are no obfuscated commands, no encoded payloads, no network beaconing, and no data exfiltration. If you or your security team want to audit the code before running it, the full source is available in this repository.

---

## Disclaimer

WinMend provides powerful, low-level access to Windows system components. While every effort has been made to ensure safe operation:

- Always **back up important data** before running disk repairs, system file operations, or large-scale deletions
- Use the **Create Restore Point (Guardrail)** task before running batch operations
- Some tasks (CHKDSK, SFC, DISM) may take a significant amount of time depending on drive size and system state
- **Debloat Windows Extreme** removes system components that cannot be easily reinstalled — read the tooltip carefully before using it
- The developer is not responsible for data loss or system instability resulting from use of this software

**Use at your own risk.**

---

<div align="center">

Made with care for the Windows community.

[![Support on Buy Me a Coffee](https://img.shields.io/badge/Support-Buy%20Me%20a%20Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/onlycyber)

</div>
