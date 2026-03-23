<div align="center">

# Windows System Cleaner

### A professional all-in-one Windows maintenance, repair, and diagnostic toolkit

[![Version](https://img.shields.io/badge/Version-1.4-0078D4?style=for-the-badge)](https://github.com/GrantEawood/Windows-System-Cleaner/releases)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D4?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/GrantEawood/Windows-System-Cleaner)
[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Support](https://img.shields.io/badge/Support-Buy%20Me%20a%20Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/onlycyber)

</div>

---

## Overview

**Windows System Cleaner (WSC)** is a feature-rich desktop application built for IT professionals, power users, and everyday users who need a single, reliable tool to maintain, repair, and optimize their Windows machines.

From one-click junk file removal to advanced BSOD analysis, network stack remediation, and a 350+ app installer — WSC brings everything under one polished, dark-themed dashboard without ever needing to open a command prompt.

> **Requires Administrator privileges** for full functionality. The standalone `.exe` will automatically prompt for elevation via UAC.

---

## Screenshots

<img width="1368" height="720" alt="Screenshot 2026-03-23 134144" src="https://github.com/user-attachments/assets/89f3e0d2-8f59-4afd-a3ad-774566d81183" />

<img width="1331" height="676" alt="Screenshot 2026-03-23 134236" src="https://github.com/user-attachments/assets/db48eff0-f472-49e8-a199-a70c13c3e730" />

<img width="1169" height="548" alt="Screenshot 2026-03-23 134505" src="https://github.com/user-attachments/assets/16bc041c-bf4b-446c-8450-3d4df5a76ce6" />


---

## Table of Contents

- [What's New in v1.4](#whats-new-in-v14)
- [Features](#features)
  - [Smart Fix Search](#smart-fix-search)
  - [Core System Tasks](#core-system-tasks)
  - [Additional Tasks](#additional-tasks)
  - [App Settings](#app-settings)
  - [Storage Analyzer](#storage-analyzer)
  - [App Installer](#app-installer)
- [UI & Customization](#ui--customization)
- [Installation](#installation)
- [Building from Source](#building-from-source)
- [Usage Guide](#usage-guide)
- [Security & Safety](#security--safety)
- [Requirements](#requirements)
- [License](#license)
- [Disclaimer](#disclaimer)

---

## What's New in v1.4

<details>
<summary><strong>Click to expand v1.4 changelog</strong></summary>

### Rebranding
- Main app header now displays the shorthand **WSC**

### Smart Search — Major Expansion
Added 10 new diagnostic categories so users can describe any problem in plain language and receive instant, targeted tool recommendations:

| New Category | Example Queries |
|---|---|
| Audio Repair | "no sound", "mic broken", "hdmi no audio" |
| High CPU / RAM | "100% cpu", "memory leak", "task manager" |
| Display & Graphics | "screen flickering", "black screen", "gpu issue" |
| USB & Peripherals | "usb not recognized", "keyboard not working" |
| Browser Performance | "chrome slow", "browser crashing" |
| Overheating | "fan loud", "laptop hot", "thermal issue" |
| Shell & Explorer | "taskbar frozen", "start menu broken" |
| Disk Health | "100% disk", "bad sector", "ssd failing" |
| App & Software Updates | "outdated apps", "winget" |
| Safe Mode / BIOS | "boot to bios", "safe mode", "startup repair" |

- 13 new single-word token entries for ultra-short searches
- 4 missing display name entries added to the task map

### Custom Typography
| Area | Font |
|---|---|
| Title, section headers, buttons | Chopsic |
| Task option labels | Evogria |
| Activity log body text | Exo 2 |

### UI Stability Fixes
- **Right-column flash eliminated** — indicator dot font size was changing between states (10pt ↔ 11pt), causing row height changes that triggered a full scroll canvas repaint. Both states are now locked to 10pt
- **Double-repaint eliminated** — click handler now writes to the LED cache immediately so the background refresh skips already-updated rows
- **Reboot banner orange box fixed** — banner is now inside a fixed-height wrapper (`pack_propagate=False`) so the column layout never reflows when it appears or disappears
- **Task highlight reset on completion** — all selected rows now correctly return to their unlit state after tasks finish running

</details>

---

## Features

### Smart Fix Search

The Smart Fix search bar lets you describe a Windows problem in plain English and instantly receive a prioritised, curated list of the best tools to fix it.

**How it works:**
1. Type your problem — e.g. `my pc is slow`, `no sound`, `blue screen`, `wifi not working`
2. WSC scores and ranks every available tool against your query in real time
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

#### Utilities
| Task | Description |
|---|---|
| Chris Titus Windows Utility | Integrated launcher for the popular WinUtil all-in-one toolkit |
| Debloat Windows | Removes pre-installed bloatware and telemetry services |
| O&O ShutUp10 | Launches the O&O ShutUp10++ privacy hardening tool |
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

A high-performance application installer built directly into WSC.

- **350+ curated applications** across categories:
  - Browsers · Development Tools · Gaming · Multimedia · Communications · Document Software · Security · Utilities
- **Categorized sidebar navigation** for fast browsing
- **Integrated search** to find any app instantly
- **Batch install** — select multiple apps across categories and install them all at once
- **Winget backend** — uses Microsoft's official Windows Package Manager for secure, verified installs

---

## UI & Customization

### Themes

Switch instantly via **View > Theme**:

| Theme | Description |
|---|---|
| Dark | Default — deep navy and charcoal tones |
| Light | Clean white and light grey |
| Cyberpunk | Neon cyan and magenta on near-black |
| Ocean | Blue and teal gradients |
| Sunset | Orange and purple warm tones |
| Forest | Muted greens on dark background |

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

Download the latest `Windows-System-Cleaner.exe` from the [Releases](https://github.com/GrantEawood/Windows-System-Cleaner/releases) page.

> Right-click → **Run as Administrator**, or the app will automatically request UAC elevation.

No Python installation or additional dependencies required.

---

### Option 2 — Run from Source

**Prerequisites**
- Windows 10 or Windows 11 (64-bit)
- Python 3.8 or higher

**1. Clone the repository**
```bash
git clone https://github.com/GrantEawood/Windows-System-Cleaner.git
cd Windows-System-Cleaner
```

**2. Install dependencies**
```bash
pip install wmi requests beautifulsoup4 psutil customtkinter
```

**3. Run as Administrator**
```bash
python "Windows System Cleaner.py"
```

---

## Building from Source

### Basic build (single file)
```bash
pyinstaller --onefile --noconsole --icon="icon.ico" "Windows System Cleaner.py"
```

### Recommended build with UAC elevation

**Step 1 — Generate the spec file**
```bash
pyinstaller --onefile --noconsole --icon="icon.ico" "Windows System Cleaner.py"
```

**Step 2 — Edit `Windows System Cleaner.spec`**

Find the `EXE(` block and add `uac_admin=True`:
```python
exe = EXE(
    ...
    name='Windows System Cleaner',
    uac_admin=True,       # Forces UAC elevation prompt on launch
    console=False,
)
```

**Step 3 — Build from the spec**
```bash
pyinstaller "Windows System Cleaner.spec"
```

The final executable will be in the `dist/` folder.

> **Antivirus note:** PyInstaller-built executables are commonly flagged by antivirus software as a false positive. This is expected behavior. You can whitelist the file or submit it to your AV vendor for review.

---

## Usage Guide

### Running your first scan

1. Launch WSC as Administrator
2. The dashboard will open with all tasks deselected
3. Tick the tasks you want to run from either column, or use the **Smart Fix Search** to get automatic recommendations
4. Click **Run Selected Tasks**
5. Monitor progress in the **Activity Log**
6. If any selected task requires a reboot, a banner will appear and you will be prompted automatically

### Smart Fix Search — Quick Start

| You type | WSC recommends |
|---|---|
| `my pc is slow` | Clean Temp, Disk Cleanup, Virtual Memory, Startup Apps, Defrag |
| `no sound` | Driver Install, Device Firmware, Service Repair, Event Log |
| `wifi not working` | Flush DNS, Deep Network Reset, DNS Switch, Network Diagnostics |
| `blue screen` | MiniDump Analyzer, BSOD Triage, Driver Rollback, Repair System |
| `100% disk` | CHKDSK, Defrag & Optimize, Storage Sense, Disk Cleanup |
| `virus` | Defender Scan, MSRT, Smart Malware Remediation, Autoruns |

### Reboot-required tasks

The following tasks will display a **"A Reboot Will Be Required"** notice when selected:
`Repair System` · `Windows Updates` · `Device & Firmware Updates` · `Check Disk` · `Reset Windows Update` · `Toggle Safe Mode` · `Boot to Advanced Options`

---

## Security & Safety

- **Administrator required** — system-level tasks require elevated permissions. UAC elevation is requested automatically in the `.exe` build
- **Input sanitization** — all commands are sanitized to prevent injection or path traversal attacks
- **Confirmation prompts** — destructive or irreversible actions (disk repair, network reset, debloat) require explicit user confirmation before executing
- **Restore Point Guardrail** — run the **Create Restore Point** task before any batch operation to create a recovery fallback
- **No data collection** — WSC does not collect, transmit, or store any personal or system data

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

## Disclaimer

Windows System Cleaner provides powerful, low-level access to Windows system components. While every effort has been made to ensure safe operation:

- Always **back up important data** before running disk repairs, system file operations, or large-scale deletions
- Use the **Create Restore Point (Guardrail)** task before running batch operations
- Some tasks (CHKDSK, SFC, DISM) may take a significant amount of time depending on drive size and system state
- The developer is not responsible for data loss or system instability resulting from use of this software

**Use at your own risk.**

---

<div align="center">

Made with care for the Windows community.

[![Support on Buy Me a Coffee](https://img.shields.io/badge/Support-Buy%20Me%20a%20Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/onlycyber)

</div>
