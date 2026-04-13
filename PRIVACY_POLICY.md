# Privacy Policy

**Application:** WinMend  
**Version:** 1.5  
**Last Updated:** 2026-04-13

---

## Overview

WinMend is a local-only Windows system maintenance and diagnostic toolkit. It does **not** collect, transmit, or share any user data with external servers. All operations are performed entirely on your local machine.

---

## Data Collection

**WinMend does not collect, transmit, or sell any personal data.**

There are no analytics, telemetry, crash reporting, or phone-home mechanisms in this application. No data is ever sent to the developer, third parties, or any remote server.

---

## Local Data Storage

WinMend stores minimal preference data locally on your machine:

| File | Location | Contents | Purpose |
|---|---|---|---|
| `font_size_pref.json` | `%APPDATA%\WinMend\` | Font size factor (number) | Remembers your UI scaling preference |
| `theme_pref.json` | `%APPDATA%\WinMend\` | Theme name (string) | Remembers your color scheme preference |

These files contain **no personally identifiable information (PII)**. They can be deleted at any time without affecting application functionality.

---

## PC Report Generation

When you use the **Generate PC Report** feature, WinMend collects a comprehensive snapshot of your system for diagnostic purposes. This report is saved **locally only** as `PC_Report.html` and is never transmitted externally.

The report may include:

- Computer name and OS version
- CPU, GPU, RAM, and storage hardware details
- Installed applications and versions
- Network adapter configuration and IP addresses
- Running processes and services
- Startup programs and scheduled tasks
- Windows Defender and firewall status
- User accounts on the system
- Environment variables
- Battery and thermal information
- Windows Update status

> **Important:** The PC Report contains sensitive system information. Exercise caution when sharing this file, as it may include usernames, network configuration, environment variables (which could contain API keys or tokens), and running process details.

---

## Wi-Fi Password Export

The **Export Wi-Fi Passwords** feature extracts saved Wi-Fi network names and passwords from Windows and saves them to a plaintext file (`WiFi_Passwords_Export.txt`) on your Desktop.

- This feature requires explicit user confirmation before execution
- The exported file contains **plaintext credentials**
- The file is stored locally only and is never transmitted
- You are responsible for securing or deleting this file after use

---

## Network Activity

WinMend makes **no outbound connections** for data collection or telemetry. The only network activity occurs when you explicitly initiate the download of external tools:

| Tool | Source | When Downloaded |
|---|---|---|
| O&O ShutUp10 | `dl5.oo-software.com` | User clicks "O&O ShutUp10++" |
| Win11Debloat | `debloat.raphi.re` | User clicks "Debloat Windows" |
| NirSoft BlueScreenView | `nirsoft.net` | User clicks "BSOD Analyzer" |
| Sysinternals Autoruns | `live.sysinternals.com` | User clicks "Autoruns" |
| Sysinternals Process Explorer | `live.sysinternals.com` | User clicks "Process Explorer" |
| Chris Titus WinUtil | `christitus.com` | User clicks "Chris Titus Utility" |

These are all well-known, trusted system utilities. No user data is sent during these downloads.

---

## Windows System Commands

Many WinMend tasks execute built-in Windows commands and PowerShell scripts (e.g., `sfc /scannow`, `DISM`, `chkdsk`, `netsh`, `winget`). These commands interact with your local system only and are the same commands available through the Windows command prompt.

---

## Registry Access

WinMend reads and writes Windows Registry keys for specific system optimization tasks (e.g., disabling fast startup, configuring Edge performance settings, managing Storage Sense). All registry modifications are to well-documented system settings and require explicit user initiation.

---

## Debug Output

WinMend contains a small number of `print()` statements for developer diagnostics. These output to the console (stdout) only when the application is launched from a terminal. They contain no sensitive or personal information and do not write to any log files.

---

## Third-Party Services

WinMend does **not** integrate with any third-party analytics, telemetry, or crash reporting services. There is no Sentry, Google Analytics, Mixpanel, Datadog, or any similar service present in the application.

---

## Children's Privacy

WinMend does not knowingly collect any data from anyone, including children under 13. Since no data is collected or transmitted, COPPA compliance concerns do not apply.

---

## Data Retention

- **Preference files** persist until manually deleted or the application is uninstalled
- **PC Reports** persist as local HTML files until you delete them
- **Wi-Fi exports** persist as local text files until you delete them
- No data is retained on any external server

---

## Open Source Verification

WinMend is open source under the MIT License. The complete source code is available for review at [github.com/CyberBigfoot/WinMend](https://github.com/CyberBigfoot/WinMend). You can verify every claim in this privacy policy by inspecting the source code directly.

---

## Changes to This Policy

Any changes to this privacy policy will be reflected in this document and committed to the repository with a clear changelog.

---

## Contact

For questions or concerns about this privacy policy, please open an issue on the [GitHub repository](https://github.com/CyberBigfoot/WinMend/issues).
