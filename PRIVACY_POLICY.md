# Privacy Policy

**Application:** WinMend  
**Version:** 2.0  
**Last Updated:** 2026-07-16

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
| `safety_journal.json` | `%APPDATA%\WinMend\` | Problem descriptions, task names, outcomes, timings, restore-point metadata, and verification summaries | Provides local history and session rollback |

The preference files contain no personally identifiable information. The Safety Journal includes the problem description that you type, so avoid entering passwords, product keys, or other secrets. WinMend deliberately excludes command output, exported passwords, and discovered file paths from the journal. These files stay on the local PC and can be deleted at any time without affecting WinMend's maintenance functions.

The journal retains the newest 200 sessions. If its JSON file is damaged, WinMend preserves a timestamped local copy before starting a clean journal.

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

WinMend makes **no outbound connections for data collection, analytics, or telemetry**. Network activity occurs only for a user-requested network diagnostic, update, application installation, or external-tool download.

Guided Fix — including the **Check for issues** full check — makes a small number of short outbound requests, all of them measurements of your own connection. None of them carries any data about your PC:

| Request | Destination | What it measures |
|---|---|---|
| DNS lookup | `www.microsoft.com` | whether name resolution works |
| DNS lookup | `cloudflare.com` | whether a second, unrelated name also resolves, and how long it takes |
| DNS lookup | a made-up name under `.invalid` | whether your resolver is answering for domains that do not exist |
| TCP connect | `1.1.1.1:443` | whether the internet is reachable, and how quickly |
| SNTP query | `time.windows.com`, falling back to `pool.ntp.org` | how far your system clock is from real time |

The three DNS lookups are ordinary name lookups sent to whichever DNS server your PC is already configured to use — the same request your browser makes for any address. The `.invalid` name is reserved by standard to never exist anywhere, so nothing receives it and no server can resolve it honestly; a reply means something in the path is answering for every domain, which is how a hijacked resolver, an ISP search page, or a captive portal is detected.

The SNTP query sends a standard 48-byte time packet containing no identifying information, and is used only to measure clock drift — a clock that is wrong by more than a few minutes silently breaks secure websites, Windows Update, and sign-in. Guided Fix sends no journal, case, or PC-report data anywhere.

Windows' own connectivity verdict is read from the operating system rather than measured again, so checking whether your connection reaches the internet costs no request of WinMend's own.

Guided Fix's **repairs** make no outbound connections of their own either. Some of them start a Windows component that does: correcting the clock asks the Windows Time service to contact `time.windows.com`, unblocking updates lets Windows Update reach Microsoft again, renewing an address contacts your router's DHCP server, and finishing a Defender removal may consult Defender's own cloud service if you have that enabled. In every case the connection is made by Windows using its existing settings, not by WinMend, and carries whatever Windows would normally send.

External tools currently used by explicit tasks include:

| Tool | Source | When Downloaded |
|---|---|---|
| NirSoft BlueScreenView | `nirsoft.net` | User clicks "BSOD Analyzer" |
| Sysinternals Autoruns | `live.sysinternals.com` | User clicks "Autoruns" |
| Sysinternals Process Explorer | `live.sysinternals.com` | User clicks "Process Explorer" |
| Chris Titus WinUtil | `christitus.com` | User clicks "Chris Titus Utility" |
| Microsoft WinDbg | Microsoft Store / WinGet | User clicks "WinDbg Crash Analyzer" |

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
- **Safety Journal entries** retain the newest 200 local sessions; deleting `safety_journal.json` clears the history
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
