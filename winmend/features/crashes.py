"""WinMend features: crashes."""

from __future__ import annotations

from datetime import datetime
from winmend.core.processes import _no_console_startupinfo, launch_visible, wm_run
from winmend.core.prompts import messagebox
from winmend.data.tools import WINDBG_DIRECT_DOWNLOAD_URL, WINDBG_LEARN_URL, WINDBG_WINGET_ID
import os
import re
import shutil
import subprocess
import time
import webbrowser


class CrashesTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    # ==================== UTILITY METHODS ====================





    def run_minidump_analyzer(self):
        """Downloads and extracts NirSoft BlueScreenView, then runs it"""
        task_label = "minidump_analyzer"

        confirmed = messagebox.askyesno(
            "Download Confirmation",
            "MiniDump Analyzer requires downloading BlueScreenView from NirSoft.\n\n"
            "Source: https://www.nirsoft.net/utils/bluescreenview-x64.zip\n"
            "Publisher: NirSoft (nirsoft.net)\n\n"
            "The file will be saved to your TEMP folder and launched.\n\n"
            "Do you want to proceed?"
        )
        if not confirmed:
            self._report_skip(f"PROGRESS:{task_label}:Download cancelled by user.")
            return

        url = "https://www.nirsoft.net/utils/bluescreenview-x64.zip"
        temp_dir = os.environ.get('TEMP', 'C:\\Windows\\Temp')
        zip_path = os.path.join(temp_dir, "bluescreenview-x64.zip")
        extract_dir = os.path.join(temp_dir, "BlueScreenView")
        exe_path = os.path.join(extract_dir, "BlueScreenView.exe")

        self.queue.put(f"PROGRESS:{task_label}:Downloading BlueScreenView from NirSoft...")
        try:
            import zipfile
            self._download(url, zip_path)

            self.queue.put(f"PROGRESS:{task_label}:Extracting BlueScreenView...")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)

            self.queue.put(f"PROGRESS:{task_label}:Launching BlueScreenView...")
            subprocess.Popen([exe_path], creationflags=subprocess.DETACHED_PROCESS)
            self.queue.put(f"PROGRESS:{task_label}:BlueScreenView launched successfully.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{task_label}:Error executing MiniDump Analyzer: {str(e)}")

    def run_windbg_crash_analyzer(self):
        """Install/launch WinDbg and open the paste-based crash analyzer."""
        task_label = "windbg_crash_analyzer"

        def _confirm():
            return messagebox.askyesno(
                "Download Confirmation",
                "WinDbg Crash Analyzer installs or opens Microsoft's WinDbg.\n\n"
                f"Learn page: {WINDBG_LEARN_URL}\n"
                f"Package: {WINDBG_WINGET_ID}\n"
                f"Direct installer: {WINDBG_DIRECT_DOWNLOAD_URL}\n\n"
                "After WinDbg opens, a paste box will appear for copied crash analysis.\n\n"
                "Do you want to proceed?"
            )

        try:
            confirmed = self._call_on_ui_thread(_confirm)
        except Exception:
            confirmed = False

        if not confirmed:
            self._report_skip(f"PROGRESS:{task_label}:Download cancelled by user.")
            return

        self.queue.put(f"PROGRESS:{task_label}:Preparing WinDbg from Microsoft's current debugger page...")
        installed_or_launched = False

        if shutil.which("winget"):
            self.queue.put(f"PROGRESS:{task_label}:Installing/updating WinDbg with winget...")
            rc, timed_out = self._run_live_command(
                [
                    "winget", "install", "--id", WINDBG_WINGET_ID, "--exact",
                    "--accept-package-agreements", "--accept-source-agreements"
                ],
                task_label,
                timeout=900
            )
            if timed_out:
                self.queue.put(f"PROGRESS:{task_label}:WinDbg install timed out. Opening direct installer fallback...")
            elif rc == 0:
                self.queue.put(f"PROGRESS:{task_label}:WinDbg install/update completed.")
                installed_or_launched = True
                time.sleep(2)
            else:
                self.queue.put(f"PROGRESS:{task_label}:winget returned code {rc}; trying to launch or download installer fallback.")
        else:
            self.queue.put(f"PROGRESS:{task_label}:winget was not found. Using Microsoft's direct WinDbg installer.")

        if self._launch_windbg(task_label):
            installed_or_launched = True
        else:
            if not self._download_windbg_appinstaller(task_label):
                self._report_failure(f"PROGRESS:{task_label}:WinDbg could not be launched and its installer could not be opened. The paste analyzer is still available.")

        if installed_or_launched:
            self.queue.put(f"PROGRESS:{task_label}:WinDbg launch requested.")

        self.queue.put(f"PROGRESS:{task_label}:Opening crash debug paste analyzer...")
        self._call_on_ui_thread(self.open_windbg_crash_paste_window)

    def _download_windbg_appinstaller(self, task_label):
        """Download Microsoft's WinDbg appinstaller fallback and open it."""
        try:
            import urllib.request
            temp_dir = os.environ.get('TEMP', 'C:\\Windows\\Temp')
            installer_path = os.path.join(temp_dir, "WinDbg.appinstaller")
            self.queue.put(f"PROGRESS:{task_label}:Downloading WinDbg installer from Microsoft...")
            req = urllib.request.Request(
                WINDBG_DIRECT_DOWNLOAD_URL,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            )
            with urllib.request.urlopen(req, timeout=120) as response, open(installer_path, 'wb') as out_file:
                out_file.write(response.read())
            self.queue.put(f"PROGRESS:{task_label}:Opening installer: {installer_path}")
            os.startfile(installer_path)
            return True
        except Exception as e:
            self.queue.put(f"PROGRESS:{task_label}:Direct WinDbg installer failed: {str(e)}")
            try:
                webbrowser.open(WINDBG_LEARN_URL)
                self.queue.put(f"PROGRESS:{task_label}:Opened Microsoft Learn WinDbg page in your browser.")
            except Exception:
                pass
            return False

    def _launch_windbg(self, task_label):
        """Try the common modern WinDbg launch paths."""
        if shutil.which("windbgx.exe"):
            try:
                launch_visible(["windbgx.exe"], creationflags=subprocess.DETACHED_PROCESS)
                self.queue.put(f"PROGRESS:{task_label}:Started WinDbg using windbgx.exe.")
                return True
            except Exception:
                pass

        if self._windbg_store_package_available():
            try:
                launch_visible(["explorer.exe", r"shell:AppsFolder\Microsoft.WinDbg_8wekyb3d8bbwe!App"],
                               creationflags=subprocess.DETACHED_PROCESS)
                self.queue.put(f"PROGRESS:{task_label}:Started WinDbg from the Start menu app package.")
                return True
            except Exception:
                pass
        return False

    def _windbg_store_package_available(self):
        try:
            result = wm_run(
                [
                    "powershell", "-NoProfile", "-Command",
                    "if (Get-AppxPackage -Name Microsoft.WinDbg -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=20,
                startupinfo=_no_console_startupinfo()
            )
            return result.returncode == 0
        except Exception:
            return False

    def analyze_crash_debug_text(self, text):
        """Heuristically explain common WinDbg/bugcheck output in plain English."""
        raw = text or ""
        if not raw.strip():
            return "I need crash text first. Paste WinDbg !analyze -v output, a BlueScreenView report, or the Event ID 1001 bugcheck message."

        normalized = raw.replace("\r\n", "\n").replace("\r", "\n")
        lower = normalized.lower()

        def first_match(patterns, flags=re.IGNORECASE):
            for pattern in patterns:
                match = re.search(pattern, normalized, flags)
                if match:
                    value = match.group(1).strip()
                    if value:
                        return value
            return ""

        bugcheck_code = first_match([
            r"BUGCHECK_CODE:\s*\(?\s*(0x[0-9a-f]+|[0-9a-f]+)\s*\)?",
            r"BugCheck\s+([0-9a-fx]+)\s*,",
            r"The bugcheck was:\s*\(?\s*(0x[0-9a-f]+|[0-9a-f]+)",
            r"STOP:\s*(0x[0-9a-f]+)",
            r"Bug Check Code\s*:\s*(0x[0-9a-f]+|[0-9a-f]+)",
        ])
        bugcheck_name = first_match([
            r"BUGCHECK_STR:\s*([^\n]+)",
            r"Bug Check String\s*:\s*([^\n]+)",
            r"STOP_CODE:\s*([^\n]+)",
        ])
        probable = first_match([
            r"Probably caused by\s*:\s*([^\n]+)",
            r"Caused By Driver\s*:\s*([^\n]+)",
            r"MODULE_NAME:\s*([^\n]+)",
        ])
        image = first_match([
            r"IMAGE_NAME:\s*([^\n]+)",
            r"Image path:\s*([^\n]+)",
        ])
        process = first_match([r"PROCESS_NAME:\s*([^\n]+)"])
        failure_bucket = first_match([r"FAILURE_BUCKET_ID:\s*([^\n]+)"])
        args = first_match([
            r"BugCheck\s+[0-9a-fx]+\s*,\s*\{([^}]+)\}",
            r"BUGCHECK_P[1-4]:\s*([^\n]+)",
        ])

        code_key = ""
        if bugcheck_code:
            code_key = bugcheck_code.lower().replace("0x", "").lstrip("0") or "0"
            code_key = "0x" + code_key.upper()

        bugcheck_info = {
            "0xA": ("IRQL_NOT_LESS_OR_EQUAL", "A driver or Windows kernel component touched memory at the wrong interrupt level.", "Focus on recently changed drivers, antivirus/VPN/filter software, and RAM stability."),
            "0xD1": ("DRIVER_IRQL_NOT_LESS_OR_EQUAL", "A device driver accessed invalid memory while running too high in the kernel.", "Update or roll back the named driver. Network, storage, USB, and security drivers are common causes."),
            "0x50": ("PAGE_FAULT_IN_NONPAGED_AREA", "Windows tried to read memory that should always exist, but it was invalid.", "Check RAM, storage health, and third-party drivers that appear near the crash."),
            "0x1A": ("MEMORY_MANAGEMENT", "Windows detected memory manager corruption.", "Run Windows Memory Diagnostic or MemTest86, remove overclocks/XMP temporarily, and update chipset/storage drivers."),
            "0x3B": ("SYSTEM_SERVICE_EXCEPTION", "A kernel service crashed while handling a request from user mode.", "Usually a buggy driver, graphics driver, security software, or corrupted system files."),
            "0x7E": ("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "A system thread hit an exception that the driver did not handle.", "The named .sys file is the first suspect. Update/roll back that driver."),
            "0x1E": ("KMODE_EXCEPTION_NOT_HANDLED", "Kernel-mode code threw an unhandled exception.", "Look for the named driver. If only ntoskrnl appears, check recent driver changes and RAM."),
            "0x133": ("DPC_WATCHDOG_VIOLATION", "A driver held the CPU too long at a high interrupt level.", "Storage, chipset, USB, Wi-Fi, Bluetooth, and GPU drivers are common suspects."),
            "0x139": ("KERNEL_SECURITY_CHECK_FAILURE", "Windows detected kernel data structure corruption.", "Common causes are buggy drivers, memory corruption, or security/filter drivers."),
            "0x124": ("WHEA_UNCORRECTABLE_ERROR", "The CPU or hardware reported a machine-check hardware error.", "Check temperatures, BIOS/UEFI, CPU/RAM overclocks, PSU stability, and GPU/PCIe/storage hardware."),
            "0x9C": ("MACHINE_CHECK_EXCEPTION", "The processor reported a hardware-level fault.", "Treat this like a hardware stability problem first: thermals, BIOS, CPU/RAM, power, motherboard."),
            "0x101": ("CLOCK_WATCHDOG_TIMEOUT", "One CPU core stopped responding in time.", "Often CPU instability, BIOS/chipset problems, thermals, or overclock/undervolt settings."),
            "0x116": ("VIDEO_TDR_FAILURE", "The graphics driver/GPU stopped responding and Windows could not recover it.", "Clean-install the GPU driver, check GPU temperature/power, remove GPU overclocks, and test the card."),
            "0x117": ("VIDEO_TDR_TIMEOUT_DETECTED", "The graphics driver/GPU timed out but Windows may have recovered.", "Update or clean-install graphics drivers and check GPU stability."),
            "0x119": ("VIDEO_SCHEDULER_INTERNAL_ERROR", "The Windows graphics scheduler found a serious GPU/driver problem.", "Focus on GPU drivers, DirectX overlays, GPU overclocking, and hardware stability."),
            "0x141": ("VIDEO_ENGINE_TIMEOUT_DETECTED", "A GPU engine stopped responding.", "Focus on the graphics driver, GPU thermals, power, and hardware stability."),
            "0x154": ("UNEXPECTED_STORE_EXCEPTION", "Windows storage or memory backing the system store failed unexpectedly.", "Check SSD/HDD SMART health, storage drivers, firmware, and RAM."),
            "0x7A": ("KERNEL_DATA_INPAGE_ERROR", "Windows could not read required kernel data from disk/pagefile into memory.", "Check drive health, cables, storage controller drivers, and RAM."),
            "0xF4": ("CRITICAL_OBJECT_TERMINATION", "A critical Windows process or thread died, often after storage stops responding.", "Check SSD/HDD health, storage firmware/drivers, and system file integrity."),
            "0xEF": ("CRITICAL_PROCESS_DIED", "A critical Windows process died.", "Often storage corruption, driver issues, malware damage, or system file corruption."),
            "0xED": ("UNMOUNTABLE_BOOT_VOLUME", "Windows could not mount the boot volume.", "Check disk health, boot volume corruption, storage mode/driver changes, and run CHKDSK from recovery."),
            "0x24": ("NTFS_FILE_SYSTEM", "The NTFS file system driver hit a serious disk/file-system problem.", "Check drive health and run CHKDSK. Storage drivers or failing disks are common causes."),
            "0xC2": ("BAD_POOL_CALLER", "A driver made an invalid memory-pool request.", "The named driver is a strong suspect; update or remove it."),
            "0xC5": ("DRIVER_CORRUPTED_EXPOOL", "A driver corrupted kernel memory pool.", "Use the named driver if present; otherwise suspect recent drivers and run memory tests."),
            "0x109": ("CRITICAL_STRUCTURE_CORRUPTION", "Kernel code or data was modified unexpectedly.", "Common causes are drivers, overclock instability, RAM errors, or low-level security/virtualization tools."),
        }

        info = bugcheck_info.get(code_key)
        if info and not bugcheck_name:
            bugcheck_name = info[0]

        suspect = self._classify_crash_suspect(probable or image or failure_bucket, lower)
        likely_lines = []
        if info:
            likely_lines.append(info[1])
        elif "whea" in lower:
            likely_lines.append("This looks hardware-related because WHEA appears in the crash text.")
        elif "memory_corruption" in lower:
            likely_lines.append("This points to memory corruption. That can be bad RAM, unstable XMP/overclocking, or a driver corrupting memory.")
        elif probable or image:
            likely_lines.append("The crash output names a driver/module, so that is the best first suspect.")
        else:
            likely_lines.append("The pasted text does not include enough symbols to name one exact cause, but it does contain crash details WinMend can summarize.")

        if suspect:
            likely_lines.append(suspect["meaning"])

        actions = []
        if suspect:
            actions.extend(suspect["actions"])
        if info:
            actions.append(info[2])
        if "ntoskrnl" in (probable + " " + image).lower() or "ntkrnlmp" in (probable + " " + image).lower():
            actions.append("Do not replace ntoskrnl.exe. It is usually where Windows noticed the crash, not the real cause.")
        if "verifier" in lower:
            actions.append("Driver Verifier is mentioned. If the PC is boot-looping, disable it from Safe Mode with: verifier /reset")
        actions.append("If this started after an update or new device, roll back that driver first.")
        actions.append("If crashes continue with different drivers named each time, run a memory test and check disk SMART health.")

        seen = set()
        unique_actions = []
        for action in actions:
            key = action.lower()
            if key not in seen:
                unique_actions.append(action)
                seen.add(key)

        summary_bits = []
        if bugcheck_name or code_key:
            summary_bits.append(f"Stop code: {bugcheck_name or 'Unknown'}" + (f" ({code_key})" if code_key else ""))
        if probable:
            summary_bits.append(f"Named suspect: {probable}")
        elif image:
            summary_bits.append(f"Named image: {image}")
        if process:
            summary_bits.append(f"Process active at crash: {process}")
        if failure_bucket:
            summary_bits.append(f"Failure bucket: {failure_bucket}")
        if args:
            summary_bits.append(f"Bugcheck arguments: {args}")

        confidence = "Medium"
        if suspect and (probable or image):
            confidence = "High"
        elif not (bugcheck_name or code_key or probable or image):
            confidence = "Low"

        output = []
        output.append("Most likely issue")
        output.append("-----------------")
        if suspect:
            output.append(suspect["headline"])
        elif info:
            output.append(f"{bugcheck_name or code_key}: {info[1]}")
        else:
            output.append(likely_lines[0])

        output.append("")
        output.append("Why I think that")
        output.append("----------------")
        for line in likely_lines:
            output.append(f"- {line}")
        for bit in summary_bits:
            output.append(f"- {bit}")
        output.append(f"- Confidence: {confidence}")

        output.append("")
        output.append("What to do next")
        output.append("---------------")
        for i, action in enumerate(unique_actions[:6], start=1):
            output.append(f"{i}. {action}")

        output.append("")
        output.append("Note")
        output.append("----")
        output.append("This is a local rule-based triage from the pasted text. For a final root cause, compare several dumps and use the full WinDbg command output with symbols loaded.")
        return "\n".join(output)

    def _classify_crash_suspect(self, suspect_text, lower_full_text):
        text = (suspect_text or "").lower()
        full = lower_full_text or ""
        combined = text + "\n" + full

        rules = [
            (
                ["nvlddmkm", "nvidia"],
                "NVIDIA graphics driver/GPU issue",
                "The crash names NVIDIA's display driver. That usually means the GPU driver crashed, the GPU is unstable, or power/temperature is marginal.",
                ["Clean-install the latest NVIDIA driver, or roll back if this started after a driver update.", "Remove GPU overclocks/undervolts and watch GPU temperatures under load."]
            ),
            (
                ["amdkmdag", "amdkmdap", "atikmpag", "amdwddmg"],
                "AMD graphics driver/GPU issue",
                "The crash names AMD's display driver. That points to the GPU driver, GPU stability, or display stack.",
                ["Clean-install the latest AMD graphics driver, or roll back to the last stable version.", "Disable GPU overclocks/undervolts and check GPU temperature and power cabling."]
            ),
            (
                ["igdkmd", "intel graphics", "igfx"],
                "Intel graphics driver issue",
                "The crash names Intel graphics components. That points to the display driver or integrated GPU stack.",
                ["Install the latest Intel/OEM graphics driver.", "If this is a laptop, prefer the OEM graphics package first."]
            ),
            (
                ["dxgkrnl", "dxgmms", "video_tdr", "watchdog.sys"],
                "Graphics stack timeout",
                "Windows graphics components are involved. They are often victims of a GPU driver or GPU hardware timeout.",
                ["Clean-install the GPU driver.", "Disable overlays/recorders temporarily and test GPU temperatures and stability."]
            ),
            (
                ["netio", "tcpip", "ndis", "wifi", "wlan", "e1d", "rtwl", "bth"],
                "Network driver or filter driver issue",
                "The crash involves the network stack. VPNs, antivirus web filters, Wi-Fi drivers, and Ethernet drivers commonly cause this.",
                ["Update the Wi-Fi/Ethernet driver from the PC or motherboard vendor.", "Temporarily remove VPN, packet filter, firewall, or third-party antivirus network components."]
            ),
            (
                ["storport", "stornvme", "iaStor", "iastor", "amd_sata", "disk.sys", "ntfs", "volmgr", "partmgr"],
                "Storage driver, SSD/HDD, or file-system issue",
                "The crash involves storage or NTFS. That can be a failing drive, firmware issue, controller driver problem, or disk corruption.",
                ["Check SMART health with CrystalDiskInfo or the drive vendor tool.", "Update SSD firmware and storage/chipset drivers, then run CHKDSK if file-system errors are present."]
            ),
            (
                ["whea", "hal.dll", "pshed", "genuineintel", "authenticamd"],
                "Hardware stability issue",
                "WHEA/HAL CPU error reporting appears in the crash. That usually points below Windows: CPU, RAM, motherboard, PCIe device, thermals, BIOS, or power.",
                ["Undo CPU/GPU/RAM overclocks or undervolts, including XMP/EXPO, and retest.", "Update BIOS/chipset drivers and check CPU/GPU temperatures and PSU stability."]
            ),
            (
                ["memory_corruption", "memtest", "ntkrnlmp", "ntoskrnl"],
                "Kernel memory corruption",
                "The output points at Windows kernel memory. ntoskrnl/ntkrnlmp is usually where the crash was detected, not the driver that caused it.",
                ["Run a long memory test and temporarily disable XMP/EXPO.", "Update chipset, storage, GPU, and network drivers; compare multiple dumps for the repeated non-Microsoft driver."]
            ),
            (
                ["usb", "usbxhci", "hidclass", "hidusb"],
                "USB controller or USB device driver issue",
                "USB stack components appear in the crash text.",
                ["Update chipset/USB controller drivers and BIOS.", "Unplug nonessential USB devices and test again."]
            ),
            (
                ["acpi", "pci.sys"],
                "Firmware/chipset or power-management issue",
                "ACPI/PCI components are involved, which often means BIOS, chipset, power management, or a device on the PCIe bus.",
                ["Update BIOS/UEFI and chipset drivers.", "Remove overclocks and test with default power settings."]
            ),
        ]

        for needles, headline, meaning, actions in rules:
            if any(needle.lower() in combined for needle in needles):
                return {"headline": headline, "meaning": meaning, "actions": actions}
        return None

    def run_bsod_triage(self):
        """Collect BSOD diagnostics into a single Desktop report and launch analyzer."""
        self.queue.put("PROGRESS:BSOD Triage:Collecting crash dump and bugcheck diagnostics...")
        try:
            desktop = self._get_desktop_dir()
            ts = time.strftime("%Y%m%d_%H%M%S")
            report_path = os.path.join(desktop, f"BSOD_Triage_{ts}.txt")
            minidump_dir = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'Minidump')
            memory_dmp = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'MEMORY.DMP')

            lines = []
            lines.append("=== EAWTECH BSOD TRIAGE REPORT ===")
            lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            lines.append("")
            lines.append(f"Minidump folder: {minidump_dir}")

            if os.path.isdir(minidump_dir):
                dumps = sorted(
                    [os.path.join(minidump_dir, f) for f in os.listdir(minidump_dir) if f.lower().endswith('.dmp')],
                    key=lambda p: os.path.getmtime(p), reverse=True
                )
                lines.append(f"Minidumps found: {len(dumps)}")
                for d in dumps[:15]:
                    dt = datetime.fromtimestamp(os.path.getmtime(d)).strftime("%Y-%m-%d %H:%M:%S")
                    lines.append(f"  - {os.path.basename(d)} ({dt})")
            else:
                lines.append("Minidump folder not found.")

            lines.append(f"MEMORY.DMP exists: {'Yes' if os.path.exists(memory_dmp) else 'No'}")
            lines.append("")

            ps_script = r'''
            Write-Host "=== RECENT BUGCHECK EVENTS (Event ID 1001) ==="
            Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001} -MaxEvents 15 -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $msg = $_.Message -replace "\r|\n", " "
                    Write-Host ("[{0}] {1}" -f $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"), $msg)
                }
            Write-Host ""
            Write-Host "=== CRASH-RELATED DRIVER EVENTS (Kernel-PnP/Display) ==="
            Get-WinEvent -FilterHashtable @{LogName='System'} -MaxEvents 250 -ErrorAction SilentlyContinue |
                Where-Object { $_.ProviderName -match 'Kernel-PnP|Display|WHEA-Logger' -and $_.LevelDisplayName -in @('Error','Critical','Warning') } |
                Select-Object -First 30 |
                ForEach-Object {
                    $msg = $_.Message -replace "\r|\n", " "
                    Write-Host ("[{0}] {1}: {2}" -f $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"), $_.ProviderName, $msg)
                }
            '''
            result = wm_run(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'RemoteSigned', '-Command', ps_script],
                capture_output=True, text=True, encoding='utf-8', errors='replace', check=False, timeout=90, startupinfo=_no_console_startupinfo()
            )
            if result.stdout:
                lines.append(result.stdout.strip())
            if result.stderr:
                lines.append("")
                lines.append("=== PowerShell stderr ===")
                lines.append(result.stderr.strip())

            with open(report_path, 'w', encoding='utf-8') as f:
                f.write("\n".join(lines))

            self.queue.put(f"PROGRESS:BSOD Triage:Report saved to {report_path}")
            self.run_minidump_analyzer()
        except Exception as e:
            self._report_failure(f"PROGRESS:BSOD Triage:Error: {str(e)}")
