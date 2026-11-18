"""WinMend reports: system software."""

from __future__ import annotations

from winmend.core.processes import _no_console_startupinfo, wm_run
from winmend.features.startup.helpers import list_startup_entries
import json
import platform
import winreg


class ReportSystemSoftwareMixin:
    """PCReporter methods grouped by responsibility."""

    def collect_software_info(self):
        """Collect installed software information"""
        software_info = {}

        try:
            if platform.system() == "Windows":
                # Try multiple methods to get installed software
                # Method 1: Try registry-based approach first (more reliable)
                try:
                    # Get software from HKLM
                    registry_paths = [
                        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                    ]

                    for registry_path in registry_paths:
                        try:
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path) as key:
                                for i in range(winreg.QueryInfoKey(key)[0]):
                                    try:
                                        subkey_name = winreg.EnumKey(key, i)
                                        with winreg.OpenKey(key, subkey_name) as subkey:
                                            try:
                                                name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                                version = winreg.QueryValueEx(subkey, "DisplayVersion")[
                                                    0] if "DisplayVersion" in [item[0] for item in winreg.QueryInfoKey(
                                                    subkey)] else "Unknown"
                                                publisher = winreg.QueryValueEx(subkey, "Publisher")[
                                                    0] if "Publisher" in [item[0] for item in
                                                                          winreg.QueryInfoKey(subkey)] else "Unknown"
                                                install_date = winreg.QueryValueEx(subkey, "InstallDate")[
                                                    0] if "InstallDate" in [item[0] for item in
                                                                            winreg.QueryInfoKey(subkey)] else ""

                                                if install_date and len(install_date) == 8:
                                                    install_date = f"{install_date[:4]}-{install_date[4:6]}-{install_date[6:8]}"

                                                software_info[name] = {
                                                    "Version": version,
                                                    "Vendor": publisher,
                                                    "Install Date": install_date
                                                }
                                            except (WindowsError, KeyError):
                                                continue
                                    except (WindowsError, KeyError):
                                        continue
                        except (WindowsError, KeyError):
                            continue

                    # Get software from HKCU
                    try:
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall") as key:
                            for i in range(winreg.QueryInfoKey(key)[0]):
                                try:
                                    subkey_name = winreg.EnumKey(key, i)
                                    with winreg.OpenKey(key, subkey_name) as subkey:
                                        try:
                                            name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                            version = winreg.QueryValueEx(subkey, "DisplayVersion")[
                                                0] if "DisplayVersion" in [item[0] for item in
                                                                           winreg.QueryInfoKey(subkey)] else "Unknown"
                                            publisher = winreg.QueryValueEx(subkey, "Publisher")[0] if "Publisher" in [
                                                item[0] for item in winreg.QueryInfoKey(subkey)] else "Unknown"
                                            install_date = winreg.QueryValueEx(subkey, "InstallDate")[
                                                0] if "InstallDate" in [item[0] for item in
                                                                        winreg.QueryInfoKey(subkey)] else ""

                                            if install_date and len(install_date) == 8:
                                                install_date = f"{install_date[:4]}-{install_date[4:6]}-{install_date[6:8]}"

                                            software_info[name] = {
                                                "Version": version,
                                                "Vendor": publisher,
                                                "Install Date": install_date
                                            }
                                        except (WindowsError, KeyError):
                                            continue
                                except (WindowsError, KeyError):
                                    continue
                    except (WindowsError, KeyError):
                        pass

                    if software_info:
                        self.report_data["software"] = software_info
                        return
                except Exception as e:
                    pass

                # Method 2: Try PowerShell as fallback
                try:
                    ps_script = '''
                    $software = @()
                    $paths = @(
                        "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
                        "HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
                        "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*"
                    )

                    foreach ($path in $paths) {
                        try {
                            Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
                                $software += [PSCustomObject]@{
                                    Name = $_.DisplayName
                                    Version = $_.DisplayVersion
                                    Publisher = $_.Publisher
                                    InstallDate = $_.InstallDate
                                }
                            }
                        } catch {
                            # Ignore errors
                        }
                    }

                    $software | ConvertTo-Json
                    '''

                    result = wm_run(
                        ["powershell", "-Command", ps_script],
                        capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30,
                        startupinfo=_no_console_startupinfo()
                    )

                    if result.returncode == 0 and result.stdout.strip():
                        try:
                            software_data = json.loads(result.stdout)
                            for item in software_data:
                                name = item.get("Name", "")
                                if name:
                                    version = item.get("Version", "Unknown")
                                    publisher = item.get("Publisher", "Unknown")
                                    install_date = item.get("InstallDate", "")

                                    if install_date and len(install_date) == 8:
                                        install_date = f"{install_date[:4]}-{install_date[4:6]}-{install_date[6:8]}"

                                    software_info[name] = {
                                        "Version": version,
                                        "Vendor": publisher,
                                        "Install Date": install_date
                                    }
                        except json.JSONDecodeError:
                            pass

                        if software_info:
                            self.report_data["software"] = software_info
                            return
                except Exception:
                    pass

                # There is deliberately no Win32_Product fallback: wmic is gone
                # from current Windows, and querying that class makes Windows
                # run a consistency check -- and sometimes a silent repair --
                # on every MSI-installed program.

                # If all methods fail, add error message
                software_info["Error"] = "Could not retrieve software information using multiple methods"
            else:
                # For Linux/Mac, try to get installed packages
                if platform.system() == "Linux":
                    # Try dpkg (Debian/Ubuntu)
                    try:
                        result = wm_run(
                            ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Maintainer}\n"],
                            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60,
                            startupinfo=_no_console_startupinfo()
                        )
                        if result.returncode == 0:
                            for line in result.stdout.split('\n'):
                                if line.strip():
                                    parts = line.split('\t')
                                    if len(parts) >= 2:
                                        software_info[parts[0]] = {
                                            "Version": parts[1],
                                            "Vendor": parts[2] if len(parts) > 2 else "Unknown"
                                        }
                    except FileNotFoundError:
                        # Try rpm (RedHat/CentOS)
                        try:
                            result = wm_run(
                                ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}\t%{VENDOR}\n"],
                                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60,
                                startupinfo=_no_console_startupinfo()
                            )
                            if result.returncode == 0:
                                for line in result.stdout.split('\n'):
                                    if line.strip():
                                        parts = line.split('\t')
                                        if len(parts) >= 2:
                                            software_info[parts[0]] = {
                                                "Version": parts[1],
                                                "Vendor": parts[2] if len(parts) > 2 else "Unknown"
                                            }
                        except FileNotFoundError:
                            pass
        except Exception as e:
            software_info["Error"] = f"Could not retrieve software information: {str(e)}"

        self.report_data["software"] = software_info

    def collect_startup_info(self):
        """Collect startup items, with the state Task Manager shows for each.

        Every entry used to be reported as "Enabled" regardless -- a PC with
        ten of its twelve startup apps switched off in Task Manager read as all
        twelve launching at sign-in.
        """
        startup_info = {
            "Registry": {},
            "Startup Folders": {}
        }
        try:
            for entry in list_startup_entries():
                status = "Enabled" if entry.get("enabled", True) else "Disabled"
                if entry.get("kind") == "folder":
                    folder = startup_info["Startup Folders"].setdefault(entry.get("source", "Startup"), {})
                    folder[entry.get("name", "")] = {"Path": entry.get("location", ""), "Status": status}
                else:
                    key = startup_info["Registry"].setdefault(entry.get("location", "Run"), {})
                    key[entry.get("name", "")] = {"Value": entry.get("command", ""), "Status": status}
            # RunOnce entries fire once at the next sign-in and then delete
            # themselves; Task Manager does not list them, so read them here.
            for root, root_name, path in (
                    (winreg.HKEY_CURRENT_USER, "HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
                    (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")):
                try:
                    with winreg.OpenKey(root, path) as key:
                        for i in range(winreg.QueryInfoKey(key)[1]):
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                            except OSError:
                                continue
                            startup_info["Registry"].setdefault(f"{root_name}\\{path}", {})[name] = {
                                "Value": value, "Status": "Runs once at the next sign-in"}
                except OSError:
                    continue
        except Exception as e:
            startup_info["Error"] = f"Could not retrieve startup information: {str(e)}"

        self.report_data["startup_items"] = startup_info

    def _collect_windows_updates(self):
        """The 20 most recently installed Windows updates."""
        out = self._ps(
            "Get-HotFix -ErrorAction SilentlyContinue | Sort-Object { $_.InstalledOn } -Descending | "
            "Select-Object -First 20 | ForEach-Object { Write-Output ('{0}|{1}|{2}' -f $_.HotFixID, "
            "$(if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } else { '' }), $_.InstalledBy) }")
        updates = []
        for line in out.splitlines():
            parts = line.strip().split("|")
            if len(parts) == 3 and parts[0]:
                updates.append({"Hotfix ID": parts[0], "Installed On": parts[1],
                                "Installed By": parts[2]})
        self.report_data["updates"] = updates or {"Error": "Could not retrieve update information"}

    def collect_vulnerability_info(self):
        """Collect vulnerability and security update information"""
        vulnerability_info = {}

        try:
            if platform.system() == "Windows":
                # Get Windows Update status
                try:
                    result = wm_run(
                        ["powershell", "(Get-WmiObject -Class Win32_QuickFixEngineering).Count"],
                        capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=15,
                        startupinfo=_no_console_startupinfo()
                    )
                    if result.returncode == 0:
                        try:
                            update_count = int(result.stdout.strip())
                            vulnerability_info["Installed Updates Count"] = str(update_count)
                        except ValueError:
                            pass
                except Exception:
                    pass

                # Check for pending updates
                try:
                    result = wm_run(
                        ["powershell",
                         "(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search(\"IsInstalled=0\").Updates.Count"],
                        capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30,
                        startupinfo=_no_console_startupinfo()
                    )
                    if result.returncode == 0:
                        try:
                            pending_count = int(result.stdout.strip())
                            if pending_count > 0:
                                vulnerability_info["Pending Updates"] = f"{pending_count} updates available"
                                vulnerability_info["Status"] = "Updates Available"
                            else:
                                vulnerability_info["Pending Updates"] = "No pending updates"
                                vulnerability_info["Status"] = "Up to Date"
                        except ValueError:
                            pass
                except Exception:
                    pass

                # Get last scan date
                try:
                    result = wm_run(
                        ["powershell",
                         "(Get-WmiObject -Class Win32_QuickFixEngineering | Sort-Object -Property InstalledOn -Descending | Select-Object -First 1).InstalledOn"],
                        capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=15,
                        startupinfo=_no_console_startupinfo()
                    )
                    if result.returncode == 0 and result.stdout.strip():
                        vulnerability_info["Last Update Scan"] = result.stdout.strip()
                except Exception:
                    pass

                # Check for Windows Defender status
                try:
                    result = wm_run(
                        ["powershell",
                         "Get-MpComputerStatus | Select-Object AntispywareEnabled, AntivirusEnabled, NISEnabled, RealTimeProtectionEnabled | Format-List"],
                        capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=15,
                        startupinfo=_no_console_startupinfo()
                    )
                    if result.returncode == 0:
                        defender_status = {}
                        for line in result.stdout.split('\n'):
                            if ':' in line and not line.strip().startswith('-'):
                                parts = line.split(':', 1)
                                if len(parts) == 2:
                                    key = parts[0].strip()
                                    value = parts[1].strip()
                                    if value:
                                        defender_status[key] = value
                        if defender_status:
                            vulnerability_info["Windows Defender"] = defender_status
                except Exception:
                    pass

                # Check for Windows version and end of life status
                try:
                    result = wm_run(
                        ["powershell",
                         "Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsVersion | Format-List"],
                        capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=15,
                        startupinfo=_no_console_startupinfo()
                    )
                    if result.returncode == 0:
                        version_info = {}
                        for line in result.stdout.split('\n'):
                            if ':' in line and not line.strip().startswith('-'):
                                parts = line.split(':', 1)
                                if len(parts) == 2:
                                    key = parts[0].strip()
                                    value = parts[1].strip()
                                    if value:
                                        version_info[key] = value

                        if version_info.get("WindowsProductName"):
                            product_name = version_info["WindowsProductName"]
                            # Check if it's a supported version
                            if "Windows 10" in product_name or "Windows 11" in product_name:
                                vulnerability_info["Windows Support Status"] = "Supported"
                            elif "Windows 7" in product_name or "Windows 8" in product_name or "Windows Server 2012" in product_name:
                                vulnerability_info["Windows Support Status"] = "End of Life - Security Risk"
                            else:
                                vulnerability_info["Windows Support Status"] = "Unknown"
                except Exception:
                    pass

                # Check for firewall status
                try:
                    result = wm_run(
                        ["netsh", "advfirewall", "show", "allprofiles"],
                        capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=10,
                        startupinfo=_no_console_startupinfo()
                    )
                    if result.returncode == 0:
                        firewall_profiles = {}
                        for line in result.stdout.split('\n'):
                            if 'State' in line:
                                parts = line.strip().split()
                                if len(parts) >= 3:
                                    profile = parts[0]
                                    state = parts[2]
                                    firewall_profiles[profile] = state
                        if firewall_profiles:
                            vulnerability_info["Windows Firewall"] = firewall_profiles
                except Exception:
                    pass
        except Exception:
            pass

        self.report_data["vulnerabilities"] = vulnerability_info
