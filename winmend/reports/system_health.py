"""WinMend reports: system health."""

from __future__ import annotations

from datetime import datetime
from winmend.core.processes import _no_console_startupinfo, wm_run
import os
import platform
import socket
import subprocess


class ReportSystemHealthMixin:
    """PCReporter methods grouped by responsibility."""

    def collect_network_info(self):
        """Collect network information"""
        import psutil
        network_info = {}

        # Get network interfaces
        interfaces = {}
        for interface, addrs in psutil.net_if_addrs().items():
            interface_info = {"IP Addresses": []}
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    interface_info["IP Addresses"].append({
                        "Address": addr.address,
                        "Netmask": addr.netmask,
                        "Broadcast": addr.broadcast
                    })
                elif addr.family == socket.AF_INET6:
                    interface_info["IPv6"] = addr.address
                elif addr.family == psutil.AF_LINK:
                    interface_info["MAC Address"] = addr.address
            interfaces[interface] = interface_info

        # Get network statistics
        net_io = psutil.net_io_counters()
        network_stats = {
            "Bytes Sent": f"{net_io.bytes_sent / (1024 ** 3):.2f} GB",
            "Bytes Received": f"{net_io.bytes_recv / (1024 ** 3):.2f} GB",
            "Packets Sent": f"{net_io.packets_sent:,}",
            "Packets Received": f"{net_io.packets_recv:,}",
            "Errin": f"{net_io.errin}",
            "Errout": f"{net_io.errout}",
            "Dropin": f"{net_io.dropin}",
            "Dropout": f"{net_io.dropout}"
        }

        # Get active connections
        connections = []
        try:
            for conn in psutil.net_connections():
                if conn.status == 'ESTABLISHED':
                    connections.append({
                        "Local Address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                        "Remote Address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                        "Status": conn.status,
                        "PID": conn.pid
                    })
        except Exception:
            pass

        # Get DNS servers
        dns_servers = self._get_dns_servers()

        network_info = {
            "Interfaces": interfaces,
            "Statistics": network_stats,
            "Active Connections": connections[:20],  # Top 20 connections
            "DNS Servers": dns_servers
        }

        self.report_data["network"] = network_info

    def _get_dns_servers(self):
        """DNS servers per network adapter, as Windows has them configured.

        The old version ran `nslookup localhost`, which prints the NAME of one
        resolver ("UnKnown" as often as not) rather than the servers in use.
        """
        out = self._ps(
            "Get-DnsClientServerAddress -ErrorAction SilentlyContinue | "
            "Where-Object { $_.ServerAddresses } | ForEach-Object { "
            "$servers = @($_.ServerAddresses | Where-Object { $_ -notlike 'fec0:*' }); "
            "if ($servers) { Write-Output ($_.InterfaceAlias + '|' + ($servers -join ', ')) } }")
        servers = {}
        for line in out.splitlines():
            alias, sep, addresses = line.strip().partition("|")
            if sep and addresses:
                servers.setdefault(alias, []).append(addresses)
        return [f"{alias}: {', '.join(addrs)}" for alias, addrs in servers.items()] or ["Could not determine"]

    def collect_security_info(self):
        """Collect security-related information"""
        security_info = {}

        try:
            if platform.system() == "Windows":
                # Get Windows Defender status
                try:
                    commands = [
                        ["powershell",
                         "Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, NISEnabled, RealTimeProtectionEnabled, QuickScanAge, FullScanAge"],
                        ["powershell", "Get-MpPreference | Select-Object DisableRealtimeMonitoring"],
                    ]

                    for cmd in commands:
                        try:
                            result = wm_run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=10,
                                                    startupinfo=_no_console_startupinfo())
                            if result.returncode == 0:
                                defender_status = {}
                                for line in result.stdout.split('\n'):
                                    if ':' in line and not line.startswith('-'):
                                        parts = line.split(':', 1)
                                        if len(parts) == 2:
                                            key = parts[0].strip()
                                            value = parts[1].strip()
                                            if value:
                                                defender_status[key] = value
                                if defender_status:
                                    security_info["Windows Defender"] = defender_status
                                    break
                        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                            continue
                except Exception:
                    security_info["Windows Defender"] = "Status not available"

                # Whatever antivirus Windows Security Center knows about --
                # third-party products included -- rather than Defender alone.
                products = [line.strip() for line in self._ps(
                    "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct "
                    "-ErrorAction SilentlyContinue | ForEach-Object { $_.displayName }").splitlines()
                    if line.strip()]
                if products:
                    security_info["Antivirus Products"] = ", ".join(dict.fromkeys(products))

                # Get Windows Firewall status
                try:
                    result = wm_run(
                        ["netsh", "advfirewall", "show", "allprofiles"],
                        capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=10,
                        startupinfo=_no_console_startupinfo()
                    )
                    if result.returncode == 0:
                        firewall_status = {}
                        for line in result.stdout.split('\n'):
                            if 'State' in line:
                                parts = line.strip().split()
                                if len(parts) >= 3:
                                    profile = parts[0]
                                    state = parts[2]
                                    firewall_status[profile] = state
                        security_info["Windows Firewall"] = firewall_status
                except Exception:
                    security_info["Windows Firewall"] = "Status not available"

                # Get UAC status
                try:
                    result = wm_run(
                        ["reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "/v",
                         "EnableLUA"],
                        capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=10,
                        startupinfo=_no_console_startupinfo()
                    )
                    if result.returncode == 0:
                        uac_enabled = "0x1" in result.stdout
                        security_info["User Account Control"] = "Enabled" if uac_enabled else "Disabled"
                except Exception:
                    security_info["User Account Control"] = "Status not available"
            else:
                security_info["Note"] = "Security software detection not implemented for this OS"
        except Exception as e:
            security_info["Error"] = f"Could not retrieve security information: {str(e)}"

        self.report_data["security"] = security_info

    def collect_user_info(self):
        """Collect user account information"""
        user_info = {}

        try:
            if platform.system() == "Windows":
                # Get user accounts
                try:
                    result = wm_run(
                        ["net", "user"],
                        capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=10,
                        startupinfo=_no_console_startupinfo()
                    )
                    if result.returncode == 0:
                        users = []
                        lines = result.stdout.split('\n')
                        for line in lines:
                            if line.strip() and not line.startswith('-') and not line.startswith('The command'):
                                users.append(line.strip())
                        user_info["User Accounts"] = users
                except Exception:
                    pass

                # Get current user details
                current_user = os.environ.get("USERNAME", "Unknown")
                user_info["Current User"] = current_user

                # Get user groups
                try:
                    result = wm_run(
                        ["net", "user", current_user],
                        capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=10,
                        startupinfo=_no_console_startupinfo()
                    )
                    if result.returncode == 0:
                        groups = []
                        for line in result.stdout.split('\n'):
                            if "Local Group Memberships" in line:
                                groups_line = line.split('*', 1)[1].strip()
                                groups = [g.strip() for g in groups_line.split() if g.strip()]
                                break
                        user_info["User Groups"] = groups
                except Exception:
                    pass
            else:
                # For Linux/Mac, get users from /etc/passwd
                if os.path.exists("/etc/passwd"):
                    users = []
                    with open("/etc/passwd", "r") as f:
                        for line in f:
                            if not line.startswith("#"):
                                parts = line.split(":")
                                if len(parts) >= 1:
                                    users.append(parts[0])
                    user_info["User Accounts"] = users

                user_info["Current User"] = os.environ.get("USER", "Unknown")
        except Exception as e:
            user_info["Error"] = f"Could not retrieve user information: {str(e)}"

        self.report_data["users"] = user_info

    def collect_environment_info(self):
        """Collect environment variables"""
        self.report_data["environment"] = dict(os.environ)

    def collect_process_info(self):
        """Collect running processes"""
        import psutil
        processes = []

        try:
            for proc in psutil.process_iter(
                    ['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'memory_info', 'create_time']):
                try:
                    create_time = datetime.fromtimestamp(proc.info['create_time']).strftime(
                        "%Y-%m-%d %H:%M:%S")
                    memory_mb = proc.info['memory_info'].rss / (1024 * 1024) if proc.info['memory_info'] else 0

                    processes.append({
                        "PID": proc.info['pid'],
                        "Name": proc.info['name'],
                        "User": proc.info['username'],
                        "CPU %": f"{proc.info['cpu_percent']:.1f}%",
                        "Memory %": f"{proc.info['memory_percent']:.1f}%",
                        "Memory (MB)": f"{memory_mb:.1f}",
                        "Started": create_time
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
        except Exception:
            pass

        # Sort by memory usage
        processes.sort(key=lambda x: float(x["Memory %"].rstrip('%')), reverse=True)
        self.report_data["processes"] = processes[:30]  # Top 30 processes

    def collect_service_info(self):
        """Collect system services"""
        services = []

        try:
            if platform.system() == "Windows":
                # Get Windows services
                commands = [
                    ["sc", "query", "type=", "service", "state=", "all"],
                    ["powershell", "Get-Service | Select-Object Name,Status,StartType | Format-Table"]
                ]

                for cmd in commands:
                    try:
                        result = wm_run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30,
                                                startupinfo=_no_console_startupinfo())
                        if result.returncode == 0:
                            lines = result.stdout.split('\n')
                            current_service = {}
                            for line in lines:
                                if line.strip():
                                    if "SERVICE_NAME:" in line:
                                        if current_service:
                                            services.append(current_service)
                                        current_service = {"Name": line.split(":", 1)[1].strip()}
                                    elif "DISPLAY_NAME:" in line:
                                        current_service["Display Name"] = line.split(":", 1)[1].strip()
                                    elif "TYPE" in line:
                                        current_service["Type"] = line.split(":", 1)[1].strip()
                                    elif "STATE" in line:
                                        current_service["State"] = line.split(":", 1)[1].strip()
                                    elif "START_TYPE" in line:
                                        current_service["Start Type"] = line.split(":", 1)[1].strip()
                            if current_service:
                                services.append(current_service)
                            if services:
                                break
                    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                        continue
            else:
                # For Linux/Mac, try to get systemd services
                if platform.system() == "Linux":
                    try:
                        result = wm_run(
                            ["systemctl", "list-units", "--type=service", "--no-pager"],
                            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30,
                            startupinfo=_no_console_startupinfo()
                        )
                        if result.returncode == 0:
                            lines = result.stdout.split('\n')
                            for line in lines[1:]:  # Skip header
                                if line.strip() and not line.startswith('UNIT'):
                                    parts = line.split()
                                    if len(parts) >= 4:
                                        services.append({
                                            "Name": parts[0],
                                            "Load": parts[1],
                                            "Active": parts[2],
                                            "State": parts[3],
                                            "Description": " ".join(parts[4:]) if len(parts) > 4 else ""
                                        })
                    except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
                        pass
        except Exception as e:
            services.append({"Error": f"Could not retrieve service information: {str(e)}"})

        self.report_data["services"] = services[:50]  # Top 50 services

    def collect_device_info(self):
        """Every Plug and Play device Windows knows about, grouped by class."""
        devices = []
        sep = "\x1f"  # unit separator: device names can contain | and ,
        out = self._ps(
            "$s = [char]31; Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue | "
            "Where-Object { $_.Name } | Sort-Object PNPClass, Name | ForEach-Object { "
            "Write-Output (@($_.Name, $_.PNPClass, $_.Manufacturer, $_.PNPDeviceID) -join $s) }")
        for line in out.splitlines():
            parts = line.strip("\r\n").split(sep)
            if len(parts) == 4 and parts[0].strip():
                devices.append({
                    "Name": parts[0].strip(),
                    "Description": parts[1].strip() or "Other",
                    "Manufacturer": parts[2].strip(),
                    "Device ID": parts[3].strip(),
                })
        if not devices:
            devices.append({"Error": "Could not retrieve device information"})
        self.report_data["devices"] = devices[:100]  # Top 100 devices

    def collect_performance_metrics(self):
        """Collect performance metrics"""
        import psutil
        perf_data = {}

        # CPU load average (Linux/Mac) or CPU usage history
        if hasattr(psutil, 'getloadavg'):
            perf_data["Load Average"] = psutil.getloadavg()

        # Memory pressure
        mem = psutil.virtual_memory()
        perf_data["Memory Pressure"] = {
            "Available": f"{mem.available / (1024 ** 3):.2f} GB",
            "Percent Used": f"{mem.percent}%"
        }

        # Disk usage summary
        disk_usage = {}
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_usage[partition.device] = {
                    "Used": f"{usage.percent}%",
                    "Free": f"{usage.free / (1024 ** 3):.2f} GB"
                }
            except:
                continue
        perf_data["Disk Usage"] = disk_usage

        self.report_data["performance"] = perf_data
