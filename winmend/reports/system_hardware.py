"""WinMend reports: system hardware."""

from __future__ import annotations

import re


class ReportSystemHardwareMixin:
    """PCReporter methods grouped by responsibility."""

    def collect_hardware_info(self):
        """Collect detailed hardware information"""
        import psutil
        # CPU Information
        cpu_freq = psutil.cpu_freq()
        cpu_info = {
            "Physical Cores": psutil.cpu_count(logical=False),
            "Total Cores": psutil.cpu_count(logical=True),
            "Max Frequency": f"{cpu_freq.max:.2f} MHz" if cpu_freq else "N/A",
            "Current Frequency": f"{cpu_freq.current:.2f} MHz" if cpu_freq else "N/A",
            "Min Frequency": f"{cpu_freq.min:.2f} MHz" if cpu_freq else "N/A",
            "CPU Usage": f"{psutil.cpu_percent(interval=1)}%",
            "CPU Usage Per Core": dict(enumerate(psutil.cpu_percent(interval=1, percpu=True)))
        }

        # Memory Information
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        memory_info = {
            "Total Memory": f"{mem.total / (1024 ** 3):.2f} GB",
            "Available Memory": f"{mem.available / (1024 ** 3):.2f} GB",
            "Used Memory": f"{mem.used / (1024 ** 3):.2f} GB",
            "Memory Percentage": f"{mem.percent}%",
            "Total Swap": f"{swap.total / (1024 ** 3):.2f} GB",
            "Used Swap": f"{swap.used / (1024 ** 3):.2f} GB",
            "Free Swap": f"{swap.free / (1024 ** 3):.2f} GB",
            "Swap Percentage": f"{swap.percent}%",
            "Memory Speed": self._get_memory_speed()
        }

        # Disk Information
        disk_info = {}
        disk_io = psutil.disk_io_counters()
        for partition in psutil.disk_partitions():
            try:
                partition_usage = psutil.disk_usage(partition.mountpoint)
                disk_info[f"Drive {partition.device}"] = {
                    "Mount Point": partition.mountpoint,
                    "File System": partition.fstype,
                    "Total Size": f"{partition_usage.total / (1024 ** 3):.2f} GB",
                    "Used": f"{partition_usage.used / (1024 ** 3):.2f} GB",
                    "Free": f"{partition_usage.free / (1024 ** 3):.2f} GB",
                    "Percentage": f"{partition_usage.percent}%",
                    "Drive Type": self._get_drive_type(partition.device)
                }
            except OSError as exc:
                # A card reader with no card, a RAW or BitLocker-locked volume:
                # disk_usage() raises (WinError 1005 for a RAW stick), and only
                # PermissionError used to be caught -- so one unreadable USB
                # stick ended the whole report. It is worth a line of its own.
                disk_info[f"Drive {partition.device}"] = {
                    "Mount Point": partition.mountpoint,
                    "File System": partition.fstype or "not recognised",
                    "Status": f"unreadable ({exc.strerror or exc})",
                }

        # Add disk I/O statistics
        if disk_io:
            disk_info["Disk I/O Statistics"] = {
                "Read Count": f"{disk_io.read_count:,}",
                "Write Count": f"{disk_io.write_count:,}",
                "Read Bytes": f"{disk_io.read_bytes / (1024 ** 3):.2f} GB",
                "Write Bytes": f"{disk_io.write_bytes / (1024 ** 3):.2f} GB",
                "Read Time": f"{disk_io.read_time} ms",
                "Write Time": f"{disk_io.write_time} ms"
            }

        # GPU Information
        gpu_info = self._get_gpu_info()

        # Motherboard Information
        motherboard_info = self._get_motherboard_info()

        # Battery Information (for laptops)
        battery_info = self._get_battery_info()

        # Temperature Information
        temp_info = self._get_temperature_info()

        self.report_data["hardware"] = {
            "CPU": cpu_info,
            "Memory": memory_info,
            "Storage": disk_info,
            "Graphics": gpu_info,
            "Motherboard": motherboard_info
        }

        if battery_info:
            self.report_data["hardware"]["Battery"] = battery_info

        if temp_info:
            self.report_data["hardware"]["Temperature"] = temp_info

    def _get_memory_speed(self):
        """Configured memory speed of the installed sticks."""
        out = self._ps(
            "Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue | "
            "ForEach-Object { if ($_.ConfiguredClockSpeed) { $_.ConfiguredClockSpeed } "
            "else { $_.Speed } }")
        speeds = sorted({int(s) for s in re.findall(r"\d+", out) if int(s) > 0})
        if not speeds:
            return "Information not available"
        return " / ".join(f"{speed} MHz" for speed in speeds)

    def _get_drive_type(self, device):
        """SSD or HDD (and the bus it sits on) for one drive letter.

        Each partition is mapped to its own physical disk. The old version
        asked for every disk at once and called a partition an SSD whenever
        any disk in the machine was one.
        """
        if self._drive_media is None:
            self._drive_media = {}
            out = self._ps(
                "$phys = @{}; Get-PhysicalDisk -ErrorAction SilentlyContinue | "
                "ForEach-Object { $phys[[string]$_.DeviceId] = $_ }; "
                "Get-Partition -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter } | "
                "ForEach-Object { $p = $phys[[string]$_.DiskNumber]; "
                "if ($p) { Write-Output ('{0}|{1}|{2}' -f $_.DriveLetter, $p.MediaType, $p.BusType) } }")
            for line in out.splitlines():
                parts = line.strip().split("|")
                if len(parts) == 3 and parts[0]:
                    self._drive_media[parts[0].upper()] = (parts[1], parts[2])
        letter = str(device).strip()[:1].upper()
        media, bus = self._drive_media.get(letter, ("", ""))
        if media in ("SSD", "HDD"):
            return f"{media} ({bus})" if bus and bus != "Unknown" else media
        return f"Unknown ({bus})" if bus and bus != "Unknown" else "Unknown"

    def _get_gpu_info(self):
        """Every graphics adapter: name, memory, driver version and date.

        Win32_VideoController.AdapterRAM is a 32-bit value and tops out at
        4 GB, so a modern card's real memory comes from the driver's own
        HardwareInformation.qwMemorySize value when the driver writes one.
        """
        out = self._ps(r'''
        $vram = @{}
        Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}' -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($p -and $p.DriverDesc -and $p.'HardwareInformation.qwMemorySize') {
                $vram[$p.DriverDesc] = [uint64]$p.'HardwareInformation.qwMemorySize'
            }
        }
        Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | ForEach-Object {
            $mem = if ($vram.ContainsKey($_.Name)) { $vram[$_.Name] } else { [uint64]$_.AdapterRAM }
            $date = if ($_.DriverDate) { $_.DriverDate.ToString('yyyy-MM-dd') } else { '' }
            Write-Output ('{0}|{1}|{2}|{3}' -f $_.Name, $mem, $_.DriverVersion, $date)
        }
        ''')
        adapters = []
        for line in out.splitlines():
            parts = line.strip().split("|")
            if len(parts) == 4 and parts[0]:
                adapters.append(parts)
        gpu_info = {}
        for number, (name, memory, version, date) in enumerate(adapters, start=1):
            single = len(adapters) == 1
            head = "GPU" if single else f"GPU {number}"
            gpu_info["GPU Name" if single else head] = name
            try:
                mem = int(memory)
            except ValueError:
                mem = 0
            if mem > 0:
                gpu_info[f"{head} Memory"] = (f"{mem / 1024 ** 3:.1f} GB" if mem >= 1024 ** 3
                                              else f"{mem // (1024 * 1024)} MB")
            if version:
                gpu_info["Driver Version" if single else f"{head} Driver Version"] = version
            if date:
                gpu_info["Driver Date" if single else f"{head} Driver Date"] = date
        if not gpu_info:
            gpu_info["GPU"] = "Information not available"
        return gpu_info

    def _get_motherboard_info(self):
        """System maker/model, motherboard and BIOS, from WMI.

        Read from WMI rather than parsed out of systeminfo, whose labels are
        translated on non-English Windows ("Systemhersteller:"), which left the
        section empty there.
        """
        out = self._ps(r'''
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
        $bb = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue
        "System Manufacturer|$($cs.Manufacturer)"
        "System Model|$($cs.Model)"
        "System Type|$($cs.SystemType)"
        "Motherboard|$(("$($bb.Manufacturer) $($bb.Product)").Trim())"
        "BIOS Version|$($bios.SMBIOSBIOSVersion)"
        "BIOS Date|$(if ($bios.ReleaseDate) { $bios.ReleaseDate.ToString('yyyy-MM-dd') })"
        "BIOS Mode|$env:firmware_type"
        ''')
        motherboard_info = {}
        for line in out.splitlines():
            key, sep, value = line.strip().partition("|")
            if sep and value.strip():
                motherboard_info[key] = value.strip()
        if not motherboard_info:
            motherboard_info["Error"] = "Information not available"
        return motherboard_info

    def _get_battery_info(self):
        """Get battery information"""
        import psutil
        try:
            battery = psutil.sensors_battery()
            if battery:
                return {
                    "Battery Percentage": f"{battery.percent}%",
                    "Power Plugged": "Yes" if battery.power_plugged else "No",
                    "Time Left": f"{battery.secsleft // 3600}h {(battery.secsleft % 3600) // 60}m" if battery.secsleft != psutil.POWER_TIME_UNLIMITED else "Unlimited"
                }
        except Exception:
            pass
        return None

    def _get_temperature_info(self):
        """Get temperature sensor information"""
        import psutil
        try:
            temps = psutil.sensors_temperatures()
            if temps:
                temp_info = {}
                for name, entries in temps.items():
                    temp_info[name] = {}
                    for entry in entries:
                        temp_info[name][entry.label or "Sensor"] = f"{entry.current:.1f}°C"
                        if entry.high:
                            temp_info[name][f"{entry.label or 'Sensor'} High"] = f"{entry.high:.1f}°C"
                        if entry.critical:
                            temp_info[name][f"{entry.label or 'Sensor'} Critical"] = f"{entry.critical:.1f}°C"
                return temp_info
        except Exception:
            pass
        return None
