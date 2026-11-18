"""WinMend diagnostics: collectors: devices."""

from __future__ import annotations

from winmend.diagnostics.reference import DEVICE_PROBLEM_CODES, describe_whea
import re
import time


class ProbeDevicesMixin:
    """DeepProbe methods grouped by responsibility."""

    # -- device and driver health ----------------------------------------

    def problem_devices(self):
        """Devices Windows has flagged, with their Device Manager problem code."""
        script = (
            "Get-PnpDevice -ErrorAction Stop | Where-Object { $_.Status -ne 'OK' -and "
            "$_.Status -ne 'Unknown' } | ForEach-Object { "
            "$c = (Get-PnpDeviceProperty -InstanceId $_.InstanceId "
            "-KeyName 'DEVPKEY_Device_ProblemCode' -ErrorAction SilentlyContinue).Data; "
            "Write-Output ($_.InstanceId + '|' + $_.Class + '|' + $_.FriendlyName + '|' "
            "+ $_.Status + '|' + [string]$c) }"
        )
        rc, rows, err = self._ps_rows(script, timeout=40)
        if rc != 0 and not rows:
            return {"available": False, "reason": err[:200]}
        devices = []
        for row in rows:
            if len(row) < 4:
                continue
            try:
                problem = int(row[4]) if len(row) > 4 and row[4].strip() else 0
            except ValueError:
                problem = 0
            meaning, remedy = DEVICE_PROBLEM_CODES.get(
                problem, ("Windows reported a problem with this device.", "Reinstall the driver."))
            devices.append({
                "instance_id": row[0].strip(),
                "class": row[1].strip(),
                "name": row[2].strip(),
                "status": row[3].strip(),
                "problem_code": problem,
                "meaning": meaning,
                "remedy": remedy,
            })
        return {"available": True, "devices": devices}

    def gpu_resets(self, days=14):
        """Display driver reset (TDR) events -- Display/4101."""
        script = (
            "$t=(Get-Date).AddDays(-%d);"
            "$e=Get-WinEvent -FilterHashtable @{LogName='System';StartTime=$t;Id=4101} "
            "-MaxEvents 60 -ErrorAction SilentlyContinue;"
            "foreach($x in $e){Write-Output ('TDR|'+$x.TimeCreated.ToString('s')+'|'+"
            "($x.Message -replace '[\\r\\n\\|]',' '))}"
        ) % max(1, int(days))
        ready, rows, _ = self._ps_events(script, timeout=25)
        events = []
        for row in rows:
            if row[0] != "TDR" or len(row) < 3:
                continue
            message = row[2]
            match = re.search(r"[Dd]isplay driver\s+([\w.]+)", message)
            events.append({"time": row[1], "driver": match.group(1) if match else "",
                           "message": message[:200]})
        return {"available": ready, "count": len(events), "events": events[:10]}

    def thermal_events(self, days=14):
        """CPU throttling events -- Kernel-Processor-Power/37."""
        script = (
            "$t=(Get-Date).AddDays(-%d);"
            "$e=Get-WinEvent -FilterHashtable @{LogName='System';StartTime=$t;"
            "ProviderName='Microsoft-Windows-Kernel-Processor-Power';Id=37} "
            "-MaxEvents 200 -ErrorAction SilentlyContinue;"
            "Write-Output ('throttle|'+@($e).Count)"
        ) % max(1, int(days))
        ready, rows, _ = self._ps_events(script, timeout=25)
        for row in rows:
            if row[0] == "throttle" and len(row) > 1 and row[1].strip().isdigit():
                return {"available": ready, "throttle_events": int(row[1].strip())}
        return {"available": False}

    def memory_config(self):
        """Installed RAM sticks, speed, and channel usage.

        Single-channel memory and un-applied XMP are two of the most common
        "why is this PC slower than it should be" answers, and neither shows up
        anywhere in Windows' own UI.
        """
        script = (
            "Get-CimInstance Win32_PhysicalMemory -ErrorAction Stop | ForEach-Object { "
            "Write-Output ([string]$_.Capacity + '|' + [string]$_.Speed + '|' + "
            "[string]$_.ConfiguredClockSpeed + '|' + [string]$_.DeviceLocator + '|' + "
            "[string]$_.Manufacturer) }"
        )
        rc, rows, err = self._ps_rows(script, timeout=25)
        if rc != 0 and not rows:
            return {"available": False, "reason": err[:200]}
        sticks = []
        for row in rows:
            if len(row) < 4:
                continue
            try:
                capacity = int(row[0]) / 1024 ** 3
            except (ValueError, TypeError):
                continue
            def _as_int(text):
                try:
                    return int(text)
                except (ValueError, TypeError):
                    return 0
            sticks.append({
                "gb": round(capacity, 1),
                "rated_mhz": _as_int(row[1]),
                "actual_mhz": _as_int(row[2]),
                "slot": row[3].strip(),
                "vendor": row[4].strip() if len(row) > 4 else "",
            })
        if not sticks:
            return {"available": False}
        total = sum(s["gb"] for s in sticks)
        rated = max((s["rated_mhz"] for s in sticks), default=0)
        actual = max((s["actual_mhz"] for s in sticks), default=0)
        return {
            "available": True,
            "sticks": sticks,
            "count": len(sticks),
            "total_gb": round(total, 1),
            "rated_mhz": rated,
            "actual_mhz": actual,
            # One stick means single channel: roughly half the bandwidth on
            # every desktop and laptop platform that supports two.
            "single_channel": len(sticks) == 1,
            "underclocked": bool(rated and actual and actual < rated * 0.9),
        }

    def disk_latency(self, seconds=2.0):
        """Average service time per disk operation, sampled live."""
        try:
            import psutil
        except Exception:
            return {"available": False}
        try:
            first = psutil.disk_io_counters()
            time.sleep(max(0.5, float(seconds)))
            second = psutil.disk_io_counters()
        except Exception:
            return {"available": False}
        if first is None or second is None:
            return {"available": False}
        ops = (second.read_count - first.read_count) + (second.write_count - first.write_count)
        busy_ms = 0
        for field in ("read_time", "write_time"):
            busy_ms += getattr(second, field, 0) - getattr(first, field, 0)
        # Below a couple of hundred operations the per-op average is dominated by
        # counter granularity, so it must not be reported as a health signal --
        # an idle NVMe and a stalling drive both round to nothing.
        if ops < 200:
            return {"available": True, "ops": max(0, ops), "avg_ms": None, "idle": True}
        return {
            "available": True,
            "ops": ops,
            "avg_ms": round(busy_ms / ops, 2),
            "idle": False,
        }

    def storage_removals(self, days=14):
        """Surprise-removal and device-reset events -- a loose or dying drive.

        Filtered to the storage providers on purpose: these event ids are reused
        by unrelated components, and an unfiltered count reads as disk trouble on
        a perfectly healthy PC.
        """
        script = (
            "$t=(Get-Date).AddDays(-%d);"
            "$e=Get-WinEvent -FilterHashtable @{LogName='System';StartTime=$t;"
            "Id=@(157,129)} -MaxEvents 100 -ErrorAction SilentlyContinue | "
            "Where-Object { $_.ProviderName -match 'disk|stor|partmgr|volmgr' };"
            "Write-Output ('removals|'+@($e).Count)"
        ) % max(1, int(days))
        ready, rows, _ = self._ps_events(script, timeout=25)
        for row in rows:
            if row[0] == "removals" and len(row) > 1 and row[1].strip().isdigit():
                return {"available": ready, "events": int(row[1].strip())}
        return {"available": False}

    def battery_wear(self):
        """Design vs full-charge capacity, i.e. how much battery is actually left."""
        script = (
            "$d=Get-CimInstance -Namespace root\\wmi -ClassName BatteryStaticData "
            "-ErrorAction Stop | Select-Object -First 1;"
            "$f=Get-CimInstance -Namespace root\\wmi -ClassName BatteryFullChargedCapacity "
            "-ErrorAction Stop | Select-Object -First 1;"
            "Write-Output ('cap|'+[string]$d.DesignedCapacity+'|'+[string]$f.FullChargedCapacity)"
        )
        rc, rows, _ = self._ps_rows(script, timeout=25)
        for row in rows:
            if row[0] != "cap" or len(row) < 3:
                continue
            try:
                design = float(row[1])
                full = float(row[2])
            except (ValueError, TypeError):
                continue
            if design <= 0 or full <= 0:
                continue
            return {
                "available": True,
                "design_mwh": int(design),
                "full_mwh": int(full),
                "wear_pct": round(max(0.0, (1 - full / design) * 100), 1),
            }
        return {"available": False}

    # -- hardware truth ----------------------------------------------------

    def whea_errors(self, days=30):
        """Hardware errors Windows itself recorded, split by what failed.

        ``event_log_errors`` already counts WHEA events, but a count cannot tell
        a corrected PCIe blip apart from a memory controller that is failing --
        and those two readings deserve opposite responses. The error *source* is
        the whole diagnosis here, so it is read out properly.
        """
        script = (
            "$t=(Get-Date).AddDays(-%d);"
            "$e=Get-WinEvent -FilterHashtable @{LogName='System';StartTime=$t;"
            "ProviderName='Microsoft-Windows-WHEA-Logger'} -MaxEvents 200 "
            "-ErrorAction SilentlyContinue;"
            "foreach($x in $e){$d=@{};try{foreach($p in ([xml]$x.ToXml()).Event.EventData.Data){"
            "$d[$p.Name]=[string]$p.'#text'}}catch{};"
            "Write-Output ('WHEA|'+$x.Id+'|'+$x.LevelDisplayName+'|'+"
            "$x.TimeCreated.ToString('s')+'|'+($x.Message -replace '[\\r\\n\\|]',' ')+'|'"
            "+($d['PrimaryDeviceName'] -replace '[\\r\\n\\|]',' ')+'|'"
            "+$d['ApicId']+'|'+$d['MCABank']+'|'+$d['Bus']+'|'+$d['Device']+'|'+$d['Function'])}"
        ) % max(1, int(days))
        ready, rows, _ = self._ps_events(script, timeout=30)
        if not ready:
            return {"available": False}
        events = []
        for row in rows:
            if row[0] != "WHEA" or len(row) < 5:
                continue
            try:
                event_id = int(row[1])
            except ValueError:
                continue
            area, meaning = describe_whea(event_id, row[4])
            events.append({
                "id": event_id,
                "level": (row[2] or "").strip(),
                "time": row[3],
                "area": area,
                "meaning": meaning,
                "device_name": row[5] if len(row) > 5 else "",
                "apic_id": row[6] if len(row) > 6 else "",
                "mca_bank": row[7] if len(row) > 7 else "",
                "pci_bus": row[8] if len(row) > 8 else "",
                "pci_device": row[9] if len(row) > 9 else "",
                "pci_function": row[10] if len(row) > 10 else "",
                "corrected": True if event_id in (17, 19, 47) else
                             False if event_id in (18, 46) else None,
            })
        areas = {}
        for event in events:
            areas[event["area"]] = areas.get(event["area"], 0) + 1
        uncorrected = [e for e in events if e["corrected"] is False]
        return {
            "available": True,
            "count": len(events),
            "uncorrected": len(uncorrected),
            "corrected": sum(e["corrected"] is True for e in events),
            "unknown_severity": sum(e["corrected"] is None for e in events),
            "areas": areas,
            "worst_area": max(areas, key=areas.get) if areas else "",
            "events": events[:12],
            "newest": events[0]["time"] if events else "",
        }

    def memory_diagnostic(self, days=180):
        """Whether Windows' own memory test has already found bad RAM.

        If the user has ever run it this is the most authoritative reading on
        the machine -- far better than inferring memory from crash patterns --
        and nothing in the engine was reading it.
        """
        script = (
            "$t=(Get-Date).AddDays(-%d);"
            "$e=Get-WinEvent -FilterHashtable @{LogName='System';StartTime=$t;"
            "ProviderName='Microsoft-Windows-MemoryDiagnostics-Results'} "
            "-MaxEvents 10 -ErrorAction SilentlyContinue;"
            "foreach($x in $e){Write-Output ('MD|'+$x.Id+'|'+$x.TimeCreated.ToString('s')+'|'+"
            "($x.Message -replace '[\\r\\n\\|]',' '))}"
        ) % max(1, int(days))
        ready, rows, _ = self._ps_events(script, timeout=25)
        if not ready:
            return {"available": False}
        runs = []
        for row in rows:
            if row[0] != "MD" or len(row) < 4:
                continue
            message = row[3]
            # 1201 is the detailed result, 1101 the summary. Both spell out
            # "detected hardware problems" when the RAM actually failed.
            failed = bool(re.search(
                r"detected hardware problem|hardware problems were detected", message, re.I))
            runs.append({"id": row[1], "time": row[2], "failed": failed,
                         "message": message[:200]})
        return {
            "available": True,
            "runs": len(runs),
            "ever_run": bool(runs),
            "failed": any(run["failed"] for run in runs),
            "last": runs[0] if runs else None,
        }

    def cpu_throttle(self):
        """Is the processor running at anything like its rated speed?

        A laptop pinned at 400 MHz feels broken but measures as *low* CPU load,
        so load alone reads it as healthy. The ratio of current to rated clock
        is what actually names that fault.
        """
        script = (
            "Get-CimInstance Win32_Processor | ForEach-Object {"
            "Write-Output ('CPU|'+$_.Name+'|'+$_.CurrentClockSpeed+'|'+$_.MaxClockSpeed+'|'+"
            "$_.LoadPercentage+'|'+$_.NumberOfCores)}"
        )
        rc, rows, _ = self._ps_rows(script, timeout=20)
        processors = []
        for row in rows:
            if row[0] != "CPU" or len(row) < 6:
                continue

            def _int(index):
                try:
                    return int(float(row[index]))
                except (ValueError, TypeError):
                    return None

            current, rated = _int(2), _int(3)
            ratio = (current / rated) if current and rated else None
            processors.append({
                "name": row[1].strip(),
                "current_mhz": current,
                "max_mhz": rated,
                "ratio": ratio,
                "load_pct": _int(4),
                "cores": _int(5),
            })
        if rc != 0 or not processors:
            return {"available": False}
        ratios = [p["ratio"] for p in processors if p["ratio"]]
        worst = min(ratios) if ratios else None
        return {
            "available": True,
            "processors": processors,
            "ratio": worst,
            # Every modern CPU idles far below its rated clock on purpose, so a
            # low reading only means something when the machine is also being
            # asked to work. The rule pairs this with load before it speaks.
            "low_clock": bool(worst is not None and worst < 0.45),
            "load_pct": max((p["load_pct"] or 0) for p in processors),
        }
