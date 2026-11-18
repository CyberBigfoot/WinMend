"""WinMend diagnostics: hardware: graphics."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from winmend.diagnostics.hardware.reference import LIVE_KERNEL_EVENTS, _age_days, _num, _tri
import os
import re
import time
try:  # pragma: no cover - absent only on non-Windows, where every probe no-ops
    import winreg
except ImportError:  # pragma: no cover
    winreg = None


class HardwareGraphicsMixin:
    """HardwareProbe methods grouped by responsibility."""

    # ---- graphics ---------------------------------------------------------

    def gpu_hardware(self):
        """Each display adapter, its driver, and the crash-recovery settings.

        ``display_config`` already answers "is Windows using the basic display
        driver". This answers the harder questions: how old the real driver is,
        whether the adapter is reporting a device error, and -- the part that
        matters most -- whether Timeout Detection and Recovery has been switched
        off. A machine with ``TdrLevel`` set to 0 does not recover from a hung
        GPU, it hard-locks; and because that hides the symptom rather than
        fixing it, the underlying fault has usually been getting worse for
        months by the time anyone looks.
        """
        script = self._SANITISE + (
            "Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | "
            "ForEach-Object { $d='';try{$d=$_.DriverDate.ToString('yyyy-MM-dd')}catch{};"
            "Write-Output ('G|'+(S $_.Name)+'|'+(S $_.DriverVersion)+'|'+$d+'|'"
            "+[string]$_.AdapterRAM+'|'+(S $_.Status)+'|'+[string]$_.ConfigManagerErrorCode+'|'"
            "+(S $_.VideoProcessor)+'|'+[string]$_.CurrentRefreshRate+'|'+(S $_.PNPDeviceID)) }"
        )
        rc, rows, err = self._ps_rows(script, timeout=35)
        adapters = []
        for row in rows:
            if row[0] != "G" or len(row) < 7:
                continue
            vram = _num(row[4])
            adapters.append({
                "name": row[1].strip(),
                "driver_version": row[2].strip(),
                "driver_date": row[3].strip(),
                "driver_age_days": _age_days(row[3].strip()),
                # AdapterRAM is a signed 32-bit field, so anything above 4 GB
                # wraps and reports nonsense. Reporting it as unknown beats
                # reporting a 24 GB card as having 0 MB.
                "vram_mb": (round(vram / (1024 ** 2)) if vram and 0 < vram < 2 ** 32 else None),
                "status": row[5].strip(),
                "error_code": _num(row[6], 0) or 0,
                "processor": row[7].strip() if len(row) > 7 else "",
                "refresh_hz": _num(row[8]) if len(row) > 8 else None,
                "pnp_id": row[9].strip() if len(row) > 9 else "",
            })

        tdr = {}
        if winreg is not None:
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers",
                ) as key:
                    for name in ("TdrLevel", "TdrDelay", "TdrDdiDelay", "HwSchMode"):
                        try:
                            tdr[name] = int(winreg.QueryValueEx(key, name)[0])
                        except (OSError, ValueError, TypeError):
                            pass
            except OSError:
                pass
        if not adapters:
            return {"available": False, "reason": (err or "")[:200]}
        return {
            "available": True,
            "adapters": adapters,
            "count": len(adapters),
            "faulted": [a for a in adapters if a["error_code"]],
            "tdr": tdr,
            # The default is 3 (recover and restart the driver). 0 means
            # detection is off entirely.
            "tdr_disabled": tdr.get("TdrLevel") == 0,
            # A raised delay is the standard "stop my GPU crashing" advice from
            # forums. It does not stop anything crashing; it just waits longer
            # before admitting it.
            "tdr_delay_raised": bool(tdr.get("TdrDelay") and tdr["TdrDelay"] > 10),
            # 2 = hardware-accelerated GPU scheduling on. It is a common cause
            # of instability on older cards and is trivially reversible.
            "hags_on": tdr.get("HwSchMode") == 2,
            "oldest_driver_days": max(
                (a["driver_age_days"] for a in adapters
                 if a["driver_age_days"] is not None), default=None),
        }

    def live_kernel_events(self, days=60):
        """Faults captured without a bluescreen -- and what they blame.

        Windows quietly writes a LiveKernelEvent when a component fails hard
        enough to be worth a dump but recovers well enough not to bugcheck. Users
        never see them, so they accumulate for months while someone reinstalls
        drivers over and over.

        The code is the diagnosis. 117 is the graphics driver timing out, which a
        driver change genuinely fixes. 141 is the GPU never answering at all,
        which no driver change has ever fixed -- that is power, seating, or the
        card. Telling a user to reinstall their driver for a 141 is exactly the
        wasted afternoon this scan exists to prevent.
        """
        found, codes = [], {}
        root = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "LiveKernelReports"
        cutoff = time.time() - max(1, int(days)) * 86400
        # Enumerating this folder needs elevation. Without it the walk yields
        # nothing, which looks exactly like a machine that has never had one --
        # so whether it could be read is recorded separately from what it held.
        readable = False
        try:
            if root.is_dir():
                for entry in root.rglob("*.dmp"):
                    readable = True
                    try:
                        stat = entry.stat()
                    except OSError:
                        continue
                    if stat.st_mtime < cutoff:
                        continue
                    # Files are named like "WATCHDOG-20240103-1234.dmp"; the
                    # parent folder carries the component.
                    component = entry.parent.name if entry.parent != root else ""
                    found.append({
                        "file": entry.name,
                        "component": component,
                        "mb": round(stat.st_size / (1024 ** 2), 1),
                        "time": datetime.fromtimestamp(
                            stat.st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
                    })
        except OSError:
            pass

        # The event log carries the numeric code, which the file names do not.
        script = (
            "$t=(Get-Date).AddDays(-%d);"
            "$e=Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=$t;"
            "ProviderName='Windows Error Reporting';Id=1001} -MaxEvents 400 "
            "-ErrorAction SilentlyContinue;"
            "foreach($x in $e){ $m=([string]$x.Message) -replace '[\\r\\n\\|]',' ';"
            "if($m -match 'LiveKernelEvent'){"
            "Write-Output ('L|'+$x.TimeCreated.ToString('s')+'|'+$m)}}"
        ) % max(1, int(days))
        ready, rows, err = self._ps_events(script, timeout=45)

        # One fault produces many of these. Windows re-reports the same capture
        # every time it works its error queue, and a single incident writes a
        # separate report for each dump it attached -- on a real machine 179
        # report rows turned out to be seven dump files and about four actual
        # events. Counting the rows would have called a driver's bad evening a
        # dying graphics card, so the incident is the unit, not the report.
        incidents, raw_rows = {}, 0
        for row in rows:
            if row[0] != "L" or len(row) < 3:
                continue
            raw_rows += 1
            message = row[2]
            # The code is the first entry of the report's problem signature, in
            # hex: "Event Name: LiveKernelEvent ... P1: 141". It is not appended
            # to the event name, which is where it looks like it should be.
            match = re.search(r"\bP1:\s*([0-9a-fA-F]{1,8})\b", message)
            code = (match.group(1).lower().lstrip("0") or "0") if match else ""
            # The attached dump names the incident, and its filename carries the
            # moment the fault actually happened -- which is what matters, not
            # when Windows got round to filing the report.
            dump = re.search(r"LiveKernelReports.([^\\/]+).([^\s]+\.dmp)", message)
            component = dump.group(1) if dump else ""
            filename = dump.group(2) if dump else ""
            when = row[1]
            stamped = re.search(r"(\d{8})-(\d{4})", filename)
            if stamped:
                date, clock = stamped.group(1), stamped.group(2)
                when = (f"{date[:4]}-{date[4:6]}-{date[6:]}"
                        f"T{clock[:2]}:{clock[2:]}:00")
            key = filename or f"{code}@{row[1]}"
            title, meaning, blame = LIVE_KERNEL_EVENTS.get(
                code,
                (f"Live kernel event {code}" if code else "Live kernel event",
                 "Windows captured a fault without crashing. This code is not one with "
                 "a settled meaning, so it is reported rather than interpreted.", ""))
            existing = incidents.get(key)
            # Several dumps can share one incident; keep whichever carries a
            # code we recognise so the incident is not filed as unattributed
            # because its sibling report was the vague one.
            if existing and not (blame and not existing["blame"]):
                existing["reports"] += 1
                continue
            incidents[key] = {
                "time": when, "code": code, "title": title, "meaning": meaning,
                "blame": blame, "component": component, "file": filename,
                "reports": (existing or {}).get("reports", 0) + 1,
            }

        if not ready and not found:
            return {"available": False, "reason": (err or "")[:200]}
        events = sorted(incidents.values(), key=lambda e: e["time"], reverse=True)
        for event in events:
            if event["code"]:
                codes[event["code"]] = codes.get(event["code"], 0) + 1
        hardware = [e for e in events if e["blame"] == "hardware"]
        driver = [e for e in events if e["blame"] == "driver"]
        # Faults spread across many days are an ongoing problem; a cluster on
        # one evening is an episode that has since passed. The difference
        # changes the advice completely, so it is measured rather than implied.
        days_seen = {e["time"][:10] for e in events if e["time"]}
        # Counted over the attributed faults only. Pairing a hardware-fault
        # count with a day-span taken from every incident produced the line
        # "1 hardware fault captured across 2 days", which cannot be true.
        hardware_days = {e["time"][:10] for e in hardware if e["time"]}
        newest_hardware = max((e["time"] for e in hardware), default="")
        newest = max((e["time"] for e in events), default="")
        return {
            "available": True,
            "reports": found[:15],
            "report_count": len(found),
            "reports_readable": readable,
            "events": events[:15],
            "event_count": len(events),
            "report_rows": raw_rows,
            "codes": codes,
            "hardware_faults": len(hardware),
            "driver_faults": len(driver),
            # Incidents whose code means nothing definite. A machine can carry
            # plenty of these and be entirely healthy, so they are counted apart
            # from the ones that justify an action.
            "unattributed": len(events) - len(hardware) - len(driver),
            "distinct_days": len(days_seen),
            "hardware_days": len(hardware_days),
            "newest": newest,
            "newest_days_ago": _age_days(newest),
            "hardware_newest_days_ago": _age_days(newest_hardware),
            "worst": hardware[0] if hardware else (driver[0] if driver else None),
            "days": int(days),
        }

    def gpu_vendor_telemetry(self):
        """NVIDIA's own telemetry, when an NVIDIA card is present.

        ``nvidia-smi`` ships with every NVIDIA driver, so this costs nothing to
        try and is simply unavailable elsewhere. What it gives that Windows never
        will: memory ECC error counts, retired pages, and the negotiated PCIe
        link width.

        That last one earns the whole collector. A card negotiated down to x1 or
        x4 when it is capable of x16 is running at a fraction of its bandwidth,
        and the cause is physical every time -- a partly seated card, a dirty
        slot, a riser. It presents as "my games got slow", it is invisible to
        every software diagnostic, and it is fixed by reseating the card.
        """
        fields = ("name,driver_version,pcie.link.gen.current,pcie.link.gen.max,"
                  "pcie.link.width.current,pcie.link.width.max,temperature.gpu,"
                  "memory.total,memory.used,ecc.errors.uncorrected.aggregate.total,"
                  "clocks_throttle_reasons.active,power.draw,power.limit")
        candidates = ["nvidia-smi"]
        program_files = os.environ.get("ProgramW6432") or os.environ.get("ProgramFiles")
        if program_files:
            candidates.append(str(Path(program_files) / "NVIDIA Corporation"
                                  / "NVSMI" / "nvidia-smi.exe"))
        candidates.append(str(Path(os.environ.get("SystemRoot", r"C:\Windows"))
                              / "System32" / "nvidia-smi.exe"))
        for executable in candidates:
            try:
                rc, out, err = self._run(
                    [executable, f"--query-gpu={fields}",
                     "--format=csv,noheader,nounits"], timeout=25)
            except Exception:
                continue
            if rc != 0 or not (out or "").strip():
                continue
            gpus = []
            for line in out.splitlines():
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 7:
                    continue

                def value(index):
                    if index >= len(parts):
                        return None
                    text = parts[index]
                    # nvidia-smi prints "[N/A]" for anything the card or the
                    # driver does not implement -- consumer cards have no ECC.
                    return None if text.startswith("[") or not text else text

                width_now = _num(value(4))
                width_max = _num(value(5))
                gpus.append({
                    "name": parts[0],
                    "driver": parts[1],
                    "pcie_gen": _num(value(2)),
                    "pcie_gen_max": _num(value(3)),
                    "pcie_width": width_now,
                    "pcie_width_max": width_max,
                    "temperature_c": _num(value(6)),
                    "vram_total_mb": _num(value(7)),
                    "vram_used_mb": _num(value(8)),
                    "ecc_uncorrected": _num(value(9)),
                    "throttle": (value(10) or "").strip(),
                    "power_w": _num(value(11)),
                    "power_limit_w": _num(value(12)),
                    "link_degraded": bool(width_now and width_max and width_now < width_max),
                })
            if not gpus:
                continue
            return {
                "available": True,
                "vendor": "nvidia",
                "gpus": gpus,
                "degraded_links": [g for g in gpus if g["link_degraded"]],
                "ecc_errors": sum(g["ecc_uncorrected"] or 0 for g in gpus),
                "hottest_c": max((g["temperature_c"] for g in gpus
                                  if g["temperature_c"] is not None), default=None),
            }
        # No NVIDIA card, or no driver. Both are perfectly normal, and neither
        # says anything at all about the health of an AMD or Intel GPU.
        return {"available": False, "reason": "nvidia-smi not present"}

    def display_links(self):
        """The monitors themselves: who made them, and how they are connected.

        A monitor that keeps blanking is one of the hardest complaints to place,
        because the cable, the port, the GPU and the panel all present the same
        way. Reading the connection technology at least separates the cases worth
        testing: a panel on DisplayPort that keeps dropping is a different
        conversation from the same panel on a converter.
        """
        script = self._SANITISE + (
            "try{Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorID "
            "-ErrorAction Stop | ForEach-Object {"
            " $n=''; if($_.UserFriendlyName){$n=-join ($_.UserFriendlyName "
            "| Where-Object {$_ -gt 0} | ForEach-Object {[char]$_})};"
            " $m=''; if($_.ManufacturerName){$m=-join ($_.ManufacturerName "
            "| Where-Object {$_ -gt 0} | ForEach-Object {[char]$_})};"
            " Write-Output ('M|'+(S $_.InstanceName)+'|'+(S $n)+'|'+(S $m)+'|'"
            "+[string]$_.YearOfManufacture+'|'+[string]$_.Active) }}catch{};"
            "try{Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorConnectionParams "
            "-ErrorAction Stop | ForEach-Object { Write-Output ('C|'+(S $_.InstanceName)+'|'"
            "+[string]$_.VideoOutputTechnology) }}catch{}"
        )
        rc, rows, err = self._ps_rows(script, timeout=30)
        # The subset of the WMI enumeration users can act on. Anything not
        # listed is reported by number rather than guessed at.
        technologies = {
            0: "VGA", 1: "S-Video", 2: "Composite", 3: "Component", 4: "DVI",
            5: "HDMI", 6: "LVDS", 8: "D-Jpn", 9: "SDI",
            10: "DisplayPort (external)", 11: "DisplayPort (embedded)",
            12: "UDI (external)", 13: "UDI (embedded)", 14: "SDTV dongle",
            15: "Miracast", 16: "Indirect wired", 2147483648: "Internal",
        }
        monitors, links = {}, {}
        for row in rows:
            if row[0] == "M" and len(row) >= 5:
                monitors[row[1].strip()] = {
                    "instance": row[1].strip(),
                    "name": row[2].strip(),
                    "vendor": row[3].strip(),
                    "year": _num(row[4]),
                    "active": _tri(row[5]) if len(row) > 5 else None,
                }
            elif row[0] == "C" and len(row) >= 3:
                links[row[1].strip()] = _num(row[2])
        if not monitors:
            return {"available": False, "reason": (err or "")[:200]}
        for instance, monitor in monitors.items():
            technology = links.get(instance)
            monitor["connection_id"] = technology
            monitor["connection"] = technologies.get(
                technology, f"type {technology}" if technology is not None else "")
        panels = list(monitors.values())
        return {
            "available": True,
            "monitors": panels,
            "count": len(panels),
            "active": sum(1 for m in panels if m["active"]),
            "connections": sorted({m["connection"] for m in panels if m["connection"]}),
        }
