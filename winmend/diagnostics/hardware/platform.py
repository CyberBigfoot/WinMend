"""WinMend diagnostics: hardware: platform."""

from __future__ import annotations

from winmend.diagnostics.hardware.reference import _age_days, _num, _tri
try:  # pragma: no cover - absent only on non-Windows, where every probe no-ops
    import winreg
except ImportError:  # pragma: no cover
    winreg = None


class HardwarePlatformMixin:
    """HardwareProbe methods grouped by responsibility."""

    # ---- the platform itself ---------------------------------------------

    def component_devices(self):
        """Present devices, including chipset, USB, audio and network controllers.

        A device problem code describes Windows' ability to use the device; it
        does not establish physical failure. Missing codes stay unknown, and
        disconnected devices are excluded instead of being reported as broken.
        """
        script = self._SANITISE + (
            "$ErrorActionPreference='Stop';"
            "$devices=@(Get-CimInstance Win32_PnPEntity -ErrorAction Stop);"
            "foreach($d in $devices){if($d.Present -eq $true){"
            "Write-Output ('P|'+(S $d.Name)+'|'+(S $d.PNPClass)+'|'"
            "+(S $d.DeviceID)+'|'+(S $d.ConfigManagerErrorCode)+'|'"
            "+(S $d.Status)+'|'+(S $d.Manufacturer))}};"
            "Write-Output 'COMPONENTS_OK|1'"
        )
        rc, rows, err = self._ps_rows(script, timeout=45)
        if rc != 0 or not any(row and row[0] == "COMPONENTS_OK" for row in rows):
            return {"available": False, "reason": (err or "Device query did not complete")[:200]}
        groups = {"system": "motherboard", "processor": "cpu", "display": "graphics",
                  "diskdrive": "storage", "hdc": "storage", "scsiadapter": "storage",
                  "net": "network", "bluetooth": "network", "media": "audio",
                  "audioendpoint": "audio", "usb": "usb", "battery": "power",
                  "monitor": "display"}
        devices = []
        seen = set()
        for row in rows:
            if not row or row[0] != "P" or len(row) < 7 or row[3] in seen:
                continue
            seen.add(row[3])
            code = _num(row[4])
            # Code 45 is a disconnected device even if a stale provider said present.
            if code == 45:
                continue
            devices.append({"name": row[1] or "Unnamed device", "class": row[2],
                            "id": row[3], "code": code, "status": row[5],
                            "vendor": row[6], "component": groups.get(row[2].lower(), "other")})
        return {"available": True, "devices": devices, "count": len(devices),
                "problems": [d for d in devices if d["code"] not in (None, 0)],
                "unknown": sum(d["code"] is None for d in devices)}

    def firmware_info(self):
        """The board, the firmware on it, and how far behind that firmware is.

        Nothing else in the sweep identifies the machine itself, and that turns
        out to matter: a board still on its launch-day firmware is behind every
        microcode, memory-training and errata fix its vendor has shipped since.
        "The BIOS is four years old" is the entire diagnosis for a real share of
        machines that are unstable with no software fault to find.
        """
        script = self._SANITISE + (
            "$b=Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue;"
            "$m=Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue;"
            "$c=Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue;"
            "$d='';try{$d=$b.ReleaseDate.ToString('yyyy-MM-dd')}catch{};"
            "Write-Output ('B|'+(S $b.Manufacturer)+'|'+(S $b.SMBIOSBIOSVersion)+'|'+$d);"
            "Write-Output ('M|'+(S $m.Manufacturer)+'|'+(S $m.Product)+'|'+(S $m.Version));"
            "Write-Output ('C|'+(S $c.Manufacturer)+'|'+(S $c.Model)+'|'+(S $c.SystemFamily));"
            # Confirm-SecureBootUEFI throws on a legacy-BIOS machine rather than
            # returning false, so the exception is itself the reading: it is the
            # only thing here that reports the firmware mode.
            "$sb='unsupported';"
            "try{ if(Confirm-SecureBootUEFI){$sb='on'}else{$sb='off'} }catch{};"
            "Write-Output ('S|'+$sb)"
        )
        rc, rows, err = self._ps_rows(script, timeout=35)
        info = {}
        for row in rows:
            tag = row[0]
            if tag == "B" and len(row) >= 4:
                info["bios_vendor"] = row[1].strip()
                info["bios_version"] = row[2].strip()
                info["bios_date"] = row[3].strip()
            elif tag == "M" and len(row) >= 4:
                info["board_vendor"] = row[1].strip()
                info["board_model"] = row[2].strip()
                info["board_version"] = row[3].strip()
            elif tag == "C" and len(row) >= 4:
                info["system_vendor"] = row[1].strip()
                info["system_model"] = row[2].strip()
                info["system_family"] = row[3].strip()
            elif tag == "S" and len(row) >= 2:
                info["secure_boot"] = row[1].strip()
        if not info:
            return {"available": False, "reason": (err or "")[:200]}
        age = _age_days(info.get("bios_date"))
        info["bios_age_days"] = age
        info["bios_age_years"] = round(age / 365.25, 1) if age is not None else None
        # Secure Boot being reportable at all implies UEFI: the cmdlet only
        # succeeds as a real call on a UEFI machine.
        info["uefi"] = info.get("secure_boot") in ("on", "off")
        info["board"] = " ".join(
            p for p in (info.get("board_vendor"), info.get("board_model")) if p).strip()
        info["available"] = True
        return info

    def memory_modules(self):
        """Every DIMM by slot: size, rated speed, running speed, part number.

        ``memory_config`` reports the array as a whole, which is the right
        summary but the wrong resolution for a fault. Memory fails one module at
        a time, so the per-slot record is what makes a fault addressable -- and
        two sticks with different part numbers or different rated speeds is a
        real instability cause that will never appear in any log.
        """
        script = self._SANITISE + (
            "Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue | "
            "ForEach-Object { Write-Output ('D|'+(S $_.DeviceLocator)+'|'+(S $_.BankLabel)"
            "+'|'+[string]$_.Capacity+'|'+[string]$_.Speed+'|'+[string]$_.ConfiguredClockSpeed"
            "+'|'+(S $_.Manufacturer)+'|'+(S $_.PartNumber)+'|'+[string]$_.SMBIOSMemoryType"
            "+'|'+[string]$_.ConfiguredVoltage) };"
            "Get-CimInstance Win32_PhysicalMemoryArray -ErrorAction SilentlyContinue | "
            "ForEach-Object { Write-Output ('A|'+[string]$_.MemoryErrorCorrection+'|'"
            "+[string]$_.MemoryDevices+'|'+[string]$_.MaxCapacityEx) }"
        )
        rc, rows, err = self._ps_rows(script, timeout=35)
        modules, array = [], {}
        for row in rows:
            if row[0] == "D" and len(row) >= 8:
                capacity = _num(row[3])
                modules.append({
                    "slot": row[1].strip() or "?",
                    "bank": row[2].strip(),
                    "gb": round(capacity / (1024 ** 3), 1) if capacity else None,
                    "rated_mhz": _num(row[4]),
                    "running_mhz": _num(row[5]),
                    "vendor": row[6].strip(),
                    "part": row[7].strip(),
                    "type": _num(row[8]) if len(row) > 8 else None,
                    "voltage_mv": _num(row[9]) if len(row) > 9 else None,
                })
            elif row[0] == "A" and len(row) >= 3:
                array = {
                    "error_correction": _num(row[1]),
                    "slots_total": _num(row[2]),
                    "max_capacity_kb": _num(row[3]) if len(row) > 3 else None,
                }
        if not modules:
            return {"available": False, "reason": (err or "")[:200]}

        parts = {m["part"] for m in modules if m["part"]}
        vendors = {m["vendor"] for m in modules if m["vendor"]}
        sizes = {m["gb"] for m in modules if m["gb"]}
        rated = {m["rated_mhz"] for m in modules if m["rated_mhz"]}
        running = [m["running_mhz"] for m in modules if m["running_mhz"]]
        slots_total = array.get("slots_total")
        return {
            "available": True,
            "modules": modules,
            "count": len(modules),
            "slots_total": slots_total,
            "slots_free": (slots_total - len(modules)
                           if isinstance(slots_total, int) and slots_total >= len(modules)
                           else None),
            # 4, 5 and 6 are the parity and ECC values in the SMBIOS table; 3 is
            # an explicit "none" and 2 means the firmware declined to say.
            "ecc": array.get("error_correction") in (4, 5, 6),
            "error_correction": array.get("error_correction"),
            # Mixed modules are a fact, not a fault: plenty of machines run them
            # for years. It is only ever weighed next to an instability signal.
            "mixed_parts": len(parts) > 1,
            "mixed_vendors": len(vendors) > 1,
            "mixed_sizes": len(sizes) > 1,
            "mixed_rated": len(rated) > 1,
            "rated_mhz": max(rated) if rated else None,
            "running_mhz": max(running) if running else None,
            # Running under the sticks' rating is the normal JEDEC default when
            # XMP/EXPO is off. Worth reporting; never a fault on its own.
            "underclocked": bool(rated and running and max(running) < max(rated) * 0.92),
        }

    def cpu_details(self):
        """Processor identity, core layout, and the microcode it is running.

        The microcode revision is the interesting part. Windows loads its own
        microcode at boot when the firmware's copy is older, and it records both
        numbers. When they differ, the board's firmware is measurably behind the
        errata fixes the CPU vendor has already shipped -- which turns "update
        the BIOS" from a guess into a supported recommendation.
        """
        if winreg is None:
            return {"available": False, "reason": "not Windows"}
        info = {}
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            ) as key:
                for name, field in (("ProcessorNameString", "name"),
                                    ("Identifier", "identifier"),
                                    ("VendorIdentifier", "vendor")):
                    try:
                        info[field] = str(winreg.QueryValueEx(key, name)[0] or "").strip()
                    except OSError:
                        pass
                try:
                    info["mhz"] = int(winreg.QueryValueEx(key, "~MHz")[0])
                except (OSError, ValueError, TypeError):
                    pass

                def revision(name):
                    """A microcode revision, stored as a little-endian blob.

                    Only the high half of the eight-byte value carries the
                    revision; the low half is zero on every machine that
                    reports one at all.
                    """
                    try:
                        raw = winreg.QueryValueEx(key, name)[0]
                    except OSError:
                        return None
                    if isinstance(raw, int):
                        return raw or None
                    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 8:
                        return None
                    return int.from_bytes(bytes(raw[4:8]), "little") or None

                info["microcode"] = revision("Update Revision")
                info["microcode_firmware"] = revision("Previous Update Revision")
        except OSError as exc:
            return {"available": False, "reason": str(exc)[:200]}
        if not info:
            return {"available": False}
        try:
            import psutil
            info["cores_physical"] = psutil.cpu_count(logical=False)
            info["cores_logical"] = psutil.cpu_count(logical=True)
        except Exception:
            pass
        current, firmware = info.get("microcode"), info.get("microcode_firmware")
        # Windows only records a "previous" revision when it actually replaced
        # one, so a higher current value is the OS patching around the board.
        info["microcode_patched_by_os"] = bool(current and firmware and current > firmware)
        info["available"] = True
        return info

    def tpm_state(self):
        """Whether the TPM is present, owned, and working.

        A TPM that has slipped into an unowned or failed state does not announce
        itself. It surfaces days later as BitLocker demanding a recovery key at
        every boot, or Windows Hello quietly refusing to enrol.
        """
        script = self._SANITISE + (
            "try{$t=Get-Tpm -ErrorAction Stop;"
            "Write-Output ('T|'+[string]$t.TpmPresent+'|'+[string]$t.TpmReady+'|'"
            "+[string]$t.TpmEnabled+'|'+[string]$t.TpmActivated+'|'+[string]$t.TpmOwned+'|'"
            "+(S $t.ManufacturerIdTxt)+'|'+(S $t.ManufacturerVersion))}"
            "catch{Write-Output ('E|'+(S $_.Exception.Message))}"
        )
        rc, rows, err = self._ps_rows(script, timeout=25)
        for row in rows:
            if row[0] == "T" and len(row) >= 6:
                return {
                    "available": True,
                    "present": _tri(row[1]),
                    "ready": _tri(row[2]),
                    "enabled": _tri(row[3]),
                    "activated": _tri(row[4]),
                    "owned": _tri(row[5]),
                    "vendor": row[6].strip() if len(row) > 6 else "",
                    "version": row[7].strip() if len(row) > 7 else "",
                }
        # Get-Tpm needs elevation, and without it the failure says nothing about
        # the TPM. This must never be allowed to read as "there is no TPM".
        reason = next((r[1] for r in rows if r[0] == "E" and len(r) > 1), err or "")
        return {"available": False, "reason": str(reason)[:200]}

    def sensor_readings(self):
        """Fans, temperatures and voltages, from whatever the board exposes.

        Consumer boards very often expose none of this to Windows -- the sensors
        are real, but they sit behind a vendor driver rather than in WMI. Four
        sources are tried because they fail independently, and the thermal-zone
        performance counter in particular is populated on many machines where
        the ACPI class is empty.

        An empty result means "this board tells Windows nothing", which is
        reported as exactly that rather than as healthy.
        """
        script = self._SANITISE + (
            # Tenths of a Kelvin, per the ACPI spec.
            "try{Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature "
            "-ErrorAction Stop | ForEach-Object { Write-Output ('Z|'+(S $_.InstanceName)+'|'"
            "+[string]$_.CurrentTemperature) }}catch{};"
            "try{Get-CimInstance Win32_PerfFormattedData_Counters_ThermalZoneInformation "
            "-ErrorAction Stop | ForEach-Object { Write-Output ('P|'+(S $_.Name)+'|'"
            "+[string]$_.HighPrecisionTemperature+'|'+[string]$_.PercentPassiveLimit+'|'"
            "+[string]$_.ThrottleReasons) }}catch{};"
            "try{Get-CimInstance Win32_Fan -ErrorAction Stop | ForEach-Object { "
            "Write-Output ('F|'+(S $_.Name)+'|'+[string]$_.DesiredSpeed+'|'+(S $_.Status)+'|'"
            "+[string]$_.ActiveCooling) }}catch{};"
            "try{Get-CimInstance Win32_VoltageProbe -ErrorAction Stop | ForEach-Object { "
            "Write-Output ('V|'+(S $_.Name)+'|'+[string]$_.CurrentReading+'|'"
            "+[string]$_.LowerThresholdCritical+'|'+[string]$_.UpperThresholdCritical) }}catch{};"
            "try{Get-CimInstance Win32_TemperatureProbe -ErrorAction Stop | ForEach-Object { "
            "Write-Output ('T|'+(S $_.Name)+'|'+[string]$_.CurrentReading) }}catch{}"
        )
        rc, rows, err = self._ps_rows(script, timeout=40)
        zones, fans, voltages, throttling = [], [], [], []
        for row in rows:
            tag = row[0]
            if tag == "Z" and len(row) >= 3:
                deci_kelvin = _num(row[2])
                if deci_kelvin:
                    celsius = round(deci_kelvin / 10.0 - 273.15, 1)
                    # Below freezing or above boiling is a placeholder value, not
                    # a reading. Boards that do not implement the method still
                    # return something.
                    if -20 < celsius < 130:
                        zones.append({"name": row[1].strip(), "celsius": celsius,
                                      "source": "acpi"})
            elif tag == "P" and len(row) >= 3:
                deci_kelvin = _num(row[2])
                if deci_kelvin:
                    celsius = round(deci_kelvin / 10.0 - 273.15, 1)
                    if -20 < celsius < 130:
                        zones.append({"name": row[1].strip(), "celsius": celsius,
                                      "source": "counter"})
                limit = _num(row[3]) if len(row) > 3 else None
                # A passive limit below 100% means the zone is actively holding
                # the part back to keep it cool: throttling, measured directly.
                if limit is not None and 0 < limit < 100:
                    throttling.append({"name": row[1].strip(), "passive_limit_pct": limit})
            elif tag == "F" and len(row) >= 4:
                fans.append({
                    "name": row[1].strip(),
                    "rpm": _num(row[2]),
                    "status": row[3].strip(),
                    "active": _tri(row[4]) if len(row) > 4 else None,
                })
            elif tag == "V" and len(row) >= 3:
                reading = _num(row[2])
                voltages.append({
                    "name": row[1].strip(),
                    "millivolts": reading,
                    "low_critical": _num(row[3]) if len(row) > 3 else None,
                    "high_critical": _num(row[4]) if len(row) > 4 else None,
                })
            elif tag == "T" and len(row) >= 3:
                reading = _num(row[2])
                if reading is not None:
                    # Win32_TemperatureProbe reports tenths of a degree.
                    celsius = round(reading / 10.0, 1)
                    if -20 < celsius < 130:
                        zones.append({"name": row[1].strip(), "celsius": celsius,
                                      "source": "probe"})

        hottest = max(zones, key=lambda z: z["celsius"]) if zones else None
        stopped = [f for f in fans
                   if f["rpm"] == 0 or (f["status"] and f["status"].lower() not in
                                        ("ok", "", "unknown"))]
        out_of_range = []
        for volt in voltages:
            reading, low, high = volt["millivolts"], volt["low_critical"], volt["high_critical"]
            if reading is None or not reading:
                continue
            if (low and reading < low) or (high and reading > high):
                out_of_range.append(volt)
        return {
            # "Available" here means the board answered at all. It is the whole
            # point of this collector that most do not.
            "available": bool(zones or fans or voltages),
            "zones": zones,
            "fans": fans,
            "voltages": voltages,
            "throttling": throttling,
            "hottest": hottest,
            "hottest_c": hottest["celsius"] if hottest else None,
            "stopped_fans": stopped,
            "voltage_alarms": out_of_range,
            "exposes_nothing": not (zones or fans or voltages),
        }

    def power_events(self, days=60):
        """Unexpected power losses, separated from ordinary crashes.

        This is the most under-read signal in the whole event log. Kernel-Power
        event 41 fires for every unclean shutdown, and tools that count it report
        "your PC crashed N times" -- but the event's own fields say *how* it went
        down, and the answers mean completely different things:

        * a bugcheck code was recorded -- it bluescreened, and the crash dump is
          the real evidence;
        * the power button was held -- a person did that;
        * neither -- the machine lost power without executing a single
          instruction of shutdown path. Nothing in software can do that. It is
          the power supply, a thermal cutoff, or the board.

        The third case is the one worth finding, and it is invisible to a count.
        """
        script = (
            "$t=(Get-Date).AddDays(-%d);"
            "$e=Get-WinEvent -FilterHashtable @{LogName='System';StartTime=$t;"
            "ProviderName='Microsoft-Windows-Kernel-Power';Id=41} -MaxEvents 60 "
            "-ErrorAction SilentlyContinue;"
            "foreach($x in $e){"
            "  $d=@{};"
            "  try{ foreach($p in ([xml]$x.ToXml()).Event.EventData.Data){"
            "    $d[$p.Name]=[string]$p.'#text' } }catch{};"
            "  Write-Output ('K|'+$x.TimeCreated.ToString('s')+'|'+[string]$d['BugcheckCode']"
            "+'|'+[string]$d['PowerButtonTimestamp']+'|'+[string]$d['SleepInProgress'])"
            "};"
            "$s=Get-WinEvent -FilterHashtable @{LogName='System';StartTime=$t;Id=6008} "
            "-MaxEvents 40 -ErrorAction SilentlyContinue;"
            "foreach($x in $s){Write-Output ('D|'+$x.TimeCreated.ToString('s'))}"
        ) % max(1, int(days))
        ready, rows, err = self._ps_events(script, timeout=45)
        if not ready:
            return {"available": False, "reason": (err or "")[:200]}

        events, dirty = [], []
        for row in rows:
            if row[0] == "K" and len(row) >= 4:
                bugcheck = _num(row[2], 0) or 0
                button = _num(row[3], 0) or 0
                # SleepInProgress is an integer describing which sleep
                # transition was under way, not a true/false. Reading it as a
                # boolean makes every value except "1" look like "no", which
                # turns a machine that dropped out during sleep into a machine
                # that lost mains power -- a far more alarming and quite
                # different diagnosis.
                sleeping = (_num(row[4], 0) or 0) if len(row) > 4 else 0
                if bugcheck:
                    kind = "bugcheck"
                elif button:
                    kind = "power_button"
                elif sleeping:
                    kind = "sleep"
                else:
                    kind = "power_loss"
                events.append({"time": row[1], "kind": kind, "bugcheck": bugcheck})
            elif row[0] == "D" and len(row) >= 2:
                dirty.append(row[1])

        losses = [e for e in events if e["kind"] == "power_loss"]
        return {
            "available": True,
            "count": len(events),
            "events": events[:20],
            "power_losses": len(losses),
            "newest_loss": losses[0]["time"] if losses else "",
            "bugcheck_shutdowns": sum(1 for e in events if e["kind"] == "bugcheck"),
            "button_shutdowns": sum(1 for e in events if e["kind"] == "power_button"),
            "sleep_failures": sum(1 for e in events if e["kind"] == "sleep"),
            "dirty_shutdowns": len(dirty),
            "days": int(days),
        }

    def firmware_errors(self, days=45):
        """ACPI and firmware complaints Windows raised against the board.

        The ACPI tables are firmware, written by the board vendor and executed by
        Windows. When Windows logs an error against them the fault is in the
        board's firmware, not in anything the user installed -- and that points
        at a BIOS update rather than at any of the software repairs the rest of
        the engine knows how to perform.
        """
        providers = ("'Microsoft-Windows-Kernel-ACPI','ACPI','Microsoft-Windows-Kernel-Boot',"
                     "'Microsoft-Windows-Kernel-PnP','Microsoft-Windows-Kernel-Processor-Power'")
        script = (
            "$t=(Get-Date).AddDays(-%d);"
            "$e=Get-WinEvent -FilterHashtable @{LogName='System';StartTime=$t;"
            "ProviderName=@(%s);Level=1,2,3} -MaxEvents 200 -ErrorAction SilentlyContinue;"
            "foreach($x in $e){Write-Output ('F|'+(([string]$x.ProviderName) -replace '\\|',' ')"
            "+'|'+[string]$x.Id+'|'+[string]$x.Level+'|'+$x.TimeCreated.ToString('s')"
            "+'|'+(([string]$x.Message) -replace '[\\r\\n\\|]',' '))}"
        ) % (max(1, int(days)), providers)
        ready, rows, err = self._ps_events(script, timeout=45)
        if not ready:
            return {"available": False, "reason": (err or "")[:200]}

        events, groups = [], {}
        for row in rows:
            if row[0] != "F" or len(row) < 5:
                continue
            provider = row[1].strip()
            event_id = _num(row[2])
            record = {
                "provider": provider,
                "id": event_id,
                "level": row[3].strip(),
                "time": row[4],
                "message": (row[5][:220] if len(row) > 5 else ""),
            }
            events.append(record)
            key = f"{provider}/{event_id}"
            groups[key] = groups.get(key, 0) + 1

        acpi = [e for e in events if "ACPI" in (e["provider"] or "").upper()]
        # Errors only -- a warning from the PnP provider is routine on any
        # machine with a dock or a card reader.
        serious = [e for e in events if e["level"].lower() in ("1", "2", "error", "critical")]
        return {
            "available": True,
            "count": len(events),
            "events": events[:15],
            "groups": dict(sorted(groups.items(), key=lambda kv: -kv[1])[:12]),
            "acpi_errors": len([e for e in acpi if e["level"].lower() in ("1", "2", "error", "critical")]),
            "serious": len(serious),
            "days": int(days),
        }
