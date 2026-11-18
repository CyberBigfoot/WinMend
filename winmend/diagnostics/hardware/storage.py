"""WinMend diagnostics: hardware: storage."""

from __future__ import annotations

from winmend.diagnostics.hardware.reference import (
    SMART_ATTRIBUTES,
    STORAGE_EVENTS,
    STORAGE_PROVIDERS,
    _num,
    _tri,
)
import re
import time


class HardwareStorageMixin:
    """HardwareProbe methods grouped by responsibility."""

    # ---- storage ----------------------------------------------------------

    def smart_attributes(self):
        """The raw SMART attribute table, straight off each ATA drive.

        ``disk_reliability`` reads the summary counters, and ``smart_health``
        reads the pass/fail flag. That flag is famously useless: it is designed
        to stay green until the drive is nearly gone, which is why drives
        "fail without warning" so often.

        The warning was there. It is attribute 197 -- sectors that failed to read
        and are queued for reallocation -- and it typically goes non-zero weeks
        to months ahead of the flag. Attribute 199 is better still in a different
        way: interface CRC errors mean the *cable* is corrupting data in flight,
        which looks exactly like a dying drive and is fixed for the price of a
        SATA lead.

        Windows exposes this as an undocumented 512-byte blob, so it is parsed
        here rather than read. NVMe drives generally expose nothing this way;
        that is expected, not a failure.
        """
        script = self._SANITISE + (
            "try{Get-CimInstance -Namespace root/wmi -ClassName MSStorageDriver_FailurePredictData "
            "-ErrorAction Stop | ForEach-Object { Write-Output ('D|'+(S $_.InstanceName)+'|'"
            "+(($_.VendorSpecific) -join ',')) }}catch{};"
            "try{Get-CimInstance -Namespace root/wmi -ClassName MSStorageDriver_FailurePredictStatus "
            "-ErrorAction Stop | ForEach-Object { Write-Output ('S|'+(S $_.InstanceName)+'|'"
            "+[string]$_.PredictFailure+'|'+[string]$_.Reason) }}catch{}"
        )
        rc, rows, err = self._ps_rows(script, timeout=45)
        drives, predicted = [], {}
        for row in rows:
            if row[0] == "S" and len(row) >= 3:
                predicted[row[1].strip()] = _tri(row[2])
                continue
            if row[0] != "D" or len(row) < 3:
                continue
            try:
                blob = [int(part) for part in row[2].split(",") if part.strip()]
            except ValueError:
                continue
            if len(blob) < 14:
                continue
            attributes = []
            # Two bytes of revision, then 30 twelve-byte entries. An entry whose
            # id is 0 is an unused slot, not attribute zero.
            for index in range(30):
                base = 2 + index * 12
                if base + 11 >= len(blob):
                    break
                attribute_id = blob[base]
                if not attribute_id:
                    continue
                raw = int.from_bytes(bytes(blob[base + 5:base + 11]), "little")
                name, critical = SMART_ATTRIBUTES.get(
                    attribute_id, (f"Attribute {attribute_id}", False))
                value = {
                    "id": attribute_id,
                    "name": name,
                    "critical": critical,
                    "current": blob[base + 3],
                    "worst": blob[base + 4],
                    "raw": raw,
                }
                if attribute_id in (190, 194):
                    # Temperature attributes pack current/min/max into the six
                    # raw bytes, so only the low byte is the reading -- and only
                    # when it lands somewhere a drive could plausibly be.
                    low = raw & 0xFF
                    value["celsius"] = low if 0 < low < 120 else None
                attributes.append(value)
            if not attributes:
                continue
            instance = row[1].strip()
            concerning = [a for a in attributes if a["critical"] and a["raw"] > 0]
            drives.append({
                "instance": instance,
                "attributes": attributes,
                "concerning": concerning,
                "predict_failure": predicted.get(instance),
                "pending_sectors": next(
                    (a["raw"] for a in attributes if a["id"] == 197), None),
                "reallocated": next(
                    (a["raw"] for a in attributes if a["id"] == 5), None),
                "uncorrectable": next(
                    (a["raw"] for a in attributes if a["id"] == 198), None),
                "crc_errors": next(
                    (a["raw"] for a in attributes if a["id"] == 199), None),
                "power_on_hours": next(
                    (a["raw"] for a in attributes if a["id"] == 9), None),
                "celsius": next((a.get("celsius") for a in attributes
                                 if a["id"] in (190, 194) and a.get("celsius")), None),
            })
        if not drives:
            # Either every drive is NVMe, or the namespace needs elevation.
            # Both are "not measured", and neither is "no problems found".
            return {"available": False, "reason": (err or "no ATA drive exposed SMART data")[:200]}
        return {
            "available": True,
            "drives": drives,
            "count": len(drives),
            "failing": [d for d in drives if d["predict_failure"]],
            "with_concerns": [d for d in drives if d["concerning"]],
        }

    def storage_bus_errors(self, days=45):
        """Storage faults grouped by what they actually blame.

        Every one of these ids gets counted as "disk errors" by tools that
        tally events rather than read them, and the right response ranges from
        "replace a cable" to "the drive is going". Event 129 -- the controller
        having to reset a drive that stopped answering -- is the one that most
        often means a physical connection rather than a dying disk, and it is
        completely lost inside an aggregate count.
        """
        ids = ",".join(str(i) for i in sorted(STORAGE_EVENTS))
        providers = ",".join(f"'{p}'" for p in STORAGE_PROVIDERS)
        script = (
            "$t=(Get-Date).AddDays(-%d);"
            "$p=@(%s);"
            "$e=Get-WinEvent -FilterHashtable @{LogName='System';StartTime=$t;Id=%s} "
            "-MaxEvents 400 -ErrorAction SilentlyContinue | "
            "Where-Object { $p -contains $_.ProviderName };"
            "foreach($x in $e){Write-Output ('S|'+(([string]$x.ProviderName) -replace '\\|',' ')"
            "+'|'+[string]$x.Id+'|'+$x.TimeCreated.ToString('s')+'|'"
            "+(([string]$x.Message) -replace '[\\r\\n\\|]',' '))}"
        ) % (max(1, int(days)), providers, ids)
        ready, rows, err = self._ps_events(script, timeout=50)
        if not ready:
            return {"available": False, "reason": (err or "")[:200]}

        events, by_id, blame = [], {}, {"drive": 0, "link": 0}
        for row in rows:
            if row[0] != "S" or len(row) < 4:
                continue
            event_id = _num(row[2])
            title, meaning, whom = STORAGE_EVENTS.get(
                event_id, ("Storage error", "", ""))
            message = row[4][:220] if len(row) > 4 else ""
            # The message names the device as \Device\Harddisk2\DR2; the disk
            # number is the only part that maps to something the user can see.
            match = re.search(r"Harddisk(\d+)", message)
            events.append({
                "provider": row[1].strip(),
                "id": event_id,
                "time": row[3],
                "title": title,
                "meaning": meaning,
                "blame": whom,
                "disk": _num(match.group(1)) if match else None,
                "message": message,
            })
            by_id[event_id] = by_id.get(event_id, 0) + 1
            if whom in blame:
                blame[whom] += 1

        disks = {}
        for event in events:
            if event["disk"] is not None:
                disks[event["disk"]] = disks.get(event["disk"], 0) + 1
        return {
            "available": True,
            "count": len(events),
            "events": events[:15],
            "by_id": by_id,
            "blame": blame,
            "by_disk": disks,
            "worst_disk": max(disks, key=disks.get) if disks else None,
            "resets": by_id.get(129, 0),
            "bad_blocks": by_id.get(7, 0),
            "days": int(days),
        }

    def disk_geometry(self):
        """Firmware revision, bus, sector size and partition alignment.

        Two faults hide here that nothing else in the sweep would catch. A drive
        whose logical and physical sector sizes disagree with how its partitions
        were laid out does every write twice, which reads as "this SSD got slow"
        and is real. And the firmware revision is the only way to recognise a
        drive on a build the vendor has since recalled for data loss -- a
        condition where the correct advice is emphatically not to keep using it.
        """
        script = self._SANITISE + (
            "try{Get-PhysicalDisk -ErrorAction Stop | ForEach-Object { Write-Output "
            "('P|'+[string]$_.DeviceId+'|'+(S $_.FriendlyName)+'|'+(S $_.FirmwareVersion)+'|'"
            "+(S $_.BusType)+'|'+[string]$_.PhysicalSectorSize+'|'+[string]$_.LogicalSectorSize"
            "+'|'+[string]$_.Size+'|'+[string]$_.SpindleSpeed+'|'+(S $_.MediaType)+'|'"
            "+(S $_.HealthStatus)) }}catch{};"
            "try{Get-Partition -ErrorAction Stop | ForEach-Object { Write-Output "
            "('Q|'+[string]$_.DiskNumber+'|'+[string]$_.PartitionNumber+'|'+[string]$_.Offset"
            "+'|'+[string]$_.Size+'|'+(S $_.DriveLetter)) }}catch{}"
        )
        rc, rows, err = self._ps_rows(script, timeout=40)
        disks, partitions = [], []
        for row in rows:
            if row[0] == "P" and len(row) >= 8:
                physical = _num(row[5])
                logical = _num(row[6])
                size = _num(row[7])
                disks.append({
                    "id": _num(row[1]),
                    "name": row[2].strip(),
                    "firmware": row[3].strip(),
                    "bus": row[4].strip(),
                    "physical_sector": physical,
                    "logical_sector": logical,
                    "gb": round(size / (1024 ** 3), 1) if size else None,
                    "rpm": _num(row[8]) if len(row) > 8 else None,
                    "media": row[9].strip() if len(row) > 9 else "",
                    "health": row[10].strip() if len(row) > 10 else "",
                    # 512e drives report a 4096-byte physical sector behind a
                    # 512-byte logical one. That is normal and not the problem;
                    # misaligned partitions on top of it are.
                    "emulated_sectors": bool(physical and logical and physical > logical),
                })
            elif row[0] == "Q" and len(row) >= 5:
                offset = _num(row[3])
                size = _num(row[4]) or 0
                # A partition with no letter comes back carrying a NUL rather
                # than an empty string, which is truthy and prints as garbage.
                letter = (row[5].strip().strip(chr(0)) if len(row) > 5 else "")
                partitions.append({
                    "disk": _num(row[1]),
                    "number": _num(row[2]),
                    "offset": offset,
                    "bytes": size,
                    "gb": round(size / (1024 ** 3), 1),
                    "letter": letter,
                    # Anything laid out by a modern Windows installer starts on
                    # a 1 MiB boundary. A partition that does not is the
                    # signature of a disk cloned from an XP-era layout.
                    "aligned": bool(offset is not None and offset % (1024 * 1024) == 0),
                })
        if not disks:
            return {"available": False, "reason": (err or "")[:200]}
        # Only partitions big enough for the overhead to matter. Every GPT disk
        # carries tiny reserved entries -- one sits at LBA 34, 17 KiB in, and is
        # unaligned by definition. Flagging those told a healthy machine it had
        # two misaligned partitions, so the size floor is what makes this
        # finding mean what it says.
        misaligned = [p for p in partitions
                      if not p["aligned"] and p["offset"] and p["bytes"] >= 1024 ** 3]
        return {
            "available": True,
            "disks": disks,
            "partitions": partitions,
            "misaligned": misaligned,
            "unhealthy": [d for d in disks
                          if d["health"] and d["health"].lower() != "healthy"],
        }

    def disk_read_sweep(self, samples=48, block=131072, budget=25.0):
        """Read a spread of blocks off each physical drive and time them.

        Every other storage check here reads what the drive *says* about itself.
        This one asks it to actually do something, because a drive can report
        clean counters and still fail to hand over data -- and a sector that
        only errors when it is read is invisible to every passive check.

        Deliberately a sample rather than a surface scan: ``samples`` blocks
        spread evenly across the whole device costs seconds instead of hours,
        and a drive that is failing rarely fails in only one place. A read that
        errors is a hard finding. A read that takes hundreds of milliseconds
        when its neighbours took one is the softer signal that usually precedes
        it, so both are recorded.

        Strictly read-only, and bounded by ``budget`` seconds in total.
        """
        script = ("Get-PhysicalDisk -ErrorAction SilentlyContinue | ForEach-Object { "
                  "Write-Output ([string]$_.DeviceId+'|'+[string]$_.Size+'|'"
                  "+[string]$_.LogicalSectorSize) }")
        rc, rows, err = self._ps_rows(script, timeout=25)
        targets = []
        for row in rows:
            device, size = _num(row[0]), _num(row[1])
            sector = _num(row[2]) or 512
            if device is not None and size and size > 0:
                targets.append((device, size, sector))
        if not targets:
            return {"available": False, "reason": (err or "no physical disk reported a size")[:200]}

        deadline = time.monotonic() + max(5.0, float(budget))
        results, unreadable = [], []
        for device, size, sector in targets:
            path = rf"\\.\PhysicalDrive{device}"
            try:
                handle = open(path, "rb", buffering=0)
            except OSError as exc:
                # Raw device reads need elevation. Saying so is the difference
                # between "the drive is fine" and "nobody looked".
                unreadable.append({"disk": device, "reason": str(exc)[:120]})
                continue
            # Offsets and lengths on a raw device handle must be sector
            # multiples; 1 MiB satisfies every sector size in use.
            align = 1024 * 1024
            span = max(align, (size - block) // max(1, samples - 1))
            span -= span % align
            span = max(align, span)
            latencies, errors, read = [], [], 0
            try:
                for index in range(max(2, int(samples))):
                    if time.monotonic() > deadline:
                        break
                    offset = index * span
                    if offset + block > size:
                        break
                    try:
                        started = time.perf_counter()
                        handle.seek(offset)
                        data = handle.read(block)
                        elapsed = (time.perf_counter() - started) * 1000.0
                    except OSError as exc:
                        errors.append({"offset_gb": round(offset / (1024 ** 3), 2),
                                       "error": str(exc)[:120]})
                        # One failed sample is enough to justify backup and
                        # independent confirmation; do not grind on bad media.
                        break
                    if not data or len(data) < block:
                        errors.append({"offset_gb": round(offset / (1024 ** 3), 2),
                                       "error": "short read"})
                        break
                    read += 1
                    latencies.append(elapsed)
            finally:
                try:
                    handle.close()
                except OSError:
                    pass
            if not latencies and not errors:
                continue
            latencies.sort()
            median = latencies[len(latencies) // 2] if latencies else None
            worst = latencies[-1] if latencies else None
            # An outlier is only meaningful against this drive's own baseline: a
            # spinning disk's normal seek is an NVMe's catastrophe.
            slow = ([round(v, 1) for v in latencies if median and v > max(50.0, median * 12)]
                    if median else [])
            results.append({
                "disk": device,
                "blocks_read": read,
                "gb_span": round(size / (1024 ** 3), 1),
                "median_ms": round(median, 2) if median is not None else None,
                "worst_ms": round(worst, 2) if worst is not None else None,
                "slow_reads": len(slow),
                "slowest": slow[-3:],
                "errors": errors,
                "error_count": len(errors),
            })
        if not results:
            return {"available": False, "elevated": False,
                    "unreadable": unreadable,
                    "reason": "no physical drive could be opened for reading"}
        return {
            "available": True,
            "disks": results,
            "unreadable": unreadable,
            "total_errors": sum(r["error_count"] for r in results),
            "failing": [r for r in results if r["error_count"]],
            # Three outliers, not one. This runs alongside the rest of the sweep,
            # so the drive is under load from other collectors while it is being
            # timed -- and a single stall under that is a busy disk, not a sick
            # one. A drive that is genuinely struggling produces them steadily.
            "sluggish": [r for r in results if r["slow_reads"] >= 3],
        }
