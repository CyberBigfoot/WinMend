"""WinMend diagnostics: collectors: storage."""

from __future__ import annotations

from pathlib import Path
from winmend.diagnostics.helpers import _tri_state
from winmend.diagnostics.repairs.storage import recycle_bin_bytes
import os
import re
import shutil
import time
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


class ProbeStorageMixin:
    """DeepProbe methods grouped by responsibility."""

    # -- every drive, not just the one Windows is on ----------------------

    def volumes(self):
        """Space and file system on every fixed drive.

        The single-drive check that came before this one answered "is Windows
        running out of room", which is not the same question as "is anything on
        this PC out of room". A full data drive breaks saves, games, backups,
        and virtual machines while the system drive sits at 50%.

        Volumes without a drive letter are skipped deliberately: the EFI and
        recovery partitions are supposed to be nearly full, and reporting them
        would put two permanent red rows on every PC.
        """
        script = (
            "Get-CimInstance Win32_Volume -Filter 'DriveType=3' -ErrorAction Stop | "
            "Where-Object { $_.DriveLetter } | ForEach-Object { Write-Output "
            "('V|'+$_.DriveLetter+'|'+[string]$_.Label+'|'+[string]$_.FileSystem+'|'"
            "+[string]$_.Capacity+'|'+[string]$_.FreeSpace+'|'+[string]$_.DirtyBitSet) }"
        )
        rc, rows, err = self._ps_rows(script, timeout=30)
        found = []
        for row in rows:
            if row[0] != "V" or len(row) < 6:
                continue
            try:
                capacity = float(row[4])
                free = float(row[5])
            except (ValueError, TypeError):
                continue
            if capacity <= 0:
                continue
            found.append({
                "drive": row[1].strip(),
                "label": row[2].strip(),
                "filesystem": row[3].strip(),
                "total_gb": round(capacity / 1024 ** 3, 1),
                "free_gb": round(free / 1024 ** 3, 1),
                "free_pct": round(free / capacity * 100, 1),
                # Blank without elevation, so it stays tri-state: "not dirty"
                # and "could not be read" are very different answers.
                "dirty": _tri_state(row[6] if len(row) > 6 else ""),
            })
        if not found:
            found = self._volumes_via_psutil()
        if not found:
            return {"available": False, "reason": (err or "")[:200]}
        system = (os.environ.get("SystemDrive", "C:") or "C:").rstrip("\\").upper()
        for volume in found:
            volume["system"] = volume["drive"].rstrip("\\").upper() == system
            # Only measured on a drive that is actually short of room. That is
            # the only place the answer changes anything, and walking the bin on
            # every healthy drive would be work done for nothing. Without it,
            # "empty the Recycle Bin" gets offered against a bin that is empty.
            volume["recycle_gb"] = None
            if volume["free_pct"] < 15:
                held, complete = recycle_bin_bytes(volume["drive"])
                volume["recycle_gb"] = round(held / 1024 ** 3, 2)
                volume["recycle_partial"] = not complete
        found.sort(key=lambda item: item["free_pct"])
        return {"available": True, "volumes": found,
                "others": [v for v in found if not v["system"]]}

    @staticmethod
    def _volumes_via_psutil():
        """Fallback with no labels, for when the CIM query is unavailable."""
        try:
            import psutil
        except Exception:
            return []
        found = []
        for part in psutil.disk_partitions(all=False):
            if "fixed" not in (part.opts or "").lower():
                continue
            try:
                usage = shutil.disk_usage(part.mountpoint)
            except OSError:
                continue
            if not usage.total:
                continue
            found.append({
                "drive": part.mountpoint.rstrip("\\"),
                "label": "",
                "filesystem": part.fstype,
                "total_gb": round(usage.total / 1024 ** 3, 1),
                "free_gb": round(usage.free / 1024 ** 3, 1),
                "free_pct": round(usage.free / usage.total * 100, 1),
                "dirty": None,
            })
        return found

    def filesystem_health(self):
        """Whether Windows has flagged a volume as needing a disk check.

        Two independent signals, because neither is complete on its own: the
        per-volume dirty bit says a volume is known to be inconsistent, and
        BootExecute says a check has already been scheduled for the next
        restart. The registry value is read rather than ``chkntfs`` because
        both ``chkntfs`` and ``fsutil dirty query`` refuse to answer without
        elevation, and the value itself is locale-proof.
        """
        result = {"available": False, "scheduled": [], "boot_execute": ""}
        if winreg is None:
            return result
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager",
            ) as key:
                try:
                    entries = winreg.QueryValueEx(key, "BootExecute")[0]
                except OSError:
                    entries = []
        except OSError:
            return result
        lines = [str(v).strip() for v in (entries or []) if str(v).strip()]
        result["available"] = True
        result["boot_execute"] = "; ".join(lines)
        # "autocheck autochk *" is the default and means nothing is queued. A
        # volume named explicitly is a check Windows intends to run at boot.
        for line in lines:
            for match in re.finditer(r"\\\?\?\\([A-Za-z]:)", line):
                drive = match.group(1).upper()
                if drive not in result["scheduled"]:
                    result["scheduled"].append(drive)
        return result

    def disk_reliability(self):
        """Wear, temperature, and uncorrected error counts straight off the drive.

        SMART's pass/fail flag is famously late -- drives routinely report
        "healthy" until the day they stop. The reliability counters are the
        numbers behind that flag, so a drive that is 96% through its rated
        write life can be reported while it is still working.
        """
        script = (
            "$trim='';"
            # -join first: fsutil returns an array of lines, and -match on an
            # array filters it instead of populating $Matches, so the capture
            # group would silently never exist.
            "try { $f = (fsutil behavior query DisableDeleteNotify) -join ' '; "
            "if ($f -match 'NTFS\\s+DisableDeleteNotify\\s*=\\s*(\\d)') "
            "{ $trim = $Matches[1] } } catch {};"
            "Write-Output ('T|'+$trim);"
            "Get-PhysicalDisk -ErrorAction Stop | ForEach-Object { $d=$_; $c=$null;"
            " try { $c = $d | Get-StorageReliabilityCounter -ErrorAction Stop } catch {};"
            " Write-Output ('R|'+($d.FriendlyName -replace '\\|',' ')+'|'+[string]$d.MediaType"
            "+'|'+[string]$d.HealthStatus+'|'+[string]$c.Wear+'|'+[string]$c.Temperature"
            "+'|'+[string]$c.ReadErrorsUncorrected+'|'+[string]$c.WriteErrorsUncorrected"
            "+'|'+[string]$c.PowerOnHours) }"
        )
        rc, rows, err = self._ps_rows(script, timeout=40)
        disks = []
        trim = None
        for row in rows:
            if row[0] == "T" and len(row) > 1:
                trim = {"0": True, "1": False}.get(row[1].strip())
                continue
            if row[0] != "R" or len(row) < 4:
                continue

            def _num(index):
                try:
                    return int(float(row[index].strip()))
                except (ValueError, TypeError, IndexError):
                    return None

            disks.append({
                "name": row[1].strip(),
                "media": row[2].strip(),
                "health": row[3].strip(),
                "wear_pct": _num(4),
                "temperature_c": _num(5),
                "read_errors": _num(6),
                "write_errors": _num(7),
                "power_on_hours": _num(8),
            })
        if not disks:
            return {"available": False, "reason": (err or "")[:200], "trim": trim}
        # The counters need elevation; the disk list does not. Saying so is the
        # difference between "no wear" and "wear could not be read".
        measured = [d for d in disks if d["wear_pct"] is not None
                    or d["read_errors"] is not None]
        return {
            "available": True,
            "disks": disks,
            "counters_readable": bool(measured),
            "trim": trim,
        }

    def dump_files(self, days=30):
        """Crash dump files on disk, which outlive the event-log record."""
        root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        found = []
        cutoff = time.time() - max(1, int(days)) * 86400
        try:
            for path in (root / "Minidump").glob("*.dmp"):
                try:
                    stat = path.stat()
                except OSError:
                    continue
                if stat.st_mtime >= cutoff:
                    found.append({"path": str(path), "mb": round(stat.st_size / 1024 ** 2, 1),
                                  "days_ago": round((time.time() - stat.st_mtime) / 86400.0, 1)})
        except OSError:
            pass
        full = root / "MEMORY.DMP"
        try:
            if full.exists():
                stat = full.stat()
                found.append({"path": str(full), "mb": round(stat.st_size / 1024 ** 2, 1),
                              "days_ago": round((time.time() - stat.st_mtime) / 86400.0, 1)})
        except OSError:
            pass
        found.sort(key=lambda item: item["days_ago"])
        return {"available": True, "dumps": found, "count": len(found),
                "mb": round(sum(d["mb"] for d in found), 1)}

    # -- storage upkeep -----------------------------------------------------

    def disk_optimization(self):
        """TRIM, and whether each volume has actually been maintained.

        An SSD with TRIM switched off degrades quietly for months; a mechanical
        disk that has never been defragmented is slow for a reason nothing else
        in the sweep would report.
        """
        rc, out, _ = self._run(["fsutil", "behavior", "query", "DisableDeleteNotify"], timeout=15)
        trim = None
        if rc == 0 and out.strip():
            # Windows 11 answers per file system ("NTFS DisableDeleteNotify = 0").
            # 0 means TRIM is allowed; any 1 means it is switched off somewhere.
            values = [int(value) for value in re.findall(r"=\s*(\d)", out)]
            if values:
                trim = not any(values)
        script = (
            "Get-Volume -ErrorAction SilentlyContinue | "
            "Where-Object {$_.DriveLetter -and $_.DriveType -eq 'Fixed'} | ForEach-Object {"
            "Write-Output ('VOL|'+$_.DriveLetter+'|'+$_.FileSystemType+'|'+$_.HealthStatus+'|'+"
            "$_.OperationalStatus)}"
        )
        ready, rows, _ = self._ps_events(script, timeout=25)
        volumes = []
        for row in rows:
            if row[0] != "VOL" or len(row) < 5:
                continue
            volumes.append({
                "drive": f"{row[1].strip()}:",
                "filesystem": row[2].strip(),
                "health": row[3].strip(),
                "operational": row[4].strip(),
                "healthy": row[3].strip().lower() == "healthy",
            })
        if trim is None and not ready:
            return {"available": False}
        return {
            "available": True,
            "trim": trim,
            "trim_readable": trim is not None,
            "volumes": volumes,
            "unhealthy": [v for v in volumes if not v["healthy"]],
        }

    def bitlocker_state(self):
        """Drive encryption, and the one state nobody means to leave a PC in.

        A volume whose protection is *suspended* is still encrypted but its key
        is sitting in the clear on the disk, which is the security of no
        encryption at all. A failed feature update leaves PCs like that.
        """
        script = (
            "$v=Get-CimInstance -Namespace root/cimv2/security/microsoftvolumeencryption "
            "-ClassName Win32_EncryptableVolume -ErrorAction SilentlyContinue;"
            "foreach($x in $v){$s=$null;$p=$null;"
            "try{$s=$x.GetConversionStatus().ConversionStatus}catch{};"
            "try{$p=$x.GetProtectionStatus().ProtectionStatus}catch{};"
            "Write-Output ('BL|'+$x.DriveLetter+'|'+$s+'|'+$p)}"
        )
        ready, rows, err = self._ps_events(script, timeout=30)
        if not ready:
            return {"available": False, "reason": (err or "needs administrator rights")[:160]}
        volumes = []
        for row in rows:
            if row[0] != "BL" or len(row) < 4:
                continue

            def _int(text):
                try:
                    return int(str(text).strip())
                except (ValueError, TypeError):
                    return None

            conversion, protection = _int(row[2]), _int(row[3])
            volumes.append({
                "drive": (row[1] or "").strip(),
                # 1 = fully encrypted, 2 = fully decrypted, 4/5 = in progress.
                "encrypted": conversion == 1,
                "conversion": conversion,
                "protection": protection,
                # Encrypted with protection off is the suspended state.
                "suspended": conversion == 1 and protection == 0,
            })
        if not volumes:
            # Every fixed NTFS volume is an *encryptable* volume whether or not
            # it has ever been encrypted, so an empty list never means "nothing
            # is encrypted here". It means the query was refused -- the class
            # needs elevation, and -ErrorAction SilentlyContinue makes that look
            # identical to a clean answer. Reporting it as measured would tell a
            # user with a suspended volume that their disk is fine.
            return {"available": False,
                    "reason": "drive encryption cannot be read without administrator rights"}
        return {
            "available": True,
            "volumes": volumes,
            "encrypted": [v for v in volumes if v["encrypted"]],
            "suspended": [v for v in volumes if v["suspended"]],
        }

    def top_disk_processes(self, seconds=1.0, top=4):
        """Which processes are actually driving the disk right now.

        "Disk at 100%" is one of the most common complaints there is, and the
        engine could measure the *latency* it caused but never name the process
        responsible for it.
        """
        try:
            import psutil
        except Exception:
            return {"available": False}
        ours = {os.getpid()}
        try:
            ours.add(os.getppid())
        except Exception:
            pass
        first = {}
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                io = proc.io_counters()
            except Exception:
                continue
            first[proc.info["pid"]] = (proc.info["name"] or "", io.read_bytes + io.write_bytes)
        time.sleep(max(0.2, min(3.0, float(seconds))))
        rows = []
        for proc in psutil.process_iter(["pid", "name"]):
            pid = proc.info["pid"]
            if pid not in first:
                continue
            try:
                io = proc.io_counters()
            except Exception:
                continue
            moved = (io.read_bytes + io.write_bytes) - first[pid][1]
            if moved <= 0:
                continue
            rows.append({
                "pid": pid,
                "name": proc.info["name"] or first[pid][0],
                "bytes_per_sec": moved / seconds,
                "mb_per_sec": (moved / seconds) / 1024 ** 2,
                "ours": pid in ours,
            })
        rows.sort(key=lambda row: -row["bytes_per_sec"])
        total = sum(row["bytes_per_sec"] for row in rows)
        # Our own sweep reads the disk, so anything we caused is excluded before
        # a process is named -- otherwise the tool reports itself as the fault.
        external = [row for row in rows if not row["ours"]]
        return {
            "available": True,
            "top": external[:top],
            "total_mb_per_sec": total / 1024 ** 2,
            "busiest": external[0] if external else None,
        }
