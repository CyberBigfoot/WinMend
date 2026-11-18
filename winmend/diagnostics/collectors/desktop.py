"""WinMend diagnostics: collectors: desktop."""

from __future__ import annotations

from pathlib import Path
from winmend.diagnostics.helpers import _days_ago
from winmend.diagnostics.reference import DEVICE_PROBLEM_CODES, PRINTER_STATUS
import os
import time
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


class ProbeDesktopMixin:
    """DeepProbe methods grouped by responsibility."""

    def printers(self):
        """Printers in an error state and jobs stuck in the queue."""
        script = (
            "Get-CimInstance Win32_Printer -ErrorAction SilentlyContinue | ForEach-Object { "
            "Write-Output ('P|'+($_.Name -replace '\\|',' ')+'|'+[string]$_.PrinterStatus+'|'"
            "+[string]$_.WorkOffline+'|'+[string]$_.Default+'|'+[string]$_.Network) };"
            "$j=@(); try { $j=@(Get-CimInstance Win32_PrintJob -ErrorAction Stop) } catch {};"
            "Write-Output ('J|'+[string]$j.Count);"
            "Write-Output ('done|1')"
        )
        rc, rows, err = self._ps_rows(script, timeout=30)
        if not any(row[0] == "done" for row in rows):
            return {"available": False, "reason": (err or "")[:200]}
        found = []
        jobs = 0
        for row in rows:
            if row[0] == "J" and len(row) > 1 and row[1].strip().isdigit():
                jobs = int(row[1].strip())
                continue
            if row[0] != "P" or len(row) < 5:
                continue
            try:
                status = int(row[2].strip())
            except (ValueError, TypeError):
                status = 2
            found.append({
                "name": row[1].strip(),
                "status": status,
                "state": PRINTER_STATUS.get(status, "unknown"),
                "offline": row[3].strip().lower() == "true" or status == 7,
                "default": row[4].strip().lower() == "true",
            })
        return {
            "available": True,
            "printers": found,
            "jobs": jobs,
            "spooler": self.service_state("Spooler"),
            # Only the default printer is judged. A printer that was used once
            # at an old address is offline forever and is not a fault.
            "default_offline": [p for p in found if p["default"] and p["offline"]],
        }

    # -- the signed-in session --------------------------------------------

    def user_profile(self):
        """Whether this is the real user profile or a temporary stand-in.

        A temporary profile looks like a wiped PC to the person using it -- no
        files, no settings -- while everything Windows reports stays healthy.
        It is worth naming explicitly because the obvious conclusion the user
        draws is that their data is gone.
        """
        path = os.environ.get("USERPROFILE", "")
        name = os.path.basename(path.rstrip("\\")) if path else ""
        backups = 0
        matched = ""
        if winreg is not None:
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
                ) as root:
                    for index in range(winreg.QueryInfoKey(root)[0]):
                        try:
                            sid = winreg.EnumKey(root, index)
                        except OSError:
                            break
                        if sid.lower().endswith(".bak"):
                            backups += 1
                        try:
                            with winreg.OpenKey(root, sid) as key:
                                stored = str(winreg.QueryValueEx(key, "ProfileImagePath")[0])
                        except OSError:
                            continue
                        if path and os.path.normcase(os.path.normpath(stored)) == \
                                os.path.normcase(os.path.normpath(path)):
                            matched = sid
            except OSError:
                pass
        redirected = []
        if winreg is not None:
            try:
                with winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
                ) as key:
                    for value, label in (("Desktop", "Desktop"), ("Personal", "Documents"),
                                         ("My Pictures", "Pictures")):
                        try:
                            target = str(winreg.QueryValueEx(key, value)[0])
                        except OSError:
                            continue
                        if "onedrive" in target.lower():
                            redirected.append(label)
            except OSError:
                pass
        return {
            "available": bool(path),
            "path": path,
            # Windows names the stand-in TEMP, and leaves the real profile
            # behind under a .bak key.
            "temporary": bool(name) and name.upper().startswith("TEMP"),
            "backup_profiles": backups,
            "sid": matched,
            "onedrive_folders": redirected,
        }

    def restart_pending(self):
        """Why a restart is pending, not just whether one is.

        ``PendingFileRenameOperations`` is deliberately *not* treated as a
        reason. Installers queue renames constantly -- this machine has 70
        queued while being perfectly up to date -- so using it would put a
        permanent "restart required" on nearly every PC.
        """
        if winreg is None:
            return {"available": False}
        reasons = []
        for hive, path, reason in (
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
             "a Windows component finished installing"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
             "Windows Update is waiting to finish"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending",
             "a package install is part-way through"),
        ):
            try:
                with winreg.OpenKey(hive, path):
                    reasons.append(reason)
            except OSError:
                continue
        queued = 0
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager",
            ) as key:
                queued = len([v for v in (winreg.QueryValueEx(
                    key, "PendingFileRenameOperations")[0] or []) if str(v).strip()])
        except (OSError, ValueError, TypeError):
            queued = 0
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName",
            ) as key:
                active = str(winreg.QueryValueEx(key, "ComputerName")[0])
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName",
            ) as key:
                configured = str(winreg.QueryValueEx(key, "ComputerName")[0])
            if active.strip().lower() != configured.strip().lower():
                reasons.append("this PC has been renamed")
        except (OSError, ValueError, TypeError):
            pass
        return {
            "available": True,
            "pending": bool(reasons),
            "reasons": reasons,
            "queued_renames": queued,
        }

    # -- apps, shell, and devices -------------------------------------------

    def appx_health(self, watch=("Microsoft.WindowsStore", "Microsoft.Windows.StartMenuExperienceHost",
                                 "Microsoft.WindowsTerminal")):
        """Store apps that Windows itself reports as damaged.

        A package whose files are gone but whose registration remains cannot
        start and cannot be repaired from the Store, which is exactly the "my
        apps just bounce and close" report.
        """
        script = (
            "$b=@(Get-AppxPackage -ErrorAction SilentlyContinue | "
            "Where-Object {$_.Status -ne 'Ok'});"
            "foreach($p in $b){Write-Output ('BAD|'+$p.Name+'|'+$p.Status+'|'+$p.PackageFullName)};"
            "Write-Output ('TOTAL|'+@(Get-AppxPackage -ErrorAction SilentlyContinue).Count);"
            + "".join(
                "Write-Output ('WATCH|%s|'+"
                "[string](Get-AppxPackage -Name '%s' -ErrorAction SilentlyContinue).Status);" % (name, name)
                for name in watch)
        )
        ready, rows, _ = self._ps_events(script, timeout=40)
        if not ready:
            return {"available": False}
        broken = []
        total = 0
        missing = []
        for row in rows:
            if row[0] == "BAD" and len(row) >= 4:
                broken.append({"name": row[1].strip(), "status": row[2].strip(),
                               "package": row[3].strip()})
            elif row[0] == "TOTAL" and len(row) >= 2 and row[1].strip().isdigit():
                total = int(row[1].strip())
            elif row[0] == "WATCH" and len(row) >= 3:
                name, status = row[1].strip(), row[2].strip()
                if not status:
                    missing.append(name)
        return {
            "available": True,
            "total": total,
            "broken": broken,
            # A missing Store or Start-menu package is a different fault from a
            # damaged one: it was removed, usually by a debloat script.
            "missing": missing,
            "store_present": "Microsoft.WindowsStore" not in missing,
        }

    def shell_health(self):
        """Explorer, the Start menu, and the caches behind them."""
        running = 0
        oldest_start = None
        try:
            import psutil
            for proc in psutil.process_iter(["name", "create_time"]):
                if (proc.info["name"] or "").lower() == "explorer.exe":
                    running += 1
                    started = proc.info.get("create_time")
                    if started:
                        oldest_start = started if oldest_start is None else min(oldest_start, started)
        except Exception:
            return {"available": False}
        cache_bytes = 0
        cache_dir = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Windows" / "Explorer"
        try:
            for path in cache_dir.glob("*.db"):
                try:
                    cache_bytes += path.stat().st_size
                except OSError:
                    continue
        except OSError:
            pass
        return {
            "available": True,
            "explorer_running": running > 0,
            "explorer_instances": running,
            "explorer_age_hours": ((time.time() - oldest_start) / 3600.0
                                   if oldest_start else None),
            "icon_cache_mb": cache_bytes / 1024 ** 2,
            # Explorer rebuilds these caches, but only up to a point; past a few
            # hundred megabytes they are the reason icons go blank.
            "icon_cache_large": cache_bytes > 400 * 1024 ** 2,
        }

    def audio_health(self):
        """The audio stack: its two services and whether any output exists.

        "No sound" had no measurement at all before this, so the engine had to
        take the complaint on trust and could never verify a repair.
        """
        services = {name: self.service_state(name)
                    for name in ("Audiosrv", "AudioEndpointBuilder")}
        script = (
            "Get-CimInstance Win32_SoundDevice -ErrorAction SilentlyContinue | ForEach-Object {"
            "Write-Output ('SND|'+$_.Name+'|'+$_.Status+'|'+$_.StatusInfo+'|'+$_.ConfigManagerErrorCode)}"
        )
        ready, rows, _ = self._ps_events(script, timeout=25)
        devices = []
        for row in rows:
            if row[0] != "SND" or len(row) < 5:
                continue
            try:
                code = int(row[4])
            except (ValueError, TypeError):
                code = 0
            devices.append({
                "name": row[1].strip(),
                "status": row[2].strip(),
                "problem_code": code,
                "problem": DEVICE_PROBLEM_CODES.get(code, "") if code else "",
                "healthy": code == 0 and row[2].strip().lower() == "ok",
            })
        if not ready and all(state == "unknown" for state in services.values()):
            return {"available": False}
        faulty = [d for d in devices if not d["healthy"]]
        return {
            "available": True,
            "services": services,
            "service_stopped": [name for name, state in services.items() if state == "stopped"],
            "devices": devices,
            "faulty": faulty,
            "any_device": bool(devices),
            "healthy": bool(devices) and not faulty and not any(
                state == "stopped" for state in services.values()),
        }

    def bluetooth_health(self):
        """Bluetooth: the service, the radio, and any device in a problem state."""
        state = self.service_state("bthserv")
        script = (
            "Get-CimInstance Win32_PnPEntity -Filter \"PNPClass='Bluetooth'\" "
            "-ErrorAction SilentlyContinue | ForEach-Object {"
            "Write-Output ('BT|'+$_.Name+'|'+$_.Status+'|'+$_.ConfigManagerErrorCode)}"
        )
        ready, rows, _ = self._ps_events(script, timeout=25)
        if not ready and state == "unknown":
            return {"available": False}
        devices = []
        for row in rows:
            if row[0] != "BT" or len(row) < 4:
                continue
            try:
                code = int(row[3])
            except (ValueError, TypeError):
                code = 0
            devices.append({
                "name": row[1].strip(),
                "status": row[2].strip(),
                "problem_code": code,
                "problem": DEVICE_PROBLEM_CODES.get(code, "") if code else "",
                "healthy": code == 0,
            })
        # A PC with no Bluetooth hardware is not a PC with broken Bluetooth.
        present = bool(devices)
        return {
            "available": True,
            "present": present,
            "service": state,
            "devices": devices,
            "faulty": [d for d in devices if not d["healthy"]],
            "healthy": (not present) or (state == "running" and
                                         all(d["healthy"] for d in devices)),
        }

    def display_config(self):
        """Graphics adapters, their drivers, and the fallback that means failure.

        "Microsoft Basic Display Adapter" driving the screen means the real
        driver did not load. Everything is huge, nothing is smooth, and no other
        check on the PC reports a fault.
        """
        script = (
            "Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | ForEach-Object {"
            "Write-Output ('GPU|'+$_.Name+'|'+$_.DriverVersion+'|'+"
            "$_.DriverDate+'|'+$_.ConfigManagerErrorCode+'|'+"
            "$_.CurrentHorizontalResolution+'x'+$_.CurrentVerticalResolution+'|'+"
            "$_.CurrentRefreshRate)}"
        )
        ready, rows, _ = self._ps_events(script, timeout=25)
        if not ready:
            return {"available": False}
        adapters = []
        for row in rows:
            if row[0] != "GPU" or len(row) < 7:
                continue
            try:
                code = int(row[4])
            except (ValueError, TypeError):
                code = 0
            name = row[1].strip()
            lowered = name.lower()
            try:
                refresh = int(row[6])
            except (ValueError, TypeError):
                refresh = None
            adapters.append({
                "name": name,
                "driver_version": row[2].strip(),
                "driver_date": row[3].strip(),
                "driver_age_days": _days_ago(row[3].strip()),
                "problem_code": code,
                "problem": DEVICE_PROBLEM_CODES.get(code, "") if code else "",
                "resolution": row[5].strip(),
                "refresh_hz": refresh,
                "basic": "basic display" in lowered or "standard vga" in lowered,
                "active": bool(row[5].strip() and not row[5].strip().startswith("x")),
            })
        active = [a for a in adapters if a["active"]]
        return {
            "available": True,
            "adapters": adapters,
            "basic_driver": [a for a in active if a["basic"]],
            "faulty": [a for a in adapters if a["problem_code"]],
            "count": len(adapters),
        }
