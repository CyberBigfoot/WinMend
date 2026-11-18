"""WinMend diagnostics: collectors: integrity."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from winmend.diagnostics.helpers import _days_ago, _iso_to_dt
from winmend.diagnostics.reference import WINDOWS_BUILDS, _POLICY_WATCHLIST
import os
import re
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


class ProbeIntegrityMixin:
    """DeepProbe methods grouped by responsibility."""

    # -- integrity and policy state --------------------------------------

    def component_store_health(self):
        """DISM /CheckHealth: reports flags already recorded, and returns in seconds.

        /ScanHealth walks the whole store and takes minutes, which is why it stays
        a user-launched task rather than part of a diagnostic sweep.
        """
        rc, out, err = self._run(
            ["dism", "/Online", "/Cleanup-Image", "/CheckHealth"], timeout=90)
        text = (out or "") + (err or "")
        lowered = text.lower()
        if "no component store corruption" in lowered:
            return {"available": True, "state": "clean"}
        if "repairable" in lowered:
            return {"available": True, "state": "repairable"}
        if "not repairable" in lowered or "cannot be repaired" in lowered:
            return {"available": True, "state": "unrepairable"}
        if rc != 0:
            return {"available": False, "reason": text.strip()[-200:]}
        return {"available": True, "state": "unknown"}

    def windows_version(self):
        """Build number, edition, and whether servicing has ended."""
        build = 0
        display = ""
        product = ""
        if winreg is not None:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
                    for name, target in (("CurrentBuildNumber", "build"),
                                         ("DisplayVersion", "display"),
                                         ("ProductName", "product")):
                        try:
                            value = winreg.QueryValueEx(key, name)[0]
                        except OSError:
                            continue
                        if target == "build":
                            try:
                                build = int(value)
                            except (TypeError, ValueError):
                                build = 0
                        elif target == "display":
                            display = str(value)
                        else:
                            product = str(value)
            except OSError:
                pass
        if not build:
            return {"available": False}
        label, eol = WINDOWS_BUILDS.get(build, ("", ""))
        supported = None
        days_left = None
        if eol:
            end = _iso_to_dt(eol)
            if end is not None:
                days_left = round((end - datetime.now(timezone.utc)).total_seconds() / 86400)
                supported = days_left > 0
        return {
            "available": True,
            "build": build,
            "display": display,
            "product": product,
            "label": label or (product or f"build {build}"),
            "eol": eol,
            "supported": supported,
            "days_left": days_left,
        }

    def pagefile(self):
        """Whether a page file exists and is managed. Disabling it breaks things."""
        automatic = None
        configured = []
        if winreg is not None:
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
                ) as key:
                    try:
                        value = winreg.QueryValueEx(key, "PagingFiles")[0]
                    except OSError:
                        value = []
                    configured = [str(v).strip() for v in (value or []) if str(v).strip()]
                    # An empty "?:\pagefile.sys" entry is how Windows records
                    # "let the system manage this" -- it is not a disabled file.
                    automatic = any("?:\\pagefile.sys" in e.lower() for e in configured)
            except OSError:
                configured = []
        script = (
            "$p=Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue;"
            "Write-Output ('pf|'+[string]@($p).Count+'|'+[string](($p | Measure-Object "
            "-Property AllocatedBaseSize -Sum).Sum))"
        )
        rc, rows, _ = self._ps_rows(script, timeout=20)
        count = 0
        size_mb = 0
        for row in rows:
            if row[0] == "pf" and len(row) > 2:
                try:
                    count = int(row[1])
                except ValueError:
                    count = 0
                try:
                    size_mb = int(float(row[2] or 0))
                except ValueError:
                    size_mb = 0
        return {
            "available": True,
            "files": count,
            "size_mb": size_mb,
            "automatic": bool(automatic),
            "configured": configured,
            "disabled": count == 0 and not automatic,
        }

    # -- system integrity and policy ----------------------------------------

    def integrity_history(self, tail_bytes=600000):
        """What the last System File Checker run concluded, read from its log.

        Deliberately read-only: running ``sfc`` takes half an hour and is a
        repair, not a check. The verdict from whenever it last ran is free, and
        "cannot repair member file" is the one line that changes the plan --
        it means the component store is damaged and DISM has to go first.
        """
        log_path = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Logs" / "CBS" / "CBS.log"
        try:
            size = log_path.stat().st_size
        except OSError:
            return {"available": False}
        try:
            with open(log_path, "rb") as handle:
                # CBS.log runs to tens of megabytes. Only the tail can say what
                # the most recent run found, and reading the whole file would
                # cost more than every other collector combined.
                handle.seek(max(0, size - max(50000, int(tail_bytes))))
                text = handle.read().decode("utf-8", "replace")
        except OSError:
            return {"available": False}
        lines = [line for line in text.splitlines() if "[SR]" in line]
        unrepairable = [line for line in lines if "cannot repair member file" in line.lower()]
        repaired = [line for line in lines if "repairing" in line.lower()
                    or "successfully repaired" in line.lower()]
        verdicts = [line for line in lines if "verify complete" in line.lower()
                    or "verification complete" in line.lower()]
        last_run = ""
        if lines:
            stamp = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", lines[-1].strip())
            last_run = stamp.group(1).replace(" ", "T") if stamp else ""
        return {
            "available": True,
            "ever_run": bool(lines),
            "last_run": last_run,
            "last_run_days": _days_ago(last_run) if last_run else None,
            "checked_lines": len(lines),
            "unrepairable": len(unrepairable),
            "repaired": len(repaired),
            "verdicts": len(verdicts),
            # A single unrepairable member file is enough: sfc has already tried
            # and failed, so running it again is not the next step.
            "corrupt": bool(unrepairable),
            "sample": [line.strip()[:180] for line in unrepairable[:3]],
        }

    def policy_health(self):
        """Restrictions applied by policy that the user did not knowingly set.

        On a home PC these are almost always the residue of a "debloat" or
        "privacy" script. Each one is a working feature that has been switched
        off somewhere the Settings app will never show.
        """
        if winreg is None:
            return {"available": False}
        found = []
        for hive, path, name, meaning, area in _POLICY_WATCHLIST:
            try:
                with winreg.OpenKey(hive, path) as key:
                    value = winreg.QueryValueEx(key, name)[0]
            except (OSError, ValueError, TypeError):
                continue
            try:
                number = int(value)
            except (ValueError, TypeError):
                continue
            if number != 1:
                continue
            found.append({
                "hive": "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU",
                "path": path, "value": name, "meaning": meaning, "area": area,
            })
        areas = {}
        for entry in found:
            areas[entry["area"]] = areas.get(entry["area"], 0) + 1
        return {
            "available": True,
            "restrictions": found,
            "count": len(found),
            "areas": areas,
        }

    def environment_health(self):
        """The system PATH -- the one setting whose damage looks like everything.

        Lose ``System32`` from it and half of Windows stops working with
        unrelated-looking errors. Over 2047 characters the classic-format value
        is truncated, which does the same thing less obviously.
        """
        if winreg is None:
            return {"available": False}
        raw = ""
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            ) as key:
                raw = str(winreg.QueryValueEx(key, "Path")[0] or "")
        except (OSError, ValueError, TypeError):
            return {"available": False}
        entries = [part.strip() for part in raw.split(";") if part.strip()]
        expanded = [(entry, os.path.expandvars(entry)) for entry in entries]
        missing = [entry for entry, full in expanded if not os.path.isdir(full)]
        system32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32").lower()
        has_system32 = any(full.rstrip("\\").lower() == system32.rstrip("\\")
                           for _entry, full in expanded)
        duplicates = len(entries) - len({entry.lower().rstrip("\\") for entry in entries})
        return {
            "available": True,
            "length": len(raw),
            "entries": len(entries),
            "missing": missing[:8],
            "missing_count": len(missing),
            "duplicates": duplicates,
            "has_system32": has_system32,
            "truncation_risk": len(raw) > 2000,
        }

    def known_folders(self):
        """Where Desktop and Documents actually point, and whether that works.

        Redirection into OneDrive is normal and deliberate. Redirection into a
        OneDrive that is not running, or to a folder that does not exist, is why
        someone's files "disappeared" -- and the difference is measurable.
        """
        if winreg is None:
            return {"available": False}
        wanted = (
            ("Desktop", "Desktop"),
            ("Personal", "Documents"),
            ("{374DE290-123F-4565-9164-39C4925E467B}", "Downloads"),
            ("My Pictures", "Pictures"),
        )
        folders = []
        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
            ) as key:
                for name, label in wanted:
                    try:
                        raw = str(winreg.QueryValueEx(key, name)[0] or "")
                    except (OSError, ValueError, TypeError):
                        continue
                    path = os.path.expandvars(raw)
                    folders.append({
                        "label": label,
                        "path": path,
                        "exists": os.path.isdir(path),
                        "onedrive": "onedrive" in path.lower(),
                    })
        except OSError:
            return {"available": False}
        if not folders:
            return {"available": False}
        redirected = [f for f in folders if f["onedrive"]]
        onedrive_running = False
        try:
            import psutil
            onedrive_running = any(
                (proc.info["name"] or "").lower() == "onedrive.exe"
                for proc in psutil.process_iter(["name"]))
        except Exception:
            onedrive_running = None
        return {
            "available": True,
            "folders": folders,
            "missing": [f for f in folders if not f["exists"]],
            "redirected": redirected,
            "onedrive_running": onedrive_running,
            # Files live in OneDrive but the client is not running: they are
            # reachable, but nothing is syncing and new files go nowhere.
            "stranded": bool(redirected and onedrive_running is False),
        }
