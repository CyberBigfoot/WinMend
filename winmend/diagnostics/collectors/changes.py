"""WinMend diagnostics: collectors: changes."""

from __future__ import annotations

from pathlib import Path
from winmend.diagnostics.helpers import _days_ago
import os
import re
import time
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


class ProbeChangesMixin:
    """DeepProbe methods grouped by responsibility."""

    # -- change history ---------------------------------------------------

    def installed_updates(self, days=45):
        """Quality updates installed recently, newest first.

        ``Get-HotFix`` is the fast, always-present source. Feature updates do not
        appear there, which is why :meth:`windows_version` is read separately.
        """
        script = (
            "Get-HotFix -ErrorAction Stop | Where-Object {$_.InstalledOn} | "
            "Sort-Object InstalledOn -Descending | Select-Object -First 40 | "
            "ForEach-Object { Write-Output ($_.HotFixID + '|' + "
            "$_.InstalledOn.ToString('yyyy-MM-dd') + '|' + $_.Description) }"
        )
        rc, rows, err = self._ps_rows(script, timeout=30)
        if rc != 0 and not rows:
            return {"available": False, "reason": err[:200]}
        updates = []
        for row in rows:
            if len(row) < 2:
                continue
            age = _days_ago(row[1])
            if age is None or age > days:
                continue
            updates.append({
                "kb": row[0].strip(),
                "installed": row[1].strip(),
                "days_ago": round(age, 1),
                "kind": (row[2].strip() if len(row) > 2 else ""),
            })
        return {"available": True, "updates": updates}

    def installed_programs(self, days=45):
        """Programs whose uninstall entry records a recent install date."""
        if winreg is None:
            return {"available": False}
        roots = (
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        )
        found = []
        for hive, path in roots:
            try:
                root_key = winreg.OpenKey(hive, path)
            except OSError:
                continue
            with root_key:
                count = winreg.QueryInfoKey(root_key)[0]
                for index in range(min(count, 2000)):
                    try:
                        name = winreg.EnumKey(root_key, index)
                        with winreg.OpenKey(root_key, name) as sub:
                            values = {}
                            for field in ("DisplayName", "InstallDate", "Publisher",
                                          "UninstallString", "DisplayVersion", "SystemComponent"):
                                try:
                                    values[field] = winreg.QueryValueEx(sub, field)[0]
                                except OSError:
                                    values[field] = None
                    except OSError:
                        continue
                    if not values.get("DisplayName") or values.get("SystemComponent"):
                        continue
                    age = _days_ago(values.get("InstallDate"))
                    if age is None or age > days or age < 0:
                        continue
                    found.append({
                        "name": str(values["DisplayName"]).strip(),
                        "publisher": str(values.get("Publisher") or "").strip(),
                        "version": str(values.get("DisplayVersion") or "").strip(),
                        "installed": str(values.get("InstallDate") or ""),
                        "days_ago": round(age, 1),
                        "uninstall": str(values.get("UninstallString") or "").strip(),
                        "key": f"{'HKLM' if hive == winreg.HKEY_LOCAL_MACHINE else 'HKCU'}\\{path}\\{name}",
                    })
        found.sort(key=lambda item: item["days_ago"])
        return {"available": True, "programs": found[:40]}

    def third_party_drivers(self, days=45):
        """Third-party driver packages, with the date each was staged.

        ``pnputil /enum-drivers`` lists the package (``oemNN.inf``) that
        :meth:`~RepairAction` can actually remove, which is what makes a targeted
        rollback possible. The INF's own date is the *release* date, so the
        DriverStore file time is used as the install-time proxy.
        """
        rc, out, err = self._run(["pnputil", "/enum-drivers"], timeout=40)
        if rc != 0 and "Published" not in out:
            return {"available": False, "reason": (err or out).strip()[:200]}
        drivers = []
        block = {}
        # pnputil localises its labels, so match on the stable token in each line.
        patterns = (
            ("published", re.compile(r"^\s*\S.*?:\s*(oem\d+\.inf)\s*$", re.I)),
            ("original", re.compile(r"^\s*Original Name\s*:\s*(.+?)\s*$", re.I)),
            ("provider", re.compile(r"^\s*(?:Provider|Driver package provider)\s*:\s*(.+?)\s*$", re.I)),
            ("class", re.compile(r"^\s*Class(?: Name)?\s*:\s*(.+?)\s*$", re.I)),
            ("version", re.compile(r"^\s*(?:Driver )?Version\s*:\s*(.+?)\s*$", re.I)),
        )
        for line in out.splitlines():
            if not line.strip():
                if block.get("published"):
                    drivers.append(block)
                block = {}
                continue
            for field, pattern in patterns:
                match = pattern.match(line)
                if match:
                    block[field] = match.group(1).strip()
                    break
        if block.get("published"):
            drivers.append(block)

        store = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "DriverStore" / "FileRepository"
        inf_dir = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "INF"
        for driver in drivers:
            stamp = None
            candidate = inf_dir / driver["published"]
            try:
                if candidate.exists():
                    stamp = candidate.stat().st_mtime
            except OSError:
                stamp = None
            driver["installed_ts"] = stamp
            driver["days_ago"] = round((time.time() - stamp) / 86400.0, 1) if stamp else None
            version = driver.get("version", "")
            match = re.search(r"(\d{1,2}/\d{1,2}/\d{4})", version)
            driver["release_date"] = match.group(1) if match else ""
        recent = [d for d in drivers
                  if d.get("days_ago") is not None and d["days_ago"] <= days]
        recent.sort(key=lambda item: item["days_ago"])
        return {
            "available": True,
            "total": len(drivers),
            "recent": recent[:30],
            "store_exists": store.exists(),
        }

    def startup_entries(self):
        """Everything Task Manager's Startup tab shows, with its enabled state.

        Collected as evidence rather than looked up inside a rule, so a rule can
        check whether a name it wants to act on is actually something that can
        be disabled -- the boot-performance log names processes Windows starts
        itself, which are not startup entries at all.
        """
        try:
            from winmend.features.startup.helpers import list_startup_entries
            entries = list_startup_entries()
        except Exception as exc:
            return {"available": False, "reason": str(exc)[:200]}
        return {
            "available": True,
            "entries": entries,
            "enabled": [e for e in entries if e.get("enabled")],
        }

    def restore_points(self, count=10):
        script = (
            "Get-ComputerRestorePoint -ErrorAction Stop | Sort-Object CreationTime -Descending | "
            "Select-Object -First %d | ForEach-Object { Write-Output "
            "($_.SequenceNumber.ToString() + '|' + $_.CreationTime.ToString('yyyy-MM-ddTHH:mm:ss') "
            "+ '|' + $_.Description) }"
        ) % max(1, int(count))
        rc, rows, err = self._ps_rows(script, timeout=30)
        if rc != 0 and not rows:
            return {"available": False, "reason": err[:200]}
        points = []
        for row in rows:
            if len(row) < 2:
                continue
            age = _days_ago(row[1])
            points.append({
                "sequence": row[0].strip(),
                "created": row[1].strip(),
                "days_ago": round(age, 1) if age is not None else None,
                "description": row[2].strip() if len(row) > 2 else "",
            })
        # "No restore points" has two very different causes, and the repair is
        # only the same for one of them: protection switched off, or protection
        # on with nothing having triggered a point yet.
        protection = None
        if winreg is not None:
            for hive, path, value in (
                (winreg.HKEY_LOCAL_MACHINE,
                 r"SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore", "DisableSR"),
                (winreg.HKEY_LOCAL_MACHINE,
                 r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore",
                 "RPSessionInterval"),
            ):
                try:
                    with winreg.OpenKey(hive, path) as key:
                        number = int(winreg.QueryValueEx(key, value)[0])
                except (OSError, ValueError, TypeError):
                    continue
                protection = (number == 0) if value == "DisableSR" else (number != 0)
                break
        return {"available": True, "points": points, "protection": protection}
