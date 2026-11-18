"""WinMend diagnostics: collectors: updates."""

from __future__ import annotations

from pathlib import Path
from winmend.diagnostics.reference import _LICENSE_STATUS
import os
import time
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


class ProbeUpdatesMixin:
    """DeepProbe methods grouped by responsibility."""

    # -- Windows servicing --------------------------------------------------

    def update_policy(self):
        """Policies that redirect or pin Windows Update.

        ``update_state`` already catches updates being switched *off*. This
        catches the quieter version: a PC pointed at an update server that does
        not exist, or pinned to a Windows version it will now never leave.
        Both report "you are up to date" while silently receiving nothing.
        """
        if winreg is None:
            return {"available": False}
        policies = []
        wsus = ""
        pinned = ""
        deferrals = []
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
            ) as key:
                for name in ("WUServer", "WUStatusServer"):
                    try:
                        value = str(winreg.QueryValueEx(key, name)[0] or "").strip()
                    except (OSError, ValueError, TypeError):
                        continue
                    if value:
                        wsus = wsus or value
                for name, label in (
                    ("TargetReleaseVersionInfo", "pinned to a specific Windows version"),
                    ("ProductVersion", "pinned to a specific Windows edition"),
                ):
                    try:
                        value = str(winreg.QueryValueEx(key, name)[0] or "").strip()
                    except (OSError, ValueError, TypeError):
                        continue
                    if value:
                        pinned = pinned or value
                        policies.append({"value": name, "data": value, "meaning": label})
                for name, label in (
                    ("DeferFeatureUpdatesPeriodInDays", "feature updates held back"),
                    ("DeferQualityUpdatesPeriodInDays", "security updates held back"),
                ):
                    try:
                        days = int(winreg.QueryValueEx(key, name)[0])
                    except (OSError, ValueError, TypeError):
                        continue
                    if days > 0:
                        deferrals.append({"value": name, "days": days, "meaning": label})
        except OSError:
            pass
        use_wsus = None
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
            ) as key:
                try:
                    use_wsus = bool(int(winreg.QueryValueEx(key, "UseWUServer")[0]))
                except (OSError, ValueError, TypeError):
                    use_wsus = None
        except OSError:
            use_wsus = None
        if wsus and use_wsus:
            policies.append({
                "value": "WUServer", "data": wsus,
                "meaning": f"updates come from {wsus} instead of Microsoft",
            })
        return {
            "available": True,
            "wsus": wsus,
            "use_wsus": bool(use_wsus),
            # A WSUS address on a home PC is almost always a leftover: a work
            # laptop that left the domain, or a "block telemetry" script.
            "redirected": bool(wsus and use_wsus),
            "pinned_version": pinned,
            "deferrals": deferrals,
            "policies": policies,
            "constrained": bool(policies or deferrals),
        }

    def update_cache(self):
        """The size and age of the Windows Update working folder.

        A download that keeps failing leaves its partial files behind and
        retries against them forever. That is the "stuck at 0%" that resetting
        the cache fixes, and the reading that says so is how big and how old
        the folder is.
        """
        root = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "SoftwareDistribution"
        download = root / "Download"
        if not root.exists():
            return {"available": False}
        total = 0
        files = 0
        oldest = None
        newest = None
        partial = False
        try:
            for path in download.rglob("*"):
                if files >= 20000:
                    partial = True
                    break
                try:
                    if not path.is_file():
                        continue
                    stat = path.stat()
                except OSError:
                    continue
                files += 1
                total += stat.st_size
                stamp = stat.st_mtime
                oldest = stamp if oldest is None else min(oldest, stamp)
                newest = stamp if newest is None else max(newest, stamp)
        except OSError:
            partial = True
        age_days = None
        if oldest is not None:
            age_days = (time.time() - oldest) / 86400.0
        return {
            "available": True,
            "gb": total / 1024 ** 3,
            "files": files,
            "partial": partial,
            "oldest_days": age_days,
            "newest_days": (time.time() - newest) / 86400.0 if newest else None,
            # Large *and* stale together: a big cache that was written this
            # morning is an update in progress, not a stuck one.
            "stale": bool(total > 2 * 1024 ** 3 and (age_days or 0) > 10),
        }

    def activation_state(self):
        """Whether Windows is licensed, and how long any grace period has left."""
        script = (
            "Get-CimInstance SoftwareLicensingProduct -Filter "
            "\"ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' "
            "AND PartialProductKey IS NOT NULL\" -ErrorAction SilentlyContinue | ForEach-Object {"
            "Write-Output ('LIC|'+$_.Name+'|'+$_.LicenseStatus+'|'+$_.GracePeriodRemaining)}"
        )
        ready, rows, _ = self._ps_events(script, timeout=25)
        if not ready:
            return {"available": False}
        products = []
        for row in rows:
            if row[0] != "LIC" or len(row) < 4:
                continue
            try:
                status = int(row[2])
            except (ValueError, TypeError):
                continue
            try:
                grace = int(row[3])
            except (ValueError, TypeError):
                grace = 0
            products.append({
                "name": row[1].strip(),
                "status": status,
                "state": _LICENSE_STATUS.get(status, f"status {status}"),
                "licensed": status == 1,
                "grace_minutes": grace,
                "grace_days": round(grace / 1440.0, 1) if grace else 0,
            })
        if not products:
            return {"available": True, "known": False, "licensed": None, "products": []}
        return {
            "available": True,
            "known": True,
            "licensed": any(p["licensed"] for p in products),
            "products": products,
            "state": products[0]["state"],
        }
