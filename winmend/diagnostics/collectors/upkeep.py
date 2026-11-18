"""WinMend diagnostics: collectors: upkeep."""

from __future__ import annotations

from winmend.diagnostics.helpers import _days_ago
from winmend.diagnostics.reference import (
    BENIGN_TASK_RESULTS,
    CRITICAL_SERVICES,
    _maintenance_task,
)
from winmend.diagnostics.repairs.common import _START_WORDS, _service_start
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


class ProbeUpkeepMixin:
    """DeepProbe methods grouped by responsibility."""

    # -- services, tasks, and scheduled maintenance ------------------------

    def service_health(self):
        """Which services are stopped, and whether any of them matter.

        The count of automatic-but-stopped services is reported as context
        only. Windows marks many services Automatic and then starts them from a
        trigger, so that number is between five and ten on a healthy PC and
        means nothing. :data:`CRITICAL_SERVICES` is the part that can fail.
        """
        script = (
            "Get-CimInstance Win32_Service -ErrorAction Stop | ForEach-Object { Write-Output "
            "('S|'+$_.Name+'|'+($_.DisplayName -replace '\\|',' ')+'|'+$_.State+'|'"
            "+$_.StartMode+'|'+[string]$_.DelayedAutoStart) }"
        )
        rc, rows, err = self._ps_rows(script, timeout=40)
        services = {}
        for row in rows:
            if row[0] != "S" or len(row) < 5:
                continue
            services[row[1].strip()] = {
                "name": row[1].strip(),
                "display": row[2].strip(),
                "state": row[3].strip(),
                "start_mode": row[4].strip(),
                "delayed": (row[5].strip().lower() == "true") if len(row) > 5 else False,
            }
        if not services:
            return {"available": False, "reason": (err or "")[:200]}
        stopped_auto = [s for s in services.values()
                        if s["start_mode"].lower() == "auto" and s["state"].lower() != "running"]
        critical = []
        for name, why in CRITICAL_SERVICES.items():
            entry = services.get(name)
            if entry is None or entry["state"].lower() == "running":
                continue
            if entry["start_mode"].lower() != "auto":
                # Manual/trigger-start or deliberately disabled is context;
                # neither proves a service crashed or needs reconfiguration.
                continue
            # A service the user (or a debloat script) set to Disabled is a
            # different fault from one that crashed, and needs saying.
            critical.append({**entry, "why": why,
                             "disabled": entry["start_mode"].lower() == "disabled"})
        return {
            "available": True,
            "total": len(services),
            "stopped_auto": [{"name": s["name"], "display": s["display"]} for s in stopped_auto],
            "critical_stopped": critical,
        }

    def scheduled_tasks(self):
        """Scheduled tasks whose last run failed.

        Graded in two bands. A failing maintenance task is a real fault -- a
        broken ScheduledDefrag means the drive is never optimised and a broken
        SR task means the restore points nobody checked were never created. A
        failing leftover from an uninstalled program is noise, so it is
        counted, not warned about.
        """
        script = (
            "Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' } | "
            "ForEach-Object { $t=$_; $i=$null;"
            " try { $i = $t | Get-ScheduledTaskInfo -ErrorAction Stop } catch {};"
            " if ($i -ne $null -and $i.LastTaskResult -ne 0) { Write-Output "
            "('K|'+(($t.TaskPath+$t.TaskName) -replace '\\|',' ')+'|'+[string]$i.LastTaskResult"
            "+'|'+[string]$i.LastRunTime) } }"
        )
        rc, rows, err = self._ps_rows(script, timeout=90)
        if rc != 0 and not rows:
            return {"available": False, "reason": (err or "")[:200]}
        failures = []
        for row in rows:
            if row[0] != "K" or len(row) < 3:
                continue
            try:
                code = int(row[2].strip()) & 0xFFFFFFFF
            except (ValueError, TypeError):
                continue
            if code in BENIGN_TASK_RESULTS:
                continue
            path = row[1].strip()
            known = _maintenance_task(path)
            failures.append({
                "task": path,
                "code": f"0x{code:08X}",
                "last_run": row[3].strip() if len(row) > 3 else "",
                "maintenance": known is not None,
                "consequence": known[0] if known else "",
                "runnable": bool(known and known[1]),
            })
        return {
            "available": True,
            "failures": failures,
            "maintenance_failures": [f for f in failures if f["maintenance"]],
        }

    def update_state(self):
        """Whether Windows Update is still able to run at all.

        Read from the registry rather than by asking Windows Update, because
        the failure this catches is exactly the one where asking gets no
        answer: a debloat script or a policy that disabled the service.
        """
        if winreg is None:
            return {"available": False}
        result = {"available": True, "services": {}, "policies": [], "paused_until": ""}
        for name in ("wuauserv", "bits", "UsoSvc", "WaaSMedicSvc"):
            start = None
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    rf"SYSTEM\CurrentControlSet\Services\{name}",
                ) as key:
                    start = int(winreg.QueryValueEx(key, "Start")[0])
            except (OSError, ValueError, TypeError):
                start = None
            result["services"][name] = {
                "start": start,
                # 4 is the only value that stops the service from ever running.
                "disabled": start == 4,
            }
        for hive, path, value, meaning in (
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
             "NoAutoUpdate", "automatic updates are turned off by policy"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
             "DoNotConnectToWindowsUpdateInternetLocations",
             "this PC is blocked from contacting Windows Update"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
             "DisableWindowsUpdateAccess", "access to Windows Update is blocked by policy"),
        ):
            try:
                with winreg.OpenKey(hive, path) as key:
                    if int(winreg.QueryValueEx(key, value)[0]):
                        result["policies"].append({"value": value, "meaning": meaning})
            except (OSError, ValueError, TypeError):
                continue
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings",
            ) as key:
                paused = str(winreg.QueryValueEx(key, "PauseUpdatesExpiryTime")[0] or "").strip()
                # Windows leaves an expired pause behind, so only a date in the
                # future actually means updates are paused right now.
                if paused and (_days_ago(paused) or 0) < 0:
                    result["paused_until"] = paused
        except (OSError, ValueError, TypeError):
            pass
        result["blocked"] = bool(
            result["policies"] or result["paused_until"]
            or result["services"].get("wuauserv", {}).get("disabled"))
        return result

    def search_index(self):
        """Windows Search: the thing behind Start-menu and File Explorer search.

        Added because "search does not work" was the one common complaint the
        engine could not measure -- it had to take the user's word for it and
        then had nothing to verify a repair against.
        """
        state = self.service_state("WSearch")
        setup = None
        if winreg is not None:
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Search",
                ) as key:
                    setup = bool(winreg.QueryValueEx(key, "SetupCompletedSuccessfully")[0])
            except (OSError, ValueError, TypeError):
                setup = None
        if state == "unknown" and setup is None:
            return {"available": False}
        # Stopped because it crashed and stopped because someone set it to
        # Disabled are different faults with different repairs -- and the
        # second is often deliberate (WinMend's own RAM Optimizations does it).
        start = _service_start("WSearch")
        return {
            "available": True,
            "service": state,
            "start": _START_WORDS.get(start, "unknown"),
            "disabled": start == 4,
            "setup_complete": setup,
            "healthy": state == "running" and setup is not False,
        }
