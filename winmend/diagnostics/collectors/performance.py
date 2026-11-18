"""WinMend diagnostics: collectors: performance."""

from __future__ import annotations

from winmend.diagnostics.reference import POWER_SCHEMES
import os
import re
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


class ProbePerformanceMixin:
    """DeepProbe methods grouped by responsibility."""

    # -- live load and configuration --------------------------------------

    def cpu_load(self, seconds=1.0, top=4):
        """Processor load, and whether one program is holding the machine down.

        The overall number is reported as context only: this sweep runs a
        couple of dozen queries at once, so it is measuring itself as much as
        anything else. What can be judged is a *single* process that keeps a
        large share of the CPU across the whole sample -- and WinMend's own
        process tree is excluded from that judgement for the same reason.
        """
        try:
            import psutil
        except Exception:
            return {"available": False}
        try:
            cores = psutil.cpu_count(logical=True) or 1
            mine = {os.getpid()}
            try:
                mine.update(child.pid for child in psutil.Process().children(recursive=True))
            except Exception:
                pass
            procs = []
            for proc in psutil.process_iter(["name"]):
                try:
                    # The idle process is the CPU doing nothing. Left in, it
                    # ranks first on every healthy PC and reads as a runaway.
                    if proc.pid == 0 or (proc.info.get("name") or "").lower() in (
                            "system idle process", "idle"):
                        continue
                    proc.cpu_percent(None)
                    procs.append(proc)
                except Exception:
                    continue
            overall = psutil.cpu_percent(interval=max(0.3, float(seconds)))
            sampled = []
            for proc in procs:
                try:
                    share = proc.cpu_percent(None) / cores
                    name = (proc.info.get("name") or "?")
                except Exception:
                    continue
                if share <= 0.5:
                    continue
                sampled.append({"name": name, "pid": proc.pid, "pct": round(share, 1),
                                "ours": proc.pid in mine})
        except Exception:
            return {"available": False}
        sampled.sort(key=lambda item: -item["pct"])
        others = [p for p in sampled if not p["ours"]]
        return {
            "available": True,
            "used_pct": round(float(overall), 1),
            "cores": cores,
            "top": sampled[:max(1, int(top))],
            "hog": others[0] if others and others[0]["pct"] >= 50 else None,
        }

    def power_config(self):
        """The active power plan and fast startup.

        Power saver on a desktop is a genuine and completely invisible cause of
        "this PC got slow": nothing reports it, and it caps the processor.
        """
        if winreg is None:
            return {"available": False}
        guid = ""
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes",
            ) as key:
                guid = str(winreg.QueryValueEx(key, "ActivePowerScheme")[0] or "").strip().lower()
        except OSError:
            guid = ""
        hiberboot = None
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Power",
            ) as key:
                hiberboot = bool(winreg.QueryValueEx(key, "HiberbootEnabled")[0])
        except (OSError, ValueError, TypeError):
            hiberboot = None
        if not guid and hiberboot is None:
            return {"available": False}
        name, saver = POWER_SCHEMES.get(guid, ("", None))
        if not name and guid:
            # OEMs ship their own schemes, so an unknown GUID gets looked up by
            # name rather than assumed to be anything in particular.
            name = self._power_scheme_name(guid)
        # Power saver on a laptop that is running on battery is the right
        # setting, not a fault, so the verdict depends on knowing which this is.
        battery = None
        try:
            import psutil
            battery = psutil.sensors_battery()
        except Exception:
            battery = None
        return {
            "available": True,
            "scheme": guid,
            "name": name or "an unrecognised plan",
            "known": guid in POWER_SCHEMES,
            "power_saver": saver,
            "fast_startup": hiberboot,
            "has_battery": battery is not None,
            "on_battery": bool(battery is not None and not battery.power_plugged),
        }

    def _power_scheme_name(self, guid):
        rc, out, _ = self._run(["powercfg", "/list"], timeout=15)
        if rc != 0:
            return ""
        for line in out.splitlines():
            if guid in line.lower():
                match = re.search(r"\(([^)]*)\)", line)
                if match:
                    return match.group(1).strip()
        return ""
