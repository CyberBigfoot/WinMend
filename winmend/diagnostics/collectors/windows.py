"""WinMend diagnostics: collectors: windows."""

from __future__ import annotations

from pathlib import Path
import os
import shutil
import socket
import subprocess
import time
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


def guard_event_query(script, marker):
    """An empty matching set is valid; other query/processing errors are not."""
    guarded = script.replace("-ErrorAction SilentlyContinue",
                             "-ErrorAction SilentlyContinue -ErrorVariable +wmQueryErrors")
    return "$ErrorActionPreference='Stop';$wmQueryErrors=@();try{" + guarded + (
        ";$bad=@($wmQueryErrors | Where-Object { $_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*' });"
        f"if($bad.Count -eq 0) {{ Write-Output ('{marker}|1') }} "
        "else { [Console]::Error.WriteLine(($bad[0].Exception.Message)) }"
        "}catch{[Console]::Error.WriteLine($_.Exception.Message);exit 1}")


class WindowsProbe:
    """Bounded, read-only checks used by the guided workflow."""

    def _run(self, command, timeout=8):
        try:
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            result = subprocess.run(
                command, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=timeout, creationflags=flags,
            )
            return result.returncode, (result.stdout or ""), (result.stderr or "")
        except Exception as exc:
            return -1, "", str(exc)

    def disk(self):
        drive = os.environ.get("SystemDrive", "C:") + os.sep
        usage = shutil.disk_usage(drive)
        free_pct = usage.free / usage.total * 100 if usage.total else 0
        return {"free_gb": usage.free / 1024 ** 3, "free_pct": free_pct}

    def memory(self):
        try:
            import psutil
            value = psutil.virtual_memory()
            return {"used_pct": float(value.percent), "available_gb": value.available / 1024 ** 3}
        except Exception as exc:
            return {"available": False, "reason": str(exc)[:200]}

    def uptime_days(self):
        try:
            import psutil
            return max(0.0, (time.time() - psutil.boot_time()) / 86400)
        except Exception:
            return None

    def temp_size(self, max_entries=40000):
        raw_roots = (
            os.environ.get("TEMP"),
            os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp"),
        )
        roots = {
            os.path.normcase(os.path.normpath(root)) for root in raw_roots if root
        }
        total = 0
        entries = 0
        for root in roots:
            if not root or not os.path.isdir(root):
                continue
            for base, dirs, files in os.walk(root, topdown=True):
                dirs[:] = dirs[:200]
                for name in files:
                    if entries >= max_entries:
                        return {"bytes": total, "partial": True}
                    entries += 1
                    try:
                        total += os.path.getsize(os.path.join(base, name))
                    except OSError:
                        pass
        return {"bytes": total, "partial": False}

    def startup_count(self):
        count = 0
        if winreg is not None:
            locations = (
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            )
            for hive, key_name in locations:
                try:
                    with winreg.OpenKey(hive, key_name) as key:
                        count += winreg.QueryInfoKey(key)[1]
                except OSError:
                    pass
        for folder in (
            os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.join(os.environ.get("PROGRAMDATA", ""), r"Microsoft\Windows\Start Menu\Programs\StartUp"),
        ):
            try:
                count += sum(1 for item in os.scandir(folder) if not item.name.startswith("."))
            except OSError:
                pass
        return count

    def pending_reboot(self):
        if winreg is None:
            return False
        checks = (
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"),
        )
        for hive, path in checks:
            try:
                with winreg.OpenKey(hive, path):
                    return True
            except OSError:
                pass
        return False

    def service_state(self, name):
        rc, out, _ = self._run(["sc", "query", name], timeout=6)
        upper = out.upper()
        if rc == 0 and "RUNNING" in upper:
            return "running"
        if rc == 0 and "STOPPED" in upper:
            return "stopped"
        return "unknown"

    def network(self):
        adapters = None
        try:
            import psutil
            adapters = sum(
                1 for name, stats in psutil.net_if_stats().items()
                if stats.isup and not name.lower().startswith(("loopback", "isatap"))
            )
        except Exception:
            pass
        # DNS is bounded by the subprocess timeout; getaddrinfo has no timeout.
        dns = None
        reachable = False
        try:
            rc, out, _ = self._run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                "Resolve-DnsName www.microsoft.com -DnsOnly -QuickTimeout -ErrorAction Stop | Select-Object -First 1 -ExpandProperty Name"], timeout=6)
            dns = bool(out.strip()) if rc == 0 else None
        except Exception:
            pass
        try:
            with socket.create_connection(("1.1.1.1", 443), timeout=2):
                reachable = True
        except OSError:
            pass
        return {"adapters": adapters, "dns": dns, "reachable": reachable}

    def crash_dumps(self):
        root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        dump_dir = root / "Minidump"
        try:
            recent = [p for p in dump_dir.glob("*.dmp") if time.time() - p.stat().st_mtime < 30 * 86400]
        except OSError:
            recent = []
        if (root / "MEMORY.DMP").exists():
            recent.append(root / "MEMORY.DMP")
        return len(recent)

    def defender(self):
        script = (
            "$s=Get-MpComputerStatus -ErrorAction Stop; "
            "Write-Output ($s.AntivirusEnabled.ToString()+'|'+"
            "$s.RealTimeProtectionEnabled.ToString()+'|'+"
            "$s.AntivirusSignatureAge.ToString()+'|'+[string]$s.AMRunningMode)"
        )
        rc, out, _ = self._run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "RemoteSigned", "-Command", script],
            timeout=12,
        )
        if rc != 0 or "|" not in out:
            return {"available": False, "enabled": None, "realtime": None, "signature_age": None}
        parts = out.strip().split("|")
        try:
            age = int(parts[2])
        except (IndexError, ValueError):
            age = None
        return {
            "available": True,
            "enabled": parts[0].lower() == "true",
            "realtime": len(parts) > 1 and parts[1].lower() == "true",
            "signature_age": age,
            "running_mode": parts[3].strip() if len(parts) > 3 else None,
        }

    def firewall_enabled(self):
        rc, out, _ = self._run(["netsh", "advfirewall", "show", "allprofiles", "state"], timeout=8)
        if rc != 0:
            return None
        states = [line.split()[-1].upper() for line in out.splitlines()
                  if line.strip().lower().startswith("state")]
        return all(state == "ON" for state in states) if states else None

    def battery(self):
        try:
            import psutil
            battery = psutil.sensors_battery()
            if battery is None:
                return {"present": False}
            return {"present": True, "percent": float(battery.percent), "plugged": bool(battery.power_plugged)}
        except Exception:
            return {"present": False}

    def smart_health(self):
        script = (
            "Get-PhysicalDisk -ErrorAction Stop | ForEach-Object { "
            "Write-Output ($_.FriendlyName + '|' + $_.HealthStatus) }"
        )
        rc, out, _ = self._run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "RemoteSigned", "-Command", script],
            timeout=15,
        )
        if rc != 0 or "|" not in out:
            return {"available": False, "disks": 0, "unhealthy": []}
        disks = 0
        unhealthy = []
        for line in out.splitlines():
            name, sep, status = line.strip().partition("|")
            if not sep:
                continue
            disks += 1
            if status.strip().lower() != "healthy":
                unhealthy.append(f"{name.strip()} ({status.strip()})")
        return {"available": disks > 0, "disks": disks, "unhealthy": unhealthy}

    def event_log_errors(self, days=7):
        script = (
            "$t=(Get-Date).AddDays(-%d); $s41=0; $dsk=0; $svc=0;"
            "$e=Get-WinEvent -FilterHashtable @{LogName='System';StartTime=$t;Id=@(41,7,51,153,7031,7034)}"
            " -MaxEvents 400 -ErrorAction SilentlyContinue;"
            "foreach($ev in $e){ $id=$ev.Id;"
            " if($id -eq 41){$s41++}"
            " elseif($id -in 7,51,153){ if($ev.ProviderName -match 'disk|stor'){$dsk++} }"
            " elseif($id -in 7031,7034){$svc++} };"
            "$w=Get-WinEvent -FilterHashtable @{LogName='System';StartTime=$t;"
            "ProviderName='Microsoft-Windows-WHEA-Logger'} -MaxEvents 100 -ErrorAction SilentlyContinue;"
            "Write-Output ('shutdowns|'+$s41); Write-Output ('disk|'+$dsk);"
            "Write-Output ('services|'+$svc); Write-Output ('hardware|'+@($w).Count)"
        ) % max(1, int(days))
        marker = "__wm_event_counts_ready__"
        script = guard_event_query(script, marker)
        rc, out, err = self._run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "RemoteSigned", "-Command", script],
            timeout=25,
        )
        counts = {}
        for line in out.splitlines():
            key, sep, value = line.strip().partition("|")
            if sep and value.strip().isdigit():
                counts[key] = int(value.strip())
        if f"{marker}|1" not in out.splitlines() or len(counts) < 4:
            return {"available": False, "reason": (err or "Event counts could not be collected")[:200]}
        return {
            "available": True,
            "unexpected_shutdowns": counts.get("shutdowns", 0),
            "disk_errors": counts.get("disk", 0),
            "service_crashes": counts.get("services", 0),
            "hardware_errors": counts.get("hardware", 0),
        }

    def ping_quality(self, host="1.1.1.1", port=443, attempts=4):
        """Latency and loss via TCP connect timing -- locale-proof, no subprocess."""
        times = []
        failures = 0
        for _ in range(max(1, attempts)):
            start = time.perf_counter()
            try:
                with socket.create_connection((host, port), timeout=2):
                    times.append((time.perf_counter() - start) * 1000)
            except OSError:
                failures += 1
        return {
            "attempts": max(1, attempts),
            "failures": failures,
            "avg_ms": (sum(times) / len(times)) if times else None,
        }

    def top_memory_processes(self, count=3):
        try:
            import psutil
        except Exception:
            return []
        totals = {}
        for proc in psutil.process_iter(["name", "memory_info"]):
            try:
                name = (proc.info["name"] or "?").lower()
                if name.endswith(".exe"):
                    name = name[:-4]
                totals[name] = totals.get(name, 0) + proc.info["memory_info"].rss
            except Exception:
                continue
        ranked = sorted(totals.items(), key=lambda item: item[1], reverse=True)
        return [{"name": name, "mb": rss / 1024 ** 2} for name, rss in ranked[:count]]

    def boot_history(self, boots=10, slow_events=30):
        """Boot durations (event 100) and per-app/service boot delays (101/103)
        from the Diagnostics-Performance log. Reading that log needs
        administrator rights; callers get {"available": False} otherwise."""
        script = (
            "$log='Microsoft-Windows-Diagnostics-Performance/Operational';"
            "$b=Get-WinEvent -FilterHashtable @{LogName=$log;Id=100} -MaxEvents %d -ErrorAction Stop;"
            "foreach($e in $b){$x=[xml]$e.ToXml();$d=@{};"
            "foreach($n in $x.Event.EventData.Data){$d[$n.Name]=$n.'#text'};"
            "Write-Output ('BOOT|'+$e.TimeCreated.ToString('s')+'|'+$d['BootTime']+'|'"
            "+$d['MainPathBootTime']+'|'+$d['BootPostBootTime'])};"
            "$s=Get-WinEvent -FilterHashtable @{LogName=$log;Id=@(101,103)} -MaxEvents %d -ErrorAction SilentlyContinue;"
            "foreach($e in $s){$x=[xml]$e.ToXml();$d=@{};"
            "foreach($n in $x.Event.EventData.Data){$d[$n.Name]=$n.'#text'};"
            "$name=$d['Name'];if(-not $name){$name=$d['ServiceFriendlyName']};"
            "$path=$d['Path'];if(-not $path){$path=$d['ServiceName']};"
            "Write-Output ('SLOW|'+$e.TimeCreated.ToString('s')+'|'+$e.Id+'|'+$name+'|'+$path+'|'+$d['DegradationTime'])}"
        ) % (max(1, int(boots)), max(1, int(slow_events)))
        rc, out, err = self._run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "RemoteSigned", "-Command", script],
            timeout=30,
        )
        boot_rows, slow_rows = [], []
        for line in out.splitlines():
            parts = line.strip().split("|")
            if parts[0] == "BOOT" and len(parts) == 5:
                try:
                    boot_rows.append({
                        "time": parts[1],
                        "total_s": float(parts[2]) / 1000.0,
                        "desktop_s": float(parts[3]) / 1000.0,
                        "background_s": float(parts[4]) / 1000.0,
                    })
                except ValueError:
                    continue
            elif parts[0] == "SLOW" and len(parts) == 6:
                try:
                    seconds = float(parts[5]) / 1000.0
                except ValueError:
                    continue
                slow_rows.append({
                    "time": parts[1],
                    "kind": "service" if parts[2] == "103" else "app",
                    "name": parts[3],
                    "path": parts[4],
                    "degradation_s": seconds,
                })
        if rc != 0 or not boot_rows:
            return {"available": False, "reason": (err or out or "").strip()[:200]}
        return {"available": True, "boots": boot_rows, "slow": slow_rows}
