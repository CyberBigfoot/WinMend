"""Bounded, read-only structured Windows context, networking and repeated load."""
from __future__ import annotations
import ctypes
import json
import os
import platform
import socket
import time
import sys

from winmend.diagnostics.observations import failure_state

PROBE_ENDPOINTS = ("1.1.1.1:443", "8.8.8.8:443", "[2606:4700:4700::1111]:443",
                   "[2001:4860:4860::8888]:443", "www.microsoft.com", "cloudflare.com")


def management_state():
    """Documented local APIs; request no domain string or registered user's UPN."""
    result = {"domain_joined": None, "mdm_managed": None}
    if os.name != "nt":
        return result
    try:
        library = ctypes.WinDLL("netapi32", winmode=0x800)
        join = library.NetGetJoinInformation
        join.argtypes = (ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_int))
        join.restype = ctypes.c_ulong
        free = library.NetApiBufferFree
        free.argtypes = (ctypes.c_void_p,)
        free.restype = ctypes.c_ulong
        buffer, state = ctypes.c_void_p(), ctypes.c_int()
        try:
            if join(None, ctypes.byref(buffer), ctypes.byref(state)) == 0 and state.value in (1, 2, 3):
                result["domain_joined"] = state.value == 3
        finally:
            if buffer.value:
                free(buffer)
    except (OSError, AttributeError):
        pass
    try:
        check = ctypes.WinDLL("MDMRegistration", winmode=0x800).IsDeviceRegisteredWithManagement
        check.argtypes = (ctypes.POINTER(ctypes.c_int), ctypes.c_ulong, ctypes.c_wchar_p)
        check.restype = ctypes.c_long
        registered = ctypes.c_int()
        if check(ctypes.byref(registered), 0, None) == 0:
            result["mdm_managed"] = bool(registered.value)
    except (OSError, AttributeError):
        pass
    return result


def commit_usage():
    """GetPerformanceInfo counts committed pages, not physical RAM caching."""
    if os.name != "nt":
        return None
    class PerformanceInfo(ctypes.Structure):
        _fields_ = [("cb", ctypes.c_ulong)] + [(n, ctypes.c_size_t) for n in (
            "CommitTotal", "CommitLimit", "CommitPeak", "PhysicalTotal", "PhysicalAvailable",
            "SystemCache", "KernelTotal", "KernelPaged", "KernelNonpaged", "PageSize")] + [
            ("HandleCount", ctypes.c_ulong), ("ProcessCount", ctypes.c_ulong),
            ("ThreadCount", ctypes.c_ulong)]
    info = PerformanceInfo()
    info.cb = ctypes.sizeof(info)
    if not ctypes.windll.psapi.GetPerformanceInfo(ctypes.byref(info), info.cb):
        return None
    return {"commit_pct": 100.0 * info.CommitTotal / info.CommitLimit if info.CommitLimit else None,
            "commit_gb": info.CommitTotal * info.PageSize / 1024**3,
            "commit_limit_gb": info.CommitLimit * info.PageSize / 1024**3}


class ProbeIntelligenceMixin:
    def _ps_json(self, script, timeout=20):
        full = "$ErrorActionPreference='Stop'; try { " + script + (
            " } catch { @{available=$false;reason=$_.Exception.Message;error_id=$_.FullyQualifiedErrorId;error_category=[string]$_.CategoryInfo.Category} | ConvertTo-Json -Compress -Depth 8; exit 1 }")
        rc, out, err = self._ps(full, timeout=timeout)
        try:
            data = json.loads(out.strip().lstrip("\ufeff"))
        except (ValueError, TypeError):
            return {"available": False, "reason": (err or "Provider returned no structured data")[:200]}
        if not isinstance(data, dict):
            return {"available": False, "reason": "Invalid provider result"}
        if rc != 0:
            data["available"] = False
        if data.get("available") is False:
            data["diagnostic_state"] = failure_state(" ".join(str(data.get(k) or "") for k in ("reason", "error_id", "error_category")))
        return data

    def system_context(self):
        # No host name, user name, domain name, serial number or MAC is requested.
        result = self._ps_json(r"""
            $c=Get-CimInstance Win32_ComputerSystem;
            $o=Get-CimInstance Win32_OperatingSystem;
            $a=@(Get-NetAdapter | Where-Object Status -eq 'Up');
            $nrpt=@(Get-DnsClientNrptPolicy -Effective);
            $boot=$null;try{$boot=Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-Kernel-General';Id=12} -MaxEvents 1 -ErrorAction Stop}catch{};
            @{available=$true;version=$o.Version;build=$o.BuildNumber;edition=$o.Caption;
              architecture=$o.OSArchitecture;
              physical_memory_gb=[math]::Round($c.TotalPhysicalMemory/1GB,2);
              vm=($c.Model -match 'Virtual|VMware|KVM|VirtualBox');
              active_adapters=@($a|ForEach-Object { @{index=$_.InterfaceIndex;physical=[bool]$_.HardwareInterface} });
              vpn_present=(@($a|Where-Object InterfaceDescription -match 'VPN|TAP|TUN|WireGuard|Tailscale|AnyConnect').Count -gt 0);
              virtual_network=(@($a|Where-Object { -not $_.HardwareInterface }).Count -gt 0);
              split_dns=($nrpt.Count -gt 0);
              boot_event_record_id=$boot.RecordId;
              capabilities=@{netadapter=[bool](Get-Command Get-NetAdapter -ErrorAction SilentlyContinue);
                            dnsclient=[bool](Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)}
            } | ConvertTo-Json -Compress -Depth 6
        """, timeout=20)
        result.update(management_state())
        try:
            import psutil
            result["boot_time"] = psutil.boot_time()
            result["uptime_seconds"] = max(0, time.time() - result["boot_time"])
            battery = psutil.sensors_battery()
            result["on_battery"] = bool(battery and not battery.power_plugged)
        except Exception:
            result["on_battery"] = None
        try:
            result["admin"] = bool(ctypes.windll.shell32.IsUserAnAdmin())
            result["remote_session"] = bool(ctypes.windll.user32.GetSystemMetrics(0x1000))
        except Exception:
            result["admin"] = result["remote_session"] = None
        result["python_architecture"] = platform.machine()
        if os.name == "nt":
            version = sys.getwindowsversion()
            result.setdefault("version", f"{version.major}.{version.minor}.{version.build}")
            result.setdefault("build", str(version.build))
            result.setdefault("architecture", platform.machine())
            tick = ctypes.windll.kernel32.GetTickCount64
            tick.argtypes = ()
            tick.restype = ctypes.c_ulonglong
            result["boot_uptime_ms"] = tick()
        return result

    def layered_network(self):
        """Two destinations, two attempts; no ICMP or traffic to user-entered URLs."""
        tcp = []
        families = {socket.AF_INET: None, socket.AF_INET6: None}
        try:
            import psutil
            stats, addresses = psutil.net_if_stats(), psutil.net_if_addrs()
            for family in families:
                families[family] = any(a.family == family and not a.address.startswith(("127.", "169.254.", "fe80:", "::1"))
                    for name, rows in addresses.items() if stats.get(name) and stats[name].isup for a in rows)
        except Exception:
            pass
        endpoints = [] if families[socket.AF_INET] is False else ["1.1.1.1", "8.8.8.8"]
        if families[socket.AF_INET6] is True:
            endpoints += ["2606:4700:4700::1111", "2001:4860:4860::8888"]
        for attempt in range(2):
            for host in endpoints:
                start = time.perf_counter()
                try:
                    with socket.create_connection((host, 443), timeout=1.5):
                        ok, error = True, None
                except OSError as exc:
                    ok, error = False, type(exc).__name__
                tcp.append({"endpoint": (f"[{host}]:443" if ":" in host else host + ":443"), "attempt": attempt, "ok": ok,
                            "family": "IPv6" if ":" in host else "IPv4",
                            "ms": round((time.perf_counter()-start)*1000, 1), "error": error})
        dns = self._ps_json(r"""
            $rows=@(); for($attempt=0;$attempt -lt 2;$attempt++) {
              foreach($name in @('www.microsoft.com','cloudflare.com')) {
                $s=[Diagnostics.Stopwatch]::StartNew();
                try { $r=@(Resolve-DnsName -Name $name -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop);
                  $rows+=@{name=$name;attempt=$attempt;ok=(@($r|Where-Object IPAddress).Count -gt 0);ms=$s.Elapsed.TotalMilliseconds} }
                catch { $rows+=@{name=$name;attempt=$attempt;ok=$false;error=$_.FullyQualifiedErrorId;ms=$s.Elapsed.TotalMilliseconds} }
              }
            }; @{available=$true;results=$rows}|ConvertTo-Json -Compress -Depth 5
        """, timeout=18)
        https = self._ps_json(r"""
            $rows=@(); foreach($uri in @('https://www.microsoft.com','https://cloudflare.com')) {
              try { $r=Invoke-WebRequest -Uri $uri -Method Head -UseBasicParsing -TimeoutSec 4 -MaximumRedirection 3;
                $rows+=@{endpoint=$uri;ok=$true;status=[int]$r.StatusCode} }
              catch { $code=$null; if($_.Exception.Response) { $code=[int]$_.Exception.Response.StatusCode };
                $rows+=@{endpoint=$uri;ok=($null -ne $code);status=$code;error=$_.Exception.GetType().Name} }
            }; @{available=$true;results=$rows}|ConvertTo-Json -Compress -Depth 4
        """, timeout=12)
        return {"available": True, "tcp": tcp, "dns": dns, "https": https,
                "address_families": {"ipv4": families[socket.AF_INET], "ipv6": families[socket.AF_INET6]},
                "repeated": True, "endpoints": list(PROBE_ENDPOINTS),
                "limitations": "Public probes cannot test a private VPN domain or the affected application. TCP failures may be filtered."}

    def performance_samples(self, samples=4, interval=0.75):
        """Short comparable window, deliberately run after the subprocess sweep."""
        import psutil
        samples = min(8, max(3, int(samples)))
        interval = min(2, max(0.25, float(interval)))
        ours = {os.getpid()}
        try:
            ours.update(p.pid for p in psutil.Process().children(recursive=True))
        except psutil.Error:
            pass
        cores = psutil.cpu_count() or 1
        processes = []
        for proc in psutil.process_iter(["name"]):
            if proc.pid in ours or proc.pid == 0:
                continue
            try:
                proc.cpu_percent(None)
                processes.append(proc)
            except psutil.Error:
                continue
        psutil.cpu_percent(None)
        previous = psutil.disk_io_counters(perdisk=True) or {}
        rows, process_rows, errors = [], {}, []
        for index in range(samples):
            time.sleep(interval)
            mem = psutil.virtual_memory()
            commit = commit_usage() or {}
            current = psutil.disk_io_counters(perdisk=True) or {}
            disks = []
            for device, now in current.items():
                old = previous.get(device)
                if old is None:
                    continue
                ops = (now.read_count-old.read_count) + (now.write_count-old.write_count)
                ms = (now.read_time-old.read_time) + (now.write_time-old.write_time)
                disks.append({"device": device, "ops": max(0, ops),
                              "latency_ms": round(ms/ops, 2) if ops >= 50 and ms >= 0 else None,
                              "throughput_mbps": max(0, now.read_bytes-old.read_bytes+now.write_bytes-old.write_bytes)/interval/1024**2})
            row = {"sample": index, "cpu_pct": psutil.cpu_percent(None),
                   "available_pct": 100*mem.available/mem.total,
                   "available_gb": mem.available/1024**3, "used_pct": mem.percent,
                   **commit, "disks": disks}
            rows.append(row)
            previous = current
            for proc in processes:
                try:
                    share = proc.cpu_percent(None)/cores
                    item = process_rows.setdefault(proc.pid, {"name": proc.info["name"], "pid": proc.pid,
                                                           "cpu_samples": [], "memory_gb": 0})
                    item["cpu_samples"].append(share)
                    item["memory_gb"] = proc.memory_info().rss/1024**3
                except psutil.Error:
                    continue
        paging = self._ps_json("$m=Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory; "
                               "@{available=$true;pages_input_per_second=$m.PagesInputPersec}|ConvertTo-Json -Compress", timeout=8)
        ranked = sorted(process_rows.values(), key=lambda p: -sum(p["cpu_samples"])/max(1,len(p["cpu_samples"])))
        return {"available": True, "samples": rows, "processes": ranked[:8],
                "paging": paging, "duration_seconds": samples*interval, "errors": errors,
                "update_active": any(str(p["name"]).lower() in ("tiworker.exe", "trustedinstaller.exe", "mousocoreworker.exe")
                                     and max(p["cpu_samples"], default=0) >= 10 for p in ranked),
                "limitations": "A few seconds of load does not establish long-term persistence or hardware health."}
