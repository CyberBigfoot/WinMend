"""WinMend features: hardware tests."""

from __future__ import annotations

from winmend.core.processes import (
    _no_console_startupinfo,
    wm_kill_tree,
    wm_run,
    wm_track_child,
    wm_untrack_child,
)
from winmend.core.prompts import messagebox
import ctypes
from contextlib import ExitStack
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

RAM_CHUNK_BYTES = 64 * 1024 * 1024


class HardwareTestsTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    # ── v1.9 hardware test handlers ──

    def _get_whea_error_count(self):
        """Count WHEA-Logger hardware error events in the System log. -1 on failure."""
        try:
            r = self._run_ps("""
                try {
                    $ev = @(Get-WinEvent -FilterHashtable @{LogName='System';
                        ProviderName='Microsoft-Windows-WHEA-Logger'; Level=1,2,3} -ErrorAction Stop)
                } catch {
                    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
                    $ev = @()
                }
                Write-Output "WHEA_OK|$($ev.Count)"
            """)
            match = re.search(r'^WHEA_OK\|(\d+)\s*$', r.stdout or "", re.MULTILINE)
            return int(match[1]) if r.returncode == 0 and match else -1
        except Exception:
            return -1

    def _get_display_errors(self, since=None):
        """Return (count, recent messages); -1 distinguishes unreadable from clean."""
        cutoff = (f"[DateTimeOffset]::FromUnixTimeSeconds({int(since)}).LocalDateTime"
                  if since is not None else "(Get-Date).AddDays(-30)")
        script = f"$cutoff = {cutoff};" + r'''
            try {
                $events = @(Get-WinEvent -FilterHashtable @{
                    LogName='System'; Level=1,2,3; StartTime=$cutoff
                } -ErrorAction Stop)
            } catch {
                if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
                $events = @()
            }
            $ev = @($events | Where-Object {
                $_.ProviderName -match '^(Display|nvlddmkm|amdkmdag|amdkmdap|amdwddmg|igfx\w*)$'
            })
            Write-Output "DISPLAY_OK|$($ev.Count)"
            foreach ($e in ($ev | Select-Object -First 3)) {
                Write-Output ("EV|" + $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + " " +
                    $e.ProviderName + " " + $e.Id + ": " + (($e.Message -split "`r?`n")[0]))
            }
        '''
        try:
            r = self._run_ps(script)
            match = re.search(r'^DISPLAY_OK\|(\d+)\s*$', r.stdout or "", re.MULTILINE)
            if r.returncode == 0 and match:
                messages = [line[3:][:200] for line in (r.stdout or "").splitlines()
                            if line.startswith("EV|")]
                return int(match[1]), messages
        except Exception:
            pass
        return -1, []

    def run_gpu_stress_test(self):
        """Run a cancellable, finite shader workload on Qt's selected hardware GPU."""
        label = "GPU Stress Test"
        duration = 60
        if not messagebox.askyesno(
                label, f"Run a graphics shader workload for {duration} seconds?\n\n"
                "GPU use, temperature and fan speed may rise. Save your work and plug "
                "laptops in first. The activity log will name the GPU being tested; "
                "on PCs with multiple GPUs, only the adapter selected by the graphics "
                "driver is tested. Use Cancel to stop early.", icon='warning'):
            self._report_skip(f"PROGRESS:{label}:Declined; no GPU load started.")
            return
        worker = None
        try:
            if self.cancel_event.is_set():
                self.queue.put(f"PROGRESS:{label}:Stopped by user before starting load.")
                return
            with ExitStack() as stack:
                directory = stack.enter_context(tempfile.TemporaryDirectory(prefix="winmend-gpu-"))
                report_path = os.path.join(directory, "result.json")
                if getattr(sys, "frozen", False):
                    command = [sys.executable, "--gpu-stress-worker"]
                else:
                    # Launch from the package's absolute source root, regardless
                    # of the shortcut's working directory.
                    from winmend.core.paths import application_root
                    command = [sys.executable, str(application_root() / "WinMend.py"),
                               "--gpu-stress-worker"]
                command += ["--duration", str(duration), "--report", report_path]
                env = dict(os.environ)
                env["QT_QPA_PLATFORM"] = "windows"
                env["QT_OPENGL"] = "desktop"
                since = time.time()
                started = time.monotonic()
                self.queue.put(f"PROGRESS:{label}:Starting hardware rendering worker...")
                worker = wm_track_child(subprocess.Popen(
                    command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, env=env, startupinfo=_no_console_startupinfo(),
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)))
                def stop_worker():
                    wm_kill_tree(worker)
                    worker.wait(timeout=5)
                # Stop the writer before removing its temporary directory,
                # including early return on Cancel or an invalid result.
                stack.callback(stop_worker)
                result = {}
                last_elapsed = -5
                while True:
                    if self.cancel_event.is_set():
                        self.queue.put(f"PROGRESS:{label}:Stopped by user — ending GPU load.")
                        return
                    try:
                        with open(report_path, encoding="utf-8") as stream:
                            result = json.load(stream)
                    except (OSError, ValueError):
                        pass
                    elapsed = float(result.get("elapsed", 0))
                    if result.get("renderer") and elapsed >= last_elapsed + 5:
                        self.queue.put(f"PROGRESS:{label}:{result['renderer']} — {elapsed:.0f}s, "
                                       f"{result.get('frames', 0)} frames rendered")
                        last_elapsed = elapsed
                    if worker.poll() is not None:
                        break
                    # This bounds a stress workload, not a repair/scan. It also
                    # covers native driver hangs and failures before the report.
                    if time.monotonic() - started > duration + 45:
                        self._report_failure(f"PROGRESS:{label}:RESULT: INCOMPLETE — GPU worker "
                                             "did not finish within the test window.")
                        return
                    self.cancel_event.wait(0.25)
                with open(report_path, encoding="utf-8") as stream:
                    result = json.load(stream)
                elapsed = float(result.get("elapsed", 0))
                if worker.returncode != 0 or result.get("state") != "done":
                    self._report_failure(f"PROGRESS:{label}:RESULT: INCOMPLETE — "
                                         + str(result.get("error") or "GPU worker exited without a verified result."))
                    return
                from winmend.features.gpu_stress import is_software_renderer
                if (is_software_renderer(result.get("renderer", ""))
                        or int(result.get("frames", 0)) < 1 or elapsed < duration):
                    self._report_failure(f"PROGRESS:{label}:RESULT: INCOMPLETE — a full hardware "
                                         "rendering run could not be confirmed.")
                    return
                self.queue.put(f"PROGRESS:{label}:GPU load finished; checking display-driver events...")
                count, messages = self._get_display_errors(since=since)
                if self.cancel_event.is_set():
                    self.queue.put(f"PROGRESS:{label}:Stopped by user.")
                    return
                if count < 0:
                    self._report_failure(f"PROGRESS:{label}:RESULT: INCOMPLETE — rendering completed, "
                                         "but display-driver events could not be checked.")
                elif count:
                    self._report_failure(f"PROGRESS:{label}:RESULT: FAIL — {count} new display-driver "
                                         "warning/error event(s) during the run. " + "; ".join(messages))
                else:
                    self.queue.put(f"PROGRESS:{label}:RESULT: completed {duration}s on {result['renderer']} "
                                   f"({result['frames']} verified render submissions), with no OpenGL "
                                   "errors or new display-driver events. This is a short stability check; "
                                   "VRAM integrity, temperature and other GPUs were not tested.")
        except Exception as exc:
            self._report_failure(f"PROGRESS:{label}:Error: {exc}")
        finally:
            if worker is not None:
                try:
                    wm_kill_tree(worker)
                    worker.wait(timeout=5)
                finally:
                    wm_untrack_child(worker)

    def run_cpu_stress_test(self):
        """Load every logical core for 60 seconds, watch load/clock, check for WHEA errors."""
        label = "CPU Stress Test"
        duration = 60
        if not messagebox.askyesno(
            "CPU Stress Test",
            f"This will load EVERY CPU core at 100% for {duration} seconds.\n\n"
            "The fans will spin up and the system may feel sluggish during the test. "
            "On a laptop, plug in the charger first.\n\nStart the test?", icon='warning'
        ):
            self._report_skip(f"PROGRESS:{label}:Cancelled by user.")
            return

        workers = []
        try:
            self.queue.put(f"PROGRESS:{label}:Reading CPU information...")
            cpu_name, base_clock = "Unknown CPU", 0
            cores, logical = 0, (os.cpu_count() or 4)
            try:
                r = self._run_ps(
                    "$cs = @(Get-CimInstance Win32_Processor -ErrorAction Stop); "
                    "$c = $cs | Select-Object -First 1; "
                    "$cores = ($cs | Measure-Object NumberOfCores -Sum).Sum; "
                    "$threads = ($cs | Measure-Object NumberOfLogicalProcessors -Sum).Sum; "
                    "Write-Output \"$($c.Name)|$cores|$threads|$($c.MaxClockSpeed)\"")
                parts = (r.stdout or "").strip().split("|")
                if r.returncode == 0 and len(parts) == 4:
                    cpu_name = parts[0].strip() or cpu_name
                    cores = int(parts[1] or 0)
                    logical = max(1, int(parts[2] or logical))
                    base_clock = int(parts[3] or 0)
            except Exception:
                pass
            self.queue.put(f"PROGRESS:{label}:{cpu_name} — {cores} cores / {logical} threads"
                           + (f", nominal clock {base_clock} MHz" if base_clock else ""))

            whea_before = self._get_whea_error_count()
            if self.cancel_event.is_set():
                self.queue.put(f"PROGRESS:{label}:Stopped by user before starting load.")
                return

            self.queue.put(f"PROGRESS:{label}:Starting {logical} worker(s) for {duration}s of full load...")
            worker_cmd = ("$sw=[Diagnostics.Stopwatch]::StartNew(); $x=1.0001; "
                          # Allow for shell startup and sampling overhead. The
                          # parent stops all workers at its monotonic deadline;
                          # this limit also bounds load if the parent crashes.
                          f"while($sw.Elapsed.TotalSeconds -lt {duration + 30}) "
                          "{ $x=[math]::Sqrt($x)*[math]::Sqrt($x)+0.0001 }")
            for _ in range(max(1, logical)):
                if self.cancel_event.is_set():
                    self.queue.put(f"PROGRESS:{label}:Stopped by user while starting workers.")
                    return
                # Tracked, so quitting WinMend mid-test ends them too.
                workers.append(wm_track_child(subprocess.Popen(
                    ['powershell', '-NoProfile', '-Command', worker_cmd],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    startupinfo=_no_console_startupinfo(),
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))))

            # The clock Task Manager shows: base clock x "% Processor
            # Performance". Win32_Processor.CurrentClockSpeed, which the old
            # version read, is the rated figure on current Windows and never
            # moves -- so throttling could not show up in it at all.
            sample_cmd = ("$p = Get-CimInstance Win32_PerfFormattedData_Counters_ProcessorInformation "
                          "-Filter \"Name='_Total'\"; "
                          "Write-Output \"$($p.PercentProcessorTime)|$($p.PercentProcessorPerformance)\"")
            peak_load, min_perf_under_load = 0, None
            samples, clock_samples = 0, 0
            start = time.monotonic()
            while time.monotonic() - start < duration:
                remaining = duration - (time.monotonic() - start)
                if self.cancel_event.wait(min(5, max(0, remaining))):
                    self.queue.put(f"PROGRESS:{label}:Stopped by user — ending test early.")
                    return
                if any(w.poll() is not None for w in workers):
                    self._report_failure(f"PROGRESS:{label}:RESULT: INCOMPLETE — a CPU worker exited early.")
                    return
                elapsed = int(time.monotonic() - start)
                try:
                    r = self._run_ps(sample_cmd)
                    if self.cancel_event.is_set():
                        self.queue.put(f"PROGRESS:{label}:Stopped by user — ending test early.")
                        return
                    parts = (r.stdout or "").strip().split("|")
                    if r.returncode != 0 or len(parts) != 2 or not parts[0].strip().isdigit():
                        raise ValueError("CPU counters unavailable")
                    load = int(parts[0])
                    if not 0 <= load <= 100:
                        raise ValueError("Invalid CPU load reading")
                    perf = int(parts[1]) if parts[1].strip().isdigit() else None
                    samples += 1
                    peak_load = max(peak_load, load)
                    clock = base_clock * perf // 100 if base_clock and perf else 0
                    if perf is not None and load >= 80:
                        clock_samples += 1
                        min_perf_under_load = perf if min_perf_under_load is None \
                            else min(min_perf_under_load, perf)
                    self.queue.put(f"PROGRESS:{label}:{min(elapsed, duration)}s — load {load}%"
                                   + (f", clock {clock} MHz" if clock else ""))
                except Exception:
                    self.queue.put(f"PROGRESS:{label}:{min(elapsed, duration)}s — sampling skipped")

            for w in workers:
                wm_kill_tree(w)
                w.wait(timeout=5)

            self.queue.put(f"PROGRESS:{label}:Load finished. Checking for new hardware errors...")
            whea_after = self._get_whea_error_count()
            if self.cancel_event.is_set():
                self.queue.put(f"PROGRESS:{label}:Stopped by user.")
                return

            issues = []
            missing = []
            if samples < 2:
                missing.append("not enough valid CPU load samples")
            if not base_clock or not clock_samples:
                missing.append("clock measurements under load unavailable")
            if whea_before < 0 or whea_after < 0 or whea_after < whea_before:
                missing.append("new WHEA errors could not be checked")
            if samples and peak_load < 80:
                issues.append(f"CPU never reached full load (peak {peak_load}%) — "
                              "another process or power limit may be interfering.")
            if min_perf_under_load is not None and min_perf_under_load < 80:
                issues.append(f"The clock fell to {base_clock * min_perf_under_load // 100} MHz under "
                              f"load ({min_perf_under_load}% of its {base_clock} MHz nominal speed) — thermal or "
                              "power limits may be active. Check cooling, dust, the charger and the power plan.")
            if whea_before >= 0 and whea_after > whea_before:
                self._report_failure(f"PROGRESS:{label}:RESULT: FAIL — {whea_after - whea_before} "
                                     "new WHEA hardware error(s) during the test. These can come from "
                                     "the CPU, memory or PCIe devices; review Event Log Viewer for details.")
                return

            if missing:
                for issue in issues:
                    self.queue.put(f"PROGRESS:{label}:WARNING — {issue}")
                self._report_failure(f"PROGRESS:{label}:RESULT: INCOMPLETE — " + "; ".join(missing)
                                     + ". A healthy result could not be confirmed.")
                return

            if issues:
                for issue in issues:
                    self.queue.put(f"PROGRESS:{label}:WARNING — {issue}")
                self.queue.put(f"PROGRESS:{label}:RESULT: completed with {len(issues)} warning(s).")
            else:
                self.queue.put(f"PROGRESS:{label}:RESULT: PASS — completed {duration}s of CPU load "
                               f"(peak {peak_load}%) with no clock drop below 80% of the nominal speed "
                               "in measured samples and no new WHEA errors. Temperature was not measured; "
                               "this short test cannot rule out every hardware fault.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")
        finally:
            for w in workers:
                try:
                    wm_kill_tree(w)
                    w.wait(timeout=5)
                except Exception:
                    pass
                wm_untrack_child(w)

    def run_ram_quick_test(self):
        """Pattern-test up to 1 GB of free RAM and report installed sticks + logged errors."""
        label = "RAM Test"
        try:
            self.queue.put(f"PROGRESS:{label}:Reading installed memory modules...")
            try:
                r = self._run_ps(
                     "Get-CimInstance Win32_PhysicalMemory | ForEach-Object { "
                     "Write-Output \"$($_.BankLabel)|$([math]::Round($_.Capacity/1GB,1)) GB|"
                     "$($_.Speed) MHz|$($_.Manufacturer)|$($_.PartNumber)\" }")
                sticks = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()]
                for stick in sticks:
                    self.queue.put(f"PROGRESS:{label}:Module: {stick.replace('|', '  ·  ')}")
            except Exception:
                pass

            # Size the test from currently available physical memory.
            avail_bytes = 0
            try:
                class _MemStatus(ctypes.Structure):
                    _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                                ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                                ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                                ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                                ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
                stat = _MemStatus()
                stat.dwLength = ctypes.sizeof(stat)
                ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
                avail_bytes = int(stat.ullAvailPhys)
            except Exception:
                pass

            mb = 1024 * 1024
            chunk_size = RAM_CHUNK_BYTES
            test_size = min(1024 * mb, avail_bytes // 4) if avail_bytes else 0
            chunk_count = test_size // chunk_size
            if not chunk_count:
                self._report_skip(f"PROGRESS:{label}:Not enough confirmed free memory for a quick test.")
                return
            test_size = chunk_count * chunk_size
            self.queue.put(f"PROGRESS:{label}:Pattern-testing {int(test_size / mb)} MB of RAM "
                           f"in {chunk_count} chunk(s) — patterns 0x55, 0xAA, random...")

            tile_size = min(mb, chunk_size)
            tile = os.urandom(tile_size)
            random_chunk = tile * (chunk_size // tile_size)
            errors = 0
            tested = 0
            # Hold verified chunks until the test ends. Releasing every chunk
            # let the allocator reuse the same 64 MB while claiming to test 1 GB.
            buffers = []
            for i in range(chunk_count):
                if self.cancel_event.is_set():
                    self.queue.put(f"PROGRESS:{label}:Stopped by user after {i}/{chunk_count} chunks.")
                    return
                try:
                    buf = bytearray(b"\x55" * chunk_size)
                    if buf.count(0x55) != chunk_size:
                        errors += 1
                    buf[:] = b"\xAA" * chunk_size
                    if buf.count(0xAA) != chunk_size:
                        errors += 1
                    buf[:] = random_chunk
                    if bytes(buf) != random_chunk:
                        errors += 1
                    buffers.append(buf)
                except MemoryError:
                    self.queue.put(f"PROGRESS:{label}:Memory pressure too high — stopping at "
                                   f"{i}/{chunk_count} chunks (not a RAM fault).")
                    break
                tested += 1
                self.queue.put(f"PROGRESS:{label}:Verified chunk {i + 1}/{chunk_count}")
            buffers.clear()
            del random_chunk
            if tested != chunk_count:
                self._report_failure(f"PROGRESS:{label}:RESULT: INCOMPLETE — verified "
                                     f"{tested * chunk_size // mb}/{test_size // mb} MB before memory "
                                     "pressure stopped the test. This is not evidence of a RAM fault.")
                return

            self.queue.put(f"PROGRESS:{label}:Checking event log for memory diagnostics & errors...")
            last_diag_failed = False
            try:
                r = self._run_ps(
                     "$e = Get-WinEvent -FilterHashtable @{LogName='System'; "
                     "ProviderName='Microsoft-Windows-MemoryDiagnostics-Results'} "
                     "-MaxEvents 1 -ErrorAction SilentlyContinue; "
                     "if ($e) { Write-Output \"$($e.Id)|$($e.TimeCreated.ToString('yyyy-MM-dd')): "
                     "$($e.Message -replace \"`r`n\", ' ')\" }")
                event_id, _, last_diag = (r.stdout or "").strip().partition("|")
                if last_diag:
                    self.queue.put(f"PROGRESS:{label}:Last Windows Memory Diagnostic: {last_diag[:300]}")
                    # 1101 = no errors found, 1102 = hardware errors found.
                    last_diag_failed = event_id.strip() == "1102"
            except Exception:
                pass
            whea = self._get_whea_error_count()
            if self.cancel_event.is_set():
                self.queue.put(f"PROGRESS:{label}:Stopped by user.")
                return
            if whea > 0:
                self.queue.put(f"PROGRESS:{label}:Note: {whea} WHEA hardware error event(s) exist in the "
                               "System log — review them in Event Log Viewer.")

            if errors:
                self._report_failure(f"PROGRESS:{label}:RESULT: FAIL — {errors} pattern mismatch(es) "
                                     "detected. Run 'Schedule Memory Diagnostic' for a thorough "
                                     "boot-time test, and re-seat / swap RAM sticks to isolate the "
                                     "faulty module.")
            elif last_diag_failed:
                self._report_failure(f"PROGRESS:{label}:RESULT: this quick check found nothing, but the "
                                     "last Windows Memory Diagnostic found hardware errors — a memory "
                                     "module is likely faulty. Re-seat or swap sticks and test again.")
            else:
                # A pass here is weak evidence, and it says so: Python gets
                # whatever memory Windows hands it, so most of the RAM -- and
                # any bad cell in it -- goes untested.
                self.queue.put(f"PROGRESS:{label}:RESULT: no errors in the {tested * chunk_size // mb} MB "
                               "tested. This quick check only covers memory Windows gave it, so it "
                               "can miss a faulty module; 'Schedule Memory Diagnostic' tests all of "
                               "it before Windows loads.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")

    def run_gpu_diagnostic_test(self):
        """Inventory GPUs, check driver/device state, TDR crash history, and dxdiag notes."""
        label = "GPU Test"
        # Win32_VideoController ConfigManagerErrorCode values worth explaining.
        cm_codes = {
            "0": None, "22": "device is disabled", "28": "drivers are not installed",
            "31": "device is not working properly (driver problem)",
            "43": "device reported a failure (Code 43)",
        }
        try:
            self.queue.put(f"PROGRESS:{label}:Reading graphics adapter information...")
            problems = []
            missing = []
            try:
                r = self._run_ps(
                    "Get-CimInstance Win32_VideoController -ErrorAction Stop | ForEach-Object { "
                    "$date = if ($_.DriverDate) { $_.DriverDate.ToString('yyyy-MM-dd') } else { '' }; "
                    "Write-Output \"$($_.Name)|$($_.DriverVersion)|$date|$($_.Status)|"
                    "$($_.ConfigManagerErrorCode)\" }; Write-Output 'GPU_OK'")
                gpu_lines = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()]
                if r.returncode != 0 or 'GPU_OK' not in gpu_lines:
                    raise ValueError("Graphics adapter query failed")
                gpu_lines.remove('GPU_OK')
                if not gpu_lines:
                    missing.append("no graphics adapters reported by Windows")
                for ln in gpu_lines:
                    parts = ln.split("|")
                    if len(parts) != 5:
                        missing.append("incomplete graphics adapter information")
                        continue
                    name = parts[0] if parts else "Unknown GPU"
                    drv = parts[1] if len(parts) > 1 else "?"
                    drv_date = parts[2] if len(parts) > 2 else "?"
                    status = parts[3] if len(parts) > 3 else "?"
                    code = parts[4].strip()
                    self.queue.put(f"PROGRESS:{label}:{name} — driver {drv} ({drv_date}), status {status}")
                    if not code.isdigit() or not drv.strip():
                        missing.append(f"{name}: driver or device error code unavailable")
                        continue
                    code_meaning = cm_codes.get(code, f"device error code {code}")
                    if code != "0" and code_meaning:
                        problems.append(f"{name}: {code_meaning}")
                    elif status not in ("OK", ""):
                        problems.append(f"{name}: device status {status}")
            except Exception:
                missing.append("graphics adapter information unavailable")

            if self.cancel_event.is_set():
                self.queue.put(f"PROGRESS:{label}:Stopped by user.")
                return

            self.queue.put(f"PROGRESS:{label}:Scanning last 30 days for display-driver crashes (TDR)...")
            # Warnings and errors only, from the display stack's own providers.
            # The old count took every event those providers logged, so routine
            # information events (Display 4107 on this kind of PC) were
            # reported as driver crashes.
            tdr_count, samples = self._get_display_errors()
            if tdr_count > 0:
                problems.append(f"{tdr_count} display-driver crash or reset event(s) in the last 30 days "
                                "— usually driver, overheating, or GPU instability. Latest: "
                                + "; ".join(samples))
            elif tdr_count == 0:
                self.queue.put(f"PROGRESS:{label}:No display-driver crash events in the last 30 days.")
            else:
                missing.append("display-driver event log unavailable")

            # NVIDIA-specific live readings when the tool is present.
            nvsmi = shutil.which('nvidia-smi') or r"C:\Windows\System32\nvidia-smi.exe"
            if os.path.exists(nvsmi):
                try:
                    r = wm_run(
                        [nvsmi, '--query-gpu=name,temperature.gpu,utilization.gpu,memory.used,memory.total',
                         '--format=csv,noheader'],
                        capture_output=True, text=True, encoding='utf-8', errors='replace',
                        cancel_event=self.cancel_event,
                        timeout=30, startupinfo=_no_console_startupinfo())
                    for ln in (r.stdout or "").splitlines():
                        if ln.strip():
                            self.queue.put(f"PROGRESS:{label}:nvidia-smi: {ln.strip()}")
                            try:
                                temp = int(ln.split(',')[1].strip().split()[0])
                                if temp >= 90:
                                    problems.append(f"GPU idle/load temperature is {temp}°C — "
                                                    "check cooling and dust buildup.")
                            except Exception:
                                pass
                except Exception:
                    self.queue.put(f"PROGRESS:{label}:NVIDIA telemetry unavailable.")
            else:
                self.queue.put(f"PROGRESS:{label}:Temperature/utilization telemetry unavailable "
                               "(nvidia-smi is not installed); these readings were not checked.")

            if self.cancel_event.is_set():
                self.queue.put(f"PROGRESS:{label}:Stopped by user.")
                return

            self.queue.put(f"PROGRESS:{label}:Running dxdiag scan (takes ~30s)...")
            try:
                # A private directory avoids reusing/deleting a predictable
                # report. XML also honours the UTF-16 declaration Windows uses.
                with tempfile.TemporaryDirectory(prefix="winmend-dxdiag-") as directory:
                    dx_path = os.path.join(directory, 'report.xml')
                    r = wm_run(['dxdiag', '/whql:off', '/x', dx_path],
                               capture_output=True, cancel_event=self.cancel_event,
                               startupinfo=_no_console_startupinfo())
                    if self.cancel_event.is_set():
                        self.queue.put(f"PROGRESS:{label}:Stopped by user.")
                        return
                    if r.returncode != 0:
                        raise ValueError("dxdiag failed")
                    root = ET.parse(dx_path).getroot()
                    notes = [(node.text or '').strip() for node in root.findall('./DxDiagNotes/*')
                             if node.tag.lower().startswith('display')]
                    if not notes or not all(notes):
                        missing.append("dxdiag display notes unavailable")
                    else:
                        for note in dict.fromkeys(notes):
                            if note.casefold().rstrip('.') != 'no problems found':
                                # Localised note text is left for review rather
                                # than guessing that it proves a hardware fault.
                                missing.append(f"dxdiag display note needs review: {note[:200]}")
                            self.queue.put(f"PROGRESS:{label}:dxdiag display: {note[:200]}")
            except Exception:
                missing.append("dxdiag report unavailable or unreadable")

            if self.cancel_event.is_set():
                self.queue.put(f"PROGRESS:{label}:Stopped by user.")
                return
            if problems:
                for p in problems:
                    self.queue.put(f"PROGRESS:{label}:WARNING — {p}")
                self._report_failure(f"PROGRESS:{label}:RESULT: {len(problems)} issue(s) found. "
                                     "Review the device and event details before choosing a repair.")
                for detail in missing:
                    self.queue.put(f"PROGRESS:{label}:Not checked: {detail}")
            elif missing:
                self._report_failure(f"PROGRESS:{label}:RESULT: INCOMPLETE — " + "; ".join(missing)
                                     + ". A healthy result could not be confirmed.")
            else:
                self.queue.put(f"PROGRESS:{label}:RESULT: PASS — drivers healthy, no device errors, "
                               "no display-driver events in the last 30 days, no dxdiag display problems. "
                               "This diagnostic does not stress the GPU; use 'GPU Stress Test (60s)' for load testing.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")
