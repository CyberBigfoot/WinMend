"""WinMend diagnostics: hardware assessment."""

from __future__ import annotations

from winmend.diagnostics.helpers import _evidence, _plural
from winmend.diagnostics.reference import describe_bugcheck


class CaseHardwareAssessmentMixin:
    """CaseEngine methods grouped by responsibility."""

    # -- evidence -> findings: the component-level scan ---------------------

    @staticmethod
    def _hardware_findings(raw):
        """Rows for the deep hardware collectors, when they have run.

        Held apart from the main body for one reason worth stating: nearly every
        source here is gated on elevation, on the board choosing to expose a
        sensor, or on a vendor tool being installed. Each row therefore has to
        distinguish "measured, and it is fine" from "could not be measured", and
        only ever colours a row on something actually read. A hardware scan that
        reports green because it was not allowed to look is worse than one that
        never ran.
        """
        out = []

        devices = raw.get("component_devices") or {}
        if devices:
            problems = devices.get("problems") or []
            out.append(_evidence(
                "component_devices", "Connected component status",
                "warn" if problems else "info" if not devices.get("available") or devices.get("unknown") else "good",
                f"{len(problems)} device status issue(s)" if devices.get("available") else "Not assessed",
                "; ".join(f"{d['name']}: Code {d['code']}" for d in problems)
                or devices.get("reason") or "Windows device status only; this does not test every physical function.",
                data=devices))

        firmware = raw.get("firmware_info") or {}
        if firmware.get("available"):
            years = firmware.get("bios_age_years")
            cpu = raw.get("cpu_details") or {}
            patched = cpu.get("microcode_patched_by_os")
            # Age alone is not a fault -- a stable machine on a four-year-old
            # BIOS is a stable machine. It only becomes a finding when Windows
            # is demonstrably patching around the firmware at every boot.
            if years is not None and years >= 3 and patched:
                status = "warn"
                value = f"{firmware.get('bios_version', '?')} -- {years} years old"
            elif years is not None:
                status = "info"
                value = f"{firmware.get('bios_version', '?')} ({years} years old)"
            else:
                status, value = "info", firmware.get("bios_version", "unknown")
            board = firmware.get("board") or firmware.get("system_model") or "unknown board"
            out.append(_evidence(
                "firmware", "Motherboard and BIOS", status,
                f"{board} -- BIOS {value}",
                ("Windows is loading newer processor microcode than this firmware provides, "
                 "which means the board is behind fixes its vendor has already shipped."
                 if status == "warn" else
                 "The board and the firmware release it is running."),
                data=firmware, task_ids=("device_firmware",)))

        cpu = raw.get("cpu_details") or {}
        if cpu.get("available"):
            cores = cpu.get("cores_physical")
            threads = cpu.get("cores_logical")
            layout = (f"{cores} cores / {threads} threads"
                      if cores and threads else "")
            out.append(_evidence(
                "cpu_hardware", "Processor", "info",
                ", ".join(p for p in (cpu.get("name", "").strip(), layout) if p) or "unknown",
                "The processor as Windows sees it, with the microcode revision in effect.",
                data=cpu))

        modules = raw.get("memory_modules") or {}
        if modules.get("available"):
            sticks = modules.get("modules") or []
            free = modules.get("slots_free")
            summary = _plural(len(sticks), "module")
            if modules.get("running_mhz"):
                summary += f" at {modules['running_mhz']} MT/s"
            if free:
                summary += f", {free} slot(s) free"
            notes = []
            if modules.get("mixed_parts"):
                notes.append("the modules are not a matched set")
            if modules.get("underclocked"):
                notes.append(f"running below their rated {modules.get('rated_mhz')} MT/s")
            if modules.get("ecc"):
                notes.append("ECC")
            out.append(_evidence(
                # Reported, never flagged: mixed memory and JEDEC-default speeds
                # are how a large share of working PCs are configured. These only
                # carry weight next to a measured instability, which is a
                # judgement for the rules rather than for this row.
                "memory_modules", "Memory modules", "info",
                summary + (" -- " + "; ".join(notes) if notes else ""),
                "Each module by slot, with what it is rated for and what it is actually running at.",
                data=modules))

        sensors = raw.get("sensor_readings") or {}
        if sensors:
            if sensors.get("exposes_nothing"):
                out.append(_evidence(
                    "sensors", "Fans and temperatures", "info",
                    "this board reports no sensors to Windows",
                    "Most consumer boards keep fan and voltage sensors behind their own "
                    "utility rather than exposing them. Nothing could be measured here.",
                    data=sensors))
            else:
                stopped = sensors.get("stopped_fans") or []
                alarms = sensors.get("voltage_alarms") or []
                hottest = sensors.get("hottest_c")
                if stopped:
                    status = "bad"
                    value = f"{_plural(len(stopped), 'fan')} reporting stopped or faulted"
                elif alarms:
                    status, value = "bad", f"{_plural(len(alarms), 'voltage rail')} out of range"
                elif hottest is not None and hottest >= 90:
                    status, value = "warn", f"hottest zone {hottest} C"
                elif sensors.get("throttling"):
                    status, value = "warn", "a thermal zone is holding a component back"
                elif hottest is not None:
                    status, value = "good", f"hottest zone {hottest} C"
                else:
                    status, value = "info", "partial sensor data"
                out.append(_evidence(
                    "sensors", "Fans and temperatures", status, value,
                    "Temperatures, fan speeds and voltage rails, as far as the board exposes them.",
                    data=sensors))

        power = raw.get("power_events") or {}
        if power.get("available"):
            losses = power.get("power_losses", 0)
            status = "bad" if losses >= 4 else "warn" if losses else "good"
            out.append(_evidence(
                "power_loss", "Unexpected shutdowns without a stop code", status,
                (f"{_plural(losses, 'time')} in {power.get('days', 60)} days"
                 if losses else f"none in {power.get('days', 60)} days"),
                ("No stop code or held-button timestamp was saved. Power loss, a hang or a "
                 "crash that could not write its dump can produce this. Check surrounding "
                 "events and symptoms before attributing it to the power supply or board."
                 if losses else
                 "No unexplained shutdowns were found in the accessible event window."),
                data=power))

        firmware_errors = raw.get("firmware_errors") or {}
        if firmware_errors.get("available"):
            acpi = firmware_errors.get("acpi_errors", 0)
            out.append(_evidence(
                "firmware_errors", "Firmware complaints", "warn" if acpi else "good",
                (f"{_plural(acpi, 'ACPI error')} logged" if acpi
                 else "no firmware errors logged"),
                ("Windows reported errors involving the ACPI firmware interface. Check the "
                 "vendor's firmware and chipset guidance; these do not prove physical board failure."
                 if acpi else
                 "Windows raised no errors against the board's firmware."),
                data=firmware_errors))

        tpm = raw.get("tpm_state") or {}
        if tpm.get("available"):
            if tpm.get("present") is False:
                status, value = "info", "no TPM on this machine"
            elif tpm.get("ready"):
                status, value = "good", "present and ready"
            else:
                status, value = "warn", "present but not ready"
            out.append(_evidence(
                "tpm", "Security chip (TPM)", status, value,
                ("A TPM that is present but not ready is why BitLocker asks for a recovery key "
                 "at every boot and why Windows Hello will not enrol."
                 if status == "warn" else
                 "The TPM stores the keys BitLocker and Windows Hello depend on."),
                data=tpm))

        gpu = raw.get("gpu_hardware") or {}
        if gpu.get("available"):
            faulted = gpu.get("faulted") or []
            adapters = gpu.get("adapters") or []
            names = ", ".join(a["name"] for a in adapters[:2]) or "unknown"
            if faulted:
                status = "bad"
                value = f"{names} -- reporting a device error"
            elif gpu.get("tdr_disabled"):
                status, value = "warn", f"{names} -- crash recovery is switched off"
            elif gpu.get("tdr_delay_raised"):
                status, value = "warn", f"{names} -- crash recovery delay has been raised"
            else:
                status, value = "good", names
            out.append(_evidence(
                "gpu_hardware", "Graphics adapter", status, value,
                ("Timeout Detection and Recovery is what lets Windows reset a hung graphics "
                 "driver instead of freezing. With it off or stretched, the machine hard-locks "
                 "where it would otherwise have recovered -- and the real fault stays hidden."
                 if status == "warn" else
                 "The display adapter, its driver, and its crash-recovery settings."),
                data=gpu, task_ids=("gpu_diagnostic", "driver_rollback_center")))

        live = raw.get("live_kernel_events") or {}
        if live.get("available"):
            hardware_faults = live.get("hardware_faults", 0)
            driver_faults = live.get("driver_faults", 0)
            unattributed = live.get("unattributed", 0)
            total = live.get("event_count", 0)
            spread = live.get("hardware_days", 0)
            if hardware_faults:
                # One day's worth is an episode; several days is a pattern.
                status = "bad" if spread >= 3 else "warn"
                value = (f"{_plural(hardware_faults, 'component timeout')} captured"
                         + (f" across {spread} days" if spread > 1 else ""))
            elif driver_faults:
                status = "warn"
                value = f"{_plural(driver_faults, 'display driver timeout')}"
            elif total:
                # A machine can carry hundreds of watchdog captures and be
                # entirely healthy. Colouring this on the raw count told a
                # working PC it had 118 faults, which buries the real ones.
                status = "info"
                value = f"{_plural(total, 'event')} with no established meaning"
            else:
                status, value = "good", "none recorded"
            out.append(_evidence(
                "live_kernel", "Faults caught without a crash", status, value,
                ("Windows captured a component timeout without a bluescreen. Its cause can "
                 "be a driver, firmware, tuning, power, cooling or hardware; the event alone "
                 "does not identify a failed part."
                 if hardware_faults or driver_faults else
                 "Windows captured these without crashing. Their codes are not ones with a "
                 "settled meaning, and healthy machines routinely carry a great many of them, "
                 "so they are recorded rather than judged."
                 if unattributed else
                 "Windows recorded no component failing badly enough to be captured."),
                data=live, task_ids=("gpu_diagnostic", "reliability_monitor")))

        telemetry = raw.get("gpu_vendor_telemetry") or {}
        if telemetry.get("available"):
            degraded = telemetry.get("degraded_links") or []
            ecc = telemetry.get("ecc_errors") or 0
            gpus = telemetry.get("gpus") or []
            if ecc:
                status, value = "bad", f"{_plural(ecc, 'uncorrected memory error')} on the GPU"
            elif degraded:
                worst = degraded[0]
                status = "warn"
                value = (f"{worst['name']} is linked at x{worst['pcie_width']} "
                         f"of x{worst['pcie_width_max']}")
            else:
                status = "good"
                value = ", ".join(g["name"] for g in gpus[:2])
            out.append(_evidence(
                "gpu_telemetry", "Graphics card telemetry", status, value,
                ("The PCIe link is below the card's maximum width. Check the board manual, "
                 "lane sharing and firmware configuration before inspecting seating or a riser."
                 if degraded else
                 "Link width, temperature and memory error counts, read from the card itself."),
                data=telemetry))

        monitors = raw.get("display_links") or {}
        if monitors.get("available"):
            panels = monitors.get("monitors") or []
            described = ", ".join(
                f"{m['name'] or m['vendor'] or 'display'}"
                + (f" ({m['connection']})" if m.get("connection") else "")
                for m in panels[:3])
            out.append(_evidence(
                "monitors", "Displays", "info",
                described or f"{_plural(len(panels), 'display')}",
                "Each panel and how it is connected -- the cable type matters when a display "
                "keeps blanking.",
                data=monitors))

        smart = raw.get("smart_attributes") or {}
        if smart.get("available"):
            drives = smart.get("drives") or []
            worst_note, status = "", "good"
            for drive in drives:
                pending = drive.get("pending_sectors") or 0
                uncorrectable = drive.get("uncorrectable") or 0
                reallocated = drive.get("reallocated") or 0
                crc = drive.get("crc_errors") or 0
                if drive.get("predict_failure") or pending or uncorrectable:
                    status = "bad"
                    worst_note = (f"{_plural(pending, 'sector')} pending reallocation"
                                  if pending else
                                  f"{_plural(uncorrectable, 'uncorrectable sector')}")
                    break
                if reallocated or crc:
                    status = "warn"
                    worst_note = (f"{_plural(reallocated, 'reallocated sector')}"
                                  if reallocated else
                                  f"{_plural(crc, 'interface CRC error')}")
            out.append(_evidence(
                "smart_detail", "Drive self-reported errors", status,
                worst_note or f"{_plural(len(drives), 'drive')} clean",
                ("Sectors pending reallocation are the earliest reliable warning a drive gives, "
                 "and they usually appear weeks before the health flag turns."
                 if status == "bad" else
                 "Interface CRC errors are errors on the cable between drive and board -- very "
                 "often the lead or the port rather than the drive."
                 if status == "warn" else
                 "The raw error counters behind the pass/fail health flag."),
                data=smart, task_ids=("disk_smart_check", "pc_report")))

        bus = raw.get("storage_bus_errors") or {}
        if bus.get("available"):
            resets = bus.get("resets", 0)
            bad_blocks = bus.get("bad_blocks", 0)
            total = bus.get("count", 0)
            if bad_blocks:
                status, value = "bad", f"{_plural(bad_blocks, 'bad block')} reported"
            elif resets:
                status, value = "warn", f"{_plural(resets, 'controller reset')}"
            elif total:
                status, value = "warn", f"{_plural(total, 'storage error')}"
            else:
                status, value = "good", "no storage errors logged"
            out.append(_evidence(
                "storage_events", "Storage errors in the log", status, value,
                ("A controller reset means the drive stopped answering and had to be kicked. "
                 "That is as often the cable or the port as the drive itself."
                 if resets and not bad_blocks else
                 "Storage faults grouped by what they blame -- the drive, or the link to it."),
                data=bus, task_ids=("disk_smart_check",)))

        geometry = raw.get("disk_geometry") or {}
        if geometry.get("available"):
            misaligned = geometry.get("misaligned") or []
            unhealthy = geometry.get("unhealthy") or []
            if unhealthy:
                status = "bad"
                value = f"{unhealthy[0]['name']} reports {unhealthy[0]['health']}"
            elif misaligned:
                status = "warn"
                value = f"{_plural(len(misaligned), 'partition')} not aligned to the drive"
            else:
                status = "good"
                value = f"{_plural(len(geometry.get('disks') or []), 'drive')} laid out correctly"
            out.append(_evidence(
                "disk_geometry", "Drive layout", status, value,
                ("A partition that does not start on a 1 MB boundary makes the drive do every "
                 "write twice. It reads as an SSD that has got slow, and it is real."
                 if misaligned else
                 "Firmware revision, bus type, sector size and partition alignment."),
                data=geometry))

        sweep = raw.get("disk_read_sweep") or {}
        if sweep.get("available"):
            failing = sweep.get("failing") or []
            sluggish = sweep.get("sluggish") or []
            if failing:
                status = "bad"
                value = (f"{_plural(sweep.get('total_errors', 0), 'read')} failed on "
                         f"disk {failing[0]['disk']}")
            elif sluggish:
                status = "warn"
                value = f"unusually slow reads on disk {sluggish[0]['disk']}"
            else:
                status = "good"
                value = f"{_plural(len(sweep.get('disks') or []), 'drive')} read cleanly"
            out.append(_evidence(
                "disk_surface", "Live read test", status, value,
                ("A block that will not read back is a hard fault. Whatever was stored there is "
                 "already gone, and the count of them tends to climb quickly."
                 if failing else
                 "Blocks sampled across each drive and timed. Reads that take hundreds of times "
                 "longer than their neighbours are what usually comes before a failure."),
                data=sweep, task_ids=("chk_dsk",)))
        elif sweep and sweep.get("unreadable"):
            out.append(_evidence(
                "disk_surface", "Live read test", "info",
                "could not open the drives for reading",
                "Reading a drive directly needs administrator rights. Nothing was tested here, "
                "which is not the same as nothing being wrong.",
                data=sweep))

        memory_test = raw.get("memory_pattern_test") or {}
        if memory_test.get("available"):
            failures = memory_test.get("failures") or []
            tested = memory_test.get("tested_mb", 0)
            if failures:
                first = failures[0]
                status = "bad"
                value = (f"data changed in memory at {first.get('offset_mb')} MB "
                         f"({first.get('bits_flipped')} bit(s))")
            else:
                status = "good"
                value = f"{tested} MB verified across {memory_test.get('passes', 0)} patterns"
            out.append(_evidence(
                "memory_pattern", "Live memory test", status, value,
                ("Bytes written to memory came back different. Patterns do not change "
                 "themselves, so this is a real fault in the memory, the controller or the bus."
                 if failures else
                 "Known patterns were written across a block of memory and read back. This "
                 "covers only the memory that could be borrowed, not the whole system."),
                data=memory_test, task_ids=("memory_diagnostic",)))

        pool = raw.get("pool_usage") or {}
        if pool.get("available"):
            if pool.get("nonpaged_high"):
                status = "warn"
                value = f"{pool.get('nonpaged_mb')} MB of non-paged pool in use"
            elif pool.get("paged_high"):
                status, value = "warn", f"{pool.get('paged_mb')} MB of paged pool in use"
            else:
                status = "good"
                value = (f"{pool.get('nonpaged_mb', 0)} MB non-paged, "
                         f"{pool.get('paged_mb', 0)} MB paged")
            out.append(_evidence(
                "kernel_pool", "Kernel memory", status, value,
                ("Non-paged pool is memory a driver has taken that cannot be swapped out. When "
                 "it climbs, RAM disappears with no process to blame it on -- which is why this "
                 "gets misdiagnosed as needing a reinstall."
                 if status == "warn" else
                 "Memory held by Windows itself and by drivers, rather than by any program."),
                data=pool))

        logs = raw.get("event_log_sweep") or {}
        if logs.get("available"):
            repeating = logs.get("repeating") or []
            critical = logs.get("critical_count", 0)
            scanned = logs.get("logs_scanned", 0)
            if critical:
                status = "warn"
                value = f"{_plural(critical, 'critical error')} across {scanned} logs"
            elif repeating:
                top = repeating[0]
                status = "warn"
                value = f"{top['provider']} event {top['id']} logged {top['count']} times"
            else:
                status = "good"
                value = f"{scanned} logs scanned, nothing repeating"
            out.append(_evidence(
                "log_sweep", "Every event log", status, value,
                ("A single error is a bad afternoon; the same one hundreds of times is the "
                 "thing that is actually wrong. These are ranked by how often they repeat."
                 if repeating or critical else
                 "Every enabled log on the machine, not just System and Application, clustered "
                 "by what repeats."),
                data=logs, task_ids=("event_log_viewer", "reliability_monitor")))

        reports = raw.get("wer_reports") or {}
        if reports.get("available"):
            if reports.get("shared_fault"):
                status = "warn"
                value = (f"{reports['top_module']} faulted in "
                         f"{_plural(reports['top_module_apps'], 'different program')}")
            else:
                status = "info"
                value = f"{_plural(reports.get('count', 0), 'crash report')} on file"
            out.append(_evidence(
                "crash_reports", "Crash reports", status, value,
                ("Unrelated programs crashing inside the same component is one broken piece of "
                 "software, not several -- and the module name is the only thing that shows it."
                 if reports.get("shared_fault") else
                 "Windows keeps the faulting module and exception for every crash. This is that "
                 "archive, grouped by what actually failed."),
                data=reports))

        dumps = raw.get("minidump_details") or {}
        if dumps.get("available"):
            count = dumps.get("count", 0)
            repeating = dumps.get("repeating", 0)
            distinct = dumps.get("distinct_codes", 0)
            if repeating >= 3:
                top = max(dumps.get("codes", {}), key=dumps["codes"].get)
                name = describe_bugcheck(top)[0] if top else ""
                status = "bad"
                value = f"{_plural(repeating, 'crash')} with the same stop code ({name or top})"
            elif count:
                status, value = "warn", f"{_plural(count, 'crash dump')}, {distinct} distinct code(s)"
            else:
                status, value = "good", "no crash dumps"
            out.append(_evidence(
                "crash_dumps_detail", "Stop codes from the dumps", status, value,
                ("The same stop code every time points at one cause. A scatter of different ones "
                 "is the signature of memory or power, where whatever happens to be running is "
                 "what dies."
                 if count else
                 "Read straight out of the dump files, which keep the stop code even when the "
                 "event log entry was never written."),
                data=dumps, task_ids=("minidump_analyzer", "bsod_triage")))

        return out
