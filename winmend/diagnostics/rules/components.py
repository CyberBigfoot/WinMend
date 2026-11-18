"""WinMend diagnostics: rules: components."""

from __future__ import annotations

from winmend.diagnostics.components import device_guidance
from winmend.diagnostics.helpers import _plural
from winmend.diagnostics.models import Hypothesis, repair_action, task_action
from winmend.diagnostics.reference import describe_bugcheck, module_vendor
from winmend.diagnostics.rules.registry import rule


# ---------------------------------------------------------------------------
# The component-level scan
#
# These read the deep hardware collectors, and they follow one rule the rest of
# the file does not have to think about: most hardware faults have no software
# repair. A dying drive and a bad DIMM both need hands inside the case.
#
# So where the rules above aim to produce an action, these aim to produce a
# *correct instruction* -- which drive, which slot, what to do first, and what
# not to waste an afternoon on. Offering a plausible-looking repair for a
# failing disk is worse than offering nothing, because it costs the user the
# window in which their data was still recoverable.
# ---------------------------------------------------------------------------


@rule
def rule_component_device_status(ctx):
    devices = ctx.get("component_devices", {})
    if not devices.get("available") or not devices.get("problems"):
        return None
    problems = devices["problems"]
    names = "; ".join(f"{d['name']} (Code {d['code']})" for d in problems[:6])
    return Hypothesis(
        "component_device_status", "Connected devices need attention",
        names + ". These are Windows device status codes, not proof of physical damage.",
        confidence=90, severity="medium",
        evidence_keys=["component_devices"], actions=[],
        advice=" ".join(f"{d['name']}: {device_guidance(d['code'])}" for d in problems[:6])
               + " Open the Hardware tab for every device and its next steps.",
    )


@rule
def rule_motherboard_firmware_errors(ctx):
    errors = ctx.get("firmware_errors", {})
    if not errors.get("available") or not errors.get("acpi_errors"):
        return None
    board = (ctx.get("firmware_info", {}) or {}).get("board") or "This system"
    return Hypothesis(
        "motherboard_firmware_errors", "Motherboard firmware errors need investigation",
        f"{board}: {errors['acpi_errors']} ACPI error(s) in the last {errors.get('days', 45)} days. "
        "These concern firmware's interface with Windows; they do not prove the board is physically damaged.",
        confidence=65, severity="medium", evidence_keys=["firmware_errors", "firmware"],
        actions=[task_action("device_firmware", "Review official firmware guidance for this exact model.")],
        advice="Check whether the event dates match the symptoms. Review the PC maker's chipset drivers "
               "and BIOS release notes for your exact model and board revision. Before updating firmware, "
               "save the BitLocker recovery key and follow the vendor's power and recovery instructions. "
               "If faults persist at stock settings, use the vendor's offline diagnostics or a technician.",
    )


@rule
def rule_drive_failing_smart(ctx):
    """Sectors the drive could not read. The earliest honest warning there is."""
    smart = ctx.get("smart_attributes", {})
    if not smart.get("available"):
        return None
    worst = None
    for drive in smart.get("drives") or []:
        pending = drive.get("pending_sectors") or 0
        uncorrectable = drive.get("uncorrectable") or 0
        reallocated = drive.get("reallocated") or 0
        if drive.get("predict_failure") or pending or uncorrectable or reallocated:
            score = (pending * 3) + (uncorrectable * 4) + reallocated
            if worst is None or score > worst[0]:
                worst = (score, drive, pending, uncorrectable, reallocated)
    if worst is None:
        return None
    _, drive, pending, uncorrectable, reallocated = worst

    signals = []
    if pending:
        signals.append(f"{_plural(pending, 'sector')} that failed to read and are waiting "
                       f"to be reallocated")
    if uncorrectable:
        signals.append(f"{_plural(uncorrectable, 'sector')} that failed even on a retry")
    if reallocated:
        signals.append(f"{_plural(reallocated, 'sector')} already swapped out for spares")
    if drive.get("predict_failure"):
        signals.append("the drive's own failure prediction has tripped")

    # Pending and uncorrectable sectors are data loss in progress. Reallocated
    # sectors on their own are a drive doing exactly what spare sectors are for,
    # so they are a warning rather than an emergency.
    critical = bool(pending or uncorrectable or drive.get("predict_failure"))
    hours = drive.get("power_on_hours")
    age = (f" It has been powered on for about {hours:,} hours "
           f"({hours // 8760} years or so)." if hours and hours > 8760 else "")
    return Hypothesis(
        "drive_failing_smart",
        "A drive is failing" if critical else "A drive has started reallocating sectors",
        (f"The drive is reporting {'; '.join(signals)}. These counters come off the drive "
         f"itself, not from Windows, and they do not go back down.{age}"
         + (" The pass/fail health flag is designed to stay green until the very end, so it "
            "being clean means nothing here." if critical else "")),
        confidence=92 if critical else 65,
        severity="critical" if critical else "medium",
        evidence_keys=["smart_detail", "smart", "drive_wear", "disk_surface"],
        # Deliberately no repair. There is no software action that fixes this,
        # and running a disk check on a drive with pending sectors gives it the
        # heaviest workload it has seen in months at the worst possible moment.
        actions=[task_action("disk_smart_check",
                             "Confirm the reading against the drive's full report."),
                 task_action("pc_report", "Capture the evidence before anything changes.")],
        # This is the entire value of finding it early, so it leads.
        advice=("Copy anything you care about off this drive now, before anything else. "
                "Do not run a disk check or a defragment first -- both hammer the drive at "
                "exactly the wrong moment, and a drive at this stage can fail during one. "
                "Once your data is somewhere else, replace the drive; these counters only "
                "ever climb."
                if critical else
                "Nothing is lost yet -- the drive moved that data to spare sectors, which is "
                "what they exist for. Check the count again in a few weeks. A number that is "
                "climbing means replace it; one that has sat still for months is fine."),
        # A failing drive makes several otherwise sensible repairs dangerous.
        suppress=["dirty_filesystem", "disk_hog", "trim_off"],
        suppress_reason="the drive is failing, so disk maintenance would be the wrong risk to take",
    )


@rule
def rule_drive_link_faults(ctx):
    """CRC errors and controller resets -- the cable, not the drive."""
    smart = ctx.get("smart_attributes", {})
    bus = ctx.get("storage_bus_errors", {})
    crc = 0
    for drive in (smart.get("drives") or []) if smart.get("available") else ():
        crc = max(crc, drive.get("crc_errors") or 0)
    resets = bus.get("resets", 0) if bus.get("available") else 0
    if not crc and resets < 2:
        return None

    signals = []
    if crc:
        signals.append(f"{_plural(crc, 'error')} on the connection between the drive and "
                       f"the board")
    if resets:
        signals.append(f"{_plural(resets, 'time')} the controller had to reset a drive that "
                       f"stopped responding")
    return Hypothesis(
        "drive_link_faults",
        "The connection to a drive is faulty",
        ("The drive is answering, but data is being corrupted or lost on the way to it: "
         + "; ".join(signals) + ". This looks exactly like a failing drive and usually is not "
         "one -- the counters that matter for the drive's own health are separate, and a bad "
         "cable will produce every symptom of a dying disk while the disk is fine."),
        confidence=70,
        severity="high",
        evidence_keys=["smart_detail", "storage_events"],
        actions=[task_action("disk_smart_check", "Read the drive's own health separately.")],
        advice=("Reseat the data cable at both ends, and move it to a different port on the "
                "board. On a SATA drive, replace the cable outright -- they fail far more "
                "often than drives do and cost almost nothing. On an M.2 drive, reseat the "
                "card and check the retaining screw. If the count stops rising afterwards, "
                "that was it."),
    )


@rule
def rule_drive_read_failures(ctx):
    """Blocks that would not come back when asked for them."""
    sweep = ctx.get("disk_read_sweep", {})
    if not sweep.get("available"):
        return None
    failing = sweep.get("failing") or []
    if not failing:
        return None
    worst = max(failing, key=lambda d: d["error_count"])
    where = ", ".join(f"{e['offset_gb']} GB" for e in (worst.get("errors") or [])[:3])
    return Hypothesis(
        "drive_read_failures",
        f"Disk {worst['disk']} cannot read parts of itself",
        (f"{_plural(worst['error_count'], 'read')} failed while sampling blocks across the "
         f"drive"
         + (f", at around {where} in" if where else " on")
         + f" a {worst['gb_span']} GB device. This is not a timing measurement or a counter "
         f"the drive keeps -- the data was asked for and did not arrive. Anything stored in "
         f"those blocks could not be read in this sample. Media, controller, connection or power problems need isolation; this test does not establish permanent data loss."),
        confidence=90,
        severity="critical",
        evidence_keys=["disk_surface", "smart_detail"],
        actions=[task_action("pc_report", "Capture the evidence before anything changes.")],
        advice=("Get your data off this drive now. Only a fraction of the drive was sampled, "
                "so the blocks found here are unlikely to be the only bad ones. Copy the "
                "important things first rather than imaging the whole drive -- an image reads "
                "every sector including the failing ones, which is the slowest and most "
                "stressful thing you can ask of it."),
        suppress=["dirty_filesystem", "disk_hog"],
        suppress_reason="the drive cannot read reliably, so disk maintenance is the wrong risk",
    )


@rule
def rule_memory_proven_faulty(ctx):
    """Data went into memory and came back different. Nothing else explains that."""
    test = ctx.get("memory_pattern_test", {})
    if not test.get("available") or not test.get("failed"):
        return None
    failure = (test.get("failures") or [{}])[0]
    bits = failure.get("bits_flipped")
    return Hypothesis(
        "memory_proven_faulty",
        "Memory is corrupting data",
        (f"A known pattern was written across {test.get('tested_mb', 0)} MB of memory and read "
         f"back changed"
         + (f" -- {_plural(bits, 'bit')} different at the {failure.get('offset_mb')} MB mark"
            if bits else "")
         + ". Memory does not do this and then recover. This is a fault in a module, in the "
         "memory controller, or in how the memory is being clocked, and everything else this "
         "PC does wrong is probably downstream of it."),
        confidence=95,
        severity="critical",
        evidence_keys=["memory_pattern", "memory_modules", "hardware_errors", "bugchecks"],
        actions=[repair_action("schedule_memory_test", {},
                               reason="Run Windows' own memory test at the next restart to "
                                      "confirm it against the full range."),
                 task_action("memory_diagnostic", "Schedule the full Windows memory test.")],
        advice=("Do not trust this PC with anything important until it is resolved -- memory "
                "that corrupts data corrupts saved files just as readily as it corrupts a "
                "running program. If the memory is overclocked, or has an XMP/EXPO profile "
                "enabled, turn that off first: it is the most common cause by a wide margin "
                "and costs nothing to test. If the fault survives that, run the sticks one at "
                "a time to find which one it is."),
        # Everything else measured on a machine with bad memory is suspect.
        suppress=["app_crash_module", "component_corruption", "system_files_corrupt"],
        suppress_reason="memory is corrupting data, so file and crash damage is a symptom of it",
    )


@rule
def rule_power_delivery(ctx):
    """The machine stopped, without executing any part of a shutdown."""
    power = ctx.get("power_events", {})
    if not power.get("available"):
        return None
    losses = power.get("power_losses", 0)
    if not losses:
        return None
    thermal = ctx.get("thermal_events", {})
    hot = (thermal.get("throttle_events", 0) if thermal.get("available") else 0)
    sensors = ctx.get("sensor_readings", {})
    hottest = sensors.get("hottest_c")
    whea = (ctx.get("whea_errors", {}) or {}).get("count", 0)
    # Corroboration is what separates a machine with a fault from a house with
    # unreliable mains. Heat and hardware errors are recorded by the PC itself;
    # a power cut leaves neither.
    corroborated = bool(hot or whea)
    if losses >= 5 or (corroborated and losses >= 2):
        severity, confidence = "critical", 80
    elif losses >= 3:
        severity, confidence = "high", 65
    else:
        # Twice in two months, with nothing else wrong, is as likely to be the
        # wall socket as the PC. Saying "your power supply is failing" here
        # would send someone shopping on the strength of a storm.
        severity, confidence = "medium", 45
    return Hypothesis(
        "power_delivery",
        "Unexpected shutdowns have no recorded stop code",
        (f"{_plural(losses, 'time')} in the last {power.get('days', 60)} days the machine went "
         f"down without recording a crash and without the power button being held. That "
         f"missing fields do not establish the cause: a hang or crash can prevent Windows "
         f"from saving a stop code. Power loss, cooling, firmware and drivers remain possibilities."
         + (f" It has also throttled for heat {hot} time(s), which points the same way."
            if hot else "")
         + (f" The hardware logged {_plural(whea, 'error')} of its own in the same period."
            if whea else "")
         + (f" The hottest zone reported {hottest} C." if hottest is not None else "")
         + ("" if corroborated else
            " Nothing else on this PC corroborates it, which matters: the machine cannot "
            "tell its own power failing apart from the mains being cut.")),
        confidence=confidence,
        severity=severity,
        evidence_keys=["power_loss", "thermal", "sensors", "hardware_errors"],
        actions=[task_action("pc_report", "Capture the machine's state for comparison.")],
        advice=("Rule out the simple explanation first: a power cut, a tripped breaker, a "
                "switched-off extension lead, or a pet finding the socket. Windows records "
                "those identically, and on a desktop they are the most common cause by far. "
                "If the timings match nothing in the house, then in rough order of "
                "likelihood it is the power supply under load, heat causing a protective "
                "cut-out, a loose power connector, or the board. Also check crash dumps and "
                "dump-write failures, and return tuning to stock settings. A fault under load "
                "needs cooling and power checks, but this event alone cannot name a failed part. "
                "Have a technician test power delivery; never open a power supply."),
    )


@rule
def rule_gpu_hardware_fault(ctx):
    """Repeated graphics engine timeouts require isolation, not a replacement verdict."""
    live = ctx.get("live_kernel_events", {})
    if not live.get("available"):
        return None
    count = live.get("hardware_faults", 0)
    # A single captured hang is worth reporting -- and it is, as a finding -- but
    # it is not evidence that a card is failing. Graphics drivers hang. Naming a
    # dying GPU off one incident is how someone replaces working hardware.
    if count < 2:
        return None
    worst = live.get("worst") or {}
    spread = live.get("hardware_days", 1) or 1
    recent = live.get("hardware_newest_days_ago")
    # Corroboration from somewhere the GPU is measured independently.
    resets = (ctx.get("gpu_resets", {}) or {}).get("count", 0)
    faulted = bool((ctx.get("gpu_hardware", {}) or {}).get("faulted"))
    # Faults on several different days are an ongoing fault. All of them in one
    # evening, months ago, is an episode that has since passed -- most often a
    # driver having a bad night. Same events, opposite advice.
    episode = spread <= 1 and (recent is None or recent > 14)
    if episode:
        severity, confidence = "medium", 45
    elif spread >= 3 or faulted or (count >= 3 and resets):
        severity, confidence = "critical", 80
    else:
        severity, confidence = "high", 62
    return Hypothesis(
        "gpu_hardware_fault",
        ("The graphics card stopped responding, though not recently" if episode else
         "The graphics engine is repeatedly timing out"),
        (f"Windows captured {_plural(count, 'fault')} where the GPU stopped responding "
         f"entirely and did not come back"
         + (f" ({worst.get('title', '')})" if worst.get("title") else "")
         + ". This records a graphics engine timeout. Drivers, tuning, cooling, power and "
         "physical hardware are all possible causes; this code does not distinguish them."
         + (f" All of them happened on the same day, {recent} days ago, and nothing has "
            f"recurred since. That pattern is usually one bad session rather than a card on "
            f"its way out." if episode and recent is not None else
            f" They are spread across {spread} separate days, which is what an ongoing "
            f"hardware fault looks like rather than a one-off." if spread >= 3 else "")),
        confidence=confidence,
        severity=severity,
        evidence_keys=["live_kernel", "gpu_resets", "gpu_hardware", "gpu_telemetry"],
        actions=[repair_action("clear_shader_cache", {},
                              reason="Rule out a corrupted shader cache first -- it is the one "
                                     "software cause that produces similar symptoms."),
                 task_action("gpu_diagnostic", "Capture the card's own diagnostic report.")],
        advice=("Nothing needs opening up yet. Faults that stopped on their own are usually a "
                "driver version or one heavy session, so note the date and see whether it "
                "recurs. If it starts happening on separate days, come back to this -- that "
                "is the point at which the card itself becomes the likely answer."
                if episode else
                "First update or roll back the official graphics driver and return GPU tuning "
                "to stock settings. If faults persist, shut down and disconnect power. "
                "Reseat the card following the manufacturer's service instructions, and make sure each PCIe "
                "power lead runs separately back to the supply rather than daisy-chained. "
                "Clear the dust out of the cooler. If the card is fed by a supply that is "
                "marginal for it, that shows up as exactly this. Test in another machine if "
                "you can -- it is the fastest way to settle whether it is the card or the "
                "board."),
    )


@rule
def rule_gpu_recovery_disabled(ctx):
    """Crash recovery switched off, which hides a fault instead of fixing it."""
    gpu = ctx.get("gpu_hardware", {})
    if not gpu.get("available"):
        return None
    disabled = gpu.get("tdr_disabled")
    raised = gpu.get("tdr_delay_raised")
    if not (disabled or raised):
        return None
    resets = (ctx.get("gpu_resets", {}) or {}).get("count", 0)
    return Hypothesis(
        "gpu_recovery_disabled",
        ("Graphics crash recovery has been switched off" if disabled
         else "Graphics crash recovery has been stretched"),
        (("Timeout Detection and Recovery is turned off on this PC. It is what lets Windows "
          "reset a hung graphics driver and carry on; without it the machine hard-locks where "
          "it would have recovered in a second."
          if disabled else
          f"The graphics timeout has been raised to "
          f"{gpu.get('tdr', {}).get('TdrDelay')} seconds from the default of 2. That does not "
          f"stop the driver hanging -- it just makes Windows wait longer before admitting it.")
         + " This is a setting someone changed, usually on forum advice, and it is the "
         "standard way a real graphics fault gets hidden for months."
         + (f" The driver has still had to be reset {resets} time(s)." if resets else "")),
        confidence=72,
        severity="medium",
        evidence_keys=["gpu_hardware", "gpu_resets"],
        actions=[repair_action("reset_tdr", {},
                               reason="Put crash recovery back to the Windows default so the "
                                      "real fault becomes visible again.")],
        advice=("Expect to see more driver resets after this, not fewer. That is the point: "
                "they were happening anyway, and now they are recoverable and countable."),
    )


@rule
def rule_gpu_link_degraded(ctx):
    """A card running at a fraction of its bandwidth, for physical reasons."""
    telemetry = ctx.get("gpu_vendor_telemetry", {})
    if not telemetry.get("available"):
        return None
    degraded = telemetry.get("degraded_links") or []
    if not degraded:
        return None
    card = degraded[0]
    width, maximum = card.get("pcie_width"), card.get("pcie_width_max")
    share = (round(100.0 * width / maximum) if width and maximum else None)
    return Hypothesis(
        "gpu_link_degraded",
        f"{card['name']} is connected at reduced bandwidth",
        (f"The card is negotiating a PCIe link of x{width} where it is capable of x{maximum}"
         + (f" -- roughly {share}% of the bandwidth it should have." if share else ".")
         + " The board's lane layout, firmware settings and lane sharing can intentionally "
         "limit the link. A seating, slot or riser problem is another possibility; this "
         "reading alone does not establish a physical fault."),
        confidence=82,
        severity="high",
        evidence_keys=["gpu_telemetry", "gpu_hardware"],
        actions=[task_action("gpu_diagnostic", "Record the card's own report of the link.")],
        advice=("Check the board manual and lane-sharing configuration first. If the width is "
                "unexpected for this configuration, shut down and disconnect power. Follow "
                "the service manual to unseat the card and put it back firmly until the retaining clip "
                "clicks. Look for dust in the slot. If the board has more than one full-length "
                "slot, try the other one -- if the link comes back, the first slot is the "
                "fault. On a laptop or a small-form-factor PC with a riser, the riser cable is "
                "the usual culprit. Check the board manual too: on many boards the top slot "
                "drops to x8 as soon as a second M.2 drive is fitted, and that is by design "
                "rather than a fault."),
    )


@rule
def rule_gpu_memory_errors(ctx):
    """Uncorrected ECC errors on the card's own memory."""
    telemetry = ctx.get("gpu_vendor_telemetry", {})
    if not telemetry.get("available"):
        return None
    errors = telemetry.get("ecc_errors") or 0
    if not errors:
        return None
    return Hypothesis(
        "gpu_memory_errors",
        "The graphics card's memory is producing errors",
        (f"The card reports {_plural(errors, 'uncorrected memory error')} in its aggregate "
         f"counters. Uncorrected means the card could not repair the data and passed it on "
         f"anyway, which shows up as visual corruption, failed renders, or results that are "
         f"quietly wrong."),
        confidence=88,
        severity="critical",
        evidence_keys=["gpu_telemetry", "live_kernel"],
        actions=[task_action("gpu_diagnostic", "Capture the full card report.")],
        advice=("If the card is overclocked -- including a factory overclock or a tuning "
                "profile in the vendor's utility -- return it to stock and re-check, because "
                "memory errors are the first thing an unstable memory clock produces. If they "
                "persist at stock settings, the card's memory is degrading and the card needs "
                "replacing."),
    )


@rule
def rule_firmware_stale(ctx):
    """Windows patching microcode around a firmware the board never updated."""
    firmware = ctx.get("firmware_info", {})
    cpu = ctx.get("cpu_details", {})
    if not (firmware.get("available") and cpu.get("available")):
        return None
    if not cpu.get("microcode_patched_by_os"):
        return None
    years = firmware.get("bios_age_years")
    if years is None or years < 2:
        return None
    # Firmware age is only worth raising when the machine is actually unstable;
    # on a PC that works, "your BIOS is old" is noise dressed up as a finding.
    crashes = len((ctx.get("bugchecks", {}) or {}).get("crashes") or [])
    whea = (ctx.get("whea_errors", {}) or {}).get("count", 0)
    losses = (ctx.get("power_events", {}) or {}).get("power_losses", 0)
    if not (crashes or whea or losses):
        return None
    board = firmware.get("board") or firmware.get("system_model") or "this board"
    return Hypothesis(
        "firmware_stale",
        "The motherboard firmware is behind",
        (f"{board} is running BIOS {firmware.get('bios_version', '?')}, released about "
         f"{years} years ago, and Windows is loading newer processor microcode over the top of "
         f"it at every boot. That is measurable evidence the firmware is behind fixes the chip "
         f"vendor has already shipped -- and this machine is unstable"
         + (f" ({_plural(crashes, 'recorded crash')})" if crashes else "")
         + (f" ({_plural(whea, 'hardware error')})" if whea else "")
         + ". Windows can patch microcode, but it cannot patch the memory training, power "
         "management and errata fixes that live in the firmware itself."),
        confidence=55,
        severity="medium",
        evidence_keys=["firmware", "cpu_hardware", "bugchecks", "hardware_errors"],
        actions=[task_action("device_firmware", "Check the vendor for a firmware update.")],
        advice=("Get the update from the board or PC vendor's own support page for your exact "
                "model -- never from a driver-updater tool. Plug a laptop into mains power "
                "before starting, and do not interrupt it. If the machine is stable and you "
                "are only chasing this because it appeared in a scan, it is reasonable to "
                "leave it alone; a firmware update is the one maintenance task that can leave "
                "a machine unbootable."),
    )


@rule
def rule_cooling_fault(ctx):
    """A fan that has stopped, or a rail out of range."""
    sensors = ctx.get("sensor_readings", {})
    if not sensors.get("available"):
        return None
    stopped = sensors.get("stopped_fans") or []
    alarms = sensors.get("voltage_alarms") or []
    hottest = sensors.get("hottest_c")
    overheating = hottest is not None and hottest >= 95
    if not (stopped or alarms or overheating):
        return None
    signals = []
    if stopped:
        signals.append(f"{_plural(len(stopped), 'fan')} reporting stopped or faulted")
    if alarms:
        signals.append(f"{_plural(len(alarms), 'voltage rail')} outside its safe range")
    if overheating:
        signals.append(f"a zone at {hottest} C")
    return Hypothesis(
        "cooling_fault",
        "A cooling or power sensor is reporting a fault",
        ("The board is reporting " + " and ".join(signals) + ". These come from the hardware "
         "monitoring chip rather than from Windows, so they describe the physical state of the "
         "machine directly."),
        confidence=76,
        severity="critical" if (stopped or alarms) else "high",
        evidence_keys=["sensors", "thermal", "power_loss"],
        actions=[],
        advice=("Shut down and look inside before running the machine further. A stopped fan "
                "on a heatsink means the part under it is being cooled by luck. Dust in the "
                "fins is the usual cause and the easiest fix. Note that some boards report a "
                "fan header as stopped simply because nothing is plugged into it, so confirm "
                "by eye that the fans are actually turning before replacing anything."),
    )


@rule
def rule_kernel_pool_leak(ctx):
    """Memory taken by a driver, which no process view will ever show."""
    pool = ctx.get("pool_usage", {})
    if not pool.get("available") or not pool.get("nonpaged_high"):
        return None
    nonpaged = pool.get("nonpaged_mb")
    share = pool.get("nonpaged_pct")
    return Hypothesis(
        "kernel_pool_leak",
        "A driver is holding an unusual amount of memory",
        (f"Non-paged pool is at {nonpaged} MB"
         + (f", about {share}% of this machine's memory" if share else "")
         + ". That is memory claimed by drivers and by Windows itself, and it cannot be "
         "swapped out. It is also invisible in Task Manager's process list, which is why this "
         "gets misdiagnosed: the user watches their RAM disappear with nothing to blame, and "
         "is told to reinstall Windows."),
        confidence=62,
        severity="medium",
        evidence_keys=["kernel_pool", "memory", "top_memory"],
        actions=[task_action("pc_report", "Record the pool figures to compare against later.")],
        advice=("Restart and watch whether the figure climbs steadily from boot -- a leak "
                "grows, a merely large pool does not. Storage, networking and virtualisation "
                "drivers are the usual sources, as is anything that filters the file system "
                "such as antivirus or backup software. If it climbs, the most recently "
                "installed driver of that kind is the first thing to remove."),
    )


@rule
def rule_shared_crash_module(ctx):
    """Unrelated programs dying in the same component."""
    reports = ctx.get("wer_reports", {})
    if not reports.get("available") or not reports.get("shared_fault"):
        return None
    module = reports.get("top_module", "")
    count = reports.get("top_module_count", 0)
    apps = reports.get("top_module_apps", 0)
    vendor = module_vendor(module)
    return Hypothesis(
        "shared_crash_module",
        f"Unrelated programs are all crashing inside {module}",
        (f"{module} has faulted {count} time(s) across {apps} different programs"
         + (f". That component belongs to {vendor}." if vendor else ".")
         + " Separate applications failing in the same place is one broken component, not "
         "several broken applications -- and it is only visible because Windows records which "
         "module faulted, not just which program did."),
        confidence=74,
        severity="high",
        evidence_keys=["crash_reports", "app_crashes"],
        actions=[task_action("repair_system",
                             "Repair Windows' own components, which covers the system "
                             "libraries this points at.")],
        advice=(f"If {module} came with a program you installed, reinstall or update that "
                f"program -- that replaces the file. If it is a Windows component, the system "
                f"file repair covers it. If it belongs to a graphics or audio driver, "
                f"reinstall that driver cleanly rather than over the top of itself."
                if not vendor else
                f"This belongs to {vendor}. Reinstalling or updating that software replaces "
                f"the faulting file, which is the fix -- repairing Windows will not, because "
                f"the file is not Windows'."),
    )


@rule
def rule_repeating_bugcheck(ctx):
    """The same stop code over and over, read out of the dumps themselves."""
    dumps = ctx.get("minidump_details", {})
    if not dumps.get("available"):
        return None
    codes = dumps.get("codes") or {}
    if not codes:
        return None
    top = max(codes, key=codes.get)
    repeats = codes[top]
    if repeats < 3:
        return None
    name, cause, tags = describe_bugcheck(top)
    scattered = dumps.get("distinct_codes", 1) > 3
    return Hypothesis(
        "repeating_bugcheck",
        f"The same crash is repeating: {name}",
        (f"{_plural(repeats, 'crash dump')} carry the stop code {top} ({name}). {cause} "
         f"This was read out of the dump files rather than the event log, so it is here even "
         f"when the log entry was never written."
         + (" There is also a scatter of other codes, which is the pattern memory and power "
            "faults produce -- whatever happens to be running is what dies."
            if scattered else
            " The consistency is useful: one repeating code points at one cause.")),
        confidence=80,
        severity="high",
        evidence_keys=["crash_dumps_detail", "bugchecks", "crash_dumps"],
        actions=[task_action("minidump_analyzer",
                             "Analyse the dumps properly to name the driver involved."),
                 task_action("bsod_triage", "Work through the crash systematically.")],
        advice=("The stop code narrows it; the dump analysis names the driver. Run that before "
                "changing anything, because the most common mistake here is reinstalling "
                "Windows over a hardware fault."
                + (" A varied set of stop codes with no single culprit is much more often "
                   "memory or power than software." if scattered else "")),
    )


@rule
def rule_log_storm(ctx):
    """One error repeating hundreds of times, found by sweeping every log."""
    logs = ctx.get("event_log_sweep", {})
    if not logs.get("available"):
        return None
    repeating = logs.get("repeating") or []
    if not repeating:
        return None
    top = repeating[0]
    # The threshold is high on purpose. A machine that has been on for a
    # fortnight logs plenty; only a genuine storm clears this.
    if top["count"] < 40:
        return None
    return Hypothesis(
        "log_storm",
        f"{top['provider']} is logging the same error constantly",
        (f"Event {top['id']} from {top['provider']} has been logged {top['count']} times in "
         f"{logs.get('days', 14)} days, in the {top['log']} log."
         + (f" The most recent reads: {top['message'][:160]}" if top.get("message") else "")
         + " This was found by sweeping every enabled log on the machine rather than just "
         "System and Application, which is where component failures like this normally sit "
         "unread."),
        confidence=58,
        severity="medium",
        evidence_keys=["log_sweep"],
        actions=[task_action("event_log_viewer", "Open the log and read the full entries.")],
        advice=("Something repeating at this rate is a component retrying and failing "
                "continuously. It is worth reading a few of the entries in full -- the message "
                "usually names the device or service involved, which turns this from a count "
                "into something specific."),
    )


@rule
def rule_partitions_misaligned(ctx):
    """A layout that makes the drive do every write twice."""
    geometry = ctx.get("disk_geometry", {})
    if not geometry.get("available"):
        return None
    misaligned = geometry.get("misaligned") or []
    if not misaligned:
        return None
    letters = ", ".join(p["letter"] + ":" for p in misaligned if p.get("letter"))
    return Hypothesis(
        "partitions_misaligned",
        "A partition is not aligned to the drive underneath it",
        (f"{_plural(len(misaligned), 'partition')}"
         + (f" ({letters})" if letters else "")
         + " does not start on a 1 MB boundary. When the partition boundaries do not line up "
         "with the drive's own block size, a single write can span two blocks and the drive "
         "has to read, modify and write both. It reads as an SSD that has become slow, and it "
         "is a real and permanent overhead rather than a measurement artefact. This is almost "
         "always the signature of a disk cloned from a much older layout."),
        confidence=64,
        severity="low",
        evidence_keys=["disk_geometry", "disk_latency"],
        actions=[],
        advice=("Alignment cannot be corrected without recreating the partition, so this is "
                "only worth acting on if the drive feels slow. The fix is to back up, "
                "reinstall or re-image onto a freshly created partition, and restore -- a "
                "modern Windows installer aligns correctly on its own."),
    )


@rule
def rule_tpm_not_ready(ctx):
    """A TPM that is fitted but not in a usable state."""
    tpm = ctx.get("tpm_state", {})
    if not tpm.get("available") or not tpm.get("present"):
        return None
    if tpm.get("ready"):
        return None
    encryption = ctx.get("bitlocker_state", {}) or {}
    return Hypothesis(
        "tpm_not_ready",
        "The security chip is present but not ready",
        ("This machine has a TPM, but it is not in a state Windows can use"
         + (" -- it is not enabled." if tpm.get("enabled") is False else "")
         + (" -- it has no owner set." if tpm.get("owned") is False else "")
         + " That is what sits behind BitLocker demanding a recovery key at every boot and "
         "Windows Hello refusing to enrol."),
        confidence=70,
        severity="medium",
        evidence_keys=["tpm", "encryption"],
        actions=[],
        advice=("Before touching the TPM, find your BitLocker recovery key and save it "
                "somewhere off this machine -- it is on your Microsoft account at "
                "aka.ms/myrecoverykey. Clearing a TPM without that key makes an encrypted "
                "drive permanently unreadable."
                if encryption.get("protected") else
                "This can usually be resolved in the firmware settings, where the TPM can be "
                "enabled and cleared. Check first that no drive on this PC is encrypted: "
                "clearing a TPM that is holding a BitLocker key makes that drive unreadable "
                "for good."),
    )
