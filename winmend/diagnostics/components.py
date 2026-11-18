"""WinMend diagnostics: components."""

from __future__ import annotations




DEVICE_GUIDANCE = {
    10: "The device cannot start. Restart Windows, then install the PC or device maker's driver for this exact model. If it persists, test the device or port separately.",
    12: "Windows cannot allocate enough resources. Disconnect optional peripherals and check the PC maker's chipset and firmware guidance.",
    14: "Windows requires a restart to finish configuring this device. Save your work and restart, then scan again.",
    18: "Reinstall this device's driver from the PC or device maker, then restart and scan again.",
    22: "This device is disabled. If you need it, enable it in Device Manager. An intentionally disabled device needs no repair.",
    24: "Windows cannot use this device. Check its connection and its driver in Device Manager before replacing anything.",
    28: "The driver is missing. Install the correct driver from Windows Update or the PC/device maker's official support page.",
    29: "Firmware has disabled this device. Check the exact model's firmware settings and manual; a Windows driver cannot enable it there.",
    31: "Windows cannot load the required drivers. Install or roll back the manufacturer's driver, then restart and re-check.",
    43: "The device reported a problem. This can be hardware, firmware or a driver. Restart, check the official driver, then test the device or connection separately.",
    48: "Windows blocked an incompatible driver. Obtain a compatible signed driver from the manufacturer or Windows Update.",
    52: "Windows cannot verify the driver signature. Install an official signed driver; do not disable signature enforcement.",
}


def device_guidance(code):
    return DEVICE_GUIDANCE.get(code, "Review this device's status in Device Manager. Check its connection and the manufacturer's driver instructions, then scan again.")


# Sources that measure behaviour, rather than merely inventory a component.
COMPONENTS = (
    ("motherboard", "Motherboard & firmware", ("firmware_errors", "whea_errors"),
     ("firmware", "firmware_errors", "hardware_errors"), "system_information",
     "Check the exact PC or board model and revision on the manufacturer's support page. Compare BIOS release notes with the symptoms; age alone is not a fault. Before any firmware update, save the BitLocker recovery key and follow the vendor's power and recovery instructions.",
     "Windows cannot test board traces, capacitors, VRMs, the CMOS battery, or every slot. A PCIe error may originate in the card, slot, CPU lanes, power or firmware; it does not identify a failed motherboard."),
    ("cpu", "Processor", ("whea_errors", "cpu_throttle"),
     ("cpu_hardware", "cpu_clock", "hardware_errors"), "system_information",
     "If errors recur, return only CPU overclock/undervolt settings to the vendor defaults. Check cooling and official firmware guidance. Persistent errors at stock settings need manufacturer diagnostics or service.",
     "Error logs and clock readings are indirect checks. This scan does not stress-test every CPU core or identify a faulty CPU socket."),
    ("memory", "Memory", ("memory_pattern_test", "memory_diagnostic"),
     ("memory_pattern", "memory_modules", "memory_test"), "memory_diagnostic",
     "Save your work and open Windows Memory Diagnostic to choose when to run the offline test. If errors occur, turn off XMP/EXPO or memory overclocking and retest. Follow the PC manual or use a technician to isolate individual modules and slots.",
     "The live test writes patterns only to its own allocated memory. It cannot test all installed RAM or map a virtual address to a specific DIMM. A passing sample does not exclude intermittent faults."),
    ("storage", "Drives & storage controllers", ("smart_attributes", "disk_read_sweep", "storage_bus_errors"),
     ("smart_detail", "smart", "disk_surface", "storage_events", "drive_wear", "disk_geometry"), "device_manager",
     "If reads fail or drive health warns, back up important files before further testing. After backup, use the drive maker's diagnostic. For recurring link errors, shut down and disconnect power before following the manual to check a cable or slot. Physical media faults require service or replacement.",
     "Only sampled blocks are read. USB bridges and RAID controllers may hide drive health; a clean sample cannot certify every sector or every drive."),
    ("graphics", "Graphics", ("live_kernel_events", "gpu_vendor_telemetry", "gpu_hardware"),
     ("live_kernel", "gpu_hardware", "gpu_telemetry", "gpu_resets"), "device_manager",
     "For recurring timeouts, update or roll back the official graphics driver and return GPU tuning to defaults. Check cooling and power connections using the manufacturer's instructions. Persistent faults need a known-good card/system comparison or service.",
     "A graphics timeout or Code 43 does not prove the card has failed. This scan does not exhaustively test VRAM or GPU stability under load."),
    ("power", "Power & battery", ("power_events", "battery_wear"),
     ("power_loss", "battery_wear"), "system_information",
     "Compare restart times with outages, sleep transitions and crashes. Check the external cable, outlet and correct adapter. Have a technician test a desktop power supply under load if unexplained restarts continue. Never open a power supply; a swollen battery needs service.",
     "Event 41 records an unexpected shutdown, not its cause. Windows generally cannot measure PSU output or exclude a motherboard power fault."),
    ("cooling", "Cooling & sensors", ("sensor_readings",),
     ("sensors", "thermal"), "system_information",
     "Compare readings with the manufacturer's limits and its hardware monitor. Check vents and actual fan operation; zero-RPM idle modes and unused fan headers can be normal. Shut down and disconnect power before cleaning or servicing internal parts.",
     "Sensor support varies by board. ACPI temperatures may be thermal zones rather than CPU core temperatures; absent readings do not indicate normal cooling."),
    ("network", "Network & Bluetooth", ("adapter_health", "bluetooth_health"),
     ("link_health", "bluetooth"), "device_manager",
     "Check the adapter in Device Manager and use the PC maker's network/Bluetooth driver. Try a known-good cable, router or USB port to separate an adapter problem from a connection problem.",
     "Device status and link readings do not test antenna damage or every radio function."),
    ("audio", "Audio", ("audio_health",), ("audio",), "device_manager",
     "Select the intended audio output in Windows and check the official audio driver. Test another headset or speaker and another port to isolate the physical connection.",
     "Software status cannot test speaker sound quality, microphones or jack contacts."),
    ("usb", "USB controllers & ports", (), (), "device_manager",
     "Disconnect optional USB devices and reconnect one at a time. Try a known-good device and cable in another port. Check the PC maker's chipset driver if a controller reports an error.",
     "Only connected devices are visible. Empty ports and available USB power require a physical test."),
    ("display", "Displays", ("display_links",), ("monitors",), "device_manager",
     "Try a known-good display cable and another output. Check the monitor input and test the monitor with another system if the issue continues.",
     "Display identification cannot detect dead pixels, backlight faults or intermittent cable failures."),
    ("other", "Other connected devices", (), (), "device_manager",
     "Check the named device in Device Manager and follow its manufacturer's diagnostic instructions. Test detachable devices on another port or computer when possible.",
     "Enumeration does not exercise every function of printers, cameras, sensors or other peripherals."),
)


def build_component_report(raw, findings):
    """Return serializable coverage, evidence and manual actions for each area."""
    inventory = raw.get("component_devices") or {}
    all_devices = inventory.get("devices") or []
    rows = []
    for key, title, sources, finding_keys, tool, guidance, limitation in COMPONENTS:
        devices = [d for d in all_devices if d.get("component") == key]
        problems = [d for d in devices if d.get("code") not in (None, 0)]
        evidence = [f for f in findings if f.get("key") in finding_keys]
        # Shared WHEA data is relevant only to the area named by its source.
        areas = (raw.get("whea_errors") or {}).get("areas") or {}
        if key == "cpu" and not areas.get("processor"):
            evidence = [f for f in evidence if f.get("key") != "hardware_errors"]
        attention = [f for f in evidence if f.get("status") in ("warn", "bad")]
        available = []
        missing = []
        for source in sources:
            value = raw.get(source) or {}
            usable = value.get("available", False)
            reason = value.get("reason") or "Not available from Windows on this scan."
            if source == "sensor_readings" and value.get("exposes_nothing"):
                usable, reason = False, "This board exposes no supported sensors."
            if source == "memory_diagnostic" and not value.get("ever_run", bool(value.get("runs"))):
                usable, reason = False, "No recorded offline memory test."
            if usable:
                available.append(source)
                if source == "disk_read_sweep" and value.get("unreadable"):
                    missing.append("One or more drives could not be sampled.")
                if source == "memory_pattern_test" and not value.get("completed"):
                    missing.append("The memory pattern test did not complete every pass.")
            else:
                missing.append(f"{source.replace('_', ' ').capitalize()}: {reason}")
        device_coverage = bool(inventory.get("available") and devices)
        if any(d.get("code") is None for d in devices):
            missing.append("Windows did not report a status code for every device.")
        if not inventory.get("available") and key not in ("memory", "cooling"):
            missing.append("Connected device status could not be read.")
        if problems or attention:
            state = "attention"
        elif not available and not device_coverage:
            state = "unavailable"
        elif missing or not sources:
            state = "limited"
        else:
            state = "no_issue"
        labels = {"attention": "Needs attention", "unavailable": "Not assessed",
                  "limited": "Limited coverage", "no_issue": "No issues found in checks"}
        details = [f"{f.get('label')}: {f.get('value')} — {f.get('detail', '')}" for f in evidence]
        if key in ("motherboard", "cpu", "memory"):
            for event in (raw.get("whea_errors") or {}).get("events", []):
                area = event.get("area")
                if key == "cpu" and area != "processor" or key == "memory" and area != "memory":
                    continue
                location = ", ".join(f"{label} {event[field]}" for field, label in (
                    ("device_name", "Device"), ("apic_id", "CPU APIC ID"),
                    ("mca_bank", "MCA bank"), ("pci_bus", "PCI bus"),
                    ("pci_device", "device"), ("pci_function", "function")) if event.get(field))
                details.append(f"WHEA {event.get('id')} at {event.get('time')}: "
                               f"{event.get('meaning', '')}. {location}")
                # A memory-specific hardware event must remain visible even
                # when the live memory sample happened to pass.
                if key == "memory":
                    state = "attention"
        steps = []
        for device in problems:
            steps.append(f"{device['name']} — Code {device['code']}: {device_guidance(device['code'])}")
        steps.append(guidance)
        if problems:
            tool = "device_manager"
        if key == "motherboard":
            fw = raw.get("firmware_info") or {}
            identity = fw.get("board") or fw.get("system_model")
            if identity:
                details.insert(0, f"{identity}; BIOS {fw.get('bios_version', 'unknown')}; release {fw.get('bios_date', 'unknown')}")
        rows.append({"id": key, "name": title, "status": state, "status_label": labels[state],
                     "devices": devices, "evidence": details, "missing": missing,
                     "next_steps": steps, "limitation": limitation, "tool": tool,
                     "summary": (f"{len(problems)} device status issue(s); {len(attention)} flagged reading(s)."
                                 if problems or attention else
                                 f"{len(available)} evidence source(s); {len(devices)} connected device(s).")})
    return rows
