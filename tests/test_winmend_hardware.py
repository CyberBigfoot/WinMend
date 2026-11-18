"""Tests for the component-level hardware scan.

Two things are being protected here, and they pull in opposite directions.

The first is that the rules fire: a drive with pending sectors, a GPU that
stopped answering, and memory that changed a byte all have to produce the right
diagnosis, and none of them can be reproduced on a working development machine.
So the engine is driven against a scripted probe.

The second matters more, and is the reason this file is not just a list of happy
paths. Almost every source in this scan is gated -- on elevation, on the board
choosing to expose a sensor, on a vendor tool being installed. A scan that
reports a clean bill of health because it was never allowed to look is worse
than one that did not run, so the tests that assert *silence* on absent evidence
are doing the more important half of the job.
"""

import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from winmend_diagnostics import (  # noqa: E402
    AUDIT_PROFILE, CaseEngine, DeepProbe, FINDING_SOURCES, HARDWARE_PROFILE,
    REPAIR_ACTIONS,
)
from winmend_hardware import (  # noqa: E402
    LIVE_KERNEL_EVENTS, SMART_ATTRIBUTES, STORAGE_EVENTS, HardwareProbe,
)

from test_winmend_diagnostics import HEALTHY, ScriptedProbe  # noqa: E402


# A machine whose every hardware collector ran and found nothing. Anything a
# test wants to be wrong is layered on top of this, so a rule that fires here
# is firing on evidence the test did not provide.
HEALTHY_HARDWARE = {
    "firmware_info": {"available": True, "bios_vendor": "Acme", "bios_version": "F12",
                      "bios_date": "2024-01-01", "bios_age_days": 200,
                      "bios_age_years": 0.5, "board": "Acme B650",
                      "board_vendor": "Acme", "board_model": "B650",
                      "secure_boot": "on", "uefi": True},
    "cpu_details": {"available": True, "name": "Test CPU", "cores_physical": 8,
                    "cores_logical": 16, "microcode": 100, "microcode_firmware": 100,
                    "microcode_patched_by_os": False},
    "memory_modules": {"available": True, "count": 2, "slots_total": 4, "slots_free": 2,
                       "modules": [{"slot": "A1", "gb": 16, "rated_mhz": 3200,
                                    "running_mhz": 3200, "vendor": "X", "part": "P1"},
                                   {"slot": "B1", "gb": 16, "rated_mhz": 3200,
                                    "running_mhz": 3200, "vendor": "X", "part": "P1"}],
                       "ecc": False, "mixed_parts": False, "mixed_vendors": False,
                       "mixed_sizes": False, "mixed_rated": False,
                       "rated_mhz": 3200, "running_mhz": 3200, "underclocked": False},
    "tpm_state": {"available": True, "present": True, "ready": True, "enabled": True,
                  "activated": True, "owned": True},
    "sensor_readings": {"available": True, "zones": [{"name": "cpu", "celsius": 45.0}],
                        "fans": [{"name": "cpu", "rpm": 900, "status": "OK"}],
                        "voltages": [], "throttling": [], "hottest_c": 45.0,
                        "stopped_fans": [], "voltage_alarms": [],
                        "exposes_nothing": False},
    "power_events": {"available": True, "count": 0, "events": [], "power_losses": 0,
                     "bugcheck_shutdowns": 0, "button_shutdowns": 0,
                     "dirty_shutdowns": 0, "days": 60},
    "firmware_errors": {"available": True, "count": 0, "events": [], "groups": {},
                        "acpi_errors": 0, "serious": 0, "days": 45},
    "gpu_hardware": {"available": True, "count": 1, "faulted": [],
                     "adapters": [{"name": "Test GPU", "driver_version": "1.0",
                                   "driver_date": "2025-01-01", "driver_age_days": 100,
                                   "vram_mb": 8192, "status": "OK", "error_code": 0}],
                     "tdr": {}, "tdr_disabled": False, "tdr_delay_raised": False,
                     "hags_on": False, "oldest_driver_days": 100},
    "live_kernel_events": {"available": True, "reports": [], "report_count": 0,
                           "events": [], "event_count": 0, "codes": {},
                           "hardware_faults": 0, "worst": None, "days": 60},
    "gpu_vendor_telemetry": {"available": False, "reason": "nvidia-smi not present"},
    "display_links": {"available": True, "count": 1, "active": 1,
                      "monitors": [{"name": "Panel", "vendor": "V", "year": 2022,
                                    "active": True, "connection": "DisplayPort (external)"}],
                      "connections": ["DisplayPort (external)"]},
    "smart_attributes": {"available": True, "count": 1, "failing": [], "with_concerns": [],
                         "drives": [{"instance": "d0", "attributes": [], "concerning": [],
                                     "predict_failure": False, "pending_sectors": 0,
                                     "reallocated": 0, "uncorrectable": 0,
                                     "crc_errors": 0, "power_on_hours": 4000,
                                     "celsius": 33}]},
    "storage_bus_errors": {"available": True, "count": 0, "events": [], "by_id": {},
                           "blame": {"drive": 0, "link": 0}, "by_disk": {},
                           "worst_disk": None, "resets": 0, "bad_blocks": 0, "days": 45},
    "disk_geometry": {"available": True, "disks": [{"id": 0, "name": "SSD", "firmware": "1",
                                                    "bus": "NVMe", "physical_sector": 4096,
                                                    "logical_sector": 512, "gb": 931.0,
                                                    "health": "Healthy"}],
                      "partitions": [{"disk": 0, "number": 1, "offset": 1048576,
                                      "gb": 930.0, "letter": "C", "aligned": True}],
                      "misaligned": [], "unhealthy": []},
    "disk_read_sweep": {"available": True, "unreadable": [], "total_errors": 0,
                        "failing": [], "sluggish": [],
                        "disks": [{"disk": 0, "blocks_read": 48, "gb_span": 931.0,
                                   "median_ms": 0.4, "worst_ms": 1.2, "slow_reads": 0,
                                   "errors": [], "error_count": 0}]},
    "memory_pattern_test": {"available": True, "tested_mb": 2048, "passes": 5,
                            "patterns": 5, "completed": True, "failures": [],
                            "failed": False},
    "pool_usage": {"available": True, "paged_mb": 400, "nonpaged_mb": 600,
                   "total_mb": 32768, "nonpaged_pct": 1.8, "nonpaged_high": False,
                   "paged_high": False, "commit_pct": 30.0},
    "event_log_sweep": {"available": True, "clusters": [], "cluster_count": 0,
                        "total_errors": 0, "critical": [], "critical_count": 0,
                        "repeating": [], "logs_scanned": 40, "logs_total": 40,
                        "complete": True, "days": 14},
    "wer_reports": {"available": True, "count": 3, "crashes": [], "modules": {},
                    "applications": {}, "types": {}, "top_module": "",
                    "top_module_count": 0, "top_module_apps": 0,
                    "shared_fault": False, "days": 45},
    "minidump_details": {"available": False, "reason": "no recent crash dumps"},
}


def deep_build(overrides=None, problem="Hardware deep scan"):
    """Run a hardware scan against scripted evidence."""
    data = dict(HEALTHY)
    data.update(HEALTHY_HARDWARE)
    data.update(overrides or {})
    engine = CaseEngine(probe=ScriptedProbe(data))
    return engine.build_case(problem, answers={}, profile=HARDWARE_PROFILE, deep=True)


def ids(case):
    return [h["id"] for h in case["hypotheses"]]


def finding(case, key):
    for row in case["findings"]:
        if row["key"] == key:
            return row
    return None


class ParserTests(unittest.TestCase):
    """The binary and text formats, which are where a silent wrong answer hides."""

    def test_reads_a_64_bit_crash_dump_header(self):
        head = bytearray(0x60)
        head[0:4] = b"PAGE"
        head[4:8] = b"DU64"
        struct.pack_into("<I", head, 0x38, 0x0000007E)
        struct.pack_into("<4Q", head, 0x40, 0xC0000005, 0xFFFFF800, 0x11, 0x22)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "test.dmp"
            path.write_bytes(bytes(head))
            parsed = HardwareProbe._read_dump_header(path)
        self.assertEqual(parsed["code"], 0x7E)
        self.assertEqual(parsed["code_hex"], "0x0000007E")
        self.assertEqual(parsed["bits"], 64)
        self.assertEqual(parsed["parameters"][0], "0xC0000005")

    def test_reads_a_32_bit_crash_dump_header(self):
        # The field offsets differ between the layouts, and reading a 32-bit
        # dump at the 64-bit offsets returns a plausible wrong code rather than
        # failing -- so the discrimination is the thing worth testing.
        head = bytearray(0x60)
        head[0:4] = b"PAGE"
        head[4:8] = b"DUMP"
        struct.pack_into("<I", head, 0x28, 0x0000004E)
        struct.pack_into("<4I", head, 0x2C, 1, 2, 3, 4)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "test.dmp"
            path.write_bytes(bytes(head))
            parsed = HardwareProbe._read_dump_header(path)
        self.assertEqual(parsed["code"], 0x4E)
        self.assertEqual(parsed["bits"], 32)

    def test_rejects_a_file_that_is_not_a_dump(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "notadump.dmp"
            path.write_bytes(b"hello there, not a crash dump at all" * 8)
            self.assertIsNone(HardwareProbe._read_dump_header(path))

    def test_reads_a_wer_report_and_folds_its_signature(self):
        report = (
            "Version=1\r\n"
            "EventType=APPCRASH\r\n"
            "Sig[0].Name=Application Name\r\n"
            "Sig[0].Value=notepad.exe\r\n"
            "Sig[6].Name=Fault Module Name\r\n"
            "Sig[6].Value=broken.dll\r\n"
            "Sig[8].Name=Exception Code\r\n"
            "Sig[8].Value=c0000005\r\n"
        )
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "Report.wer"
            path.write_text(report, encoding="utf-16")
            fields = HardwareProbe._read_wer(path)
        self.assertEqual(fields["EventType"], "APPCRASH")
        # The point of the parser: the meaning lives in the Name, not the key.
        self.assertEqual(fields["Fault Module Name"], "broken.dll")
        self.assertEqual(fields["Application Name"], "notepad.exe")
        self.assertEqual(fields["Exception Code"], "c0000005")

    def test_wer_parser_survives_a_file_it_cannot_decode(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "Report.wer"
            path.write_bytes(bytes(range(256)) * 4)
            # Must return something empty-ish rather than raising: one unreadable
            # report cannot be allowed to sink the whole collector.
            self.assertIsInstance(HardwareProbe._read_wer(path), dict)

    def test_mismatch_describes_the_first_bad_byte_and_its_bits(self):
        reference = memoryview(b"\xaa" * 16)
        buffer = bytearray(b"\xaa" * 16)
        buffer[5] = 0xAB  # one bit different
        described = HardwareProbe._describe_mismatch(
            memoryview(buffer), reference, 0, 16, "alternating")
        self.assertEqual(described["wrote"], 0xAA)
        self.assertEqual(described["read"], 0xAB)
        self.assertEqual(described["bits_flipped"], 1)
        self.assertEqual(described["pattern"], "alternating")


class SmartTableTests(unittest.TestCase):
    """The 512-byte SMART blob, parsed rather than read."""

    @staticmethod
    def blob(entries):
        """Build a vendor-specific SMART payload from {id: raw} pairs."""
        data = bytearray(512)
        for index, (attribute_id, raw) in enumerate(entries.items()):
            base = 2 + index * 12
            data[base] = attribute_id
            data[base + 3] = 100      # current
            data[base + 4] = 100      # worst
            data[base + 5:base + 11] = int(raw).to_bytes(6, "little")
        return data

    def probe_with(self, entries, predict=False):
        probe = DeepProbe()
        payload = ",".join(str(b) for b in self.blob(entries))
        rows = [["D", "drive0", payload],
                ["S", "drive0", "True" if predict else "False", "0"]]
        probe._ps_rows = lambda *a, **k: (0, rows, "")
        return probe.smart_attributes()

    def test_extracts_the_counters_that_predict_failure(self):
        result = self.probe_with({5: 12, 9: 20000, 197: 3, 198: 1, 199: 0})
        drive = result["drives"][0]
        self.assertTrue(result["available"])
        self.assertEqual(drive["reallocated"], 12)
        self.assertEqual(drive["pending_sectors"], 3)
        self.assertEqual(drive["uncorrectable"], 1)
        self.assertEqual(drive["power_on_hours"], 20000)

    def test_temperature_uses_only_the_low_byte(self):
        # Drives pack current/min/max into the six raw bytes, so the whole raw
        # value is a nonsense temperature.
        result = self.probe_with({194: (45 | (30 << 16) | (60 << 32))})
        self.assertEqual(result["drives"][0]["celsius"], 45)

    def test_unused_slots_are_not_read_as_attribute_zero(self):
        result = self.probe_with({5: 0})
        # One attribute set, 29 empty slots -- all of which have id 0.
        self.assertEqual(len(result["drives"][0]["attributes"]), 1)

    def test_no_ata_drive_reports_unavailable_rather_than_healthy(self):
        probe = DeepProbe()
        probe._ps_rows = lambda *a, **k: (0, [], "")
        result = probe.smart_attributes()
        self.assertFalse(result["available"])
        self.assertIn("reason", result)


class HardwareRuleTests(unittest.TestCase):
    """Each fault the scan exists to find, on evidence a healthy PC cannot give."""

    def test_pending_sectors_are_reported_as_a_failing_drive(self):
        case = deep_build({"smart_attributes": {
            "available": True, "count": 1, "failing": [], "with_concerns": [],
            "drives": [{"instance": "d0", "attributes": [], "concerning": [],
                        "predict_failure": False, "pending_sectors": 8,
                        "reallocated": 0, "uncorrectable": 0, "crc_errors": 0,
                        "power_on_hours": 30000, "celsius": 40}]}})
        self.assertIn("drive_failing_smart", ids(case))
        lead = case["hypotheses"][0]
        self.assertEqual(lead["severity"], "critical")
        # The advice is the deliverable here, so it has to lead with the data.
        self.assertIn("Copy anything you care about off this drive", lead["advice"])

    def test_a_failing_drive_offers_no_disk_maintenance(self):
        # The whole point of catching it early: chkdsk and defrag are the worst
        # possible thing to run on a drive at this stage.
        case = deep_build({"smart_attributes": {
            "available": True, "count": 1, "failing": [], "with_concerns": [],
            "drives": [{"instance": "d0", "attributes": [], "concerning": [],
                        "predict_failure": True, "pending_sectors": 40,
                        "reallocated": 5, "uncorrectable": 9, "crc_errors": 0,
                        "power_on_hours": 40000, "celsius": 44}]}})
        planned = [step["id"] for step in case["plan"]]
        self.assertNotIn("chk_dsk", planned)
        self.assertNotIn("defrag_optimize", planned)

    def test_reallocated_sectors_alone_are_a_warning_not_an_emergency(self):
        case = deep_build({"smart_attributes": {
            "available": True, "count": 1, "failing": [], "with_concerns": [],
            "drives": [{"instance": "d0", "attributes": [], "concerning": [],
                        "predict_failure": False, "pending_sectors": 0,
                        "reallocated": 4, "uncorrectable": 0, "crc_errors": 0,
                        "power_on_hours": 20000, "celsius": 38}]}})
        found = [h for h in case["hypotheses"] if h["id"] == "drive_failing_smart"]
        self.assertTrue(found)
        self.assertEqual(found[0]["severity"], "medium")

    def test_crc_errors_blame_the_cable_rather_than_the_drive(self):
        case = deep_build({"smart_attributes": {
            "available": True, "count": 1, "failing": [], "with_concerns": [],
            "drives": [{"instance": "d0", "attributes": [], "concerning": [],
                        "predict_failure": False, "pending_sectors": 0,
                        "reallocated": 0, "uncorrectable": 0, "crc_errors": 25,
                        "power_on_hours": 9000, "celsius": 36}]}})
        found = [h for h in case["hypotheses"] if h["id"] == "drive_link_faults"]
        self.assertTrue(found)
        self.assertIn("cable", found[0]["advice"].lower())

    def test_failed_reads_are_reported_as_data_already_lost(self):
        case = deep_build({"disk_read_sweep": {
            "available": True, "unreadable": [], "total_errors": 3,
            "sluggish": [],
            "disks": [{"disk": 0, "blocks_read": 40, "gb_span": 931.0,
                       "median_ms": 0.4, "worst_ms": 900.0, "slow_reads": 1,
                       "errors": [{"offset_gb": 120.5, "error": "device error"}],
                       "error_count": 3}],
            "failing": [{"disk": 0, "blocks_read": 40, "gb_span": 931.0,
                         "median_ms": 0.4, "worst_ms": 900.0, "slow_reads": 1,
                         "errors": [{"offset_gb": 120.5, "error": "device error"}],
                         "error_count": 3}]}})
        self.assertIn("drive_read_failures", ids(case))

    def test_a_memory_pattern_failure_outranks_what_it_would_cause(self):
        case = deep_build({"memory_pattern_test": {
            "available": True, "tested_mb": 2048, "passes": 2, "patterns": 5,
            "completed": False, "failed": True,
            "failures": [{"pattern": "alternating", "offset_mb": 812.5,
                          "wrote": 170, "read": 171, "bits_flipped": 1,
                          "bit_mask": "0x01"}]}})
        self.assertIn("memory_proven_faulty", ids(case))
        lead = [h for h in case["hypotheses"] if h["id"] == "memory_proven_faulty"][0]
        self.assertEqual(lead["severity"], "critical")
        # XMP/EXPO is the most common cause by a wide margin, so it leads.
        self.assertIn("XMP", lead["advice"])

    def test_power_loss_is_separated_from_a_recorded_crash(self):
        case = deep_build({"power_events": {
            "available": True, "count": 5, "events": [], "power_losses": 3,
            "bugcheck_shutdowns": 2, "button_shutdowns": 0, "sleep_failures": 0,
            "dirty_shutdowns": 3, "days": 60}})
        found = [h for h in case["hypotheses"] if h["id"] == "power_delivery"]
        self.assertTrue(found)
        self.assertIn("dump-write failures", found[0]["advice"])
        self.assertNotIn("Software cannot do this", found[0]["advice"])

    def test_uncorroborated_power_loss_is_not_called_critical(self):
        # Twice in two months with nothing else wrong is as likely to be the
        # mains as the PC, and Windows records both identically.
        case = deep_build({"power_events": {
            "available": True, "count": 2, "events": [], "power_losses": 2,
            "bugcheck_shutdowns": 0, "button_shutdowns": 0, "sleep_failures": 0,
            "dirty_shutdowns": 2, "days": 60}})
        found = [h for h in case["hypotheses"] if h["id"] == "power_delivery"]
        self.assertTrue(found)
        self.assertEqual(found[0]["severity"], "medium")
        self.assertIn("power cut", found[0]["advice"])
        self.assertIn("corroborates", found[0]["explanation"])

    def test_power_loss_the_machine_corroborates_is_critical(self):
        case = deep_build({
            "power_events": {"available": True, "count": 2, "events": [],
                             "power_losses": 2, "bugcheck_shutdowns": 0,
                             "button_shutdowns": 0, "sleep_failures": 0,
                             "dirty_shutdowns": 2, "days": 60},
            "thermal_events": {"available": True, "throttle_events": 9}})
        found = [h for h in case["hypotheses"] if h["id"] == "power_delivery"]
        self.assertTrue(found)
        self.assertEqual(found[0]["severity"], "critical")

    def test_a_drop_during_sleep_is_not_reported_as_lost_mains(self):
        # SleepInProgress is an integer describing which transition was under
        # way, and reading it as a boolean turned a failed resume into a power
        # supply diagnosis.
        probe = DeepProbe()
        rows = [["K", "2026-09-04T10:05:42", "0", "0", "4"],
                ["K", "2026-09-03T19:57:25", "0", "0", "0"]]
        probe._ps_events = lambda *a, **k: (True, rows, "")
        result = probe.power_events()
        self.assertEqual(result["power_losses"], 1)
        self.assertEqual(result["sleep_failures"], 1)

    def test_shutdowns_that_were_all_crashes_do_not_blame_the_power_supply(self):
        case = deep_build({"power_events": {
            "available": True, "count": 4, "events": [], "power_losses": 0,
            "bugcheck_shutdowns": 4, "button_shutdowns": 0,
            "dirty_shutdowns": 4, "days": 60}})
        self.assertNotIn("power_delivery", ids(case))

    @staticmethod
    def live_kernel(hardware_faults, distinct_days, newest_days_ago):
        return {"live_kernel_events": {
            "available": True, "reports": [], "report_count": 0, "events": [],
            "event_count": hardware_faults, "codes": {"141": hardware_faults},
            "hardware_faults": hardware_faults, "driver_faults": 0,
            "unattributed": 0, "distinct_days": distinct_days,
            "hardware_days": distinct_days,
            "newest_days_ago": newest_days_ago,
            "hardware_newest_days_ago": newest_days_ago,
            "newest": "2026-08-01T10:00:00",
            "worst": {"time": "2026-08-01T10:00:00", "code": "141",
                      "title": "Graphics hardware fault", "meaning": "",
                      "blame": "hardware"},
            "days": 60}}

    def test_a_gpu_hardware_fault_is_not_treated_as_a_driver_problem(self):
        # Spread across separate days: an ongoing fault.
        case = deep_build(self.live_kernel(6, distinct_days=4, newest_days_ago=2))
        found = [h for h in case["hypotheses"] if h["id"] == "gpu_hardware_fault"]
        self.assertTrue(found)
        self.assertEqual(found[0]["severity"], "critical")
        self.assertIn("Reseat the card", found[0]["advice"])
        # It must not propose a driver rollback, which is the wasted afternoon.
        self.assertNotIn("rollback_driver",
                         [a.get("action") for a in found[0]["actions"]])

    def test_one_bad_evening_months_ago_is_not_a_dying_card(self):
        # The same events clustered on a single day, long past. A real machine
        # produced exactly this, and calling it a failing card would have sent
        # its owner shopping for a GPU that works.
        case = deep_build(self.live_kernel(3, distinct_days=1, newest_days_ago=64))
        found = [h for h in case["hypotheses"] if h["id"] == "gpu_hardware_fault"]
        self.assertTrue(found)
        self.assertEqual(found[0]["severity"], "medium")
        self.assertIn("Nothing needs opening up yet", found[0]["advice"])
        row = finding(case, "live_kernel")
        self.assertEqual(row["status"], "warn")

    def test_a_single_captured_hang_is_not_a_failing_card(self):
        # It still shows as a finding; it just does not get to be a diagnosis.
        case = deep_build(self.live_kernel(1, distinct_days=1, newest_days_ago=3))
        self.assertNotIn("gpu_hardware_fault", ids(case))
        row = finding(case, "live_kernel")
        self.assertEqual(row["status"], "warn")
        # And the count and the day span have to agree with each other.
        self.assertNotIn("across", row["value"])

    def test_repeated_reports_of_one_incident_count_once(self):
        # Windows re-files the same capture every time it works its error
        # queue, and one incident attaches several dumps. On a real machine 179
        # report rows were seven dump files.
        probe = DeepProbe()
        message = ("Fault bucket , type 0   Event Name: LiveKernelEvent   "
                   "Problem signature:   P1: 141   P2: a   "
                   "Attached files:   "
                   r"C:\WINDOWS\LiveKernelReports\WATCHDOG\WATCHDOG-20260903-1955.dmp ")
        rows = [["L", "2026-09-06T00:47:56", message] for _ in range(20)]
        rows.append(["L", "2026-09-06T00:47:56",
                     message.replace("WATCHDOG-20260903-1955", "WATCHDOG-20260904-0210")])
        probe._ps_events = lambda *a, **k: (True, rows, "")
        result = probe.live_kernel_events()
        self.assertEqual(result["report_rows"], 21)
        self.assertEqual(result["event_count"], 2)
        self.assertEqual(result["hardware_faults"], 2)
        # The incident is dated from the dump, not from when Windows filed it.
        self.assertEqual(result["distinct_days"], 2)
        self.assertTrue(any(e["time"].startswith("2026-09-03")
                            for e in result["events"]))

    def test_disabled_crash_recovery_is_offered_a_reversible_repair(self):
        case = deep_build({"gpu_hardware": dict(
            HEALTHY_HARDWARE["gpu_hardware"],
            tdr={"TdrLevel": 0}, tdr_disabled=True)})
        found = [h for h in case["hypotheses"] if h["id"] == "gpu_recovery_disabled"]
        self.assertTrue(found)
        self.assertIn("reset_tdr", [a.get("action") for a in found[0]["actions"]])
        self.assertTrue(REPAIR_ACTIONS["reset_tdr"].reversible)

    def test_a_degraded_pcie_link_is_blamed_on_something_physical(self):
        case = deep_build({"gpu_vendor_telemetry": {
            "available": True, "vendor": "nvidia", "ecc_errors": 0, "hottest_c": 60,
            "gpus": [{"name": "Test 4070", "pcie_width": 4, "pcie_width_max": 16,
                      "link_degraded": True, "ecc_uncorrected": 0,
                      "temperature_c": 60}],
            "degraded_links": [{"name": "Test 4070", "pcie_width": 4,
                                "pcie_width_max": 16, "link_degraded": True}]}})
        found = [h for h in case["hypotheses"] if h["id"] == "gpu_link_degraded"]
        self.assertTrue(found)
        advice = found[0]["advice"]
        # Every cause named has to be something physical, and the one benign
        # explanation -- a slot sharing lanes with an M.2 drive -- has to be
        # there too, or this sends people chasing a fault that is by design.
        self.assertIn("unseat", advice)
        self.assertIn("riser", advice)
        self.assertIn("M.2", advice)

    def test_a_stopped_fan_is_critical_and_offers_no_software_repair(self):
        case = deep_build({"sensor_readings": dict(
            HEALTHY_HARDWARE["sensor_readings"],
            stopped_fans=[{"name": "cpu", "rpm": 0, "status": "Error"}],
            fans=[{"name": "cpu", "rpm": 0, "status": "Error"}])})
        found = [h for h in case["hypotheses"] if h["id"] == "cooling_fault"]
        self.assertTrue(found)
        self.assertEqual(found[0]["severity"], "critical")
        self.assertEqual(found[0]["actions"], [])

    def test_repeating_stop_codes_are_read_from_the_dumps(self):
        case = deep_build({"minidump_details": {
            "available": True, "count": 5, "dumps": [{"time": "2026-08-01T00:00:00"}],
            "codes": {"0x0000001A": 5}, "distinct_codes": 1, "repeating": 5,
            "newest": "2026-08-01T00:00:00", "days": 90}})
        self.assertIn("repeating_bugcheck", ids(case))

    def test_one_module_faulting_across_programs_is_one_broken_component(self):
        case = deep_build({"wer_reports": {
            "available": True, "count": 12, "crashes": [], "modules": {"broken.dll": 9},
            "applications": {}, "types": {}, "top_module": "broken.dll",
            "top_module_count": 9, "top_module_apps": 4, "shared_fault": True,
            "days": 45}})
        self.assertIn("shared_crash_module", ids(case))

    def test_a_log_storm_needs_a_real_storm(self):
        # Ten of an error in a fortnight is a pattern worth showing in the
        # findings, but not a diagnosis worth ranking as a cause.
        modest = deep_build({"event_log_sweep": dict(
            HEALTHY_HARDWARE["event_log_sweep"],
            repeating=[{"log": "System", "provider": "Foo", "id": 7,
                        "count": 12, "level": "Error", "newest": "", "message": ""}])})
        self.assertNotIn("log_storm", ids(modest))
        storm = deep_build({"event_log_sweep": dict(
            HEALTHY_HARDWARE["event_log_sweep"],
            repeating=[{"log": "System", "provider": "Foo", "id": 7,
                        "count": 400, "level": "Error", "newest": "",
                        "message": "the device is not ready"}])})
        self.assertIn("log_storm", ids(storm))


class HonestyTests(unittest.TestCase):
    """The half that matters more: what the scan must refuse to claim."""

    def test_old_firmware_alone_is_not_a_finding(self):
        # "Your BIOS is old" on a machine that works is noise dressed as a
        # diagnosis, and a firmware update is the one job that can brick a PC.
        case = deep_build({
            "firmware_info": dict(HEALTHY_HARDWARE["firmware_info"],
                                  bios_age_years=6.0, bios_age_days=2190),
            "cpu_details": dict(HEALTHY_HARDWARE["cpu_details"],
                                microcode=200, microcode_firmware=100,
                                microcode_patched_by_os=True)})
        self.assertNotIn("firmware_stale", ids(case))

    def test_old_firmware_on_an_unstable_machine_is_a_finding(self):
        case = deep_build({
            "firmware_info": dict(HEALTHY_HARDWARE["firmware_info"],
                                  bios_age_years=6.0, bios_age_days=2190),
            "cpu_details": dict(HEALTHY_HARDWARE["cpu_details"],
                                microcode=200, microcode_firmware=100,
                                microcode_patched_by_os=True),
            "whea_errors": {"available": True, "count": 6, "uncorrected": 2,
                            "areas": {"memory": 6}, "worst_area": "memory",
                            "events": [], "newest": "2026-08-01T00:00:00"}})
        self.assertNotIn("firmware_stale", ids(case))
        self.assertIn("hardware_error", ids(case))

    def test_collectors_that_could_not_run_produce_no_coloured_findings(self):
        """A scan that was not allowed to look must not report health."""
        blank = {name: {"available": False, "reason": "gated"}
                 for name, _label in CaseEngine.HARDWARE_COLLECTORS}
        case = deep_build(blank)
        hardware_keys = {
            "firmware", "cpu_hardware", "memory_modules", "sensors", "power_loss",
            "firmware_errors", "tpm", "gpu_hardware", "live_kernel", "gpu_telemetry",
            "monitors", "smart_detail", "storage_events", "disk_geometry",
            "disk_surface", "memory_test", "kernel_pool", "log_sweep",
            "crash_reports", "crash_dumps_detail",
        }
        for row in case["findings"]:
            if row["key"] in hardware_keys:
                self.assertNotIn(row["status"], ("good", "warn", "bad"), f"{row['key']} claimed {row['status']}")

    def test_a_board_exposing_no_sensors_says_so_rather_than_passing(self):
        case = deep_build({"sensor_readings": {
            "available": False, "zones": [], "fans": [], "voltages": [],
            "throttling": [], "hottest": None, "hottest_c": None,
            "stopped_fans": [], "voltage_alarms": [], "exposes_nothing": True}})
        row = finding(case, "sensors")
        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "unsupported")
        self.assertIn("no sensors", row["detail"])

    def test_an_unelevated_read_sweep_does_not_read_as_a_clean_drive(self):
        case = deep_build({"disk_read_sweep": {
            "available": False, "elevated": False,
            "unreadable": [{"disk": 0, "reason": "Access is denied"}],
            "reason": "no physical drive could be opened for reading"}})
        row = finding(case, "disk_surface")
        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "permission_denied")
        self.assertIn("denied", row["detail"])

    def test_a_clean_scan_does_not_promise_the_hardware_is_good(self):
        case = deep_build()
        self.assertNotIn("drive_failing_smart", ids(case))
        # A sampled, user-space scan cannot rule out a load-dependent fault, and
        # saying otherwise is how someone ignores a real one.
        self.assertIn("under", case["summary"])
        self.assertIn("load", case["summary"])

    def test_mixed_memory_is_reported_but_never_flagged(self):
        case = deep_build({"memory_modules": dict(
            HEALTHY_HARDWARE["memory_modules"],
            mixed_parts=True, mixed_vendors=True, underclocked=True)})
        row = finding(case, "memory_modules")
        self.assertEqual(row["status"], "info")


class WiringTests(unittest.TestCase):
    """That the new tier is actually reachable, and re-measurable."""

    def test_every_hardware_collector_exists_on_the_probe(self):
        for name, label in CaseEngine.HARDWARE_COLLECTORS:
            self.assertTrue(callable(getattr(DeepProbe, name, None)), name)
            self.assertTrue(label, name)

    def test_hardware_collectors_are_not_duplicated_in_the_other_tiers(self):
        # A collector in two tiers would run twice per scan.
        deep = {name for name, _ in CaseEngine.HARDWARE_COLLECTORS}
        other = {name for name, _ in
                 CaseEngine.FAST_COLLECTORS + CaseEngine.DEEP_COLLECTORS}
        self.assertEqual(deep & other, set())

    def test_every_hardware_finding_can_be_re_measured(self):
        # Without a FINDING_SOURCES entry a "verify" after a repair silently
        # measures nothing at all.
        case = deep_build()
        collectors = {name for name, _ in CaseEngine.HARDWARE_COLLECTORS}
        for row in case["findings"]:
            self.assertIn(row["key"], FINDING_SOURCES, row["label"])
        mapped = set()
        for sources in FINDING_SOURCES.values():
            mapped.update(sources)
        self.assertEqual(collectors - mapped, set(),
                         "hardware collectors no finding maps back to")

    def test_remeasure_can_reach_the_hardware_collectors(self):
        engine = CaseEngine(probe=ScriptedProbe(dict(HEALTHY, **HEALTHY_HARDWARE)))
        raw = engine.remeasure(["smart_detail", "memory_pattern"])
        self.assertIn("smart_attributes", raw)
        self.assertIn("memory_pattern_test", raw)

    def test_the_windows_memory_diagnostic_keeps_its_own_finding_key(self):
        # These are two different measurements with two different answers, and
        # reusing one key silently repointed the Windows Memory Diagnostic's
        # re-check at the live pattern test instead.
        self.assertEqual(FINDING_SOURCES["memory_test"], ("memory_diagnostic",))
        self.assertEqual(FINDING_SOURCES["memory_pattern"], ("memory_pattern_test",))

    def test_no_two_findings_share_a_key(self):
        case = deep_build()
        keys = [row["key"] for row in case["findings"]]
        duplicated = sorted({k for k in keys if keys.count(k) > 1})
        self.assertEqual(duplicated, [], f"duplicate finding keys: {duplicated}")

    def test_a_hardware_scan_opens_every_rule_area(self):
        engine = CaseEngine(probe=ScriptedProbe(dict(HEALTHY, **HEALTHY_HARDWARE)))
        case = engine.hardware_scan()
        self.assertEqual(case["profile"], HARDWARE_PROFILE)
        self.assertNotEqual(HARDWARE_PROFILE, AUDIT_PROFILE)

    def test_an_ordinary_sweep_does_not_run_the_hardware_tier(self):
        # The deep tier costs minutes, so it must never be pulled into the
        # paths that promise seconds.
        probe = ScriptedProbe(dict(HEALTHY, **HEALTHY_HARDWARE))
        CaseEngine(probe=probe).build_case("my pc is slow", answers={})
        for name, _label in CaseEngine.HARDWARE_COLLECTORS:
            self.assertNotIn(name, probe.calls, name)

    def test_hardware_repairs_verify_against_real_finding_keys(self):
        for action_id in ("reset_tdr", "set_gpu_scheduling", "clear_shader_cache",
                          "schedule_memory_test", "disable_pcie_power_saving"):
            action = REPAIR_ACTIONS[action_id]
            self.assertTrue(action.verify_keys, action_id)
            for key in action.verify_keys:
                self.assertIn(key, FINDING_SOURCES, f"{action_id} -> {key}")

    def test_reference_tables_are_internally_consistent(self):
        for code, entry in LIVE_KERNEL_EVENTS.items():
            self.assertEqual(len(entry), 3, code)
            self.assertIn(entry[2], ("driver", "hardware"), code)
        for event_id, entry in STORAGE_EVENTS.items():
            self.assertEqual(len(entry), 3, event_id)
            self.assertIn(entry[2], ("drive", "link"), event_id)
        for attribute_id, (name, critical) in SMART_ATTRIBUTES.items():
            self.assertTrue(name, attribute_id)
            self.assertIsInstance(critical, bool)


if __name__ == "__main__":
    unittest.main()
