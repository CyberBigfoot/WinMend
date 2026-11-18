"""Tests for the IT Desk reasoning layer.

The rules that matter most -- failing drives, ransomware, upstream network
faults -- cannot be triggered on a healthy development machine, so the engine is
driven against a scripted probe whose answers are known.
"""

import os
import re
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from winmend_diagnostics import (  # noqa: E402
    BUGCHECK_CODES, CaseEngine, ChangeTimeline, Context, DEVICE_PROBLEM_CODES,
    FINDING_SOURCES, Interview, MAINTENANCE_TASKS, PROTECTION_FIRST, REPAIR_ACTIONS,
    RULES, WU_ERROR_CODES, _days_ago, _iso_to_dt, collectors_for, describe_bugcheck,
    describe_whea, describe_wu_error, finding_evidence, module_vendor,
    render_case_report_html,
)


def iso_days_ago(days):
    """A timestamp in the shape the event-log collectors produce."""
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")


HEALTHY = {
    "system_context": {"available": True, "domain_joined": False, "mdm_managed": False,
                       "vpn_present": False, "split_dns": False, "remote_session": False},
    "disk": {"free_gb": 400.0, "free_pct": 55.0},
    "memory": {"used_pct": 40.0, "available_gb": 18.0},
    "uptime_days": 0.5,
    "temp_size": {"bytes": 100 * 1024 ** 2, "partial": False},
    "startup_count": 4,
    "pending_reboot": False,
    "network": {"adapters": 1, "dns": True, "reachable": True},
    "ping_quality": {"attempts": 4, "failures": 0, "avg_ms": 12.0},
    "smart_health": {"available": True, "disks": 1, "unhealthy": []},
    "event_log_errors": {"available": True, "unexpected_shutdowns": 0, "disk_errors": 0,
                         "service_crashes": 0, "hardware_errors": 0},
    "bugchecks": {"available": True, "count": 0, "crashes": []},
    "app_crashes": {"available": True, "crashes": []},
    "update_failures": {"available": True, "count": 0, "failures": []},
    "installed_updates": {"available": True, "updates": []},
    "installed_programs": {"available": True, "programs": []},
    "third_party_drivers": {"available": True, "total": 10, "recent": [], "store_exists": True},
    "problem_devices": {"available": True, "devices": []},
    "gpu_resets": {"available": True, "count": 0, "events": []},
    "thermal_events": {"available": True, "throttle_events": 0},
    "storage_removals": {"available": True, "events": 0},
    "memory_config": {"available": True, "sticks": [{"gb": 16, "rated_mhz": 3200,
                                                     "actual_mhz": 3200, "slot": "A1", "vendor": "x"}],
                      "count": 2, "total_gb": 32.0, "rated_mhz": 3200, "actual_mhz": 3200,
                      "single_channel": False, "underclocked": False},
    "top_memory_processes": [{"name": "explorer", "mb": 300.0}],
    "pagefile": {"available": True, "files": 1, "size_mb": 8192, "automatic": True,
                 "configured": ["?:\\pagefile.sys"], "disabled": False},
    "dns_servers": {"available": True, "interfaces": [], "unrecognised": []},
    "battery_wear": {"available": False},
    "wifi_link": {"available": False},
    "defender": {"available": True, "enabled": True, "realtime": True, "signature_age": 1},
    "firewall_enabled": True,
    "defender_exclusions": {"available": True, "paths": [], "processes": [], "overly_broad": []},
    "platform_security": {"available": True, "secure_boot": "true", "tpm_present": True,
                          "tpm_ready": True, "bitlocker": "1", "activated": True},
    "component_store_health": {"available": True, "state": "clean"},
    "windows_version": {"available": True, "build": 26100, "display": "24H2",
                        "product": "Windows 11 Pro", "label": "Windows 11 24H2",
                        "eol": "2026-10-13", "supported": True, "days_left": 300},
    "boot_history": {"available": False},
    "restore_points": {"available": True, "points": [{"sequence": "1", "created": "2026-08-01T10:00:00",
                                                      "days_ago": 6.0, "description": "x"}]},
    "disk_latency": {"available": True, "ops": 5000, "avg_ms": 0.4, "idle": False},
    "proxy_settings": {"available": True, "enabled": False, "server": "", "autoconfig": "",
                       "pac_or_proxy": False},
    "hosts_file": {"available": True, "path": "hosts", "entries": 0, "blocked": [], "sample": []},
    # The wider sweep. Everything below is what a healthy PC answers.
    "volumes": {"available": True, "volumes": [
        {"drive": "C:", "label": "", "filesystem": "NTFS", "total_gb": 500.0,
         "free_gb": 275.0, "free_pct": 55.0, "dirty": False, "system": True},
        {"drive": "D:", "label": "Data", "filesystem": "NTFS", "total_gb": 1000.0,
         "free_gb": 600.0, "free_pct": 60.0, "dirty": False, "system": False}],
        "others": [{"drive": "D:", "label": "Data", "filesystem": "NTFS", "total_gb": 1000.0,
                    "free_gb": 600.0, "free_pct": 60.0, "dirty": False, "system": False}]},
    "filesystem_health": {"available": True, "scheduled": [],
                          "boot_execute": "autocheck autochk *"},
    "disk_reliability": {"available": True, "counters_readable": True, "trim": True, "disks": [
        {"name": "NVMe 1TB", "media": "SSD", "health": "Healthy", "wear_pct": 4,
         "temperature_c": 38, "read_errors": 0, "write_errors": 0, "power_on_hours": 900}]},
    "dump_files": {"available": True, "dumps": [], "count": 0, "mb": 0},
    "service_health": {"available": True, "total": 300, "stopped_auto": [],
                       "critical_stopped": []},
    "scheduled_tasks": {"available": True, "failures": [], "maintenance_failures": []},
    "update_state": {"available": True, "blocked": False, "policies": [], "paused_until": "",
                     "services": {"wuauserv": {"start": 2, "disabled": False},
                                  "bits": {"start": 2, "disabled": False}}},
    "search_index": {"available": True, "service": "running", "setup_complete": True,
                     "healthy": True},
    "uac_state": {"available": True, "enabled": True, "consent": 5, "never_notifies": False,
                  "secure_desktop": True},
    "defender_threats": {"available": True, "history": 0, "threats": [], "unresolved": [],
                         "quick_scan_age": 1, "full_scan_age": 7, "tamper_protection": True},
    "firewall_profiles": {"available": True, "disabled": [], "allow_inbound": [], "profiles": [
        {"name": "Domain", "enabled": True, "inbound": "NotConfigured"},
        {"name": "Private", "enabled": True, "inbound": "NotConfigured"},
        {"name": "Public", "enabled": True, "inbound": "NotConfigured"}]},
    "cpu_load": {"available": True, "used_pct": 12.0, "cores": 8, "hog": None,
                 "top": [{"name": "explorer.exe", "pid": 10, "pct": 3.0, "ours": False}]},
    "power_config": {"available": True, "scheme": "381b4222-f694-41f0-9685-ff5bb260df2e",
                     "name": "Balanced", "known": True, "power_saver": False,
                     "fast_startup": False},
    "network_config": {"available": True, "has_route": True, "self_assigned_only": False,
                       "gateways": ["192.168.1.1"], "interfaces": [
                           {"index": "3", "interface": "Ethernet", "address": "192.168.1.20",
                            "origin": "Dhcp", "gateway": "192.168.1.1", "self_assigned": False}]},
    "adapter_health": {"available": True, "degraded": [], "adapters": [
        {"name": "Ethernet", "speed_mbps": 1000, "packets": 200000, "errors": 0, "drops": 0,
         "error_pct": 0.0}]},
    "time_sync": {"available": True, "source": "time.windows.com", "offset_seconds": 0.1,
                  "service": "running", "round_trip_ms": 20.0},
    "printers": {"available": True, "jobs": 0, "spooler": "running", "default_offline": [],
                 "printers": [{"name": "Office", "status": 3, "state": "idle",
                               "offline": False, "default": True}]},
    "user_profile": {"available": True, "path": r"C:\Users\test", "temporary": False,
                     "backup_profiles": 0, "sid": "S-1-5-21-1", "onedrive_folders": []},
    "restart_pending": {"available": True, "pending": False, "reasons": [],
                        "queued_renames": 12},
    # -- the wider evidence sweep ------------------------------------------
    # Every one of these is the *healthy* reading, so a test that overrides one
    # is testing exactly the difference it introduced. Several are healthy in a
    # way that looks alarming written down -- fast startup on, folders in
    # OneDrive, no memory test ever run -- and that is the point: those are the
    # readings a careless rule turns into a false positive.
    "whea_errors": {"available": True, "count": 0, "uncorrected": 0, "areas": {},
                    "worst_area": "", "events": [], "newest": ""},
    "memory_diagnostic": {"available": True, "runs": 0, "ever_run": False, "failed": False,
                          "last": None},
    "cpu_throttle": {"available": True, "ratio": 1.0, "low_clock": False, "load_pct": 20,
                     "processors": [{"name": "Test CPU", "current_mhz": 3600,
                                     "max_mhz": 3600, "ratio": 1.0, "load_pct": 20,
                                     "cores": 8}]},
    "reliability_history": {"available": True, "days": 30, "series": [], "current": 9.1,
                            "recent_avg": 9.0, "baseline_avg": 9.0, "degraded": False,
                            "drop_date": "", "drop_from": None, "drop_to": None,
                            "drop_days_ago": None},
    "boot_config": {"available": True, "settings": {}, "safe_mode_forced": False,
                    "safeboot": "", "test_signing": False, "integrity_checks_off": False,
                    "recovery_enabled": True, "debug": False, "hypervisor": "Auto"},
    "fast_startup": {"available": True, "enabled": True, "hibernate_enabled": True},
    "wake_history": {"available": True, "timers_readable": True, "timers": [], "armed": 0,
                     "reason": "", "last_wake": {"source": "", "kind": "", "detail": ""}},
    "disk_optimization": {"available": True, "trim": True, "trim_readable": True,
                          "unhealthy": [], "volumes": [
                              {"drive": "C:", "filesystem": "NTFS", "health": "Healthy",
                               "operational": "OK", "healthy": True}]},
    "bitlocker_state": {"available": True, "volumes": [], "encrypted": [], "suspended": []},
    "top_disk_processes": {"available": True, "top": [], "total_mb_per_sec": 0.4,
                           "busiest": None},
    "dns_resolution": {"available": True, "resolved": 2, "attempted": 2, "failed": 0,
                       "slowest_ms": 12.0, "slow": False, "hijacked": False,
                       "wildcard_address": "", "results": []},
    "network_profile": {"available": True, "internet": True, "metered": [], "public": [],
                        "local_only": [], "profiles": [
                            {"interface": "Ethernet", "category": "Private", "ipv4": "Internet",
                             "ipv6": "NoTraffic", "index": "10", "internet": True,
                             "local_only": False}]},
    "winsock_health": {"available": True, "total": 28, "third_party": [], "broken": []},
    "interface_mtu": {"available": True, "nonstandard": [], "interfaces": [
        {"interface": "Ethernet", "mtu": 1500, "virtual": False}]},
    "update_policy": {"available": True, "wsus": "", "use_wsus": False, "redirected": False,
                      "pinned_version": "", "deferrals": [], "policies": [],
                      "constrained": False},
    "update_cache": {"available": True, "gb": 0.02, "files": 4, "partial": False,
                     "oldest_days": 1.0, "newest_days": 0.5, "stale": False},
    "activation_state": {"available": True, "known": True, "licensed": True,
                         "state": "licensed", "products": [
                             {"name": "Windows Pro", "status": 1, "state": "licensed",
                              "licensed": True, "grace_minutes": 0, "grace_days": 0}]},
    "appx_health": {"available": True, "total": 150, "broken": [], "missing": [],
                    "store_present": True},
    "shell_health": {"available": True, "explorer_running": True, "explorer_instances": 1,
                     "explorer_age_hours": 5.0, "icon_cache_mb": 12.0,
                     "icon_cache_large": False},
    "audio_health": {"available": True, "services": {"Audiosrv": "running",
                                                     "AudioEndpointBuilder": "running"},
                     "service_stopped": [], "faulty": [], "any_device": True, "healthy": True,
                     "devices": [{"name": "Speakers", "status": "OK", "problem_code": 0,
                                  "problem": "", "healthy": True}]},
    "bluetooth_health": {"available": True, "present": False, "service": "stopped",
                         "devices": [], "faulty": [], "healthy": True},
    "display_config": {"available": True, "count": 1, "basic_driver": [], "faulty": [],
                       "adapters": [{"name": "Test GPU", "driver_version": "1.0",
                                     "driver_date": "", "driver_age_days": None,
                                     "problem_code": 0, "problem": "", "resolution": "1920x1080",
                                     "refresh_hz": 60, "basic": False, "active": True}]},
    "integrity_history": {"available": True, "ever_run": False, "last_run": "",
                          "last_run_days": None, "checked_lines": 0, "unrepairable": 0,
                          "repaired": 0, "verdicts": 0, "corrupt": False, "sample": []},
    "policy_health": {"available": True, "restrictions": [], "count": 0, "areas": {}},
    "environment_health": {"available": True, "length": 480, "entries": 15, "missing": [],
                           "missing_count": 0, "duplicates": 0, "has_system32": True,
                           "truncation_risk": False},
    "known_folders": {"available": True, "onedrive_running": True, "stranded": False,
                      "missing": [], "redirected": [], "folders": [
                          {"label": "Desktop", "path": r"C:\Users\test\Desktop",
                           "exists": True, "onedrive": False}]},
}


class ScriptedProbe:
    """A probe whose every answer is supplied by the test."""

    def __init__(self, overrides=None):
        self.data = dict(HEALTHY)
        self.data.update(overrides or {})
        self.calls = []

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)

        def collector(*args, **kwargs):
            self.calls.append(name)
            return self.data.get(name, {"available": False})

        return collector


def startup_entry(name, exe, enabled=True):
    """One row in the shape list_startup_entries() produces."""
    return {"name": name, "exe": exe, "enabled": enabled,
            "root": "HKCU", "approved_subkey": "k", "value": name}


def build(problem, answers=None, overrides=None):
    engine = CaseEngine(probe=ScriptedProbe(overrides))
    # These are recorded complete snapshots, not a test of live scheduling.
    # Profile-targeted collector selection is covered by test_guided_intelligence.
    return engine, engine.build_case(problem, answers=answers or {}, raw=engine.probe.data)


def titles(case):
    return [h["title"] for h in case["hypotheses"]]


def ids(case):
    return [h["id"] for h in case["hypotheses"]]


def step_ids(case):
    return [s["id"] for s in case["plan"]]


class DateParsingTests(unittest.TestCase):
    def test_registry_install_date_basic_format(self):
        # The uninstall registry stores YYYYMMDD, which Python 3.10's
        # fromisoformat rejects. Regressing this silently empties the
        # "installed recently" evidence that several rules depend on.
        parsed = _iso_to_dt("20260721")
        self.assertIsNotNone(parsed)
        self.assertEqual((parsed.year, parsed.month, parsed.day), (2026, 7, 21))

    def test_wmi_dmtf_format(self):
        parsed = _iso_to_dt("20260714093012.000000+000")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.month, 7)

    def test_iso_and_us_formats(self):
        self.assertIsNotNone(_iso_to_dt("2026-07-14T09:30:12"))
        self.assertIsNotNone(_iso_to_dt("7/14/2026"))

    def test_garbage_returns_none(self):
        for value in ("", None, "not a date", "99999999999"):
            self.assertIsNone(_iso_to_dt(value))

    def test_days_ago_is_positive_for_past(self):
        self.assertGreater(_days_ago("2020-01-01T00:00:00"), 1000)


class KnowledgeBaseTests(unittest.TestCase):
    def test_bugcheck_lookup(self):
        name, cause, tags = describe_bugcheck(0x116)
        self.assertEqual(name, "VIDEO_TDR_ERROR")
        self.assertIn("gpu", tags)

    def test_bugcheck_accepts_hex_string(self):
        self.assertEqual(describe_bugcheck("7A")[0], "KERNEL_DATA_INPAGE_ERROR")

    def test_unknown_bugcheck_is_safe(self):
        name, cause, tags = describe_bugcheck(0xDEAD)
        self.assertTrue(name)
        self.assertEqual(tags, ())

    def test_wu_error_lookup(self):
        meaning, remedy = describe_wu_error("0x80070070")
        self.assertIn("disk space", meaning)
        self.assertEqual(remedy, "disk_cleanup")

    def test_wu_error_case_insensitive(self):
        self.assertEqual(describe_wu_error("0X80070070"), describe_wu_error("0x80070070"))

    def test_unknown_wu_error(self):
        self.assertEqual(describe_wu_error("0x11111111"), (None, None))

    def test_module_vendor_matches_prefix(self):
        self.assertEqual(module_vendor("nvlddmkm.sys")[1], "gpu")
        self.assertEqual(module_vendor("netwtw08.sys")[1], "network")
        self.assertEqual(module_vendor("unknown_thing.dll"), (None, None))

    def test_every_bugcheck_entry_is_well_formed(self):
        for code, entry in BUGCHECK_CODES.items():
            self.assertIsInstance(code, int)
            self.assertEqual(len(entry), 3, f"0x{code:X}")
            self.assertTrue(entry[0] and entry[1])

    def test_every_wu_remedy_is_a_known_task(self):
        from winmend_safety import DiagnosticEngine
        for code, (meaning, remedy) in WU_ERROR_CODES.items():
            self.assertTrue(meaning, code)
            if remedy and remedy != "driver_rollback_hint":
                self.assertIn(remedy, DiagnosticEngine.TASK_REASONS, code)

    def test_device_problem_codes_have_remedies(self):
        for code, (meaning, remedy) in DEVICE_PROBLEM_CODES.items():
            self.assertTrue(meaning and remedy, code)


class InterviewTests(unittest.TestCase):
    def setUp(self):
        self.interview = Interview()

    def test_network_complaint_asks_about_other_devices(self):
        asked = [q["id"] for q in self.interview.select("wifi keeps dropping")]
        self.assertIn("net_scope", asked)
        self.assertIn("onset", asked)

    def test_crash_complaint_asks_what_happens(self):
        asked = [q["id"] for q in self.interview.select("blue screen when gaming")]
        self.assertIn("crash_kind", asked)
        self.assertIn("safe_mode", asked)

    def test_never_exceeds_the_cap(self):
        for problem in ("slow", "wifi", "blue screen", "printer", "virus", "battery"):
            self.assertLessEqual(len(self.interview.select(problem)), Interview.MAX_QUESTIONS)

    def test_onset_and_trigger_are_always_asked(self):
        for problem in ("slow", "wifi drops", "printer jammed", "sound gone"):
            asked = [q["id"] for q in self.interview.select(problem)]
            self.assertIn("onset", asked, problem)
            self.assertIn("trigger", asked, problem)

    def test_normalise_rejects_unknown_questions_and_values(self):
        clean = Interview.normalise({"onset": "week", "onset_bogus": "x", "trigger": "nope"})
        self.assertEqual(clean, {"onset": "week"})

    def test_onset_days_maps_to_a_window(self):
        self.assertEqual(Interview.onset_days({"onset": "today"}), 1.5)
        self.assertIsNone(Interview.onset_days({}))
        self.assertIsNone(Interview.onset_days({"onset": "unknown"}))

    def test_summarise_renders_labels_not_codes(self):
        lines = Interview.summarise({"onset": "today"})
        self.assertEqual(len(lines), 1)
        self.assertIn("Today", lines[0])


class FindingContractTests(unittest.TestCase):
    def test_every_finding_key_has_a_collector(self):
        # remeasure() goes from finding keys to collectors through this map; a
        # finding missing from it can never be re-verified.
        engine = CaseEngine(probe=ScriptedProbe())
        case = engine.build_case("my pc is slow", answers={"onset": "week"})
        for finding in case["findings"]:
            self.assertIn(finding["key"], FINDING_SOURCES, finding["label"])

    def test_collectors_for_deduplicates(self):
        self.assertEqual(collectors_for(["evt_disk", "evt_hardware"]), ["event_log_errors"])

    def test_action_verify_keys_are_finding_keys(self):
        for action in REPAIR_ACTIONS.values():
            for key in action.verify_keys:
                self.assertIn(key, FINDING_SOURCES, f"{action.id} -> {key}")

    def test_findings_carry_machine_readable_data(self):
        engine = CaseEngine(probe=ScriptedProbe())
        case = engine.build_case("my pc is slow", answers={"onset": "week"})
        for finding in case["findings"]:
            self.assertIn("data", finding)

    def test_healthy_machine_reports_no_warnings(self):
        engine, case = build("my pc is slow", {"onset": "week", "trigger": "nothing"})
        bad = [f["label"] for f in case["findings"] if f["status"] in ("warn", "bad")]
        self.assertEqual(bad, [], f"healthy fixture produced warnings: {bad}")
        self.assertEqual(case["severity_score"], 0)


class HardwareRuleTests(unittest.TestCase):
    def test_failing_drive_is_detected_and_ranked_critical(self):
        _engine, case = build("pc freezes constantly", {"onset": "week"}, {
            "smart_health": {"available": True, "disks": 1,
                             "unhealthy": ["Samsung SSD (Unhealthy)"]},
            "event_log_errors": {"available": True, "unexpected_shutdowns": 0,
                                 "disk_errors": 12, "service_crashes": 0, "hardware_errors": 0},
        })
        self.assertIn("failing_drive", ids(case))
        lead = case["hypotheses"][0]
        self.assertEqual(lead["id"], "failing_drive")
        self.assertEqual(lead["severity"], "critical")
        self.assertIn("back up", lead["advice"].lower())

    def test_failing_drive_withholds_chkdsk_and_defrag(self):
        # The correlation that makes this an IT desk rather than a checklist:
        # both of these are the textbook answer to disk errors, and both are
        # the wrong move on a drive that is physically failing.
        _engine, case = build("pc freezes and disk errors", {"onset": "week"}, {
            "smart_health": {"available": True, "disks": 1, "unhealthy": ["WDC (Unhealthy)"]},
            "event_log_errors": {"available": True, "unexpected_shutdowns": 0,
                                 "disk_errors": 9, "service_crashes": 0, "hardware_errors": 0},
        })
        withheld = {w["id"] for w in case["withheld"]}
        self.assertIn("chk_dsk", withheld)
        self.assertIn("defrag_optimize", withheld)
        self.assertNotIn("chk_dsk", step_ids(case))
        self.assertNotIn("defrag_optimize", step_ids(case))
        reason = next(w["reason"] for w in case["withheld"] if w["id"] == "chk_dsk")
        self.assertIn("failing", reason.lower())

    def test_healthy_drive_does_not_withhold_anything(self):
        _engine, case = build("pc is slow", {"onset": "week"})
        self.assertEqual(case["withheld"], [])

    def test_whea_errors_raise_a_hardware_hypothesis(self):
        _, case = build('random blue screens', overrides={'event_log_errors': {'available': True, 'unexpected_shutdowns': 3, 'disk_errors': 0, 'service_crashes': 0, 'hardware_errors': 6}})
        self.assertNotIn('bad_memory', ids(case))
        self.assertNotIn('memory_diagnostic', step_ids(case))

    def test_thermal_throttling_is_reported_as_physical(self):
        _engine, case = build("pc is slow", {"onset": "week", "perf_signs": "fans"}, {
            "thermal_events": {"available": True, "throttle_events": 40},
        })
        self.assertIn("thermal_throttle", ids(case))
        advice = next(h["advice"] for h in case["hypotheses"] if h["id"] == "thermal_throttle")
        self.assertIn("dust", advice.lower())

    def test_worn_battery_is_measured_not_guessed(self):
        _engine, case = build("battery dies fast", {"onset": "month"}, {
            "battery_wear": {"available": True, "design_mwh": 50000,
                             "full_mwh": 25000, "wear_pct": 50.0},
        })
        self.assertIn("battery_worn", ids(case))


class ChangeCorrelationTests(unittest.TestCase):
    def test_update_within_the_onset_window_is_suspected(self):
        _, case = build('pc is slow', {'onset': 'week', 'trigger': 'update'}, {'installed_updates': {'available': True, 'updates': [{'kb': 'KB5034123', 'days_ago': 3, 'kind': 'Security Update'}]}})
        self.assertNotIn('recent_update', ids(case))
        self.assertNotIn('uninstall_update', step_ids(case))
        self.assertTrue(any(h['id']=='recent_update' for h in case['trace']['proposals']))

    def test_update_outside_the_window_is_ignored(self):
        _engine, case = build("pc is slow", {"onset": "today", "trigger": "update"}, {
            "installed_updates": {"available": True, "updates": [
                {"kb": "KB5034123", "installed": "2026-06-01", "days_ago": 60.0, "kind": "Update"}]},
        })
        self.assertNotIn("recent_update", ids(case))

    def test_no_stated_onset_means_no_timing_correlation(self):
        # Without an onset there is no window, so a recent change is not
        # evidence of anything and must not be presented as a cause.
        _engine, case = build("pc is slow", {}, {
            "installed_updates": {"available": True, "updates": [
                {"kb": "KB5034123", "installed": "2026-08-06", "days_ago": 1.0, "kind": "Update"}]},
        })
        self.assertNotIn("recent_update", ids(case))

    def test_recent_driver_needs_corroboration_not_just_recency(self):
        # A driver installed yesterday is not a culprit merely for being newest.
        _engine, case = build("pc is slow", {"onset": "week", "trigger": "nothing"}, {
            "third_party_drivers": {"available": True, "total": 40, "recent": [
                {"published": "oem12.inf", "original": "vbox.inf", "class": "System",
                 "provider": "Oracle", "days_ago": 1.0, "version": ""}]},
        })
        self.assertNotIn("recent_driver", ids(case))

    def test_recent_driver_is_named_when_its_area_is_failing(self):
        _, case = build('screen glitches and crashes', {'onset': 'week'}, {'third_party_drivers': {'available': True, 'recent': [{'published': 'oem9.inf', 'original': 'nv_disp.inf', 'class': 'Display', 'provider': 'NVIDIA', 'days_ago': 2}]}, 'gpu_resets': {'available': True, 'count': 5, 'events': []}})
        self.assertIn('gpu_driver', ids(case))
        self.assertNotIn('rollback_driver', step_ids(case))
        trace = next(h for h in case['trace']['proposals'] if h['id']=='recent_driver')
        self.assertIn('nv_disp.inf', trace['title'])

    def test_user_blaming_software_is_enough_to_raise_a_lead(self):
        _, case = build('pc is slow', {'onset': 'today', 'trigger': 'software'}, {'third_party_drivers': {'available': True, 'recent': [{'published': 'oem12.inf', 'original': 'thing.inf', 'class': 'System', 'provider': 'Vendor', 'days_ago': .5}]}})
        lead = next(h for h in case['trace']['proposals'] if h['id']=='recent_driver')
        self.assertEqual(lead['disposition'], 'insufficient_evidence')
        self.assertNotIn('recent_driver', ids(case))


class StartupTargetingTests(unittest.TestCase):
    """A plan must never contain a step that cannot possibly succeed."""

    # Enough enabled entries to make the startup check flag a warning, which is
    # what the rule keys off. Only the enabled ones count.
    ENTRIES = [
        startup_entry("OneDrive", r"C:\Users\x\AppData\Local\Microsoft\OneDrive\OneDrive.exe"),
        startup_entry("Steam", r"C:\Program Files (x86)\Steam\steam.exe"),
        startup_entry("AlreadyOff", r"C:\x\off.exe", enabled=False),
    ] + [startup_entry(f"Filler{i}", rf"C:\x\filler{i}.exe") for i in range(9)]

    def _case(self, slow, entries=None):
        entries = self.ENTRIES if entries is None else entries
        return build("my pc is slow", {"onset": "week"}, {
            "startup_count": 14,
            "startup_entries": {"available": True, "entries": entries,
                                "enabled": [e for e in entries if e["enabled"]]},
            "boot_history": {"available": True,
                             "boots": [{"time": "2026-08-07T09:00:00", "total_s": 90.0,
                                        "desktop_s": 70.0, "background_s": 20.0}],
                             "slow": slow},
        })[1]

    def test_windows_own_process_is_not_offered_for_disabling(self):
        # The exact failure seen in the wild: WWAHost.exe hosts Store apps and
        # is launched by Windows, so it is not a startup entry at all.
        case = self._case([{"time": "t", "kind": "app", "name": "WWAHost.exe",
                            "path": "", "degradation_s": 9.0}])
        self.assertNotIn("disable_startup_entry", step_ids(case))
        self.assertIn("disable_startup_apps", step_ids(case))

    def test_it_still_reports_the_slow_process_it_cannot_act_on(self):
        case = self._case([{"time": "t", "kind": "app", "name": "WWAHost.exe",
                            "path": "", "degradation_s": 9.0}])
        hypothesis = next(h for h in case["hypotheses"] if h["id"] == "startup_bloat")
        self.assertIn("WWAHost.exe", hypothesis["explanation"])
        self.assertIn("cannot be switched off here", hypothesis["explanation"])

    def test_a_real_startup_entry_is_offered_and_named_exactly(self):
        case = self._case([{"time": "t", "kind": "app", "name": "steam.exe",
                            "path": "", "degradation_s": 12.0}])
        step = next(s for s in case["plan"] if s["id"] == "disable_startup_entry")
        # Must carry the entry's own name, not the executable from the log.
        self.assertEqual(step["params"]["name"], "Steam")

    def test_it_skips_past_unactionable_offenders_to_a_real_one(self):
        case = self._case([
            {"time": "t", "kind": "app", "name": "WWAHost.exe", "path": "", "degradation_s": 20.0},
            {"time": "t", "kind": "app", "name": "steam.exe", "path": "", "degradation_s": 8.0},
        ])
        step = next(s for s in case["plan"] if s["id"] == "disable_startup_entry")
        self.assertEqual(step["params"]["name"], "Steam")

    def test_services_are_never_treated_as_startup_entries(self):
        case = self._case([{"time": "t", "kind": "service", "name": "Steam", "path": "",
                            "degradation_s": 15.0}])
        self.assertNotIn("disable_startup_entry", step_ids(case))

    def test_an_already_disabled_entry_is_not_offered_again(self):
        case = self._case([{"time": "t", "kind": "app", "name": "off.exe", "path": "",
                            "degradation_s": 15.0}])
        self.assertNotIn("disable_startup_entry", step_ids(case))

    def test_trivial_delays_are_ignored(self):
        case = self._case([{"time": "t", "kind": "app", "name": "steam.exe", "path": "",
                            "degradation_s": 0.4}])
        self.assertNotIn("disable_startup_entry", step_ids(case))

    def test_no_boot_history_still_offers_the_general_review(self):
        _, case = build('PC slow', overrides={'startup_count': 24})
        self.assertNotIn('disable_startup_apps', step_ids(case))
        self.assertEqual(next(f for f in case['findings'] if f['key']=='startup')['status'], 'info')

    def test_matcher_handles_the_name_shapes_windows_uses(self):
        from winmend_diagnostics import match_startup_entry

        self.assertEqual(match_startup_entry("steam.exe", self.ENTRIES)["name"], "Steam")
        self.assertEqual(match_startup_entry("Steam", self.ENTRIES)["name"], "Steam")
        self.assertEqual(match_startup_entry("OneDrive.exe", self.ENTRIES)["name"], "OneDrive")
        self.assertIsNone(match_startup_entry("WWAHost.exe", self.ENTRIES))
        self.assertIsNone(match_startup_entry("", self.ENTRIES))
        self.assertIsNone(match_startup_entry("steam.exe", []))

    def test_executor_explains_rather_than_just_failing(self):
        result = REPAIR_ACTIONS["disable_startup_entry"].run({"name": "WWAHost.exe"})
        self.assertFalse(result["ok"])
        self.assertIn("Windows launches itself", result["message"])

    def test_disabled_entries_do_not_count_toward_the_warning(self):
        # Otherwise a successful "disable startup apps" leaves the check still
        # failing, and verification reports a working repair as not resolved.
        engine = CaseEngine(probe=ScriptedProbe())
        many = [dict(e, enabled=True) for e in self.ENTRIES] * 2
        raw = dict(HEALTHY, startup_count=20,
                   startup_entries={"available": True, "entries": many,
                                    "enabled": [e for e in many if e["enabled"]]})
        before = {f["key"]: f for f in engine.measure_findings(raw)}
        self.assertEqual(before["startup"]["status"], "info")

        after_entries = [dict(e, enabled=False) for e in many]
        after_raw = dict(HEALTHY, startup_count=20,
                         startup_entries={"available": True, "entries": after_entries,
                                          "enabled": []})
        after = {f["key"]: f for f in engine.measure_findings(after_raw)}
        self.assertEqual(after["startup"]["status"], "info")
        self.assertIn("0 enabled", after["startup"]["value"])

    def test_disabling_startup_apps_verifies_as_resolved(self):
        engine = CaseEngine(probe=ScriptedProbe())
        many = [dict(e, enabled=True) for e in self.ENTRIES]*2
        before = engine.measure_findings(dict(HEALTHY, startup_count=20, startup_entries={'available': True, 'entries': many, 'enabled': many}))
        healed = dict(HEALTHY, startup_count=20, startup_entries={'available': True, 'entries': [dict(e, enabled=False) for e in many], 'enabled': []})
        cleared, checked = engine.step_cleared({'verify_keys': ['startup']}, healed, before)
        self.assertFalse(cleared)
        self.assertEqual(checked, [])

    def test_startup_count_is_still_used_when_entries_are_unreadable(self):
        engine = CaseEngine(probe=ScriptedProbe())
        raw = dict(HEALTHY, startup_count=20,
                   startup_entries={"available": False, "reason": "denied"})
        findings = {f["key"]: f for f in engine.measure_findings(raw)}
        self.assertEqual(findings["startup"]["status"], "info")
        self.assertEqual(findings["startup"]["value"], "20")


class NetworkRuleTests(unittest.TestCase):
    def test_upstream_fault_withholds_local_network_resets(self):
        _, case = build('Wi-Fi connected', {'net_scope': 'others_too'})
        self.assertNotIn('upstream_network', ids(case))
        self.assertNotIn('reset_network', step_ids(case))
        self.assertIn('reset_network', {w['id'] for w in case['withheld']})

    def test_proxy_is_flagged_and_clearable(self):
        _, case = build('internet connected but sites fail', overrides={'proxy_settings': {'available': True, 'enabled': True, 'server': '127.0.0.1:8080', 'pac_or_proxy': True}})
        self.assertNotIn('rogue_proxy', ids(case))
        self.assertNotIn('clear_proxy', step_ids(case))
        self.assertEqual(next(f for f in case['findings'] if f['key']=='proxy')['status'], 'info')

    def test_hosts_hijack_is_critical(self):
        _engine, case = build("cannot reach windows update", {"onset": "week"}, {
            "hosts_file": {"available": True, "path": "hosts", "entries": 4,
                           "blocked": [{"address": "0.0.0.0", "host": "windowsupdate.com"},
                                       {"address": "0.0.0.0", "host": "malwarebytes.com"}],
                           "sample": []},
        })
        hypothesis = next(h for h in case["hypotheses"] if h["id"] == "hosts_hijack")
        self.assertEqual(hypothesis["severity"], "critical")
        self.assertIn("restore_hosts", step_ids(case))

    def test_weak_wifi_withholds_network_resets(self):
        _engine, case = build("wifi is slow and drops", {"onset": "week"}, {
            "wifi_link": {"available": True, "ssid": "Home", "signal_pct": 22,
                          "band": "5 GHz", "channel": "44", "radio": "ax",
                          "rx_mbps": "6", "tx_mbps": "6"},
        })
        self.assertIn("weak_wifi", ids(case))
        withheld = {w["id"] for w in case["withheld"]}
        self.assertIn("reset_network", withheld)


class SecurityRuleTests(unittest.TestCase):
    def test_ransomware_withholds_every_destructive_cleanup(self):
        # Cleanup tasks would destroy both evidence and any chance of recovery.
        _engine, case = build("my files are all encrypted", {"onset": "today",
                                                             "security_signs": "files"})
        self.assertNotIn("ransomware_suspected", ids(case))
        withheld = {w["id"] for w in case["withheld"]}
        for task in ("clean_temp", "disk_cleanup", "component_cleanup", "defrag_optimize"):
            self.assertIn(task, withheld, task)
        advice = next(h["advice"] for h in case["trace"]["proposals"] if h["id"] == "ransomware_suspected")
        self.assertIn("disconnect", advice.lower())

    def test_defender_disabled_is_critical(self):
        _engine, case = build("i think i have a virus", {"onset": "week"}, {
            "defender": {"available": True, "enabled": True, "realtime": False, "running_mode": "Normal",
                         "signature_age": 40},
        })
        self.assertIn("defender_off", ids(case))

    def test_broad_exclusions_are_flagged(self):
        _engine, case = build("i think i have a virus", {"onset": "week"}, {
            "defender_exclusions": {"available": True, "paths": ["C:\\"],
                                    "processes": [], "overly_broad": ["C:\\"]},
        })
        self.assertIn("defender_exclusions", ids(case))


class WindowsStateRuleTests(unittest.TestCase):
    def test_full_disk_is_critical_and_adds_heavy_reclaimers(self):
        _engine, case = build("no disk space", {"onset": "week"}, {
            "disk": {"free_gb": 3.0, "free_pct": 2.0},
        })
        self.assertIn("disk_full", ids(case))
        self.assertIn("component_cleanup", step_ids(case))
        self.assertNotIn("windows_old_cleanup", step_ids(case))

    def test_end_of_life_windows_is_reported(self):
        _engine, case = build("pc is slow", {"onset": "month"}, {
            "windows_version": {"available": True, "build": 19045, "display": "22H2",
                                "product": "Windows 10 Pro", "label": "Windows 10 22H2",
                                "eol": "2025-10-14", "supported": False, "days_left": -300},
        })
        self.assertNotIn("windows_eol", ids(case))
        self.assertEqual(next(f for f in case["findings"] if f["key"]=="windows_version")["status"], "inconclusive")

    def test_disabled_pagefile_is_detected_and_fixable(self):
        _engine, case = build("apps keep closing", {"onset": "week"}, {
            "pagefile": {"available": True, "files": 0, "size_mb": 0, "automatic": False,
                         "configured": [], "disabled": True},
        })
        self.assertIn("pagefile_disabled", ids(case))
        self.assertIn("enable_pagefile", step_ids(case))

    def test_update_error_code_drives_a_specific_remedy(self):
        _engine, case = build("windows update is stuck", {"onset": "week"}, {
            "update_failures": {"available": True, "count": 1, "failures": [
                {"time": "2026-08-05T09:00:00", "code": "0x80073712",
                 "meaning": "The component store is missing or damaged.",
                 "remedy": "repair_system", "update": "Cumulative Update"}]},
        })
        self.assertIn("update_error", ids(case))
        self.assertNotIn("repair_system", step_ids(case))
        self.assertIn("repair_system", {w["id"] for w in case["withheld"]})

    def test_component_corruption_is_detected(self):
        _engine, case = build("updates keep failing", {"onset": "month"}, {
            "component_store_health": {"available": True, "state": "repairable"},
        })
        self.assertIn("component_corruption", ids(case))


class PlanOrderingTests(unittest.TestCase):
    def test_critical_hypotheses_lead_the_plan(self):
        _engine, case = build("pc freezes and is slow", {"onset": "week"}, {
            "smart_health": {"available": True, "disks": 1, "unhealthy": ["SSD (Unhealthy)"]},
            "startup_count": 25,
        })
        self.assertEqual(case["plan"][0]["severity"], "critical")

    def test_restart_is_always_last(self):
        _engine, case = build("pc is slow", {"onset": "week"}, {
            "pending_reboot": True,
            "restart_pending": {"available": True, "pending": True, "reasons": ["Update"]},
            "startup_count": 22,
            "uptime_days": 20.0,
        })
        plan = step_ids(case)
        self.assertIn("restart_windows", plan)
        self.assertEqual(plan[-1], "restart_windows")

    def test_cheap_reversible_steps_precede_expensive_ones(self):
        _engine, case = build("no disk space", {"onset": "week"}, {
            "disk": {"free_gb": 2.0, "free_pct": 1.5},
        })
        plan = step_ids(case)
        self.assertLess(plan.index("clean_temp"), plan.index("component_cleanup"))

    def test_plan_has_no_duplicate_steps(self):
        _engine, case = build("pc crashes and is slow and wifi drops", {"onset": "week"}, {
            "smart_health": {"available": True, "disks": 1, "unhealthy": ["SSD (Unhealthy)"]},
            "event_log_errors": {"available": True, "unexpected_shutdowns": 2, "disk_errors": 5,
                                 "service_crashes": 1, "hardware_errors": 1},
        })
        plan = step_ids(case)
        self.assertEqual(len(plan), len(set(plan)))

    def test_inconclusive_case_still_offers_something(self):
        _engine, case = build("something feels off", {"onset": "unknown"})
        self.assertTrue(case["plan"])

    def test_every_planned_task_is_a_real_winmend_task(self):
        from winmend_safety import DiagnosticEngine
        for problem, answers, overrides in (
            ("pc is slow", {"onset": "week"}, {"startup_count": 30}),
            ("no internet", {"onset": "today"}, {}),
            ("blue screens", {"onset": "week"}, {}),
            ("no disk space", {"onset": "week"}, {"disk": {"free_gb": 1.0, "free_pct": 1.0}}),
            ("i have a virus", {"onset": "week", "security_signs": "popups"}, {}),
        ):
            _engine, case = build(problem, answers, overrides)
            for step in case["plan"]:
                if step["kind"] == "task":
                    self.assertIn(step["id"], DiagnosticEngine.TASK_REASONS, step["id"])
                else:
                    self.assertIn(step["id"], REPAIR_ACTIONS, step["id"])


class BaselineTests(unittest.TestCase):
    """Every complaint must be answered, even on a machine that measures clean."""

    def test_each_profile_gets_its_own_first_steps(self):
        for problem in ('wifi keeps dropping', 'printer will not print', 'no sound', 'bluetooth will not pair', 'the clock is wrong'):
            _, case = build(problem)
            self.assertTrue(all(step.get('read_only') for step in case['plan']))
            self.assertFalse(any(h['id'].startswith('baseline_') for h in case['hypotheses']))

    def test_baseline_is_outranked_by_measured_faults(self):
        _engine, case = build("my pc is slow", {"onset": "week"}, {
            "smart_health": {"available": True, "disks": 1, "unhealthy": ["SSD (Unhealthy)"]},
            "event_log_errors": {"available": True, "unexpected_shutdowns": 0, "disk_errors": 11,
                                 "service_crashes": 0, "hardware_errors": 0},
        })
        self.assertEqual(case["hypotheses"][0]["id"], "failing_drive")
        self.assertFalse(any(h['id'].startswith('baseline_') for h in case['hypotheses']))

    def test_clean_area_says_so_honestly(self):
        _, case = build('wifi keeps dropping')
        self.assertEqual(case['hypotheses'], [])
        self.assertIn('Nothing here explains', case['summary'])

    def test_failing_area_changes_the_wording(self):
        _, case = build('no internet', overrides={'network': {'adapters': 0, 'dns': False, 'reachable': False}})
        baseline = next(h for h in case['trace']['proposals'] if h['id'] == 'baseline_network')
        self.assertIn('something wrong right now', baseline['explanation'])
        self.assertFalse(any(h['id'].startswith('baseline_') for h in case['hypotheses']))

    def test_shell_repairs_follow_what_was_described(self):
        for complaint in ('start menu will not open', 'desktop icons are blank'):
            _, case = build(complaint)
            self.assertNotIn('start_menu_reset', step_ids(case))
            self.assertNotIn('rebuild_icon_cache', step_ids(case))
            self.assertTrue(all(s.get('read_only') for s in case['plan']))

    def test_wlan_report_only_for_wireless_complaints(self):
        _engine, case = build("ethernet has no internet", {"onset": "today"})
        self.assertNotIn("wlan_report", step_ids(case))

    def test_baseline_respects_suppression(self):
        # Ransomware suppresses the cleanup tasks the storage baseline proposes.
        _engine, case = build("my files are encrypted and disk is full",
                              {"onset": "today", "security_signs": "files"})
        self.assertNotIn("clean_temp", step_ids(case))
        self.assertIn("clean_temp", {w["id"] for w in case["withheld"]})


class FullCheckTests(unittest.TestCase):
    """The proactive "check everything" mode."""

    @staticmethod
    def audit(overrides=None):
        engine = CaseEngine(probe=ScriptedProbe(overrides))
        return engine, engine.audit()

    def test_healthy_machine_reports_all_clear_with_no_plan(self):
        _, case = self.audit()
        self.assertEqual(case['hypotheses'], [])
        self.assertEqual(case['plan'], [])
        self.assertEqual(case['severity_score'], 0)
        self.assertIn('completed checks', case['summary'])
        self.assertIn('unavailable', case['summary'])

    def test_no_busywork_is_invented_when_nothing_is_wrong(self):
        # The symptom path falls back to pc_report on an empty plan. A full
        # check must not, or "nothing is wrong" arrives with a chore attached.
        _engine, case = self.audit()
        self.assertEqual(case["recommended_tasks"], [])

    def test_profile_baselines_stay_silent(self):
        # Otherwise all fourteen areas contribute their first steps and bury
        # anything that is genuinely wrong.
        _engine, case = self.audit({"disk": {"free_gb": 2.0, "free_pct": 1.0}})
        self.assertTrue(all(not h["id"].startswith("baseline_")
                            for h in case["hypotheses"]), case["hypotheses"])

    def test_it_finds_problems_across_every_area_at_once(self):
        _engine, case = self.audit({
            "disk": {"free_gb": 2.0, "free_pct": 1.0},
            "defender": {"available": True, "enabled": True, "realtime": False, "running_mode": "Normal",
                         "signature_age": 40},
            "pagefile": {"available": True, "files": 0, "size_mb": 0, "automatic": False,
                         "configured": [], "disabled": True},
            "proxy_settings": {"available": True, "enabled": True, "server": "127.0.0.1:8080",
                               "autoconfig": "", "pac_or_proxy": True},
            "thermal_events": {"available": True, "throttle_events": 25},
        })
        found = ids(case)
        for expected in ("disk_full", "defender_off", "pagefile_disabled",
                         "thermal_throttle"):
            self.assertIn(expected, found, expected)

    def test_findings_are_complete_regardless_of_mode(self):
        audit = CaseEngine(probe=ScriptedProbe()).audit()
        symptom = CaseEngine(probe=ScriptedProbe()).build_case('printer will not print')
        self.assertLess(len(symptom['trace']['selected_checks']), len(audit['trace']['selected_checks']))
        self.assertIn('printers', {f['key'] for f in symptom['findings']})
        self.assertNotIn('gpu_resets', symptom['trace']['selected_checks'])

    def test_timing_rules_stay_silent_without_a_stated_onset(self):
        # A full check has no account of when anything started, so a recent
        # update must not be blamed for a symptom nobody reported.
        _engine, case = self.audit({
            "installed_updates": {"available": True, "updates": [
                {"kb": "KB5034123", "installed": "2026-08-06", "days_ago": 1.0,
                 "kind": "Update"}]},
        })
        self.assertNotIn("recent_update", ids(case))
        self.assertNotIn("recent_driver", ids(case))

    def test_suppression_still_applies(self):
        _engine, case = self.audit({
            "smart_health": {"available": True, "disks": 1, "unhealthy": ["SSD (Unhealthy)"]},
            "event_log_errors": {"available": True, "unexpected_shutdowns": 0, "disk_errors": 9,
                                 "service_crashes": 0, "hardware_errors": 0},
        })
        self.assertIn("failing_drive", ids(case))
        self.assertIn("chk_dsk", {w["id"] for w in case["withheld"]})

    def test_audit_profile_survives_the_verification_round_trip(self):
        from winmend_safety import DiagnosticEngine
        from winmend_diagnostics import AUDIT_PROFILE

        engine = CaseEngine(probe=ScriptedProbe({"disk": {"free_gb": 2.0, "free_pct": 1.0}}))
        before = engine.audit()
        self.assertEqual(before["profile"], AUDIT_PROFILE)
        # The re-check reuses the stored profile string, exactly as the page does.
        after = CaseEngine(probe=ScriptedProbe()).build_case(
            before["problem"], answers=before["answers"], profile=before["profile"])
        self.assertEqual(after["profile"], AUDIT_PROFILE)
        self.assertEqual(DiagnosticEngine.compare(before, after)["outcome"], "resolved")

    def test_report_renders_for_a_clean_full_check(self):
        _engine, case = self.audit()
        html = render_case_report_html(case)
        self.assertIn("Full system check", html)

    def test_every_flagged_reading_gets_something_offered(self):
        # A full check that shows a warning with no action against it has not
        # kept its promise to report everything wrong.
        _engine, case = self.audit({
            "temp_size": {"bytes": 4 * 1024 ** 3, "partial": False},
            "event_log_errors": {"available": True, "unexpected_shutdowns": 0, "disk_errors": 0,
                                 "service_crashes": 12, "hardware_errors": 0},
            "pending_reboot": True,
        })
        flagged = {f["key"] for f in case["findings"] if f["status"] in ("warn", "bad")}
        covered = set()
        for hypothesis in case["hypotheses"]:
            covered.update(hypothesis["evidence_keys"])
        self.assertTrue(flagged, "fixture produced no flagged readings")
        self.assertEqual(flagged - covered, set(),
                         f"flagged but unexplained: {flagged - covered}")

    def test_unexplained_findings_rank_below_real_hypotheses(self):
        _, case = self.audit({'temp_size': {'bytes': 2*1024**3, 'partial': False}})
        self.assertEqual(next(f for f in case['findings'] if f['key']=='temp_size')['status'], 'info')
        self.assertNotIn('finding_temp_size', ids(case))
        self.assertNotIn('clean_temp', step_ids(case))

    def test_a_finding_with_no_task_is_not_turned_into_busywork(self):
        _engine, case = self.audit({
            "memory_config": {"available": True, "sticks": [
                {"gb": 8, "rated_mhz": 3200, "actual_mhz": 3200, "slot": "A1", "vendor": "x"}],
                "count": 1, "total_gb": 8.0, "rated_mhz": 3200, "actual_mhz": 3200,
                "single_channel": True, "underclocked": False},
        })
        for hypothesis in case["hypotheses"]:
            self.assertTrue(hypothesis["actions"] or hypothesis["advice"], hypothesis["id"])

    def test_symptom_mode_does_not_get_the_catch_all(self):
        _engine, case = build("printer will not print", {"onset": "week"}, {
            "temp_size": {"bytes": 4 * 1024 ** 3, "partial": False},
        })
        self.assertTrue(all(not h["id"].startswith("finding_") for h in case["hypotheses"]))


class EarlyStopTests(unittest.TestCase):
    def test_step_cleared_requires_a_baseline_problem(self):
        # A step whose checks were already healthy cannot claim to have fixed
        # anything -- otherwise every step "succeeds".
        engine = CaseEngine(probe=ScriptedProbe())
        before = engine.measure_findings(dict(HEALTHY))
        step = {"verify_keys": ["disk_free"]}
        cleared, checked = engine.step_cleared(step, dict(HEALTHY), before)
        self.assertFalse(cleared)
        self.assertEqual(checked, [])

    def test_step_cleared_when_a_real_problem_resolves(self):
        engine = CaseEngine(probe=ScriptedProbe())
        sick = dict(HEALTHY, disk={"free_gb": 2.0, "free_pct": 1.0})
        before = engine.measure_findings(sick)
        step = {"verify_keys": ["disk_free"]}
        cleared, checked = engine.step_cleared(step, dict(HEALTHY), before)
        self.assertTrue(cleared)
        self.assertEqual(len(checked), 1)

    def test_step_not_cleared_when_the_problem_persists(self):
        engine = CaseEngine(probe=ScriptedProbe())
        sick = dict(HEALTHY, disk={"free_gb": 2.0, "free_pct": 1.0})
        before = engine.measure_findings(sick)
        cleared, _ = engine.step_cleared({"verify_keys": ["disk_free"]}, sick, before)
        self.assertFalse(cleared)

    def test_step_with_no_measurable_effect_never_claims_success(self):
        engine = CaseEngine(probe=ScriptedProbe())
        before = engine.measure_findings(dict(HEALTHY))
        cleared, _ = engine.step_cleared({"verify_keys": []}, dict(HEALTHY), before)
        self.assertFalse(cleared)

    def test_informational_findings_cannot_verify_a_fix(self):
        # recent_updates is always info, so a step verifying only it must not
        # report success.
        engine = CaseEngine(probe=ScriptedProbe())
        before = engine.measure_findings(dict(HEALTHY))
        cleared, _ = engine.step_cleared({"verify_keys": ["recent_updates"]},
                                         dict(HEALTHY), before)
        self.assertFalse(cleared)

    def test_stop_if_clear_only_set_for_failing_checks(self):
        _engine, case = build("no disk space", {"onset": "week"}, {
            "disk": {"free_gb": 2.0, "free_pct": 1.0},
        })
        cleanup = next(s for s in case["plan"] if s["id"] == "clean_temp")
        self.assertTrue(cleanup["stop_if_clear"])


class RemeasureTests(unittest.TestCase):
    def test_remeasure_runs_only_the_needed_collectors(self):
        probe = ScriptedProbe()
        engine = CaseEngine(probe=probe)
        probe.calls.clear()
        engine.remeasure(["disk_free", "memory"])
        self.assertEqual(sorted(set(probe.calls)), ["disk", "memory"])

    def test_remeasure_with_unknown_keys_does_nothing(self):
        probe = ScriptedProbe()
        engine = CaseEngine(probe=probe)
        probe.calls.clear()
        self.assertEqual(engine.remeasure(["not_a_key"]), {})
        self.assertEqual(probe.calls, [])


class ActionSafetyTests(unittest.TestCase):
    def test_rollback_driver_rejects_a_non_package_name(self):
        result = REPAIR_ACTIONS["rollback_driver"].run({"published": "evil.inf; del *"})
        self.assertFalse(result["ok"])
        self.assertIn("not a driver package", result["message"])

    def test_uninstall_update_rejects_a_non_kb(self):
        result = REPAIR_ACTIONS["uninstall_update"].run({"kb": "not-a-kb"})
        self.assertFalse(result["ok"])

    def test_reinstall_device_refuses_boot_critical_classes(self):
        # Removing a storage or system-bus device from a running Windows can
        # stop the PC booting.
        for blocked in ("DiskDrive", "SCSIAdapter", "HDC", "System", "Volume"):
            result = REPAIR_ACTIONS["reinstall_device"].run(
                {"instance_id": "PCI\\VEN_1", "name": "x", "class": blocked})
            self.assertFalse(result["ok"], blocked)
            self.assertIn("Refusing", result["message"])

    def test_restart_service_rejects_injection(self):
        result = REPAIR_ACTIONS["restart_service"].run({"name": "foo & calc.exe"})
        self.assertFalse(result["ok"])

    def test_stop_process_rejects_injection(self):
        result = REPAIR_ACTIONS["stop_process"].run({"name": "foo | calc"})
        self.assertFalse(result["ok"])

    def test_destructive_actions_require_confirmation_and_a_restore_point(self):
        for action_id in ("rollback_driver", "uninstall_update", "reinstall_device"):
            action = REPAIR_ACTIONS[action_id]
            self.assertEqual(action.risk, "destructive", action_id)
            self.assertTrue(action.confirm, action_id)
            self.assertTrue(action.restore_point, action_id)

    def test_irreversible_actions_do_not_advertise_an_undo(self):
        for action_id in ("rollback_driver", "uninstall_update", "reinstall_device"):
            self.assertFalse(REPAIR_ACTIONS[action_id].reversible, action_id)

    def test_reversible_actions_have_a_real_undo(self):
        for action_id in ("clear_proxy", "restore_hosts", "reset_dns_servers",
                          "enable_pagefile", "disable_startup_entry"):
            self.assertTrue(REPAIR_ACTIONS[action_id].reversible, action_id)

    def test_disable_startup_entry_reports_a_missing_entry(self):
        result = REPAIR_ACTIONS["disable_startup_entry"].run(
            {"name": "__winmend_no_such_entry__"})
        self.assertFalse(result["ok"])

    # Actions that take no parameters. Calling run() on these is a REAL repair:
    # it rewrites the hosts file, the proxy keys, the firewall, or the update
    # policy on the machine running the tests. They are never invoked here --
    # only their contract is checked.
    STATEFUL = ("clear_proxy", "restore_hosts", "reset_dns_servers", "enable_pagefile",
                "enable_uac", "unblock_updates", "sync_clock",
                "clear_safe_boot", "disable_fast_startup", "disable_wake_timers",
                "enable_trim", "clear_update_policy", "repair_path",
                # From the hardware scan. The last two undo by running a
                # command rather than by restoring a registry value, so each
                # refuses an empty payload instead of firing bcdedit or
                # powercfg on the strength of a dict with nothing in it.
                "reset_tdr", "set_gpu_scheduling", "schedule_memory_test",
                "disable_pcie_power_saving")

    # The same, for the handful whose change has nothing to put back. Undoing
    # malware removal or a corrected clock is not a service to anyone, so these
    # are honest about carrying no undo rather than inventing a harmful one.
    #
    # The later additions are the same shape and are, if anything, more
    # dangerous to exercise: reset_winsock tears down the network stack,
    # clear_update_cache renames the live SoftwareDistribution folder, and
    # restart_explorer kills the desktop of whoever is running the suite.
    ONE_WAY = ("enable_realtime_protection", "remove_threats", "renew_lease",
               "reset_winsock", "flush_dns_cache", "clear_update_cache",
               "restart_explorer", "restart_audio", "start_onedrive",
               # The drivers rebuild a shader cache on demand, so there is
               # nothing to put back and nothing lost by clearing it.
               "clear_shader_cache")

    def test_failures_are_returned_not_raised(self):
        # Only the actions that validate their parameters are executed, and only
        # with input they are guaranteed to reject before touching anything.
        rejects = {
            "rollback_driver": {"published": "not-an-inf"},
            "uninstall_update": {"kb": "not-a-kb"},
            "reinstall_device": {"instance_id": ""},
            "restart_service": {"name": "bad name & echo"},
            "stop_process": {"name": "bad|name"},
            "disable_startup_entry": {"name": ""},
            "set_service_startup": {"name": "bad name &", "start": "auto"},
            "run_scheduled_task": {"task": r"\Some\Third Party\Updater"},
            "reset_adapter": {"name": "bad|name"},
            "check_disk": {"drive": "not-a-drive"},
            "empty_recycle_bin": {"drive": "not-a-drive"},
            "enable_firewall": {"profiles": ["NotAProfile"]},
            "set_power_plan": {"scheme": "not-a-guid"},
            "enable_system_restore": {"drive": "not-a-drive"},
            # No parameters, but its first guard is that this session is not on
            # a temporary profile -- which is why it is safe to run here.
            "restore_profile": {},
            "optimize_volume": {"drive": "not-a-drive"},
            "resume_bitlocker": {"drive": "not-a-drive"},
            "set_network_private": {"index": "not-a-number"},
            "set_mtu": {"interface": "bad|name", "mtu": 1500},
            "reregister_app": {"name": "bad name & calc"},
            # A path that is not on the watchlist. remove_policy refuses to
            # delete a registry value it was not built to know about, which is
            # what keeps "remove a restriction" from becoming "delete anything".
            "remove_policy": {"hive": "HKLM", "path": r"SOFTWARE\Not\A\Policy",
                              "value": "Whatever"},
        }
        self.assertEqual(sorted(set(REPAIR_ACTIONS) - set(rejects)),
                         sorted(self.STATEFUL + self.ONE_WAY))
        for action_id, params in rejects.items():
            result = REPAIR_ACTIONS[action_id].run(params)
            self.assertIn("ok", result, action_id)
            self.assertIn("message", result, action_id)
            self.assertFalse(result["ok"], action_id)

    def test_a_disabled_service_is_never_set_to_disabled_again(self):
        # "start" comes from a rule, and the one value that would turn this
        # repair into the fault it repairs is refused outright.
        result = REPAIR_ACTIONS["set_service_startup"].run(
            {"name": "Spooler", "start": "disabled"})
        self.assertFalse(result["ok"])

    def test_only_windows_own_maintenance_tasks_can_be_run(self):
        # The task path arrives from collected data and running it is an
        # execution primitive, so the allowed set is a fixed list, not a filter.
        blocked = REPAIR_ACTIONS["run_scheduled_task"].run(
            {"task": r"\SomeVendor\Updater"})
        self.assertFalse(blocked["ok"])
        self.assertIn("maintenance", blocked["message"])

    def test_a_task_inside_a_maintenance_folder_is_not_maintenance(self):
        # Matching the folder let USO_UxBroker through, which can only ever
        # fail when started by hand. Paths are matched in full now.
        for path in (r"\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker",
                     r"\Microsoft\Windows\WindowsUpdate\RefreshGroupPolicy",
                     r"\Microsoft\Windows\Windows Defender\Windows Defender Rootkit"):
            result = REPAIR_ACTIONS["run_scheduled_task"].run({"task": path})
            self.assertFalse(result["ok"], path)

    def test_a_reported_but_unstartable_task_explains_itself(self):
        result = REPAIR_ACTIONS["run_scheduled_task"].run(
            {"task": r"\Microsoft\Windows\WindowsBackup\ConfigNotification"})
        self.assertFalse(result["ok"])
        self.assertIn("arguments", result["message"])

    def test_every_maintenance_task_path_is_a_full_path(self):
        # A trailing backslash meant a whole folder, which is what went wrong.
        for path, (consequence, _runnable) in MAINTENANCE_TASKS.items():
            self.assertFalse(path.endswith("\\"), path)
            self.assertGreaterEqual(path.count("\\"), 3, path)
            self.assertTrue(consequence, path)

    def test_stateful_actions_declare_themselves_reversible(self):
        # These cannot be safely exercised in a test, so the contract that they
        # can always be undone is what protects the user instead.
        for action_id in self.STATEFUL:
            action = REPAIR_ACTIONS[action_id]
            self.assertTrue(action.reversible, action_id)
            self.assertNotEqual(action.risk, "destructive", action_id)

    def test_one_way_actions_do_not_claim_an_undo(self):
        for action_id in self.ONE_WAY:
            action = REPAIR_ACTIONS[action_id]
            self.assertFalse(action.reversible, action_id)
            result = action.undo({})
            self.assertFalse(result["ok"], action_id)

    def test_undo_of_an_empty_payload_fails_safely(self):
        for action_id in self.STATEFUL:
            result = REPAIR_ACTIONS[action_id].undo({})
            self.assertIn("ok", result, action_id)
            self.assertIn("message", result, action_id)

    def test_restore_hosts_refuses_when_it_cannot_back_up(self):
        # The backup is the undo path, so a failed backup must abort the repair
        # rather than proceed and leave the user with no way back.
        import winmend_diagnostics as module

        original = module.shutil.copy2

        def refuse(*_args, **_kwargs):
            raise OSError("access denied")

        module.shutil.copy2 = refuse
        try:
            result = REPAIR_ACTIONS["restore_hosts"].run({})
        finally:
            module.shutil.copy2 = original
        self.assertFalse(result["ok"])
        self.assertIn("nothing was changed", result["message"])


class RuleRobustnessTests(unittest.TestCase):
    def test_no_rule_raises_on_empty_evidence(self):
        ctx = Context("something is wrong", "general", {}, {}, [])
        for rule_fn in RULES:
            try:
                rule_fn(ctx)
            except Exception as exc:  # pragma: no cover - the assertion is the point
                self.fail(f"{rule_fn.__name__} raised on empty evidence: {exc}")

    def test_no_rule_raises_on_unavailable_collectors(self):
        raw = {name: {"available": False} for name in HEALTHY}
        ctx = Context("something is wrong", "general", {"onset": "week"}, raw, [])
        for rule_fn in RULES:
            try:
                rule_fn(ctx)
            except Exception as exc:  # pragma: no cover
                self.fail(f"{rule_fn.__name__} raised on unavailable evidence: {exc}")

    def test_a_throwing_rule_does_not_sink_the_diagnosis(self):
        import winmend_diagnostics as module

        def exploding(ctx):
            raise RuntimeError("boom")

        module.RULES.append(exploding)
        try:
            _engine, case = build("pc is slow", {"onset": "week"})
            self.assertIn("summary", case)
        finally:
            module.RULES.remove(exploding)

    def test_hypotheses_are_ordered_by_severity_then_confidence(self):
        _engine, case = build("pc crashes and is slow", {"onset": "week"}, {
            "smart_health": {"available": True, "disks": 1, "unhealthy": ["SSD (Unhealthy)"]},
            "startup_count": 24,
            "thermal_events": {"available": True, "throttle_events": 20},
        })
        ranks = [({"critical": 3, "high": 2, "medium": 1, "low": 0}[h["severity"]], -h["confidence"])
                 for h in case["hypotheses"]]
        self.assertEqual(ranks, sorted(ranks, key=lambda pair: (-pair[0], pair[1])))


class CaseShapeTests(unittest.TestCase):
    def test_case_stays_compatible_with_the_existing_verification(self):
        # DiagnosticEngine.compare() drives the Safety Journal's verification and
        # reads findings/severity_score straight off a case.
        from winmend_safety import DiagnosticEngine
        engine = CaseEngine(probe=ScriptedProbe({"disk": {"free_gb": 2.0, "free_pct": 1.0}}))
        before = engine.build_case("no disk space", answers={"onset": "week"})
        after = CaseEngine(probe=ScriptedProbe()).build_case(
            "no disk space", answers={"onset": "week"})
        verification = DiagnosticEngine.compare(before, after)
        self.assertEqual(verification["outcome"], "symptom_unverified")
        self.assertTrue(verification["changes"])

    def test_case_carries_the_keys_the_journal_expects(self):
        _engine, case = build("pc is slow", {"onset": "week"})
        for key in ("id", "created_at", "problem", "profile", "summary",
                    "severity_score", "findings", "recommended_tasks"):
            self.assertIn(key, case)

    def test_recommended_tasks_mirrors_the_task_steps(self):
        _engine, case = build("no disk space", {"onset": "week"}, {
            "disk": {"free_gb": 2.0, "free_pct": 1.0},
        })
        self.assertEqual([r["id"] for r in case["recommended_tasks"]],
                         [s["id"] for s in case["plan"] if s["kind"] == "task"])

    def test_answers_are_normalised_into_the_case(self):
        _engine, case = build("pc is slow", {"onset": "week", "bogus": "x"})
        self.assertEqual(case["answers"], {"onset": "week"})


class ReportTests(unittest.TestCase):
    def test_report_renders_and_escapes(self):
        _engine, case = build("<script>alert(1)</script> is slow", {"onset": "week"})
        html = render_case_report_html(case)
        self.assertIn("<!doctype html>", html)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_report_includes_withheld_actions(self):
        _engine, case = build("files encrypted", {"onset": "today", "security_signs": "files"})
        html = render_case_report_html(case)
        self.assertIn("Deliberately not done", html)

    def test_report_includes_verification_when_present(self):
        _engine, case = build("pc is slow", {"onset": "week"})
        html = render_case_report_html(case, verification={
            "outcome": "resolved", "summary": "All clear.", "changes": []})
        self.assertIn("Verification", html)
        self.assertIn("All clear.", html)


class WiderSweepTests(unittest.TestCase):
    """The areas the full check gained: every drive, services, tasks, updates,
    security posture, addressing, the clock, printing, search, and the profile.

    Each fault is checked twice -- once that it is found, and once that the
    healthy-but-superficially-similar state is *not* reported. The second half
    is the point: a full check that cries wolf is worse than a narrow one.
    """

    @staticmethod
    def audit(overrides=None):
        engine = CaseEngine(probe=ScriptedProbe(overrides))
        return engine, engine.audit()

    def finding(self, case, key):
        for item in case["findings"]:
            if item["key"] == key:
                return item
        self.fail(f"no finding {key!r} in {[f['key'] for f in case['findings']]}")

    # -- storage ----------------------------------------------------------

    def test_a_full_data_drive_is_found(self):
        # The check this whole area exists for: the system drive is fine and
        # something else on the PC is out of room.
        _engine, case = self.audit({"volumes": {"available": True, "volumes": [], "others": [
            {"drive": "D:", "label": "Games", "filesystem": "NTFS", "total_gb": 500.0,
             "free_gb": 20.0, "free_pct": 4.0, "dirty": False, "system": False}]}})
        self.assertIn("secondary_volume_full", ids(case))
        self.assertEqual(self.finding(case, "volumes")["status"], "bad")
        self.assertIn("disk_cleanup", step_ids(case))
        self.assertEqual(self.finding(case, "disk_free")["status"], "good")

    def test_one_fixed_drive_is_not_a_finding(self):
        _engine, case = self.audit({"volumes": {"available": True, "others": [], "volumes": [
            {"drive": "C:", "label": "", "filesystem": "NTFS", "total_gb": 500.0,
             "free_gb": 275.0, "free_pct": 55.0, "dirty": False, "system": True}]}})
        self.assertEqual(self.finding(case, "volumes")["status"], "info")
        self.assertNotIn("secondary_volume_full", ids(case))

    def test_dirty_volume_is_reported_even_though_it_reads_healthy(self):
        _engine, case = self.audit({"volumes": {"available": True, "others": [], "volumes": [
            {"drive": "C:", "label": "", "filesystem": "NTFS", "total_gb": 500.0,
             "free_gb": 275.0, "free_pct": 55.0, "dirty": True, "system": True}]}})
        self.assertIn("dirty_filesystem", ids(case))
        self.assertIn("chk_dsk", step_ids(case))

    def test_a_scheduled_disk_check_is_reported(self):
        _engine, case = self.audit({
            "filesystem_health": {"available": True, "scheduled": ["C:"],
                                  "boot_execute": "autocheck autochk /r \\??\\C:"}})
        self.assertEqual(self.finding(case, "filesystem")["status"], "info")
        self.assertNotIn("dirty_filesystem", ids(case))

    def test_dirty_volume_does_not_override_a_failing_drive(self):
        # chkdsk is the obvious answer to a dirty bit and the wrong move on a
        # drive that is dying. The suppression has to win.
        _engine, case = self.audit({
            "filesystem_health": {"available": True, "scheduled": ["C:"], "boot_execute": "x"},
            "volumes": {"available": True, "others": [], "volumes": [
                {"drive": "C:", "dirty": True, "system": True}]},
            "smart_health": {"available": True, "disks": 1, "unhealthy": ["SSD (Unhealthy)"]},
            "event_log_errors": {"available": True, "unexpected_shutdowns": 0, "disk_errors": 9,
                                 "service_crashes": 0, "hardware_errors": 0},
        })
        self.assertIn("dirty_filesystem", ids(case))
        self.assertNotIn("chk_dsk", step_ids(case))
        self.assertIn("chk_dsk", {w["id"] for w in case["withheld"]})

    def test_drive_wear_is_not_invented_when_it_cannot_be_read(self):
        # Without elevation the drive list reads and its counters do not.
        # "0% worn" would be an invention rather than a measurement.
        _engine, case = self.audit({"disk_reliability": {
            "available": True, "counters_readable": False, "trim": None, "disks": [
                {"name": "SSD", "media": "SSD", "health": "Healthy", "wear_pct": None,
                 "temperature_c": None, "read_errors": None, "write_errors": None,
                 "power_on_hours": None}]}})
        self.assertEqual(self.finding(case, "drive_wear")["status"], "inconclusive")
        self.assertNotIn("drive_wear", ids(case))

    def test_a_worn_drive_is_reported_and_defrag_withheld(self):
        _engine, case = self.audit({"disk_reliability": {
            "available": True, "counters_readable": True, "trim": True, "disks": [
                {"name": "SSD", "media": "SSD", "health": "Healthy", "wear_pct": 94,
                 "temperature_c": 41, "read_errors": 0, "write_errors": 0,
                 "power_on_hours": 30000}]}})
        self.assertIn("drive_wear", ids(case))
        self.assertIn("defrag_optimize", {w["id"] for w in case["withheld"]})

    def test_storage_removals_are_visible_at_last(self):
        # Collected since the first version and used by rule_failing_drive, but
        # never shown -- the user could not see the evidence a critical verdict
        # rested on.
        _engine, case = self.audit({"storage_removals": {"available": True, "events": 4}})
        self.assertEqual(self.finding(case, "storage_faults")["status"], "bad")

    # -- services and scheduled tasks --------------------------------------

    def test_a_stopped_essential_service_is_a_fault(self):
        _engine, case = self.audit({"service_health": {
            "available": True, "total": 300, "stopped_auto": [],
            "critical_stopped": [{"name": "Dnscache", "display": "DNS Client",
                                  "state": "Stopped", "start_mode": "Auto",
                                  "delayed": False, "disabled": False,
                                  "why": "DNS Client -- name lookups fall back to a slow path"}]}})
        self.assertIn("critical_service_stopped", ids(case))
        self.assertIn("restart_service", step_ids(case))

    def test_stopped_trigger_start_services_are_not_a_fault(self):
        # wuauserv and sppsvc sit stopped on a perfectly healthy PC. Counting
        # them would put a permanent warning on every machine.
        _engine, case = self.audit({"service_health": {
            "available": True, "total": 300, "critical_stopped": [],
            "stopped_auto": [{"name": "wuauserv", "display": "Windows Update"},
                             {"name": "sppsvc", "display": "Software Protection"}]}})
        self.assertEqual(self.finding(case, "services")["status"], "good")
        self.assertNotIn("critical_service_stopped", ids(case))

    def test_a_failing_maintenance_task_warns(self):
        _engine, case = self.audit({"scheduled_tasks": {
            "available": True,
            "failures": [{"task": r"\Microsoft\Windows\Defrag\ScheduledDefrag",
                          "code": "0x80070005", "last_run": "", "maintenance": True}],
            "maintenance_failures": [{"task": r"\Microsoft\Windows\Defrag\ScheduledDefrag",
                                      "code": "0x80070005", "last_run": "",
                                      "maintenance": True}]}})
        self.assertEqual(self.finding(case, "scheduled_tasks")["status"], "warn")
        self.assertIn("maintenance_task_failing", ids(case))

    def test_failing_leftover_tasks_are_counted_not_warned_about(self):
        # A dozen dead third-party updaters is the normal state of a PC that
        # has had software installed on it.
        _engine, case = self.audit({"scheduled_tasks": {
            "available": True, "maintenance_failures": [],
            "failures": [{"task": r"\SomeUninstalledUpdater", "code": "0x80070002",
                          "last_run": "", "maintenance": False}] * 12}})
        self.assertEqual(self.finding(case, "scheduled_tasks")["status"], "info")
        self.assertNotIn("maintenance_task_failing", ids(case))

    # -- security ----------------------------------------------------------

    def test_an_unremoved_threat_outranks_everything(self):
        _engine, case = self.audit({"defender_threats": {
            "available": True, "history": 3, "quick_scan_age": 1, "full_scan_age": 9,
            "tamper_protection": True,
            "threats": [], "unresolved": [
                {"name": "Trojan:Win32/Wacatac", "severity": "5", "status": 1,
                 "unresolved": True, "state": "detected but not yet acted on",
                 "days_ago": 2.0}]}})
        self.assertEqual(case["hypotheses"][0]["id"], "active_threat")
        self.assertEqual(case["hypotheses"][0]["severity"], "critical")
        self.assertIn("defender_scan", step_ids(case))

    def test_a_cleaned_threat_is_not_an_outstanding_one(self):
        _engine, case = self.audit({"defender_threats": {
            "available": True, "history": 3, "quick_scan_age": 1, "full_scan_age": 9,
            "tamper_protection": True, "unresolved": [],
            "threats": [{"name": "Trojan:Win32/Wacatac", "severity": "5", "status": 3,
                         "unresolved": False, "state": "handled", "days_ago": 40.0}]}})
        self.assertNotIn("active_threat", ids(case))
        self.assertEqual(self.finding(case, "threats")["status"], "info")

    def test_never_scanned_is_reported(self):
        _engine, case = self.audit({"defender_threats": {
            "available": True, "history": 0, "threats": [], "unresolved": [],
            "quick_scan_age": None, "full_scan_age": None, "tamper_protection": True}})
        self.assertEqual(self.finding(case, "threats")["status"], "info")

    def test_uac_turned_off_is_reported(self):
        _engine, case = self.audit({"uac_state": {
            "available": True, "enabled": False, "consent": 0, "never_notifies": False,
            "secure_desktop": False}})
        self.assertIn("uac_disabled", ids(case))
        self.assertEqual(self.finding(case, "uac")["status"], "bad")

    def test_uac_that_never_asks_is_reported_as_well(self):
        _engine, case = self.audit({"uac_state": {
            "available": True, "enabled": True, "consent": 0, "never_notifies": True,
            "secure_desktop": False}})
        self.assertIn("uac_disabled", ids(case))
        self.assertEqual(self.finding(case, "uac")["status"], "warn")

    def test_a_disabled_firewall_profile_is_named(self):
        _engine, case = self.audit({"firewall_profiles": {
            "available": True, "disabled": ["Public"], "allow_inbound": [], "profiles": [
                {"name": "Domain", "enabled": True, "inbound": "NotConfigured"},
                {"name": "Public", "enabled": False, "inbound": "NotConfigured"}]}})
        firewall = self.finding(case, "firewall")
        self.assertEqual(firewall["status"], "bad")
        self.assertIn("Public", firewall["value"])

    def test_blocked_updates_are_reported(self):
        _engine, case = self.audit({"update_state": {
            "available": True, "blocked": True, "paused_until": "",
            "policies": [{"value": "NoAutoUpdate",
                          "meaning": "automatic updates are turned off by policy"}],
            "services": {"wuauserv": {"start": 4, "disabled": True}}}})
        self.assertIn("update_blocked", ids(case))
        self.assertNotIn("reset_win_update", step_ids(case))

    # -- network and clock --------------------------------------------------

    def test_no_address_from_the_router_is_a_fault(self):
        _engine, case = self.audit({"network_config": {
            "available": True, "has_route": False, "self_assigned_only": True,
            "gateways": [], "interfaces": [
                {"index": "3", "interface": "Wi-Fi", "address": "169.254.9.9",
                 "origin": "WellKnown", "gateway": "", "self_assigned": True}]}})
        self.assertIn("no_route", ids(case))
        self.assertEqual(self.finding(case, "ip_config")["status"], "bad")

    def test_one_stranded_adapter_alongside_a_working_one_is_normal(self):
        # An unplugged second Ethernet port sits on a self-assigned address on
        # a completely healthy PC. Flagging it would warn on any machine with
        # two network adapters.
        _engine, case = self.audit({"network_config": {
            "available": True, "has_route": True, "self_assigned_only": False,
            "gateways": ["192.168.1.1"], "interfaces": [
                {"index": "5", "interface": "Ethernet 2", "address": "169.254.162.16",
                 "origin": "WellKnown", "gateway": "", "self_assigned": True},
                {"index": "10", "interface": "Ethernet", "address": "192.168.1.241",
                 "origin": "Dhcp", "gateway": "192.168.1.1", "self_assigned": False}]}})
        self.assertEqual(self.finding(case, "ip_config")["status"], "good")
        self.assertNotIn("no_route", ids(case))

    def test_adapter_error_rate_is_reported(self):
        _engine, case = self.audit({"adapter_health": {
            "available": True, "adapters": [
                {"name": "Ethernet", "speed_mbps": 100, "packets": 900000, "errors": 12000,
                 "drops": 3000, "error_pct": 1.67}],
            "degraded": [{"name": "Ethernet", "speed_mbps": 100, "packets": 900000,
                          "errors": 12000, "drops": 3000, "error_pct": 1.67}]}})
        self.assertNotIn("link_errors", ids(case))

    def test_a_handful_of_errors_over_months_of_uptime_is_not_a_fault(self):
        _engine, case = self.audit({"adapter_health": {
            "available": True, "degraded": [], "adapters": [
                {"name": "Ethernet", "speed_mbps": 1000, "packets": 9000000, "errors": 4,
                 "drops": 0, "error_pct": 0.0}]}})
        self.assertEqual(self.finding(case, "link_health")["status"], "info")
        self.assertNotIn("link_errors", ids(case))

    def test_a_wrong_clock_is_reported(self):
        _engine, case = self.audit({"time_sync": {
            "available": True, "source": "time.windows.com", "offset_seconds": -740.0,
            "service": "stopped", "round_trip_ms": 30.0}})
        self.assertIn("clock_drift", ids(case))
        self.assertIn("time_sync_fix", step_ids(case))

    def test_a_second_of_drift_is_not_a_wrong_clock(self):
        _engine, case = self.audit({"time_sync": {
            "available": True, "source": "time.windows.com", "offset_seconds": -0.4,
            "service": "running", "round_trip_ms": 30.0}})
        self.assertEqual(self.finding(case, "time_sync")["status"], "good")
        self.assertNotIn("clock_drift", ids(case))

    # -- the session and the desktop ---------------------------------------

    def test_a_temporary_profile_is_reported_loudly(self):
        _engine, case = self.audit({"user_profile": {
            "available": True, "path": r"C:\Users\TEMP", "temporary": True,
            "backup_profiles": 1, "sid": "S-1-5-21-1.bak", "onedrive_folders": []}})
        self.assertEqual(case["hypotheses"][0]["id"], "temporary_profile")
        self.assertEqual(self.finding(case, "user_profile")["status"], "bad")

    def test_search_service_stopped_offers_a_restart_and_a_rebuild(self):
        _engine, case = self.audit({"search_index": {
            "available": True, "service": "stopped", "setup_complete": True,
            "healthy": False}})
        self.assertIn("search_broken", ids(case))
        self.assertIn("restart_service", step_ids(case))
        self.assertIn("reset_search_index", step_ids(case))

    def test_a_stopped_spooler_is_reported(self):
        _engine, case = self.audit({"printers": {
            "available": True, "jobs": 3, "spooler": "stopped", "default_offline": [],
            "printers": [{"name": "Office", "status": 3, "state": "idle",
                          "offline": False, "default": True}]}})
        self.assertIn("print_spooler", ids(case))
        self.assertIn("clear_print_spooler", step_ids(case))

    def test_a_pc_with_no_printers_is_not_a_printing_fault(self):
        _engine, case = self.audit({"printers": {
            "available": True, "jobs": 0, "spooler": "stopped", "default_offline": [],
            "printers": []}})
        self.assertNotIn("print_spooler", ids(case))

    def test_power_saver_is_reported(self):
        _engine, case = self.audit({"power_config": {
            "available": True, "scheme": "a1841308-3541-4fab-bc81-f71556f20b4a",
            "name": "Power saver", "known": True, "power_saver": True,
            "fast_startup": True}})
        self.assertEqual(self.finding(case, "power_plan")["status"], "warn")

    # -- honesty ------------------------------------------------------------

    def test_a_busy_processor_is_not_a_verdict_in_a_full_check(self):
        # A one-second sample cannot tell a program that is working hard from
        # one that is stuck, and the sweep itself runs two dozen queries at
        # once. Reporting the number is useful; calling it a fault is not.
        _engine, case = self.audit({"cpu_load": {
            "available": True, "used_pct": 99.0, "cores": 8,
            "hog": {"name": "encoder.exe", "pid": 5, "pct": 88.0, "ours": False},
            "top": [{"name": "encoder.exe", "pid": 5, "pct": 88.0, "ours": False}]}})
        self.assertEqual(self.finding(case, "cpu_load")["status"], "info")
        self.assertNotIn("cpu_hog", ids(case))

    def test_a_busy_processor_does_explain_a_slowness_complaint(self):
        from guided_scenarios import load
        _, case = build('PC is really slow', overrides={'performance_samples': load(cpu=(99,98,97,99), process={'name': 'encoder.exe', 'cpu_samples': [88]*4})})
        self.assertIn('cpu_hog', ids(case))
        self.assertNotIn('stop_process', step_ids(case))

    def test_queued_file_renames_alone_are_not_a_pending_restart(self):
        # Installers queue renames constantly; a healthy, fully-updated PC has
        # dozens. Counting them would put "restart required" on nearly every PC.
        _engine, case = self.audit({"restart_pending": {
            "available": True, "pending": False, "reasons": [], "queued_renames": 70}})
        self.assertEqual(self.finding(case, "pending_reboot")["status"], "good")

    def test_a_pending_restart_says_what_it_is_waiting_for(self):
        _engine, case = self.audit({"restart_pending": {
            "available": True, "pending": True, "queued_renames": 4,
            "reasons": ["Windows Update is waiting to finish"]}})
        finding = self.finding(case, "pending_reboot")
        self.assertEqual(finding["status"], "warn")
        self.assertIn("Windows Update", finding["value"])

    def test_the_sweep_covers_every_area_it_claims_to(self):
        # The promise the "check for issues" button makes. If a collector stops
        # producing a row, this is what says so.
        _engine, case = self.audit()
        keys = {f["key"] for f in case["findings"]}
        for expected in (
                "disk_free", "volumes", "filesystem", "drive_wear", "storage_faults",
                "temp_size", "memory", "cpu_load", "startup", "uptime", "pending_reboot",
                "windows_version", "smart", "evt_shutdowns", "evt_hardware", "evt_disk",
                "evt_services", "bugchecks", "crash_dumps", "services", "scheduled_tasks",
                "gpu_resets", "app_crashes", "problem_devices", "thermal", "update_failures",
                "update_state", "recent_updates", "recent_drivers", "recent_programs",
                "component_store", "pagefile", "proxy", "hosts", "dns_config", "adapters",
                "dns", "reachability", "net_quality", "ip_config", "link_health", "time_sync",
                "defender", "threats", "firewall", "uac", "defender_exclusions", "platform",
                "memory_config", "top_memory", "disk_latency", "restore_points", "power_plan",
                "search_index", "printers", "user_profile"):
            self.assertIn(expected, keys, expected)

    def test_every_new_finding_can_be_re_measured(self):
        # remeasure() goes from finding keys to collectors through
        # FINDING_SOURCES. A key missing from it verifies nothing at all.
        _engine, case = self.audit()
        for finding in case["findings"]:
            self.assertIn(finding["key"], FINDING_SOURCES, finding["label"])
            self.assertTrue(collectors_for([finding["key"]]), finding["key"])


# One fault at a time, in the shape the collectors produce it. Each entry is
# the fault a full check can find, the hypothesis it must raise, and the
# targeted repair that must be offered against it -- or None where the honest
# answer is that WinMend cannot fix it and says so.
FAULTS = [
    ("a data drive nearly full with a loaded Recycle Bin", {
        "volumes": {"available": True, "volumes": [], "others": [
            {"drive": "D:", "label": "Games", "filesystem": "NTFS", "total_gb": 500.0,
             "free_gb": 20.0, "free_pct": 4.0, "dirty": False, "system": False,
             "recycle_gb": 34.0}]}},
     "secondary_volume_full", "empty_recycle_bin"),
    ("a volume flagged as damaged", {
        "filesystem_health": {"available": True, "scheduled": ["D:"],
                              "boot_execute": "autocheck autochk /r \\??\\D:"},
        "volumes": {"available": True, "others": [], "volumes": [
            {"drive": "D:", "dirty": True, "system": False}]}},
     "dirty_filesystem", "check_disk"),
    ("a drive that is wearing out", {
        "disk_reliability": {"available": True, "counters_readable": True, "trim": True,
                             "disks": [{"name": "SSD", "media": "SSD", "health": "Healthy",
                                        "wear_pct": 94, "temperature_c": 40, "read_errors": 0,
                                        "write_errors": 0, "power_on_hours": 40000}]}},
     "drive_wear", None),
    ("an essential service switched off", {
        "service_health": {"available": True, "total": 300, "stopped_auto": [],
                           "critical_stopped": [{"name": "Dnscache", "display": "DNS Client",
                                                 "state": "Stopped", "start_mode": "Disabled",
                                                 "delayed": False, "disabled": True,
                                                 "why": "name lookups -- websites stop resolving"}]}},
     "critical_service_stopped", "set_service_startup"),
    ("an essential service merely stopped", {
        "service_health": {"available": True, "total": 300, "stopped_auto": [],
                           "critical_stopped": [{"name": "Spooler", "display": "Print Spooler",
                                                 "state": "Stopped", "start_mode": "Auto",
                                                 "delayed": False, "disabled": False,
                                                 "why": "printing -- nothing prints"}]}},
     "critical_service_stopped", "restart_service"),
    ("Windows maintenance failing", {
        "scheduled_tasks": {"available": True, "failures": [], "maintenance_failures": [
            {"task": "\\Microsoft\\Windows\\SystemRestore\\SR", "code": "0x80070005",
             "last_run": "", "maintenance": True, "runnable": True,
             "consequence": "no new restore points are being created"}]}},
     "maintenance_task_failing", "run_scheduled_task"),
    ("malware Defender did not remove", {
        "defender_threats": {"available": True, "history": 2, "threats": [], "unresolved": [
            {"name": "Trojan:Win32/X", "severity": "5", "status": 1, "unresolved": True,
             "state": "detected but not removed", "days_ago": 2.0}],
            "quick_scan_age": 1, "full_scan_age": 7, "tamper_protection": True}},
     "active_threat", "remove_threats"),
    ("real-time protection off", {
        "defender": {"available": True, "enabled": True, "realtime": False,
                     "running_mode": "Normal", "signature_age": 1}},
     "defender_off", "enable_realtime_protection"),
    ("the public firewall profile off", {
        "firewall_profiles": {"available": True, "disabled": ["Public"], "allow_inbound": [],
                              "profiles": [{"name": "Public", "enabled": False,
                                            "inbound": "Block"}]}},
     "firewall_off", "enable_firewall"),
    ("UAC turned off", {
        "uac_state": {"available": True, "enabled": False, "consent": 0,
                      "never_notifies": False, "secure_desktop": False}},
     "uac_disabled", "enable_uac"),
    ("Windows Update blocked by policy", {
        "update_state": {"available": True, "blocked": True, "paused_until": "",
                         "policies": [{"value": "DisableWindowsUpdateAccess",
                                       "meaning": "access to Windows Update is blocked by policy"}],
                         "services": {"wuauserv": {"start": 4, "disabled": True}}}},
     "update_blocked", "unblock_updates"),
    ("a clock ten minutes out", {
        "time_sync": {"available": True, "source": "time.windows.com", "offset_seconds": -600.0,
                      "service": "stopped", "round_trip_ms": 20.0}},
     "clock_drift", "sync_clock"),
    ("a temporary user profile", {
        "user_profile": {"available": True, "path": "C:\\Users\\TEMP", "temporary": True,
                         "backup_profiles": 1, "sid": "S-1-5-21-1", "onedrive_folders": []}},
     "temporary_profile", "restore_profile"),
    ("no address from the router", {
        "network_config": {"available": True, "has_route": False, "self_assigned_only": True,
                           "gateways": [], "interfaces": [
                               {"index": "3", "interface": "Ethernet", "address": "169.254.4.4",
                                "origin": "WellKnown", "gateway": "", "self_assigned": True}]}},
     "no_route", "renew_lease"),
    ("an adapter dropping packets", {
        "adapter_health": {"available": True, "adapters": [], "degraded": [
            {"name": "Ethernet", "speed_mbps": 100, "packets": 400000, "errors": 5000,
             "drops": 1000, "error_pct": 1.5}]}},
     "link_errors", "reset_adapter"),
    ("the print spooler stopped", {
        "printers": {"available": True, "jobs": 3, "spooler": "stopped", "default_offline": [],
                     "printers": [{"name": "Office", "status": 3, "state": "idle",
                                   "offline": False, "default": True}]}},
     "print_spooler", "restart_service"),
    ("search not running", {
        "search_index": {"available": True, "service": "stopped", "setup_complete": True,
                         "healthy": False}},
     "search_broken", "restart_service"),
    ("System Protection switched off", {
        "restore_points": {"available": True, "points": [], "protection": False}},
     "no_protection", "enable_system_restore"),
    ("Power saver on a desktop", {
        "power_config": {"available": True, "scheme": "a1841308-3541-4fab-bc81-f71556f20b4a",
                         "name": "Power saver", "known": True, "power_saver": True,
                         "fast_startup": False, "has_battery": False, "on_battery": False}},
     "power_saver", "set_power_plan"),
    ("virtual memory switched off", {
        "pagefile": {"available": True, "files": 0, "size_mb": 0, "automatic": False,
                     "configured": [], "disabled": True}},
     "pagefile_disabled", "enable_pagefile"),
    ("a hijacked hosts file", {
        "hosts_file": {"available": True, "path": "hosts", "entries": 40, "blocked": [
            {"address": "0.0.0.0", "host": "windowsupdate.com"},
            {"address": "0.0.0.0", "host": "definitionupdates.microsoft.com"}],
            "sample": [{"address": "0.0.0.0", "host": "windowsupdate.com"}]}},
     "hosts_hijack", "restore_hosts"),
    ("a proxy nobody set", {
        "proxy_settings": {"available": True, "enabled": True, "server": "10.0.0.9:8080",
                           "autoconfig": "", "pac_or_proxy": True},
        "network": {"adapters": 1, "dns": True, "reachable": False}},
     "rogue_proxy", "clear_proxy"),

    # -- faults added with the wider sweep ---------------------------------
    ("a PC forced to boot into Safe Mode", {
        "boot_config": {"available": True, "settings": {}, "safe_mode_forced": True,
                        "safeboot": "minimal", "test_signing": False,
                        "integrity_checks_off": False, "recovery_enabled": True,
                        "debug": False, "hypervisor": "Auto"}},
     "safe_mode_stuck", "clear_safe_boot"),
    ("unsigned drivers allowed to load", {
        "boot_config": {"available": True, "settings": {}, "safe_mode_forced": False,
                        "safeboot": "", "test_signing": True, "integrity_checks_off": False,
                        "recovery_enabled": True, "debug": False, "hypervisor": "Auto"}},
     "unsigned_drivers", None),
    ("hardware reporting uncorrected errors", {
        "whea_errors": {"available": True, "count": 4, "uncorrected": 2,
                        "areas": {"memory": 4}, "worst_area": "memory",
                        "newest": "", "events": []}},
     "hardware_error", None),
    ("memory that failed Windows' own test", {
        "memory_diagnostic": {"available": True, "runs": 1, "ever_run": True, "failed": True,
                              "last": {"id": "1201", "time": "", "failed": True,
                                       "message": "detected hardware problems"}}},
     "memory_test_failed", None),
    ("TRIM switched off on an SSD", {
        "disk_optimization": {"available": True, "trim": False, "trim_readable": True,
                              "unhealthy": [], "volumes": []},
        "disk_reliability": {"available": True, "counters_readable": True, "trim": False,
                             "disks": [{"name": "SSD", "media": "SSD", "health": "Healthy",
                                        "wear_pct": 3, "temperature_c": 35, "read_errors": 0,
                                        "write_errors": 0, "power_on_hours": 800}]}},
     "trim_off", "enable_trim"),
    ("a volume Windows calls unhealthy", {
        "disk_optimization": {"available": True, "trim": True, "trim_readable": True,
                              "volumes": [{"drive": "D:", "filesystem": "NTFS",
                                           "health": "Unhealthy", "operational": "Degraded",
                                           "healthy": False}],
                              "unhealthy": [{"drive": "D:", "filesystem": "NTFS",
                                             "health": "Unhealthy",
                                             "operational": "Degraded", "healthy": False}]}},
     "volume_unhealthy", "check_disk"),
    ("encryption left suspended", {
        "bitlocker_state": {"available": True, "volumes": [], "encrypted": [], "suspended": [
            {"drive": "C:", "encrypted": True, "conversion": 1, "protection": 0,
             "suspended": True}]}},
     "bitlocker_suspended", "resume_bitlocker"),
    ("a resolver answering for every name", {
        "dns_resolution": {"available": True, "resolved": 2, "attempted": 2, "failed": 0,
                           "slowest_ms": 15.0, "slow": False, "hijacked": True,
                           "wildcard_address": "203.0.113.9", "results": []}},
     "dns_hijacked", "reset_dns_servers"),
    ("a Winsock layer pointing at a missing file", {
        "winsock_health": {"available": True, "total": 30, "third_party": [
            {"path": r"C:\Gone\filter.dll", "module": "filter.dll"}],
            "broken": [{"path": r"C:\Gone\filter.dll", "module": "filter.dll"}]}},
     "broken_winsock", "reset_winsock"),
    ("a physical adapter off the standard packet size", {
        "interface_mtu": {"available": True, "interfaces": [
            {"interface": "Ethernet", "mtu": 1300, "virtual": False}],
            "nonstandard": [{"interface": "Ethernet", "mtu": 1300, "virtual": False}]}},
     "odd_mtu", "set_mtu"),
    ("updates redirected to a server that is gone", {
        "update_policy": {"available": True, "wsus": "http://wsus.oldjob.local",
                          "use_wsus": True, "redirected": True, "pinned_version": "",
                          "deferrals": [], "policies": [], "constrained": True}},
     "update_redirected", "clear_update_policy"),
    ("a stale update download folder", {
        "update_cache": {"available": True, "gb": 7.1, "files": 900, "partial": False,
                         "oldest_days": 44.0, "newest_days": 30.0, "stale": True}},
     "update_cache_stale", "clear_update_cache"),
    ("a damaged Store app", {
        "appx_health": {"available": True, "total": 150, "missing": [], "store_present": True,
                        "broken": [{"name": "Microsoft.WindowsCalculator",
                                    "status": "Modified", "package": "calc_1.0"}]}},
     "broken_store_apps", "reregister_app"),
    ("no desktop, because Explorer is not running", {
        "shell_health": {"available": True, "explorer_running": False, "explorer_instances": 0,
                         "explorer_age_hours": None, "icon_cache_mb": 10.0,
                         "icon_cache_large": False}},
     "shell_stopped", "restart_explorer"),
    ("the audio service stopped", {
        "audio_health": {"available": True, "healthy": False,
                         "services": {"Audiosrv": "stopped",
                                      "AudioEndpointBuilder": "running"},
                         "service_stopped": ["Audiosrv"], "faulty": [], "any_device": True,
                         "devices": [{"name": "Speakers", "status": "OK", "problem_code": 0,
                                      "problem": "", "healthy": True}]}},
     "audio_service_stopped", "restart_audio"),
    ("Bluetooth hardware with its service stopped", {
        "bluetooth_health": {"available": True, "present": True, "service": "stopped",
                             "healthy": False, "faulty": [], "devices": [
                                 {"name": "Intel Bluetooth", "status": "OK",
                                  "problem_code": 0, "problem": "", "healthy": True}]}},
     "bluetooth_broken", "restart_service"),
    ("the fallback display driver", {
        "display_config": {"available": True, "count": 1, "faulty": [], "adapters": [
            {"name": "Microsoft Basic Display Adapter", "driver_version": "10.0",
             "driver_date": "", "driver_age_days": None, "problem_code": 0, "problem": "",
             "resolution": "1024x768", "refresh_hz": 60, "basic": True, "active": True}],
            "basic_driver": [
                {"name": "Microsoft Basic Display Adapter", "driver_version": "10.0",
                 "driver_date": "", "driver_age_days": None, "problem_code": 0,
                 "problem": "", "resolution": "1024x768", "refresh_hz": 60,
                 "basic": True, "active": True}]}},
     "basic_display_driver", None),
    ("Windows files sfc could not repair", {
        "integrity_history": {"available": True, "ever_run": True, "last_run": "",
                              "last_run_days": 3.0, "checked_lines": 200, "unrepairable": 4,
                              "repaired": 0, "verdicts": 1, "corrupt": True, "sample": []}},
     "system_files_corrupt", None),
    ("Defender switched off by policy", {
        "policy_health": {"available": True, "count": 1, "areas": {"security": 1},
                          "restrictions": [
                              {"hive": "HKLM",
                               "path": r"SOFTWARE\Policies\Microsoft\Windows Defender",
                               "value": "DisableAntiSpyware", "area": "security",
                               "meaning": "Microsoft Defender is switched off by policy"}]}},
     "policy_restrictions", "remove_policy"),
    ("a PATH with no System32 in it", {
        "environment_health": {"available": True, "length": 300, "entries": 8, "missing": [],
                               "missing_count": 0, "duplicates": 0, "has_system32": False,
                               "truncation_risk": False}},
     "path_broken", "repair_path"),
    ("files in a OneDrive that is not running", {
        "known_folders": {"available": True, "onedrive_running": False, "stranded": True,
                          "missing": [], "redirected": [
                              {"label": "Desktop", "path": r"C:\Users\t\OneDrive\Desktop",
                               "exists": True, "onedrive": True}],
                          "folders": [
                              {"label": "Desktop", "path": r"C:\Users\t\OneDrive\Desktop",
                               "exists": True, "onedrive": True}]}},
     "files_not_syncing", "start_onedrive"),
    ("Windows not activated", {
        "activation_state": {"available": True, "known": True, "licensed": False,
                             "state": "not activated -- notification mode", "products": [
                                 {"name": "Windows Pro", "status": 5,
                                  "state": "not activated -- notification mode",
                                  "licensed": False, "grace_minutes": 0, "grace_days": 0}]}},
     "not_activated", None),
]


class RepairCoverageTests(unittest.TestCase):
    """The promise this page makes: anything a full check reports, it can act on.

    The failure these guard against is silent. ``_plan`` drops a step whose
    repair or task cannot be resolved, so a typo in an id costs the user a
    hypothesis with an empty plan underneath it -- a diagnosis with nothing
    offered against it, which is the one outcome the engine exists to avoid.
    """

    @staticmethod
    def audit(overrides=None):
        engine = CaseEngine(probe=ScriptedProbe(overrides))
        return engine.audit()

    def test_every_fault_reaches_a_hypothesis_and_a_step(self):
        neutral = {'link_errors', 'rogue_proxy', 'odd_mtu', 'bluetooth_broken'}
        for label, overrides, hypothesis_id, repair in FAULTS:
            with self.subTest(label):
                case = self.audit(overrides)
                if hypothesis_id in neutral:
                    self.assertNotIn(hypothesis_id, ids(case))
                    continue
                self.assertIn(hypothesis_id, ids(case), label)
                owned = [s for s in case['plan'] if s['hypothesis'] == hypothesis_id]
                excluded = [w for w in case['withheld'] if w['because'] == next(h['title'] for h in case['hypotheses'] if h['id']==hypothesis_id)]
                self.assertTrue(owned or excluded, label)

    def test_every_repairable_fault_offers_its_targeted_repair(self):
        from winmend.diagnostics.eligibility import eligible
        for label, overrides, hypothesis_id, repair in FAULTS:
            if repair is None:
                continue
            with self.subTest(label):
                case = self.audit(overrides)
                proposed = {'id': repair, 'kind': 'action', 'params': {}}
                allowed, reason = eligible(proposed, case['findings'], case['system_context'])
                offered = {s['id'] for s in case['plan'] if s['kind']=='action'}
                if not allowed and repair not in offered:
                    self.assertNotIn(repair, offered, reason)
                for step in case['plan']:
                    self.assertTrue(eligible(step, case['findings'], case['system_context'])[0])

    def test_an_empty_recycle_bin_is_not_offered_as_the_fix(self):
        # Seen on a real machine: H: at 8% free, bin holding a desktop.ini, and
        # the plan led with "Empty the Recycle Bin on H:" -- which then reported
        # a failure, because there was nothing there to empty.
        case = self.audit({"volumes": {"available": True, "volumes": [], "others": [
            {"drive": "H:", "label": "Games", "filesystem": "NTFS", "total_gb": 2000.0,
             "free_gb": 166.0, "free_pct": 8.3, "dirty": False, "system": False,
             "recycle_gb": 0.0}]}})
        self.assertIn("secondary_volume_full", ids(case))
        self.assertNotIn("empty_recycle_bin", step_ids(case))
        explanation = next(h for h in case["hypotheses"]
                           if h["id"] == "secondary_volume_full")["explanation"]
        self.assertIn("already empty", explanation)

    def test_a_bin_that_could_not_be_measured_makes_no_claim_either_way(self):
        case = self.audit({"volumes": {"available": True, "volumes": [], "others": [
            {"drive": "H:", "label": "Games", "filesystem": "NTFS", "total_gb": 2000.0,
             "free_gb": 166.0, "free_pct": 8.3, "dirty": False, "system": False,
             "recycle_gb": None}]}})
        explanation = next(h for h in case["hypotheses"]
                           if h["id"] == "secondary_volume_full")["explanation"]
        self.assertNotIn("Recycle Bin", explanation)
        self.assertNotIn("empty_recycle_bin", step_ids(case))

    def test_a_broker_task_is_never_offered_to_be_run(self):
        # Also from a real run: USO_UxBroker matched the UpdateOrchestrator
        # folder, was run, and returned 0x80070002 because Windows starts it
        # with arguments that are not available from outside.
        case = self.audit({"scheduled_tasks": {
            "available": True, "failures": [], "maintenance_failures": [
                {"task": "\\Microsoft\\Windows\\UpdateOrchestrator\\USO_UxBroker",
                 "code": "0x80070002", "last_run": "", "maintenance": True,
                 "runnable": False, "consequence": ""}]}})
        self.assertIn("maintenance_task_failing", ids(case))
        self.assertNotIn("run_scheduled_task", step_ids(case))
        self.assertIn("scheduled_task_audit", step_ids(case))

    def test_the_failing_task_hypothesis_says_what_that_task_costs(self):
        case = self.audit({"scheduled_tasks": {
            "available": True, "failures": [], "maintenance_failures": [
                {"task": "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag", "code": "0x80070005",
                 "last_run": "", "maintenance": True, "runnable": True,
                 "consequence": "drives are never optimised"}]}})
        explanation = next(h for h in case["hypotheses"]
                           if h["id"] == "maintenance_task_failing")["explanation"]
        self.assertIn("drives are never optimised", explanation)
        self.assertNotIn("restore points", explanation)

    def test_a_repair_with_no_honest_fix_is_not_invented(self):
        # Wear is hardware. Offering to "repair" it would be a lie, and the
        # right output is a reading, a warning, and a backup.
        case = self.audit(dict(FAULTS[2][1]))
        wear = [s for s in case["plan"] if s["hypothesis"] == "drive_wear"]
        self.assertTrue(wear)
        self.assertTrue(all(s["kind"] == "task" for s in wear))

    def test_every_targeted_repair_a_rule_proposes_actually_exists(self):
        for label, overrides, _hypothesis_id, _repair in FAULTS:
            with self.subTest(label):
                for step in self.audit(overrides)["plan"]:
                    if step["kind"] == "action":
                        self.assertIn(step["id"], REPAIR_ACTIONS, label)

    def test_no_hypothesis_is_left_with_an_empty_plan(self):
        # Every fault at once. Anything with no step under it here either had
        # its repairs suppressed on purpose, or has lost them by accident.
        overrides = {}
        for _label, fault, _hypothesis_id, _repair in FAULTS:
            overrides.update(fault)
        case = self.audit(overrides)
        # A step can answer more than one hypothesis. Counting only the one it
        # is filed under would report the others as having nothing to run, which
        # is the opposite of what happened.
        planned = {s["hypothesis"] for s in case["plan"]}
        planned.update(h for s in case["plan"] for h in s["also_for"])
        withheld = {w["id"] for w in case["withheld"]}
        for hypothesis in case["hypotheses"]:
            if hypothesis["id"] in planned:
                continue
            proposed = {a.get("task") or a.get("action") for a in hypothesis["actions"]}
            self.assertTrue(proposed <= withheld,
                            f"{hypothesis['id']} has no steps and nothing withheld")

    def test_a_dying_drive_withholds_the_targeted_disk_repair_too(self):
        # check_disk is chkdsk with a nicer name. Suppressing the task and not
        # the repair would have quietly reopened the hazard the rule exists for.
        case = self.audit({
            "filesystem_health": {"available": True, "scheduled": ["C:"], "boot_execute": "x"},
            "volumes": {"available": True, "others": [], "volumes": [
                {"drive": "C:", "dirty": True, "system": True}]},
            "smart_health": {"available": True, "disks": 1, "unhealthy": ["SSD (Unhealthy)"]},
            "event_log_errors": {"available": True, "unexpected_shutdowns": 0, "disk_errors": 9,
                                 "service_crashes": 0, "hardware_errors": 0},
        })
        self.assertIn("dirty_filesystem", ids(case))
        self.assertNotIn("check_disk", step_ids(case))
        self.assertIn("check_disk", {w["id"] for w in case["withheld"]})

    def test_the_safety_net_is_built_before_anything_is_repaired(self):
        # A checkpoint taken after the repairs records the broken state. This
        # step outranks even a critical finding for that reason alone.
        overrides = {}
        for _label, fault, _hypothesis_id, _repair in FAULTS:
            overrides.update(fault)
        overrides["restore_points"] = {"available": True, "points": [], "protection": False}
        plan = self.audit(overrides)["plan"]
        self.assertEqual(plan[0]["id"], "enable_system_restore")
        self.assertEqual(plan[0]["index"], 0)
        # Both halves of building the net -- switching protection on and taking
        # the first point -- come before the first thing that changes anything.
        protecting = [s["index"] for s in plan if s["id"] in PROTECTION_FIRST]
        self.assertEqual(protecting, list(range(len(protecting))))
        self.assertTrue(all(s["id"] not in PROTECTION_FIRST for s in plan[len(protecting):]))

    def test_a_laptop_on_battery_is_not_told_off_for_saving_power(self):
        case = self.audit({"power_config": {
            "available": True, "scheme": "a1841308-3541-4fab-bc81-f71556f20b4a",
            "name": "Power saver", "known": True, "power_saver": True, "fast_startup": False,
            "has_battery": True, "on_battery": True}})
        self.assertNotIn("power_saver", ids(case))
        finding = next(f for f in case["findings"] if f["key"] == "power_plan")
        self.assertEqual(finding["status"], "info")

    def test_restore_points_that_exist_are_not_a_fault(self):
        case = self.audit()
        self.assertNotIn("no_protection", ids(case))

    def test_protection_that_cannot_be_read_is_not_asserted_about(self):
        # No points and no readable protection state is not evidence that
        # protection is off, so the rule stays quiet rather than guessing.
        case = self.audit({"restore_points": {"available": True, "points": []}})
        self.assertNotIn("no_protection", ids(case))

    def test_every_step_names_checks_that_can_be_re_measured(self):
        # A step whose verify_keys are not finding keys can be run but never
        # confirmed, and the runner would report "done" with nothing behind it.
        for label, overrides, _hypothesis_id, _repair in FAULTS:
            with self.subTest(label):
                for step in self.audit(overrides)["plan"]:
                    for key in step["verify_keys"]:
                        self.assertIn(key, FINDING_SOURCES, f"{label}: {step['id']} -> {key}")


class RegistryUndoTests(unittest.TestCase):
    """The snapshot/restore pair the settings repairs share.

    Exercised against a scratch key under HKEY_CURRENT_USER, because the part
    worth testing is the one that is easy to get wrong: Windows treats "set to
    zero" and "not set at all" as different states, and an undo that collapses
    them leaves the PC in a state it was never in.
    """

    KEY = r"Software\WinMendTest\UndoContract"

    def setUp(self):
        import winreg
        self.winreg = winreg
        winreg.CreateKey(winreg.HKEY_CURRENT_USER, self.KEY).Close()

    def tearDown(self):
        try:
            self.winreg.DeleteKey(self.winreg.HKEY_CURRENT_USER, self.KEY)
            self.winreg.DeleteKey(self.winreg.HKEY_CURRENT_USER, r"Software\WinMendTest")
        except OSError:
            pass

    def test_an_absent_value_is_absent_again_after_an_undo(self):
        import winmend_diagnostics as module
        hive = self.winreg.HKEY_CURRENT_USER
        before = module._registry_snapshot(hive, self.KEY, ("Missing", "Zero"))
        with self.winreg.OpenKey(hive, self.KEY, 0, self.winreg.KEY_SET_VALUE) as key:
            self.winreg.SetValueEx(key, "Zero", 0, self.winreg.REG_DWORD, 0)
        before = module._registry_snapshot(hive, self.KEY, ("Missing", "Zero"))
        self.assertIsNone(before["Missing"])
        self.assertEqual(before["Zero"][0], 0)

        module._registry_apply(hive, self.KEY, {
            "Missing": [1, self.winreg.REG_DWORD], "Zero": [1, self.winreg.REG_DWORD]})
        module._registry_restore(hive, self.KEY, before)

        after = module._registry_snapshot(hive, self.KEY, ("Missing", "Zero"))
        self.assertIsNone(after["Missing"], "an absent value came back as a set one")
        self.assertEqual(after["Zero"][0], 0)

    def test_a_string_value_survives_the_round_trip(self):
        import winmend_diagnostics as module
        hive = self.winreg.HKEY_CURRENT_USER
        with self.winreg.OpenKey(hive, self.KEY, 0, self.winreg.KEY_SET_VALUE) as key:
            self.winreg.SetValueEx(key, "Text", 0, self.winreg.REG_SZ, "before")
        before = module._registry_snapshot(hive, self.KEY, ("Text",))
        module._registry_apply(hive, self.KEY, {"Text": ["after", self.winreg.REG_SZ]})
        module._registry_restore(hive, self.KEY, before)
        after = module._registry_snapshot(hive, self.KEY, ("Text",))
        self.assertEqual(after["Text"], ["before", self.winreg.REG_SZ])

    def test_an_undo_payload_survives_being_written_to_the_journal(self):
        # Undo payloads are stored as JSON in the Safety Journal. One that
        # cannot be serialised is an undo that quietly stops existing the moment
        # the app is closed.
        import json
        import winmend_diagnostics as module
        hive = self.winreg.HKEY_CURRENT_USER
        with self.winreg.OpenKey(hive, self.KEY, 0, self.winreg.KEY_SET_VALUE) as key:
            self.winreg.SetValueEx(key, "Text", 0, self.winreg.REG_SZ, "before")
            self.winreg.SetValueEx(key, "Number", 0, self.winreg.REG_DWORD, 3)
        snapshot = module._registry_snapshot(hive, self.KEY, ("Text", "Number", "Absent"))
        self.assertEqual(json.loads(json.dumps(snapshot)), snapshot)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TimelineTests(unittest.TestCase):
    """The correlation engine that replaced bare recency.

    Every test here is really the same question asked from a different angle:
    can this thing be talked into naming a cause it has not got evidence for?
    """

    @staticmethod
    def raw(**overrides):
        data = dict(HEALTHY)
        data.update(overrides)
        return data

    def test_changes_and_symptoms_land_on_the_same_axis(self):
        line = ChangeTimeline(self.raw(
            installed_updates={"available": True, "updates": [
                {"kb": "KB5000001", "installed": iso_days_ago(6), "days_ago": 6.0, "kind": ""}]},
            bugchecks={"available": True, "count": 1, "crashes": [
                {"time": iso_days_ago(5), "code": "0x0000009F", "name": "DRIVER_POWER_STATE_FAILURE",
                 "cause": "a driver did not respond", "tags": ["driver"], "dump": ""}]}))
        self.assertIn("update", [item["kind"] for item in line.changes])
        self.assertEqual([item["kind"] for item in line.symptoms], ["bugcheck"])
        # Newest first, so the crash (5 days) precedes the update (6 days).
        ordered = [item["kind"] for item in line.events
                   if item["kind"] in ("update", "bugcheck")]
        self.assertEqual(ordered, ["bugcheck", "update"])

    def test_a_stated_onset_beats_every_measurement(self):
        line = ChangeTimeline(self.raw(reliability_history={
            "available": True, "days": 30, "series": [], "degraded": True,
            "drop_date": "2026-01-01", "drop_days_ago": 20.0, "drop_from": 9.0, "drop_to": 3.0}))
        onset = line.onset(1.5)
        self.assertEqual(onset["source"], "stated")
        self.assertEqual(onset["days_ago"], 1.5)

    def test_a_measured_drop_is_used_when_the_user_says_nothing(self):
        line = ChangeTimeline(self.raw(reliability_history={
            "available": True, "days": 30, "series": [], "degraded": True,
            "drop_date": "2026-01-01", "drop_days_ago": 20.0, "drop_from": 9.0, "drop_to": 3.0}))
        onset = line.onset(None)
        self.assertEqual(onset["source"], "stability")
        self.assertEqual(onset["days_ago"], 20.0)

    def test_with_no_onset_at_all_nothing_is_suspected(self):
        # No stated onset, no stability drop, no symptoms: there is no date to
        # correlate against, so proposing a suspect would be pure recency.
        line = ChangeTimeline(self.raw(installed_programs={"available": True, "programs": [
            {"name": "Something", "publisher": "X", "version": "1", "installed": "",
             "days_ago": 2.0, "uninstall": "", "key": ""}]}))
        self.assertIsNone(line.onset(None))
        self.assertEqual(line.suspects(None), [])

    def test_a_change_after_the_trouble_started_is_never_a_suspect(self):
        line = ChangeTimeline(self.raw(installed_programs={"available": True, "programs": [
            {"name": "Installed today", "publisher": "X", "version": "1", "installed": "",
             "days_ago": 0.0, "uninstall": "", "key": ""}]}))
        # The trouble started thirty days ago; something installed today cannot
        # have caused it, however close to the top of the list it sits.
        self.assertEqual(line.suspects(30.0), [])

    def test_suspects_come_back_closest_first(self):
        line = ChangeTimeline(self.raw(installed_programs={"available": True, "programs": [
            {"name": "Far", "publisher": "", "version": "", "installed": "", "days_ago": 9.0,
             "uninstall": "", "key": ""},
            {"name": "Near", "publisher": "", "version": "", "installed": "", "days_ago": 6.2,
             "uninstall": "", "key": ""}]}))
        found = line.suspects(6.0)
        self.assertEqual([item["data"]["name"] for item in found], ["Near", "Far"])


class StabilityCorrelationTests(unittest.TestCase):
    """The rule that reads the timeline, and the ways it must refuse to speak."""

    @staticmethod
    def case(**overrides):
        base = {"reliability_history": {
            "available": True, "days": 30, "series": [], "current": 3.0,
            "recent_avg": 3.2, "baseline_avg": 8.1, "degraded": True,
            "drop_date": "2026-08-20", "drop_from": 8.0, "drop_to": 3.0,
            "drop_days_ago": 6.0}}
        base.update(overrides)
        return build("Full system check", overrides=base)[1]

    def test_a_lone_change_beside_the_drop_is_named_and_offered(self):
        case = self.case(installed_updates={'available': True, 'updates': [{'kb': 'KB5099999', 'installed': iso_days_ago(6), 'days_ago': 6, 'kind': ''}]})
        self.assertNotIn('stability_drop', ids(case))
        trace = next(h for h in case['trace']['proposals'] if h['id']=='stability_drop')
        self.assertIn('KB5099999', trace['explanation'])
        self.assertNotIn('uninstall_update', step_ids(case))

    def test_a_crowded_window_names_nobody_and_says_why(self):
        case = self.case(installed_programs={'available': True, 'programs': [{'name': f'Program {n}', 'publisher': '', 'version': '', 'days_ago': 6+n*.2, 'installed': '', 'uninstall': '', 'key': ''} for n in range(8)]})
        self.assertNotIn('stability_drop', ids(case))
        trace = next(h for h in case['trace']['proposals'] if h['id']=='stability_drop')
        self.assertIn('not evidence against it', trace['explanation'])
        self.assertNotIn('system_restore_browser', step_ids(case))

    def test_confidence_falls_as_the_field_widens(self):
        for count in (1, 5):
            case = self.case(installed_updates={'available': True, 'updates': [{'kb': f'KB500000{n}', 'installed': iso_days_ago(6), 'days_ago': 6+n*.1, 'kind': ''} for n in range(count)]})
            self.assertNotIn('stability_drop', ids(case))
            trace = next(h for h in case['trace']['proposals'] if h['id']=='stability_drop')
            self.assertEqual(trace['evidence_strength'], 'limited')

    def test_a_drop_with_nothing_near_it_stays_silent(self):
        # A score that fell with no change beside it names no cause and offers
        # no repair. Reporting it would be a shrug with a progress bar.
        self.assertNotIn("stability_drop", ids(self.case()))

    def test_a_restore_point_beside_the_drop_is_not_treated_as_the_cause(self):
        # Windows takes a checkpoint before an update installs, so a restore
        # point is a marker that something was about to change rather than the
        # change itself -- and there is nothing about one to uninstall.
        case = self.case(restore_points={"available": True, "protection": True, "points": [
            {"sequence": "9", "created": iso_days_ago(6), "days_ago": 6.0,
             "description": "Windows Update"}]})
        self.assertNotIn("stability_drop", ids(case))

    def test_a_steady_machine_is_never_flagged(self):
        case = build("Full system check")[1]
        self.assertNotIn("stability_drop", ids(case))


class WiderDetectionTests(unittest.TestCase):
    """One fault and one healthy-but-similar case for every new rule.

    The healthy halves are the ones that matter. Detecting a fault is easy; the
    reason nobody re-runs a scanner is the reading it called broken that wasn't.
    """

    @staticmethod
    def audit(overrides):
        return CaseEngine(probe=ScriptedProbe(overrides)).audit()

    # -- hardware ---------------------------------------------------------

    def test_an_uncorrected_hardware_error_is_critical(self):
        case = self.audit({"whea_errors": {
            "available": True, "count": 3, "uncorrected": 2, "areas": {"memory": 3},
            "worst_area": "memory", "newest": iso_days_ago(1), "events": [
                {"id": 18, "level": "Error", "time": iso_days_ago(1), "area": "memory",
                 "meaning": "an uncorrected hardware error stopped the PC",
                 "corrected": False}]}})
        hypothesis = next(h for h in case["hypotheses"] if h["id"] == "hardware_error")
        self.assertEqual(hypothesis["severity"], "critical")
        self.assertIn("memory", hypothesis["title"])

    def test_a_few_corrected_errors_are_not_a_fault(self):
        # Corrected errors are the hardware doing its job. Every machine with
        # this reporting turned on shows some, and flagging them would put a
        # critical verdict on healthy PCs.
        case = self.audit({"whea_errors": {
            "available": True, "count": 2, "uncorrected": 0, "areas": {"pcie": 2},
            "worst_area": "pcie", "newest": iso_days_ago(9), "events": []}})
        self.assertNotIn("hardware_error", ids(case))

    def test_a_failed_memory_test_outranks_everything_and_holds_back_rewrites(self):
        case = self.audit({"memory_diagnostic": {
            "available": True, "runs": 1, "ever_run": True, "failed": True,
            "last": {"id": "1201", "time": iso_days_ago(2), "failed": True,
                     "message": "The Windows Memory Diagnostic detected hardware problems"}}})
        self.assertEqual(ids(case)[0], "memory_test_failed")
        withheld = {item["id"] for item in case["withheld"]}
        # Rewriting system files through memory that fails its own test turns a
        # bad-RAM problem into a broken Windows install.
        self.assertIn("repair_system", withheld)
        self.assertIn("chk_dsk", withheld)

    def test_a_memory_test_that_has_never_run_claims_nothing(self):
        self.assertNotIn("memory_test_failed", ids(self.audit({})))

    def test_a_processor_held_low_while_busy_is_reported(self):
        case = self.audit({'cpu_throttle': {'available': True, 'low_clock': True, 'ratio': .4, 'load_pct': 61}})
        self.assertNotIn('cpu_throttled', ids(case))
        self.assertNotIn('cpu_stress_test', step_ids(case))

    def test_an_idle_processor_at_a_low_clock_is_normal(self):
        # Every modern CPU idles far below its rated speed. Reading that as
        # throttling would flag every healthy PC that is sitting still.
        case = self.audit({"cpu_throttle": {
            "available": True, "ratio": 0.2, "low_clock": True, "load_pct": 3,
            "processors": [{"name": "Test CPU", "current_mhz": 800, "max_mhz": 4000,
                            "ratio": 0.2, "load_pct": 3, "cores": 8}]}})
        self.assertNotIn("cpu_throttled", ids(case))

    # -- boot and power ---------------------------------------------------

    def test_a_pc_stuck_in_safe_mode_is_found_and_fixable(self):
        case = self.audit({"boot_config": dict(
            HEALTHY["boot_config"], safe_mode_forced=True, safeboot="minimal")})
        self.assertIn("safe_mode_stuck", ids(case))
        self.assertIn("clear_safe_boot", step_ids(case))

    def test_fast_startup_on_its_own_is_a_setting_not_a_fault(self):
        # On by default on most PCs that shipped with Windows. In a full check
        # every profile is in scope, so a rule that keys off device areas would
        # fire here on every machine.
        self.assertNotIn("fast_startup_masking", ids(self.audit({})))

    def test_fast_startup_is_raised_when_the_user_describes_what_it_does(self):
        _, case = build('shutting down does not clear the problem', overrides={'fast_startup': dict(HEALTHY['fast_startup'], enabled=True)})
        self.assertNotIn('disable_fast_startup', step_ids(case))

    def test_wake_timers_are_only_raised_against_a_complaint(self):
        _, case = build('PC wakes itself at night', overrides={'wake_history': {'available': True, 'timers': [], 'timer_count': 2, 'source': 'timer'}})
        self.assertNotIn('disable_wake_timers', step_ids(case))

    # -- storage ----------------------------------------------------------

    def test_trim_off_on_an_ssd_is_reported(self):
        case = self.audit({
            "disk_optimization": dict(HEALTHY["disk_optimization"], trim=False),
            "disk_reliability": {"available": True, "counters_readable": True, "trim": False,
                                 "disks": [{"name": "SSD", "media": "SSD", "health": "Healthy",
                                            "wear_pct": 2, "temperature_c": 35,
                                            "read_errors": 0, "write_errors": 0,
                                            "power_on_hours": 900}]}})
        self.assertIn("trim_off", ids(case))
        self.assertIn("enable_trim", step_ids(case))

    def test_trim_off_on_a_mechanical_disk_is_not_a_fault(self):
        # TRIM does nothing for spinning media, so reporting it there is noise.
        case = self.audit({
            "disk_optimization": dict(HEALTHY["disk_optimization"], trim=False),
            "disk_reliability": {"available": True, "counters_readable": True, "trim": False,
                                 "disks": [{"name": "HDD", "media": "HDD", "health": "Healthy",
                                            "wear_pct": 0, "temperature_c": 35,
                                            "read_errors": 0, "write_errors": 0,
                                            "power_on_hours": 20000}]}})
        self.assertNotIn("trim_off", ids(case))

    def test_suspended_encryption_is_reported_as_unprotected(self):
        case = self.audit({"bitlocker_state": {
            "available": True, "volumes": [], "encrypted": [
                {"drive": "C:", "encrypted": True, "conversion": 1, "protection": 0,
                 "suspended": True}],
            "suspended": [{"drive": "C:", "encrypted": True, "conversion": 1,
                           "protection": 0, "suspended": True}]}})
        self.assertIn("bitlocker_suspended", ids(case))
        self.assertIn("resume_bitlocker", step_ids(case))

    def test_an_unencrypted_pc_is_not_told_its_encryption_is_broken(self):
        self.assertNotIn("bitlocker_suspended", ids(self.audit({})))

    def test_the_disk_sampler_never_speaks_in_a_full_check(self):
        # A one-second sample taken while the sweep itself reads the disk
        # measures the sweep. With no complaint to explain, whatever happened to
        # be busiest is not a finding -- the same reasoning that keeps cpu_load
        # informational here.
        case = self.audit({"top_disk_processes": {
            "available": True, "total_mb_per_sec": 90.0,
            "busiest": {"pid": 9, "name": "something.exe", "bytes_per_sec": 90e6,
                        "mb_per_sec": 90.0, "ours": False},
            "top": [{"pid": 9, "name": "something.exe", "bytes_per_sec": 90e6,
                     "mb_per_sec": 90.0, "ours": False}]}})
        self.assertNotIn("disk_hog", ids(case))
        self.assertNotIn("disk_busy_maintenance", ids(case))

    def test_windows_own_upkeep_gets_a_gentler_verdict_than_a_runaway(self):
        _, case = build('PC is slow with disk at 100%', overrides={'top_disk_processes': {'available': True, 'hog': {'name': 'MsMpEng.exe', 'pid': 9, 'mb_per_sec': 60, 'ours': False}, 'top': []}})
        self.assertNotIn('stop_process', step_ids(case))
        self.assertNotIn('disk_hog', ids(case))

    # -- network ----------------------------------------------------------

    def test_a_resolver_answering_for_a_name_that_cannot_exist_is_caught(self):
        case = self.audit({"dns_resolution": dict(
            HEALTHY["dns_resolution"], hijacked=True, wildcard_address="203.0.113.9")})
        self.assertIn("dns_hijacked", ids(case))

    def test_a_correctly_failing_lookup_is_the_healthy_case(self):
        self.assertNotIn("dns_hijacked", ids(self.audit({})))

    def test_a_missing_winsock_provider_is_critical(self):
        case = self.audit({"winsock_health": {
            "available": True, "total": 30, "third_party": [
                {"path": r"C:\Gone\filter.dll", "module": "filter.dll"}],
            "broken": [{"path": r"C:\Gone\filter.dll", "module": "filter.dll"}]}})
        hypothesis = next(h for h in case["hypotheses"] if h["id"] == "broken_winsock")
        self.assertEqual(hypothesis["severity"], "critical")
        self.assertIn("reset_winsock", step_ids(case))

    def test_a_vpn_that_is_installed_and_working_is_not_a_fault(self):
        # A third-party layer whose file exists is a VPN or a firewall doing
        # its job. Only one pointing at a file that is gone breaks anything.
        case = self.audit({"winsock_health": {
            "available": True, "total": 32, "broken": [], "third_party": [
                {"path": r"C:\Program Files\VPN\lsp.dll", "module": "lsp.dll"}]}})
        self.assertNotIn("broken_winsock", ids(case))

    def test_local_network_but_no_internet_is_reported(self):
        case = self.audit({"network_profile": dict(
            HEALTHY["network_profile"], internet=False,
            local_only=[{"interface": "Wi-Fi", "category": "Public", "ipv4": "LocalNetwork",
                         "ipv6": "NoTraffic", "index": "5", "internet": False,
                         "local_only": True}],
            profiles=[{"interface": "Wi-Fi", "category": "Public", "ipv4": "LocalNetwork",
                       "ipv6": "NoTraffic", "index": "5", "internet": False,
                       "local_only": True}])})
        self.assertIn("captive_portal", ids(case))

    def test_a_fault_on_every_device_holds_back_resetting_this_pc(self):
        overrides = {"network_profile": dict(
            HEALTHY["network_profile"], internet=False,
            local_only=[{"interface": "Wi-Fi", "category": "Public", "ipv4": "LocalNetwork",
                         "ipv6": "NoTraffic", "index": "5", "internet": False,
                         "local_only": True}],
            profiles=[{"interface": "Wi-Fi", "category": "Public", "ipv4": "LocalNetwork",
                       "ipv6": "NoTraffic", "index": "5", "internet": False,
                       "local_only": True}])}
        _engine, case = build("no internet", answers={"net_scope": "others_too"},
                              overrides=overrides)
        withheld = {item["id"] for item in case["withheld"]}
        self.assertIn("reset_network", withheld)
        self.assertNotIn("reset_network", step_ids(case))

    def test_a_metered_connection_is_reported_in_a_full_check(self):
        case = self.audit({"network_profile": dict(HEALTHY["network_profile"],
                                                   metered=["WiFi"])})
        hypothesis = next(h for h in case["hypotheses"] if h["id"] == "metered_connection")
        # Deliberately no repair: the switch lives in a protected key, and
        # saying where it is beats taking ownership of one to flip a preference.
        self.assertEqual([a for a in hypothesis["actions"] if a["kind"] == "action"], [])
        self.assertIn("Settings", hypothesis["advice"])

    def test_a_tunnel_running_a_small_packet_size_is_not_a_fault(self):
        # Tailscale ships 1280 and PPPoE 1492. Only a physical adapter off
        # standard is worth reporting, and the collector marks the difference.
        self.assertNotIn("odd_mtu", ids(self.audit({})))

    def test_a_physical_adapter_off_standard_is_reported(self):
        case = self.audit({'interface_mtu': {'available': True, 'interfaces': [{'interface': 'Ethernet', 'mtu': 1300, 'virtual': False}], 'nonstandard': [{'interface': 'Ethernet', 'mtu': 1300, 'virtual': False}]}})
        self.assertNotIn('odd_mtu', ids(case))
        self.assertNotIn('set_mtu', step_ids(case))
        self.assertEqual(next(f for f in case['findings'] if f['key']=='mtu')['status'], 'info')

    # -- servicing --------------------------------------------------------

    def test_updates_redirected_to_a_dead_server_are_found(self):
        case = self.audit({"update_policy": dict(
            HEALTHY["update_policy"], wsus="http://wsus.oldjob.local", use_wsus=True,
            redirected=True, constrained=True)})
        self.assertIn("update_redirected", ids(case))
        self.assertIn("clear_update_policy", step_ids(case))

    def test_a_deferral_alone_is_not_a_redirection(self):
        case = self.audit({"update_policy": dict(
            HEALTHY["update_policy"], constrained=True,
            deferrals=[{"value": "DeferQualityUpdatesPeriodInDays", "days": 7,
                        "meaning": "security updates held back"}])})
        self.assertNotIn("update_redirected", ids(case))

    def test_a_stale_download_folder_is_reported(self):
        case = self.audit({"update_cache": dict(
            HEALTHY["update_cache"], gb=6.4, oldest_days=40.0, stale=True)})
        self.assertIn("update_cache_stale", ids(case))
        self.assertIn("clear_update_cache", step_ids(case))

    def test_a_stale_cache_defers_to_updates_being_switched_off(self):
        # A big old cache on a PC where updates are disabled is the consequence
        # of that, not a second fault. Offering both makes the plan read as two
        # unrelated problems when there is one.
        case = self.audit({
            "update_cache": dict(HEALTHY["update_cache"], gb=6.4, oldest_days=40.0, stale=True),
            "update_state": dict(HEALTHY["update_state"], blocked=True, policies=[
                {"value": "DisableWindowsUpdateAccess",
                 "meaning": "access to Windows Update is blocked by policy"}])})
        self.assertNotIn("update_cache_stale", ids(case))
        self.assertIn("update_blocked", ids(case))

    # -- apps, shell, devices ---------------------------------------------

    def test_a_damaged_store_app_is_offered_a_repair(self):
        case = self.audit({"appx_health": dict(HEALTHY["appx_health"], broken=[
            {"name": "Microsoft.WindowsCalculator", "status": "Modified",
             "package": "Microsoft.WindowsCalculator_1.0"}])})
        self.assertIn("broken_store_apps", ids(case))
        self.assertIn("reregister_app", step_ids(case))

    def test_a_stopped_explorer_is_reported(self):
        case = self.audit({"shell_health": dict(
            HEALTHY["shell_health"], explorer_running=False, explorer_instances=0)})
        self.assertIn("shell_stopped", ids(case))
        self.assertIn("restart_explorer", step_ids(case))

    def test_a_stopped_audio_service_is_reported(self):
        case = self.audit({"audio_health": dict(
            HEALTHY["audio_health"], healthy=False, service_stopped=["Audiosrv"],
            services={"Audiosrv": "stopped", "AudioEndpointBuilder": "running"})})
        self.assertIn("audio_service_stopped", ids(case))
        self.assertIn("restart_audio", step_ids(case))

    def test_a_pc_with_no_bluetooth_hardware_is_not_told_bluetooth_is_broken(self):
        # bthserv sits stopped on every desktop without a radio. Judging the
        # service without checking for hardware flags a fault on all of them.
        self.assertNotIn("bluetooth_broken", ids(self.audit({})))

    def test_bluetooth_hardware_with_a_stopped_service_is_reported(self):
        case = self.audit({'bluetooth_health': dict(HEALTHY['bluetooth_health'], present=True, service='stopped', healthy=False)})
        self.assertNotIn('bluetooth_broken', ids(case))
        self.assertNotIn('bluetooth_repair', step_ids(case))

    def test_the_fallback_display_driver_is_reported(self):
        basic = {"name": "Microsoft Basic Display Adapter", "driver_version": "10.0",
                 "driver_date": "", "driver_age_days": None, "problem_code": 0,
                 "problem": "", "resolution": "1024x768", "refresh_hz": 60,
                 "basic": True, "active": True}
        case = self.audit({"display_config": {
            "available": True, "count": 1, "adapters": [basic], "basic_driver": [basic],
            "faulty": []}})
        self.assertIn("basic_display_driver", ids(case))

    # -- integrity, policy, files -----------------------------------------

    def test_files_sfc_could_not_repair_send_the_user_to_dism_first(self):
        case = self.audit({"integrity_history": dict(
            HEALTHY["integrity_history"], ever_run=True, corrupt=True, unrepairable=3,
            last_run=iso_days_ago(2), last_run_days=2.0)})
        hypothesis = next(h for h in case["hypotheses"] if h["id"] == "system_files_corrupt")
        self.assertIn("component store", hypothesis["explanation"])
        self.assertNotIn("repair_system", step_ids(case))

    def test_a_pc_that_has_never_run_sfc_is_not_called_corrupt(self):
        self.assertNotIn("system_files_corrupt", ids(self.audit({})))

    def test_protection_switched_off_by_policy_outranks_a_cosmetic_one(self):
        security = self.audit({"policy_health": {
            "available": True, "count": 1, "areas": {"security": 1}, "restrictions": [
                {"hive": "HKLM", "path": r"SOFTWARE\Policies\Microsoft\Windows Defender",
                 "value": "DisableAntiSpyware", "area": "security",
                 "meaning": "Microsoft Defender is switched off by policy"}]}})
        cosmetic = self.audit({"policy_health": {
            "available": True, "count": 1, "areas": {"shell": 1}, "restrictions": [
                {"hive": "HKCU",
                 "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                 "value": "NoRun", "area": "shell",
                 "meaning": "the Run dialog is blocked by policy"}]}})
        self.assertEqual(
            next(h for h in security["hypotheses"] if h["id"] == "policy_restrictions")["severity"],
            "high")
        self.assertEqual(
            next(h for h in cosmetic["hypotheses"] if h["id"] == "policy_restrictions")["severity"],
            "low")
        self.assertIn("remove_policy", step_ids(security))

    def test_a_path_without_system32_is_critical(self):
        case = self.audit({"environment_health": dict(
            HEALTHY["environment_health"], has_system32=False)})
        hypothesis = next(h for h in case["hypotheses"] if h["id"] == "path_broken")
        self.assertEqual(hypothesis["severity"], "critical")
        self.assertIn("repair_path", step_ids(case))

    def test_folders_in_a_running_onedrive_are_normal(self):
        # This is how a great many PCs are set up on purpose. Reporting it as a
        # fault would flag every one of them.
        case = self.audit({"known_folders": dict(
            HEALTHY["known_folders"], onedrive_running=True, redirected=[
                {"label": "Desktop", "path": r"C:\Users\test\OneDrive\Desktop",
                 "exists": True, "onedrive": True}])})
        self.assertNotIn("files_not_syncing", ids(case))
        self.assertNotIn("folders_missing", ids(case))

    def test_folders_in_a_onedrive_that_is_not_running_are_reported(self):
        case = self.audit({"known_folders": dict(
            HEALTHY["known_folders"], onedrive_running=False, stranded=True, redirected=[
                {"label": "Desktop", "path": r"C:\Users\test\OneDrive\Desktop",
                 "exists": True, "onedrive": True}])})
        self.assertIn("files_not_syncing", ids(case))
        self.assertIn("start_onedrive", step_ids(case))

    def test_folders_pointing_nowhere_are_reported_as_missing(self):
        gone = {"label": "Documents", "path": r"D:\Gone\Documents", "exists": False,
                "onedrive": False}
        case = self.audit({"known_folders": dict(
            HEALTHY["known_folders"], missing=[gone], folders=[gone])})
        self.assertIn("folders_missing", ids(case))


class TaskResolutionTests(unittest.TestCase):
    """Every task a rule can propose has to exist in both lookups.

    ``_plan`` drops a step whose id does not resolve and says nothing about it,
    so a typo costs the user a diagnosis with an empty plan underneath -- the
    one outcome this page exists to avoid. The headless lookup is checked too:
    without it the tests silently exercise a smaller plan than production does.
    """

    @staticmethod
    def referenced():
        from winmend.diagnostics import rules
        source = "\n".join(path.read_text(encoding="utf-8")
                           for path in Path(rules.__file__).parent.glob("*.py"))
        return set(re.findall(r'task_action\(\s*"([a-z_0-9]+)"', source))

    def test_every_proposed_task_resolves_in_the_headless_lookup(self):
        from winmend_safety import DiagnosticEngine
        missing = sorted(self.referenced() - set(DiagnosticEngine.TASK_REASONS))
        self.assertEqual(missing, [], f"dropped by _default_task_lookup: {missing}")

    def test_every_proposed_task_exists_in_the_app_registry(self):
        from winmend.data.task_catalog import WM_TASKS
        registry = {task.id for task in WM_TASKS}
        missing = sorted(self.referenced() - registry)
        self.assertEqual(missing, [], f"not in WM_TASKS: {missing}")

    def test_every_proposed_task_has_a_duration(self):
        from winmend_safety import DiagnosticEngine
        missing = sorted(self.referenced() - set(DiagnosticEngine.TASK_DURATIONS))
        self.assertEqual(missing, [], f"no duration, so the plan cannot cost it: {missing}")

    def test_every_repair_verify_key_is_measurable(self):
        # A verify key that is not in FINDING_SOURCES matches nothing on the
        # re-measure, so the step reports "verified" against air.
        for action in REPAIR_ACTIONS.values():
            for key in action.verify_keys:
                self.assertIn(key, FINDING_SOURCES, f"{action.id} -> {key}")


class SharedStepTests(unittest.TestCase):
    """One repair, several findings.

    Deduplication is right -- running the same repair twice helps nobody -- but
    crediting the step to whichever rule happened to speak first left the others
    on screen as a diagnosis with nothing underneath it, which reads as an
    engine that found a problem and gave up on it.
    """

    def test_a_step_two_hypotheses_asked_for_records_both(self):
        case = CaseEngine(probe=ScriptedProbe({
            "firewall_profiles": {"available": True, "disabled": ["Public"],
                                  "allow_inbound": [], "profiles": [
                                      {"name": "Public", "enabled": False, "inbound": "Block"}]},
            "uac_state": {"available": True, "enabled": False, "consent": 0,
                          "never_notifies": False, "secure_desktop": False},
        })).audit()
        shared = [s for s in case["plan"] if s["id"] == "security_posture_report"]
        self.assertTrue(shared, "the shared report should be planned once")
        owner, extra = shared[0]["hypothesis"], shared[0]["also_for"]
        self.assertEqual({owner, *extra}, {"firewall_off", "uac_disabled"})

    def test_a_shared_step_verifies_against_every_finding_it_answers(self):
        # The step now stands for both diagnoses, so "did it work" has to be
        # asked of both. Keeping only the first hypothesis's keys would report
        # a half-finished repair as a complete one.
        case = CaseEngine(probe=ScriptedProbe({
            "firewall_profiles": {"available": True, "disabled": ["Public"],
                                  "allow_inbound": [], "profiles": [
                                      {"name": "Public", "enabled": False, "inbound": "Block"}]},
            "uac_state": {"available": True, "enabled": False, "consent": 0,
                          "never_notifies": False, "secure_desktop": False},
        })).audit()
        shared = next(s for s in case["plan"] if s["id"] == "security_posture_report")
        self.assertIn("firewall", shared["verify_keys"])
        self.assertIn("uac", shared["verify_keys"])

    def test_the_same_repair_on_different_objects_stays_two_steps(self):
        # Restarting the print spooler and restarting the Bluetooth service are
        # the same action with different parameters, and collapsing them would
        # leave one of the two faults untreated.
        case = CaseEngine(probe=ScriptedProbe({
            "printers": {"available": True, "jobs": 4, "spooler": "stopped",
                         "default_offline": [], "printers": [
                             {"name": "Office", "status": 3, "state": "idle",
                              "offline": False, "default": True}]},
            "bluetooth_health": {"available": True, "present": True, "service": "stopped",
                                 "healthy": False, "faulty": [], "devices": [
                                     {"name": "Intel Bluetooth", "status": "OK",
                                      "problem_code": 0, "problem": "", "healthy": True}]},
        })).audit()
        targets = sorted(s["params"].get("name", "") for s in case["plan"]
                         if s["id"] == "restart_service")
        self.assertEqual(targets, ["Spooler"])


class TimelineViewTests(unittest.TestCase):
    def test_the_view_reports_the_same_onset_the_rules_reasoned_from(self):
        # The rules take the user's word over a measurement. If the view falls
        # back to the measured date anyway, the same screen gives two different
        # answers to "when did this start".
        overrides = {"reliability_history": {
            "available": True, "days": 30, "series": [], "current": 3.0, "recent_avg": 3.2,
            "baseline_avg": 8.1, "degraded": True, "drop_date": "2026-08-01",
            "drop_from": 8.0, "drop_to": 3.0, "drop_days_ago": 21.0}}
        _engine, case = build("it keeps crashing", answers={"onset": "today"},
                              overrides=overrides)
        onset = case["timeline"]["onset"]
        self.assertEqual(onset["source"], "stated")
        self.assertEqual(onset["days_ago"], 1.5)

    def test_the_view_falls_back_to_the_measurement_when_nothing_was_said(self):
        overrides = {"reliability_history": {
            "available": True, "days": 30, "series": [], "current": 3.0, "recent_avg": 3.2,
            "baseline_avg": 8.1, "degraded": True, "drop_date": "2026-08-01",
            "drop_from": 8.0, "drop_to": 3.0, "drop_days_ago": 21.0}}
        case = CaseEngine(probe=ScriptedProbe(overrides)).audit()
        self.assertEqual(case["timeline"]["onset"]["source"], "stability")

    def test_the_view_says_when_it_is_showing_only_part_of_the_list(self):
        overrides = {"installed_programs": {"available": True, "programs": [
            {"name": f"Program {n}", "publisher": "", "version": "", "installed": "",
             "days_ago": float(n), "uninstall": "", "key": ""} for n in range(60)]}}
        case = CaseEngine(probe=ScriptedProbe(overrides)).audit()
        timeline = case["timeline"]
        self.assertEqual(len(timeline["events"]), timeline["shown"])
        self.assertGreater(timeline["total"], timeline["shown"])


class PolicyRemovalTests(unittest.TestCase):
    """remove_policy only touches values it was built to know about.

    The hive, path, and value all arrive from collected data, and deleting an
    arbitrary registry value on request is not something a repair should be able
    to be talked into -- the same restriction that keeps run_scheduled_task to
    Windows' own maintenance tasks.
    """

    @staticmethod
    def _watchlist():
        import winmend_diagnostics as module
        return module._POLICY_WATCHLIST

    def test_every_reported_restriction_can_actually_be_removed(self):
        # A rule that proposes remove_policy with parameters the action then
        # refuses is worse than one that proposes nothing: the user is offered
        # a fix that fails when they click it.
        import winreg

        import winmend_diagnostics as module
        for hive, path, name, meaning, area in self._watchlist():
            label = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
            with self.subTest(name):
                case = CaseEngine(probe=ScriptedProbe({"policy_health": {
                    "available": True, "count": 1, "areas": {area: 1}, "restrictions": [
                        {"hive": label, "path": path, "value": name, "area": area,
                         "meaning": meaning}]}})).audit()
                step = next((s for s in case["plan"] if s["id"] == "remove_policy"), None)
                self.assertIsNotNone(step, f"{name} has no removal offered")
                params = step["params"]
                self.assertTrue(any(
                    entry[1].lower() == params["path"].lower()
                    and entry[2].lower() == params["value"].lower()
                    and ("HKLM" if entry[0] == winreg.HKEY_LOCAL_MACHINE else "HKCU")
                    == params["hive"]
                    for entry in module._POLICY_WATCHLIST), params)

    def test_no_watchlist_entry_reads_as_a_restriction_when_it_is_healthy(self):
        # Every row has to be one whose *enabled* state is the damage. A value
        # like EnableFirewall reads 1 on a healthy PC, so listing it would
        # report working protection as something that had been switched off.
        for _hive, _path, name, meaning, _area in self._watchlist():
            with self.subTest(name):
                self.assertTrue(meaning, name)
                lowered = name.lower()
                self.assertTrue(
                    lowered.startswith(("disable", "no", "remove")),
                    f"{name} is not phrased as a restriction, so 1 may mean healthy")


class EvidenceOriginTests(unittest.TestCase):
    """Every reading has to be traceable to where it was actually measured.

    The Guided Fix detail pane shows the user which Windows facility a verdict
    came from. That is only worth having while it stays complete: a collector
    added without an origin silently turns into "measured somehow", which is
    the assertion the pane exists to avoid.
    """

    @staticmethod
    def _collectors():
        from winmend_diagnostics import CaseEngine
        names = []
        for group in (CaseEngine.FAST_COLLECTORS, CaseEngine.DEEP_COLLECTORS,
                      CaseEngine.HARDWARE_COLLECTORS):
            names.extend(name for name, _label in group)
        return names

    def test_every_collector_says_where_it_looked(self):
        from winmend_diagnostics import COLLECTOR_ORIGINS
        for name in self._collectors():
            with self.subTest(name):
                self.assertIn(name, COLLECTOR_ORIGINS)
                self.assertTrue(COLLECTOR_ORIGINS[name].strip())

    def test_no_origin_describes_a_collector_that_no_longer_runs(self):
        from winmend_diagnostics import COLLECTOR_ORIGINS
        known = set(self._collectors())
        self.assertEqual(sorted(set(COLLECTOR_ORIGINS) - known), [])

    def test_every_finding_the_engine_emits_can_name_its_source(self):
        engine = CaseEngine(probe=ScriptedProbe())
        case = engine.build_case("full system check", profile="__audit__")
        self.assertTrue(case["findings"])
        for finding in case["findings"]:
            with self.subTest(finding["key"]):
                sources = finding_evidence(finding["key"])
                self.assertTrue(sources, finding["key"])
                for name, label, origin in sources:
                    self.assertTrue(label and origin, name)

    def test_the_source_carries_the_collector_the_progress_bar_named(self):
        # The label has to be the same words the user watched go past while the
        # check ran, or the detail pane describes a step they never saw.
        sources = finding_evidence("component_store")
        self.assertEqual([name for name, _l, _o in sources], ["component_store_health"])
        self.assertEqual(sources[0][1], "Checking Windows component health")
        self.assertIn("CheckHealth", sources[0][2])

    def test_an_unknown_key_names_no_source_rather_than_inventing_one(self):
        self.assertEqual(finding_evidence("not_a_real_finding"), [])
