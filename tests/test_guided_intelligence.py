import json
import unittest
from copy import deepcopy
from unittest.mock import patch

from guided_scenarios import BASE, SCENARIOS, RecordedProbe, internet, load
from winmend.diagnostics.engine import CaseEngine
from winmend.diagnostics.eligibility import eligible, repair_identity
from winmend.diagnostics.models import Hypothesis
from winmend.diagnostics.context import Context
from winmend.diagnostics.reasoning import evaluate
from winmend.diagnostics.verification import compare
from winmend.diagnostics.symptoms import interpret
from winmend.diagnostics.interview import Interview
from winmend.diagnostics.collectors.deep import DeepProbe
from winmend.reports.case import render_case_report_html


def run_case(problem, overrides=None, profile=None, answers=None):
    probe = RecordedProbe(overrides)
    engine = CaseEngine(probe)
    return engine, engine.build_case(problem, profile=profile, answers=answers)


class LabeledFlowTests(unittest.TestCase):
    pass


def scenario_test(scenario):
    name, problem, data, expected, forbidden = scenario
    def test(self):
        profile = "audit" if name == "healthy_audit" else "hardware" if name in (
            "sampled_reads", "allocated_memory", "hardware_denied") else None
        engine, case = run_case(problem, data, profile=profile)
        ids = [h["id"] for h in case["hypotheses"]]
        if expected:
            self.assertTrue(set(expected) & set(ids[:3]), (name, ids, case["trace"]["rule_errors"]))
        else:
            self.assertEqual(ids, [], (name, ids))
        proposed = [s["id"] for s in case["plan"]]
        self.assertFalse(set(forbidden) & set(proposed), (name, proposed))
        for hypothesis in case["hypotheses"]:
            self.assertTrue(hypothesis["supporting"])
            self.assertNotIn("%", case["summary"])
        for step in case["plan"]:
            permitted, reason = eligible(step, case["findings"], case["system_context"])
            self.assertTrue(permitted, reason)
        repeated = engine.build_case(problem, profile=profile, answers=case["answers"])
        self.assertEqual([h["id"] for h in repeated["hypotheses"]], ids)
        self.assertEqual(compare(case, repeated)["condition_outcome"], "not_resolved" if any(
            f["status"] in ("warn", "bad") and not f.get("historical") for f in case["findings"])
            else "inconclusive")
    return test


for scenario in SCENARIOS:
    setattr(LabeledFlowTests, "test_" + scenario[0], scenario_test(scenario))


class EvidenceContractTests(unittest.TestCase):
    def test_differential_records_healthy_alternatives(self):
        _, case = run_case("PC slow")
        decisions = {d["id"]: d for d in case["trace"]["proposals"]}
        for key in ("cpu_hog", "memory_pressure", "storage_bottleneck"):
            self.assertIn(key, decisions)
            self.assertTrue(decisions[key]["contradictory"])
        self.assertEqual(case["root_cause_assessment"]["status"], "not_identified")

    def test_missing_resource_values_never_pass(self):
        _, case = run_case("PC slow", {"performance_samples": {"available": True,
            "samples": [{"cpu_pct": None, "available_pct": None, "commit_pct": None, "disks": []}]*4}})
        rows = {f["key"]: f for f in case["findings"]}
        for key in ("resource_cpu", "resource_memory", "resource_storage"):
            self.assertEqual(rows[key]["status"], "inconclusive")

    def test_malformed_provider_does_not_sink_other_measurements(self):
        _, case = run_case("PC slow and USB faults", {"disk": {"available": True}, "problem_devices": {"available": True, "devices": ["malformed"]}})
        self.assertIn("resource_cpu", {f["key"] for f in case["findings"]})
        self.assertEqual(next(f for f in case["findings"] if f["key"] == "problem_devices")["status"], "collection_failed")

    def test_external_probes_can_be_disabled(self):
        probe = RecordedProbe()
        case = CaseEngine(probe, allow_external_probes=False).build_case("Internet fails")
        self.assertNotIn("layered_network", probe.calls)
        self.assertNotIn("dns_resolution", probe.calls)
        self.assertEqual(next(f for f in case["findings"] if f["key"] == "resolver_queries")["status"], "not_tested")

    def test_per_check_timeout_discards_late_result(self):
        import time
        class Probe:
            def disk(self):
                time.sleep(.25)
                return {"free_pct": 1, "free_gb": 1}
        engine = CaseEngine(Probe())
        engine.CHECK_TIMEOUTS = {"disk": .01}
        raw = engine._collect([("disk", "Disk")])
        self.assertEqual(raw["disk"]["diagnostic_state"], "collection_failed")
        self.assertNotIn("free_pct", raw["disk"])

    def test_crash_in_other_app_does_not_explain_chrome(self):
        _, case = run_case("Only Chrome crashes", {"app_crashes": {"available": True, "crashes": [
            {"app": "teams.exe", "module": "teams.dll", "count": 12}]}})
        self.assertNotIn("app_crash_module", [h["id"] for h in case["hypotheses"]])

    def test_defender_passive_mode_is_not_primary_protection_failure(self):
        _, case = run_case("Security check", {"defender": {"available": True, "enabled": False,
            "realtime": False, "signature_age": 1, "running_mode": "SxS Passive Mode"}})
        self.assertNotIn("defender_off", [h["id"] for h in case["hypotheses"]])
        self.assertNotIn("enable_realtime_protection", [s["id"] for s in case["plan"]])

    def test_device_fault_without_driver_evidence_is_not_reinstalled(self):
        from guided_scenarios import DEVICE
        _, case = run_case("USB device is broken", {"problem_devices": DEVICE})
        self.assertNotIn("reinstall_device", [s["id"] for s in case["plan"]])
        self.assertIn("reinstall_device", [s["id"] for s in case["withheld"]])

    def test_exact_device_precondition_rejects_a_different_device(self):
        rows = [{"key": "problem_devices", "status": "bad", "data": {"devices": [
            {"instance_id": "USB\\OTHER", "problem_code": 31}]}}]
        allowed, _ = eligible({"id": "reinstall_device", "kind": "action", "params": {"instance_id": "USB\\TARGET"}}, rows, BASE["system_context"])
        self.assertFalse(allowed)

    def test_update_success_replaces_only_older_failure_of_same_update(self):
        class Probe(DeepProbe):
            def _ps_events(self, _script, **kwargs):
                return True, [["WUS", "2026-10-12T15:00:00Z", "", "Update A", "GUID-A", "1", "12"],
                              ["WUF", "2026-10-12T14:00:00Z", "0x80070070", "Update A", "GUID-A", "1", "10"],
                              ["WUF", "2026-10-12T14:00:00Z", "0x80070070", "Update B", "GUID-B", "1", "11"]], ""
        result = Probe().update_failures()
        self.assertEqual([f["identity"] for f in result["failures"]], ["GUID-B:1"])
        self.assertEqual(result["max_record_id"], 12)

    def test_failed_disk_memory_and_scalar_never_become_zero(self):
        _, case = run_case("PC slow", {"disk": PermissionError("Access denied"), "memory": RuntimeError("Provider failed"),
            "uptime_days": None, "performance_samples": {"available": False}})
        by_key = {f["key"]: f for f in case["findings"]}
        self.assertEqual(by_key["disk_free"]["status"], "permission_denied")
        self.assertEqual(by_key["memory"]["status"], "collection_failed")
        self.assertNotIn("disk_full", [h["id"] for h in case["hypotheses"]])

    def test_unknown_observations_have_identity_provenance_and_no_value(self):
        _, case = run_case("Disk slow", {"smart_health": {"available": False}})
        smart = next(o for o in case["observations"] if o["check_id"] == "smart")
        self.assertEqual(smart["session_id"], case["id"])
        self.assertIsNone(smart["value"])
        self.assertIn(smart["state"], ("inconclusive", "collection_failed"))
        self.assertTrue(smart["source"])
        json.dumps(case)

    def test_cancellation_propagates(self):
        from winmend.diagnostics.catalog import Cancelled
        with self.assertRaises(Cancelled):
            CaseEngine(RecordedProbe()).build_case("PC slow", cancel=lambda: True)

    def test_selected_checks_do_not_include_unrelated_categories(self):
        engine, case = run_case("Bluetooth headphones cutting out")
        selected = case["trace"]["selected_checks"]
        self.assertIn("bluetooth_health", selected)
        self.assertNotIn("layered_network", selected)
        self.assertNotIn("installed_programs", selected)
        self.assertNotIn("memory_pattern_test", selected)

    def test_hardware_read_samples_withheld_on_bad_media(self):
        probe = RecordedProbe({"smart_health": {"available": True, "disks": 1, "unhealthy": ["Drive Warning"]}})
        case = CaseEngine(probe).hardware_scan()
        self.assertNotIn("disk_read_sweep", probe.calls)
        row = next(f for f in case["findings"] if f["key"] == "disk_surface")
        self.assertEqual(row["status"], "not_tested")

    def test_correlated_rows_contribute_one_failure_family(self):
        h = Hypothesis("test", "Storage", "Example", evidence_keys=("smart", "drive_wear", "smart_detail"))
        rows = [{"key": key, "status": "bad"} for key in h.evidence_keys]
        _, trace = evaluate(Context("disk slow", "storage", {}, {}, rows), [h])
        self.assertEqual(trace[0]["independent_groups"], {"storage_health": 3})

    def test_contradictory_dns_results_reduce_score(self):
        h = Hypothesis("dns_dead", "DNS", "DNS", evidence_keys=("dns_resolution", "resolver_queries"))
        a = [{"key": "dns_resolution", "status": "bad"}]
        _, support = evaluate(Context("network", "network", {}, {}, a), [h])
        b = a + [{"key": "resolver_queries", "status": "good"}]
        kept, contradicted = evaluate(Context("network", "network", {}, {}, b), [h])
        self.assertLess(contradicted[0]["rank_score"], support[0]["rank_score"])
        self.assertEqual(kept, [])

    def test_event_completion_marker_does_not_override_access_error(self):
        class Probe(DeepProbe):
            def _ps_rows(self, script, **kwargs):
                self.script = script
                return 1, [], "Access denied"
        probe = Probe()
        ready, _, _ = probe._ps_events("Get-WinEvent -ErrorAction SilentlyContinue")
        self.assertFalse(ready)
        self.assertIn("NoMatchingEventsFound", probe.script)
        self.assertIn("ErrorVariable", probe.script)

    def test_bounded_dns_negative_control_and_missing_timing(self):
        class Probe(DeepProbe):
            def _ps_json(self, script, **kwargs):
                self.script = script
                self.timeout = kwargs["timeout"]
                return {"available": True, "results": [{"ok": True}, {"ok": True}],
                        "negative": {"tested": False, "answered": None}}
        probe = Probe()
        result = probe.dns_resolution()
        self.assertIsNone(result["hijacked"])
        self.assertLessEqual(probe.timeout, 20)
        self.assertIn(".invalid", probe.script)
        rows = CaseEngine(probe)._findings({"dns_resolution": result})
        row = next(r for r in rows if r["key"] == "dns_resolution")
        self.assertEqual(row["status"], "good")
        self.assertIn("not verified", row["detail"])

    def test_partial_dns_success_does_not_support_a_global_dns_failure(self):
        _, case = run_case("Websites fail", {"dns_resolution": {"available": True,
            "resolved": 1, "attempted": 2, "failed": 1, "slowest_ms": None}})
        self.assertNotIn("dns_dead", [h["id"] for h in case["hypotheses"]])
        row = next(r for r in case["findings"] if r["key"] == "dns_resolution")
        self.assertEqual(row["status"], "warn")

    def test_historical_only_evidence_is_limited(self):
        _, case = run_case("Chrome crashes", {"app_crashes": {"available": True,
            "crashes": [{"app": "chrome.exe", "module": "chrome.dll", "count": 4}]}})
        hypothesis = next(h for h in case["hypotheses"] if h["id"] == "app_crash_module")
        self.assertEqual(hypothesis["evidence_strength"], "limited")
        self.assertTrue(hypothesis["title"].startswith("Recorded evidence:"))

    def test_single_slow_dns_pass_is_information(self):
        _, case = run_case("Websites slow", {"dns_resolution": {"available": True,
            "resolved": 2, "attempted": 2, "failed": 0, "slowest_ms": 1449, "slow": True}})
        self.assertNotIn("dns_slow", [h["id"] for h in case["hypotheses"]])
        row = next(r for r in case["findings"] if r["key"] == "dns_resolution")
        self.assertEqual(row["status"], "info")


class InterpretationTests(unittest.TestCase):
    def test_negated_symptoms(self):
        self.assertNotIn("performance", interpret("My PC isn't slow, but crashes opening games").categories)

    def test_misspelling_temporal_and_multiple_symptoms(self):
        s = interpret("Slwo and intenet drops after a driver update")
        self.assertIn("performance", s.categories)
        self.assertIn("network", s.categories)
        self.assertTrue(s.temporal)
        self.assertNotIn("updates", s.categories)

    def test_connected_is_distinct_from_disconnected(self):
        self.assertTrue(interpret("Wi-Fi connects, but websites won't load").connected)

    def test_questions_are_adaptive_capped_and_skips_unknown(self):
        interview = Interview()
        first = interview.select("Wi-Fi drops", limit=20)
        self.assertLessEqual(len(first), 5)
        second = interview.select("Wi-Fi drops", answers={"net_scope": "others_too"})
        self.assertNotIn("net_scope", [q["id"] for q in second])
        self.assertNotIn("net_medium", [q["id"] for q in second])
        self.assertEqual(interview.normalise({}), {})


class VerificationTests(unittest.TestCase):
    def test_cancelled_repairs_keep_the_execution_outcome(self):
        before = self.baseline()
        before["repair_status"] = "cancelled"
        after = run_case("Disk full")[1]
        after["symptom_resolved"] = True
        self.assertEqual(compare(before, after)["outcome"], "cancelled")

    def test_clock_change_is_not_a_restart(self):
        before = self.baseline()
        before["restart_required"] = True
        after = run_case("Disk full")[1]
        after["system_context"]["boot_time"] = 200
        self.assertEqual(compare(before, after)["outcome"], "restart_required")

    def test_skipped_repairs_cannot_be_reported_successful(self):
        before = self.baseline()
        before["repair_status"] = "not_applied"
        self.assertEqual(compare(before, run_case("Disk full")[1])["outcome"], "not_applied")

    def test_exact_new_update_success_can_verify_a_historical_fault(self):
        before = {"findings": [{"key": "update_failures", "status": "bad", "data": {
            "max_record_id": 100, "failures": [{"identity": "GUID:1"}]}}]}
        after = {"findings": [{"key": "update_failures", "status": "good", "data": {
            "failures": [], "successes": [{"identity": "GUID:1", "record_id": 102}]}}]}
        self.assertEqual(compare(before, after)["condition_outcome"], "resolved")
        after["findings"][0]["data"]["failures"] = [{"identity": "GUID:1"}]
        after["findings"][0]["status"] = "bad"
        self.assertEqual(compare(before, after)["condition_outcome"], "inconclusive")

    def test_an_unrelated_update_success_does_not_clear_the_target(self):
        before = {"findings": [{"key": "update_failures", "status": "bad", "data": {
            "max_record_id": 100, "failures": [{"identity": "GUID-A:1"}]}}]}
        after = {"findings": [{"key": "update_failures", "status": "good", "data": {
            "failures": [], "successes": [{"identity": "GUID-B:1", "record_id": 102}]}}]}
        self.assertEqual(compare(before, after)["outcome"], "inconclusive")

    def baseline(self):
        return run_case("Disk full", {"disk": {"free_gb": 1, "free_pct": 1}})[1]

    def test_command_success_with_fault_remaining(self):
        before = self.baseline()
        after = self.baseline()
        before["repair_status"] = "complete"
        self.assertEqual(compare(before, after)["outcome"], "not_resolved")

    def test_partial_measured_improvement(self):
        before = self.baseline()
        after = run_case("Disk full", {"disk": {"free_gb": 5, "free_pct": 10}})[1]
        self.assertEqual(compare(before, after)["outcome"], "improved")

    def test_fault_cleared_symptom_not_confirmed(self):
        result = compare(self.baseline(), run_case("Disk full")[1])
        self.assertEqual(result["condition_outcome"], "resolved")
        self.assertEqual(result["outcome"], "symptom_unverified")

    def test_confirmed_resolution(self):
        after = run_case("Disk full")[1]
        after["symptom_resolved"] = True
        self.assertEqual(compare(self.baseline(), after)["outcome"], "resolved")

    def test_missing_verification_is_not_success(self):
        before = self.baseline()
        after = run_case("Disk full", {"disk": {"available": False}})[1]
        self.assertEqual(compare(before, after)["outcome"], "inconclusive")
        engine = CaseEngine(RecordedProbe())
        self.assertFalse(engine.step_cleared({"verify_keys": ["disk_free"]}, {"disk": {"available": False}}, before["findings"])[0])

    def test_unknown_state_cannot_clear(self):
        for status in ("info", "inconclusive", "collection_failed", "permission_denied", "not_tested", "cancelled", "unsupported"):
            before = {"findings": [{"key": "disk_free", "status": "bad"}]}
            after = {"findings": [{"key": "disk_free", "status": status}]}
            self.assertEqual(compare(before, after)["outcome"], "inconclusive", status)

    def test_dns_improves_but_https_still_fails(self):
        before = run_case("Websites fail", {"layered_network": internet(dns=False, https=False)})[1]
        after = run_case("Websites fail", {"layered_network": internet(https=False)})[1]
        self.assertEqual(compare(before, after)["outcome"], "improved")

    def test_restart_required_and_later_recheck(self):
        before = self.baseline()
        before["restart_required"] = True
        after = run_case("Disk full")[1]
        self.assertEqual(compare(before, after)["outcome"], "restart_required")
        after["system_context"]["boot_time"] = 200
        after["system_context"]["boot_event_record_id"] = 43
        self.assertEqual(compare(before, after)["outcome"], "symptom_unverified")

    def test_repair_failure_not_hidden_by_measurements(self):
        before = self.baseline()
        before["repair_status"] = "failed"
        self.assertEqual(compare(before, run_case("Disk full")[1])["outcome"], "repair_failed")

    def test_unrelated_measurement_improvement_cannot_clear_target(self):
        before = self.baseline()
        before["verification_targets"] = ["disk_free"]
        after = self.baseline()
        after["severity_score"] = 0
        self.assertEqual(compare(before, after)["outcome"], "not_resolved")

    def test_failed_attempt_excluded_from_new_plan(self):
        engine, before = run_case("Disk full", {"disk": {"free_gb": 1, "free_pct": 1}})
        step = next(s for s in before["plan"] if s["id"] == "clean_temp")
        after = engine.build_case("Disk full", history=[{"attempts": [{"identity": repair_identity(step), "outcome": "not_resolved"}]}])
        self.assertNotIn("clean_temp", [s["id"] for s in after["plan"]])

    def test_report_escape_redaction_and_trace(self):
        case = self.baseline()
        case["problem"] = '<script>alert(1)</script> C:\\Users\\Alice\\private token=abc'
        report = render_case_report_html(case)
        self.assertNotIn("<script>", report)
        self.assertNotIn("Alice", report)
        self.assertNotIn("token=abc", report)
        self.assertNotIn("% confidence", report)
        self.assertIn("Diagnostic decision trace", report)


if __name__ == "__main__":
    unittest.main()
