import json
import tempfile
import unittest
from pathlib import Path

from winmend_safety import DiagnosticEngine, SafetyJournal
from winmend.safety.seals import (
    MemoryUndoSeals,
    RegistryUndoSeals,
    seal_digest,
    security_is_admin_only,
)


class FakeProbe:
    def disk(self):
        return {"free_gb": 4.0, "free_pct": 4.0}

    def memory(self):
        return {"used_pct": 88.0, "available_gb": 2.0}

    def uptime_days(self):
        return 10.0

    def temp_size(self, max_entries=40000):
        return {"bytes": 2 * 1024 ** 3, "partial": False}

    def startup_count(self):
        return 14

    def pending_reboot(self):
        return True

    def service_state(self, name):
        return "stopped"

    def network(self):
        return {"adapters": 1, "dns": False, "reachable": True}

    def crash_dumps(self):
        return 2

    def defender(self):
        return {"available": True, "enabled": True, "realtime": True, "signature_age": 0}

    def firewall_enabled(self):
        return True

    def battery(self):
        return {"present": True, "percent": 70.0, "plugged": False}

    def smart_health(self):
        return {"available": True, "disks": 1, "unhealthy": ["Samsung SSD (Warning)"]}

    def event_log_errors(self, days=7):
        return {"available": True, "unexpected_shutdowns": 2, "disk_errors": 1,
                "service_crashes": 3, "hardware_errors": 0}

    def ping_quality(self, host="1.1.1.1", port=443, attempts=4):
        return {"attempts": 4, "failures": 1, "avg_ms": 210.0}

    def top_memory_processes(self, count=3):
        return [{"name": "chrome", "mb": 2200.0}, {"name": "teams", "mb": 900.0}]


class HealedProbe(FakeProbe):
    def service_state(self, name):
        return "running"


class DiagnosticEngineTests(unittest.TestCase):
    def setUp(self):
        self.engine = DiagnosticEngine(FakeProbe())

    def test_classifies_and_builds_network_plan(self):
        report = self.engine.diagnose("Wi-Fi connects but websites will not load")
        self.assertEqual("network", report["profile"])
        task_ids = [task["id"] for task in report["recommended_tasks"]]
        self.assertNotIn("flush_dns", task_ids)
        self.assertTrue(all(s.get("read_only") for s in report["plan"]))
        self.assertEqual(len(task_ids), len(set(task_ids)))

    def test_performance_plan_responds_to_measured_pressure(self):
        report = self.engine.diagnose("My PC is very slow")
        task_ids = [task["id"] for task in report["recommended_tasks"]]
        self.assertNotIn("clean_temp", task_ids)
        self.assertIn("clean_temp", {w["id"] for w in report["withheld"]})
        self.assertNotIn("disable_startup_apps", task_ids)
        self.assertGreater(report["severity_score"], 0)

    def test_shell_search_complaint_is_measurable(self):
        report = self.engine.diagnose('start menu search is broken')
        self.assertEqual(report['profile'], 'shell')
        self.assertTrue(any(f['status'] not in ('good','warn','bad','info') for f in report['findings']))
        self.assertNotIn('reset_search_index', [t['id'] for t in report['recommended_tasks']])

    def test_shell_verification_can_resolve(self):
        before = self.engine.diagnose("search is broken")
        after = DiagnosticEngine(HealedProbe()).diagnose("search is broken", profile="shell")
        result = self.engine.compare(before, after)
        self.assertEqual("inconclusive", result["outcome"])

    def test_verification_reports_improvement(self):
        before = {
            "severity_score": 2,
            "findings": [{"key": "dns", "label": "DNS", "status": "bad", "value": "failed"}],
        }
        after = {
            "severity_score": 0,
            "findings": [{"key": "dns", "label": "DNS", "status": "good", "value": "working"}],
        }
        result = self.engine.compare(before, after)
        self.assertEqual("resolved", result["outcome"])
        self.assertEqual(1, result["improved_checks"])

    def test_new_profiles_classify(self):
        for text, expected in (
            ("bluetooth headphones will not pair", "bluetooth"),
            ("microsoft store apps won't open", "apps"),
            ("my clock is wrong and I get certificate errors", "time"),
            ("chrome is painfully sluggish", None),
        ):
            profile = self.engine.classify(text)
            if expected:
                self.assertIn(expected, profile.split("+"), text)
        report = self.engine.diagnose("bluetooth mouse keeps disconnecting")
        self.assertIn("bluetooth", report["profile"].split("+"))
        self.assertNotIn("bluetooth_repair", [t["id"] for t in report["recommended_tasks"]])

    def test_blends_close_profiles(self):
        report = self.engine.diagnose("my pc is slow and wifi keeps disconnecting")
        parts = set(report["profile"].split("+"))
        self.assertEqual({"network", "performance"}, parts)
        keys = {f["key"] for f in report["findings"]}
        self.assertIn("disk_free", keys)
        self.assertIn("dns", keys)

    def test_escalation_from_recent_history(self):
        history = [{
            "source": "guided",
            "started_at": "2099-01-01T00:00:00+00:00",
            "diagnosis_before": {"profile": "network"},
        }]
        # Future timestamps are within any window; also check the plain path.
        report = self.engine.diagnose("wifi keeps dropping", history=history)
        task_ids = [t["id"] for t in report["recommended_tasks"]]
        self.assertFalse(report["escalated"])
        self.assertNotIn("reset_network", task_ids)
        self.assertNotIn("deep_network_remediation", task_ids)
        fresh = self.engine.diagnose("wifi keeps dropping")
        self.assertFalse(fresh["escalated"])
        self.assertNotIn("reset_network", [t["id"] for t in fresh["recommended_tasks"]])

    def test_restart_recommended_last_on_pending_reboot(self):
        report = self.engine.diagnose("something feels generally off")
        task_ids = [t["id"] for t in report["recommended_tasks"]]
        self.assertIn("restart_windows", task_ids)
        self.assertEqual("restart_windows", task_ids[-1])

    def test_smart_failure_changes_the_plan(self):
        report = self.engine.diagnose("my pc is very slow")
        task_ids = [t["id"] for t in report["recommended_tasks"]]
        self.assertIn("disk_smart_check", task_ids)
        self.assertNotIn("chk_dsk", task_ids)
        smart = next(f for f in report["findings"] if f["key"] == "smart")
        self.assertEqual("bad", smart["status"])

    def test_crashes_profile_reads_event_log(self):
        report = self.engine.diagnose("I keep getting blue screens")
        keys = {f["key"]: f["status"] for f in report["findings"]}
        self.assertEqual("bad", keys["evt_shutdowns"])
        self.assertEqual("warn", keys["evt_services"])
        task_ids = [t["id"] for t in report["recommended_tasks"]]
        self.assertNotIn('ram_quick_test', task_ids)
        self.assertNotIn('repair_system', task_ids)
        self.assertIn('disk_smart_check', task_ids)

    def test_low_confidence_flag(self):
        self.assertTrue(self.engine.diagnose("everything is weird")["low_confidence"])
        self.assertFalse(self.engine.diagnose("my pc is slow")["low_confidence"])
        self.assertFalse(self.engine.diagnose("whatever", profile="network")["low_confidence"])

    def test_every_recommendation_has_reason_and_duration(self):
        for text in ("my pc is slow", "wifi keeps dropping", "blue screen", "virus",
                     "printer stuck", "no sound", "bluetooth broken", "store apps won't open"):
            for task in self.engine.diagnose(text)["recommended_tasks"]:
                self.assertTrue(task["reason"], task["id"])
                self.assertTrue(task["duration"], task["id"])


class SafetyJournalTests(unittest.TestCase):
    def test_session_lifecycle_is_persistent(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "journal.json"
            journal = SafetyJournal(path)
            session_id = journal.start_session(
                "guided",
                [{"id": "repair", "title": "Repair", "risk": "caution", "restore_point": True}],
                problem="Windows is broken",
                diagnosis={"summary": "One issue"},
            )
            journal.set_protection(session_id, True, 42, "WinMend checkpoint")
            journal.task_started(session_id, "repair")
            journal.task_finished(session_id, "repair", "done", 1.25)
            journal.complete_session(
                session_id, "complete", {"outcome": "resolved", "summary": "Fixed"}
            )

            reloaded = SafetyJournal(path).get_session(session_id)
            self.assertEqual("complete", reloaded["status"])
            self.assertEqual(42, reloaded["protection"]["sequence"])
            self.assertTrue(reloaded["undo"]["available"])
            self.assertEqual("done", reloaded["tasks"][0]["state"])
            self.assertEqual("resolved", reloaded["verification"]["outcome"])

            with path.open("r", encoding="utf-8") as stream:
                raw = json.load(stream)
            self.assertEqual(1, raw["schema"])

    def test_cancelled_session_marks_queued_tasks(self):
        with tempfile.TemporaryDirectory() as folder:
            journal = SafetyJournal(Path(folder) / "journal.json")
            session_id = journal.start_session(
                "manual",
                [{"id": "one", "title": "One"}, {"id": "two", "title": "Two"}],
            )
            journal.task_started(session_id, "one")
            journal.task_finished(session_id, "one", "cancelled", 0.1)
            journal.complete_session(session_id, "cancelled")
            session = journal.get_session(session_id)
            self.assertEqual(["cancelled", "cancelled"], [t["state"] for t in session["tasks"]])

    def test_set_verification_after_the_fact(self):
        with tempfile.TemporaryDirectory() as folder:
            journal = SafetyJournal(Path(folder) / "journal.json")
            session_id = journal.start_session(
                "guided", [{"id": "repair", "title": "Repair"}], problem="slow pc",
                diagnosis={"profile": "performance"},
            )
            journal.complete_session(session_id, "interrupted",
                                     {"outcome": "unavailable", "summary": "Restarted."})
            self.assertTrue(journal.set_verification(
                session_id, {"outcome": "resolved", "summary": "Re-check confirmed the fix."}))
            session = journal.get_session(session_id)
            self.assertEqual("resolved", session["verification"]["outcome"])

    def test_recovers_session_interrupted_by_restart(self):
        with tempfile.TemporaryDirectory() as folder:
            journal = SafetyJournal(Path(folder) / "journal.json")
            session_id = journal.start_session(
                "manual", [{"id": "repair", "title": "Repair", "restore_point": True}]
            )
            journal.task_started(session_id, "repair")
            self.assertEqual(1, journal.recover_interrupted_sessions())
            session = journal.get_session(session_id)
            self.assertEqual("interrupted", session["status"])
            self.assertEqual("interrupted", session["tasks"][0]["state"])


class UndoSealTests(unittest.TestCase):
    """The journal is in %APPDATA%, where any program running as the user can
    write; WinMend replays its undo payloads with administrator rights. These
    pin down that only what WinMend itself recorded can be replayed."""

    UAC_UNDO = {"kind": "uac", "previous": {"EnableLUA": [1, 4],
                                            "ConsentPromptBehaviorAdmin": [5, 4],
                                            "PromptOnSecureDesktop": [1, 4]}}

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.path = Path(self._dir.name) / "journal.json"
        self.journal = SafetyJournal(self.path)
        self.session_id = self.journal.start_session(
            "guided", [{"id": "enable_uac", "title": "Turn User Account Control back on"}])

    def tearDown(self):
        self._dir.cleanup()

    def record_uac_repair(self):
        self.journal.task_finished(self.session_id, "enable_uac", "done", 1.0, undo=self.UAC_UNDO)

    def edit_file(self, change):
        """What a program running as the user can do to the journal."""
        with self.path.open("r", encoding="utf-8") as stream:
            data = json.load(stream)
        change(data)
        with self.path.open("w", encoding="utf-8") as stream:
            json.dump(data, stream)

    def test_a_recorded_undo_is_reversible(self):
        self.record_uac_repair()
        steps = self.journal.reversible_steps(self.session_id)
        self.assertEqual(["enable_uac"], [s["id"] for s in steps])
        self.assertEqual(self.UAC_UNDO, steps[0]["undo_payload"])

    def test_an_edited_payload_is_not_reversible(self):
        self.record_uac_repair()

        def never_prompt(data):
            task = data["sessions"][0]["tasks"][0]
            task["undo_payload"]["previous"]["ConsentPromptBehaviorAdmin"] = [0, 4]
        self.edit_file(never_prompt)
        self.assertEqual([], self.journal.reversible_steps(self.session_id))

    def test_a_forged_step_is_not_reversible(self):
        def forge(data):
            data["sessions"][0]["tasks"][0].update({
                "state": "done", "undo_state": "available",
                "undo_payload": {"kind": "uac", "previous": {"EnableLUA": [0, 4]}}})
        self.edit_file(forge)
        self.assertEqual([], self.journal.reversible_steps(self.session_id))

    def test_a_genuine_payload_copied_to_another_session_is_not_reversible(self):
        self.record_uac_repair()
        other = self.journal.start_session("guided", [{"id": "enable_uac", "title": "UAC"}])

        def copy(data):
            source = next(s for s in data["sessions"] if s["id"] == self.session_id)
            target = next(s for s in data["sessions"] if s["id"] == other)
            target["tasks"][0].update({k: source["tasks"][0][k]
                                       for k in ("state", "undo_state", "undo_payload")})
        self.edit_file(copy)
        self.assertEqual([], self.journal.reversible_steps(other))

    def test_a_reversed_step_cannot_be_rearmed_from_the_file(self):
        self.record_uac_repair()
        self.journal.set_step_undo_state(self.session_id, "enable_uac", "reversed")

        def rearm(data):
            data["sessions"][0]["tasks"][0]["undo_state"] = "available"
        self.edit_file(rearm)
        self.assertEqual([], self.journal.reversible_steps(self.session_id))

    def test_a_payload_that_cannot_be_sealed_is_recorded_as_unsealed(self):
        class Unwritable(MemoryUndoSeals):
            def _write(self, name, digest):
                raise OSError("Access is denied.")
        journal = SafetyJournal(self.path, seals=Unwritable())
        session_id = journal.start_session("guided", [{"id": "enable_uac", "title": "UAC"}])
        journal.task_finished(session_id, "enable_uac", "done", 1.0, undo=self.UAC_UNDO)
        self.assertEqual("unsealed", journal.get_session(session_id)["tasks"][0]["undo_state"])
        self.assertEqual([], journal.reversible_steps(session_id))

    def test_the_rollback_restore_point_must_be_the_one_recorded(self):
        self.journal.set_protection(self.session_id, True, 42, "EAWTECH Guardrail")
        self.assertEqual(42, self.journal.verified_restore_point(self.session_id))

        def older_point(data):
            data["sessions"][0]["protection"]["sequence"] = 7
        self.edit_file(older_point)
        self.assertIsNone(self.journal.verified_restore_point(self.session_id))

    def test_a_restore_point_added_to_the_file_is_not_trusted(self):
        def invent(data):
            data["sessions"][0]["protection"].update({"created": True, "sequence": 3})
        self.edit_file(invent)
        self.assertIsNone(self.journal.verified_restore_point(self.session_id))

    def test_the_digest_is_of_what_json_gives_back(self):
        # Tuples come back as lists and integer keys as strings; a seal taken
        # before the round trip must still match the payload after it.
        payload = {"previous": {"AC": 1, "DC": 0}, "pair": ("x", 1), "n": {1: "a", 10: "b", 2: "c"}}
        self.assertEqual(seal_digest("s", "t", payload),
                         seal_digest("s", "t", json.loads(json.dumps(payload))))

    def test_seals_for_sessions_the_journal_dropped_are_pruned(self):
        seals = MemoryUndoSeals()
        journal = SafetyJournal(self.path, max_sessions=20, seals=seals)
        first = journal.start_session("guided", [{"id": "enable_uac", "title": "UAC"}])
        journal.task_finished(first, "enable_uac", "done", 1.0, undo=self.UAC_UNDO)
        for _ in range(20):
            later = journal.start_session("guided", [{"id": "enable_uac", "title": "UAC"}])
        journal.task_finished(later, "enable_uac", "done", 1.0, undo=self.UAC_UNDO)
        self.assertFalse(any(name.startswith(first) for name in seals._names()))
        self.assertTrue(any(name.startswith(later) for name in seals._names()))


class SealKeySecurityTests(unittest.TestCase):
    """The seal key is only worth anything if non-administrators cannot write it."""

    @staticmethod
    def descriptor(sddl):
        import win32security
        return win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            sddl, win32security.SDDL_REVISION_1)

    def test_the_dacl_the_key_is_created_with_passes(self):
        from winmend.safety import seals
        self.assertTrue(security_is_admin_only(self.descriptor(seals._SEALS_SDDL)))

    def test_users_with_write_access_fail(self):
        self.assertFalse(security_is_admin_only(
            self.descriptor("O:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KW;;;BU)")))
        self.assertFalse(security_is_admin_only(
            self.descriptor("O:BAD:P(A;;KA;;;SY)(A;;0x2;;;AU)")))  # KEY_SET_VALUE alone

    def test_an_ordinary_owner_fails(self):
        # The owner can always rewrite the DACL, so it must be an administrator.
        self.assertFalse(security_is_admin_only(
            self.descriptor("O:S-1-5-21-1-2-3-1001D:P(A;;KA;;;SY)(A;;KA;;;BA)")))

    def test_a_null_dacl_fails(self):
        self.assertFalse(security_is_admin_only(self.descriptor("O:BAD:NO_ACCESS_CONTROL")))

    def test_inherit_only_and_deny_entries_do_not_count_against_it(self):
        self.assertTrue(security_is_admin_only(self.descriptor(
            "O:BAD:P(D;;KA;;;WD)(A;;KA;;;BA)(A;CIIO;KA;;;CO)(A;;KR;;;BU)")))

    TEST_KEY = r"SOFTWARE\WinMend\UndoSealsTest"

    def test_this_unelevated_process_cannot_write_a_seal(self):
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin():
            self.skipTest("elevated: this test is about what a non-administrator can do")
        store = RegistryUndoSeals(key=self.TEST_KEY)
        self.assertFalse(store.seal("session", "enable_uac", {"previous": {}}))
        self.assertFalse(store.verify("session", "enable_uac", {"previous": {}}))

    def test_an_elevated_process_seals_into_a_key_only_administrators_can_change(self):
        # Run the suite from an administrator prompt to exercise this: it is
        # the only path that really creates the HKLM key WinMend relies on.
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            self.skipTest("needs an elevated run: only an administrator can create the seal key")
        import win32api
        import win32con
        import win32security
        store = RegistryUndoSeals(key=self.TEST_KEY)
        try:
            self.assertTrue(store.seal("session", "enable_uac", {"previous": {}}))
            self.assertTrue(store.verify("session", "enable_uac", {"previous": {}}))
            self.assertFalse(store.verify("session", "enable_uac", {"previous": {"x": 1}}))
            handle = win32api.RegOpenKeyEx(win32con.HKEY_LOCAL_MACHINE, self.TEST_KEY, 0,
                                           win32con.KEY_READ | win32con.KEY_WOW64_64KEY)
            try:
                descriptor = win32api.RegGetKeySecurity(
                    handle, win32security.OWNER_SECURITY_INFORMATION
                    | win32security.DACL_SECURITY_INFORMATION)
            finally:
                handle.Close()
            self.assertTrue(security_is_admin_only(descriptor))
            self.assertEqual("S-1-5-32-544", win32security.ConvertSidToStringSid(
                descriptor.GetSecurityDescriptorOwner()))
        finally:
            try:
                win32api.RegDeleteKeyEx(win32con.HKEY_LOCAL_MACHINE, self.TEST_KEY,
                                        samDesired=win32con.KEY_WOW64_64KEY)
            except Exception:
                pass


if __name__ == "__main__":
    unittest.main()
