"""SSD Saver: stop, then disable, the AMD External Events Utility on AMD PCs.

Services, sc.exe and the hardware query are mocked; the undo record is written
to a scratch key under HKCU, never to WinMend's real one.
"""

import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import ast
import shutil
import subprocess
import tempfile
import unittest
import uuid
import winreg
from pathlib import Path
from unittest import mock

from winmend.core.processes import WMCompleted
from winmend.core.task_runner import TaskRunnerMixin
from winmend.data.task_catalog import WM_HANDLERS, WM_TASKS
from winmend.features import amd
from winmend.features.amd import AMD_EVENTS_SERVICE, amd_components, parse_gpus, record_previous_start
from winmend.ui.task_host import WMTaskHost

ROOT = Path(__file__).resolve().parents[1]
RADEON = ("PCI\\VEN_1002&DEV_7480&SUBSYS_06071043&REV_C0\\6&4702CE7&0&00000009",
          "Advanced Micro Devices, Inc.", "AMD Radeon RX 7600 XT")
GEFORCE = ("PCI\\VEN_10DE&DEV_2684&SUBSYS_16F110DE&REV_A1\\4&1", "NVIDIA", "NVIDIA GeForce RTX 4090")


class Runner(TaskRunnerMixin):
    def __init__(self, host):
        self.host = host
        self.simple = False
        self.journal = mock.Mock()


class DetectionTests(unittest.TestCase):
    def test_amd_processor_or_graphics_counts(self):
        self.assertEqual(amd_components("AuthenticAMD", "AMD Ryzen 7 5700G", [GEFORCE]),
                         ["processor: AMD Ryzen 7 5700G"])
        self.assertEqual(amd_components("GenuineIntel", "Intel Core i7", [RADEON]),
                         ["graphics: AMD Radeon RX 7600 XT"])
        self.assertEqual(len(amd_components("AuthenticAMD", "Ryzen", [RADEON])), 2)

    def test_intel_and_nvidia_is_not_amd(self):
        self.assertEqual(amd_components("GenuineIntel", "Intel Core i7", [GEFORCE]), [])

    def test_amd_graphics_without_a_driver_still_counts_by_vendor_id(self):
        basic = ("PCI\\VEN_1002&DEV_73DF", "(Standard display types)", "Microsoft Basic Display Adapter")
        self.assertEqual(len(amd_components("GenuineIntel", "", [basic])), 1)

    def test_parse_gpus(self):
        out = "GPU|PCI\\VEN_1002&DEV_7480|Advanced Micro Devices, Inc.|AMD Radeon RX 7600 XT\nnoise\n"
        self.assertEqual(parse_gpus(out), [("PCI\\VEN_1002&DEV_7480", "Advanced Micro Devices, Inc.",
                                            "AMD Radeon RX 7600 XT")])


class Service:
    """A fake service: sc stop / sc config change it the way Windows would."""

    def __init__(self, status="running", start="automatic", refuse_config=False):
        self.state = {"status": status, "start": start}
        self.refuse_config = refuse_config
        self.calls = []

    def query(self, name):
        return dict(self.state) if name == AMD_EVENTS_SERVICE else None

    def sc(self, argv, **_kw):
        self.calls.append(argv[1])
        if argv[1] == "stop":
            self.state["status"] = "stopped"
            return WMCompleted(argv, 0, "", "")
        if argv[1] == "config":
            if self.refuse_config:
                return WMCompleted(argv, 5, "[SC] ChangeServiceConfig FAILED 5:\n\nAccess is denied.\n", "")
            self.state["start"] = argv[-1]
            return WMCompleted(argv, 0, "[SC] ChangeServiceConfig SUCCESS\n", "")
        raise AssertionError(argv)


class HandlerTests(unittest.TestCase):
    def run_option(self, cpu=("AuthenticAMD", "AMD Ryzen 7 5700G"), gpus=(RADEON,), service=None,
                   recorded=True):
        host = WMTaskHost(None)
        service = service if service is not None else Service()
        gpu_out = "".join(f"GPU|{p}|{m}|{n}\n" for p, m, n in gpus)
        with mock.patch.object(amd, "cpu_identity", return_value=cpu), \
                mock.patch.object(host, "_run_ps", return_value=WMCompleted([], 0, gpu_out, "")), \
                mock.patch.object(amd, "service_state", side_effect=service.query), \
                mock.patch.object(amd, "wm_run", side_effect=service.sc), \
                mock.patch.object(amd, "_delayed_autostart", return_value=False), \
                mock.patch.object(amd, "record_previous_start", return_value=recorded) as record:
            state, _ = Runner(host)._run_task_handler("ssd_saver", "SSD Saver")
        lines = []
        while not host.queue.empty():
            lines.append(host.queue.get_nowait())
        return state, service, record, "\n".join(lines)

    def test_stops_then_disables_and_records_the_old_start_type_first(self):
        state, service, record, log = self.run_option()
        self.assertEqual(state, "done", log)
        self.assertEqual(service.calls, ["stop", "config"])
        self.assertEqual(service.state, {"status": "stopped", "start": "disabled"})
        record.assert_called_once_with("automatic")
        self.assertIn("stopped and disabled", log)

    def test_no_amd_hardware_changes_nothing(self):
        state, service, record, log = self.run_option(cpu=("GenuineIntel", "Intel Core i7"),
                                                      gpus=(GEFORCE,))
        self.assertEqual(state, "skip", log)
        self.assertEqual(service.calls, [])
        record.assert_not_called()

    def test_service_not_installed_is_a_skip(self):
        class Missing(Service):
            def query(self, name):
                return None
        state, service, _record, log = self.run_option(service=Missing())
        self.assertEqual(state, "skip", log)
        self.assertIn("not installed", log)
        self.assertEqual(service.calls, [])

    def test_already_stopped_and_disabled_is_left_alone(self):
        state, service, record, log = self.run_option(service=Service("stopped", "disabled"))
        self.assertEqual(state, "done", log)
        self.assertEqual(service.calls, [])
        record.assert_not_called()  # "disabled" must never be recorded as the original
        self.assertIn("already stopped and disabled", log)

    def test_disabled_but_running_is_only_stopped(self):
        state, service, record, log = self.run_option(service=Service("running", "disabled"))
        self.assertEqual(state, "done", log)
        self.assertEqual(service.calls, ["stop"])
        record.assert_not_called()

    def test_without_an_undo_record_nothing_changes(self):
        state, service, _record, log = self.run_option(recorded=False)
        self.assertEqual(state, "fail", log)
        self.assertEqual(service.calls, [])

    def test_refused_disable_is_a_failure_with_the_reason(self):
        state, service, _record, log = self.run_option(service=Service(refuse_config=True))
        self.assertEqual(state, "fail", log)
        self.assertIn("Access is denied.", log)

    def test_unreadable_hardware_is_a_failure_not_a_skip(self):
        state, service, _record, log = self.run_option(cpu=("", ""), gpus=())
        self.assertEqual(state, "fail", log)
        self.assertEqual(service.calls, [])


class UndoRecordTests(unittest.TestCase):
    def setUp(self):
        self.key = rf"Software\WinMendTests\{uuid.uuid4().hex}"

    def tearDown(self):
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, self.key)
        except OSError:
            pass

    def read(self, name):
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.key) as key:
            return winreg.QueryValueEx(key, name)[0]

    def test_recorded_once_so_a_rerun_keeps_the_original(self):
        self.assertTrue(record_previous_start("manual", key_path=self.key))
        self.assertTrue(record_previous_start("automatic", key_path=self.key))
        self.assertEqual(self.read(amd.UNDO_START), "manual")
        self.assertEqual(self.read(amd.UNDO_RECORDED), 1)

    def test_only_restorable_start_types_are_recorded(self):
        self.assertFalse(record_previous_start("disabled", key_path=self.key))


class RegistrationTests(unittest.TestCase):
    def test_listed_under_repair_and_recovery(self):
        task = next(t for t in WM_TASKS if t.id == "ssd_saver")
        self.assertEqual((task.title, task.category), ("SSD Saver", "repair"))
        self.assertTrue(task.admin)
        self.assertNotEqual(task.risk, "safe")  # it changes a service
        self.assertEqual(WM_HANDLERS["ssd_saver"], "run_ssd_saver")
        self.assertTrue(callable(getattr(WMTaskHost(None), "run_ssd_saver")))

    def test_search_finds_it(self):
        host = WMTaskHost(None)
        for query in ("amd", "radeon", "amd external events utility", "atiesrxx"):
            with self.subTest(query=query):
                self.assertIn("ssd_saver", host._recommend_tasks_for_query(query)[0])

    @unittest.skipUnless(shutil.which("powershell"), "needs Windows PowerShell")
    def test_reset_defaults_restores_it_and_still_parses(self):
        tree = ast.parse((ROOT / "winmend" / "features" / "recovery.py").read_text(encoding="utf-8"))
        script = next(n.value.value for n in ast.walk(tree)
                      if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "ps_script"
                      and "AmdExternalEventsRecorded" in getattr(n.value, "value", ""))
        self.assertIn("'AMD External Events Utility'", script)
        with tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False, encoding="utf-8-sig") as fh:
            fh.write(script)
        self.addCleanup(os.unlink, fh.name)
        check = ("$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile("
                 f"'{fh.name}',[ref]$null,[ref]$e); if($e){{$e|%{{$_.Message}}; exit 1}}")
        r = subprocess.run(["powershell", "-NoProfile", "-Command", check], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
