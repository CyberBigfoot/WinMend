"""Regressions for the faults the second option sweep found (Nov 18 2026).

1. Create AutoPilot CSV ran an elevated script from C:\\PowerShell, which every
   account on the PC can modify.
2. Windows Update Forensic Fixer reset the update components over a failure a
   later install of the same update had already cleared.
3. Windows Updates reported "succeeded with errors" as a total failure.
4. PowerShell failures were reported by their FullyQualifiedErrorId line.
5. Battery Health Report and Wi-Fi Channel Analyzer said Completed with no
   battery or adapter to look at.
6. PC Report's "System UUID" was the network adapter's MAC address.

Nothing here changes Windows: PowerShell and the update calls are mocked.
"""

import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import ast
import shutil
import subprocess
import tempfile
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from winmend.core.processes import WMCompleted
from winmend.core.search import _wm_last_line
from winmend.core.task_runner import TaskRunnerMixin
from winmend.features import power, reporting, updates
from winmend.features.updates import classify_update_errors, parse_update_event
from winmend.reports.system import PCReporter
from winmend.ui.task_host import WMTaskHost

ROOT = Path(__file__).resolve().parents[1]


class Runner(TaskRunnerMixin):
    def __init__(self, host):
        self.host = host
        self.simple = False
        self.journal = mock.Mock()


def drain(host):
    lines = []
    while not host.queue.empty():
        lines.append(host.queue.get_nowait())
    return "\n".join(lines)


def run(host, task_id):
    return Runner(host)._run_task_handler(task_id, task_id)[0]


HASH = "T0FBM" * 60


class AutopilotTests(unittest.TestCase):
    def setUp(self):
        self.host = WMTaskHost(None)
        self.folder = tempfile.mkdtemp(prefix="wm-autopilot-")
        self.addCleanup(shutil.rmtree, self.folder, True)

    def run_export(self, result):
        with mock.patch.object(self.host, "_get_desktop_dir", return_value=self.folder), \
                mock.patch.object(self.host, "_run_ps", return_value=result) as query, \
                mock.patch("os.makedirs") as makedirs:
            state = run(self.host, "autopilot_csv")
        return state, query, makedirs, drain(self.host)

    def test_no_script_file_and_no_shared_folder(self):
        state, query, makedirs, log = self.run_export(
            WMCompleted([], 0, f"SERIAL|ABC123\nHASH|{HASH}\n", ""))
        self.assertEqual(state, "done", log)
        makedirs.assert_not_called()
        script = query.call_args.args[0]
        for forbidden in ("Out-File", "Set-Content", "PowerShell\\", "-File"):
            self.assertNotIn(forbidden, script)
        self.assertNotIn("C:\\PowerShell", log)

    def test_csv_is_the_layout_intune_imports(self):
        state, _query, _makedirs, log = self.run_export(
            WMCompleted([], 0, f"SERIAL|ABC123\nHASH|{HASH}\n", ""))
        self.assertEqual(state, "done", log)
        [name] = os.listdir(self.folder)
        data = Path(self.folder, name).read_bytes()
        self.assertEqual(data, (f"Device Serial Number,Windows Product ID,Hardware Hash\r\n"
                                f"ABC123,,{HASH}\r\n").encode("ascii"))

    def test_failure_is_not_followed_by_completed(self):
        state, _q, _m, log = self.run_export(WMCompleted([], 1, "ERR|Access denied\n", ""))
        self.assertEqual(state, "fail")
        self.assertIn("Access denied", log)
        self.assertNotIn("completed", log.lower())

    def test_shared_folder_is_no_longer_an_allowed_root(self):
        from winmend.core.security import SecurityUtils
        with self.assertRaises(ValueError):
            SecurityUtils.sanitize_path("C:\\PowerShell\\Get-AutoPilotInfo.ps1")


def _ev(event_id, when, update="", code="", title="Update"):
    return parse_update_event(f"EV|{event_id}|{when}|{update}|{code}|{title}")


KB = "6a784757-f861-4592-8657-627f630f6d2f"
TITLE = "2026-11 Security Update (KB5132061) (26300.9974)"


class UpdateErrorTests(unittest.TestCase):
    def test_this_pcs_kb5132061_failure_is_already_resolved(self):
        events = [_ev(20, "2026-11-11T22:05:43", KB, "0x80070002", TITLE),
                  _ev(19, "2026-11-13T03:13:26", KB, "", TITLE)]
        current, resolved = classify_update_errors(events)
        self.assertEqual(current, [])
        self.assertEqual(resolved[0][1]["update"], KB)

    def test_a_failure_with_no_later_install_of_that_update_is_current(self):
        events = [_ev(19, "2026-11-10T00:00:00", KB, "", TITLE),  # success BEFORE the failure
                  _ev(20, "2026-11-11T00:00:00", KB, "0x80070002", TITLE),
                  _ev(19, "2026-11-12T00:00:00", "other-update", "", "Defender intelligence")]
        current, resolved = classify_update_errors(events)
        self.assertEqual(len(current), 1)
        self.assertEqual(resolved, [])

    def test_an_error_naming_no_update_is_cleared_by_any_later_install(self):
        events = [_ev(25, "2026-11-11T00:00:00", "", "", "Windows Update failed to check"),
                  _ev(19, "2026-11-12T00:00:00", "x", "", "Defender intelligence")]
        self.assertEqual(classify_update_errors(events)[0], [])

    def test_store_apps_are_ignored_both_ways(self):
        events = [_ev(20, "2026-11-11T00:00:00", "s", "0x80073D02", "9PLM9XGG6VKS-OpenAI.Codex"),
                  _ev(25, "2026-11-11T00:00:00", "", "", "Windows Update failed to check"),
                  _ev(19, "2026-11-12T00:00:00", "y", "", "9NRZT3Q9R3DL-Microsoft.WindowsAppRuntime.2")]
        current, resolved = classify_update_errors(events)
        self.assertEqual([e["id"] for e in current], [25])  # a Store install proves nothing
        self.assertEqual(resolved, [])

    def test_malformed_lines_are_dropped(self):
        for line in ("EV|x|2026-11-11T00:00:00|||t", "EV|20|yesterday|||t", "EV|20|2026"):
            self.assertIsNone(parse_update_event(line))

    def forensic(self, stdout):
        host = WMTaskHost(None)
        with mock.patch.object(host, "_run_ps", return_value=WMCompleted([], 0, stdout, "")), \
                mock.patch.object(host, "reset_windows_update") as reset, \
                mock.patch.object(host, "check_and_install_windows_updates") as check:
            state = run(host, "windows_update_forensic")
        return state, reset, check, drain(host)

    def test_forensic_fixer_leaves_components_alone_when_resolved(self):
        out = ("SVC|wuauserv|Stopped|Automatic\nREBOOT|False\n"
               f"EV|20|2026-11-11T22:05:43|{KB}|0x80070002|{TITLE}\n"
               f"EV|19|2026-11-13T03:13:26|{KB}||{TITLE}\n")
        state, reset, check, log = self.forensic(out)
        self.assertEqual(state, "done", log)
        reset.assert_not_called()
        check.assert_called_once()
        self.assertIn("already resolved", log)

    def test_forensic_fixer_still_resets_for_a_current_failure(self):
        out = f"REBOOT|False\nEV|20|2026-11-11T22:05:43|{KB}|0x80070002|{TITLE}\n"
        _state, reset, _check, log = self.forensic(out)
        reset.assert_called_once()
        self.assertIn("failed to install (0x80070002)", log)


class PartialInstallTests(unittest.TestCase):
    def outcome(self, rc):
        host = WMTaskHost(None)
        with mock.patch.object(host, "_run_live_command", return_value=(rc, False)):
            state = run(host, "windows_updates")
        return state, drain(host)

    def test_result_codes(self):
        for rc, state, restart in ((0, "done", False), (2, "done", True),
                                   (3, "fail", False), (4, "fail", True), (1, "fail", False)):
            with self.subTest(rc=rc):
                got, log = self.outcome(rc)
                self.assertEqual(got, state, log)
                self.assertEqual("REBOOTRECOMMEND" in log, restart, log)

    @unittest.skipUnless(shutil.which("powershell"), "needs Windows PowerShell")
    def test_update_script_parses(self):
        tree = ast.parse((ROOT / "winmend" / "features" / "updates.py").read_text(encoding="utf-8"))
        scripts = [n.value.value for n in ast.walk(tree)
                   if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "ps_script"]
        self.assertTrue(scripts)
        for script in scripts:
            self.assertIn("GetUpdateResult", script)
            with tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False, encoding="utf-8-sig") as fh:
                fh.write(script)
            self.addCleanup(os.unlink, fh.name)
            check = ("$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile("
                     f"'{fh.name}',[ref]$null,[ref]$e); if($e){{$e|%{{$_.Message}}; exit 1}}")
            r = subprocess.run(["powershell", "-NoProfile", "-Command", check],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


# Captured from Windows PowerShell 5.1 on this PC, redirected as WinMend runs it.
PS_CMDLET = """Get-AppxProvisionedPackage : The requested operation requires elevation.
At line:1 char:1
+ Get-AppxProvisionedPackage -Online -ErrorAction Stop
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Get-AppxProvisionedPackage], COMException
    + FullyQualifiedErrorId : Microsoft.Dism.Commands.GetAppxProvisionedPackageCommand

"""
PS_WRITE_ERROR = """try {
  $x = 1
  throw 'inner'
} catch {
  Write-Error "Error checking/installing updates: $($_.Exception.Message)"
  exit 1
} : Error checking/installing updates: inner
    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException
    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException

"""
PS_THROW = """The thing broke badly
At line:3 char:5
+     throw 'The thing broke badly'
+     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : OperationStopped: (The thing broke badly:String) [], RuntimeException
    + FullyQualifiedErrorId : The thing broke badly

"""
PS_WRAPPED = """Write-Error ('This is a deliberately long error message that keeps going ' * 2) : This is a deliberately long error
message that keeps going This is a deliberately long error message that keeps going
    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException
    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException

"""
PS_TWO = """Get-Item : Cannot find path 'C:\\nope1' because it does not exist.
At line:1 char:1
+ Get-Item C:\\nope1 -ErrorAction Continue; Get-Item C:\\nope2
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (C:\\nope1:String) [Get-Item], ItemNotFoundException
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.GetItemCommand

Get-Item : Cannot find path 'C:\\nope2' because it does not exist.
At line:1 char:42
+ Get-Item C:\\nope1 -ErrorAction Continue; Get-Item C:\\nope2
+                                          ~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (C:\\nope2:String) [Get-Item], ItemNotFoundException
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.GetItemCommand

"""


class PowerShellMessageTests(unittest.TestCase):
    def test_the_message_not_the_error_id(self):
        cases = {
            PS_CMDLET: "The requested operation requires elevation.",
            PS_WRITE_ERROR: "Error checking/installing updates: inner",
            PS_THROW: "The thing broke badly",
            PS_WRAPPED: ("This is a deliberately long error message that keeps going "
                         "This is a deliberately long error message that keeps going"),
            PS_TWO: "Cannot find path 'C:\\nope2' because it does not exist.",
        }
        for text, expected in cases.items():
            with self.subTest(expected=expected[:30]):
                self.assertEqual(_wm_last_line(text), expected)

    def test_other_output_keeps_its_last_line(self):
        self.assertEqual(_wm_last_line("step 1 ok\nstep 2: access denied\n"), "step 2: access denied")
        self.assertEqual(_wm_last_line("", "fallback\n"), "fallback")
        self.assertEqual(_wm_last_line(None, ""), "")

    def test_debloat_now_says_why(self):
        # What the sweep saw: unelevated, both inventory cmdlets refuse.
        host = WMTaskHost(None)
        with mock.patch.object(host, "_run_ps", return_value=WMCompleted([], 1, "", PS_CMDLET)):
            host._run_debloat("Debloat Windows", extreme=False)
        log = drain(host)
        self.assertIn("Could not list the installed apps: The requested operation requires elevation.", log)
        self.assertNotIn("FullyQualifiedErrorId", log)


class MissingHardwareTests(unittest.TestCase):
    def test_no_battery_is_a_skip(self):
        host = WMTaskHost(None)
        with mock.patch.object(power, "wm_run", return_value=WMCompleted([], 0, "0\n", "")) as query:
            self.assertEqual(run(host, "battery_health_report"), "skip")
        self.assertEqual(query.call_count, 1)  # no powercfg /batteryreport

    def test_no_wifi_adapter_is_a_skip(self):
        host = WMTaskHost(None)
        reply = WMCompleted([], 1, "There is no wireless interface on the system.\n", "")
        with mock.patch("winmend.features.network.wm_run", return_value=reply):
            self.assertEqual(run(host, "wifi_channel_analyzer"), "skip")


class SystemUuidTests(unittest.TestCase):
    def test_uuid_is_the_firmware_uuid_not_the_mac(self):
        reporter = PCReporter()
        with mock.patch.object(PCReporter, "_ps", return_value="4c4c4544-0042-3510-8058-b4c04f4d3233\r\n"):
            self.assertEqual(reporter._system_uuid(), "4C4C4544-0042-3510-8058-B4C04F4D3233")
        with mock.patch.object(PCReporter, "_ps", return_value=""):
            self.assertEqual(reporter._system_uuid(), "Unavailable")
        with mock.patch.object(PCReporter, "_ps", return_value="4c4c4544\n"):
            reporter.collect_system_info()
        self.assertNotEqual(reporter.report_data["system_info"]["System UUID"], str(uuid.getnode()))


if __name__ == "__main__":
    unittest.main()
