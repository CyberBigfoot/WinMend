"""Regression tests for the September 2026 whole-app audit.

Each class pins one defect the audit proved on a real Windows 11 25H2 PC:

* a task that caught its own error was drawn as a green "Completed";
* a delayed callback armed from a worker thread never fired, so the restart
  prompts after Windows Updates and Check Disk never appeared;
* the search box filtered only the page on screen, and the symptom matcher
  could not match "Wi-Fi" or any keyword with an apostrophe;
* changing the drive mid-scan built the Storage tree for the wrong root;
* the Debloat lists would silently remove Teams, the Store and OneDrive;
* Reset File Associations ignored UserChoiceLatest and used a registry path
  for web links that does not exist;
* Guided Fix called a VPN's DNS "rogue" and a deliberately disabled Windows
  Search "broken", then offered a start that cannot work on it;
* quitting mid-task left the task's processes running.

Nothing here changes the real system: registry work happens under a scratch
HKCU key, and the only processes started are short-lived Python children.
"""

import os
import queue
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None

try:
    from PySide6.QtWidgets import QApplication
    HAVE_QT = True
except ImportError:  # pragma: no cover
    HAVE_QT = False

import winmend_diagnostics as D  # noqa: E402
from winmend.diagnostics.repairs import services as services_module
from winmend.features import network as network_module
from winmend.ui.pages import storage as storage_module
from winmend_safety import (  # noqa: E402
    ONEDRIVE_DEBLOAT_KEY, build_debloat_options, delete_registry_tree, reset_user_choices,
)


def _app():
    return QApplication.instance() or QApplication([])


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class FailureChannelTests(unittest.TestCase):
    """A failure a handler only logged used to read as success."""

    @classmethod
    def setUpClass(cls):
        import WinMend
        cls.W = WinMend

    def test_report_failure_logs_the_line_and_keeps_the_first_reason(self):
        host = self.W.WMTaskHost(None)
        host._report_failure("PROGRESS:Disk Health:Could not read disk health: access denied")
        host._report_failure("PROGRESS:Disk Health:a second, later problem")
        self.assertEqual(host._task_failure, "Could not read disk health: access denied")
        logged = [host.queue.get_nowait() for _ in range(host.queue.qsize())]
        self.assertEqual(len(logged), 2, "both lines still reach the activity log")

    class _Host:
        def __init__(self, handler):
            self.queue = queue.Queue()
            self.cancel_event = threading.Event()
            self.admin_status = True
            self._task_failure = None
            self.handler = handler

        def __getattr__(self, name):
            if name.startswith("_"):
                raise AttributeError(name)
            return lambda: self.handler(self)

        def _report_failure(self, message):
            self.queue.put(message)
            if self._task_failure is None:
                self._task_failure = message.split(":", 2)[-1]

    def _run(self, handler, task_id="disk_smart_check"):
        window = self.W.WMMainWindow.__new__(self.W.WMMainWindow)
        window.host = self._Host(handler)
        window.journal = None
        window.diagnostic_engine = None
        window.simple = False
        task = next(t for t in self.W.WM_TASKS if t.id == task_id)
        self.W.WMMainWindow._worker(window, [task])
        lines = [window.host.queue.get_nowait() for _ in range(window.host.queue.qsize())]
        self.assertFalse([line for line in lines if "Unexpected runner error" in line], lines)
        return [line for line in lines if line.startswith("TASKEND:")]

    def test_a_reported_failure_ends_the_task_as_failed(self):
        ends = self._run(lambda host: host._report_failure("PROGRESS:Disk Health:no disks"))
        self.assertEqual(ends, ["TASKEND:disk_smart_check:fail"])

    def test_a_clean_run_still_ends_as_done(self):
        ends = self._run(lambda host: host.queue.put("PROGRESS:Disk Health:All drives Healthy."))
        self.assertEqual(ends, ["TASKEND:disk_smart_check:done"])

    def test_stop_outranks_a_failure(self):
        def stop_then_fail(host):
            host.cancel_event.set()
            host._report_failure("PROGRESS:Disk Health:interrupted")
        ends = self._run(stop_then_fail)
        self.assertEqual(ends, ["TASKEND:disk_smart_check:cancel"])

    def test_guided_fix_steps_read_the_same_channel(self):
        window = self.W.WMMainWindow.__new__(self.W.WMMainWindow)
        window.host = self._Host(lambda host: host._report_failure("PROGRESS:x:it broke"))
        step = {"kind": "task", "id": "disk_smart_check", "title": "Disk Health", "admin": False}
        state, message, _undo = self.W.WMMainWindow._run_step(window, step, lambda _m: None)
        self.assertEqual(state, "fail")
        self.assertIn("it broke", message)


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class DelayedCallbackTests(unittest.TestCase):
    """root.after(ms > 0) from a worker thread must still fire."""

    def test_delayed_call_from_a_worker_thread_runs_on_the_ui_thread(self):
        import WinMend as W
        app = _app()
        stub = W.WMRootStub(None)
        fired = []
        ui_thread = threading.get_ident()
        worker = threading.Thread(
            target=lambda: stub.after(50, lambda: fired.append(threading.get_ident())))
        worker.start()
        worker.join()
        deadline = time.time() + 3
        while not fired and time.time() < deadline:
            app.processEvents()
            time.sleep(0.01)
        self.assertEqual(fired, [ui_thread])


class QueryNormalisationTests(unittest.TestCase):
    """The symptom matcher and the search box read text the same way."""

    @classmethod
    def setUpClass(cls):
        import WinMend
        cls.W = WinMend

    def test_hyphens_apostrophes_and_symbols(self):
        norm = self.W.wm_normalize_query
        self.assertEqual(norm("Wi-Fi keeps dropping"), "wifi keeps dropping")
        self.assertEqual(norm("I can\u2019t connect"), "i cant connect")
        self.assertEqual(norm("100% CPU!"), "100 cpu")
        self.assertEqual(norm("Hyper-V"), "hyperv")

    def test_terms_match_at_the_start_of_a_word_only(self):
        has = self.W.wm_query_has
        self.assertTrue(has("keeps crashing", "crash"))
        self.assertFalse(has("my report is slow", "port"), "'port' inside 'report'")
        self.assertFalse(has("the program froze", "ram"), "'ram' inside 'program'")
        self.assertTrue(has("i cant connect", "can't connect"))

    def test_the_matcher_now_answers_what_it_used_to_miss(self):
        host = self.W.WMTaskHost(None)
        cases = {
            "Wi-Fi keeps dropping": "wlan_report",
            "I can't connect to anything": "network_diagnostic_bundle",
            "bluetooth won't pair": "bluetooth_repair",
        }
        for query, expected in cases.items():
            with self.subTest(query=query):
                ranked, _reason = host._recommend_tasks_for_query(query)
                self.assertIn(expected, ranked)


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class GlobalSearchTests(unittest.TestCase):
    """The search box searches every task, not the page on screen."""

    @classmethod
    def setUpClass(cls):
        import WinMend
        cls.W = WinMend
        cls.window = WinMend.WMMainWindow.__new__(WinMend.WMMainWindow)
        cls.window.host = WinMend.WMTaskHost(None)

    def search(self, text):
        return self.W.WMMainWindow._search_task_ids(self.window, text)

    def test_the_placeholder_examples_find_tasks(self):
        for text, expected in (("PC is slow", "clean_temp"), ("no internet", "flush_dns"),
                               ("blue screen", "bsod_triage"), ("printer", "clear_print_spooler")):
            with self.subTest(text=text):
                found, explanation = self.search(text)
                self.assertIn(expected, found)
                self.assertTrue(explanation)

    def test_a_task_name_ranks_first(self):
        found, _ = self.search("cpu stress")
        self.assertEqual(found[0], "cpu_stress_test")

    def test_a_mere_mention_ranks_below_the_suggestions(self):
        # Debloat's description explains a restore point cannot bring apps
        # back; that must not put it ahead of the restore-point tools.
        found, _ = self.search("restore point")
        self.assertLess(found.index("system_restore_browser"), found.index("debloat_windows"))

    def test_gibberish_gets_the_labelled_check_up_pack(self):
        found, explanation = self.search("xyzzy")
        self.assertTrue(found)
        self.assertIn("general check-up", explanation)

    def test_only_real_task_ids_are_returned(self):
        known = {t.id for t in self.W.WM_TASKS}
        for text in ("pc is slow", "virus", "privacy", "security check", "camera"):
            with self.subTest(text=text):
                found, _ = self.search(text)
                self.assertTrue(set(found) <= known)


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class StorageScanRootTests(unittest.TestCase):
    """The tree is built for the drive that was scanned, not the combo's value."""

    def test_finish_uses_the_scanned_path(self):
        import WinMend as W
        page = mock.MagicMock()
        page.scan_path = "C:\\"
        page.drive.currentData.return_value = "D:\\"   # changed mid-scan
        page.results = {}
        page.right_view = "Folders"
        page.started = time.time()
        page.scanner.is_running = False
        page.scanner.total_files = 0
        page.scanner.total_errors = 0
        with mock.patch.object(storage_module, "wm_build_tree") as build:
            build.return_value.size = 0
            W.WMStoragePage._finish_scan(page)
        build.assert_called_once_with({}, "C:\\")
        page.drive.setEnabled.assert_called_with(True)


class DebloatChecklistTests(unittest.TestCase):
    """Only what is installed is listed, and nothing risky is pre-ticked."""

    def rows(self, installed, extreme=False, **kwargs):
        return {row["key"]: row for row in
                build_debloat_options(installed, [], extreme, **kwargs)}

    def test_absent_apps_are_not_offered(self):
        rows = self.rows({"Microsoft.BingNews"})
        self.assertEqual(list(rows), ["Microsoft.BingNews"])
        self.assertTrue(rows["Microsoft.BingNews"]["checked"])

    def test_apps_people_use_are_listed_unticked(self):
        rows = self.rows({"MSTeams", "SpotifyAB.SpotifyMusic"})
        self.assertFalse(rows["MSTeams"]["checked"])
        self.assertFalse(rows["Spotify"]["checked"])
        self.assertEqual(rows["Spotify"]["packages"], ["SpotifyAB.SpotifyMusic"])

    def test_extreme_explains_what_breaks_and_leaves_it_unticked(self):
        rows = self.rows({"Microsoft.WindowsStore", "Microsoft.WindowsCalculator"}, extreme=True)
        for key in ("Microsoft.WindowsStore", "Microsoft.WindowsCalculator"):
            with self.subTest(key=key):
                self.assertFalse(rows[key]["checked"])
                self.assertIn("breaks", rows[key]["detail"])
        self.assertNotIn("Microsoft.WindowsStore",
                         self.rows({"Microsoft.WindowsStore"}, extreme=False),
                         "the standard list never touches Windows' own apps")

    def test_onedrive_is_optional_and_warns_about_synced_folders(self):
        self.assertNotIn(ONEDRIVE_DEBLOAT_KEY, self.rows(set(), extreme=True))
        rows = self.rows(set(), extreme=True, onedrive_present=True, onedrive_holds_files=True)
        self.assertFalse(rows[ONEDRIVE_DEBLOAT_KEY]["checked"])
        self.assertIn("Desktop or Documents", rows[ONEDRIVE_DEBLOAT_KEY]["detail"])


@unittest.skipIf(winreg is None, "Windows only")
class ResetUserChoicesTests(unittest.TestCase):
    """Works on a scratch copy of the association keys, never the real ones."""

    SCRATCH = r"Software\WinMend\Tests\UserChoice"
    EXTS = SCRATCH + r"\FileExts"
    URLS = SCRATCH + r"\UrlAssociations"

    def setUp(self):
        delete_registry_tree(winreg.HKEY_CURRENT_USER, self.SCRATCH)

    def tearDown(self):
        delete_registry_tree(winreg.HKEY_CURRENT_USER, self.SCRATCH)

    def _make(self, subkey):
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "ProgId", 0, winreg.REG_SZ, "SomeApp.Document")

    def _exists(self, subkey):
        try:
            winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey).Close()
            return True
        except OSError:
            return False

    def reset(self, extensions, protocols):
        return reset_user_choices(extensions, protocols, root=winreg.HKEY_CURRENT_USER,
                                  file_exts_key=self.EXTS, url_key=self.URLS)

    def test_clears_both_user_choice_keys(self):
        self._make(self.EXTS + r"\.txt\UserChoice")
        # 24H2 and later read UserChoiceLatest first, with the ProgId a level down.
        self._make(self.EXTS + r"\.txt\UserChoiceLatest\ProgId")
        self.assertEqual(self.reset([".txt"], []), {".txt": "cleared"})
        self.assertFalse(self._exists(self.EXTS + r"\.txt\UserChoice"))
        self.assertFalse(self._exists(self.EXTS + r"\.txt\UserChoiceLatest"))
        self.assertTrue(self._exists(self.EXTS + r"\.txt"), "only the choice is removed")

    def test_web_links_use_the_url_associations_key(self):
        self._make(self.URLS + r"\https\UserChoice")
        result = self.reset([], ["https", "http"])
        self.assertEqual(result, {"https": "cleared", "http": "not set"})

    def test_an_unset_type_is_reported_as_such(self):
        self.assertEqual(self.reset([".pdf"], []), {".pdf": "not set"})


class DnsRecognitionTests(unittest.TestCase):
    """A VPN's resolver or the network's own is not a hijack."""

    def test_the_shared_address_range_is_not_public(self):
        self.assertTrue(D._is_private_address("100.95.0.251"))     # Twingate
        self.assertTrue(D._is_private_address("100.100.100.100"))  # Tailscale
        self.assertFalse(D._is_private_address("100.128.0.1"))
        self.assertFalse(D._is_private_address("8.8.8.8"))

    def _collect(self, rows):
        probe = D.DeepProbe.__new__(D.DeepProbe)
        with mock.patch.object(D.DeepProbe, "_ps_rows", return_value=(0, rows, "")):
            return probe.dns_servers()

    def test_only_typed_in_public_unknown_servers_are_unrecognised(self):
        result = self._collect([
            ["Twingate", "100.95.0.251,203.0.113.9", "dhcp", "Twingate TAP-Windows Adapter V9"],
            ["Ethernet", "203.0.113.53", "dhcp", "Realtek PCIe GbE Family Controller"],
            ["Wi-Fi", "198.51.100.7,1.1.1.1", "static", "Intel(R) Wi-Fi 6 AX201"],
        ])
        self.assertEqual(result["unrecognised"], ["198.51.100.7"])
        self.assertEqual(result["from_network"], ["203.0.113.53"])
        vpn = {entry["interface"]: entry["vpn"] for entry in result["interfaces"]}
        self.assertEqual(vpn, {"Twingate": True, "Ethernet": False, "Wi-Fi": False})

    def test_hijack_repair_depends_on_where_the_servers_came_from(self):
        def plan(source):
            raw = {"dns_resolution": {"available": True, "hijacked": True,
                                      "wildcard_address": "203.0.113.80"},
                   "dns_servers": {"available": True, "unrecognised": [], "from_network": [],
                                   "interfaces": [{"interface": "Ethernet", "source": source,
                                                   "vpn": False, "servers": [
                                                       {"address": "203.0.113.53", "known": ""}]}]}}
            engine = D.CaseEngine(probe=_Scripted(raw))
            case = engine.build_case("websites go to the wrong page", answers={"onset": "week"})
            return [s["id"] for s in case["plan"]]
        self.assertNotIn("reset_dns_servers", plan("static"))
        dhcp = plan("dhcp")
        self.assertNotIn("reset_dns_servers", dhcp, "automatic cannot undo what DHCP hands out")
        self.assertNotIn("change_dns", dhcp)


class _Scripted:
    """A probe answering from a dict, with the healthy defaults the engine expects."""

    def __init__(self, overrides):
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from test_winmend_diagnostics import HEALTHY
        self.data = dict(HEALTHY)
        self.data.update(overrides)

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return lambda *a, **k: self.data.get(name, {"available": False})


class WindowsSearchDisabledTests(unittest.TestCase):
    """Disabled on purpose is not broken, and a disabled service cannot be started."""

    DISABLED = {"search_index": {"available": True, "service": "stopped", "start": "disabled",
                                 "disabled": True, "setup_complete": True, "healthy": False}}

    def test_a_full_check_does_not_call_it_broken(self):
        case = D.CaseEngine(probe=_Scripted(self.DISABLED)).audit()
        self.assertNotIn("search_broken", [h["id"] for h in case["hypotheses"]])
        finding = next(f for f in case["findings"] if f["key"] == "search_index")
        self.assertEqual(finding["status"], "info")

    def test_a_search_complaint_offers_to_turn_it_back_on(self):
        case = D.CaseEngine(probe=_Scripted(self.DISABLED)).build_case(
            "windows search finds nothing", answers={"onset": "week"})
        self.assertNotIn("search_broken", [h["id"] for h in case["hypotheses"]])
        steps = [s["id"] for s in case["plan"]]
        self.assertNotIn("set_service_startup", steps)
        self.assertNotIn("restart_service", steps)

    def test_a_merely_stopped_service_still_gets_a_start(self):
        stopped = {"search_index": {"available": True, "service": "stopped", "start": "auto",
                                    "disabled": False, "setup_complete": True, "healthy": False}}
        case = D.CaseEngine(probe=_Scripted(stopped)).audit()
        self.assertIn("search_broken", [h["id"] for h in case["hypotheses"]])
        self.assertIn("restart_service", [s["id"] for s in case["plan"]])

    def test_restart_service_refuses_a_disabled_service_without_touching_it(self):
        with mock.patch.object(services_module, "_service_start", return_value=4), \
                mock.patch.object(services_module, "_run_command",
                                  side_effect=AssertionError("must not run sc")):
            result = D.REPAIR_ACTIONS["restart_service"].run({"name": "WSearch"})
        self.assertFalse(result["ok"])
        self.assertIn("Disabled", result["message"])


NETSH_BSSID = """
Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : HomeMesh
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:00:00:01
         Signal             : 92%
         Radio type         : 802.11ax
         Band               : 5 GHz
         Channel            : 36
    BSSID 2                 : aa:bb:cc:00:00:02
         Signal             : 70%
         Radio type         : 802.11n
         Band               : 2.4 GHz
         Channel            : 6

SSID 2 : Neighbour
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : dd:ee:ff:00:00:01
         Signal             : 40%
         Radio type         : 802.11n
         Band               : 2.4 GHz
         Channel            : 6
"""


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class WifiAnalyzerTests(unittest.TestCase):
    """Every access point counts -- a dual-band router is two radios."""

    def test_each_bssid_is_its_own_row(self):
        import WinMend as W
        host = W.WMTaskHost(None)
        result = mock.Mock(stdout=NETSH_BSSID, stderr="", returncode=0)
        with mock.patch.object(network_module, "wm_run", return_value=result):
            host.run_wifi_channel_analyzer()
        lines = [host.queue.get_nowait() for _ in range(host.queue.qsize())]
        text = "\n".join(lines)
        self.assertIn("Found 3 access point(s) on 2 network(s)", text)
        self.assertIn("Ch   36", text)   # HomeMesh's 5 GHz radio was dropped before
        self.assertIn("ch 6 (2.4 GHz): 2", text)
        self.assertIn("Least crowded 2.4 GHz channel of 1/6/11: 1", text)
        self.assertIsNone(host._task_failure)


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class PCReportDriveTests(unittest.TestCase):
    """One unreadable drive used to end the whole PC Report."""

    def test_an_unreadable_volume_gets_a_line_instead_of_an_exception(self):
        import psutil
        import WinMend as W
        Part = type("Part", (), {})
        good, raw = Part(), Part()
        good.device, good.mountpoint, good.fstype = "C:\\", "C:\\", "NTFS"
        raw.device, raw.mountpoint, raw.fstype = "D:\\", "D:\\", ""
        from collections import namedtuple
        usage = namedtuple("usage", "total used free percent")(
            100 * 2**30, 40 * 2**30, 60 * 2**30, 40.0)

        def disk_usage(path):
            if path.startswith("D"):
                raise OSError(22, "The volume does not contain a recognized file system",
                              None, 1005)
            return usage

        reporter = W.PCReporter()
        with mock.patch.object(psutil, "disk_partitions", return_value=[good, raw]), \
                mock.patch.object(psutil, "disk_usage", side_effect=disk_usage), \
                mock.patch.object(psutil, "cpu_percent",
                                  side_effect=lambda interval=None, percpu=False:
                                  [1.0, 2.0] if percpu else 1.0), \
                mock.patch.object(W.PCReporter, "_get_memory_speed", return_value="3600 MHz"), \
                mock.patch.object(W.PCReporter, "_get_drive_type", return_value="SSD"), \
                mock.patch.object(W.PCReporter, "_ps", return_value=""):
            try:
                reporter.collect_hardware_info()
            except OSError as exc:  # pragma: no cover - the regression
                self.fail(f"the report died on an unreadable drive: {exc}")
        storage = next(v for v in reporter.report_data["hardware"].values()
                       if isinstance(v, dict) and "Drive D:\\" in v)
        self.assertIn("unreadable", storage["Drive D:\\"]["Status"])
        self.assertEqual(storage["Drive C:\\"]["Drive Type"], "SSD")


@unittest.skipUnless(HAVE_QT, "PySide6 is not installed")
class ChildProcessTests(unittest.TestCase):
    """What a task starts, quitting WinMend ends."""

    @classmethod
    def setUpClass(cls):
        import WinMend
        cls.W = WinMend

    def test_kill_children_ends_tracked_processes(self):
        child = self.W.wm_track_child(subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        try:
            self.assertGreaterEqual(self.W.wm_kill_children(), 1)
            child.wait(timeout=15)
            self.assertIsNotNone(child.poll())
        finally:
            self.W.wm_untrack_child(child)
            if child.poll() is None:
                child.kill()

    def test_wm_run_gives_children_an_empty_stdin(self):
        # A tool that stops to ask a question must read end-of-file, not wait
        # forever on an input nobody can see. Bounded by a cancel, in case.
        cancel = threading.Event()
        timer = threading.Timer(20, cancel.set)
        timer.start()
        try:
            result = self.W.wm_run(
                [sys.executable, "-c", "import sys; print(repr(sys.stdin.read()))"],
                capture_output=True, text=True, cancel_event=cancel)
        finally:
            timer.cancel()
        self.assertFalse(cancel.is_set(), "the child waited on stdin")
        self.assertEqual(result.stdout.strip(), "''")


if __name__ == "__main__":
    unittest.main()
