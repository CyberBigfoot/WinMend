"""Tests for the Office & Outlook repair helpers: the licence parser, the
add-in/crash matcher, the auth watchlist, the data-file ceiling, and the
option builder that turns a measured report into the checklist.

Facts measured on a real Windows 11 PC with Microsoft 365 (Click-to-Run):

* `OSPP.VBS /dstatus` prints "<No installed product keys detected>" for a
  subscription -- an empty product list is normal there, not a fault.
* Event 1000 properties are 0=app, 3=module, 6=exception, 11=module path.
* The Teams meeting add-in's ProgId has no CLSID of its own; it points at
  `TeamsAddin.FastConnect.1` through CurVer. Office's built-in add-ins live in
  the Click-to-Run virtual registry and under Office's own folder, which is
  why a crash inside OUTLOOK.EXE must never be pinned on one of them.
* An Exchange account's .ost path sits in profile property 001f6610, not the
  PST property 001f6700.
"""

import unittest
from winmend.features.office import operations as office_module

from winmend_safety import (
    OFFICE_AUTH_WATCHLIST,
    OUTLOOK_DEFAULT_SIZE_LIMIT_MB,
    addin_for_module,
    build_office_repair_options,
    classify_office_crash,
    data_file_verdict,
    decode_utf16_path,
    office_auth_findings,
    office_c2r_repair_command,
    office_c2r_update_command,
    office_credential_targets,
    parse_cmdkey_list,
    parse_office_crash_output,
    parse_ospp_status,
    summarize_office_crashes,
    windowless_processes,
)

OFFICE_ROOT = r"C:\Program Files\Microsoft Office"

TEAMS = {"hive": "HKCU", "key": r"Software\Microsoft\Office\Outlook\Addins\TeamsAddin.FastConnect",
         "progid": "TeamsAddin.FastConnect", "name": "Microsoft Teams Meeting Add-in",
         "load_behavior": 3, "behavior": "on at startup",
         "path": r"C:\Users\me\AppData\Local\Microsoft\TeamsMeetingAdd-in\1.26\x64\Microsoft.Teams.AddinLoader.dll",
         "home": r"C:\Users\me\AppData\Local\Microsoft\TeamsMeetingAdd-in\1.26\x64"}
SKYPE = {"hive": "HKLM", "key": r"Software\Microsoft\Office\Outlook\Addins\UCAddin.LyncAddin.1",
         "progid": "UCAddin.LyncAddin.1", "name": "Skype Meeting Add-in", "load_behavior": 3,
         "behavior": "on at startup", "path": OFFICE_ROOT + r"\root\Office16\UCADDIN.DLL",
         "home": OFFICE_ROOT + r"\root\Office16"}
ADDINS = [TEAMS, SKYPE]


class OsppTests(unittest.TestCase):
    def test_subscription_reports_no_keys_and_that_is_an_empty_list(self):
        text = ("---Processing--------------------------\n---------------------------------------\n"
                "<No installed product keys detected>\n---------------------------------------\n"
                "---Exiting-----------------------------\n")
        self.assertEqual(parse_ospp_status(text), [])

    def test_keyed_products_are_parsed_with_status_grace_and_error(self):
        text = """
        PRODUCT ID: 00000-00000-00000-AA000
        SKU ID: 6f327760-8c5c-417c-9b61-836a98287e0c
        LICENSE NAME: Office 21, Office21ProPlus2021VL_KMS_Client_AE edition
        LICENSE DESCRIPTION: Office 21, VOLUME_KMSCLIENT channel
        BETA EXPIRATION: 1/1/1601
        LICENSE STATUS:  ---NOTIFICATIONS---
        ERROR CODE: 0xC004F074
        ERROR DESCRIPTION: The Software Licensing Service reported that the product could not be activated.
        Last 5 characters of installed product key: XXXXX
        ---------------------------------------
        LICENSE NAME: Office 16, Office16ProPlusR_Grace edition
        LICENSE STATUS:  ---LICENSED---
        REMAINING GRACE: 29 days  (42480 minute(s) before expiring)
        """
        products = parse_ospp_status(text)
        self.assertEqual(len(products), 2)
        self.assertEqual(products[0]["status"], "NOTIFICATIONS")
        self.assertIn("0xC004F074", products[0]["error"])
        self.assertIn("could not be activated", products[0]["error"])
        self.assertEqual(products[1]["status"], "LICENSED")
        self.assertTrue(products[1]["grace"].startswith("29 days"))
        self.assertEqual(products[0]["key_tail"], "XXXXX")
        self.assertEqual(products[1]["key_tail"], "")


class CommandTests(unittest.TestCase):
    def test_quick_repair_command_matches_office_documentation(self):
        argv = office_c2r_repair_command(r"C:\x\OfficeClickToRun.exe", "quick", "x64", "en-us")
        self.assertEqual(argv[0], r"C:\x\OfficeClickToRun.exe")
        self.assertIn("scenario=Repair", argv)
        self.assertIn("RepairType=QuickRepair", argv)
        self.assertIn("platform=x64", argv)
        self.assertIn("culture=en-us", argv)
        self.assertIn("forceappshutdown=True", argv)
        self.assertIn("DisplayLevel=True", argv)

    def test_full_repair_and_update(self):
        self.assertIn("RepairType=FullRepair", office_c2r_repair_command("c.exe", "full"))
        argv = office_c2r_update_command(r"C:\x\OfficeC2RClient.exe")
        self.assertEqual(argv[:3], [r"C:\x\OfficeC2RClient.exe", "/update", "user"])


class AddinMatchTests(unittest.TestCase):
    def test_a_crash_inside_the_addin_folder_names_the_addin(self):
        module = r"C:\Users\me\AppData\Local\Microsoft\TeamsMeetingAdd-in\1.26\x64\Microsoft.Teams.AddinLoader.dll"
        self.assertIs(addin_for_module(module, ADDINS, OFFICE_ROOT), TEAMS)
        helper = r"C:\Users\me\AppData\Local\Microsoft\TeamsMeetingAdd-in\1.26\x64\helper.dll"
        self.assertIs(addin_for_module(helper, ADDINS, OFFICE_ROOT), TEAMS)

    def test_a_crash_in_outlook_itself_is_not_pinned_on_a_built_in_addin(self):
        module = OFFICE_ROOT + r"\root\Office16\OUTLOOK.EXE"
        self.assertIsNone(addin_for_module(module, ADDINS, OFFICE_ROOT))
        # but the built-in add-in's own DLL still matches by name
        self.assertIs(addin_for_module(OFFICE_ROOT + r"\root\Office16\UCADDIN.DLL", ADDINS, OFFICE_ROOT), SKYPE)

    def test_classification_by_module(self):
        self.assertEqual(classify_office_crash("OUTLOOK.EXE", OFFICE_ROOT + r"\root\Office16\OUTLOOK.EXE",
                                               ADDINS, OFFICE_ROOT)[0], "office")
        self.assertEqual(classify_office_crash("mso20win32client.dll", "", ADDINS, OFFICE_ROOT)[0], "office")
        self.assertEqual(classify_office_crash("nvwgf2umx.dll", r"C:\Windows\System32\DriverStore\x\nvwgf2umx.dll",
                                               ADDINS, OFFICE_ROOT)[0], "gpu")
        self.assertEqual(classify_office_crash("ntdll.dll", r"C:\Windows\SYSTEM32\ntdll.dll",
                                               ADDINS, OFFICE_ROOT, r"C:\Windows")[0], "windows")
        self.assertEqual(classify_office_crash("avhook.dll", r"C:\Program Files\Contoso AV\avhook.dll",
                                               ADDINS, OFFICE_ROOT, r"C:\Windows")[0], "other")
        self.assertEqual(classify_office_crash("", "", ADDINS, OFFICE_ROOT)[0], "unknown")
        cat, addin = classify_office_crash("Microsoft.Teams.AddinLoader.dll", TEAMS["path"], ADDINS, OFFICE_ROOT)
        self.assertEqual((cat, addin), ("addin", TEAMS))


class CrashEventTests(unittest.TestCase):
    OUT = ('[\n[{"time":"2026-09-10T08:00:00","id":1000,"app":"OUTLOOK.EXE","module":"Microsoft.Teams.AddinLoader.dll",'
           '"exception":"c0000005","module_path":"' + TEAMS["path"].replace("\\", "\\\\") + '"},'
           '{"time":"2026-09-11T08:00:00","id":1002,"app":"OUTLOOK.EXE","module":"","exception":"","module_path":""},'
           '{"time":"2026-09-12T08:00:00","id":1000,"app":"BMO.exe","module":"sip.pyd","exception":"c0000005","module_path":"C:\\\\x\\\\sip.pyd"},'
           '{"time":"2026-09-13T08:00:00","id":1000,"app":"EXCEL.EXE","module":"igd10iumd64.dll","exception":"c0000005",'
           '"module_path":"C:\\\\Windows\\\\System32\\\\DriverStore\\\\FileRepository\\\\igd10iumd64.dll"}]\n]\nWINMEND-EVENTS-DONE\n')

    def test_non_office_apps_are_dropped_and_hangs_kept(self):
        events = parse_office_crash_output(self.OUT)
        self.assertEqual([e["app"] for e in events], ["Outlook", "Outlook", "Excel"])
        self.assertEqual([e["kind"] for e in events], ["crash", "hang", "crash"])

    def test_missing_completion_marker_means_unreadable_not_clean(self):
        self.assertIsNone(parse_office_crash_output("[\n]\n"))
        self.assertEqual(parse_office_crash_output("[\n]\nWINMEND-EVENTS-DONE"), [])

    def test_single_row_object_is_accepted(self):
        out = ('[\n{"time":"t","id":1000,"app":"WINWORD.EXE","module":"wwlib.dll","exception":"c0000005",'
               '"module_path":""}\n]\nWINMEND-EVENTS-DONE')
        self.assertEqual(len(parse_office_crash_output(out)), 1)

    def test_summary_groups_by_cause(self):
        events = parse_office_crash_output(self.OUT)
        summary = summarize_office_crashes(events, ADDINS, OFFICE_ROOT)
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["hangs"], 1)
        self.assertEqual(summary["by_app"], {"Outlook": 2, "Excel": 1})
        self.assertEqual(summary["gpu"], 1)
        self.assertEqual(list(summary["addins"]), ["TeamsAddin.FastConnect"])
        self.assertEqual(summary["addins"]["TeamsAddin.FastConnect"]["count"], 1)


class AuthWatchlistTests(unittest.TestCase):
    def test_only_the_harmful_setting_is_a_finding(self):
        values = {("HKCU", r"Software\Microsoft\Office\16.0\Common\Identity", "EnableADAL"): 0,
                  ("HKCU", r"Software\Microsoft\Office\16.0\Outlook\AutoDiscover", "ExcludeExplicitO365Endpoint"): 0}
        findings = office_auth_findings(read=lambda h, k, v: values.get((h, k, v)))
        self.assertEqual([f["value"] for f in findings], ["EnableADAL"])
        self.assertIn("modern authentication", findings[0]["harm"])

    def test_absent_values_are_not_findings(self):
        self.assertEqual(office_auth_findings(read=lambda h, k, v: None), [])

    def test_every_watchlist_row_names_a_consequence(self):
        for row in OFFICE_AUTH_WATCHLIST:
            self.assertEqual(len(row), 5)
            self.assertTrue(len(row[4]) > 20, row)


class DataFileTests(unittest.TestCase):
    def test_ceiling_verdicts(self):
        gb = 1024 ** 3
        self.assertEqual(data_file_verdict(6 * gb, OUTLOOK_DEFAULT_SIZE_LIMIT_MB)[0], "good")
        self.assertEqual(data_file_verdict(42 * gb, OUTLOOK_DEFAULT_SIZE_LIMIT_MB)[0], "warn")
        self.assertEqual(data_file_verdict(49 * gb, OUTLOOK_DEFAULT_SIZE_LIMIT_MB)[0], "bad")
        self.assertIn("50 GB ceiling", data_file_verdict(49 * gb, OUTLOOK_DEFAULT_SIZE_LIMIT_MB)[1])

    def test_utf16_store_path_decoding(self):
        blob = "C:\\Users\\me\\AppData\\Local\\Microsoft\\Outlook\\me@x.com.ost\x00".encode("utf-16-le")
        self.assertEqual(decode_utf16_path(blob), r"C:\Users\me\AppData\Local\Microsoft\Outlook\me@x.com.ost")
        self.assertEqual(decode_utf16_path(b""), "")
        self.assertEqual(decode_utf16_path(None), "")


class CredentialTests(unittest.TestCase):
    def test_cmdkey_targets_lose_the_legacygeneric_prefix(self):
        text = ("Currently stored credentials:\n\n"
                "    Target: LegacyGeneric:target=MicrosoftOffice16_Data:ADAL:abc\n    Type: Generic\n    User: 02x\n\n"
                "    Target: MicrosoftAccount:target=SSO_POP_Device\n    Type: Domain Extended Credentials\n\n"
                "    Target: LegacyGeneric:target=WinMendScratchCred\n    Type: Generic\n    User: scratch\n")
        targets = parse_cmdkey_list(text)
        self.assertEqual(targets, ["MicrosoftOffice16_Data:ADAL:abc", "MicrosoftAccount:target=SSO_POP_Device",
                                   "WinMendScratchCred"])
        self.assertEqual(office_credential_targets(targets), ["MicrosoftOffice16_Data:ADAL:abc"])


class WindowlessProcessTests(unittest.TestCase):
    def test_only_old_windowless_office_processes_are_reported(self):
        now = 10_000.0
        procs = [(1, "OUTLOOK.EXE", now - 600), (2, "OUTLOOK.EXE", now - 10), (3, "olk.exe", now - 900),
                 (4, "WINWORD.EXE", now - 900), (5, "notepad.exe", now - 900)]
        found = windowless_processes(["outlook.exe", "olk.exe", "winword.exe"], min_age=60, now=now,
                                     procs=procs, windowed={4})
        self.assertEqual([p["pid"] for p in found], [1])
        self.assertEqual(found[0]["friendly"], "Outlook")
        self.assertAlmostEqual(found[0]["age"], 600)


def report(**over):
    base = {
        "c2r": {"platform": "x64", "culture": "en-us", "version": "16.0.1", "products": ["O365BusinessRetail"],
                "path": OFFICE_ROOT, "repair_exe": r"C:\c\OfficeClickToRun.exe", "update_exe": r"C:\c\OfficeC2RClient.exe"},
        "apps": {"Outlook": "x", "Word": "y"}, "missing": [], "new_outlook": "1.0",
        "clicktorun": {"status": "running", "start": "automatic"},
        "sppsvc": {"status": "stopped", "start": "automatic"},
        "wsearch": {"status": "running", "start": "automatic"},
        "stuck": [], "auth": [], "crashes": {"total": 0, "hangs": 0, "by_app": {}, "by_category": {}, "addins": {}, "gpu": 0},
        "profiles": {"default": "Outlook", "profiles": ["Outlook"]},
        "data_files": [{"path": "a.ost", "kind": "ost", "bytes": 6 * 1024 ** 3, "verdict": "good"}],
        "ospp": [], "hw_accel_off": False,
    }
    base.update(over)
    return base


class OptionBuilderTests(unittest.TestCase):
    def keys(self, opts):
        return [o["key"] for o in opts]

    def checked(self, opts):
        return [o["key"] for o in opts if o["checked"]]

    def test_healthy_machine_offers_only_unticked_optional_repairs(self):
        opts = build_office_repair_options(report())
        self.assertEqual(self.checked(opts), [])
        self.assertIn("repair:quick", self.keys(opts))
        self.assertIn("outlook:navpane", self.keys(opts))
        self.assertIn("outlook:rebuild_ost", self.keys(opts))
        self.assertIn("identity:reset", self.keys(opts))
        self.assertNotIn("service:clicktorun", self.keys(opts))
        self.assertNotIn("service:wsearch", self.keys(opts))
        self.assertNotIn("install:new_outlook", self.keys(opts))

    def test_stopped_clicktorun_service_is_ticked(self):
        opts = build_office_repair_options(report(clicktorun={"status": "stopped", "start": "disabled"}))
        self.assertIn("service:clicktorun", self.checked(opts))

    def test_a_stopped_software_protection_service_is_not_a_fault_only_disabled_is(self):
        self.assertNotIn("service:sppsvc", self.keys(build_office_repair_options(report())))
        opts = build_office_repair_options(report(sppsvc={"status": "stopped", "start": "disabled"}))
        self.assertIn("service:sppsvc", self.checked(opts))

    def test_windows_search_is_offered_only_with_classic_outlook(self):
        disabled = {"status": "stopped", "start": "disabled"}
        opts = build_office_repair_options(report(wsearch=disabled))
        self.assertIn("service:wsearch", self.checked(opts))
        self.assertIn("RAM Optimizations", [o for o in opts if o["key"] == "service:wsearch"][0]["detail"])
        opts = build_office_repair_options(report(wsearch=disabled, apps={"Word": "y"}))
        self.assertNotIn("service:wsearch", self.keys(opts))

    def test_crashes_tick_quick_repair_and_name_the_reason(self):
        crashes = {"total": 3, "hangs": 1, "by_app": {"Outlook": 3}, "by_category": {"office": 2, "hang": 1},
                   "addins": {}, "gpu": 0}
        opts = build_office_repair_options(report(crashes=crashes))
        quick = [o for o in opts if o["key"] == "repair:quick"][0]
        self.assertTrue(quick["checked"])
        self.assertIn("3 crash/hang event(s)", quick["detail"])
        self.assertIn("crashes inside Office's own files", quick["detail"])
        full = [o for o in opts if o["key"] == "repair:full"][0]
        self.assertFalse(full["checked"])

    def test_addin_crashes_offer_to_turn_that_addin_off(self):
        crashes = {"total": 2, "hangs": 0, "by_app": {"Outlook": 2}, "by_category": {"addin": 2},
                   "addins": {"TeamsAddin.FastConnect": {"addin": TEAMS, "count": 2}}, "gpu": 0}
        opts = build_office_repair_options(report(crashes=crashes))
        key = f"addin:{TEAMS['hive']}\\{TEAMS['key']}"
        self.assertIn(key, self.checked(opts))
        self.assertIn("Microsoft.Teams.AddinLoader.dll", [o for o in opts if o["key"] == key][0]["detail"])

    def test_an_addin_already_off_is_not_offered_again(self):
        off = dict(TEAMS, load_behavior=2)
        crashes = {"total": 1, "hangs": 0, "by_app": {}, "by_category": {"addin": 1},
                   "addins": {"TeamsAddin.FastConnect": {"addin": off, "count": 1}}, "gpu": 0}
        opts = build_office_repair_options(report(crashes=crashes))
        self.assertFalse(any(k.startswith("addin:") for k in self.keys(opts)))

    def test_gpu_crashes_offer_hardware_acceleration_off_unless_already_off(self):
        crashes = {"total": 1, "hangs": 0, "by_app": {}, "by_category": {"gpu": 1}, "addins": {}, "gpu": 1}
        self.assertIn("graphics:off", self.checked(build_office_repair_options(report(crashes=crashes))))
        self.assertNotIn("graphics:off", self.keys(build_office_repair_options(report(crashes=crashes, hw_accel_off=True))))

    def test_stuck_outlook_is_ticked_but_stuck_word_is_not(self):
        stuck = [{"pid": 11, "name": "OUTLOOK.EXE", "friendly": "Outlook", "age": 700},
                 {"pid": 12, "name": "WINWORD.EXE", "friendly": "Word", "age": 700}]
        opts = build_office_repair_options(report(stuck=stuck))
        self.assertIn("end:11", self.checked(opts))
        self.assertIn("end:12", self.keys(opts))
        self.assertNotIn("end:12", self.checked(opts))

    def test_auth_findings_are_ticked_and_reversible(self):
        auth = [{"hive": "HKCU", "key": r"Software\Microsoft\Office\16.0\Common\Identity", "value": "EnableADAL",
                 "current": 0, "harm": "modern authentication is switched off"}]
        opts = build_office_repair_options(report(auth=auth))
        key = r"auth:HKCU\Software\Microsoft\Office\16.0\Common\Identity\EnableADAL"
        self.assertIn(key, self.checked(opts))
        self.assertIn("Reversible", [o for o in opts if o["key"] == key][0]["detail"])

    def test_licence_fault_ticks_identity_reset(self):
        ospp = [{"name": "Office 21", "status": "NOTIFICATIONS", "error": "0xC004F074", "grace": ""}]
        self.assertIn("identity:reset", self.checked(build_office_repair_options(report(ospp=ospp))))
        licensed = [{"name": "Office 21", "status": "LICENSED", "error": "", "grace": ""}]
        self.assertNotIn("identity:reset", self.checked(build_office_repair_options(report(ospp=licensed))))

    def test_ost_at_the_ceiling_ticks_the_rebuild(self):
        files = [{"path": "a.ost", "kind": "ost", "bytes": 49 * 1024 ** 3, "verdict": "bad"}]
        self.assertIn("outlook:rebuild_ost", self.checked(build_office_repair_options(report(data_files=files))))
        self.assertNotIn("outlook:rebuild_ost", self.keys(build_office_repair_options(report(data_files=[]))))

    def test_no_outlook_at_all_offers_the_store_install(self):
        opts = build_office_repair_options(report(apps={"Word": "y"}, new_outlook=""))
        self.assertIn("install:new_outlook", self.keys(opts))
        self.assertNotIn("outlook:navpane", self.keys(opts))

    def test_no_click_to_run_means_no_c2r_repairs(self):
        opts = build_office_repair_options(report(c2r=None))
        for key in ("repair:quick", "repair:full", "update:office", "identity:reset", "service:clicktorun"):
            self.assertNotIn(key, self.keys(opts))

    def test_every_option_explains_itself(self):
        crashes = {"total": 1, "hangs": 0, "by_app": {}, "by_category": {"gpu": 1}, "addins": {}, "gpu": 1}
        opts = build_office_repair_options(report(
            crashes=crashes, stuck=[{"pid": 1, "name": "OUTLOOK.EXE", "friendly": "Outlook", "age": 100}],
            clicktorun={"status": "stopped", "start": "manual"}, wsearch={"status": "stopped", "start": "disabled"}))
        for o in opts:
            self.assertTrue(o["label"] and o["detail"], o)
            self.assertEqual(len(set(self.keys(opts))), len(opts), "duplicate option keys")


class _Completed:
    def __init__(self, returncode=0, stdout="", stderr="", cancelled=False):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.cancelled = cancelled


class RepairActionTests(unittest.TestCase):
    """The repair steps against scratch registry keys, temp files and a
    throwaway process. Anything that would touch the real Office state
    (services, the identity reset's deletions, Click-to-Run) is mocked and
    only the decisions and the undo lines are checked."""

    @classmethod
    def setUpClass(cls):
        import WinMend as W
        cls.W = W

    def setUp(self):
        import uuid
        from unittest import mock
        self.mock = mock
        self.host = self.W.WMTaskHost(None)
        self.scratch = rf"Software\WinMendTests\{uuid.uuid4().hex}"

    def tearDown(self):
        from winmend_safety import delete_registry_tree
        import winreg
        delete_registry_tree(winreg.HKEY_CURRENT_USER, self.scratch)

    def log(self):
        out = []
        while not self.host.queue.empty():
            out.append(self.host.queue.get().split(":", 2)[-1])
        return "\n".join(out)

    def test_set_dword_records_the_old_value_and_an_undo_line(self):
        import winreg
        ok = self.host._office_set_dword("T", "HKCU", self.scratch + r"\Graphics", "DisableHardwareAcceleration", 1)
        self.assertTrue(ok)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.scratch + r"\Graphics") as k:
            self.assertEqual(winreg.QueryValueEx(k, "DisableHardwareAcceleration")[0], 1)
        log = self.log()
        self.assertIn("(was not set)", log)
        self.assertIn("reg delete", log)
        # a second write over an existing value records that value instead
        self.host._office_set_dword("T", "HKCU", self.scratch + r"\Graphics", "DisableHardwareAcceleration", 0)
        log = self.log()
        self.assertIn("(was 1)", log)
        self.assertIn("/d 1 /f", log)

    def test_delete_value_removes_it_and_logs_how_to_put_it_back(self):
        import winreg
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, self.scratch + r"\Identity") as k:
            winreg.SetValueEx(k, "EnableADAL", 0, winreg.REG_DWORD, 0)
        self.assertTrue(self.host._office_delete_value("T", "HKCU", self.scratch + r"\Identity", "EnableADAL"))
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.scratch + r"\Identity") as k:
            with self.assertRaises(FileNotFoundError):
                winreg.QueryValueEx(k, "EnableADAL")
        log = self.log()
        self.assertIn("(was 0)", log)
        self.assertIn("/v EnableADAL /t REG_DWORD /d 0 /f", log)
        # absent already is success, not failure
        self.assertTrue(self.host._office_delete_value("T", "HKCU", self.scratch + r"\Identity", "EnableADAL"))
        self.assertIn("already absent", self.log())

    def test_ost_rebuild_renames_not_deletes_and_never_touches_pst(self):
        import os, tempfile
        with tempfile.TemporaryDirectory() as d:
            ost = os.path.join(d, "me@x.com.ost")
            nst = os.path.join(d, "me@x.com.nst")
            pst = os.path.join(d, "archive.pst")
            for p in (ost, nst, pst):
                with open(p, "wb") as f:
                    f.write(b"x" * 1024)
            files = [{"path": ost, "kind": "ost", "bytes": 1024}, {"path": nst, "kind": "nst", "bytes": 1024},
                     {"path": pst, "kind": "pst", "bytes": 1024}]
            with self.mock.patch.object(self.host, "_office_close_apps", lambda label, why: True):
                self.assertTrue(self.host._office_rebuild_ost("T", files))
            self.assertFalse(os.path.exists(ost))
            self.assertFalse(os.path.exists(nst))
            self.assertTrue(os.path.exists(pst))
            baks = [n for n in os.listdir(d) if n.endswith(".bak")]
            self.assertEqual(len(baks), 2)
            log = self.log()
            self.assertIn("Undo (with Outlook closed): ren", log)
            self.assertNotIn("archive.pst", log)

    def test_ost_rebuild_is_skipped_when_the_user_keeps_outlook_open(self):
        with self.mock.patch.object(self.host, "_office_close_apps", lambda label, why: False):
            self.assertFalse(self.host._office_rebuild_ost("T", [{"path": "x.ost", "kind": "ost", "bytes": 1}]))

    def test_end_process_terminates_a_windowless_process(self):
        import subprocess, psutil
        proc = subprocess.Popen(["powershell", "-NoProfile", "-Command", "Start-Sleep 60"],
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            ok = self.host._office_run_repair("T", f"end:{proc.pid}", {"c2r": None, "apps": {}}, {}, [], "")
            self.assertTrue(ok)
            self.assertIsNotNone(proc.poll())
            self.assertIn("Ended powershell.exe", self.log())
        finally:
            try:
                proc.kill()
            except Exception:
                pass

    def test_identity_reset_backs_up_before_it_removes_and_names_the_backup(self):
        W = self.W
        calls = {"exports": [], "deleted": [], "moved": [], "cmd": []}

        def fake_run(argv, **kw):
            calls["cmd"].append(argv)
            if argv[:2] == ["cmdkey", "/list"]:
                return _Completed(0, "    Target: LegacyGeneric:target=MicrosoftOffice16_Data:ADAL:1\n"
                                     "    Target: LegacyGeneric:target=Other\n")
            return _Completed(0, "Product key uninstall successful")

        inst = {"c2r": {"path": r"C:\Program Files\Microsoft Office"}, "msi_roots": [], "apps": {}}
        products = [{"name": "Office 21", "status": "NOTIFICATIONS", "error": "", "grace": "", "key_tail": "ABCDE"}]
        with self.mock.patch.object(self.host, "_office_close_apps", lambda label, why: True), \
             self.mock.patch.object(W.SystemCleanerGUI, "_export_hkcu_key",
                                    staticmethod(lambda subkey, dest: calls["exports"].append(subkey) or True)), \
             self.mock.patch.object(office_module, "delete_registry_tree", lambda hive, subkey: calls["deleted"].append(subkey) or True), \
             self.mock.patch.object(office_module, "wm_run", fake_run), \
             self.mock.patch.object(W.shutil, "move", lambda src, dst: calls["moved"].append(src)), \
             self.mock.patch.object(W.os.path, "isdir", lambda p: True), \
             self.mock.patch.object(W.Path, "mkdir", lambda self_, **kw: None):
            ok = self.host._office_identity_reset("T", inst, products, r"C:\ospp.vbs")
        self.assertTrue(ok)
        self.assertEqual(calls["exports"], list(W.OFFICE_IDENTITY_KEYS))
        self.assertEqual(calls["deleted"], list(W.OFFICE_IDENTITY_KEYS))
        self.assertEqual(len(calls["moved"]), len(W.OFFICE_LICENSE_FOLDERS))
        self.assertIn(["cscript", "//nologo", r"C:\ospp.vbs", "/unpkey:ABCDE"], calls["cmd"])
        self.assertIn(["cmdkey", "/delete:MicrosoftOffice16_Data:ADAL:1"], calls["cmd"])
        self.assertNotIn(["cmdkey", "/delete:Other"], calls["cmd"])
        log = self.log()
        self.assertIn("Backed up", log)
        self.assertIn("Removed 1 Office credential entry", log)
        self.assertIn("sign in", log)

    def test_identity_reset_stops_when_office_stays_open(self):
        with self.mock.patch.object(self.host, "_office_close_apps", lambda label, why: False):
            self.assertFalse(self.host._office_identity_reset("T", {"c2r": None, "msi_roots": []}, [], ""))

    def test_quick_repair_waits_for_the_launcher_and_reads_the_install_back(self):
        W = self.W
        inst = {"c2r": {"repair_exe": r"C:\c\OfficeClickToRun.exe", "platform": "x64", "culture": "en-us",
                        "path": r"C:\Program Files\Microsoft Office"}, "apps": {"Word": "w"}}
        seen = {}

        def fake_run(argv, **kw):
            seen["argv"] = argv
            return _Completed(0)

        with self.mock.patch.object(office_module, "wm_run", fake_run), \
             self.mock.patch.object(office_module, "processes_named", lambda names: []), \
             self.mock.patch.object(office_module, "office_installation", lambda: {"apps": {"Word": "w", "Outlook": "o"}, "missing": []}):
            self.assertTrue(self.host._office_c2r_repair("T", inst, "quick"))
        self.assertIn("RepairType=QuickRepair", seen["argv"])
        log = self.log()
        self.assertIn("Quick Repair", log)
        self.assertIn("2 Office program(s) present", log)

    def test_set_service_logs_before_after_and_undo(self):
        W = self.W
        states = iter([{"status": "stopped", "start": "disabled"}, {"status": "running", "start": "automatic"}])
        with self.mock.patch.object(office_module, "wm_run", lambda argv, **kw: _Completed(0)), \
             self.mock.patch.object(office_module, "service_state", lambda name: next(states)):
            self.assertTrue(self.host._office_set_service("T", "WSearch", "delayed-auto", "Windows Search"))
        log = self.log()
        self.assertIn("was stopped / disabled", log)
        self.assertIn("now running / automatic", log)
        self.assertIn("Undo: sc config WSearch start= disabled", log)

    def test_repair_order_runs_process_end_first_and_navpane_after_the_repair(self):
        order = self.host._OFFICE_REPAIR_ORDER
        self.assertLess(order.index("end:"), order.index("repair:"))
        self.assertLess(order.index("identity:reset"), order.index("repair:"))
        self.assertLess(order.index("repair:"), order.index("outlook:navpane"))


class QtCheckPickerTests(unittest.TestCase):
    """The Qt multi-select picker, offscreen: pre-ticked options come back as
    chosen keys, an untick is honoured, and Cancel returns None."""

    @classmethod
    def setUpClass(cls):
        import os
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        try:
            from PySide6.QtWidgets import QApplication
        except ImportError:  # pragma: no cover
            raise unittest.SkipTest("PySide6 not installed")
        import WinMend as W
        cls.W = W
        cls.app = QApplication.instance() or QApplication([])

    def _host(self):
        from PySide6.QtWidgets import QWidget
        W = self.W
        window = QWidget()
        window.T = W.WM_DARK
        host = W.WMTaskHost(window)
        return host, window

    def _drive(self, host, options, act):
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication, QCheckBox

        def _later():
            dlg = QApplication.activeModalWidget()
            if dlg is None:
                QTimer.singleShot(20, _later)
                return
            act(dlg, dlg.findChildren(QCheckBox))
        QTimer.singleShot(20, _later)
        return host._ui_check_picker("Office & Outlook repairs", "Tick the repairs to run.", options)

    OPTIONS = [
        {"key": "service:wsearch", "label": "Turn Windows Search back on", "detail": "d1", "checked": True},
        {"key": "repair:quick", "label": "Quick Repair", "detail": "d2", "checked": False},
        {"key": "identity:reset", "label": "Reset sign-in", "detail": "d3", "checked": False},
    ]

    def test_pre_ticked_options_come_back_and_a_new_tick_is_honoured(self):
        host, window = self._host()

        def act(dlg, boxes):
            self.assertEqual([b.text() for b in boxes], [o["label"] for o in self.OPTIONS])
            self.assertEqual([b.isChecked() for b in boxes], [True, False, False])
            boxes[1].setChecked(True)
            dlg.accept()
        chosen = self._drive(host, self.OPTIONS, act)
        self.assertEqual(chosen, ["service:wsearch", "repair:quick"])
        window.deleteLater()

    def test_untick_everything_returns_an_empty_list_not_none(self):
        host, window = self._host()

        def act(dlg, boxes):
            boxes[0].setChecked(False)
            dlg.accept()
        self.assertEqual(self._drive(host, self.OPTIONS, act), [])
        window.deleteLater()

    def test_cancel_returns_none(self):
        host, window = self._host()
        self.assertIsNone(self._drive(host, self.OPTIONS, lambda dlg, boxes: dlg.reject()))
        window.deleteLater()


if __name__ == "__main__":
    unittest.main()
