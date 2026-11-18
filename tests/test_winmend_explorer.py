"""Tests for the File Explorer repair: the Quick Access jump-list reader, the
dead-network-link detection behind it, and the re-pin logic.

Two facts measured on a real Windows 11 PC shape these tests:

* The DestList stream of a jump list is version 6 on current builds, with a
  130-byte fixed part per entry; the pin index sits at offset 108 and -1 means
  "frequent, not pinned".
* The shell's `pintohome` verb is a TOGGLE. Invoking it on a folder that is
  already pinned unpins it, so the re-pin loop has to re-read the list before
  every pin. `RestorePinsTests` fakes that toggle and asserts nothing already
  present is ever touched.
"""

import os
import socket
import struct
import tempfile
import threading
import time
import unittest

try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None

from winmend_safety import (
    EXPLORER_HISTORY_KEYS,
    EXPLORER_JUMP_LISTS,
    KNOWN_FOLDER_ALIASES,
    QUICK_ACCESS_APPID,
    delete_registry_tree,
    drive_kind,
    host_answers,
    is_microsoft_company,
    jump_list_kind,
    jump_list_path,
    known_folder_path,
    network_target_host,
    network_shortcuts,
    network_target_port,
    parse_destlist,
    persistent_mapped_drives,
    quick_access_pins,
    read_jump_list,
    shell_extension_inventory,
)


def destlist(entries, version=6):
    """Build a DestList stream the way Windows 10/11 lays it out.

    entries: (path, pin_index, access_count, host) tuples.
    """
    blob = bytearray(struct.pack("<III", version, len(entries), sum(1 for e in entries if e[1] >= 0)))
    blob += b"\x00" * (32 - len(blob))
    for number, (path, pin_index, access_count, host) in enumerate(entries, start=1):
        fixed = bytearray(130)
        struct.pack_into("<Q", fixed, 0, 0xDEADBEEF)          # checksum (unused)
        fixed[72:72 + len(host)] = host.encode("ascii")     # NetBIOS host name
        struct.pack_into("<I", fixed, 88, number)            # entry number
        struct.pack_into("<Q", fixed, 100, 132_000_000_000_000_000)  # FILETIME
        struct.pack_into("<i", fixed, 108, pin_index)        # pin status
        struct.pack_into("<I", fixed, 116, access_count)     # access count
        struct.pack_into("<H", fixed, 128, len(path))        # path length (chars)
        blob += fixed + path.encode("utf-16-le") + b"\x00\x00\x00\x00"
    return bytes(blob)


class ParseDestListTests(unittest.TestCase):
    ENTRIES = [
        (r"C:\Users\me\AppData\Roaming\.minecraft", 7, 0, "mypc"),
        ("knownfolder:{374DE290-123F-4565-9164-39C4925E467B}", 1, 10, "mypc"),
        (r"Z:\\", -1, 0, "truenas"),
        ("knownfolder:{754AC886-DF64-4CBA-86B5-F7FBF4FBCEF5}", 0, 103, "mypc"),
        (r"\\nas\media\films", -1, 3, "nas"),
    ]

    def test_reads_every_field(self):
        entries = parse_destlist(destlist(self.ENTRIES))
        self.assertEqual(len(entries), 5)
        first = entries[0]
        self.assertEqual(first["path"], r"C:\Users\me\AppData\Roaming\.minecraft")
        self.assertTrue(first["pinned"])
        self.assertEqual(first["pin_index"], 7)
        self.assertEqual(first["host"], "mypc")
        self.assertEqual(first["entry"], 1)
        third = entries[2]
        self.assertFalse(third["pinned"])
        self.assertEqual(third["pin_index"], -1)
        self.assertEqual(third["host"], "truenas")
        self.assertEqual(entries[1]["access_count"], 10)

    def test_pins_come_out_in_display_order(self):
        entries = parse_destlist(destlist(self.ENTRIES))
        self.assertEqual(quick_access_pins(entries), [
            "knownfolder:{754AC886-DF64-4CBA-86B5-F7FBF4FBCEF5}",
            "knownfolder:{374DE290-123F-4565-9164-39C4925E467B}",
            r"C:\Users\me\AppData\Roaming\.minecraft",
        ])

    def test_empty_list_is_an_empty_list_not_none(self):
        self.assertEqual(parse_destlist(destlist([])), [])

    def test_unreadable_is_none_not_empty(self):
        # A repair must not tell the user "nothing was pinned" about a list it
        # never managed to read -- so every failure mode is None, never [].
        self.assertIsNone(parse_destlist(b""))
        self.assertIsNone(parse_destlist(None))
        self.assertIsNone(parse_destlist(b"\x00" * 31))
        good = destlist(self.ENTRIES)
        self.assertIsNone(parse_destlist(good[:-40]), "truncated mid-entry")
        self.assertIsNone(parse_destlist(destlist(self.ENTRIES, version=1)),
                          "the Windows 7 layout is not the one this reader knows")
        corrupt = bytearray(good)
        struct.pack_into("<I", corrupt, 4, 500)   # claims 500 entries
        self.assertIsNone(parse_destlist(bytes(corrupt)))

    def test_quick_access_pins_tolerates_none(self):
        self.assertEqual(quick_access_pins(None), [])


class PathClassificationTests(unittest.TestCase):
    def test_jump_list_kinds(self):
        self.assertEqual(jump_list_kind("knownfolder:{374DE290-123F-4565-9164-39C4925E467B}"), "knownfolder")
        self.assertEqual(jump_list_kind("::{645FF040-5081-101B-9F08-00AA002F954E}"), "shell")
        self.assertEqual(jump_list_kind(r"\\truenas\share\x"), "unc")
        self.assertEqual(jump_list_kind("Z:\\"), "drive")
        self.assertEqual(jump_list_kind(r"C:\Users"), "drive")
        self.assertEqual(jump_list_kind("shell:foo"), "other")
        self.assertEqual(jump_list_kind(""), "other")
        self.assertEqual(jump_list_kind(None), "other")

    def test_network_hosts(self):
        self.assertEqual(network_target_host(r"\\truenas\share\x"), "truenas")
        self.assertEqual(network_target_host(r"\\srv@SSL\DavWWWRoot\sites"), "srv")
        self.assertEqual(network_target_host(r"\\srv@8080\dav"), "srv")
        self.assertEqual(network_target_host(r"\\?\UNC\nas\media"), "nas")
        self.assertEqual(network_target_host("https://corp.sharepoint.com/sites/x"), "corp.sharepoint.com")
        self.assertEqual(network_target_host("http://[fe80::1]:8080/dav"), "fe80::1")
        self.assertEqual(network_target_host("ftp://user:pw@ftp.example.com/x"), "ftp.example.com")
        self.assertEqual(network_target_host(r"C:\Users"), "")
        self.assertEqual(network_target_host("knownfolder:{X}"), "")
        self.assertEqual(network_target_host(""), "")

    def test_network_ports_follow_the_protocol_explorer_uses(self):
        self.assertEqual(network_target_port(r"\\truenas\share"), 445)
        self.assertEqual(network_target_port(r"\\srv@SSL\DavWWWRoot\sites"), 443)
        self.assertEqual(network_target_port(r"\\srv@8080\dav"), 8080)
        self.assertEqual(network_target_port("https://corp.sharepoint.com/sites/x"), 443)
        self.assertEqual(network_target_port("http://intranet/dav"), 80)
        self.assertEqual(network_target_port("ftp://ftp.example.com"), 21)

    def test_explorer_jump_lists_are_named(self):
        self.assertEqual(EXPLORER_JUMP_LISTS[0][0], QUICK_ACCESS_APPID)
        self.assertTrue(str(jump_list_path(QUICK_ACCESS_APPID)).endswith(
            "AutomaticDestinations\\f01b4d95cf55d32a.automaticDestinations-ms"))
        self.assertTrue(str(jump_list_path(QUICK_ACCESS_APPID, "custom")).endswith(
            "CustomDestinations\\f01b4d95cf55d32a.customDestinations-ms"))
        for subkey, _what in EXPLORER_HISTORY_KEYS:
            self.assertTrue(subkey.startswith("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\"))

    def test_is_microsoft_company(self):
        self.assertTrue(is_microsoft_company("Microsoft Corporation"))
        self.assertTrue(is_microsoft_company("microsoft"))
        self.assertFalse(is_microsoft_company("Igor Pavlov"))
        self.assertFalse(is_microsoft_company(""))
        self.assertFalse(is_microsoft_company(None))


class HostAnswersTests(unittest.TestCase):
    def test_listening_socket_answers(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        try:
            cache = {}
            self.assertTrue(host_answers("127.0.0.1", timeout=2.0, port=port, cache=cache))
            self.assertEqual(cache, {("127.0.0.1", port): True})
        finally:
            server.close()

    def test_closed_port_is_silent(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        server.close()
        # Windows retries the SYN on a refused local port, so this rides
        # out to the deadline; the bound is what is being tested.
        started = time.monotonic()
        self.assertFalse(host_answers("127.0.0.1", timeout=0.75, port=port))
        self.assertLess(time.monotonic() - started, 2.0)

    def test_unresolvable_name_returns_at_the_deadline(self):
        # Windows keeps trying LLMNR and mDNS for ~8 s on a name DNS rejects;
        # the caller must get its answer at the deadline regardless.
        started = time.monotonic()
        self.assertFalse(host_answers("winmend-no-such-host.invalid", timeout=1.0, port=445))
        self.assertLess(time.monotonic() - started, 2.5)

    def test_cache_short_circuits(self):
        cache = {("cached-host", 445): True}
        self.assertTrue(host_answers("Cached-Host", timeout=0.1, port=445, cache=cache))

    def test_blank_host_is_never_reachable(self):
        self.assertFalse(host_answers("", timeout=0.1))
        self.assertFalse(host_answers(None, timeout=0.1))


@unittest.skipIf(winreg is None, "Windows only")
class RegistryHelperTests(unittest.TestCase):
    SCRATCH = r"Software\WinMend\Tests\ExplorerRepair"

    def setUp(self):
        delete_registry_tree(winreg.HKEY_CURRENT_USER, self.SCRATCH)

    def tearDown(self):
        delete_registry_tree(winreg.HKEY_CURRENT_USER, self.SCRATCH)

    def _make(self, subkey, values=()):
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_SET_VALUE) as key:
            for name, data in values:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, data)

    def _exists(self, subkey):
        try:
            winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey).Close()
            return True
        except OSError:
            return False

    def test_delete_registry_tree_removes_nested_keys(self):
        self._make(self.SCRATCH + r"\a\b\c", [("v", "1")])
        self._make(self.SCRATCH + r"\a\d")
        self.assertTrue(self._exists(self.SCRATCH + r"\a\b\c"))
        self.assertTrue(delete_registry_tree(winreg.HKEY_CURRENT_USER, self.SCRATCH))
        self.assertFalse(self._exists(self.SCRATCH))

    def test_deleting_a_missing_key_is_success(self):
        self.assertTrue(delete_registry_tree(winreg.HKEY_CURRENT_USER, self.SCRATCH + r"\never"))

    def test_persistent_mapped_drives_reads_the_letters(self):
        self._make(self.SCRATCH + r"\Z", [("RemotePath", r"\\truenas\media"), ("ProviderName", "Microsoft Windows Network")])
        self._make(self.SCRATCH + r"\y", [("RemotePath", r"\\fileserver\home\me")])
        self._make(self.SCRATCH + r"\Q")                       # no RemotePath: not a mapping
        self._make(self.SCRATCH + r"\Extra", [("RemotePath", r"\\x\y")])  # not a letter
        drives = persistent_mapped_drives(self.SCRATCH)
        self.assertEqual(
            [(d["letter"], d["remote"], d["host"]) for d in drives],
            [(r"Y:", r"\\fileserver\home\me", "fileserver"),
             (r"Z:", r"\\truenas\media", "truenas")])
        self.assertEqual(drives[1]["subkey"], self.SCRATCH + r"\Z")

    def test_no_mappings_key_means_no_drives(self):
        self.assertEqual(persistent_mapped_drives(self.SCRATCH + r"\missing"), [])

    def test_export_hkcu_key_writes_a_restorable_reg_file(self):
        import WinMend as W
        self._make(self.SCRATCH + r"\Z", [("RemotePath", r"\\truenas\media")])
        with tempfile.TemporaryDirectory() as folder:
            dest = os.path.join(folder, "MappedDrive_Z.reg")
            self.assertTrue(W.WMTaskHost._export_hkcu_key(self.SCRATCH + r"\Z", dest))
            with open(dest, encoding="utf-16") as handle:
                text = handle.read()
            self.assertIn("Windows Registry Editor", text)
            self.assertIn(r"\\\\truenas\\media", text)
            self.assertFalse(W.WMTaskHost._export_hkcu_key(self.SCRATCH + r"\missing",
                                                           os.path.join(folder, "none.reg")),
                             "a key that does not exist has nothing to save")


@unittest.skipIf(os.name != "nt", "Windows only")
class NetworkShortcutTests(unittest.TestCase):
    def test_reads_targets_out_of_the_lnk_without_touching_them(self):
        # The fixture points at the local admin share: the shell resolves a
        # target when the .lnk is *written*, and a dead server would make
        # that step take ten seconds. Reading it back must stay instant
        # regardless -- that is the property production depends on.
        import win32com.client
        target = r"\\localhost\C$\Windows"
        with tempfile.TemporaryDirectory() as folder:
            location = os.path.join(folder, "Team files")
            os.makedirs(location)
            shortcut = win32com.client.Dispatch("WScript.Shell").CreateShortCut(
                os.path.join(location, "target.lnk"))
            shortcut.TargetPath = target
            shortcut.Save()
            with open(os.path.join(folder, "desktop.ini"), "w") as handle:
                handle.write("[.ShellClassInfo]\n")
            os.makedirs(os.path.join(folder, "Empty one"))
            started = time.monotonic()
            items = network_shortcuts(folder)
            self.assertLess(time.monotonic() - started, 1.0, "reading a .lnk must not resolve it")
        names = {item["name"]: item for item in items}
        self.assertEqual(set(names), {"Team files", "Empty one"})
        self.assertEqual(names["Team files"]["target"].lower(), target.lower())
        self.assertEqual(names["Team files"]["host"], "localhost")
        self.assertEqual(names["Team files"]["port"], 445)
        self.assertEqual(names["Empty one"]["target"], "")
        self.assertEqual(names["Empty one"]["host"], "")

    def test_missing_folder_means_no_shortcuts(self):
        self.assertEqual(network_shortcuts(os.path.join(tempfile.gettempdir(), "winmend-no-such-dir")), [])


@unittest.skipIf(os.name != "nt", "Windows only")
class WindowsProbeTests(unittest.TestCase):
    def test_known_folder_resolves_and_virtual_alias_maps_to_desktop(self):
        downloads = known_folder_path("{374DE290-123F-4565-9164-39C4925E467B}")
        self.assertTrue(os.path.isdir(downloads), downloads)
        virtual_desktop = "{754AC886-DF64-4CBA-86B5-F7FBF4FBCEF5}"
        self.assertEqual(known_folder_path(virtual_desktop), "")
        self.assertTrue(os.path.isdir(known_folder_path(KNOWN_FOLDER_ALIASES[virtual_desktop])))
        self.assertEqual(known_folder_path("{00000000-0000-0000-0000-000000000000}"), "")
        self.assertEqual(known_folder_path("not a guid"), "")

    def test_drive_kind_distinguishes_present_from_absent(self):
        system = os.environ.get("SystemDrive", "C:")
        self.assertEqual(drive_kind(system + "\\Windows"), "fixed")
        import ctypes
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        unused = next(chr(ord("A") + i) for i in range(25, -1, -1) if not mask & (1 << i))
        self.assertEqual(drive_kind(unused + ":\\"), "absent")
        self.assertEqual(drive_kind("knownfolder:{X}"), "unknown")

    def test_read_jump_list_of_a_missing_file_is_none(self):
        self.assertIsNone(read_jump_list(os.path.join(tempfile.gettempdir(), "winmend-no-such.automaticDestinations-ms")))

    def test_read_jump_list_of_a_non_ole_file_is_none(self):
        with tempfile.NamedTemporaryFile("wb", suffix=".automaticDestinations-ms", delete=False) as handle:
            handle.write(b"this is not a compound file")
        try:
            self.assertIsNone(read_jump_list(handle.name))
        finally:
            os.unlink(handle.name)

    def test_shell_extension_inventory_is_read_only_and_well_formed(self):
        inventory = shell_extension_inventory(company_of=lambda dll: "Microsoft Corporation")
        self.assertTrue(inventory["available"])
        self.assertEqual(inventory["overlay_limit"], 15)
        self.assertGreater(len(inventory["handlers"]), 0)
        for handler in inventory["handlers"]:
            self.assertRegex(handler["clsid"], r"^\{[0-9A-F-]{36}\}$")
            self.assertTrue(handler["microsoft"], "the injected publisher makes everything Microsoft")
            self.assertTrue(handler["where"])
        # Built-in handlers keep their DLL under %SystemRoot% as REG_EXPAND_SZ;
        # if the reader could not expand those, every one would show as broken.
        resolved = [h for h in inventory["handlers"] if h["dll"]]
        self.assertGreater(len(resolved), len(inventory["handlers"]) // 2)


class RestorePinsTests(unittest.TestCase):
    """The re-pin loop against a fake shell whose pin verb toggles, exactly
    like the real one."""

    def setUp(self):
        import WinMend as W
        self.host = W.WMTaskHost(None)

    def _fake_quick_access(self, initial):
        state = {"pins": list(initial), "verbs": []}

        def read_pins():
            return list(state["pins"])

        def pin(target):
            state["verbs"].append(target)
            if target in state["pins"]:
                state["pins"].remove(target)      # the toggle
            else:
                state["pins"].append(target)
            return ""

        return state, read_pins, pin

    def test_already_pinned_folders_are_never_toggled(self):
        here = os.path.dirname(os.path.abspath(__file__))
        state, read_pins, pin = self._fake_quick_access([here])
        restored, dropped = self.host._restore_quick_access_pins(
            [here], read_pins, pin, sleep=lambda _s: None)
        self.assertEqual(state["verbs"], [], "pintohome must not run for a pin that is present")
        self.assertEqual(state["pins"], [here])
        self.assertEqual(restored, [(here, "already back")])
        self.assertEqual(dropped, [])

    def test_missing_pins_are_pinned_in_order_and_verified(self):
        here = os.path.dirname(os.path.abspath(__file__))
        parent = os.path.dirname(here)
        state, read_pins, pin = self._fake_quick_access([])
        restored, dropped = self.host._restore_quick_access_pins(
            [here, parent], read_pins, pin, sleep=lambda _s: None)
        self.assertEqual(state["verbs"], [here, parent])
        self.assertEqual(state["pins"], [here, parent])
        self.assertEqual(restored, [(here, "pinned"), (parent, "pinned")])
        self.assertEqual(dropped, [])

    def test_a_pin_that_never_lands_gets_one_deferred_retry_then_is_reported(self):
        # Two attempts in all: one in the first pass and one in the second,
        # which only runs after every other pin has had time to land -- a
        # retry any sooner could toggle a late-landing pin back off.
        here = os.path.dirname(os.path.abspath(__file__))
        verbs = []

        def pin(target):
            verbs.append(target)
            return ""

        restored, dropped = self.host._restore_quick_access_pins(
            [here], lambda: [], pin, sleep=lambda _s: None, attempts=2)
        self.assertEqual(verbs, [here, here])
        self.assertEqual(restored, [])
        self.assertEqual(dropped, [(here, "could not be confirmed as pinned")])

    def test_unresolvable_and_refused_pins_are_dropped_with_reasons(self):
        here = os.path.dirname(os.path.abspath(__file__))
        restored, dropped = self.host._restore_quick_access_pins(
            ["knownfolder:{00000000-0000-0000-0000-000000000000}", "shell:nonsense", here],
            lambda: [], lambda target: "Explorer could not open it", sleep=lambda _s: None)
        self.assertEqual(restored, [])
        self.assertEqual(dropped, [
            ("knownfolder:{00000000-0000-0000-0000-000000000000}", "could not be resolved to a folder"),
            ("shell:nonsense", "could not be resolved to a folder"),
            (here, "Explorer could not open it"),
        ])

    def test_unreadable_list_is_never_pinned_against(self):
        # The first real run: Explorer was still writing its fresh list, the
        # read failed, and treating that as "no pins" pinned Desktop blind --
        # toggling off the Desktop pin Windows had just put back.
        here = os.path.dirname(os.path.abspath(__file__))
        verbs = []
        restored, dropped = self.host._restore_quick_access_pins(
            [here], lambda: None, lambda t: verbs.append(t) or "", sleep=lambda _s: None, attempts=3)
        self.assertEqual(verbs, [])
        self.assertEqual(restored, [])
        self.assertEqual(len(dropped), 1)
        self.assertIn("not pinned blind", dropped[0][1])

    def test_a_read_that_recovers_is_waited_for(self):
        here = os.path.dirname(os.path.abspath(__file__))
        reads = iter([None, None, [here]])
        verbs = []
        restored, dropped = self.host._restore_quick_access_pins(
            [here], lambda: next(reads, [here]), lambda t: verbs.append(t) or "",
            sleep=lambda _s: None)
        self.assertEqual(verbs, [], "once readable, the pin was found present")
        self.assertEqual(restored, [(here, "already back")])

    def test_a_pin_recorded_under_another_spelling_counts_as_landed_once(self):
        # Pinning the Desktop path lands as knownfolder:{754AC886-...}. The
        # second pass must recognise that spelling, or it would "retry" and
        # toggle the pin straight back off.
        here = os.path.dirname(os.path.abspath(__file__))
        state = {"pins": ["knownfolder:{374DE290-123F-4565-9164-39C4925E467B}"]}
        verbs = []

        def pin(target):
            verbs.append(target)
            state["pins"].append("knownfolder:{754AC886-DF64-4CBA-86B5-F7FBF4FBCEF5}")
            return ""

        restored, dropped = self.host._restore_quick_access_pins(
            [here], lambda: list(state["pins"]), pin, sleep=lambda _s: None)
        self.assertEqual(verbs, [here])
        self.assertEqual(restored, [(here, "pinned")])
        self.assertEqual(dropped, [])

    def test_a_default_written_between_read_and_verb_is_repaired_on_the_second_pass(self):
        # The race the second real run hit: the read says "not pinned",
        # Windows writes Downloads as a default in the same instant, and the
        # verb -- a toggle -- unpins it. Only the second pass can see that.
        downloads = "knownfolder:{374DE290-123F-4565-9164-39C4925E467B}"
        state = {"pins": [], "verbs": 0}

        def read_pins():
            return list(state["pins"])

        def pin(target):
            state["verbs"] += 1
            if state["verbs"] == 1:
                state["pins"].append(downloads)   # Windows' default lands first...
            if downloads in state["pins"]:
                state["pins"].remove(downloads)   # ...and the verb toggles it off
            else:
                state["pins"].append(downloads)
            return ""

        restored, dropped = self.host._restore_quick_access_pins(
            [downloads], read_pins, pin, sleep=lambda _s: None, attempts=2)
        self.assertEqual(state["verbs"], 2)
        self.assertEqual(state["pins"], [downloads])
        self.assertEqual(restored, [(downloads, "pinned on the second pass")])
        self.assertEqual(dropped, [])

    def test_wait_for_quick_access_needs_agreeing_reads(self):
        reads = iter([None, [], ["a"], ["a", "b"], ["a", "b"], ["a", "b"], ["a", "b", "c"]])
        clock = iter(range(100))
        settled = self.host._wait_for_quick_access(
            lambda: next(reads), sleep=lambda _s: None, clock=lambda: next(clock))
        self.assertEqual(settled, ["a", "b"])

    def test_wait_for_quick_access_gives_up_with_none_at_the_deadline(self):
        # Reads never agree: the clock is consulted once for the deadline
        # (t=0) and once per read (t=10, 20, 30); at t=30 the 25 s deadline
        # has passed and the caller gets None, never a half-written list.
        reads = iter([None, ["a"], ["a", "b"], ["a", "b", "c"], ["a", "b", "c", "d"]])
        clock = iter(range(0, 100, 10))
        settled = self.host._wait_for_quick_access(
            lambda: next(reads), timeout=25, sleep=lambda _s: None, clock=lambda: next(clock))
        self.assertIsNone(settled)

    def test_wait_for_quick_access_never_readable_is_none(self):
        clock = iter(range(0, 100, 10))
        settled = self.host._wait_for_quick_access(
            lambda: None, timeout=25, sleep=lambda _s: None, clock=lambda: next(clock))
        self.assertIsNone(settled)

    def test_cancel_stops_before_the_next_pin(self):
        here = os.path.dirname(os.path.abspath(__file__))
        calls = []
        restored, dropped = self.host._restore_quick_access_pins(
            [here, here], lambda: [], lambda t: calls.append(t) or "", cancelled=lambda: True)
        self.assertEqual(calls, [])
        self.assertEqual((restored, dropped), ([], []))

    @unittest.skipIf(os.name != "nt", "Windows only")
    def test_pin_targets(self):
        target = self.host._quick_access_pin_target("knownfolder:{374DE290-123F-4565-9164-39C4925E467B}")
        self.assertTrue(os.path.isdir(target))
        self.assertEqual(
            self.host._quick_access_pin_target("::{645FF040-5081-101B-9F08-00AA002F954E}"),
            "::{645FF040-5081-101B-9F08-00AA002F954E}")
        self.assertEqual(self.host._quick_access_pin_target("knownfolder:{00000000-0000-0000-0000-000000000000}"), "")
        self.assertEqual(self.host._quick_access_pin_target(r"\\nas\media"), r"\\nas\media")
        self.assertEqual(self.host._quick_access_pin_target("shell:nonsense"), "")

    @unittest.skipIf(os.name != "nt", "Windows only")
    def test_link_verdicts_never_touch_the_network_for_local_paths(self):
        host = self.host
        host._EXPLORER_PROBE_SECS = 0.3   # keep the dead-host case fast
        here = os.path.dirname(os.path.abspath(__file__))
        self.assertEqual(host._explorer_link_verdict("knownfolder:{X}", {})[0], "virtual")
        self.assertEqual(host._explorer_link_verdict("::{645FF040-5081-101B-9F08-00AA002F954E}", {})[0], "virtual")
        self.assertEqual(host._explorer_link_verdict(here, {})[0], "local")
        self.assertEqual(host._explorer_link_verdict(os.path.join(here, "no-such-folder"), {})[0], "missing")
        started = time.monotonic()
        status, detail = host._explorer_link_verdict(r"\\winmend-no-such-host.invalid\share", {})
        self.assertEqual(status, "dead")
        self.assertIn("does not answer", detail)
        self.assertLess(time.monotonic() - started, 2.0)


class TaskWiringTests(unittest.TestCase):
    def setUp(self):
        import WinMend as W
        self.W = W
        self.host = W.WMTaskHost(None)

    def test_task_is_declared_and_wired_everywhere(self):
        task = next(t for t in self.W.WM_TASKS if t.id == "explorer_repair")
        self.assertEqual(task.category, "repair")
        self.assertFalse(task.admin, "everything it touches is per-user")
        self.assertEqual(task.risk, "caution")
        self.assertFalse(task.reboot)
        self.assertTrue(task.simple)
        self.assertEqual(self.W.WM_HANDLERS["explorer_repair"], "run_explorer_repair")
        self.assertTrue(callable(self.host.run_explorer_repair))
        self.assertIn("explorer_repair", self.host._task_var_map())
        self.assertIn("explorer_repair", self.host._task_friendly_names())
        self.assertIn("explorer_repair", self.host._task_display_names())
        self.assertEqual(self.host._task_runtime_weights()["explorer_repair"], task.secs)

    def test_explorer_complaints_rank_the_repair_first(self):
        for query in ("file explorer is slow to open", "quick access working on it",
                      "folders take forever to load", "explorer hangs"):
            with self.subTest(query=query):
                ranked, _reason = self.host._recommend_tasks_for_query(query)
                self.assertEqual(ranked[0], "explorer_repair")


if __name__ == "__main__":
    unittest.main()
