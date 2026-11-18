"""Tests for the handle-based tree delete behind Clean Temp Files, Clear Browser
Cache and the shader-cache repair.

The attack these guard against was measured, not assumed: on this machine
C:\\Windows\\Temp grants BUILTIN\\Users "create files / create folders" (inherited
into every subfolder), and Python 3.10's shutil.rmtree on Windows is the
path-based version its own source marks "vulnerable to race conditions". A
standard account could swap a subfolder for a junction between rmtree listing
its parent and stepping into it, and WinMend -- elevated -- would empty the
junction's target. Every test that matters here plants a victim folder outside
the tree and checks it survives.

The cache cleanups are the same-user version: a program running as the user
can junction a browser or shader cache folder to somewhere only an
administrator may write, and the old os.walk / iterdir code then emptied it
with no race needed.

Junctions need no privilege to create, so all of this runs unelevated.
"""

import _winapi
import inspect
import os
import shutil
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

from winmend.core import safe_delete
from winmend.core.safe_delete import clear_folder, final_path, remove_tree
from winmend.diagnostics.repairs.graphics import _do_clear_shader_cache
from winmend.features.cleanup import CleanupTasks


class _Fixture(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.base = Path(self._dir.name)
        self.root = final_path(str(self.base))
        self.victim = self.base / "victim"
        self.victim.mkdir()
        (self.victim / "precious.txt").write_text("keep me")
        (self.victim / "inner").mkdir()
        (self.victim / "inner" / "deep.txt").write_text("keep me too")

    def tearDown(self):
        self._dir.cleanup()

    def assertVictimIntact(self):
        self.assertEqual((self.victim / "precious.txt").read_text(), "keep me")
        self.assertEqual((self.victim / "inner" / "deep.txt").read_text(), "keep me too")

    def path(self, *parts):
        return "\\".join((self.root,) + parts)


class RemoveTreeTests(_Fixture):
    def test_removes_a_nested_tree_of_files_and_folders(self):
        tree = self.base / "junk"
        (tree / "a" / "b").mkdir(parents=True)
        for name in ("one.tmp", "a/two.tmp", "a/b/three.tmp"):
            (tree / name).write_text("x")
        self.assertTrue(remove_tree(self.path("junk")))
        self.assertFalse(tree.exists())

    def test_removes_a_single_file(self):
        (self.base / "lone.tmp").write_text("x")
        self.assertTrue(remove_tree(self.path("lone.tmp")))
        self.assertFalse((self.base / "lone.tmp").exists())

    def test_a_junction_inside_the_tree_is_unlinked_not_followed(self):
        tree = self.base / "junk"
        tree.mkdir()
        (tree / "file.tmp").write_text("x")
        _winapi.CreateJunction(str(self.victim), str(tree / "link"))
        self.assertTrue(remove_tree(self.path("junk")))
        self.assertFalse(tree.exists())
        self.assertVictimIntact()

    def test_a_top_level_junction_is_removed_as_the_link(self):
        _winapi.CreateJunction(str(self.victim), str(self.base / "link"))
        self.assertTrue(remove_tree(self.path("link")))
        self.assertFalse(os.path.lexists(self.base / "link"))
        self.assertVictimIntact()

    def test_a_subfolder_swapped_for_a_junction_mid_delete_is_not_followed(self):
        # The race itself, made deterministic: the parent is listed while
        # "swap" is a real folder, then -- before it is opened -- the attacker
        # replaces it with a junction to the victim.
        tree = self.base / "junk"
        (tree / "swap").mkdir(parents=True)
        (tree / "decoy.tmp").write_text("x")
        real_list = safe_delete._list_names
        swapped = []

        def list_then_swap(handle):
            names = real_list(handle)
            if "swap" in names and not swapped:
                (tree / "swap").rmdir()
                _winapi.CreateJunction(str(self.victim), str(tree / "swap"))
                swapped.append(True)
            return names

        with mock.patch.object(safe_delete, "_list_names", side_effect=list_then_swap):
            self.assertTrue(remove_tree(self.path("junk")))
        self.assertTrue(swapped, "the swap never happened, so the test proved nothing")
        self.assertVictimIntact()
        self.assertFalse(tree.exists())

    def test_an_object_reached_through_a_junction_above_it_is_refused(self):
        # As if a folder above it had been swapped for a junction: the path
        # still reads <root>\link\precious.txt, but the file really lives in
        # the victim folder, so it is not the object that was listed.
        _winapi.CreateJunction(str(self.victim), str(self.base / "link"))
        self.assertFalse(remove_tree(self.path("link", "precious.txt")))
        self.assertVictimIntact()

    def test_a_file_in_use_is_left_and_reported(self):
        tree = self.base / "junk"
        tree.mkdir()
        (tree / "free.tmp").write_text("x")
        with open(tree / "busy.tmp", "w") as held:  # the CRT never shares delete
            held.write("x")
            self.assertFalse(remove_tree(self.path("junk")))
            self.assertTrue((tree / "busy.tmp").exists())
            self.assertFalse((tree / "free.tmp").exists())
        self.assertTrue(remove_tree(self.path("junk")))

    def test_a_missing_entry_is_reported_not_raised(self):
        self.assertFalse(remove_tree(self.path("never-existed")))

    def test_a_deep_tree_does_not_hit_the_recursion_limit(self):
        # A standard user decides how deep a tree in C:\Windows\Temp goes, and
        # a RecursionError would escape the task's OSError handling.
        deep = self.base / "deep"
        os.makedirs("\\\\?\\" + str(deep) + "\\d" * 200)
        limit = sys.getrecursionlimit()
        sys.setrecursionlimit(len(inspect.stack()) + 50)
        try:
            removed = remove_tree(self.path("deep"))
        finally:
            sys.setrecursionlimit(limit)
        self.assertTrue(removed)
        self.assertFalse(deep.exists())


class ClearFolderTests(_Fixture):
    def make_cache(self, name="Cache"):
        cache = self.base / name
        (cache / "Cache_Data" / "index-dir").mkdir(parents=True)
        (cache / "Cache_Data" / "f_000001").write_bytes(b"x" * 1000)
        (cache / "Cache_Data" / "index-dir" / "the-real-index").write_bytes(b"x" * 24)
        (cache / "top.bin").write_bytes(b"x" * 100)
        return cache

    def files_in(self, folder):
        return [p for p in folder.rglob("*") if not p.is_dir()]

    def test_keep_dirs_deletes_every_file_and_keeps_every_folder(self):
        cache = self.make_cache()
        self.assertEqual(clear_folder(self.path("Cache"), keep_dirs=True), (3, 1124, 0))
        self.assertTrue((cache / "Cache_Data" / "index-dir").is_dir())
        self.assertEqual(self.files_in(cache), [])

    def test_without_keep_dirs_everything_inside_goes_but_the_folder_stays(self):
        cache = self.make_cache()
        self.assertEqual(clear_folder(self.path("Cache")), (3, 1124, 0))
        self.assertTrue(cache.is_dir())
        self.assertEqual(list(cache.iterdir()), [])

    def test_a_junction_inside_is_unlinked_not_followed(self):
        for keep_dirs in (True, False):
            with self.subTest(keep_dirs=keep_dirs):
                name = f"Cache-{keep_dirs}"
                cache = self.make_cache(name)
                _winapi.CreateJunction(str(self.victim), str(cache / "Cache_Data" / "link"))
                deleted, freed, left = clear_folder(self.path(name), keep_dirs=keep_dirs)
                self.assertVictimIntact()
                self.assertFalse(os.path.lexists(cache / "Cache_Data" / "link"))
                # Three files and the link; the victim's bytes are not counted.
                self.assertEqual((deleted, freed, left), (4, 1124, 0))

    def test_a_subfolder_swapped_for_a_junction_mid_clear_is_not_followed(self):
        cache = self.make_cache()
        real_list = safe_delete._list_names
        swapped = []

        def list_then_swap(handle):
            names = real_list(handle)
            if "Cache_Data" in names and not swapped:
                shutil.rmtree(cache / "Cache_Data")
                _winapi.CreateJunction(str(self.victim), str(cache / "Cache_Data"))
                swapped.append(True)
            return names

        with mock.patch.object(safe_delete, "_list_names", side_effect=list_then_swap):
            clear_folder(self.path("Cache"), keep_dirs=True)
        self.assertTrue(swapped, "the swap never happened, so the test proved nothing")
        self.assertVictimIntact()

    def test_a_cache_folder_that_is_a_junction_is_refused(self):
        _winapi.CreateJunction(str(self.victim), str(self.base / "Cache"))
        for keep_dirs in (True, False):
            with self.subTest(keep_dirs=keep_dirs):
                with self.assertRaises(OSError) as caught:
                    clear_folder(self.path("Cache"), keep_dirs=keep_dirs)
                self.assertNotIsInstance(caught.exception, FileNotFoundError)
                self.assertVictimIntact()

    def test_a_cache_folder_reached_through_a_junction_is_refused(self):
        _winapi.CreateJunction(str(self.victim), str(self.base / "link"))
        with self.assertRaises(OSError) as caught:
            clear_folder(self.path("link", "inner"))
        self.assertNotIsInstance(caught.exception, FileNotFoundError)
        self.assertVictimIntact()

    def test_a_missing_folder_raises_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            clear_folder(self.path("never-existed"))

    def test_a_file_is_not_a_folder_to_clear(self):
        (self.base / "lone.tmp").write_text("x")
        with self.assertRaises(NotADirectoryError):
            clear_folder(self.path("lone.tmp"))
        self.assertTrue((self.base / "lone.tmp").exists())

    def test_a_file_in_use_is_left_and_counted(self):
        cache = self.make_cache()
        busy = cache / "Cache_Data" / "busy"
        with open(busy, "w") as held:  # the CRT never shares delete
            held.write("x")
            deleted, _freed, left = clear_folder(self.path("Cache"), keep_dirs=True)
        self.assertEqual((deleted, left), (3, 1))
        self.assertTrue(busy.exists())

    def test_a_hard_link_is_deleted_without_claiming_its_bytes(self):
        cache = self.make_cache()
        os.link(self.victim / "precious.txt", cache / "hardlink.txt")
        self.assertEqual(clear_folder(self.path("Cache"), keep_dirs=True), (4, 1124, 0))
        self.assertVictimIntact()


class CleanTempFilesTests(_Fixture):
    """The task end to end, pointed at a fake SystemRoot and TEMP."""

    class Host(CleanupTasks):
        def __init__(self):
            import queue
            import threading
            self.queue = queue.Queue()
            self.cancel_event = threading.Event()
            self.failures = []

        def _report_failure(self, message):
            self.failures.append(message)
            self.queue.put(message)

    def setUp(self):
        super().setUp()
        self.system_root = self.base / "Windows"
        self.windows_temp = self.system_root / "Temp"
        self.user_temp = self.base / "UserTemp"
        self.windows_temp.mkdir(parents=True)
        self.user_temp.mkdir()

    @staticmethod
    def age(path, days=3):
        old = time.time() - days * 86400
        os.utime(path, (old, old))

    def run_task(self):
        host = self.Host()
        env = {"SystemRoot": str(self.system_root), "TEMP": str(self.user_temp)}
        with mock.patch.dict(os.environ, env):
            host.clean_temp_files()
        lines = []
        while not host.queue.empty():
            lines.append(host.queue.get())
        return host, lines

    def test_old_items_go_recent_items_stay_and_a_planted_junction_is_not_followed(self):
        attacker = self.windows_temp / f"tmp{uuid.uuid4().hex[:6]}"
        (attacker / "sub").mkdir(parents=True)
        (attacker / "sub" / "x.tmp").write_text("x")
        _winapi.CreateJunction(str(self.victim), str(attacker / "sub" / "into-victim"))
        self.age(attacker)
        old_file = self.user_temp / "old.log"
        old_file.write_text("x")
        self.age(old_file)
        fresh = self.user_temp / "installer-in-progress.msi"
        fresh.write_text("x")

        host, lines = self.run_task()

        self.assertEqual(host.failures, [])
        self.assertFalse(attacker.exists())
        self.assertFalse(old_file.exists())
        self.assertTrue(fresh.exists(), "items changed in the last 24 hours must be kept")
        self.assertVictimIntact()
        self.assertTrue(any("deleted 1 item(s)" in line for line in lines), lines)

    def test_a_locked_item_is_counted_as_in_use(self):
        held_dir = self.windows_temp / "held"
        held_dir.mkdir()
        with open(held_dir / "busy.tmp", "w"):
            self.age(held_dir)
            _host, lines = self.run_task()
        self.assertTrue(held_dir.exists())
        self.assertTrue(any("1 in use" in line for line in lines), lines)


class ClearBrowserCacheTests(_Fixture):
    """The task end to end, pointed at a fake LOCALAPPDATA."""

    Host = CleanTempFilesTests.Host

    def setUp(self):
        super().setUp()
        self.local = self.base / "Local"
        self.profile = self.local / "Google" / "Chrome" / "User Data" / "Default"
        (self.profile / "Cache" / "Cache_Data").mkdir(parents=True)
        (self.profile / "Preferences").write_text("{}")
        (self.profile / "Cache" / "Cache_Data" / "f_000001").write_bytes(b"x" * 2 * 1048576)
        (self.profile / "Code Cache" / "js").mkdir(parents=True)
        (self.profile / "Code Cache" / "js" / "abc_0").write_bytes(b"x")

    def run_task(self, local=None):
        host = self.Host()
        with mock.patch.dict(os.environ, {"LOCALAPPDATA": str(local or self.local)}):
            host.run_clear_browser_cache()
        lines = []
        while not host.queue.empty():
            lines.append(host.queue.get())
        self.assertEqual(host.failures, [])
        return lines

    def assertCacheCleared(self):
        self.assertTrue((self.profile / "Cache" / "Cache_Data").is_dir(),
                        "browsers expect their cache folders to stay")
        self.assertTrue((self.profile / "Code Cache" / "js").is_dir())
        self.assertFalse((self.profile / "Cache" / "Cache_Data" / "f_000001").exists())
        self.assertFalse((self.profile / "Code Cache" / "js" / "abc_0").exists())
        self.assertTrue((self.profile / "Preferences").exists())

    def test_files_go_folders_stay_and_a_planted_junction_is_not_followed(self):
        _winapi.CreateJunction(str(self.victim), str(self.profile / "Cache" / "Cache_Data" / "x"))
        lines = self.run_task()
        self.assertVictimIntact()
        self.assertCacheCleared()
        # Two files and the link -- and only their bytes.
        self.assertTrue(any("Google Chrome (Default): Deleted 3 files (2 MB)" in line
                            for line in lines), lines)

    def test_a_cache_folder_that_is_a_junction_is_left_alone_and_said_so(self):
        _winapi.CreateJunction(str(self.victim), str(self.profile / "GPUCache"))
        lines = self.run_task()
        self.assertVictimIntact()
        self.assertTrue(os.path.lexists(self.profile / "GPUCache"))
        self.assertTrue(any("GPUCache was not cleared" in line for line in lines), lines)
        self.assertCacheCleared()

    def test_a_profile_reached_through_a_junction_is_left_alone(self):
        # Every folder below LOCALAPPDATA belongs to the user's own programs,
        # so a link anywhere there, not only at the cache folder, is refused.
        (self.victim / "cache2" / "entries").mkdir(parents=True)
        (self.victim / "cache2" / "entries" / "E1").write_text("keep me")
        profiles = self.local / "Mozilla" / "Firefox" / "Profiles"
        profiles.mkdir(parents=True)
        _winapi.CreateJunction(str(self.victim), str(profiles / "abc.default"))
        lines = self.run_task()
        self.assertVictimIntact()
        self.assertEqual((self.victim / "cache2" / "entries" / "E1").read_text(), "keep me")
        self.assertTrue(any("Firefox (abc.default): cache2 was not cleared" in line
                            for line in lines), lines)

    def test_a_redirected_local_app_data_folder_is_still_cleaned(self):
        # LOCALAPPDATA itself may legitimately live elsewhere; it is resolved,
        # and only what lies below it has to be free of links.
        redirect = self.base / "LocalRedirect"
        _winapi.CreateJunction(str(self.local), str(redirect))
        self.run_task(local=redirect)
        self.assertCacheCleared()


class ClearShaderCacheTests(_Fixture):
    """The repair end to end, pointed at a fake LOCALAPPDATA and APPDATA."""

    def setUp(self):
        super().setUp()
        self.local = self.base / "Local"
        self.roaming = self.base / "Roaming"
        self.local.mkdir()
        self.roaming.mkdir()

    def run_repair(self):
        logs = []
        env = {"LOCALAPPDATA": str(self.local), "APPDATA": str(self.roaming)}
        with mock.patch.dict(os.environ, env):
            result = _do_clear_shader_cache({}, logs.append)
        return result, logs

    def test_contents_go_the_folder_stays_and_a_nested_junction_is_not_followed(self):
        cache = self.local / "D3DSCache"
        (cache / "4d1e" / "sub").mkdir(parents=True)
        (cache / "4d1e" / "shader.idx").write_bytes(b"x" * 3 * 1048576)
        (cache / "4d1e" / "sub" / "shader.val").write_bytes(b"x")
        _winapi.CreateJunction(str(self.victim), str(cache / "4d1e" / "sub" / "link"))
        (self.victim / "big.bin").write_bytes(b"v" * 5 * 1048576)
        result, _logs = self.run_repair()
        self.assertTrue(result["ok"], result)
        self.assertTrue(cache.is_dir(), "the drivers expect the cache folder to stay")
        self.assertEqual(list(cache.iterdir()), [])
        self.assertVictimIntact()
        self.assertTrue((self.victim / "big.bin").exists())
        # The old size count walked through the junction and claimed 8 MB.
        self.assertIn("freeing 3 MB", result["message"])

    def test_a_cache_folder_that_is_a_junction_is_left_alone(self):
        (self.local / "NVIDIA").mkdir()
        _winapi.CreateJunction(str(self.victim), str(self.local / "NVIDIA" / "DXCache"))
        result, _logs = self.run_repair()
        self.assertFalse(result["ok"], result)
        self.assertIn("NVIDIA\\DXCache", result["message"])
        self.assertVictimIntact()

    def test_a_refused_cache_does_not_stop_the_others(self):
        (self.local / "D3DSCache").mkdir()
        (self.local / "D3DSCache" / "a.bin").write_bytes(b"x")
        (self.local / "AMD").mkdir()
        _winapi.CreateJunction(str(self.victim), str(self.local / "AMD" / "DxCache"))
        result, logs = self.run_repair()
        self.assertTrue(result["ok"], result)
        self.assertFalse((self.local / "D3DSCache" / "a.bin").exists())
        self.assertVictimIntact()
        self.assertTrue(any("AMD\\DxCache" in line for line in logs), logs)

    def test_an_item_in_use_is_left_and_mentioned(self):
        cache = self.roaming / "NVIDIA" / "ComputeCache"
        cache.mkdir(parents=True)
        with open(cache / "busy", "w"):
            result, _logs = self.run_repair()
        self.assertTrue(result["ok"], result)
        self.assertIn("1 item could not be deleted", result["message"])

    def test_nothing_to_clear(self):
        result, _logs = self.run_repair()
        self.assertTrue(result["ok"], result)
        self.assertIn("no shader caches", result["message"])


if __name__ == "__main__":
    unittest.main()
