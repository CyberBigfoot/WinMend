"""Tests for the pure logic behind the Startup Manager page and the winget
App-updates panel: StartupApproved blobs, Run-key command parsing, and the
winget upgrade-table parser."""

import struct
import unittest

from winmend_safety import (
    exe_from_command,
    parse_winget_list,
    parse_winget_upgrade,
    startup_blob_is_disabled,
    startup_disable_blob,
    startup_enable_blob,
)


class StartupBlobTests(unittest.TestCase):
    def test_enable_blob_layout(self):
        blob = startup_enable_blob()
        self.assertEqual(len(blob), 12)
        self.assertEqual(struct.unpack("<I", blob[:4])[0], 2)
        self.assertEqual(blob[4:], b"\x00" * 8)

    def test_disable_blob_layout_and_filetime(self):
        # 2026-01-01 00:00:00 UTC as a known point in time
        blob = startup_disable_blob(now=1767225600.0)
        self.assertEqual(len(blob), 12)
        self.assertEqual(struct.unpack("<I", blob[:4])[0], 3)
        filetime = struct.unpack("<Q", blob[4:])[0]
        self.assertEqual(filetime, (1767225600 + 11644473600) * 10_000_000)

    def test_disabled_detection_uses_low_bit(self):
        self.assertTrue(startup_blob_is_disabled(startup_disable_blob()))
        self.assertFalse(startup_blob_is_disabled(startup_enable_blob()))
        # Task Manager writes other even/odd first bytes too (0x06/0x07)
        self.assertTrue(startup_blob_is_disabled(b"\x07" + b"\x00" * 11))
        self.assertFalse(startup_blob_is_disabled(b"\x06" + b"\x00" * 11))

    def test_missing_or_malformed_blob_means_enabled(self):
        self.assertFalse(startup_blob_is_disabled(b""))
        self.assertFalse(startup_blob_is_disabled(None))
        self.assertFalse(startup_blob_is_disabled("not-bytes"))


class ExeFromCommandTests(unittest.TestCase):
    def test_quoted_path_with_arguments(self):
        self.assertEqual(
            exe_from_command('"C:\\Program Files\\App\\app.exe" --minimized'),
            "C:\\Program Files\\App\\app.exe")

    def test_unquoted_path_with_spaces_and_arguments(self):
        real = "C:\\Program Files\\App\\app.exe"
        exists = lambda p: p == real
        self.assertEqual(
            exe_from_command("C:\\Program Files\\App\\app.exe /background",
                             exists=exists),
            real)

    def test_simple_unquoted_path(self):
        self.assertEqual(
            exe_from_command("C:\\Tools\\thing.exe", exists=lambda p: False),
            "C:\\Tools\\thing.exe")

    def test_empty_command(self):
        self.assertEqual(exe_from_command(""), "")
        self.assertEqual(exe_from_command(None), "")


WINGET_SAMPLE = """\
Name                     Id                    Version      Available    Source
-------------------------------------------------------------------------------
Mozilla Firefox          Mozilla.Firefox       127.0        128.0.1      winget
Some Very Long App Na…   SomePublisher.SomeV…  1.2.3        1.3.0        winget
7-Zip                    7zip.7zip             23.01        24.08        winget
3 upgrades available.
"""

WINGET_TWO_TABLES = """\
Name       Id             Version   Available   Source
------------------------------------------------------
7-Zip      7zip.7zip      23.01     24.08       winget
1 upgrades available.

The following packages have an upgrade available, but require explicit targeting for upgrade:
Name       Id             Version   Available   Source
------------------------------------------------------
OldTool    Vendor.OldTool 1.0       2.0         winget
"""


class WingetParseTests(unittest.TestCase):
    def test_parses_rows_and_skips_count_line(self):
        rows = parse_winget_upgrade(WINGET_SAMPLE)
        self.assertEqual(len(rows), 3)
        firefox = rows[0]
        self.assertEqual(firefox["id"], "Mozilla.Firefox")
        self.assertEqual(firefox["version"], "127.0")
        self.assertEqual(firefox["available"], "128.0.1")
        self.assertEqual(firefox["source"], "winget")
        self.assertFalse(firefox["truncated"])

    def test_truncated_id_is_flagged(self):
        rows = parse_winget_upgrade(WINGET_SAMPLE)
        truncated = [r for r in rows if r["truncated"]]
        self.assertEqual(len(truncated), 1)
        self.assertIn("…", truncated[0]["id"])

    def test_multiple_tables_are_all_parsed(self):
        rows = parse_winget_upgrade(WINGET_TWO_TABLES)
        self.assertEqual([r["id"] for r in rows],
                         ["7zip.7zip", "Vendor.OldTool"])

    def test_progress_garbage_and_empty_input(self):
        self.assertEqual(parse_winget_upgrade(""), [])
        self.assertEqual(parse_winget_upgrade(None), [])
        noisy = "\x08\x08- \r\n" + WINGET_SAMPLE
        self.assertEqual(len(parse_winget_upgrade(noisy)), 3)

    def test_no_table_means_no_rows(self):
        self.assertEqual(parse_winget_upgrade("No installed package found "
                                              "matching input criteria."), [])


# Shape taken from this machine's real `winget list`: most rows have an empty
# Available column, packages winget did not install itself carry an invented
# ARP\/MSIX\ pseudo-id, and some of those pseudo-ids contain spaces.
WINGET_LIST_SAMPLE = """\
Name                     Id                                        Version      Available    Source
----------------------------------------------------------------------------------------------------
7-Zip 24.08 (x64)        7zip.7zip                                 24.08                     winget
Mozilla Firefox          Mozilla.Firefox                           127.0        128.0.1      winget
AMD Software             ARP\\Machine\\X64\\AMD Catalyst Install Man 26.3.1
Discord                  MSIX\\discord.com-EA2E0C84_1.0.0.1_neutral 1.0.0.1
Some Very Long App Na…   SomePublisher.SomeVeryLongIdentifier…      1.2.3                     winget
195 packages installed.
"""


class WingetListParseTests(unittest.TestCase):
    def test_installed_ids_are_lowercased(self):
        installed = parse_winget_list(WINGET_LIST_SAMPLE)
        self.assertIn("7zip.7zip", installed)
        self.assertIn("mozilla.firefox", installed)
        self.assertEqual(installed["7zip.7zip"], "24.08")

    def test_row_without_an_available_version_still_counts(self):
        # The upgrade parser drops these; an installed-listing must not.
        self.assertIn("7zip.7zip", parse_winget_list(WINGET_LIST_SAMPLE))

    def test_truncated_and_spaced_pseudo_ids_are_dropped(self):
        installed = parse_winget_list(WINGET_LIST_SAMPLE)
        self.assertFalse([i for i in installed if "…" in i or " " in i])

    def test_msix_pseudo_id_never_matches_a_catalogue_id(self):
        installed = parse_winget_list(WINGET_LIST_SAMPLE)
        self.assertNotIn("discord.discord", installed)

    def test_count_line_and_empty_input(self):
        self.assertEqual(parse_winget_list(""), {})
        self.assertEqual(parse_winget_list(None), {})
        self.assertNotIn("195", "".join(parse_winget_list(WINGET_LIST_SAMPLE)))

    def test_nothing_installed_means_nothing_reported(self):
        self.assertEqual(parse_winget_list("No installed package found "
                                           "matching input criteria."), {})


if __name__ == "__main__":
    unittest.main()
