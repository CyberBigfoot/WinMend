"""Tests for the Windows-preference tweak engine.

The engine writes to the live registry, so these tests use a scratch key under
HKCU that they create and delete themselves -- no real setting is touched. What
is being pinned here is the behaviour that makes the page trustworthy: reading
reports the registry rather than a default, writing restores the other state
exactly, and nothing outside the tweak's own value is disturbed.
"""

import unittest

try:
    import winreg
except ImportError:                                   # pragma: no cover
    winreg = None

from winmend_safety import (
    DNS_PROVIDERS,
    REMOVE,
    TweakValue,
    WM_TWEAKS,
    WindowsTweak,
    apply_tweak,
    dns_provider,
    read_tweak_state,
    tweak_groups,
)

SCRATCH = r"Software\WinMendTweakTests"


def _tweak(*values, **kwargs):
    return WindowsTweak("t", "t", "", "Test", list(values), **kwargs)


@unittest.skipIf(winreg is None, "Windows only")
class TweakEngineTests(unittest.TestCase):
    def setUp(self):
        winreg.CreateKey(winreg.HKEY_CURRENT_USER, SCRATCH).Close()

    def tearDown(self):
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, SCRATCH)
        except OSError:
            pass

    def _set(self, name, data, kind=None):
        if kind is None:
            kind = winreg.REG_DWORD if isinstance(data, int) else winreg.REG_SZ
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, SCRATCH, 0,
                            winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, name, 0, kind, data)

    def _get(self, name):
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, SCRATCH) as key:
            return winreg.QueryValueEx(key, name)

    def test_state_comes_from_the_registry_not_the_default(self):
        tweak = _tweak(TweakValue("HKCU", SCRATCH, "V", "dword", 1, 0),
                       default_on=True)
        self._set("V", 0)
        self.assertFalse(read_tweak_state(tweak))
        self._set("V", 1)
        self.assertTrue(read_tweak_state(tweak))

    def test_absent_value_falls_back_to_the_windows_default(self):
        on = _tweak(TweakValue("HKCU", SCRATCH, "Missing", "dword", 1, 0),
                    default_on=True)
        off = _tweak(TweakValue("HKCU", SCRATCH, "Missing", "dword", 1, 0),
                     default_on=False)
        self.assertTrue(read_tweak_state(on))
        self.assertFalse(read_tweak_state(off))

    def test_unrecognised_value_is_not_reported_as_on(self):
        # Something else set a third state; claiming "on" would be a guess.
        tweak = _tweak(TweakValue("HKCU", SCRATCH, "V", "dword", 1, 0))
        self._set("V", 7)
        self.assertFalse(read_tweak_state(tweak))

    def test_off_state_can_be_the_value_being_absent(self):
        tweak = _tweak(TweakValue("HKCU", SCRATCH, "V", "dword", 1, REMOVE),
                       default_on=False)
        self.assertEqual(apply_tweak(tweak, True), "")
        self.assertEqual(self._get("V")[0], 1)
        self.assertEqual(apply_tweak(tweak, False), "")
        with self.assertRaises(OSError):
            self._get("V")

    def test_deleting_an_already_absent_value_is_not_an_error(self):
        tweak = _tweak(TweakValue("HKCU", SCRATCH, "Gone", "dword", 1, REMOVE))
        self.assertEqual(apply_tweak(tweak, False), "")

    def test_existing_value_keeps_its_registry_type(self):
        # StickyKeys' Flags is a REG_SZ holding a number; rewriting it as a
        # REG_DWORD changes something the user never asked us to touch.
        tweak = _tweak(TweakValue("HKCU", SCRATCH, "V", "dword", 1, 0))
        self._set("V", "0", winreg.REG_SZ)
        apply_tweak(tweak, True)
        data, kind = self._get("V")
        self.assertEqual(kind, winreg.REG_SZ)
        self.assertEqual(data, "1")

    def test_bitmask_preserves_the_other_bits(self):
        tweak = _tweak(TweakValue("HKCU", SCRATCH, "Flags", "dword",
                                  0x08, 0x00, mask=0x08))
        self._set("Flags", 498)
        self.assertFalse(read_tweak_state(tweak))
        apply_tweak(tweak, True)
        self.assertEqual(self._get("Flags")[0], 506)
        self.assertTrue(read_tweak_state(tweak))
        apply_tweak(tweak, False)
        self.assertEqual(self._get("Flags")[0], 498)

    def test_round_trip_restores_every_value(self):
        tweak = _tweak(TweakValue("HKCU", SCRATCH, "A", "dword", 1, 0),
                       TweakValue("HKCU", SCRATCH, "B", "string", "yes", "no"))
        self._set("A", 0)
        self._set("B", "no")
        apply_tweak(tweak, True)
        apply_tweak(tweak, False)
        self.assertEqual(self._get("A")[0], 0)
        self.assertEqual(self._get("B")[0], "no")

    def test_reader_and_writer_replace_the_value_machinery(self):
        box = {"on": False}
        tweak = WindowsTweak("k", "k", "", "Test", [],
                             reader=lambda: box["on"],
                             writer=lambda enable: box.__setitem__("on", enable) or "")
        self.assertFalse(read_tweak_state(tweak))
        self.assertEqual(apply_tweak(tweak, True), "")
        self.assertTrue(read_tweak_state(tweak))


class TweakCatalogueTests(unittest.TestCase):
    def test_ids_are_unique(self):
        ids = [t.id for t in WM_TWEAKS]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_tweak_can_be_read_and_written(self):
        for tweak in WM_TWEAKS:
            with self.subTest(tweak=tweak.id):
                self.assertTrue(tweak.values or (tweak.reader and tweak.writer))
                self.assertTrue(tweak.name and tweak.description and tweak.group)

    def test_value_definitions_are_well_formed(self):
        for tweak in WM_TWEAKS:
            for value in tweak.values:
                with self.subTest(tweak=tweak.id, value=value.name):
                    self.assertIn(value.root, ("HKCU", "HKLM", "HKU"))
                    self.assertIn(value.kind, ("dword", "string"))
                    self.assertNotEqual(value.on, value.off)

    def test_on_and_off_are_never_both_absent(self):
        # A tweak whose both states are "value missing" could never be toggled.
        for tweak in WM_TWEAKS:
            for value in tweak.values:
                with self.subTest(tweak=tweak.id):
                    self.assertFalse(value.on is REMOVE and value.off is REMOVE)

    def test_after_is_a_known_kind(self):
        for tweak in WM_TWEAKS:
            with self.subTest(tweak=tweak.id):
                self.assertIn(tweak.after, ("", "explorer", "signout", "reboot"))

    def test_groups_cover_every_tweak_once(self):
        grouped = [t for _name, tweaks in tweak_groups() for t in tweaks]
        self.assertEqual(len(grouped), len(WM_TWEAKS))
        self.assertEqual({t.id for t in grouped}, {t.id for t in WM_TWEAKS})

    def test_hklm_tweaks_declare_that_they_need_admin(self):
        for tweak in WM_TWEAKS:
            needs = any(v.root in ("HKLM", "HKU") and not v.optional
                        for v in tweak.values)
            with self.subTest(tweak=tweak.id):
                self.assertEqual(tweak.needs_admin(), needs or tweak.admin)


class DnsProviderTests(unittest.TestCase):
    def test_ids_are_unique_and_lookup_works(self):
        ids = [p["id"] for p in DNS_PROVIDERS]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(dns_provider("cloudflare")["v4"][0], "1.1.1.1")
        self.assertIsNone(dns_provider("nope"))

    def test_every_provider_is_complete(self):
        for provider in DNS_PROVIDERS:
            with self.subTest(provider=provider["id"]):
                self.assertTrue(provider["name"] and provider["detail"])
                self.assertEqual(len(provider["v4"]), 2)
                self.assertEqual(len(provider["v6"]), 2)
                self.assertTrue(provider["doh"].startswith("https://"))

    def test_addresses_look_like_addresses(self):
        # These are injected into a PowerShell command, so they must never be
        # anything but digits and dots / hex and colons.
        import re
        for provider in DNS_PROVIDERS:
            for address in provider["v4"]:
                with self.subTest(address=address):
                    self.assertRegex(address, r"^\d{1,3}(\.\d{1,3}){3}$")
            for address in provider["v6"]:
                with self.subTest(address=address):
                    self.assertRegex(address, r"^[0-9a-f:]+$")


if __name__ == "__main__":
    unittest.main()
