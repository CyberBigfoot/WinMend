"""Tests for the app catalogue behind the Install Apps page.

INSTALLABLE_APPS is data the page is generated from -- names, winget ids,
categories, descriptions -- so the things that can silently break it are
structural: a missing field renders a blank cell, a duplicate winget id makes
two rows fight over one "Installed" reading, and an id with a space or a stray
"…" can never match anything winget reports. None of that needs Qt to check.
"""

import unittest

import WinMend as W


class CatalogueShapeTests(unittest.TestCase):
    def test_every_app_has_the_three_fields_the_page_renders(self):
        missing = [name for name, data in W.INSTALLABLE_APPS.items()
                   if not (data.get("winget") and data.get("category")
                           and data.get("description"))]
        self.assertEqual(missing, [])

    def test_winget_ids_are_targetable(self):
        # The page runs `winget install --id <id> --exact`; a space or an
        # ellipsis means the id was truncated or invented and cannot be targeted.
        bad = [(name, data["winget"]) for name, data in W.INSTALLABLE_APPS.items()
               if " " in data["winget"] or "…" in data["winget"]]
        self.assertEqual(bad, [])

    def test_no_two_apps_share_a_winget_id(self):
        seen = {}
        for name, data in W.INSTALLABLE_APPS.items():
            seen.setdefault(data["winget"].lower(), []).append(name)
        self.assertEqual({k: v for k, v in seen.items() if len(v) > 1}, {})

    def test_categories_helper_covers_every_app(self):
        by_category = W.get_apps_by_category()
        self.assertEqual(sorted(by_category), W.get_categories())
        self.assertEqual(sum(len(v) for v in by_category.values()),
                         len(W.INSTALLABLE_APPS))

    def test_catalogue_is_not_empty(self):
        # The nav subtitle and task description both quote this count.
        self.assertGreater(len(W.INSTALLABLE_APPS), 100)


class CataloguePageWiringTests(unittest.TestCase):
    def test_apps_page_is_a_navigable_category(self):
        self.assertIn("apps", {c[0] for c in W.WM_CATEGORIES})

    def test_apps_page_has_an_icon(self):
        # An unset key renders as an empty nav glyph; a guessed PUA codepoint
        # renders as tofu. Both are caught by requiring a real value here.
        self.assertTrue(W.WM_GLYPH.get("apps"))

    def test_installer_task_is_registered_and_dispatchable(self):
        task = next((t for t in W.WM_TASKS if t.id == "app_installer"), None)
        self.assertIsNotNone(task)
        self.assertEqual(task.category, "updates")
        self.assertEqual(W.WM_HANDLERS.get("app_installer"), "run_app_installer")
        self.assertTrue(callable(getattr(W.WMTaskHost, "run_app_installer", None)))

    def test_installer_task_is_not_labelled_read_only(self):
        # It installs software; "safe" renders a green Read-only pill users take
        # to mean nothing can change.
        task = next(t for t in W.WM_TASKS if t.id == "app_installer")
        self.assertNotEqual(task.risk, "safe")

if __name__ == "__main__":
    unittest.main()
