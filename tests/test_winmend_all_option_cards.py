"""Every catalog card selects its variable and dispatches its own Run button."""
import os
import unittest
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QCoreApplication, QEvent
from PySide6.QtWidgets import QApplication, QPushButton
from winmend.data.task_catalog import WM_TASKS
from winmend.ui import main_window as window_module
from winmend.ui.dialogs import WMMessageBox, WMSimpleDialog
from winmend.ui.main_window import WMMainWindow
from winmend.ui.theme import WM_DARK
from winmend.ui.widgets.winget import WMWingetPanel


class AllOptionCardsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_every_option_selects_persists_and_dispatches_the_correct_task(self):
        old_message_host, old_dialog_host = WMMessageBox.host, WMSimpleDialog.host
        with mock.patch.object(window_module, "SafetyJournal"), \
                mock.patch.object(WMMainWindow, "_load_dashboard", lambda *_: None), \
                mock.patch.object(WMWingetPanel, "refresh", lambda *_: None):
            window = WMMainWindow(WM_DARK)
            window.pump.stop()
            window.tick.stop()
            window._set_mode(False)
            try:
                observed = set()
                for category in dict.fromkeys(task.category for task in WM_TASKS):
                    window._show_category(category)
                    expected = {task.id for task in WM_TASKS if task.category == category}
                    self.assertEqual({card.task.id for card in window.cards}, expected)
                    for card in window.cards:
                        with self.subTest(task=card.task.id):
                            card.cb.click()
                            self.assertTrue(window.host.vars[card.task.id].get())
                            with mock.patch.object(window, "_start") as start:
                                run = next(button for button in card.findChildren(QPushButton)
                                           if button.text() == "Run")
                                run.click()
                            start.assert_called_once_with([card.task])
                            observed.add(card.task.id)
                    window._show_category(category)
                    for card in window.cards:
                        self.assertTrue(card.cb.isChecked(), card.task.id)
                        card.cb.click()
                        self.assertFalse(window.host.vars[card.task.id].get())
                self.assertEqual(observed, {task.id for task in WM_TASKS})
                found, _ = window._search_task_ids("gpu stress")
                self.assertEqual(found[0], "gpu_stress_test")
            finally:
                window.deleteLater()
                QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
                WMMessageBox.host, WMSimpleDialog.host = old_message_host, old_dialog_host


if __name__ == "__main__":
    unittest.main()
