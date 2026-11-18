"""Startup follows Windows; manual theme changes preserve the live UI."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QTextCursor
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QTreeWidget, QTreeWidgetItem

import WinMend as W
from winmend.ui import main_window as window_module, theme as theme_module


class StartupThemeTests(unittest.TestCase):
    def test_each_launch_reads_windows_even_with_an_old_manual_preference(self):
        with tempfile.TemporaryDirectory() as directory:
            preference = Path(directory) / "theme_pref.json"
            for windows_mode, saved_mode, expected in (
                    ("light", "dark", W.WM_LIGHT), ("dark", "light", W.WM_DARK)):
                with self.subTest(windows=windows_mode):
                    preference.write_text(json.dumps({"theme_mode": saved_mode}))
                    with mock.patch.object(W, "_get_pref_path", return_value=str(preference)), \
                            mock.patch.object(theme_module, "wm_detect_windows_theme", return_value=windows_mode) as detect:
                        self.assertIs(W.wm_load_theme_pref(), expected)
                        detect.assert_called_once_with()
                    self.assertEqual(json.loads(preference.read_text())["theme_mode"], saved_mode)

    def test_unreadable_windows_theme_falls_back_to_dark(self):
        with mock.patch.object(W.winreg, "OpenKey", side_effect=PermissionError):
            self.assertEqual(W.wm_detect_windows_theme(), "dark")


class ManualThemeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def _window(self, theme):
        # No dashboard probes, journal writes, repairs or app installs.
        previous_message_host = W.WMMessageBox.host
        previous_dialog_host = W.WMSimpleDialog.host
        with mock.patch.object(window_module, "SafetyJournal"), \
                mock.patch.object(W.WMMainWindow, "_load_dashboard", lambda *_: None):
            window = W.WMMainWindow(theme)
        window.pump.stop()
        window.tick.stop()
        self.app.processEvents()
        self.addCleanup(window.deleteLater)
        self.addCleanup(setattr, W.WMMessageBox, "host", previous_message_host)
        self.addCleanup(setattr, W.WMSimpleDialog, "host", previous_dialog_host)
        return window

    def test_switching_keeps_page_selection_and_running_task(self):
        window = self._window(W.WM_DARK)
        window._show_category("network")
        card = window.cards[0]
        card.cb.click()
        selected = {key for key, value in window.host.vars.items() if value.get()}
        cards = list(window.cards)
        page = window.stack.currentWidget()
        running = object()
        window.run_thread = running
        window.pending = ["flush_dns"]
        shared_tokens = window.T

        window.theme_switch.click()

        self.assertIs(window.T, shared_tokens)
        self.assertEqual(window.T, W.WM_LIGHT)
        self.assertEqual(W.WM_DARK['name'], 'dark')
        self.assertEqual(window.current_cat, "network")
        self.assertEqual(window.cards, cards)
        self.assertIs(window.stack.currentWidget(), page)
        self.assertIs(window.run_thread, running)
        self.assertEqual(window.pending, ["flush_dns"])
        self.assertEqual({key for key, value in window.host.vars.items() if value.get()}, selected)
        self.assertTrue(card.cb.isChecked())
        self.assertIn(W.WM_LIGHT['card'], card.styleSheet())
        self.assertFalse(window.theme_switch.isChecked())
        window.run_thread = None

    def test_return_trip_restores_styles_and_keeps_primary_button_text_white(self):
        window = self._window(W.WM_DARK)
        window._show_category("network")
        original = {widget: widget.styleSheet() for widget in window.cards[0].findChildren(W.QWidget)}
        window._set_theme(False)
        self.assertIn("color:#fff", window.run_btn.styleSheet())
        self.assertEqual(window.palette().color(W.QPalette.Window), QColor(W.WM_LIGHT['bg']))
        window._set_theme(True)
        self.assertEqual(window.T, W.WM_DARK)
        for widget, stylesheet in original.items():
            self.assertEqual(widget.styleSheet(), stylesheet)

    def test_table_and_log_colours_change_without_losing_content_or_selection(self):
        window = self._window(W.WM_DARK)
        tree = QTreeWidget(window.centralWidget())
        tree.setColumnCount(1)
        item = QTreeWidgetItem(["Selected app"])
        item.setCheckState(0, Qt.Checked)
        item.setForeground(0, QColor(W.WM_DARK['text_3']))
        tree.addTopLevelItem(item)
        window._log("Existing task result", W.WM_DARK['ok'])
        plain_text = window.log_view.toPlainText()
        cursor = window.log_view.textCursor()
        cursor.setPosition(plain_text.index("Existing"))
        cursor.movePosition(QTextCursor.End, QTextCursor.KeepAnchor)
        window.log_view.setTextCursor(cursor)
        selected = cursor.selectedText()

        window._set_theme(False)

        self.assertEqual(tree.topLevelItem(0), item)
        self.assertEqual(item.checkState(0), Qt.Checked)
        self.assertEqual(item.foreground(0).color(), QColor(W.WM_LIGHT['text_3']))
        self.assertEqual(window.log_view.toPlainText(), plain_text)
        self.assertEqual(window.log_view.textCursor().selectedText(), selected)
        self.assertIn(W.WM_LIGHT['ok'].lower(), window.log_view.toHtml())

    def test_cached_pages_detached_by_navigation_receive_the_new_theme(self):
        window = self._window(W.WM_DARK)
        cached = W.QFrame()
        cached.T = window.T
        cached.setStyleSheet(f"background:{window.T['card']};color:{window.T['text_2']};")
        window.speedtest_page = cached
        window.stack.addWidget(cached)
        window._show_category("network")
        self.assertIsNone(cached.parentWidget())
        self.addCleanup(cached.deleteLater)

        window._set_theme(False)

        self.assertIs(window.speedtest_page, cached)
        self.assertIs(cached.T, window.T)
        self.assertIn(W.WM_LIGHT['card'], cached.styleSheet())
        self.assertIn(W.WM_LIGHT['text_2'], cached.styleSheet())

    def test_manual_override_is_not_saved_for_the_next_launch(self):
        with mock.patch.object(theme_module, "wm_detect_windows_theme", return_value="light"), \
                mock.patch.object(W, "_get_pref_path", side_effect=AssertionError("Theme must not persist")):
            window = self._window(W.wm_load_theme_pref())
            self.assertFalse(window.theme_switch.isChecked())
            window.theme_switch.click()
            self.assertEqual(window.T['name'], "dark")
            next_window = self._window(W.wm_load_theme_pref())
            self.assertEqual(next_window.T['name'], "light")
            self.assertFalse(next_window.theme_switch.isChecked())

    def test_theme_switch_supports_mouse_keyboard_and_quick_reversal(self):
        switch = W.WMThemeSwitch(dict(W.WM_LIGHT))
        events = []
        switch.toggled.connect(events.append)
        switch.show()
        self.addCleanup(switch.deleteLater)
        self.app.processEvents()
        QTest.mouseClick(switch, Qt.LeftButton)
        self.assertTrue(switch.isChecked())
        QTest.qWait(40)
        QTest.keyClick(switch, Qt.Key_Space)
        QTest.qWait(600)
        self.assertFalse(switch.isChecked())
        self.assertEqual(events, [True, False])
        self.assertEqual(switch.accessibleName(), "Dark mode")
        self.assertEqual(switch._position, 0.0)

    def test_transition_captures_the_window_background_and_finishes(self):
        window = self._window(W.WM_DARK)
        window.show()
        self.app.processEvents()
        window._set_theme(False)
        curtain = window._theme_curtain
        self.assertIsNotNone(curtain)
        self.assertTrue(curtain.testAttribute(Qt.WA_TransparentForMouseEvents))
        image = curtain._snapshot.toImage()
        self.assertEqual(image.pixelColor(image.width() // 2, 5), QColor(W.WM_DARK['bg']))
        curtain.animation.setCurrentTime(150)
        revealed = window.grab().toImage()
        self.assertEqual(revealed.pixelColor(revealed.width() // 2, 5), QColor(W.WM_LIGHT['bg']))
        self.assertEqual(revealed.pixelColor(revealed.width() - 10, 5), QColor(W.WM_DARK['sidebar']))
        QTest.qWait(400)
        self.assertIsNone(window._theme_curtain)


if __name__ == "__main__":
    unittest.main()
