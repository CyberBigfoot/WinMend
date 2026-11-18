"""Module boundaries, resource lookup and application lifetime regressions."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')


class PackageBoundaryTests(unittest.TestCase):
    def test_backend_imports_do_not_load_qt_or_run_startup(self):
        code = (
            'import sys; '
            'import winmend.core.task_host_base; '
            'import winmend.core.task_runner; '
            'import winmend.diagnostics.engine; '
            'import winmend.safety.journal; '
            'assert not any(n.startswith("PySide6") for n in sys.modules)'
        )
        result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True,
                                cwd=Path(__file__).resolve().parents[1], timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '')

    def test_compatibility_imports_share_the_actual_objects(self):
        import WinMend
        import winmend_diagnostics
        import winmend_safety
        from winmend.diagnostics.engine import CaseEngine
        from winmend.features.tweaks import REMOVE, WM_TWEAKS
        from winmend.safety.journal import SafetyJournal
        from winmend.ui.task_host import WMTaskHost
        self.assertIs(WinMend.WMTaskHost, WMTaskHost)
        self.assertIs(winmend_diagnostics.CaseEngine, CaseEngine)
        self.assertIs(winmend_safety.SafetyJournal, SafetyJournal)
        self.assertIs(WinMend.WM_TWEAKS, WM_TWEAKS)
        self.assertIs(winmend_safety.REMOVE, REMOVE)

    def test_source_resources_still_resolve_to_the_project_root(self):
        from winmend.core.paths import application_root
        with mock.patch.object(sys, '_MEIPASS', None, create=True):
            self.assertEqual(application_root(), Path(__file__).resolve().parents[1])
            self.assertTrue((application_root() / 'icon.ico').is_file())

    def test_frozen_resources_use_the_extraction_directory(self):
        from winmend.core.paths import application_root
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(sys, '_MEIPASS', directory, create=True):
                self.assertEqual(application_root(), Path(directory))


class ElevationEntryTests(unittest.TestCase):
    def test_script_and_module_entry_points_keep_their_arguments(self):
        from winmend import bootstrap
        root = Path(__file__).resolve().parents[1]
        for entry, expected in (
                (str(root / 'WinMend.py'), str(root / 'WinMend.py')),
                (str(root / 'winmend/__main__.py'), '-m winmend')):
            with self.subTest(entry=entry):
                with mock.patch.object(sys, 'argv', [entry, '--no-relaunch']), \
                        mock.patch.object(sys, 'frozen', False, create=True), \
                        mock.patch.object(bootstrap.ctypes.windll.shell32, 'ShellExecuteW', return_value=33) as launch:
                    with self.assertRaises(SystemExit) as stopped:
                        bootstrap.restart_as_admin()
                self.assertEqual(stopped.exception.code, 0)
                self.assertIn(expected, launch.call_args.args[3])
                self.assertIn('--no-relaunch', launch.call_args.args[3])


class LogCallbackLifetimeTests(unittest.TestCase):
    def test_closing_the_log_before_its_scroll_callback_is_safe(self):
        from PySide6.QtWidgets import QApplication, QTextBrowser
        import shiboken6
        from winmend.ui.theme import WM_DARK
        from winmend.ui.window_queue import WindowQueueMixin
        app = QApplication.instance() or QApplication([])
        view = QTextBrowser()
        harness = SimpleNamespace(T=WM_DARK, log_view=view)
        errors = []
        with mock.patch.object(sys, 'excepthook', lambda *args: errors.append(args)):
            WindowQueueMixin._log(harness, 'A final log message before closing.')
            shiboken6.delete(view)
            app.processEvents()
        self.assertEqual(errors, [])


if __name__ == '__main__':
    unittest.main()
