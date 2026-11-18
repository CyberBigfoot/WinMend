"""WinMend bootstrap."""

from __future__ import annotations

from PySide6.QtCore import Qt as QtC
from PySide6.QtWidgets import QApplication
from pathlib import Path
from winmend.core.prompts import messagebox
from winmend.core.security import SecurityUtils
from winmend.ui.main_window import WMMainWindow
from winmend.ui.theme import wm_load_theme_pref

import ctypes
import os
import sys
import time
import traceback


def prepare_startup():
    startup_log("Application starting")

    # Skip relaunch with pythonw.exe for now to troubleshoot
    skip_relaunch = True
    if '--no-relaunch' not in sys.argv:
        # Only relaunch if we're running from a console and not already using pythonw.exe
        if not getattr(sys, 'frozen', False) and sys.stdout is not None and 'pythonw' not in sys.executable.lower():
            startup_log("Attempting to relaunch with pythonw.exe")
            try:
                pythonw_path = os.path.join(os.path.dirname(sys.executable), 'pythonw.exe')
                if os.path.exists(pythonw_path):
                    startup_log(f"Found pythonw.exe at: {pythonw_path}")
                    startup_log("Skipping automatic relaunch for debugging")
                    skip_relaunch = True
                else:
                    startup_log("pythonw.exe not found, continuing in console mode")
            except Exception as e:
                startup_log(f"Error during relaunch attempt: {str(e)}")
                startup_log("Continuing in console mode")

    # Check if running on Windows
    if os.name != 'nt':
        print("This application is designed to run on Windows only.")
        startup_log("Not running on Windows, exiting")
        sys.exit(1)

    if not check_dependencies():
        print("Dependencies check failed. Exiting.")
        sys.exit(1)


# Enhanced startup logging

def startup_log(message):
    """Log startup messages to console only"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"{timestamp} - {message}")


# Check dependencies first
def check_dependencies():
    startup_log("Checking dependencies")
    required_modules = [
        'ctypes', 'subprocess', 'winreg', 'threading',
        'queue', 'time', 'json', 'hashlib', 're', 'pathlib',
        'webbrowser'
    ]
    # pythoncom is bundled by PyInstaller as a native DLL and may not be
    # importable via the standard import mechanism in a frozen exe.
    # It is checked separately as an optional/warn-only dependency.
    optional_modules = ['pythoncom']

    missing_modules = []
    for module in required_modules:
        try:
            __import__(module)
            startup_log(f"Module OK: {module}")
        except ImportError as e:
            missing_modules.append(f"{module}: {str(e)}")
            startup_log(f"Module missing: {module} - {str(e)}")

    for module in optional_modules:
        try:
            __import__(module)
            startup_log(f"Module OK: {module}")
        except ImportError as e:
            startup_log(f"Module optional/warn: {module} - {str(e)} (non-fatal)")

    if missing_modules:
        print("Missing required modules:")
        startup_log("Missing modules detected:")
        for module in missing_modules:
            print(f"  - {module}")
            startup_log(f"  - {module}")
        print("\nPlease install them using: pip install <module_name>")
        startup_log("Dependency check failed, exiting")
        return False
    startup_log("All dependencies OK")
    return True


def wm_main_qt():
    """Entry point for the UI."""
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        QtC.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv)
    app.setApplicationName("WinMend")
    win = WMMainWindow(wm_load_theme_pref())
    win.show()
    return app.exec()


def is_frozen():
    """Check if the application is running as a frozen executable"""
    return getattr(sys, 'frozen', False)


def restart_as_admin():
    """Restart the application with administrator privileges"""
    try:
        # Get the path to the current executable
        executable = sys.executable

        # Build command line arguments
        if is_frozen():
            # Running as a frozen executable
            args = sys.argv[1:]  # Skip the first argument (the executable path)
        else:
            # Running as a script
            if Path(sys.argv[0]).resolve() == Path(__file__).resolve().with_name("__main__.py"):
                args = ["-m", "winmend"]
            else:
                args = [os.path.abspath(sys.argv[0])]  # The script path
            if len(sys.argv) > 1:
                args.extend(sys.argv[1:])

        # Sanitize arguments
        safe_args = SecurityUtils.sanitize_command_args(args)

        # Quote any argument that contains spaces so the path is passed correctly
        # (e.g. "Windows System Cleaner.py" has a space and must be wrapped in quotes)
        quoted_args = [f'"{a}"' if ' ' in a else a for a in safe_args]

        # Start new process with admin rights
        # Using ShellExecuteW with runas verb to trigger UAC
        result = ctypes.windll.shell32.ShellExecuteW(
            None,  # hwnd
            "runas",  # verb
            executable,  # file to execute
            " ".join(quoted_args),  # parameters (properly quoted)
            None,  # current directory
            1  # show command (SW_SHOWNORMAL)
        )

        # Check if ShellExecuteW succeeded (returns >32 on success)
        if result <= 32:
            messagebox.showerror("Error", f"Failed to restart as administrator. Error code: {result}")
            return False

        # Exit the current instance
        sys.exit(0)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to restart as administrator: {str(e)}")
        return False


def _startup_alert(title, message, icon=0x30):
    """Native message box for failures that happen before any UI exists.

    main() runs before QApplication is created, so the Qt boxes are not
    available yet and the tkinter ones are gone. MessageBoxW needs neither.
    """
    try:
        ctypes.windll.user32.MessageBoxW(None, str(message), str(title), icon)
    except Exception:
        print(f"{title}: {message}")


def main():
    try:
        startup_log("Main function started")

        # Check if we're in a relaunch process
        if '--relaunched' in sys.argv:
            startup_log("Application relaunched with pythonw.exe")

        # Check if running as admin, if not restart. --no-elevate skips it, which
        # is only for reviewing the UI without a UAC prompt; admin tasks then
        # report themselves as unavailable rather than failing obscurely.
        if '--no-elevate' not in sys.argv and not ctypes.windll.shell32.IsUserAnAdmin():
            startup_log("Not running as admin, restarting with admin privileges")
            if not restart_as_admin():
                startup_log("Failed to restart as admin, continuing without admin rights")
                _startup_alert(
                    "Administrator Rights Required",
                    "This application requires administrator privileges to function "
                    "properly.\nSome features may not work correctly.\n\n"
                    "Please restart the application as administrator.")

        startup_log("Running with admin privileges")
        startup_log("Starting Qt UI (WinMend 2.0)")
        sys.exit(wm_main_qt())

    except Exception as e:
        startup_log(f"Application error: {str(e)}")
        startup_log(f"Traceback: {traceback.format_exc()}")
        print(f"Error: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        _startup_alert("Application Error", f"An error occurred: {str(e)}", 0x10)
        sys.exit(1)
