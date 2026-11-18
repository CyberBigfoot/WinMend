"""WinMend diagnostics: repairs: common."""

from __future__ import annotations

from winmend.diagnostics.repairs.base import _run_command
import re
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


# -- shared plumbing for the settings repairs -------------------------------
#
# Six of the repairs below turn one policy or one service back on. Writing the
# snapshot/restore pair by hand six times is how an undo ends up subtly
# different from the change it is supposed to reverse -- particularly the
# difference between "this value was zero" and "this value was not set at all",
# which Windows treats as two different states and which a careless undo
# silently collapses into one.

def _ps_run(script, timeout=90):
    """Run one PowerShell script. Returns (returncode, stdout, stderr)."""
    return _run_command(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned",
         "-Command", script], timeout=timeout)


def _registry_snapshot(hive, path, names):
    """Record the named values, with ``None`` for anything that is not set."""
    previous = {name: None for name in names}
    if winreg is None:
        return previous
    try:
        with winreg.OpenKey(hive, path) as key:
            for name in names:
                try:
                    value, kind = winreg.QueryValueEx(key, name)
                    previous[name] = [value, int(kind)]
                except OSError:
                    previous[name] = None
    except OSError:
        pass
    return previous


def _registry_apply(hive, path, changes):
    """Set or delete values. ``None`` in ``changes`` means delete.

    Returns an error string, or "" on success. The key is opened rather than
    created: every caller here is turning an existing Windows setting back to
    its default, and a repair that has to invent the key it is repairing is
    a repair aimed at the wrong place.
    """
    if winreg is None:
        return "Registry access is unavailable."
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
            for name, entry in changes.items():
                if entry is None:
                    try:
                        winreg.DeleteValue(key, name)
                    except OSError:
                        pass
                    continue
                value, kind = entry
                winreg.SetValueEx(key, name, 0, int(kind), value)
    except OSError as exc:
        return str(exc)
    return ""


def _registry_restore(hive, path, previous):
    """Put back exactly what :func:`_registry_snapshot` recorded."""
    return _registry_apply(hive, path, previous)


_SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"


_START_WORDS = {0: "boot", 1: "system", 2: "auto", 3: "demand", 4: "disabled"}


_START_VALUES = {word: number for number, word in _START_WORDS.items()}


def _service_start(name):
    """The service's configured start type as a number, or None."""
    if winreg is None:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf"{_SERVICES_KEY}\{name}") as key:
            return int(winreg.QueryValueEx(key, "Start")[0])
    except (OSError, ValueError, TypeError):
        return None


def _valid_service_name(name):
    return bool(re.fullmatch(r"[A-Za-z0-9_\-.]{1,64}", name))


def _valid_drive(drive):
    return bool(re.fullmatch(r"[A-Za-z]:", str(drive).strip()))
