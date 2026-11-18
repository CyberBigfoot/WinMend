"""WinMend diagnostics: repairs: startup."""

from __future__ import annotations

from winmend.diagnostics.repairs.base import _result
import os


def _do_disable_startup_entry(params, log):
    from winmend.features.startup.helpers import list_startup_entries
    from winmend.features.startup.helpers import set_startup_entry_enabled
    wanted = str(params.get("name", "")).strip().lower()
    if not wanted:
        return _result(False, "No startup entry was identified.")
    entries = list_startup_entries()
    match = next((e for e in entries if e["name"].strip().lower() == wanted), None)
    if match is None:
        # Boot-performance events name the friendly app, not the registry value.
        match = next((e for e in entries
                      if wanted in e["name"].strip().lower()
                      or wanted in os.path.basename(e.get("exe", "")).lower()), None)
    if match is None:
        return _result(
            False,
            f"There is no startup entry named {params.get('name')!r}. If Windows reported it "
            "as slowing startup, it is a process Windows launches itself rather than something "
            "listed in Startup, and it cannot be switched off here.")
    if not match.get("enabled"):
        return _result(True, f"{match['name']} was already disabled.")
    error = set_startup_entry_enabled(match, False)
    if error:
        return _result(False, error)
    return _result(True, f"{match['name']} will no longer start with Windows.",
                   undo={"kind": "startup", "entry": {k: match[k] for k in
                                                      ("name", "root", "approved_subkey", "value")}})


def _undo_disable_startup_entry(payload, log):
    from winmend.features.startup.helpers import set_startup_entry_enabled
    entry = payload.get("entry") or {}
    if not entry.get("value"):
        return _result(False, "The recorded startup entry is incomplete.")
    error = set_startup_entry_enabled(entry, True)
    if error:
        return _result(False, error)
    return _result(True, f"{entry.get('name', 'The startup entry')} was re-enabled.")
