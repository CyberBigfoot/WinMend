"""WinMend diagnostics: repairs: profile."""

from __future__ import annotations

from winmend.diagnostics.repairs.base import _result
import os
import re
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


# -- the temporary profile --------------------------------------------------
#
# When Windows cannot load a profile at sign-in it makes a blank one, points
# ``ProfileList\<SID>`` at it, and moves the real entry to ``<SID>.bak``. To the
# person using the PC every file they own has vanished. The fix is to put the
# two entries back the right way round -- which is also the single easiest way
# to lock someone out of their own account, so every step below is guarded and
# nothing is deleted until its contents have been copied somewhere recoverable.

_PROFILE_LIST = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"


def _read_key_values(root, name):
    """Every value under one key, or None when the key is absent."""
    try:
        with winreg.OpenKey(root, name) as key:
            count, values, _ = winreg.QueryInfoKey(key)
            if count:
                # A ProfileList entry has no subkeys. Something that does is not
                # the shape this repair understands, and it stops here.
                return None
            found = []
            for index in range(values):
                try:
                    found.append(winreg.EnumValue(key, index))
                except OSError:
                    break
            return found
    except OSError:
        return None


def _write_key_values(root, name, values):
    with winreg.CreateKey(root, name) as key:
        for value_name, data, kind in values:
            winreg.SetValueEx(key, value_name, 0, kind, data)


def _profile_path_of(values):
    for value_name, data, _kind in values or ():
        if value_name.lower() == "profileimagepath":
            return str(data)
    return ""


def _do_restore_profile(params, log):
    if winreg is None:
        return _result(False, "Registry access is unavailable.")
    current = os.environ.get("USERPROFILE", "")
    leaf = os.path.basename(current.rstrip("\\")) if current else ""
    if not leaf.upper().startswith("TEMP"):
        return _result(
            False,
            "This session is not running on a temporary profile, so there is nothing to put "
            "back. Repairing a profile that is already the right one is how a working account "
            "gets broken.")
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _PROFILE_LIST, 0,
                              winreg.KEY_READ | winreg.KEY_WRITE)
    except OSError as exc:
        return _result(False, f"The profile list could not be opened: {exc}")
    with root:
        sid = ""
        for index in range(winreg.QueryInfoKey(root)[0]):
            try:
                candidate = winreg.EnumKey(root, index)
            except OSError:
                break
            if candidate.lower().endswith(".bak"):
                continue
            stored = _profile_path_of(_read_key_values(root, candidate))
            if stored and os.path.normcase(os.path.normpath(stored)) == \
                    os.path.normcase(os.path.normpath(current)):
                sid = candidate
                break
        if not sid:
            return _result(False, "No profile list entry points at this session's folder, so "
                                  "there is nothing to swap.")
        temp_values = _read_key_values(root, sid)
        real_values = _read_key_values(root, sid + ".bak")
        if temp_values is None:
            return _result(False, f"The entry for {sid} could not be read.")
        if real_values is None:
            return _result(
                False,
                "Windows did not keep a backup entry for this account, so the real profile "
                "cannot be pointed back to from here. The files are still on the disk under "
                r"C:\Users -- copying them into a new account is the recovery path, and it is "
                "worth doing by hand rather than automatically.")
        real_path = _profile_path_of(real_values)
        if not real_path or not os.path.isdir(real_path):
            return _result(
                False,
                f"The backup entry points at {real_path or 'nothing'}, which is not on this PC. "
                "Restoring it would sign you in to a folder that does not exist.")
        log(f"The real profile is {real_path}. Keeping a copy of the temporary entry...")
        try:
            _write_key_values(root, sid + ".winmend-temp", temp_values)
        except OSError as exc:
            return _result(False, f"The temporary entry could not be saved, so nothing was "
                                  f"changed: {exc}")
        log("Pointing the account back at the real profile...")
        try:
            with winreg.OpenKey(root, sid, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
                for value_name, _data, _kind in temp_values:
                    if value_name.lower() not in {v[0].lower() for v in real_values}:
                        try:
                            winreg.DeleteValue(key, value_name)
                        except OSError:
                            pass
                for value_name, data, kind in real_values:
                    winreg.SetValueEx(key, value_name, 0, kind, data)
                # State 0 is a healthy profile. A non-zero State is what makes
                # Windows decide the profile is broken and hand out a temporary
                # one again at the next sign-in.
                winreg.SetValueEx(key, "State", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key, "RefCount", 0, winreg.REG_DWORD, 0)
        except OSError as exc:
            return _result(False, f"The profile entry could not be rewritten: {exc}")
        try:
            _write_key_values(root, sid + ".winmend-bak", real_values)
            winreg.DeleteKey(root, sid + ".bak")
        except OSError as exc:
            log(f"The old backup entry could not be tidied away ({exc}); it is harmless.")
    return _result(
        True,
        f"This account points at {real_path} again. Restart, then sign in: the desktop, "
        f"documents, and settings come back with it. Nothing was deleted -- anything saved "
        f"during the temporary session is still in {current}.",
        undo={"kind": "profile", "sid": sid}, needs_restart=True)


def _undo_restore_profile(payload, log):
    if winreg is None:
        return _result(False, "Registry access is unavailable.")
    sid = str(payload.get("sid", "")).strip()
    if not re.fullmatch(r"S-[0-9\-]{4,80}", sid):
        return _result(False, "The recorded profile entry is incomplete.")
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _PROFILE_LIST, 0,
                              winreg.KEY_READ | winreg.KEY_WRITE)
    except OSError as exc:
        return _result(False, f"The profile list could not be opened: {exc}")
    with root:
        temp_values = _read_key_values(root, sid + ".winmend-temp")
        real_values = _read_key_values(root, sid + ".winmend-bak")
        if temp_values is None:
            return _result(False, "The saved temporary entry is no longer present, so this "
                                  "cannot be reversed from here.")
        try:
            if real_values is not None:
                _write_key_values(root, sid + ".bak", real_values)
            with winreg.OpenKey(root, sid, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
                for value_name, _data, _kind in (real_values or ()):
                    if value_name.lower() not in {v[0].lower() for v in temp_values}:
                        try:
                            winreg.DeleteValue(key, value_name)
                        except OSError:
                            pass
                for value_name, data, kind in temp_values:
                    winreg.SetValueEx(key, value_name, 0, kind, data)
            winreg.DeleteKey(root, sid + ".winmend-temp")
            if real_values is not None:
                winreg.DeleteKey(root, sid + ".winmend-bak")
        except OSError as exc:
            return _result(False, f"The profile entries could not be put back: {exc}")
    return _result(True, "The profile list was put back exactly as it was, temporary profile "
                         "and all.", needs_restart=True)
