"""WinMend safety: undo seals.

The Safety Journal lives in %APPDATA%, which every program running as the user
can rewrite. Reversing a change replays what the journal recorded -- with
administrator rights, because WinMend runs elevated. Trusting the file would let
an ordinary program write an "undo" of its own (put User Account Control back to
never prompting, prepend a folder to the system PATH) and have WinMend apply it
the next time someone clicks Reverse.

A seal is a SHA-256 of exactly what WinMend recorded, bound to the session and
step it belongs to, kept in HKLM\\SOFTWARE\\WinMend\\UndoSeals: a key created with
a protected DACL (SYSTEM and Administrators write, Users read) and an
Administrators owner. An undo runs only while the journal still matches its
seal; a journal entry with no seal -- forged, edited, or written before seals
existed -- is not offered for automatic reversal.

The seal is not a secret, so a hash is enough: what matters is that only an
administrator can write one.
"""

from __future__ import annotations

import hashlib
import json

RESTORE_POINT_STEP = "__restore_point__"

SEALS_KEY = r"SOFTWARE\WinMend\UndoSeals"

# O:BA      owned by Administrators, so the owner's implicit WRITE_DAC is theirs
# D:P       protected: nothing inherited from HKLM\SOFTWARE (no CREATOR OWNER)
_SEALS_SDDL = "O:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)"

_TRUSTED_SIDS = {
    "S-1-5-18",      # SYSTEM
    "S-1-5-32-544",  # Administrators
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",  # TrustedInstaller
}

# Anything that lets the holder change the key, its values or its security.
_KEY_WRITE_RIGHTS = (0x0002 | 0x0004 | 0x0020    # KEY_SET_VALUE, KEY_CREATE_SUB_KEY, KEY_CREATE_LINK
                     | 0x00010000 | 0x00040000 | 0x00080000  # DELETE, WRITE_DAC, WRITE_OWNER
                     | 0x02000000 | 0x10000000 | 0x40000000)  # MAXIMUM_ALLOWED, GENERIC_ALL, GENERIC_WRITE

_ACCESS_ALLOWED_ACE_TYPE = 0
_ACCESS_DENIED_ACE_TYPE = 1
_INHERIT_ONLY_ACE = 0x08
_SE_DACL_PROTECTED = 0x1000


def seal_digest(session_id, step_id, payload):
    """SHA-256 of `payload` as the journal will store it, bound to its step."""
    # Round-trip first so the digest is of what json.load gives back later:
    # tuples become lists, integer keys become strings.
    stored = json.loads(json.dumps(payload, ensure_ascii=False))
    canonical = json.dumps(stored, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    text = f"{session_id}\n{step_id}\n{canonical}"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _seal_name(session_id, step_id):
    return f"{session_id}|{step_id}"


class _UndoSeals:
    """Seal bookkeeping over a small name -> digest store."""

    def _write(self, name, digest):
        raise NotImplementedError

    def _read(self, name):
        raise NotImplementedError

    def _delete(self, name):
        raise NotImplementedError

    def _names(self):
        raise NotImplementedError

    # Every failure below is a safe one -- an unrecorded seal means "cannot be
    # reversed automatically", never "reversed without a check" -- so they are
    # caught broadly: pywin32 errors are not OSErrors, and a missing pywin32 is
    # an ImportError.

    def seal(self, session_id, step_id, payload):
        """Record `payload` as WinMend's own. False when it could not be recorded."""
        try:
            self._write(_seal_name(session_id, step_id), seal_digest(session_id, step_id, payload))
            return True
        except Exception:
            return False

    def verify(self, session_id, step_id, payload):
        """True only when `payload` is exactly what WinMend sealed for this step."""
        if not payload:
            return False
        try:
            stored = self._read(_seal_name(session_id, step_id))
            return bool(stored) and stored == seal_digest(session_id, step_id, payload)
        except Exception:
            return False

    def revoke(self, session_id, step_id):
        try:
            self._delete(_seal_name(session_id, step_id))
        except Exception:
            pass

    def prune(self, keep_session_ids):
        """Drop seals for sessions the journal no longer keeps."""
        keep = set(keep_session_ids)
        try:
            for name in self._names():
                if name.split("|", 1)[0] not in keep:
                    self._delete(name)
        except Exception:
            pass


class MemoryUndoSeals(_UndoSeals):
    """In-process seals for a journal at a custom path (tests and tools)."""

    def __init__(self):
        self._values = {}

    def _write(self, name, digest):
        self._values[name] = digest

    def _read(self, name):
        return self._values.get(name)

    def _delete(self, name):
        self._values.pop(name, None)

    def _names(self):
        return list(self._values)


def security_is_admin_only(descriptor):
    """True when only SYSTEM, Administrators or TrustedInstaller can change the key.

    `descriptor` is a pywin32 PySECURITY_DESCRIPTOR carrying the owner and DACL.
    """
    import win32security

    owner = descriptor.GetSecurityDescriptorOwner()
    if owner is None or win32security.ConvertSidToStringSid(owner) not in _TRUSTED_SIDS:
        return False
    dacl = descriptor.GetSecurityDescriptorDacl()
    if dacl is None:
        return False  # a NULL DACL grants everyone everything
    for index in range(dacl.GetAceCount()):
        ace = dacl.GetAce(index)
        (ace_type, ace_flags), mask, sid = ace[0], ace[1], ace[-1]
        if ace_type == _ACCESS_DENIED_ACE_TYPE or ace_flags & _INHERIT_ONLY_ACE:
            continue  # denies never widen access; inherit-only ACEs skip this key
        if win32security.ConvertSidToStringSid(sid) in _TRUSTED_SIDS:
            continue
        if ace_type != _ACCESS_ALLOWED_ACE_TYPE or mask & _KEY_WRITE_RIGHTS:
            return False
    return True


class _UntrustedKey(Exception):
    """The seal key exists but someone other than an administrator can change it."""


_ERROR_FILE_NOT_FOUND = 2
_ERROR_NO_MORE_ITEMS = 259


class RegistryUndoSeals(_UndoSeals):
    """Seals in HKLM, writable by administrators only.

    Every open checks the key's security first: seals in a key someone else can
    write prove nothing, so such a key verifies nothing. Writing to it (which
    takes an administrator) deletes it and starts again with the right DACL.
    Without administrator rights nothing can be sealed, so nothing recorded in
    that run is offered for automatic reversal.
    """

    def __init__(self, key=SEALS_KEY):
        self.key = key

    @staticmethod
    def _modules():
        import win32api
        import win32con
        import win32security
        return win32api, win32con, win32security

    def _open(self, write):
        win32api, win32con, win32security = self._modules()
        access = win32con.KEY_READ | win32con.KEY_WOW64_64KEY
        if write:
            access |= win32con.KEY_SET_VALUE
        handle = win32api.RegOpenKeyEx(win32con.HKEY_LOCAL_MACHINE, self.key, 0, access)
        try:
            descriptor = win32api.RegGetKeySecurity(
                handle,
                win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
            if not security_is_admin_only(descriptor):
                raise _UntrustedKey(f"HKLM\\{self.key} can be changed by non-administrators")
        except BaseException:
            handle.Close()
            raise
        return handle

    def _create(self):
        win32api, win32con, win32security = self._modules()
        attributes = win32security.SECURITY_ATTRIBUTES()
        attributes.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            _SEALS_SDDL, win32security.SDDL_REVISION_1)
        parent = self.key.rsplit("\\", 1)[0]
        access = win32con.KEY_ALL_ACCESS | win32con.KEY_WOW64_64KEY
        # The parent takes HKLM\SOFTWARE's usual inheritance; the seal key
        # itself is created with its own DACL in the same call, so there is no
        # moment when it exists with a weaker one.
        handle, _ = win32api.RegCreateKeyEx(win32con.HKEY_LOCAL_MACHINE, parent, access,
                                            None, 0, None, None)
        handle.Close()
        handle, _ = win32api.RegCreateKeyEx(win32con.HKEY_LOCAL_MACHINE, self.key, access,
                                            None, 0, attributes, None)
        handle.Close()

    def _writable(self):
        """The seal key opened for writing, created or re-created with an admin-only DACL."""
        win32api, win32con, _ = self._modules()
        try:
            return self._open(write=True)
        except _UntrustedKey:
            # Someone else could have written these; none of them can be trusted.
            win32api.RegDeleteKeyEx(win32con.HKEY_LOCAL_MACHINE, self.key,
                                    samDesired=win32con.KEY_WOW64_64KEY)
        except Exception as exc:
            if getattr(exc, "winerror", None) != _ERROR_FILE_NOT_FOUND:
                raise
        self._create()
        return self._open(write=True)

    def _write(self, name, digest):
        win32api, win32con, _ = self._modules()
        handle = self._writable()
        try:
            win32api.RegSetValueEx(handle, name, 0, win32con.REG_SZ, digest)
        finally:
            handle.Close()

    def _read(self, name):
        win32api, _, _ = self._modules()
        try:
            handle = self._open(write=False)
        except Exception:
            return None  # no key, or one that proves nothing
        try:
            value, _kind = win32api.RegQueryValueEx(handle, name)
            return value if isinstance(value, str) else None
        except Exception:
            return None
        finally:
            handle.Close()

    def _delete(self, name):
        win32api, _, _ = self._modules()
        handle = self._open(write=True)
        try:
            win32api.RegDeleteValue(handle, name)
        except Exception as exc:
            if getattr(exc, "winerror", None) != _ERROR_FILE_NOT_FOUND:
                raise
        finally:
            handle.Close()

    def _names(self):
        win32api, _, _ = self._modules()
        handle = self._open(write=False)
        names = []
        try:
            index = 0
            while True:
                try:
                    names.append(win32api.RegEnumValue(handle, index)[0])
                except Exception as exc:
                    if getattr(exc, "winerror", None) == _ERROR_NO_MORE_ITEMS:
                        break
                    raise
                index += 1
        finally:
            handle.Close()
        return names
