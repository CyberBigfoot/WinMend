"""WinMend diagnostics: repairs: base."""

from __future__ import annotations

import subprocess


# ---------------------------------------------------------------------------
# Targeted repair actions
#
# These are what separate this from a checklist: the engine has identified a
# specific object, and these act on that object rather than on a whole category.
# Everything here either records an undo payload or is covered by the session
# restore point -- an action that can do neither does not belong in this file.
# ---------------------------------------------------------------------------

def _run_command(command, timeout=180):
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout, creationflags=flags,
        )
        return result.returncode, (result.stdout or ""), (result.stderr or "")
    except FileNotFoundError as exc:
        return -1, "", str(exc)
    except subprocess.TimeoutExpired:
        return -1, "", f"Timed out after {timeout} seconds."
    except Exception as exc:  # pragma: no cover - defensive
        return -1, "", str(exc)


def _result(ok, message, undo=None, needs_restart=False):
    return {"ok": bool(ok), "message": message, "undo": undo or {},
            "needs_restart": bool(needs_restart)}


class RepairAction:
    """One targeted repair.

    ``run(params, log)`` returns the dict built by :func:`_result`. When it
    reports an ``undo`` payload, ``undo(payload, log)`` must be able to put the
    system back exactly as it was.
    """

    __slots__ = ("id", "title", "summary", "risk", "admin", "restore_point",
                 "duration", "reboot", "_run", "_undo", "verify_keys", "confirm",
                 "_reversible")

    def __init__(self, id, title, summary, run, undo=None, risk="caution", admin=True,
                 restore_point=False, duration="1-2 min", reboot=False,
                 verify_keys=(), confirm=False, reversible=None):
        self.id = id
        self.title = title
        self.summary = summary
        self.risk = risk
        self.admin = admin
        self.restore_point = restore_point
        self.duration = duration
        self.reboot = reboot
        self._run = run
        self._undo = undo
        self.verify_keys = tuple(verify_keys)
        # True for anything that cannot be put back automatically.
        self.confirm = confirm
        # Some actions carry an undo that only *explains* why the change cannot
        # be reversed in place (a removed driver package no longer exists).
        # Those must not advertise themselves as reversible: the restore point
        # is their real undo path, and the UI decides what to promise from this.
        self._reversible = (undo is not None) if reversible is None else bool(reversible)

    @property
    def reversible(self):
        return self._reversible

    def run(self, params=None, log=None):
        logger = log or (lambda _message: None)
        try:
            return self._run(dict(params or {}), logger)
        except Exception as exc:
            return _result(False, f"The repair could not run: {exc}")

    def undo(self, payload, log=None):
        if self._undo is None:
            return _result(False, "This repair has no automatic undo.")
        logger = log or (lambda _message: None)
        try:
            return self._undo(dict(payload or {}), logger)
        except Exception as exc:
            return _result(False, f"The undo could not run: {exc}")
