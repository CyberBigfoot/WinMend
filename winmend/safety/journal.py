"""WinMend safety: journal."""

from __future__ import annotations

from pathlib import Path
from winmend.core.findings import JOURNAL_SCHEMA, utc_now
from winmend.safety.seals import MemoryUndoSeals, RESTORE_POINT_STEP, RegistryUndoSeals
import json
import os
import shutil
import threading
import time
import uuid


class SafetyJournal:
    """Small, atomic JSON journal of WinMend runs.

    Only task names, outcomes, protection metadata, and diagnostic summaries are
    stored.  Command output and discovered file paths are deliberately excluded
    because they may contain private information.

    The file is in %APPDATA%, where any program running as the user can edit
    it, so nothing in it is trusted to drive an elevated undo on its own: every
    undo payload and restore-point number WinMend records is also sealed (see
    winmend.safety.seals), and only sealed records are offered for reversal.
    The default journal seals in HKLM; one at a custom path seals in memory
    unless given ``seals``, so tests never touch the machine's registry.
    """

    def __init__(self, path=None, max_sessions=200, seals=None):
        if seals is None:
            seals = RegistryUndoSeals() if path is None else MemoryUndoSeals()
        if path is None:
            appdata = os.environ.get("APPDATA", str(Path.home()))
            path = Path(appdata) / "WinMend" / "safety_journal.json"
        self.path = Path(path)
        self.max_sessions = max(20, int(max_sessions))
        self.seals = seals
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _empty():
        return {"schema": JOURNAL_SCHEMA, "sessions": []}

    def _load_unlocked(self):
        if not self.path.exists():
            return self._empty()
        try:
            with self.path.open("r", encoding="utf-8") as stream:
                data = json.load(stream)
            if not isinstance(data, dict) or not isinstance(data.get("sessions"), list):
                raise ValueError("invalid journal structure")
            data.setdefault("schema", JOURNAL_SCHEMA)
            return data
        except (OSError, ValueError, json.JSONDecodeError):
            # Preserve the damaged source for support/recovery instead of silently
            # destroying it the next time a session is written.
            backup = self.path.with_name(
                f"{self.path.stem}.corrupt-{int(time.time())}{self.path.suffix}")
            try:
                shutil.copy2(self.path, backup)
            except OSError:
                pass
            return self._empty()

    def _save_unlocked(self, data):
        data["schema"] = JOURNAL_SCHEMA
        data["sessions"] = data.get("sessions", [])[: self.max_sessions]
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        with temp.open("w", encoding="utf-8", newline="\n") as stream:
            json.dump(data, stream, indent=2, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, self.path)

    def _mutate(self, callback):
        with self._lock:
            data = self._load_unlocked()
            result = callback(data)
            self._save_unlocked(data)
            return result

    def list_sessions(self):
        with self._lock:
            data = self._load_unlocked()
            return json.loads(json.dumps(data["sessions"]))

    def recover_interrupted_sessions(self):
        """Close sessions left running by a reboot, crash, or forced app exit."""
        def update(data):
            recovered = 0
            for session in data["sessions"]:
                if session.get("status") != "running":
                    continue
                recovered += 1
                session["status"] = "interrupted"
                session["completed_at"] = utc_now()
                session["verification"] = {
                    "outcome": "unavailable",
                    "summary": "WinMend closed or Windows restarted before this session could be finalized.",
                }
                for task in session.get("tasks", []):
                    if task.get("state") in ("queued", "running"):
                        task["state"] = "interrupted"
                        task["completed_at"] = utc_now()
            return recovered

        return self._mutate(update)

    def get_session(self, session_id):
        for session in self.list_sessions():
            if session.get("id") == session_id:
                return session
        return None

    def start_session(self, source, planned_tasks, problem="", diagnosis=None):
        session_id = uuid.uuid4().hex
        started = utc_now()
        tasks = []
        for task in planned_tasks:
            tasks.append({
                "id": task.get("id", ""),
                "title": task.get("title", task.get("id", "Unknown task")),
                "risk": task.get("risk", "caution"),
                "restore_point": bool(task.get("restore_point")),
                "state": "queued",
                "started_at": None,
                "completed_at": None,
                "duration_seconds": None,
                "error": "",
            })
        session = {
            "id": session_id,
            "started_at": started,
            "completed_at": None,
            "source": source,
            "problem": problem.strip(),
            "status": "running",
            "tasks": tasks,
            "diagnosis_before": diagnosis or {},
            "verification": {},
            "protection": {
                "requested": any(t["restore_point"] for t in tasks),
                "created": False,
                "sequence": None,
                "description": "",
                "created_at": None,
            },
            "undo": {"available": False, "status": "not_available", "requested_at": None},
        }

        def add(data):
            data["sessions"].insert(0, session)
            return session_id

        return self._mutate(add)

    @staticmethod
    def _session(data, session_id):
        return next((s for s in data["sessions"] if s.get("id") == session_id), None)

    def _prune_seals(self):
        try:
            self.seals.prune(s.get("id") for s in self.list_sessions())
        except Exception:
            pass

    def set_protection(self, session_id, created, sequence=None, description=""):
        if created and sequence not in (None, ""):
            self.seals.seal(session_id, RESTORE_POINT_STEP, {"sequence": int(sequence)})

        def update(data):
            session = self._session(data, session_id)
            if session is None:
                return False
            protection = session["protection"]
            protection.update({
                "created": bool(created),
                "sequence": int(sequence) if sequence not in (None, "") else None,
                "description": str(description or ""),
                "created_at": utc_now() if created else None,
            })
            session["undo"] = {
                "available": bool(created and sequence is not None),
                "status": "available" if created and sequence is not None else "not_available",
                "requested_at": None,
            }
            return True

        result = self._mutate(update)
        if created and sequence not in (None, ""):
            self._prune_seals()
        return result

    def verified_restore_point(self, session_id):
        """The session's restore-point number, if WinMend itself recorded it.

        None for a session with no checkpoint, and for one whose number does
        not match its seal -- a journal edited to point the rollback at a
        different restore point.
        """
        session = self.get_session(session_id)
        sequence = ((session or {}).get("protection") or {}).get("sequence")
        if sequence is None:
            return None
        try:
            payload = {"sequence": int(sequence)}
        except (TypeError, ValueError):
            return None
        if not self.seals.verify(session_id, RESTORE_POINT_STEP, payload):
            return None
        return payload["sequence"]

    def task_started(self, session_id, task_id):
        def update(data):
            session = self._session(data, session_id)
            if session is None:
                return False
            task = next((t for t in session["tasks"] if t["id"] == task_id), None)
            if task is None:
                return False
            task.update({"state": "running", "started_at": utc_now()})
            return True

        return self._mutate(update)

    def task_finished(self, session_id, task_id, state, duration_seconds=0, error="",
                      undo=None, note=""):
        """Record how one task or targeted repair ended.

        ``undo`` carries the payload a targeted repair needs to reverse itself
        (which registry values it overwrote, where it filed a backup). It is
        stored per task rather than per session because a guided run can make
        several independent changes and the user may want only one of them back.
        It is sealed from this in-memory copy -- never from the file -- and a
        payload that could not be sealed is recorded as "unsealed", which is
        never offered for reversal.
        """
        sealed = bool(undo) and self.seals.seal(session_id, task_id, undo)

        def update(data):
            session = self._session(data, session_id)
            if session is None:
                return False
            task = next((t for t in session["tasks"] if t["id"] == task_id), None)
            if task is None:
                return False
            task.update({
                "state": state,
                "completed_at": utc_now(),
                "duration_seconds": max(0, round(float(duration_seconds), 2)),
                "error": str(error)[:500],
            })
            if note:
                task["note"] = str(note)[:500]
            if undo:
                task["undo_payload"] = undo
                task["undo_state"] = "available" if sealed else "unsealed"
            return True

        result = self._mutate(update)
        if sealed:
            self._prune_seals()
        return result

    def reversible_steps(self, session_id):
        """Steps in this session whose recorded undo payload WinMend can vouch for.

        A payload that does not match its seal -- edited in the file, added to
        it, or recorded before seals existed -- is left out, so it can neither
        be offered nor run.
        """
        session = self.get_session(session_id)
        if not session:
            return []
        return [task for task in session.get("tasks", [])
                if task.get("undo_payload") and task.get("undo_state") == "available"
                and self.seals.verify(session_id, task.get("id"), task["undo_payload"])]

    def set_step_undo_state(self, session_id, task_id, state):
        if state != "available":
            # A reversed step's seal is spent: re-marking it "available" in the
            # file must not make it runnable again.
            self.seals.revoke(session_id, task_id)

        def update(data):
            session = self._session(data, session_id)
            if session is None:
                return False
            task = next((t for t in session["tasks"] if t["id"] == task_id), None)
            if task is None:
                return False
            task["undo_state"] = str(state)
            return True

        return self._mutate(update)

    def complete_session(self, session_id, status, verification=None):
        def update(data):
            session = self._session(data, session_id)
            if session is None:
                return False
            session.update({
                "status": status,
                "completed_at": utc_now(),
                "verification": verification or {},
            })
            # Anything never started was skipped by cancellation or an early error.
            for task in session["tasks"]:
                if task["state"] in ("queued", "running"):
                    task["state"] = "cancelled" if status == "cancelled" else "skipped"
                    task["completed_at"] = utc_now()
            return True

        return self._mutate(update)

    def set_verification(self, session_id, verification):
        """Replace a session's verification -- used by delayed re-checks that run
        after the session closed (for example after the restart a fix needed)."""
        def update(data):
            session = self._session(data, session_id)
            if session is None:
                return False
            session["verification"] = verification or {}
            return True

        return self._mutate(update)

    def mark_undo_requested(self, session_id):
        def update(data):
            session = self._session(data, session_id)
            if session is None:
                return False
            session["undo"].update({"status": "requested", "requested_at": utc_now()})
            return True

        return self._mutate(update)

    def set_undo_status(self, session_id, status):
        def update(data):
            session = self._session(data, session_id)
            if session is None:
                return False
            session["undo"]["status"] = str(status)
            if status == "available":
                session["undo"]["requested_at"] = None
            return True

        return self._mutate(update)
