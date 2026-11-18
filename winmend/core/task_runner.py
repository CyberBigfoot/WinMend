"""WinMend core: task runner."""

from __future__ import annotations

from winmend.core.prompts import messagebox as WMMessageBox
from winmend.data.task_catalog import WM_HANDLERS
from winmend.diagnostics.reference import AUDIT_PROFILE as WM_AUDIT_PROFILE
from winmend.diagnostics.repairs.catalog import REPAIR_ACTIONS
from winmend.safety.restore_points import wm_find_restore_point
import re
import time


class TaskRunnerMixin:
    """WMMainWindow methods grouped by responsibility."""

    def _run_task_handler(self, task_id, title, emit=None):
        """Use the same reporting contract for manual runs and Guided Fix."""
        if emit is None:
            emit = lambda message: self.host.queue.put(f"PROGRESS:{title}:{message}")
        name = WM_HANDLERS.get(task_id)
        if name is None:
            message = "No handler is wired for this build."
            emit(message)
            return "skip", message
        self.host._task_failure = None
        self.host._task_skip = None
        activity = self.host.queue
        tracked = hasattr(activity, "begin_task")
        if tracked:
            activity.begin_task()
        try:
            getattr(self.host, name)()
        except Exception as exc:
            emit(f"{title}: Failed: {exc}")
            if self.host.cancel_event.is_set():
                return "cancel", "Stopped."
            return "fail", str(exc)
        finally:
            count = activity.end_task() if tracked else None
        if self.host.cancel_event.is_set():
            return "cancel", "Stopped."
        if self.host._task_failure:
            return "fail", self.host._task_failure
        if self.host._task_skip:
            return "skip", self.host._task_skip
        if count == 0:
            message = "No activity details were reported; this option's result could not be confirmed."
            emit(message)
            return "fail", message
        return "done", (f"Reported {count} activity log entries; see the activity log for details."
                        if count is not None else "Completed.")

    def _case_worker(self, steps, session_id, case):
        """Execute plan steps one at a time, measuring between each.

        The early stop is the point of this path: once a step's own checks come
        back clean, the later steps aimed at the same problem are skipped rather
        than run for completeness. A user whose DNS flush fixed the problem
        should not then sit through a 45-minute component repair.

        How much gets skipped depends on what the plan is. A plan built from one
        complaint is a sequence of attempts at a single thing, so the first one
        that works ends the run. A full check's plan is a list of unrelated
        faults that happened to be found together, and there correcting the
        clock says nothing at all about the printer -- so only the remaining
        steps belonging to the same hypothesis are dropped.
        """
        failed = False
        cancelled = False
        stopped_early = None
        verification = {}
        performed = []
        baseline = case.get("findings", [])
        profile = case.get("profile", "general")
        # All plans may contain multiple independent faults, including compound
        # complaints and hardware checks. Clear only the verified hypothesis.
        independent = True
        resolved = set()
        from winmend.diagnostics.eligibility import eligible, repair_identity
        case["verification_targets"] = list(dict.fromkeys(k for s in steps if not s.get("read_only")
                                                          for k in s.get("verify_keys", [])))
        case.setdefault("attempts", [])

        def emit(message):
            self.host.queue.put(f"PROGRESS:Guided repair:{message}")

        try:
            if not self._prepare_protection(steps, session_id):
                cancelled = True
                return

            for position, step in enumerate(steps):
                if self.host.cancel_event.is_set():
                    cancelled = True
                    self.host.queue.put(f"LOG::Stopped before {step['title']}.")
                    break

                if step.get("hypothesis") in resolved:
                    self.host.queue.put(f"TASKEND:{step['id']}:skip")
                    if session_id:
                        try:
                            self.journal.task_finished(
                                session_id, step["id"], "skipped", 0,
                                note="Skipped: an earlier step already resolved this fault.")
                        except Exception:
                            pass
                    continue

                self.host.queue.put(f"TASKSTART:{step['id']}:{step['title']}")
                started = time.time()
                if session_id:
                    try:
                        self.journal.task_started(session_id, step["id"])
                    except Exception:
                        pass

                if not step.get("read_only"):
                    # Revalidate evidence and safety immediately before touching
                    # settings. The planning result is not an execution permit.
                    try:
                        from winmend.diagnostics.eligibility import DISK_MUTATIONS
                        keys = list(dict.fromkeys(step.get("required_evidence", []) + ["system_context"] +
                                                 (["smart", "drive_wear", "smart_detail"] if step["id"] in DISK_MUTATIONS else [])))
                        current = self.case_engine.remeasure(keys, cancel=self.host.cancel_event.is_set)
                        allowed, reason = eligible(step, self.case_engine.measure_findings(current),
                                                   current.get("system_context"), case["attempts"])
                    except Exception as exc:
                        allowed, reason = False, f"Preconditions could not be checked: {exc}"
                    if not allowed:
                        state, message, undo = "skip", reason, None
                        emit(f"{step['title']} withheld: {reason}")
                    else:
                        state, message, undo = self._run_step(step, emit)
                else:
                    state, message, undo = self._run_step(step, emit)
                if state == "fail":
                    failed = True
                self.host.queue.put(f"TASKEND:{step['id']}:{state}")
                if session_id:
                    try:
                        self.journal.task_finished(
                            session_id, step["id"],
                            {"done": "done", "fail": "failed", "skip": "skipped"}.get(state, state),
                            time.time() - started, "" if state != "fail" else message,
                            undo=undo, note=message)
                    except Exception:
                        pass
                performed.append({"id": step["id"], "title": step["title"], "state": state,
                                  "read_only": bool(step.get("read_only")), "result": message})
                if state in ("done", "fail") and not step.get("read_only"):
                    case["attempts"].append({"identity": repair_identity(step), "id": step["id"],
                                             "outcome": "failed" if state == "fail" else "inconclusive"})
                    case["restart_required"] = case.get("restart_required", False) or bool(step.get("reboot") or step.get("needs_restart"))

                if self.host.cancel_event.is_set():
                    cancelled = True
                    break
                if state != "done" or not step.get("stop_if_clear"):
                    continue
                if step.get("reboot") or step.get("needs_restart"):
                    continue
                if position == len(steps) - 1:
                    continue

                emit(f"Re-checking whether that resolved it ({', '.join(step['verify_keys'])})...")
                try:
                    fresh = self.case_engine.remeasure(
                        step["verify_keys"], cancel=self.host.cancel_event.is_set)
                    cleared, checked = self.case_engine.step_cleared(
                        step, fresh, baseline)
                except Exception as exc:
                    emit(f"The re-check could not run: {exc}")
                    continue
                if not cleared:
                    continue
                if case["attempts"] and case["attempts"][-1].get("identity") == repair_identity(step):
                    case["attempts"][-1]["outcome"] = "resolved"

                names = ", ".join(item["label"] for item in checked)
                if independent:
                    # A step can stand for more than one finding. Its verify
                    # keys cover all of them, so a clear result clears all of
                    # them -- and every one has to go into the resolved set or
                    # the later steps for the others get run against a fault
                    # that is already fixed.
                    resolved.add(step.get("hypothesis"))
                    resolved.update(step.get("also_for") or ())
                    later = [s for s in steps[position + 1:]
                             if s.get("hypothesis") in resolved]
                    emit(f"Resolved: {names} now measures healthy."
                         + (f" Skipping {len(later)} further step(s) for this fault; the rest of "
                            f"the check's findings are unrelated and still get their turn."
                            if later else " Moving on to the next finding."))
                    continue

                stopped_early = {
                    "step": step["title"],
                    "checks": names,
                    "skipped": [s["title"] for s in steps[position + 1:]],
                }
                emit(f"Resolved: {names} now measures healthy. "
                     f"Skipping the remaining {len(steps) - position - 1} step(s).")
                for remaining in steps[position + 1:]:
                    self.host.queue.put(f"TASKEND:{remaining['id']}:skip")
                    if session_id:
                        try:
                            self.journal.task_finished(
                                session_id, remaining["id"], "skipped", 0,
                                note="Skipped: the problem cleared at an earlier step.")
                        except Exception:
                            pass
                break
        except Exception as exc:
            failed = True
            emit(f"Unexpected runner error: {exc}")
        finally:
            cancelled = cancelled or self.host.cancel_event.is_set()
            case["repair_status"] = ("cancelled" if cancelled else "failed" if failed else "complete" if any(
                p["state"] == "done" and not p.get("read_only") for p in performed) else "not_applied")
            if not cancelled:
                emit("Repeating the full read-only checks to measure the result...")
                try:
                    after = self.case_engine.build_case(
                        case.get("problem", ""), answers=case.get("answers"),
                        profile=profile, task_lookup=self.wm_task_lookup,
                        history=[{"attempts": case["attempts"]}])
                    verification = self.diagnostic_engine.compare(case, after)
                    for attempt in case["attempts"]:
                        if attempt["outcome"] == "inconclusive":
                            attempt["outcome"] = verification.get("condition_outcome", "inconclusive")
                    after["attempts"] = list(case["attempts"])
                    if stopped_early:
                        verification["stopped_early"] = stopped_early
                    emit(verification.get("summary", "Verification complete."))
                except Exception as exc:
                    verification = {
                        "outcome": "unavailable",
                        "summary": f"The repair finished, but verification could not complete: {exc}",
                    }
                    emit(verification["summary"])
            else:
                # A cancelled run has no verification. Saying so explicitly stops
                # the journal and the page reading an empty dict as success.
                verification = {
                    "outcome": "cancelled",
                    "summary": "The run was stopped, so the result was not measured.",
                }
            verification["performed"] = performed
            verification["repair_status"] = case["repair_status"]
            verification["attempts"] = list(case.get("attempts", []))
            status = "cancelled" if cancelled else "failed" if failed else "complete"
            if session_id:
                try:
                    self.journal.complete_session(session_id, status, verification)
                except Exception as exc:
                    emit(f"Could not finalize the session: {exc}")
                self.host.queue.put(f"SESSIONDONE:{session_id}")
            self.host.queue.put("ALLDONE::")

    def _prepare_protection(self, steps, session_id):
        """Create the session restore point. False means the user cancelled."""
        wants = [s for s in steps if s.get("restore_point")
                 and (self.host.admin_status or not s.get("admin"))]
        if not wants:
            return True
        reason = f"Safety session {session_id[:8]}" if session_id else "Safety session"
        safe_reason = re.sub(r'[^a-zA-Z0-9 _-]', '', reason)[:42]
        description = f"EAWTECH Guardrail - {safe_reason}"
        try:
            created = bool(self.host._create_restore_point_guardrail(reason))
        except Exception as exc:
            created = False
            self.host.queue.put(
                f"PROGRESS:Guardrail:Could not create the session restore point ({exc}).")
        point = None
        if created:
            for delay in (1.5, 2.0):
                time.sleep(delay)
                point = wm_find_restore_point(description)
                if point:
                    break
        if session_id:
            try:
                self.journal.set_protection(
                    session_id, created,
                    sequence=(point or {}).get("sequence"),
                    description=(point or {}).get("description", description if created else ""))
            except Exception as exc:
                self.host.queue.put(f"PROGRESS:Safety Journal:Could not record protection: {exc}")
        if created and point:
            self.host.queue.put(
                f"PROGRESS:Guardrail:Session protected by restore point #{point['sequence']}.")
            return True
        if any(s.get("recovery_required") for s in wants):
            self.host.queue.put("PROGRESS:Guardrail:Required recovery checkpoint could not be verified. Protected repairs were withheld.")
            return False
        if created:
            self.host.queue.put(
                "PROGRESS:Guardrail:The checkpoint was created, but Windows did not return its "
                "exact sequence number. It remains available in System Restore.")
            return True
        proceed = WMMessageBox.askyesno(
            "Protection unavailable",
            "Windows could not create the requested System Restore checkpoint.\n\n"
            "This plan includes steps that remove a driver or an update. Without a "
            "checkpoint there is no one-click way back.\n\n"
            "Continue without the checkpoint?",
        )
        if not proceed:
            self.host.queue.put(
                "LOG::Protected run cancelled because a restore point was unavailable.")
        return bool(proceed)

    def _run_step(self, step, emit):
        """Run one plan step. Returns (state, message, undo payload)."""
        if step.get("admin") and not self.host.admin_status:
            message = "Needs administrator rights. Restart WinMend as administrator."
            emit(f"{step['title']}: {message}")
            return "skip", message, None

        if step["kind"] == "action":
            action = REPAIR_ACTIONS.get(step["id"])
            if action is None:
                return "skip", "No handler is wired for this repair.", None
            result = action.run(step.get("params"), emit)
            step["needs_restart"] = bool(result.get("needs_restart"))
            emit(f"{step['title']}: {result['message']}")
            if result.get("needs_restart"):
                emit("This change takes full effect after a restart.")
            return ("done" if result["ok"] else "fail"), result["message"], result.get("undo")

        state, message = self._run_task_handler(step["id"], step["title"], emit)
        return state, message, None

    def _worker(self, tasks, session_id=None, workflow=None):
        """Run one journaled session and verify a guided repair afterward."""
        failed = False
        cancelled = False
        verification = {}
        try:
            # One checkpoint represents the entire run. This makes the undo target
            # unambiguous and avoids asking Windows to create a point for each task.
            protected = [
                task for task in tasks
                if task.restore_point and (self.host.admin_status or not task.admin)
            ]
            if protected:
                reason = f"Safety session {session_id[:8]}" if session_id else "Safety session"
                safe_reason = re.sub(r'[^a-zA-Z0-9 _-]', '', reason)[:42]
                description = f"EAWTECH Guardrail - {safe_reason}"
                try:
                    created = bool(self.host._create_restore_point_guardrail(reason))
                except Exception as exc:
                    created = False
                    self.host.queue.put(
                        f"PROGRESS:Guardrail:Could not create the session restore point ({exc})."
                    )
                point = None
                if created:
                    # WMI may report that creation was accepted before the point
                    # appears in Get-ComputerRestorePoint, so allow two bounded
                    # discovery attempts before falling back to the restore browser.
                    for delay in (1.5, 2.0):
                        time.sleep(delay)
                        point = wm_find_restore_point(description)
                        if point:
                            break
                if session_id:
                    try:
                        self.journal.set_protection(
                            session_id, created,
                            sequence=(point or {}).get("sequence"),
                            description=(point or {}).get("description", description if created else ""),
                        )
                    except Exception as exc:
                        self.host.queue.put(f"PROGRESS:Safety Journal:Could not record protection: {exc}")
                if created and point:
                    self.host.queue.put(
                        f"PROGRESS:Guardrail:Session protected by restore point #{point['sequence']}."
                    )
                elif created:
                    self.host.queue.put(
                        "PROGRESS:Guardrail:The checkpoint was created, but Windows did not return its exact "
                        "sequence number. It remains available in System Restore."
                    )
                else:
                    proceed = WMMessageBox.askyesno(
                        "Protection unavailable",
                        "Windows could not create the requested System Restore checkpoint.\n\n"
                        "The planned settings changes will not have a session-level rollback point. "
                        "File cleanup is never recoverable through System Restore.\n\n"
                        "Continue without the checkpoint?",
                    )
                    if not proceed:
                        cancelled = True
                        self.host.queue.put(
                            "LOG::Protected run cancelled because a restore point was unavailable."
                        )
                        return

            for task in tasks:
                if self.host.cancel_event.is_set():
                    cancelled = True
                    self.host.queue.put(f"LOG::Stopped before {task.title}.")
                    break

                self.host.queue.put(
                    f"TASKSTART:{task.id}:{task.display_title(self.simple)}"
                )
                started = time.time()
                if session_id:
                    try:
                        self.journal.task_started(session_id, task.id)
                    except Exception:
                        pass

                if task.admin and not self.host.admin_status:
                    message = "Administrator rights required."
                    self.host.queue.put(
                        f"PROGRESS:{task.title}:Needs administrator rights. Restart WinMend "
                        "as administrator to run this one."
                    )
                    self.host.queue.put(f"TASKEND:{task.id}:skip")
                    if session_id:
                        try:
                            self.journal.task_finished(
                                session_id, task.id, "skipped", time.time() - started, message
                            )
                        except Exception:
                            pass
                    continue

                handler_name = WM_HANDLERS.get(task.id)
                if handler_name is None:
                    message = "No handler is wired for this build."
                    self.host.queue.put(f"PROGRESS:{task.title}:{message}")
                    self.host.queue.put(f"TASKEND:{task.id}:skip")
                    if session_id:
                        try:
                            self.journal.task_finished(
                                session_id, task.id, "skipped", time.time() - started, message
                            )
                        except Exception:
                            pass
                    continue

                try:
                    state, message = self._run_task_handler(task.id, task.title)
                    stopped = state == "cancel"
                    failure = message if state == "fail" else None
                    self.host.queue.put(f"TASKEND:{task.id}:{state}")
                    if stopped:
                        cancelled = True
                    if failure:
                        failed = True
                    if session_id:
                        try:
                            self.journal.task_finished(
                                session_id, task.id,
                                {"cancel": "cancelled", "fail": "failed",
                                 "skip": "skipped", "done": "done"}[state],
                                time.time() - started, failure or "",
                                note=(message if state == "done" else ""),
                            )
                        except Exception:
                            pass
                except Exception as exc:
                    failed = True
                    self.host.queue.put(f"PROGRESS:{task.title}:Failed: {exc}")
                    self.host.queue.put(f"TASKEND:{task.id}:fail")
                    if session_id:
                        try:
                            self.journal.task_finished(
                                session_id, task.id, "failed", time.time() - started, str(exc)
                            )
                        except Exception:
                            pass
        except Exception as exc:
            failed = True
            self.host.queue.put(f"PROGRESS:Safety session:Unexpected runner error: {exc}")
        finally:
            cancelled = cancelled or self.host.cancel_event.is_set()
            if workflow and not cancelled:
                self.host.queue.put(
                    "PROGRESS:Verification:Repeating the original read-only checks to measure the result..."
                )
                try:
                    after = self.diagnostic_engine.diagnose(
                        workflow.get("problem", ""), profile=workflow.get("profile")
                    )
                    verification = self.diagnostic_engine.compare(
                        workflow.get("diagnosis", {}), after
                    )
                    self.host.queue.put(
                        f"PROGRESS:Verification:{verification.get('summary', 'Verification complete.')}"
                    )
                except Exception as exc:
                    verification = {
                        "outcome": "unavailable",
                        "summary": f"The repair run finished, but verification could not complete: {exc}",
                    }
                    self.host.queue.put(f"PROGRESS:Verification:{verification['summary']}")

            status = "cancelled" if cancelled else "failed" if failed else "complete"
            if session_id:
                try:
                    self.journal.complete_session(session_id, status, verification)
                except Exception as exc:
                    self.host.queue.put(
                        f"PROGRESS:Safety Journal:Could not finalize the session: {exc}"
                    )
                self.host.queue.put(f"SESSIONDONE:{session_id}")
            self.host.queue.put("ALLDONE::")
