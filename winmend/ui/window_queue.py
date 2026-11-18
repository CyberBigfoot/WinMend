"""WinMend ui: window queue."""

from __future__ import annotations

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QMessageBox
from winmend.ui.widgets.queue import WMQueueRow
from winmend.data.task_catalog import WM_TASKS
import html as _html
import queue
import subprocess
import time


class WindowQueueMixin:
    """WMMainWindow methods grouped by responsibility."""

    # ---- queue drain ----

    def _drain_queue(self):
        T = self.T
        for _ in range(60):  # bounded so the UI never stalls on a chatty task
            try:
                msg = self.host.queue.get_nowait()
            except queue.Empty:
                return
            if not isinstance(msg, str):
                continue
            if msg.startswith("TASKSTART:"):
                _, tid, title = msg.split(":", 2)
                self.running_task = (tid, title)
                self.run_started = time.time()
                self.pending = [t for t in self.pending if t.id != tid]
                self._log(f"▶ {title}", T['accent'])
                self._rebuild_queue()
            elif msg.startswith("TASKEND:"):
                _, tid, state = msg.split(":", 2)
                is_running = bool(self.running_task and self.running_task[0] == tid)
                task = next((t for t in self.pending if t.id == tid), None)
                if task is None:
                    task = next((t for t in WM_TASKS if t.id == tid), None)
                title = (self.running_task[1] if is_running else
                         task.display_title(self.simple) if task else tid)
                took = int(time.time() - (self.run_started or time.time())) if is_running else 0
                self.pending = [t for t in self.pending if t.id != tid]
                self.finished.append((title, state, took))
                if is_running:
                    self.running_task = None
                word = {"done": "Completed", "fail": "Failed", "skip": "Skipped",
                        "cancel": "Stopped"}.get(state, state)
                self._log(f"{word}: {title} ({took // 60}m {took % 60}s)",
                          T['ok'] if state == "done" else
                          T['danger'] if state == "fail" else T['text_3'])
                self._rebuild_queue()
            elif msg.startswith("SESSIONDONE:"):
                session_id = msg.split(":", 1)[1]
                session = self.journal.get_session(session_id)
                if self.journal_page is not None:
                    self.journal_page.refresh(select_id=session_id)
                if (self.guided_page is not None and session
                        and session.get("source") == "guided"):
                    self.guided_page.on_session_finished(session)
            elif msg == "ALLDONE::":
                self.run_thread = None
                self.running_task = None
                self.active_session_id = None
                counts = {s: sum(1 for _, state, _ in self.finished if state == s)
                          for s in ("done", "fail", "skip", "cancel")}
                summary = ", ".join(f"{counts[s]} {word}" for s, word in
                                    (("done", "completed"), ("fail", "failed"),
                                     ("skip", "skipped"), ("cancel", "stopped")) if counts[s])
                self._log(f"Run finished: {summary or 'no tasks completed'}.",
                          T['danger'] if counts['fail'] else
                          T['warn'] if counts['cancel'] or counts['skip'] else T['ok'])
                self._rebuild_queue()
                # Auto-clear the checkboxes for the tasks that just ran, so the
                # selection resets for the next batch. A cancelled run keeps its
                # selection so it's easy to retry.
                if not self.host.cancel_event.is_set():
                    self._uncheck_tasks(self._run_task_ids)
                self._run_task_ids = []
                self._update_selection()
                if self.guided_page is not None:
                    self.guided_page._update_run_button()
                if self.journal_page is not None:
                    self.journal_page.refresh()
                # Asked last, so it lands after the queue and log have settled.
                reasons, self._reboot_reasons = self._reboot_reasons, []
                if reasons and not self.host.cancel_event.is_set():
                    self._prompt_recommended_reboot(reasons)
            elif msg.startswith("UNDORESULT:"):
                _, session_id, state, detail = msg.split(":", 3)
                self.undo_thread = None
                if state == "ok":
                    self._log(detail, T['ok'])
                    QMessageBox.information(self, "System Restore", detail)
                else:
                    try:
                        self.journal.set_undo_status(session_id, "available")
                    except Exception:
                        pass
                    self._log(f"Rollback could not start: {detail}", T['danger'])
                    QMessageBox.critical(
                        self, "Rollback could not start",
                        f"Windows did not accept the restore request.\n\n{detail}"
                    )
                self._update_selection()
                if self.journal_page is not None:
                    self.journal_page.refresh(select_id=session_id)
            elif msg.startswith("REBOOTRECOMMEND:"):
                parts = msg.split(":", 2)
                reason = (parts[2] if len(parts) > 2 else "").strip()
                if reason and reason not in self._reboot_reasons:
                    self._reboot_reasons.append(reason)
                self._log(f"\u27f3 Restart recommended \u2014 {reason}", T['warn'])
            elif msg.startswith("PROGRESS:"):
                parts = msg.split(":", 2)
                body = parts[2] if len(parts) > 2 else msg
                col = T['warn'] if "Still working" in body else T['text_2']
                self._log(body.strip(), col)
            elif msg.startswith("LOG:"):
                parts = msg.split(":", 2)
                self._log((parts[2] if len(parts) > 2 else msg).strip(), T['text_2'])
            else:
                self._log(str(msg), T['text_2'])

    def _tick_elapsed(self):
        if self.running_task and self.run_started and self.queue_rows:
            el = int(time.time() - self.run_started)
            for row in self.queue_rows:
                if getattr(row, "_is_running", False):
                    row.detail.setText(
                        f"Running · {el // 60:02d}:{el % 60:02d} elapsed · no time limit")

    def _queued_preview(self):
        """Tasks ticked but not started yet, so the checklist can list them.

        Before this, a selection of twenty tasks was a number on a label and
        nothing else: the only way to see what was actually ticked was to
        scroll every category looking for ticks.
        """
        if self.running_task or self.pending or self.run_thread is not None:
            return []
        if getattr(self, "host", None) is None:
            return []
        return self._selected()

    def _rebuild_queue(self):
        """Redraw the checklist: selected, running, queued, and everything done.

        Nothing is elided. The finished list used to be cut to its last four
        entries, which meant a twenty-task run could not be reviewed at all --
        the record of what had already happened was thrown away while the run
        that produced it was still going.
        """
        T = self.T
        for r in self.queue_rows:
            r.setParent(None)
            r.deleteLater()
        self.queue_rows = []
        selected = self._queued_preview()
        self.q_empty.setVisible(
            not (self.running_task or self.pending or self.finished or selected))

        position = 0  # the stretch at the end of q_box must stay last
        running_row = None
        if self.running_task:
            r = WMQueueRow(self.running_task[1], "run",
                           "Running · 00:00 elapsed · no time limit", T, self.request_stop)
            r._is_running = True
            self.q_box.insertWidget(position, r)
            position += 1
            self.queue_rows.append(r)
            running_row = r
        total_pending = len(self.pending)
        for index, t in enumerate(self.pending, start=1):
            r = WMQueueRow(t.display_title(self.simple), "wait",
                           f"Queued · {index} of {total_pending}", T)
            self.q_box.insertWidget(position, r)
            position += 1
            self.queue_rows.append(r)
        for index, task in enumerate(selected, start=1):
            r = WMQueueRow(task.display_title(self.simple), "wait",
                           f"Selected · {index} of {len(selected)} · not started yet", T)
            self.q_box.insertWidget(position, r)
            position += 1
            self.queue_rows.append(r)
        for title, state, took in self.finished:
            r = WMQueueRow(title, "done" if state == "done" else
                           "fail" if state == "fail" else "cancel",
                           {"done": f"Completed in {took // 60}m {took % 60}s",
                            "fail": "Failed — see log",
                            "skip": "Skipped",
                            "cancel": "Stopped"}.get(state, state), T)
            self.q_box.insertWidget(position, r)
            position += 1
            self.queue_rows.append(r)
        done = len(self.finished)
        parts = []
        if self.running_task:
            parts.append("1 running")
        if self.pending:
            parts.append(f"{len(self.pending)} queued")
        if selected:
            parts.append(f"{len(selected)} selected")
        if done:
            parts.append(f"{done} done")
        self.q_count.setText(" · ".join(parts) if parts else "idle")
        if running_row is not None:
            QTimer.singleShot(0, lambda: self._reveal_queue_row(running_row))

    def _reveal_queue_row(self, row):
        """Scroll the running step into view, if it is still the running step.

        A second rebuild can land between the timer being armed and it firing,
        which leaves this holding a row whose C++ side is already gone.
        """
        try:
            self.q_scroll.ensureWidgetVisible(row)
        except RuntimeError:
            pass

    def _log(self, text, color=None):
        """Append one line to the session log, keeping everything before it."""
        T = self.T
        bar = self.log_view.verticalScrollBar()
        follow = bar.value() >= bar.maximum() - 4  # don't yank a user who scrolled back
        line = (f"<span style='color:{T['text_3']}'>{time.strftime('%H:%M:%S')}</span>"
                f"&nbsp;&nbsp;&nbsp;<span style='color:{color or T['text_2']}'>"
                f"{_html.escape(str(text))}</span>")
        self.log_view.append(line)
        if follow:
            QTimer.singleShot(0, bar, lambda: bar.setValue(bar.maximum()))

    def _prompt_recommended_reboot(self, reasons):
        """End-of-run dialog for changes that only fully land after a restart.

        Nothing restarts on its own here: the task that raised this has already
        finished and written its settings. 'Restart now' uses the same 60-second
        countdown as the Restart Windows task, so open work can still be saved
        and 'shutdown /a' still cancels it.
        """
        T = self.T
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Information)
        box.setWindowTitle("Restart recommended")
        box.setText("Restart to finish applying these changes")
        box.setInformativeText(
            "\n".join(f"\u2022  {r}" for r in reasons)
            + "\n\nThe settings are saved already. Until you restart, Windows keeps "
              "the affected services and the memory they were using loaded, so you "
              "will not see the full effect yet.\n\n"
              "Restarting now gives you a 60-second countdown \u2014 long enough to "
              "save open work \u2014 and 'shutdown /a' cancels it."
        )
        restart_now = box.addButton("Restart now", QMessageBox.AcceptRole)
        later = box.addButton("Restart later", QMessageBox.RejectRole)
        box.setDefaultButton(later)
        box.exec()
        if box.clickedButton() is not restart_now:
            self._log("Restart postponed \u2014 the changes finish applying on your "
                      "next restart.", T['warn'])
            return
        try:
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            result = subprocess.run(
                ["shutdown", "/r", "/t", "60",
                 "/c", "WinMend: restarting to finish applying your changes."],
                capture_output=True, text=True, creationflags=flags)
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "").strip() or \
                    f"exit code {result.returncode}"
                self._log(f"Windows refused the restart request: {detail}", T['danger'])
                QMessageBox.critical(
                    self, "Restart could not be scheduled",
                    f"Windows did not accept the restart request.\n\n{detail}")
                return
            self._log("Restarting in 60 seconds \u2014 run 'shutdown /a' in a command "
                      "prompt to cancel.", T['warn'])
        except Exception as exc:
            self._log(f"Restart could not be scheduled: {exc}", T['danger'])

    def _open_system_restore(self):
        if self.run_thread is not None or self.undo_thread is not None:
            QMessageBox.information(
                self, "WinMend is busy",
                "Wait for the current operation to finish before opening System Restore."
            )
            return
        try:
            subprocess.Popen(
                ["rstrui.exe"], creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
            self._log("Opened Windows System Restore.", self.T['text_2'])
        except Exception as exc:
            QMessageBox.critical(self, "System Restore", f"Could not open System Restore: {exc}")
