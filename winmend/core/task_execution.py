"""WinMend core: task execution."""

from __future__ import annotations

from winmend.core.processes import (
    WM_STALL_NOTICE_SECS,
    _no_console_startupinfo,
    wm_kill_tree,
    wm_run,
    wm_track_child,
    wm_untrack_child,
)
import ctypes
import os
import queue
import subprocess
import threading
import time
import winreg


class TaskExecutionTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    # ── Option-name search & highlight ──


    def is_admin(self):
        try:
            result = ctypes.windll.shell32.IsUserAnAdmin()
            return result
        except Exception as e:
            return False

    # ---- live command runner --------------------------------------------------

    def _report_failure(self, message):
        """Log a failure line and mark the running task as failed.

        Most task bodies catch their own errors so that one bad step cannot take
        the rest of a batch down with it. But an error that is only logged gives
        the runner nothing to go on: the task was drawn as a green "Completed"
        and journaled as done. This records the first failure of the run -- the
        message is the same queue line the task would have logged -- and the
        runner reads it when the handler returns.
        """
        self.queue.put(message)
        if getattr(self, "_task_failure", None) is None:
            text = str(message)
            if text.startswith("PROGRESS:") and text.count(":") >= 2:
                text = text.split(":", 2)[2]
            self._task_failure = text.strip() or "The task reported a failure."

    def _report_skip(self, message):
        """Report an option that was declined or had nothing applicable to do."""
        self.queue.put(message)
        text = str(message).split(":", 2)[-1].strip()
        self._task_skip = text or "No action was taken."

    @staticmethod
    def _is_progress_noise(line):
        """True for a frame a console tool redraws in place.

        A spinner, or a progress bar drawn in block characters, arrives as one
        line per frame once the carriage return between frames is read as a
        line break -- hundreds of them for one winget download, burying the
        lines that say what actually happened.
        """
        text = line.strip()
        if not text or set(text) <= set("-\\|/"):
            return True
        bar = text.rstrip("0123456789.,%KMGiB /")
        return bool(bar) and all(ch == " " or "▀" <= ch <= "▟" for ch in bar)

    def _run_live_command(self, cmd, task_label, timeout=None, encoding=None,
                          answers=None, output=None):
        """Stream a command's output to the activity log. NO time limit.

        The process runs to completion however long it takes -- a chkdsk on a
        failing drive or a DISM on a mangled image can legitimately run for
        hours, and killing it mid-repair is worse than waiting.

        timeout= is accepted and ignored so the ~51 legacy call sites that still
        pass it keep working. Nothing here kills a process for being slow.

        Both pipes are drained by reader threads feeding a queue, and the main
        loop polls that queue. That matters: the previous implementation called
        readline() directly in the loop, which blocks -- so on a process that
        hung *silently* the loop never iterated again, and neither the timeout
        nor the Cancel button could ever fire. Cancel now works even when the
        process has gone completely quiet.

        Returns: (return_code, was_timeout). was_timeout is always False and is
        retained only so existing `rc, timed_out = ...` call sites still unpack.

        encoding  how the tool writes when its output is piped. The default (the
                  console code page) suits most; sfc writes UTF-16, which read
                  any other way arrives as every letter followed by a NUL.
        answers   text typed into the tool's stdin, for a tool that stops to ask
                  (chkdsk's "check at the next restart? (Y/N)"). Without it the
                  tool gets an empty stdin, so a question reads end-of-file
                  instead of waiting forever for an answer nobody can see.
        output    a list that receives every line, for callers that judge the
                  result from what the tool said rather than its exit code.
        """
        if getattr(self, 'cancel_event', None) is not None and self.cancel_event.is_set():
            self.queue.put(f"PROGRESS:{task_label}:Cancelled before starting the command.")
            return -1, False
        # Do not log arguments: these can contain a product key, credentials,
        # or an entire PowerShell script. The executable and exit status remain
        # useful even for tools which produce no console output.
        executable = os.path.basename(cmd[0]) if isinstance(cmd, (list, tuple)) else "command"
        self.queue.put(f"PROGRESS:{task_label}:Running {executable}...")
        try:
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE if answers is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True, encoding=encoding, errors="replace",
                startupinfo=_no_console_startupinfo()
            )
        except Exception as e:
            self.queue.put(f"PROGRESS:{task_label}:Error running command: {str(e)}")
            return -1, False

        wm_track_child(process)
        try:
            if answers is not None:
                try:
                    process.stdin.write(answers)
                    process.stdin.close()
                except OSError:
                    pass  # the tool exited without asking; nothing to answer

            lines_q = queue.Queue()

            def _pump(stream, tag):
                try:
                    for line in iter(stream.readline, ''):
                        lines_q.put((tag, line.rstrip('\r\n')))
                except Exception as exc:
                    lines_q.put(('read_error', str(exc)))
                finally:
                    stream.close()
                    lines_q.put((tag, None))  # EOF marker

            for stream, tag in ((process.stdout, 'out'), (process.stderr, 'err')):
                threading.Thread(target=_pump, args=(stream, tag), daemon=True).start()

            open_pipes = 2
            last_output = time.time()
            stall_notified = False

            while open_pipes or process.poll() is None:
                try:
                    tag, line = lines_q.get(timeout=0.25)
                    if line is None:
                        open_pipes -= 1
                        continue
                    last_output = time.time()
                    stall_notified = False
                    if tag == 'read_error':
                        self._report_failure(f"PROGRESS:{task_label}:Could not read command output: {line}")
                        continue
                    if not self._is_progress_noise(line):
                        if output is not None:
                            output.append(line.strip())
                        # Lines a script prints for its caller to read
                        # (WM_APPLIED, WM_FAIL|...) are data, not log text.
                        if line.strip().startswith("WM_"):
                            continue
                        prefix = "  [stderr] " if tag == 'err' else "  "
                        self.queue.put(f"PROGRESS:{task_label}:{prefix}{line.strip()}")
                except queue.Empty:
                    pass

                if getattr(self, 'cancel_event', None) is not None and self.cancel_event.is_set():
                    wm_kill_tree(process)
                    self.queue.put(
                        f"PROGRESS:{task_label}:Cancelled by user — subprocess terminated.")
                    return -1, False

                # Advisory only. Report the silence; never act on it.
                quiet = time.time() - last_output
                if not stall_notified and quiet > WM_STALL_NOTICE_SECS:
                    stall_notified = True
                    self.queue.put(
                        f"PROGRESS:{task_label}:  Still working — no output for "
                        f"{int(quiet // 60)} min. This is normal on slower PCs; "
                        f"nothing will be cut off. Press Stop to cancel.")

            process.wait()
            self.queue.put(f"PROGRESS:{task_label}:{executable} exited with code {process.returncode}.")
            return process.returncode, False

        except Exception as e:
            self.queue.put(f"PROGRESS:{task_label}:Error running command: {str(e)}")
            return -1, False
        finally:
            wm_untrack_child(process)

    def _download(self, url, path):
        """Fetch `url` to `path`, checking Stop between chunks.

        The socket timeout bounds one silent read, not the download: a stalled
        connection used to hang the task with no way to stop it, while a slow
        but moving one still completes however long it takes.
        """
        import urllib.request
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
        got = 0
        try:
            with urllib.request.urlopen(req, timeout=60) as response, open(path, 'wb') as out:
                total = int(response.headers.get("Content-Length") or 0)
                while True:
                    if self.cancel_event.is_set():
                        raise RuntimeError("download stopped")
                    chunk = response.read(1 << 16)
                    if not chunk:
                        break
                    out.write(chunk)
                    got += len(chunk)
            if total and got < total:
                raise RuntimeError(f"download incomplete ({got:,} of {total:,} bytes)")
        except Exception:
            try:
                os.remove(path)
            except OSError:
                pass
            raise
        return got

    def _call_on_ui_thread(self, func, *args, **kwargs):
        """Run a callable on Tk's UI thread and return its result."""
        if threading.get_ident() == getattr(self, "_ui_thread_id", None):
            return func(*args, **kwargs)

        done = threading.Event()
        result = {"value": None, "error": None}

        def _invoke():
            try:
                result["value"] = func(*args, **kwargs)
            except Exception as exc:
                result["error"] = exc
            finally:
                done.set()

        try:
            self.root.after(0, _invoke)
            done.wait()
        except Exception as exc:
            result["error"] = exc

        if result["error"] is not None:
            raise result["error"]
        return result["value"]

    def _get_desktop_dir(self):
        """Real Desktop folder, honoring OneDrive/folder redirection.

        %USERPROFILE%\\Desktop does not exist when OneDrive redirects the Desktop,
        so resolve it from the shell's User Shell Folders registration instead."""
        return self._get_shell_folder("Desktop", "Desktop")

    def _get_documents_dir(self):
        """Real Documents folder, honoring OneDrive/folder redirection."""
        return self._get_shell_folder("Personal", "Documents")

    @staticmethod
    def _get_shell_folder(value_name, default_name):
        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
            ) as key:
                raw = winreg.QueryValueEx(key, value_name)[0]
            path = os.path.expandvars(raw)
            if os.path.isdir(path):
                return path
        except Exception:
            pass
        fallback = os.path.join(os.path.expanduser("~"), default_name)
        if os.path.isdir(fallback):
            return fallback
        return os.path.expanduser("~")

    @staticmethod
    def _is_cloud_synced(path):
        """True when `path` sits inside a OneDrive folder that syncs to the cloud."""
        target = os.path.normcase(os.path.abspath(path or ""))
        for var in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
            root = os.environ.get(var)
            if root:
                root = os.path.normcase(os.path.abspath(root))
                if target == root or target.startswith(root + os.sep):
                    return True
        return False

    def _run_ps(self, script, timeout=90):
        """Run a PowerShell snippet and return the WMCompleted result."""
        return wm_run(
            ['powershell', '-NoProfile', '-ExecutionPolicy', 'RemoteSigned',
             '-Command', script],
            capture_output=True, text=True, encoding='utf-8', errors='replace',
            cancel_event=self.cancel_event,
            timeout=timeout, startupinfo=_no_console_startupinfo()
        )
