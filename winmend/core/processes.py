"""WinMend core: processes."""

from __future__ import annotations

import subprocess
import threading
import time


# Helper: build a STARTUPINFO that hides the console window.
# This is the standard Windows-API approach for GUI applications and avoids
# the raw CREATE_NO_WINDOW flag that AV heuristics associate with malware.
#
# For CONSOLE programs only. SW_HIDE is not specific to consoles: Windows applies
# a STARTUPINFO's wShowWindow to the first window any program shows, so a GUI
# tool started with this (perfmon, mdsched, Outlook, Office's repair) runs with
# its window hidden and looks as if it never opened. A program the user is meant
# to see goes through launch_visible(), or wm_run(..., visible=True).
def _no_console_startupinfo():
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0  # SW_HIDE
    return si


def launch_visible(argv, **kw):
    """Start a program the user is meant to see and work in; returns its Popen.

    No show-state is passed, so the program opens its window the way it does
    when started from Explorer. Any startupinfo= is dropped: that is the very
    thing that hid these windows (see _no_console_startupinfo).
    """
    kw.pop("startupinfo", None)
    return subprocess.Popen(argv, **kw)


# ============================================================================
# ==================== PROCESS RUNNER — NO TIME LIMITS =======================
# ============================================================================
# WinMend runs scans that legitimately take hours on slow or failing hardware:
# chkdsk on a dying 5400rpm drive, DISM on a badly serviced image, a Defender
# full scan on a 4TB spindle. A fixed timeout on any of those is a bug -- it
# reports failure for work that was progressing fine.
#
# So nothing here kills a process for taking too long. Ever.
#
# The catch: subprocess.run() blocks uninterruptibly. Simply deleting timeout=
# would mean a genuinely hung process could never be stopped and the Cancel
# button would do nothing. So the no-limit guarantee is paired with a runner
# that stays cancellable for as long as it takes:
#
#   * no time limit       -- the process runs until it finishes
#   * always cancellable  -- Cancel kills the whole process tree, promptly
#   * stall reporting     -- silence is *reported*, never acted on
#
# WM_STALL_NOTICE_SECS is a notification threshold, NOT a timeout. Crossing it
# emits a log line and nothing else. The process keeps running.

WM_STALL_NOTICE_SECS = 120


class WMCompleted:
    """subprocess.CompletedProcess work-alike returned by wm_run()."""

    __slots__ = ('args', 'returncode', 'stdout', 'stderr', 'cancelled')

    def __init__(self, args, returncode, stdout=None, stderr=None, cancelled=False):
        self.args = args
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.cancelled = cancelled

    def check_returncode(self):
        if self.returncode:
            raise subprocess.CalledProcessError(
                self.returncode, self.args, self.stdout, self.stderr)


def wm_kill_tree(proc):
    """Kill a process and every child it spawned.

    DISM, SFC and winget all spawn helpers. Killing only the parent orphans
    them and they keep holding locks, so take the whole tree with taskkill /T.
    This is the one place a timeout is legitimate: it bounds the *kill*, not
    the work.
    """
    if proc.poll() is not None:
        return
    try:
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
            capture_output=True, timeout=15,
            startupinfo=_no_console_startupinfo(),
        )
    except Exception:
        pass
    try:
        proc.kill()
    except Exception:
        pass


# Every process a task starts is tracked here until it exits, so that closing
# WinMend mid-task can take it down too. The task threads are daemons: when the
# window closes, Python abandons them where they stand, and whatever they had
# launched -- DISM, SFC, a winget install -- kept running with nobody left to
# report on it, even though the user had just answered "Stop it and quit".
_WM_CHILDREN = set()


_WM_CHILDREN_LOCK = threading.Lock()


def wm_track_child(proc):
    with _WM_CHILDREN_LOCK:
        _WM_CHILDREN.add(proc)
    return proc


def wm_untrack_child(proc):
    with _WM_CHILDREN_LOCK:
        _WM_CHILDREN.discard(proc)


def wm_kill_children():
    """End every tracked process tree that is still running. Returns how many."""
    with _WM_CHILDREN_LOCK:
        live = [p for p in _WM_CHILDREN if p.poll() is None]
        _WM_CHILDREN.clear()
    for proc in live:
        wm_kill_tree(proc)
    return len(live)


def wm_run(cmd, cancel_event=None, on_stall=None, poll=0.25, visible=False, **kw):
    """Drop-in for subprocess.run() with NO time limit and working cancellation.

    Accepts the same kwargs as subprocess.run. A timeout= kwarg is accepted and
    deliberately ignored, so legacy call sites keep working while losing their
    limit -- that is the point.

    on_stall(elapsed_seconds) fires once when the process has been quiet for
    WM_STALL_NOTICE_SECS. It is advisory: it informs the user, and the process
    continues regardless.

    visible=True is for a program with a window the user has to see, such as
    Office's repair: its window is left alone instead of being started hidden.
    """
    kw.pop("timeout", None)  # intentionally dropped -- see section note above

    if kw.pop("capture_output", False):
        kw.setdefault("stdout", subprocess.PIPE)
        kw.setdefault("stderr", subprocess.PIPE)
    check = kw.pop("check", False)
    data = kw.pop("input", None)
    if data is not None:
        kw.setdefault("stdin", subprocess.PIPE)
    else:
        # Nothing to type into the process, so hand it an empty stdin rather
        # than WinMend's own. A console tool that stops to ask a question then
        # reads end-of-file and carries on, instead of waiting forever for an
        # answer nobody can see.
        kw.setdefault("stdin", subprocess.DEVNULL)
    if visible:
        kw.pop("startupinfo", None)
    else:
        kw.setdefault("startupinfo", _no_console_startupinfo())

    proc = wm_track_child(subprocess.Popen(cmd, **kw))
    try:
        # communicate() must run off-thread: it blocks until EOF, and we need to
        # stay responsive to cancel_event for the entire run.
        box = {}

        def _pump():
            try:
                box["out"] = proc.communicate(data)
            except Exception as e:  # surfaced to the caller below
                box["err"] = e

        th = threading.Thread(target=_pump, daemon=True)
        th.start()

        started = time.time()
        stalled = False
        cancelled = False
        while th.is_alive():
            th.join(poll)
            if not th.is_alive():
                break
            if cancel_event is not None and cancel_event.is_set():
                wm_kill_tree(proc)
                cancelled = True
                th.join(10)
                break
            if not stalled and on_stall is not None:
                elapsed = time.time() - started
                if elapsed > WM_STALL_NOTICE_SECS:
                    stalled = True
                    try:
                        on_stall(elapsed)  # advisory only -- nothing is killed
                    except Exception:
                        pass
    finally:
        wm_untrack_child(proc)

    if "err" in box:
        raise box["err"]
    out, err = box.get("out", (None, None))
    rc = proc.poll()
    result = WMCompleted(cmd, -1 if rc is None else rc, out, err, cancelled)
    if check and not cancelled:
        result.check_returncode()
    return result
