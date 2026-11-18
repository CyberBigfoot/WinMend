"""WinMend features: cleanup helpers."""

from __future__ import annotations

import shutil
import time
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


# ============================================================================
# Deep Disk Cleanup: cleanmgr staging, activity measurement, stuck prompts
# ============================================================================
#
# `cleanmgr /sagerun:N` is one opaque process. With every handler enabled it can
# legitimately run for 40 minutes (Windows Update Cleanup walks the entire
# component store) and it reports nothing while it does -- which is how "hung
# at 95%" happens: the bar had nowhere left to go and no way to tell slow from
# stuck. It can also genuinely stall: a handler that raises a message box
# behind other windows waits forever for a click.
#
# The pieces here let the task run the handlers in stages (each its own sage
# profile, so the log can say which part is slow), measure whether cleanmgr or
# anything it waits on is *doing* work -- CPU time, I/O operations, free space
# -- rather than guessing from the clock, and find a prompt it may be sitting
# behind.

VOLUME_CACHES_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"


# Handlers Deep Disk Cleanup never enables. Windows' own Disk Cleanup leaves
# each of these unticked: ticking them deletes personal files or a recovery
# option, not junk. The Recycle Bin is emptied by the task itself *after*
# cleanmgr, where a corrupted bin (which raises a modal "empty it?" prompt)
# cannot stall the run.
CLEANMGR_EXCLUDED = {
    "DownloadsFolder": "your Downloads folder holds personal files, not junk",
    "Windows ESD installation files": "'Reset this PC' needs them",
    "User file versions": "these are File History backups",
    "Recycle Bin": "emptied separately after cleanmgr, where a corrupted bin cannot stall the run",
}


# Profile 1 is what every "cleanmgr /sagerun:1" example on the internet uses and
# what earlier WinMend versions wrote to. The stages use their own range and
# leave 1 to whoever else configures it.
CLEANMGR_LEGACY_PROFILE = 1


# key, sage profile, title, handlers (None = everything not placed elsewhere),
# advisory shown when the stage starts.
CLEANMGR_STAGES = (
    ("quick", 61, "Temporary files, caches, logs and error reports", None, ""),
    ("delivery", 62, "Delivery Optimization cache and superseded driver packages",
     ("Delivery Optimization Files", "Device Driver Packages"), ""),
    ("updates", 63, "Windows Update Cleanup", ("Update Cleanup",),
     "This is the slow one. It walks the whole component store, and 10-40 minutes is "
     "normal on a PC that has never run it. Free space is re-read every 30 seconds so "
     "you can see it working."),
    ("previous", 64, "Previous Windows installation and upgrade leftovers",
     ("Previous Installations", "Upgrade Discarded Files"), ""),
)


# Processes whose CPU time and I/O count as "cleanmgr is working". cleanmgr
# blocks on Windows servicing (TiWorker/TrustedInstaller) for Update Cleanup and
# on DismHost for component-store work, so their activity is its activity.
CLEANMGR_WORKER_NAMES = ("cleanmgr.exe", "tiworker.exe", "trustedinstaller.exe",
                         "dismhost.exe", "mpcmdrun.exe")


# Services a stage hands work to that live inside a shared svchost; their host
# process joins the activity set for that stage only.
CLEANMGR_STAGE_SERVICES = {"delivery": ("DoSvc", "PlugPlay")}


def cleanmgr_profile_value(profile):
    """The VolumeCaches value name for a sage profile: 61 -> 'StateFlags0061'."""
    return "StateFlags%04d" % int(profile)


def plan_cleanmgr_stages(handlers, stages=CLEANMGR_STAGES, excluded=CLEANMGR_EXCLUDED):
    """Assign every VolumeCaches handler to a stage.

    Explicit stages take their named handlers (matched case-insensitively, so a
    Windows build that recases one still lands in the right place); the
    catch-all stage takes everything else that is not excluded; stages with
    nothing to do are dropped. Returns (stages, excluded_present) where stages
    is a list of {key, profile, title, handlers, note} in run order.
    """
    lower_excluded = {name.lower(): why for name, why in excluded.items()}
    present = list(handlers)
    remaining = [h for h in present if h.lower() not in lower_excluded]
    excluded_present = [h for h in present if h.lower() in lower_excluded]

    plan = []
    catch_all_index = None
    for key, profile, title, names, note in stages:
        entry = {"key": key, "profile": int(profile), "title": title,
                 "handlers": [], "note": note}
        if names is None:
            catch_all_index = len(plan)
            plan.append(entry)
            continue
        wanted = {n.lower() for n in names}
        entry["handlers"] = [h for h in remaining if h.lower() in wanted]
        remaining = [h for h in remaining if h.lower() not in wanted]
        plan.append(entry)
    if catch_all_index is not None:
        plan[catch_all_index]["handlers"] = list(remaining)
    return [s for s in plan if s["handlers"]], excluded_present


def configure_cleanmgr_profile(profile, enabled, handlers, key=VOLUME_CACHES_KEY, hive=None):
    """Write one sage profile exactly: StateFlagsNNNN = 2 for `enabled`, 0 for
    every other handler. Returns (written, failures) where failures is a list
    of (handler, error)."""
    if winreg is None:
        return [], [("registry", "unavailable")]
    hive = winreg.HKEY_LOCAL_MACHINE if hive is None else hive
    value = cleanmgr_profile_value(profile)
    wanted = {h.lower() for h in enabled}
    written, failures = [], []
    for handler in handlers:
        flag = 2 if handler.lower() in wanted else 0
        try:
            with winreg.OpenKey(hive, rf"{key}\{handler}", 0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, value, 0, winreg.REG_DWORD, flag)
            written.append(handler)
        except OSError as exc:
            failures.append((handler, str(exc)))
    return written, failures


def disarm_legacy_profile(handlers, profile=CLEANMGR_LEGACY_PROFILE,
                          excluded=CLEANMGR_EXCLUDED, key=VOLUME_CACHES_KEY, hive=None):
    """Earlier WinMend versions enabled *every* handler in profile 1 -- the
    Downloads folder included. Turn the excluded ones off there, so a later
    'cleanmgr /sagerun:1' from any tool cannot delete them. Returns the handler
    names that were armed and are now off."""
    if winreg is None:
        return []
    hive = winreg.HKEY_LOCAL_MACHINE if hive is None else hive
    value = cleanmgr_profile_value(profile)
    lower_excluded = {name.lower() for name in excluded}
    disarmed = []
    for handler in handlers:
        if handler.lower() not in lower_excluded:
            continue
        try:
            with winreg.OpenKey(hive, rf"{key}\{handler}", 0,
                                winreg.KEY_READ | winreg.KEY_SET_VALUE) as k:
                try:
                    current = winreg.QueryValueEx(k, value)[0]
                except FileNotFoundError:
                    continue
                if current == 2:
                    winreg.SetValueEx(k, value, 0, winreg.REG_DWORD, 0)
                    disarmed.append(handler)
        except OSError:
            continue
    return disarmed


def service_pids(names):
    """Host process ids of the named Windows services (empty for any that are
    stopped or unknown)."""
    pids = set()
    try:
        import psutil
    except ImportError:
        return pids
    for name in names:
        try:
            pid = psutil.win_service_get(name).pid()
        except Exception:
            pid = None
        if pid:
            pids.add(int(pid))
    return pids


def processes_named(names):
    """psutil.Process objects whose image name is in `names` (case-insensitive)."""
    try:
        import psutil
    except ImportError:
        return []
    wanted = {n.lower() for n in names}
    found = []
    for proc in psutil.process_iter(["name"]):
        try:
            if (proc.info.get("name") or "").lower() in wanted:
                found.append(proc)
        except Exception:
            continue
    return found


def cleanmgr_activity_signature(drive, extra_pids=(), names=CLEANMGR_WORKER_NAMES):
    """A value that changes whenever cleanmgr, or anything it waits on, does
    any work at all: summed CPU seconds, summed I/O operations (reads, writes
    and metadata ops), and free bytes on `drive`.

    Equal signatures across a long window mean *nothing* is happening -- not
    "quiet", nothing -- which is the difference between a slow handler and a
    process blocked on a prompt or a dead RPC. A process that is merely slow
    still accrues CPU ticks and directory-walk I/O every few seconds.
    """
    cpu = 0.0
    ops = 0
    try:
        import psutil
        wanted = {n.lower() for n in names}
        extra = set(int(p) for p in extra_pids)
        for proc in psutil.process_iter(["name", "pid"]):
            try:
                if (proc.info.get("name") or "").lower() not in wanted and proc.pid not in extra:
                    continue
                times = proc.cpu_times()
                cpu += times.user + times.system
                io = proc.io_counters()
                ops += io.read_count + io.write_count + io.other_count
            except Exception:
                continue
    except ImportError:
        pass
    try:
        free = shutil.disk_usage(drive).free
    except OSError:
        free = -1
    return (round(cpu, 3), ops, free)


class IdleWatch:
    """How long has a signature gone unchanged? Feed it every poll; it answers
    in seconds since the value last moved."""

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._last = None
        self._since = None

    def update(self, signature):
        now = self._clock()
        if self._since is None or signature != self._last:
            self._last = signature
            self._since = now
        return now - self._since

    @property
    def idle_seconds(self):
        if self._since is None:
            return 0.0
        return self._clock() - self._since


def format_bytes_freed(delta):
    """'1.2 GB' / '340 MB' / 'no change' for a free-space delta."""
    if delta is None or delta < 1024 * 1024:
        return "no change"
    if delta >= 1024 ** 3:
        return f"{delta / 1024 ** 3:.2f} GB"
    return f"{delta / 1024 ** 2:.0f} MB"


def format_elapsed(seconds):
    seconds = max(0, int(seconds))
    if seconds >= 3600:
        return f"{seconds // 3600}h {seconds % 3600 // 60:02d}m"
    if seconds >= 60:
        return f"{seconds // 60}m {seconds % 60:02d}s"
    return f"{seconds}s"
