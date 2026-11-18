"""WinMend diagnostics: repairs: storage."""

from __future__ import annotations

from pathlib import Path
from winmend.diagnostics.repairs.base import _result, _run_command
from winmend.diagnostics.repairs.common import _ps_run, _valid_drive
import os
import re
import shutil


# -- storage ----------------------------------------------------------------

def _do_check_disk(params, log):
    drive = str(params.get("drive", "")).strip().rstrip("\\").upper()
    if not _valid_drive(drive):
        return _result(False, f"{drive!r} is not a drive letter.")
    log(f"Running the online scan on {drive} -- this reads the whole file system...")
    # /scan is the online repair: it runs against a mounted volume, needs no
    # restart, and fixes most of what it finds. It is always worth trying before
    # asking the user to sit through a boot-time check.
    rc, out, err = _run_command(["chkdsk", drive, "/scan", "/perf"], timeout=3600)
    text = (out + err).strip()
    if rc == 0:
        return _result(True, f"The online scan of {drive} completed and found nothing left to "
                             f"repair. No restart is needed.")
    log("The online scan could not finish the repair. Scheduling the boot-time check...")
    # chkntfs /c puts the volume back in autochk's list. autochk only acts on a
    # volume whose dirty bit is set, which is exactly the case that got us here.
    rc2, out2, err2 = _run_command(["chkntfs", "/c", drive], timeout=60)
    if rc2 != 0:
        return _result(False, f"{drive} could not be scheduled for a check: "
                              f"{(out2 + err2).strip()[-200:]}")
    return _result(
        True,
        f"{drive} is scheduled for a full repair at the next restart. It can take a long time "
        f"on a large drive, and it must not be interrupted once it starts.",
        undo={"kind": "chkdsk", "drive": drive}, needs_restart=True)


def _undo_check_disk(payload, log):
    drive = str(payload.get("drive", "")).strip().upper()
    if not _valid_drive(drive):
        return _result(False, "The recorded drive letter is incomplete.")
    rc, out, err = _run_command(["chkntfs", "/x", drive], timeout=60)
    if rc != 0:
        return _result(False, f"The scheduled check could not be cancelled: "
                              f"{(out + err).strip()[-200:]}")
    return _result(True, f"The boot-time check of {drive} was cancelled. The volume is still "
                         f"flagged as damaged.")


def recycle_bin_bytes(drive, cap=40000):
    """How much is in one drive's Recycle Bin, and whether that count is whole.

    Windows keeps a separate bin per drive, under a per-user folder inside
    ``<drive>\\$Recycle.Bin``. The walk is capped because a bin with a hundred
    thousand files in it would otherwise stall a sweep, and a floor is enough:
    the question is only ever "is there anything worth reclaiming here".
    """
    root = Path(str(drive).rstrip("\\") + "\\$Recycle.Bin")
    total = 0
    seen = 0
    try:
        if not root.is_dir():
            return 0, True
        for base, _dirs, names in os.walk(str(root)):
            for name in names:
                try:
                    total += os.path.getsize(os.path.join(base, name))
                except OSError:
                    continue
                seen += 1
                if seen >= cap:
                    return total, False
    except OSError:
        return total, False
    return total, True


def _do_empty_recycle_bin(params, log):
    drive = str(params.get("drive", "")).strip().rstrip("\\").upper()
    if not _valid_drive(drive):
        return _result(False, f"{drive!r} is not a drive letter.")
    try:
        before = shutil.disk_usage(drive + "\\").free
    except OSError as exc:
        return _result(False, f"{drive} could not be read: {exc}")
    # Measured first, because Clear-RecycleBin's own report cannot be trusted to
    # tell the two apart: on a drive whose bin is already empty it throws
    # "the system cannot find the path specified", which is not a failure of
    # anything. What matters is whether there was something to reclaim.
    held, complete = recycle_bin_bytes(drive)
    if complete and held < 1024 ** 2:
        return _result(
            True,
            f"The Recycle Bin on {drive} is already empty, so there is nothing to reclaim "
            f"there -- the space is being used by real files. The Storage Analyzer page shows "
            f"what they are.")
    log(f"Emptying the Recycle Bin on {drive} "
        f"({held / 1024 ** 3:.1f} GB{'+' if not complete else ''})...")
    rc, out, err = _ps_run(
        f"Clear-RecycleBin -DriveLetter {drive[0]} -Force -ErrorAction Stop; Write-Output 'OK'",
        timeout=600)
    try:
        freed = max(0, shutil.disk_usage(drive + "\\").free - before)
    except OSError:
        freed = 0
    left, _complete = recycle_bin_bytes(drive)
    # Judged on what actually changed rather than on the exit code, for the same
    # reason as above.
    if freed >= 1024 ** 2 or left < held:
        return _result(True, f"Emptied the Recycle Bin on {drive} and freed "
                             f"{freed / 1024 ** 3:.1f} GB.")
    if "OK" in out:
        return _result(True, f"The Recycle Bin on {drive} was cleared, but no space came back. "
                             f"What is in it belongs to another user account, and only that "
                             f"account can empty it.")
    return _result(False, f"The Recycle Bin on {drive} could not be emptied: "
                          f"{(out + err).strip()[-200:]}")


# -- storage -----------------------------------------------------------------

def _do_enable_trim(params, log):
    """Let the system tell an SSD which blocks are free again."""
    rc, out, _ = _run_command(
        ["fsutil", "behavior", "query", "DisableDeleteNotify"], timeout=30)
    values = [int(value) for value in re.findall(r"=\s*(\d)", out or "")] if rc == 0 else []
    if values and not any(values):
        return _result(True, "TRIM was already on, so nothing needed changing.")
    log("Turning TRIM back on...")
    rc, out, err = _run_command(
        ["fsutil", "behavior", "set", "DisableDeleteNotify", "0"], timeout=30)
    if rc != 0:
        return _result(False, "TRIM could not be turned on: "
                              + (err or out or "administrator rights are needed").strip()[:160])
    return _result(
        True,
        "TRIM is on again. The drive will be told about free blocks from now on; the backlog "
        "clears the next time Windows optimises the volume.",
        undo={"kind": "trim", "previous": 1 if values and any(values) else 0})


def _undo_enable_trim(payload, log):
    if int(payload.get("previous", 0)) != 1:
        return _result(True, "TRIM was already on before this ran, so there is nothing to undo.")
    _run_command(["fsutil", "behavior", "set", "DisableDeleteNotify", "1"], timeout=30)
    return _result(True, "TRIM was switched off again, as it was before.")


def _do_optimize_volume(params, log):
    """Retrim an SSD or defragment a mechanical disk."""
    drive = str(params.get("drive", "")).strip().rstrip("\\")
    if not _valid_drive(drive):
        return _result(False, f"{drive!r} is not a drive letter.")
    log(f"Optimising {drive} -- this reads the whole volume and can take a while...")
    rc, out, err = _run_command(["defrag", drive, "/O"], timeout=1800)
    if rc != 0:
        return _result(False, f"{drive} could not be optimised: "
                              + (err or out or "").strip()[:200])
    return _result(True, f"{drive} was optimised. Windows chose the right operation for the "
                         f"media -- a retrim for an SSD, a defragment for a mechanical disk.")


def _do_resume_bitlocker(params, log):
    """Turn drive protection back on where it was left suspended."""
    drive = str(params.get("drive", "")).strip().rstrip("\\")
    if not _valid_drive(drive):
        return _result(False, f"{drive!r} is not a drive letter.")
    log(f"Re-enabling BitLocker protection on {drive}...")
    rc, out, err = _run_command(["manage-bde", "-protectors", "-enable", drive], timeout=120)
    if rc != 0:
        return _result(False, f"Protection could not be re-enabled on {drive}: "
                              + (err or out or "").strip()[:200])
    # Deliberately one-way. An undo here would re-suspend protection and put the
    # key back in the clear, which is a footgun rather than a safety feature --
    # the same reasoning that leaves remove_threats without an undo.
    return _result(True, f"Protection is on again for {drive}. The key is no longer stored in "
                         f"the clear, so the encryption is doing its job.")
