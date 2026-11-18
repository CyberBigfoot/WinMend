"""WinMend safety: restore points."""

from __future__ import annotations

from winmend.core.processes import _no_console_startupinfo, wm_run


def wm_find_restore_point(description):
    """Return the newest restore point matching *description*, if available."""
    script = (
        "Get-ComputerRestorePoint -ErrorAction SilentlyContinue | "
        "Sort-Object SequenceNumber -Descending | Select-Object -First 30 | "
        "ForEach-Object { Write-Output "
        "($_.SequenceNumber.ToString() + '|' + $_.Description) }"
    )
    try:
        result = wm_run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "RemoteSigned", "-Command", script],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=45, startupinfo=_no_console_startupinfo(),
        )
        for line in (result.stdout or "").splitlines():
            sequence, sep, desc = line.strip().partition("|")
            if sep and desc.strip() == description and sequence.isdigit():
                return {"sequence": int(sequence), "description": desc.strip()}
    except Exception:
        pass
    return None
