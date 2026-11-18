"""WinMend features: speedtest: history."""

from __future__ import annotations

from pathlib import Path
import json
import os
import threading


def summarize_result_for_history(result):
    """Compact one full run into the record kept in the trend history."""
    down = result.get("download") or {}
    up = result.get("upload") or {}
    idle = result.get("idle_latency") or {}
    server = result.get("server") or {}
    return {
        "at": result.get("started_at"),
        "advanced": bool(result.get("advanced")),
        "download_mbps": down.get("mbps"),
        "upload_mbps": up.get("mbps"),
        "ping_ms": idle.get("min_ms"),
        "jitter_ms": idle.get("jitter_ms"),
        "isp": server.get("isp"),
        "colo": server.get("colo"),
        "grade_down": (result.get("bufferbloat_download") or {}).get("grade"),
        "grade_up": (result.get("bufferbloat_upload") or {}).get("grade"),
    }


class SpeedTestHistory:
    """A short JSON trend log of past runs -- lets the page answer 'is my
    connection getting worse?'. Kept separate from the Safety Journal on
    purpose: a speed test changes nothing, so it has no place among the
    journal's undoable actions."""

    def __init__(self, path=None, max_entries=30):
        if path is None:
            appdata = os.environ.get("APPDATA", str(Path.home()))
            path = Path(appdata) / "WinMend" / "speedtest_history.json"
        self.path = Path(path)
        self.max_entries = max(5, int(max_entries))
        self._lock = threading.RLock()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    def list(self):
        with self._lock:
            if not self.path.exists():
                return []
            try:
                with self.path.open("r", encoding="utf-8") as stream:
                    data = json.load(stream)
                entries = data.get("entries", [])
                return entries if isinstance(entries, list) else []
            except (OSError, ValueError, json.JSONDecodeError):
                return []

    def add(self, entry):
        with self._lock:
            entries = self.list()
            entries.insert(0, entry)
            entries = entries[: self.max_entries]
            temp = self.path.with_suffix(self.path.suffix + ".tmp")
            try:
                with temp.open("w", encoding="utf-8", newline="\n") as stream:
                    json.dump({"entries": entries}, stream, indent=2, ensure_ascii=False)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temp, self.path)
            except OSError:
                pass
            return entries
