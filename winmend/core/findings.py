"""WinMend core: findings."""

from __future__ import annotations

from datetime import datetime, timezone


JOURNAL_SCHEMA = 1


SEVERITY = {"good": 0, "info": 0, "warn": 1, "bad": 2}


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _finding(key, label, status, value, detail, task_ids=()):
    return {
        "key": key,
        "label": label,
        "status": status,
        "value": str(value),
        "detail": detail,
        "task_ids": list(task_ids),
    }
