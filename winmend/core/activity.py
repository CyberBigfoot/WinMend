"""Track task reporting without retaining command output in the safety journal."""

from __future__ import annotations

import queue
import threading


class TaskActivityQueue(queue.Queue):
    """The normal UI queue, with a per-worker count of task detail messages."""

    def __init__(self):
        super().__init__()
        self._local = threading.local()

    def begin_task(self):
        self._local.count = 0

    def end_task(self):
        count = getattr(self._local, "count", None)
        self._local.count = None
        return count

    def put(self, item, block=True, timeout=None):
        count = getattr(self._local, "count", None)
        if count is not None and isinstance(item, str):
            parts = item.split(":", 2)
            if len(parts) == 3 and parts[0] in ("PROGRESS", "LOG") and parts[2].strip():
                self._local.count += 1
        super().put(item, block=block, timeout=timeout)
