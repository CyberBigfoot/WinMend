"""WinMend core: models."""

from __future__ import annotations




# ============================================================================
# ==================== TASK REGISTRY =========================================
# ============================================================================
# Every task is declared once, as data. The UI is generated from this list:
# category pages, Simple/Advanced filtering, search, the queue, restore-point
# policy and ETA all read from here. Adding a task means adding one WMTask
# entry and one handler method -- not 30 lines of hand-placed widgets.


class WMTask:
    """One maintenance task.

    id            matches the handler and the legacy task-var name, so existing
                  run_selected_tasks() dispatch keeps working unchanged.
    plain         Simple-mode title. None means Advanced-only.
    risk          'safe'        read-only; observes, never changes state
                  'caution'     changes settings; reversible
                  'destructive' removes apps or resets a large surface; confirm first
    restore_point True if System Restore can actually roll this back. Restore
                  covers registry, system files and drivers -- NOT user files --
                  so file-deletion tasks deliberately opt out rather than offer
                  a rollback that would not work.
    reboot        Restarts the PC. Called out on the card because it is the
                  thing users most want warned about.
    reboot_after  Restarts nothing itself, but the change only fully lands after
                  a restart, so the run ends by offering one. Kept separate from
                  `reboot` so the card can say "Restart to finish" instead of the
                  much scarier -- and here untrue -- "Restarts PC".
    """

    __slots__ = ('id', 'title', 'category', 'desc', 'admin', 'secs',
                 'risk', 'simple', 'plain', 'restore_point', 'reboot',
                 'reboot_after')

    def __init__(self, id, title, category, desc, admin=False, secs=60,
                 risk="caution", simple=False, plain=None, restore_point=False,
                 reboot=False, reboot_after=False):
        self.id = id
        self.title = title
        self.category = category
        self.desc = desc
        self.admin = admin
        self.secs = secs
        self.risk = risk
        self.simple = simple
        self.plain = plain
        self.restore_point = restore_point
        self.reboot = reboot
        self.reboot_after = reboot_after

    def display_title(self, simple_mode):
        return self.plain if (simple_mode and self.plain) else self.title

    def duration_label(self):
        if self.secs < 60:
            return "under a min"
        return f"~{round(self.secs / 60)} min"
