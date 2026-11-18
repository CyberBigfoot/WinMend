"""Select useful read-only providers, retaining broad and explicit hardware scans."""
from winmend.diagnostics.catalog import collectors_for
from winmend.diagnostics.reasoning import AREAS


def select_collectors(profile, fast, deep, hardware=(), answers=None, temporal=False):
    if profile in ("audit", "hardware"):
        return list(fast + deep + hardware)
    parts = set(str(profile).split("+"))
    if "general" in parts:
        parts.update(("performance", "crashes", "network", "storage", "updates", "devices"))
    keys = set().union(*(AREAS.get(part, set()) for part in parts))
    names = set(collectors_for(keys))
    names.update(("system_context", "disk", "windows_version", "restart_pending"))
    if temporal or (answers or {}).get("onset") or (answers or {}).get("trigger"):
        names.update(("installed_updates", "installed_programs", "third_party_drivers", "reliability_history"))
    return [pair for pair in fast + deep + hardware if pair[0] in names]
