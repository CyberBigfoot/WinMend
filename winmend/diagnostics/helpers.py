"""WinMend diagnostics: helpers."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from winmend.core.findings import _finding
import re


# ---------------------------------------------------------------------------
# Small shared helpers
# ---------------------------------------------------------------------------

def _evidence(key, label, status, value, detail, data=None, task_ids=()):
    """A finding with a machine-readable payload attached.

    The wire shape stays compatible with ``winmend_safety._finding`` so the
    existing journal, verification compare(), and Guided Fix table keep working
    unchanged; ``data`` is what the rules actually reason over.
    """
    item = _finding(key, label, status, value, detail, task_ids)
    item["data"] = data if isinstance(data, dict) else {}
    return item


def _iso_to_dt(text):
    """Parse the several date shapes Windows tooling hands back."""
    if not text:
        return None
    text = str(text).strip()
    if not text:
        return None
    # WMI/CIM DMTF: 20260714093012.000000+000
    match = re.match(r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})", text)
    if match and len(text) >= 14:
        try:
            zone = timezone.utc
            if len(text) >= 25 and text[21] in "+-" and text[22:25].isdigit():
                minutes = int(text[22:25]) * (1 if text[21] == "+" else -1)
                zone = timezone(timedelta(minutes=minutes))
            return datetime(*(int(g) for g in match.groups()), tzinfo=zone).astimezone(timezone.utc)
        except ValueError:
            return None
    cleaned = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(cleaned)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    # %Y%m%d is what the uninstall registry's InstallDate actually holds, and
    # Python 3.10's fromisoformat rejects that basic form.
    for fmt in ("%Y%m%d", "%m/%d/%Y", "%d/%m/%Y", "%Y-%m-%d", "%m/%d/%Y %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _days_ago(value):
    moment = _iso_to_dt(value)
    if moment is None:
        return None
    return (datetime.now(timezone.utc) - moment).total_seconds() / 86400.0


def _plural(count, word, suffix="s"):
    return f"{count} {word}{'' if count == 1 else suffix}"


def _tri_state(text):
    """True/False for a PowerShell boolean, None when it could not be read."""
    lowered = str(text or "").strip().lower()
    if lowered in ("true", "1"):
        return True
    if lowered in ("false", "0"):
        return False
    return None


def _scan_age(text):
    """Defender reports "never scanned" as an unsigned -1, not as a large age."""
    try:
        value = int(float(str(text).strip()))
    except (ValueError, TypeError):
        return None
    return None if value < 0 or value >= 0xFFFFFFF else value


def _is_private_address(address):
    """True for addresses that cannot be a public resolver: RFC1918, loopback,
    link-local, and the 100.64.0.0/10 shared range -- carrier-grade NAT, and the
    DNS of Tailscale (100.100.100.100) and Twingate (100.95.0.x)."""
    try:
        parts = [int(p) for p in str(address).split(".")]
    except ValueError:
        return False
    if len(parts) != 4:
        return False
    if parts[0] == 10 or parts[0] == 127:
        return True
    if parts[0] == 100 and 64 <= parts[1] <= 127:
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    if parts[0] == 169 and parts[1] == 254:
        return True
    return False
