"""WinMend diagnostics: hardware: reference."""

from __future__ import annotations

from datetime import datetime


# ---------------------------------------------------------------------------
# Small helpers.
#
# Deliberately local copies rather than imports from winmend_diagnostics: that
# module imports this one, and a cycle here would break the whole engine to save
# fifteen lines.
# ---------------------------------------------------------------------------

def _num(value, default=None):
    """An int from anything, or ``default`` -- never an exception."""
    try:
        return int(float(str(value).strip()))
    except (ValueError, TypeError):
        return default


def _tri(text):
    """True/False for a PowerShell boolean, None when it could not be read."""
    lowered = str(text or "").strip().lower()
    if lowered in ("true", "1", "yes"):
        return True
    if lowered in ("false", "0", "no"):
        return False
    return None


def _age_days(stamp):
    """Whole days since an ISO-ish date string, or None if it will not parse."""
    text = str(stamp or "").strip()
    if not text:
        return None
    for pattern in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            moment = datetime.strptime(text[:len(pattern) + 2].strip(), pattern)
        except ValueError:
            continue
        delta = datetime.now() - moment
        return max(0, int(delta.total_seconds() // 86400))
    return None


# SMART attributes worth naming. The raw counters that actually predict failure
# are a small subset of the table, and every one of them means something
# different -- lumping them into "SMART errors" is why so many tools report a
# dying drive as healthy right up until it stops.
#
# ``critical`` marks the attributes where *any* non-zero raw value is a real
# finding rather than a number to watch.
SMART_ATTRIBUTES = {
    1: ("Read error rate", False),
    5: ("Reallocated sectors", True),
    9: ("Power-on hours", False),
    10: ("Spin retry count", True),
    12: ("Power cycles", False),
    177: ("Wear levelling count", False),
    184: ("End-to-end error", True),
    187: ("Uncorrectable errors reported", True),
    188: ("Command timeouts", False),
    190: ("Airflow temperature", False),
    194: ("Temperature", False),
    196: ("Reallocation events", False),
    197: ("Sectors pending reallocation", True),
    198: ("Uncorrectable sectors", True),
    199: ("Interface CRC errors", True),
    201: ("Soft read error rate", False),
    231: ("Life left", False),
    233: ("Media wear-out indicator", False),
    241: ("Total data written", False),
}


# The handful whose meaning is worth spelling out to a non-technical reader,
# because the right response differs so sharply between them.
SMART_MEANING = {
    5: "The drive has already moved data out of sectors that stopped working.",
    10: "The drive is struggling to spin up -- a mechanical symptom.",
    184: "Data arrived at the drive differently from how it left the controller.",
    187: "The drive hit errors it could not correct on its own.",
    197: "Sectors are failing to read and are waiting to be reallocated. This is "
         "the earliest reliable warning a drive gives.",
    198: "Sectors failed even on a retry. Data in them is already gone.",
    199: "Errors on the cable between the drive and the board -- very often the "
         "cable or the port rather than the drive itself.",
}


# LiveKernelEvent codes Windows writes when something misbehaves badly enough to
# be captured but not badly enough to bluescreen. The distinction between 117
# and 141 is the one that matters most: they look identical to a user and mean
# opposite things.
LIVE_KERNEL_EVENTS = {
    "117": ("Display driver timeout",
            "The graphics driver stopped responding and Windows reset it. Usually "
            "the driver, not the card.", "driver"),
    "141": ("Graphics engine timeout",
            "A graphics engine did not respond in time. Drivers, tuning, power, "
            "cooling and hardware are possible causes; the code alone cannot distinguish them.",
            "hardware"),
    "144": ("USB controller fault",
            "A USB controller stopped responding.", "hardware"),
}


# Deliberately short. Only these three codes have a well-established meaning, and
# a code is only allowed to carry "blame" when acting on it would be right.
#
# This list was longer, and testing on a working machine is why it is not: that
# machine had 118 live kernel events, none of them 117 or 141, and it is
# perfectly healthy. Watchdog captures of this kind are routine on some hardware
# and driver combinations. Guessing that an unrecognised code meant a failing GPU
# would have told its owner to replace a card that is fine -- so an unknown code
# is now reported as an unknown code.


# Storage event ids, by the provider that raises them. Every one of these gets
# lumped into "disk errors" by tools that count events instead of reading them,
# and the response ranges from "replace the cable" to "the drive is going".
STORAGE_EVENTS = {
    7: ("Bad block", "The drive reported a sector it could not use.", "drive"),
    9: ("Device timeout", "The drive did not answer in time.", "link"),
    11: ("Controller error", "The storage controller reported a fault.", "link"),
    15: ("Device not ready", "The drive was not ready when Windows needed it.", "link"),
    51: ("Paging error", "An error occurred writing to or reading from the disk.", "drive"),
    52: ("Failure predicted", "The drive's own failure prediction has tripped.", "drive"),
    129: ("Controller reset", "The controller had to be reset because the drive "
                              "stopped responding. Cabling, the port, or the drive.", "link"),
    153: ("I/O retried", "A read or write had to be retried.", "drive"),
    157: ("Disk removed", "The disk was surprise-removed.", "link"),
}


STORAGE_PROVIDERS = ("disk", "storahci", "stornvme", "iaStorA", "iaStorAC",
                     "amdsata", "nvme", "msahci", "vhdmp", "volmgr")
