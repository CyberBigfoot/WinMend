"""WinMend diagnostics: hardware: probe."""

from __future__ import annotations

from winmend.diagnostics.hardware.events import HardwareEventsMixin
from winmend.diagnostics.hardware.graphics import HardwareGraphicsMixin
from winmend.diagnostics.hardware.memory import HardwareMemoryMixin
from winmend.diagnostics.hardware.platform import HardwarePlatformMixin
from winmend.diagnostics.hardware.storage import HardwareStorageMixin


class HardwareProbe(
    HardwarePlatformMixin,
    HardwareGraphicsMixin,
    HardwareStorageMixin,
    HardwareMemoryMixin,
    HardwareEventsMixin,
):
    """Component-level collectors, mixed into ``DeepProbe``.

    Every method returns a plain dict and never raises: a collector that cannot
    read its source returns ``{"available": False}`` with a reason, so one
    gated source never sinks the scan.
    """

    # A PowerShell helper that flattens any value to a single pipe-free line.
    # The row parsers split on "|", so a device name containing one would
    # silently shift every field after it.
    _SANITISE = (
        "function S($v){if($null -eq $v){return ''};"
        "return (([string]$v) -replace '[\\r\\n|]',' ').Trim()};"
    )
