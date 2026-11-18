"""Compatibility imports for the modular WinMend package."""

from datetime import datetime, timezone
from pathlib import Path
from winmend.diagnostics.hardware.probe import HardwareProbe
from winmend.diagnostics.hardware.reference import (
    LIVE_KERNEL_EVENTS,
    SMART_ATTRIBUTES,
    SMART_MEANING,
    STORAGE_EVENTS,
    STORAGE_PROVIDERS,
    _age_days,
    _num,
    _tri,
)
import os
import re
import struct
import time
try:  # pragma: no cover - absent only on non-Windows, where every probe no-ops
    import winreg
except ImportError:  # pragma: no cover
    winreg = None
