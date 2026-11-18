"""WinMend diagnostics: repairs: graphics."""

from __future__ import annotations

from winmend.core.safe_delete import clear_folder, final_path
from winmend.diagnostics.helpers import _plural
from winmend.diagnostics.repairs.base import _result
from winmend.diagnostics.repairs.common import (
    _registry_apply,
    _registry_restore,
    _registry_snapshot,
)
import os
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


# -- hardware-scan repairs --------------------------------------------------
#
# Short list on purpose. Most of what the hardware scan finds has no software
# fix, and inventing one would be worse than saying so. These are the cases
# where a *setting* rather than a component is genuinely at fault, plus the two
# pieces of housekeeping that clear a real class of graphics symptom.

_GRAPHICS_KEY = r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers"


def _do_reset_tdr(params, log):
    """Put graphics crash recovery back to the Windows default.

    Deleting the values rather than writing 3 and 2 is deliberate: absent is
    the real default, and a machine that has never been tampered with has no
    values here at all. Writing the numbers would leave a fingerprint that
    looks like tampering to the next person who checks.
    """
    names = ("TdrLevel", "TdrDelay", "TdrDdiDelay")
    previous = _registry_snapshot(winreg.HKEY_LOCAL_MACHINE, _GRAPHICS_KEY, names) \
        if winreg is not None else {}
    if all(value is None for value in previous.values()):
        return _result(True, "Graphics crash recovery was already at the Windows default.")
    error = _registry_apply(winreg.HKEY_LOCAL_MACHINE, _GRAPHICS_KEY,
                            {name: None for name in names})
    if error:
        return _result(False, f"The graphics settings could not be changed: {error}")
    log("Removed the timeout overrides so Windows uses its own defaults.")
    return _result(
        True,
        "Graphics crash recovery is back to the Windows default. Expect to see driver "
        "resets reported again -- they were happening before, just not recoverably.",
        undo={"kind": "tdr", "previous": previous}, needs_restart=True)


def _undo_reset_tdr(payload, log):
    error = _registry_restore(winreg.HKEY_LOCAL_MACHINE, _GRAPHICS_KEY,
                              payload.get("previous") or {})
    if error:
        return _result(False, error)
    return _result(True, "The previous graphics timeout settings were put back.",
                   needs_restart=True)


def _do_set_gpu_scheduling(params, log):
    """Turn hardware-accelerated GPU scheduling off.

    A genuine fix rather than folklore: on older cards and some driver versions
    it produces stutter and driver resets, and it is one registry value away
    from being ruled out. Reversible, so trying it costs a restart.
    """
    if winreg is None:
        return _result(False, "Registry access is unavailable.")
    previous = _registry_snapshot(winreg.HKEY_LOCAL_MACHINE, _GRAPHICS_KEY, ("HwSchMode",))
    current = (previous.get("HwSchMode") or [None])[0]
    if current == 1:
        return _result(True, "Hardware-accelerated GPU scheduling was already off.")
    error = _registry_apply(winreg.HKEY_LOCAL_MACHINE, _GRAPHICS_KEY,
                            {"HwSchMode": [1, winreg.REG_DWORD]})
    if error:
        return _result(False, f"The setting could not be changed: {error}")
    log("Set hardware-accelerated GPU scheduling to off.")
    return _result(True,
                   "Hardware-accelerated GPU scheduling is off. This takes effect after a "
                   "restart.",
                   undo={"kind": "hags", "previous": previous}, needs_restart=True)


def _undo_set_gpu_scheduling(payload, log):
    error = _registry_restore(winreg.HKEY_LOCAL_MACHINE, _GRAPHICS_KEY,
                              payload.get("previous") or {})
    if error:
        return _result(False, error)
    return _result(True, "GPU scheduling was put back to its previous setting.",
                   needs_restart=True)


# Where each vendor's compiled shader cache lives. A corrupted cache produces
# exactly the artefacts and crashes people blame on a failing card, and it is
# rebuilt automatically -- so clearing it is the cheapest way to rule that out.
_SHADER_CACHES = (
    ("LOCALAPPDATA", r"D3DSCache"),
    ("LOCALAPPDATA", r"NVIDIA\DXCache"),
    ("LOCALAPPDATA", r"NVIDIA\GLCache"),
    ("LOCALAPPDATA", r"AMD\DxCache"),
    ("LOCALAPPDATA", r"AMD\DxcCache"),
    ("LOCALAPPDATA", r"Intel\ShaderCache"),
    ("APPDATA", r"NVIDIA\ComputeCache"),
)


def _do_clear_shader_cache(params, log):
    """Delete the compiled shader caches so the drivers rebuild them."""
    removed, freed, in_use, failed = [], 0, 0, []
    for variable, relative in _SHADER_CACHES:
        base = os.environ.get(variable)
        if not base:
            continue
        # The cache directory itself is left in place: the drivers expect to
        # find it and some will not recreate it themselves. Its contents go by
        # handle, never through a link: this runs elevated, and the user's own
        # programs can plant a junction here. The app-data folder may itself be
        # redirected, so it is resolved; nothing below it is followed.
        try:
            _count, size, left = clear_folder(final_path(base) + "\\" + relative)
        except FileNotFoundError:
            continue
        except OSError as exc:
            failed.append(f"{relative}: {exc}")
            continue
        removed.append(relative)
        freed += size
        in_use += left
    if not removed and not failed:
        return _result(True, "There were no shader caches to clear.")
    if not removed:
        return _result(False, "The shader caches could not be cleared: " + "; ".join(failed))
    log(f"Cleared {len(removed)} shader cache folder(s).")
    if failed:
        log("Not cleared: " + "; ".join(failed))
    note = ""
    if in_use:
        note = (f" {_plural(in_use, 'item')} could not be deleted, usually because a game or "
                f"3D application has it open; close those and run this again.")
    return _result(
        True,
        f"Cleared {_plural(len(removed), 'shader cache')}, freeing "
        f"{freed / (1024 ** 2):.0f} MB. The drivers rebuild these automatically, so the first "
        f"launch of a game or 3D application will be slower than usual.{note}")
