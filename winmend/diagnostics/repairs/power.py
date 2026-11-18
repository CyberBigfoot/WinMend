"""WinMend diagnostics: repairs: power."""

from __future__ import annotations

from winmend.diagnostics.repairs.base import _result, _run_command
import re


# -- power and protection ---------------------------------------------------

_BALANCED_SCHEME = "381b4222-f694-41f0-9685-ff5bb260df2e"


def _do_set_power_plan(params, log):
    scheme = str(params.get("scheme", _BALANCED_SCHEME)).strip().lower()
    if not re.fullmatch(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", scheme):
        return _result(False, f"{scheme!r} is not a power scheme.")
    previous = ""
    rc, out, _ = _run_command(["powercfg", "/getactivescheme"], timeout=30)
    match = re.search(r"([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})", out.lower())
    if match:
        previous = match.group(1)
    if previous == scheme:
        return _result(True, "That power plan is already active.")
    log("Switching the active power plan...")
    rc, out, err = _run_command(["powercfg", "/setactive", scheme], timeout=30)
    if rc != 0:
        return _result(False, f"Windows refused the change: {(out + err).strip()[-200:]}")
    return _result(True, "The Balanced power plan is active, so the processor is no longer "
                         "capped.", undo={"kind": "power", "previous": previous})


def _undo_set_power_plan(payload, log):
    previous = str(payload.get("previous", "")).strip().lower()
    if not re.fullmatch(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", previous):
        return _result(False, "There was no recorded power plan to restore.")
    rc, out, err = _run_command(["powercfg", "/setactive", previous], timeout=30)
    if rc != 0:
        return _result(False, f"Windows refused the change: {(out + err).strip()[-200:]}")
    return _result(True, "The previous power plan was restored.")


def _do_disable_pcie_power_saving(params, log):
    """Stop Windows putting PCIe links into low-power states.

    Aggressive link power management is a documented cause of NVMe drives
    dropping off the bus and of storage controller resets. It is a power-plan
    setting, so it is fully reversible and takes effect immediately.
    """
    changed = []
    for scope, flag in (("current", "/setacvalueindex"), ("battery", "/setdcvalueindex")):
        rc, out, err = _run_command(
            ["powercfg", flag, "SCHEME_CURRENT", "SUB_PCIEXPRESS", "ASPM", "0"],
            timeout=45)
        if rc == 0:
            changed.append(scope)
    if not changed:
        return _result(False,
                       "The PCIe power setting could not be changed. This machine may not "
                       "expose it.")
    _run_command(["powercfg", "/setactive", "SCHEME_CURRENT"], timeout=45)
    log("Set PCI Express link power management to off.")
    return _result(
        True,
        "PCI Express link power saving is off. If a drive was dropping off the bus, that "
        "should stop; on a laptop this costs a little battery life.",
        undo={"kind": "aspm"})


def _undo_disable_pcie_power_saving(payload, log):
    """Return the setting to Windows' default of maximum power saving."""
    if (payload or {}).get("kind") != "aspm":
        return _result(False, "No PCIe power change was recorded, so there is nothing "
                              "to put back.")
    ok = False
    for flag in ("/setacvalueindex", "/setdcvalueindex"):
        rc, _out, _err = _run_command(
            ["powercfg", flag, "SCHEME_CURRENT", "SUB_PCIEXPRESS", "ASPM", "2"], timeout=45)
        ok = ok or rc == 0
    if not ok:
        return _result(False, "The PCIe power setting could not be put back.")
    _run_command(["powercfg", "/setactive", "SCHEME_CURRENT"], timeout=45)
    return _result(True, "PCI Express link power saving was put back on.")
