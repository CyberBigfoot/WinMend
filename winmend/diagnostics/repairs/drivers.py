"""WinMend diagnostics: repairs: drivers."""

from __future__ import annotations

from winmend.diagnostics.repairs.base import _result, _run_command
import re


# -- driver and update actions ----------------------------------------------

def _do_rollback_driver(params, log):
    published = str(params.get("published", "")).strip()
    if not re.fullmatch(r"oem\d+\.inf", published, re.I):
        return _result(False, f"{published!r} is not a driver package name.")
    name = params.get("name") or published
    log(f"Removing driver package {published} ({name})...")
    rc, out, err = _run_command(
        ["pnputil", "/delete-driver", published, "/uninstall", "/force"], timeout=180)
    text = (out + err).strip()
    if rc != 0:
        return _result(False, f"Windows refused to remove {published}: {text[-200:]}")
    log("Package removed. Rescanning for hardware so Windows reinstalls its own driver...")
    _run_command(["pnputil", "/scan-devices"], timeout=120)
    return _result(
        True,
        f"Removed the {name} driver package. Windows will fall back to its own driver.",
        undo={"kind": "driver", "published": published, "name": name},
        needs_restart=True,
    )


def _undo_rollback_driver(payload, log):
    # Deliberately honest: the package file is gone, so this cannot be reversed
    # in place. The session restore point is the real undo path, which is why
    # this action sets restore_point=True.
    name = payload.get("name", "the driver")
    return _result(
        False,
        f"Reinstalling {name} means installing it again from the manufacturer, or rolling "
        "back to this session's restore point. WinMend cannot recreate a removed driver package.",
    )


def _do_uninstall_update(params, log):
    kb = str(params.get("kb", "")).strip().upper()
    digits = re.sub(r"\D", "", kb)
    if not digits:
        return _result(False, f"{kb!r} is not a KB number.")
    log(f"Asking Windows to uninstall KB{digits}...")
    rc, out, err = _run_command(
        ["wusa", "/uninstall", f"/kb:{digits}", "/quiet", "/norestart"], timeout=600)
    # wusa reports 0x80240017 when the update is not removable this way; the
    # servicing-stack path can still do it, so try that before giving up.
    if rc not in (0, 3010):
        log("The standard uninstaller declined. Trying the servicing-stack path...")
        found = _find_update_package(digits)
        if found:
            rc2, out2, err2 = _run_command(
                ["dism", "/Online", "/Remove-Package", f"/PackageName:{found}",
                 "/NoRestart", "/Quiet"], timeout=900)
            if rc2 in (0, 3010):
                return _result(True, f"Removed KB{digits} through the servicing stack.",
                               undo={"kind": "update", "kb": digits}, needs_restart=True)
            return _result(False, f"KB{digits} could not be removed: {(out2 + err2).strip()[-200:]}")
        return _result(
            False,
            f"KB{digits} cannot be uninstalled on this PC. Updates that have been superseded, "
            "or that are part of the servicing stack, are permanent by design.")
    return _result(True, f"Removed KB{digits}.",
                   undo={"kind": "update", "kb": digits}, needs_restart=True)


def _find_update_package(digits):
    rc, out, _ = _run_command(["dism", "/Online", "/Get-Packages", "/Format:Table"], timeout=300)
    if rc != 0:
        return ""
    for line in out.splitlines():
        if digits in line and "Package_" in line:
            match = re.search(r"(Package_\S+)", line)
            if match:
                return match.group(1).rstrip("|").strip()
    return ""


def _undo_uninstall_update(payload, log):
    kb = payload.get("kb", "")
    return _result(
        False,
        f"KB{kb} is reinstalled by running Windows Update again. WinMend does not force it "
        "back, because the whole point of removing it was to keep it off for now.")


def _do_reinstall_device(params, log):
    instance = str(params.get("instance_id", "")).strip()
    if not instance:
        return _result(False, "No device was identified.")
    # Removing the storage, boot, or system-bus device out from under a running
    # Windows is how a PC stops booting. These classes are never worth the risk
    # from an automated repair.
    blocked = {"diskdrive", "hdc", "scsiadapter", "volume", "system", "computer",
               "processor", "usb"}
    device_class = str(params.get("class", "")).strip().lower()
    if device_class in blocked:
        return _result(
            False,
            f"Refusing to reinstall a {params.get('class')} device automatically: removing "
            "storage, bus, or system devices from a running Windows can stop it booting. "
            "Use Device Manager for this one.")
    name = params.get("name") or instance
    log(f"Removing {name} so Windows redetects it...")
    rc, out, err = _run_command(["pnputil", "/remove-device", instance], timeout=120)
    if rc != 0:
        return _result(False, f"Windows refused to remove the device: {(out + err).strip()[-200:]}")
    log("Rescanning for hardware...")
    rc2, out2, err2 = _run_command(["pnputil", "/scan-devices"], timeout=180)
    return _result(
        rc2 == 0,
        f"Reinstalled {name}." if rc2 == 0 else
        f"{name} was removed but the rescan failed; restart to let Windows redetect it.",
        undo={"kind": "device", "instance_id": instance, "name": name},
        needs_restart=rc2 != 0,
    )
