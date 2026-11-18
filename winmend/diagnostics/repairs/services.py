"""WinMend diagnostics: repairs: services."""

from __future__ import annotations

from winmend.diagnostics.repairs.base import _result, _run_command
from winmend.diagnostics.repairs.common import (
    _START_VALUES,
    _START_WORDS,
    _service_start,
    _valid_service_name,
)
import re
import time


def _do_restart_service(params, log):
    name = str(params.get("name", "")).strip()
    if not re.fullmatch(r"[A-Za-z0-9_\-. ]{1,64}", name):
        return _result(False, f"{name!r} is not a service name.")
    if _service_start(name) == 4:
        # sc start fails with error 1058 on a disabled service; say why in
        # words, and leave re-enabling it to set_service_startup, which records
        # the change so it can be undone.
        return _result(False, f"The {name} service is set to Disabled, so it cannot be started. "
                              f"It has to be set back to starting on its own first.")
    log(f"Restarting the {name} service...")
    _run_command(["sc", "stop", name], timeout=60)
    time.sleep(1.5)
    rc, out, err = _run_command(["sc", "start", name], timeout=60)
    if rc != 0 and "1056" not in (out + err):  # 1056: already running
        return _result(False, f"The {name} service did not start: {(out + err).strip()[-200:]}")
    return _result(True, f"The {name} service was restarted.")


def _do_stop_process(params, log):
    name = str(params.get("name", "")).strip()
    if not re.fullmatch(r"[A-Za-z0-9_\-.]{1,64}", name):
        return _result(False, f"{name!r} is not a process name.")
    image = name if name.lower().endswith(".exe") else name + ".exe"
    log(f"Closing {image}...")
    rc, out, err = _run_command(["taskkill", "/IM", image, "/F", "/T"], timeout=60)
    if rc != 0:
        return _result(False, f"{image} could not be closed: {(out + err).strip()[-160:]}")
    return _result(True, f"{image} was closed. Reopen it whenever you need it.")


# -- services and scheduled work --------------------------------------------

def _do_set_service_startup(params, log):
    name = str(params.get("name", "")).strip()
    if not _valid_service_name(name):
        return _result(False, f"{name!r} is not a service name.")
    wanted = str(params.get("start", "auto")).strip().lower()
    if wanted not in _START_VALUES or wanted == "disabled":
        return _result(False, f"{wanted!r} is not a start type this repair will set.")
    previous = _service_start(name)
    if previous is None:
        return _result(False, f"The {name} service is not installed on this PC.")
    if previous == _START_VALUES[wanted]:
        log(f"{name} is already set to start {wanted}; starting it.")
    else:
        log(f"Setting {name} to start {wanted} (it was {_START_WORDS.get(previous, previous)})...")
        rc, out, err = _run_command(["sc", "config", name, "start=", wanted], timeout=60)
        if rc != 0:
            return _result(False, f"Windows refused the change: {(out + err).strip()[-200:]}")
    rc2, out2, err2 = _run_command(["sc", "start", name], timeout=90)
    running = rc2 == 0 or "1056" in (out2 + err2)  # 1056: already running
    undo = {"kind": "service_start", "name": name, "previous": previous}
    if not running:
        return _result(
            False,
            f"The {name} service is set to start {wanted} again, but it did not start now: "
            f"{(out2 + err2).strip()[-160:]}",
            undo=undo)
    return _result(True, f"The {name} service is set to start {wanted} and is running.", undo=undo)


def _undo_set_service_startup(payload, log):
    name = str(payload.get("name", "")).strip()
    previous = payload.get("previous")
    if not _valid_service_name(name) or previous not in _START_WORDS:
        return _result(False, "The recorded service configuration is incomplete.")
    word = _START_WORDS[int(previous)]
    rc, out, err = _run_command(["sc", "config", name, "start=", word], timeout=60)
    if rc != 0:
        return _result(False, f"Windows refused the change: {(out + err).strip()[-200:]}")
    if int(previous) == 4:
        _run_command(["sc", "stop", name], timeout=60)
    return _result(True, f"The {name} service was set back to start {word}.")
