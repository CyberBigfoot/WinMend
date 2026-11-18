"""WinMend features: SSD Saver -- stop and disable the AMD External Events Utility.

The service (atiesrxx.exe) is installed by AMD's graphics driver, including the
Radeon graphics built into Ryzen "G" processors. The option acts only on a PC
with an AMD processor or graphics card, records the start type it replaces so
'Reset Windows Defaults (Undo Tweaks)' can put it back, and reports the state it
reads back afterwards rather than the exit codes of the commands it ran.
"""

from __future__ import annotations

import re
import time
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None

from winmend.core.processes import _no_console_startupinfo, wm_run
from winmend.core.search import _wm_last_line
from winmend.features.office.helpers import service_state

AMD_EVENTS_SERVICE = "AMD External Events Utility"

# AMD graphics keep ATI's PCI vendor id.
AMD_PCI_VENDOR = "VEN_1002"

# Where the start type is kept for Reset Windows Defaults, beside the page file
# and Memory Integrity records the other options leave there.
UNDO_KEY = r"Software\WinMend\Undo"
UNDO_RECORDED = "AmdExternalEventsRecorded"
UNDO_START = "AmdExternalEventsStartType"

# psutil's start type -> the sc.exe word that restores it.
RESTORABLE_START = {"automatic": "auto", "delayed-auto": "delayed-auto", "manual": "demand"}

GPU_QUERY = r'''
Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop | ForEach-Object {
    Write-Output ("GPU|" + $_.PNPDeviceID + "|" + $_.AdapterCompatibility + "|" + $_.Name)
}
'''


def cpu_identity():
    """(vendor id, processor name) from the registry, or ('', '') if unreadable."""
    if winreg is None:
        return "", ""
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
            vendor = str(winreg.QueryValueEx(key, "VendorIdentifier")[0]).strip()
            try:
                name = str(winreg.QueryValueEx(key, "ProcessorNameString")[0]).strip()
            except OSError:
                name = ""
            return vendor, name
    except OSError:
        return "", ""


def parse_gpus(stdout):
    """[(PnP device id, maker, name)] from GPU_QUERY's output."""
    gpus = []
    for line in (stdout or "").splitlines():
        parts = line.strip().split("|", 3)
        if parts[0] == "GPU" and len(parts) == 4:
            gpus.append((parts[1].strip(), parts[2].strip(), parts[3].strip()))
    return gpus


def amd_components(cpu_vendor, cpu_name, gpus):
    """Descriptions of the AMD parts among the processor and graphics adapters.

    The processor counts by its vendor id, AuthenticAMD. A graphics adapter
    counts by its PCI vendor id, which holds even before a driver is installed,
    or failing that by the maker Windows names.
    """
    found = []
    if cpu_vendor == "AuthenticAMD":
        found.append(f"processor: {cpu_name or 'AMD'}")
    for pnp, maker, name in gpus:
        if AMD_PCI_VENDOR in pnp.upper() or re.search(r"advanced micro devices|\bati technologies",
                                                      maker, re.IGNORECASE):
            found.append(f"graphics: {name or 'AMD graphics adapter'}")
    return found


def _delayed_autostart(service):
    if winreg is None:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            rf"SYSTEM\CurrentControlSet\Services\{service}") as key:
            return winreg.QueryValueEx(key, "DelayedAutostart")[0] == 1
    except OSError:
        return False


def record_previous_start(start, key_path=UNDO_KEY):
    """Remember the start type SSD Saver replaces. Returns False if it could not.

    Recorded once: a second run, after the service is already Disabled, must not
    overwrite the original with "disabled".
    """
    if winreg is None or start not in RESTORABLE_START:
        return False
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_path, 0,
                                winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
            try:
                if winreg.QueryValueEx(key, UNDO_RECORDED)[0] == 1:
                    return True
            except OSError:
                pass
            winreg.SetValueEx(key, UNDO_START, 0, winreg.REG_SZ, start)
            winreg.SetValueEx(key, UNDO_RECORDED, 0, winreg.REG_DWORD, 1)
        return True
    except OSError:
        return False


class AmdTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    def run_ssd_saver(self):
        """On an AMD PC, stop the AMD External Events Utility, then disable it."""
        label = "SSD Saver"
        self.queue.put(f"PROGRESS:{label}:Checking for an AMD processor or graphics card...")
        vendor, cpu_name = cpu_identity()
        query = self._run_ps(GPU_QUERY, timeout=60)
        gpus = parse_gpus(query.stdout)
        parts = amd_components(vendor, cpu_name, gpus)
        if not parts:
            if not vendor and not gpus:
                self._report_failure(f"PROGRESS:{label}:Could not identify the processor or graphics "
                                     f"card ({_wm_last_line(query.stderr) or 'no answer'}), so "
                                     f"nothing was changed.")
                return
            self._report_skip(f"PROGRESS:{label}:This PC has no AMD processor or graphics card, so "
                              f"there is nothing to change.")
            return
        for part in parts:
            self.queue.put(f"PROGRESS:{label}:AMD {part}")

        state = service_state(AMD_EVENTS_SERVICE)
        if state is None:
            self._report_skip(f"PROGRESS:{label}:The {AMD_EVENTS_SERVICE} service is not installed "
                              f"here (AMD's graphics driver adds it), so there is nothing to stop.")
            return
        status, start = state.get("status", ""), state.get("start", "")
        self.queue.put(f"PROGRESS:{label}:{AMD_EVENTS_SERVICE}: {status}, start type {start}.")
        if status == "stopped" and start == "disabled":
            self.queue.put(f"PROGRESS:{label}:It is already stopped and disabled; nothing was changed.")
            return

        if start != "disabled":
            previous = "delayed-auto" if (start == "automatic"
                                          and _delayed_autostart(AMD_EVENTS_SERVICE)) else start
            # No change without a way back.
            if not record_previous_start(previous):
                self._report_failure(f"PROGRESS:{label}:Could not record the current start type "
                                     f"({start}) for Reset Windows Defaults, so nothing was changed.")
                return

        problems = []
        if status != "stopped":
            self.queue.put(f"PROGRESS:{label}:Stopping {AMD_EVENTS_SERVICE}...")
            r = wm_run(["sc", "stop", AMD_EVENTS_SERVICE], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=30,
                       startupinfo=_no_console_startupinfo())
            deadline = time.monotonic() + 20
            while (time.monotonic() < deadline and not self.cancel_event.is_set()
                   and (service_state(AMD_EVENTS_SERVICE) or {}).get("status") not in ("stopped", None)):
                time.sleep(0.5)
            if (service_state(AMD_EVENTS_SERVICE) or {}).get("status") != "stopped":
                problems.append(f"it did not stop ({_wm_last_line(r.stdout, r.stderr) or r.returncode})")
        if self.cancel_event.is_set():
            return

        if start != "disabled":
            self.queue.put(f"PROGRESS:{label}:Setting it to Disabled...")
            r = wm_run(["sc", "config", AMD_EVENTS_SERVICE, "start=", "disabled"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=30, startupinfo=_no_console_startupinfo())
            if r.returncode != 0:
                problems.append(f"Windows refused to disable it "
                                f"({_wm_last_line(r.stdout, r.stderr) or r.returncode})")

        after = service_state(AMD_EVENTS_SERVICE) or {}
        self.queue.put(f"PROGRESS:{label}:Now: {after.get('status', 'unknown')}, start type "
                       f"{after.get('start', 'unknown')}.")
        if after.get("status") == "stopped" and after.get("start") == "disabled":
            self.queue.put(f"PROGRESS:{label}:{AMD_EVENTS_SERVICE} is stopped and disabled, and stays "
                           f"off after a restart.")
            self.queue.put(f"PROGRESS:{label}:Radeon Software uses this service for display and "
                           f"hotkey events. If FreeSync or Radeon's hotkeys stop working, 'Reset "
                           f"Windows Defaults (Undo Tweaks)' turns it back on.")
            return
        for why in problems or ["the service did not read back as stopped and disabled"]:
            self._report_failure(f"PROGRESS:{label}:{AMD_EVENTS_SERVICE}: {why}.")
        if after.get("start") == "disabled" and after.get("status") != "stopped":
            self.queue.put(f"PROGRESS:{label}:It is disabled, so it will not start again after a "
                           f"restart.")
