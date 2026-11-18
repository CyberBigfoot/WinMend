"""WinMend diagnostics: repairs: security."""

from __future__ import annotations

from winmend.diagnostics.helpers import _plural
from winmend.diagnostics.repairs.base import _result
from winmend.diagnostics.repairs.common import (
    _ps_run,
    _registry_apply,
    _registry_restore,
    _registry_snapshot,
)
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


# -- security posture -------------------------------------------------------

_UAC_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"


def _do_enable_uac(params, log):
    names = ("EnableLUA", "ConsentPromptBehaviorAdmin", "PromptOnSecureDesktop")
    previous = _registry_snapshot(winreg.HKEY_LOCAL_MACHINE, _UAC_KEY, names) if winreg else {}
    if not previous or previous.get("EnableLUA") is None:
        return _result(False, "The User Account Control settings could not be read, "
                              "so nothing was changed.")
    log("Recording the current UAC settings so this can be undone...")
    # 5 is the Windows default: prompt for consent when a non-Windows program
    # asks for administrator rights. 1 on the secure desktop is what stops a
    # program from drawing its own fake prompt over the real one.
    error = _registry_apply(winreg.HKEY_LOCAL_MACHINE, _UAC_KEY, {
        "EnableLUA": [1, winreg.REG_DWORD],
        "ConsentPromptBehaviorAdmin": [5, winreg.REG_DWORD],
        "PromptOnSecureDesktop": [1, winreg.REG_DWORD],
    })
    if error:
        return _result(False, f"Windows refused the change: {error}")
    return _result(
        True,
        "User Account Control is back on and set to ask before a program gets administrator "
        "rights. This takes effect after a restart.",
        undo={"kind": "uac", "previous": previous}, needs_restart=True)


def _undo_enable_uac(payload, log):
    error = _registry_restore(winreg.HKEY_LOCAL_MACHINE, _UAC_KEY,
                              payload.get("previous") or {})
    if error:
        return _result(False, f"Windows refused the change: {error}")
    return _result(True, "The previous User Account Control settings were restored.",
                   needs_restart=True)


def _do_enable_realtime(params, log):
    log("Turning Microsoft Defender real-time protection back on...")
    rc, out, err = _ps_run(
        "Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop; "
        "Write-Output ('R|'+[string](Get-MpComputerStatus).RealTimeProtectionEnabled)",
        timeout=90)
    if "R|True" in out:
        return _result(True, "Real-time protection is on again.")
    text = (out + err).strip()
    # Tamper Protection exists precisely to stop a program doing this, and it
    # refuses without saying so plainly. Naming it saves the user a hunt.
    if "tamper" in text.lower() or rc != 0:
        return _result(
            False,
            "Windows refused to turn real-time protection on from outside Windows Security. "
            "That is Tamper Protection doing its job. Open Windows Security > Virus & threat "
            "protection > Manage settings and switch it on there.")
    return _result(False, f"Real-time protection did not come back on: {text[-200:]}")


def _do_remove_threats(params, log):
    log("Asking Defender to finish removing what it has already found...")
    rc, out, err = _ps_run(
        "$before=@(Get-MpThreat -ErrorAction SilentlyContinue).Count;"
        "try { Remove-MpThreat -ErrorAction Stop } catch { Write-Output ('E|'+$_.Exception.Message) };"
        "$t=@(Get-MpThreat -ErrorAction SilentlyContinue);"
        "$left=@($t | Where-Object { $_.ThreatStatusID -in @(1,5,102,103,104,105,107) }).Count;"
        "Write-Output ('L|'+[string]$left+'|'+[string]$before)", timeout=600)
    left = None
    for line in out.splitlines():
        if line.startswith("L|"):
            try:
                left = int(line.split("|")[1])
            except (IndexError, ValueError):
                left = None
    if left is None:
        return _result(False, f"Defender did not report a result: {(out + err).strip()[-200:]}")
    if left:
        return _result(
            False,
            f"{_plural(left, 'detection')} could not be removed in place. Run a full scan, and "
            "if it is still there afterwards the file is in use or protected -- an offline scan "
            "from Windows Security is the next step.")
    return _result(True, "Defender finished removing everything outstanding.")


_FIREWALL_NAMES = ("Domain", "Private", "Public")


def _do_enable_firewall(params, log):
    wanted = [p for p in (params.get("profiles") or _FIREWALL_NAMES)
              if str(p).strip().capitalize() in _FIREWALL_NAMES]
    wanted = [str(p).strip().capitalize() for p in wanted]
    if not wanted:
        return _result(False, "No firewall profile was identified.")
    rc, out, err = _ps_run(
        "Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { Write-Output "
        "('P|'+$_.Name+'|'+[string]$_.Enabled+'|'+[string]$_.DefaultInboundAction) }", timeout=60)
    previous = {}
    for line in out.splitlines():
        parts = line.split("|")
        if len(parts) >= 4 and parts[0] == "P":
            previous[parts[1].strip()] = {"enabled": parts[2].strip(),
                                          "inbound": parts[3].strip()}
    if not previous:
        return _result(False, "The firewall profiles could not be read, so nothing was changed.")
    names = ",".join(f"'{name}'" for name in wanted)
    log(f"Turning the {', '.join(wanted)} firewall profile(s) back on...")
    # Only Enabled and the inbound default are touched. The outbound default is
    # left exactly as it is: turning a firewall on should not also start
    # blocking traffic the user has been allowing out.
    rc, out2, err2 = _ps_run(
        f"Set-NetFirewallProfile -Name {names} -Enabled True "
        f"-DefaultInboundAction Block -ErrorAction Stop; Write-Output 'OK'", timeout=90)
    if "OK" not in out2:
        return _result(False, f"Windows refused the change: {(out2 + err2).strip()[-200:]}")
    return _result(True, f"The {', '.join(wanted)} firewall profile(s) are on and blocking "
                         f"unrequested inbound connections.",
                   undo={"kind": "firewall", "previous": {k: previous[k] for k in wanted
                                                          if k in previous}})


def _undo_enable_firewall(payload, log):
    previous = payload.get("previous") or {}
    if not previous:
        return _result(False, "There was no recorded firewall state to restore.")
    restored = []
    for name, state in previous.items():
        if name not in _FIREWALL_NAMES:
            continue
        enabled = "True" if str(state.get("enabled", "")).lower() == "true" else "False"
        inbound = state.get("inbound") or "Block"
        if inbound not in ("Block", "Allow", "NotConfigured"):
            inbound = "Block"
        rc, out, _ = _ps_run(
            f"Set-NetFirewallProfile -Name '{name}' -Enabled {enabled} "
            f"-DefaultInboundAction {inbound} -ErrorAction Stop; Write-Output 'OK'", timeout=60)
        if "OK" in out:
            restored.append(name)
    if not restored:
        return _result(False, "No firewall profile accepted the change.")
    return _result(True, f"The previous firewall state was restored on {', '.join(restored)}.")
