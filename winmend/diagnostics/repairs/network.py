"""WinMend diagnostics: repairs: network."""

from __future__ import annotations

from winmend.diagnostics.collectors.deep import DeepProbe
from winmend.diagnostics.repairs.base import _result, _run_command
from winmend.diagnostics.repairs.common import _START_WORDS, _ps_run, _service_start
import re


# -- clock, addressing, and links -------------------------------------------

def _do_sync_clock(params, log):
    previous = _service_start("W32Time")
    if previous == 4:
        log("The Windows Time service is disabled. Setting it back to start on demand...")
        _run_command(["sc", "config", "W32Time", "start=", "demand"], timeout=60)
    log("Starting the Windows Time service...")
    _run_command(["sc", "start", "W32Time"], timeout=60)
    log("Asking Windows to resynchronise the clock...")
    rc, out, err = _run_command(["w32tm", "/resync", "/force"], timeout=120)
    if rc != 0:
        # A PC that has never been on a domain often has no configured peer at
        # all, and /resync fails with nothing to sync against.
        log("No time source answered. Pointing the service at time.windows.com...")
        _run_command(["w32tm", "/config", "/manualpeerlist:time.windows.com,0x9",
                      "/syncfromflags:manual", "/reliable:no", "/update"], timeout=60)
        _run_command(["sc", "stop", "W32Time"], timeout=60)
        _run_command(["sc", "start", "W32Time"], timeout=60)
        rc, out, err = _run_command(["w32tm", "/resync", "/force"], timeout=120)
    if rc != 0:
        return _result(
            False,
            f"The clock could not be synchronised: {(out + err).strip()[-200:]} "
            "Check that this PC can reach the internet first -- the two faults look identical.",
            undo={"kind": "time", "previous": previous})
    return _result(True, "The clock was resynchronised against an internet time server, and "
                         "the Windows Time service is running.",
                   undo={"kind": "time", "previous": previous})


def _undo_sync_clock(payload, log):
    # The clock itself is deliberately not put back: the whole point was that it
    # was wrong. Only the service configuration this repair changed is restored.
    previous = payload.get("previous")
    if previous not in _START_WORDS:
        return _result(True, "Nothing about the time service needed putting back.")
    word = _START_WORDS[int(previous)]
    _run_command(["sc", "config", "W32Time", "start=", word], timeout=60)
    if int(previous) == 4:
        _run_command(["sc", "stop", "W32Time"], timeout=60)
    return _result(True, f"The Windows Time service was set back to start {word}. The clock "
                         f"itself was left correct.")


def _do_renew_lease(params, log):
    log("Asking the router for an address again...")
    rc, out, err = _run_command(["ipconfig", "/renew"], timeout=180)
    probe = DeepProbe()
    state = probe.network_config()
    if state.get("has_route"):
        _run_command(["ipconfig", "/flushdns"], timeout=30)
        gateways = ", ".join(state.get("gateways") or []) or "the router"
        return _result(True, f"This PC has an address and a route out through {gateways}.")
    # Renewing an existing self-assigned lease gets the same answer back. The
    # release is what makes Windows ask from scratch, so it is only worth doing
    # once the cheap attempt has visibly failed.
    log("That did not produce a route. Releasing the lease and asking from scratch...")
    _run_command(["ipconfig", "/release"], timeout=120)
    rc, out, err = _run_command(["ipconfig", "/renew"], timeout=180)
    _run_command(["ipconfig", "/flushdns"], timeout=30)
    state = probe.network_config()
    if state.get("has_route"):
        gateways = ", ".join(state.get("gateways") or []) or "the router"
        return _result(True, f"This PC has an address and a route out through {gateways}.")
    return _result(
        False,
        "No router answered, so this PC still has no address. That points at the cable, the "
        "Wi-Fi connection, or DHCP on the router rather than at Windows -- a phone on the same "
        "network settles which in about ten seconds.")


def _do_reset_adapter(params, log):
    name = str(params.get("name", "")).strip()
    if not re.fullmatch(r"[\w \-()#._]{1,64}", name):
        return _result(False, f"{name!r} is not an adapter name.")
    log(f"Restarting the {name} adapter...")
    rc, out, err = _ps_run(
        f"Restart-NetAdapter -Name '{name}' -Confirm:$false -ErrorAction Stop; "
        "Start-Sleep -Seconds 4; Write-Output 'OK'", timeout=120)
    if "OK" not in out:
        return _result(False, f"Windows refused to restart the adapter: "
                              f"{(out + err).strip()[-200:]}")
    _run_command(["ipconfig", "/flushdns"], timeout=30)
    return _result(True, f"{name} was restarted. Its error counters start from zero again, so "
                         f"a re-check now measures the link as it is from this moment.")


# -- network -----------------------------------------------------------------

def _do_reset_winsock(params, log):
    """Put the network stack back to the state Windows ships."""
    log("Resetting the Winsock catalog...")
    rc, out, err = _run_command(["netsh", "winsock", "reset"], timeout=120)
    if rc != 0:
        return _result(False, "The network stack could not be reset: "
                              + (err or out or "administrator rights are needed").strip()[:200])
    return _result(
        True,
        "The network stack is back to its default layers. Anything a VPN or filtering product "
        "had inserted is gone, so those may need reinstalling. This only takes effect after a "
        "restart.",
        needs_restart=True)


def _do_flush_dns(params, log):
    """Throw away cached name lookups."""
    log("Clearing the DNS cache...")
    rc, out, err = _run_command(["ipconfig", "/flushdns"], timeout=60)
    if rc != 0:
        return _result(False, "The cache could not be cleared: " + (err or out or "").strip()[:160])
    return _result(True, "The DNS cache is empty, so the next lookup for every name asks the "
                         "server again rather than reusing a stale answer.")


def _do_set_network_private(params, log):
    """Move a connection from the Public profile to Private."""
    index = str(params.get("index", "")).strip()
    if not index.isdigit():
        return _result(False, f"{index!r} is not an interface number.")
    rc, out, err = _ps_run(
        f"$p=Get-NetConnectionProfile -InterfaceIndex {index} -ErrorAction Stop;"
        f"Write-Output ('WAS|'+$p.NetworkCategory);"
        f"Set-NetConnectionProfile -InterfaceIndex {index} -NetworkCategory Private", timeout=60)
    if rc != 0:
        return _result(False, "The connection profile could not be changed: "
                              + (err or out or "").strip()[:200])
    was = ""
    for line in (out or "").splitlines():
        if line.startswith("WAS|"):
            was = line.split("|", 1)[1].strip()
    return _result(
        True,
        "The connection is on the Private profile now, so file sharing and device discovery "
        "work again. Only do this on a network you trust.",
        undo={"kind": "netprofile", "index": index, "category": was or "Public"})


def _undo_set_network_private(payload, log):
    index = str(payload.get("index", "")).strip()
    category = str(payload.get("category", "")).strip()
    if not index.isdigit() or category not in ("Public", "Private", "DomainAuthenticated"):
        return _result(False, "The recorded profile could not be put back.")
    if category == "DomainAuthenticated":
        return _result(False, "This connection was on a domain profile, which Windows sets "
                              "itself and will restore when the domain is next reachable.")
    rc, out, err = _ps_run(
        f"Set-NetConnectionProfile -InterfaceIndex {index} -NetworkCategory {category}",
        timeout=60)
    if rc != 0:
        return _result(False, (err or out or "").strip()[:200])
    return _result(True, f"The connection is back on the {category} profile.")


def _do_set_mtu(params, log):
    """Put an adapter's packet size back to the standard 1500."""
    name = str(params.get("interface", "")).strip()
    if not name or not re.fullmatch(r"[A-Za-z0-9 ._#()\-]{1,64}", name):
        return _result(False, f"{name!r} is not an interface name.")
    try:
        mtu = int(params.get("mtu", 1500))
    except (TypeError, ValueError):
        return _result(False, "The packet size has to be a number.")
    if not 576 <= mtu <= 9014:
        return _result(False, f"{mtu} is outside the range a network interface accepts.")
    previous = None
    rc, out, _ = _run_command(
        ["netsh", "interface", "ipv4", "show", "subinterfaces"], timeout=30)
    if rc == 0:
        for line in (out or "").splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0].isdigit() and " ".join(parts[4:]).strip() == name:
                previous = int(parts[0])
                break
    log(f"Setting {name} to a {mtu}-byte packet size...")
    rc, out, err = _run_command(
        ["netsh", "interface", "ipv4", "set", "subinterface", name,
         f"mtu={mtu}", "store=persistent"], timeout=60)
    if rc != 0:
        return _result(False, "The packet size could not be changed: "
                              + (err or out or "").strip()[:200])
    return _result(
        True,
        f"{name} is set to {mtu} bytes, which is the standard size. Transfers that were "
        f"stalling part-way should complete now.",
        undo={"kind": "mtu", "interface": name, "mtu": previous} if previous else None)


def _undo_set_mtu(payload, log):
    name = str(payload.get("interface", "")).strip()
    mtu = payload.get("mtu")
    if not name or not isinstance(mtu, int):
        return _result(False, "The old packet size was not recorded.")
    _run_command(["netsh", "interface", "ipv4", "set", "subinterface", name,
                  f"mtu={mtu}", "store=persistent"], timeout=60)
    return _result(True, f"{name} is back to a {mtu}-byte packet size.")
