"""WinMend diagnostics: rules: network stack."""

from __future__ import annotations

from winmend.diagnostics.models import Hypothesis, repair_action, task_action
from winmend.diagnostics.rules.registry import rule


# -- network -----------------------------------------------------------------

@rule
def rule_dns_hijacked(ctx):
    """Something is answering for every domain, including ones that cannot exist."""
    resolution = ctx.get("dns_resolution", {})
    if not resolution.get("available") or not resolution.get("hijacked"):
        return None
    address = resolution.get("wildcard_address", "")
    servers = ctx.get("dns_servers", {})
    interfaces = (servers.get("interfaces") or []) if servers.get("available") else []
    # The collector reports servers per interface; this used to read a flat
    # "servers" list that does not exist, so the sentence below never showed.
    configured = list(dict.fromkeys(
        s.get("address", "") for entry in interfaces for s in entry.get("servers", [])))
    typed_in = any(entry.get("source") == "static" for entry in interfaces)
    return Hypothesis(
        "dns_hijacked",
        "Name lookups are being answered by something that should not be answering",
        (f"A made-up name that cannot exist anywhere was answered with the address {address}. "
         f"A correctly working resolver returns \"no such name\" for that. Something in the "
         f"path is replying for every domain instead: an ISP's advertising or search page, a "
         f"captive portal that has not been signed into, or adware that pointed this PC at a "
         f"resolver of its own."
         + (f" The configured servers are {', '.join(configured[:3])}." if configured else "")),
        confidence=85, severity="high",
        evidence_keys=["dns_resolution", "dns_config"],
        # "Back to automatic" only changes something when a server was typed in
        # on this PC; when the network hands out the resolver doing this, the
        # way out is a different resolver.
        actions=[repair_action("reset_dns_servers", {},
                               reason="Put name lookups back on the router's own servers.")
                 if typed_in or not interfaces else
                 task_action("change_dns", "Use a public resolver instead of the one the "
                                           "network hands out."),
                 repair_action("flush_dns_cache", {},
                               reason="Throw away the answers that were cached from it."),
                 task_action("defender_scan", "Rule out adware that changed the resolver.")],
        advice=("If this is a hotel or cafe network, open a browser and sign in -- the portal "
                "does this deliberately and it stops once you are through."),
    )


@rule
def rule_dns_dead(ctx):
    """Nothing resolves at all."""
    resolution = ctx.get("dns_resolution", {})
    if not resolution.get("available"):
        return None
    if resolution.get("resolved") or not resolution.get("attempted"):
        return None
    profile = ctx.get("network_profile", {})
    reachable = (ctx.get("network", {}) or {}).get("reachable")
    if profile.get("available") and not profile.get("internet") and profile.get("local_only"):
        # There is no internet at all, so failing lookups are the consequence
        # rather than the fault. rule_captive_portal owns that case.
        return None
    services = ctx.get("service_health", {})
    stopped = [s for s in (services.get("critical_stopped") or [])
               if s.get("name") in ("Dnscache", "nsi")]
    return Hypothesis(
        "dns_dead",
        "Names cannot be looked up",
        ("Not one name would resolve. Every program will report being offline, and websites "
         "fail with a \"cannot find the server\" message even though the connection itself "
         "may be fine."
         + (f" The {stopped[0]['display']} service is stopped, which is enough on its own."
            if stopped else "")
         + ("" if reachable is None else
            " The network itself is reachable." if reachable else
            " The network is not reachable either, so this may be downstream of that.")),
        confidence=85 if stopped else 70, severity="high",
        evidence_keys=["dns_resolution", "dns", "dns_config"],
        actions=([repair_action("restart_service", {"name": stopped[0]["name"]},
                                title=f"Start {stopped[0]['display']}",
                                reason="Name lookups cannot work while it is stopped.")]
                 if stopped else [])
                + [repair_action("flush_dns_cache", {},
                                 reason="Clear cached failures before retesting."),
                   repair_action("reset_dns_servers", {},
                                 reason="Go back to the servers the router hands out."),
                   task_action("change_dns", "Try a public resolver if the router's is broken.")],
    )


@rule
def rule_broken_winsock(ctx):
    """The network stack routes through a file that is no longer there."""
    winsock = ctx.get("winsock_health", {})
    broken = winsock.get("broken") or []
    if not winsock.get("available") or not broken:
        return None
    modules = ", ".join(entry["module"] for entry in broken[:3])
    return Hypothesis(
        "broken_winsock",
        "The network stack is routing through a missing file",
        (f"Every socket this PC opens is passed through {modules}, and that file no longer "
         f"exists. Something -- usually a VPN, a firewall, or a parental-control product -- "
         f"was uninstalled without removing its layer from the catalog. Programs report being "
         f"connected, the adapter looks fine, and nothing loads. No other check on this PC can "
         f"see this."),
        confidence=90, severity="critical",
        evidence_keys=["winsock", "reachability", "dns_resolution"],
        actions=[repair_action("reset_winsock", {},
                               reason="Put the catalog back to the layers Windows ships.")],
        advice=("After the restart, any VPN or filtering software you still use will need "
                "reinstalling -- resetting the catalog removes its layer along with the "
                "broken one."),
    )


@rule
def rule_captive_portal(ctx):
    """The local network answers but the internet does not."""
    profile = ctx.get("network_profile", {})
    if not profile.get("available") or profile.get("internet"):
        return None
    local_only = profile.get("local_only") or []
    if not local_only:
        return None
    interface = local_only[0]["interface"]
    scope = ctx.answer("net_scope")
    return Hypothesis(
        "captive_portal",
        "This PC reaches the network but not the internet",
        (f"Windows' own connectivity check reports {interface} as local-only: the router "
         f"answers, addresses work, and nothing beyond the router responds. That is either a "
         f"portal waiting to be signed into, or the connection upstream of the router being "
         f"down."
         + (" You said other devices are affected too, which puts the fault at the router or "
            "the line rather than on this PC." if scope == "others_too" else
            " You said other devices work, so something on this PC is being blocked "
            "specifically -- a firewall rule, a VPN, or a proxy." if scope == "others_fine"
            else "")),
        confidence=80, severity="high",
        evidence_keys=["connection_profile", "reachability", "dns_resolution"],
        actions=([task_action("network_diagnostic_bundle",
                              "Capture the full picture of what is and is not reachable.")]
                 if scope == "others_too" else
                 [repair_action("clear_proxy", {},
                                reason="A proxy left behind blocks exactly this way."),
                  repair_action("renew_lease", {},
                                reason="Ask the router for a fresh address and gateway."),
                  task_action("network_diagnostic_bundle", "Capture the full picture.")]),
        advice=("Open a browser and try any http:// address -- if a sign-in page appears, that "
                "is the portal and signing in fixes it. If every device is affected, restart "
                "the router and check the line."),
        # Resetting this PC's stack cannot fix a fault that is upstream of it.
        suppress=(["reset_network", "reset_winsock", "deep_network_remediation"]
                  if scope == "others_too" else []),
        suppress_reason=("You said every device on the network is affected, so the fault is the "
                         "router or the line. Resetting this PC's networking would change "
                         "nothing and would lose your saved Wi-Fi networks."),
    )


@rule
def rule_metered_connection(ctx):
    """A metered connection silently stops updates and Store downloads."""
    profile = ctx.get("network_profile", {})
    metered = profile.get("metered") or []
    if not profile.get("available") or not metered:
        return None
    relevant = ("updates" in ctx.parts or "apps" in ctx.parts or ctx.audit
                or ctx.mentions("update", "download", "store", "install"))
    if not relevant:
        return None
    return Hypothesis(
        "metered_connection",
        "The connection is marked as metered",
        (f"{' and '.join(metered)} is set as a metered connection. Windows treats that as "
         f"\"this data costs money\", so it holds back updates, stops Store apps downloading, "
         f"and pauses OneDrive -- all without reporting an error anywhere. Everything looks "
         f"like it is working and nothing arrives."),
        confidence=80, severity="medium",
        evidence_keys=["connection_profile", "update_state"],
        # Deliberately no repair action. The metered flag lives in a key owned by
        # TrustedInstaller, and a repair that takes ownership of a protected
        # registry key to flip a user preference is a worse idea than a sentence
        # telling the user exactly where the switch is.
        actions=[task_action("windows_updates", "Check for updates once it is switched off.")],
        advice=("Settings > Network & internet > your connection > Metered connection. Turn it "
                "off there, then check for updates. WinMend does not change this itself: the "
                "setting is protected, and reaching it needs changes to Windows' own "
                "permissions that are not worth making for a preference."),
    )


@rule
def rule_public_profile(ctx):
    """A home network stuck on the Public profile blocks sharing and discovery."""
    profile = ctx.get("network_profile", {})
    public = profile.get("public") or []
    if not profile.get("available") or not public:
        return None
    if not ctx.mentions("share", "sharing", "network drive", "shared", "discover", "see other",
                        "cast", "printer", "nas", "remote"):
        return None
    first = public[0]
    return Hypothesis(
        "public_profile",
        f"{first['interface']} is on the Public network profile",
        (f"Windows has {first['interface']} classified as a public network, which blocks file "
         f"and printer sharing and hides this PC from other devices. That is the correct "
         f"setting on a cafe or hotel network and the wrong one at home -- and Windows picks "
         f"it by default whenever it is not sure."),
        confidence=75, severity="medium",
        evidence_keys=["connection_profile"],
        actions=[repair_action("set_network_private", {"index": first.get("index", "")},
                               title=f"Set {first['interface']} to Private",
                               reason="Allow sharing and discovery on this network.")],
        advice="Only do this on a network you own or trust. On public Wi-Fi, leave it as it is.",
    )


@rule
def rule_odd_mtu(ctx):
    """A physical adapter set to a non-standard packet size."""
    mtu = ctx.get("interface_mtu", {})
    odd = mtu.get("nonstandard") or []
    if not mtu.get("available") or not odd:
        return None
    first = odd[0]
    return Hypothesis(
        "odd_mtu",
        f"{first['interface']} is using a non-standard packet size",
        (f"{first['interface']} is set to {first['mtu']} bytes instead of the standard 1500. "
         f"Too small and every large transfer is slower than it should be; too large and "
         f"packets get silently dropped somewhere along the path, so small pages load "
         f"instantly and anything big hangs forever. It is the fault that looks like \"half "
         f"the internet works\", and no reachability test catches it."),
        confidence=70, severity="medium",
        evidence_keys=["mtu", "net_quality"],
        actions=[repair_action("set_mtu",
                               {"interface": first["interface"], "mtu": 1500},
                               title=f"Set {first['interface']} back to 1500",
                               reason="Use the standard packet size.")],
        advice=("If you set this yourself for a PPPoE connection or a VPN, 1492 is the usual "
                "correct value and this is not a fault."),
    )
