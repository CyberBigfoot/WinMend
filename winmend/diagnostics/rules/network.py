"""WinMend diagnostics: rules: network."""

from __future__ import annotations

from winmend.diagnostics.models import Hypothesis, repair_action, task_action
from winmend.diagnostics.rules.registry import rule


# -- network -----------------------------------------------------------------

@rule
def rule_upstream_network(ctx):
    """If every device is affected, nothing done on this PC can help."""
    if ctx.answer("net_scope") != "others_too":
        return None
    return Hypothesis(
        "upstream_network",
        "A shared network or upstream problem is possible",
        "You report that other devices are affected. Compare the router and provider with this PC's measurements; that report alone cannot exclude a local fault.",
        confidence=88,
        severity="high",
        evidence_keys=["reachability", "net_quality"],
        actions=[task_action("network_diagnostic_bundle",
                             "Collect the evidence to show your provider.")],
        advice=("Restart the router and modem (30 seconds unplugged). If that does not fix it, "
                "contact your internet provider -- repairs on this PC cannot help."),
        suppress=["reset_network", "deep_network_remediation", "network_adapter_reset"],
        suppress_reason=("Withheld because the problem affects every device on the network. "
                         "Resetting this PC's network stack cannot fix a router or line fault, "
                         "and it will disconnect you while it runs."),
    )


@rule
def rule_rogue_proxy(ctx):
    proxy = ctx.get("proxy_settings", {})
    if not proxy.get("available") or not proxy.get("pac_or_proxy"):
        return None
    detail = []
    if proxy.get("enabled") and proxy.get("server"):
        detail.append(f"a proxy server is set ({proxy['server']})")
    if proxy.get("autoconfig"):
        detail.append(f"an automatic configuration script is set ({proxy['autoconfig']})")
    return Hypothesis(
        "rogue_proxy",
        "A proxy is configured on this PC",
        "Windows is routing web traffic through a proxy: " + " and ".join(detail) + ". "
        "If you did not set this up deliberately, it is a very common cause of "
        "'connected but nothing loads' -- and a common leftover from adware or an "
        "uninstalled VPN.",
        confidence=80,
        severity="high",
        evidence_keys=["proxy"],
        actions=[repair_action(
            "clear_proxy", {},
            title="Clear the proxy configuration",
            reason="Send web traffic directly again. The old settings are recorded so this can be undone.")],
        advice="If your workplace or school requires this proxy, skip this step.",
    )


@rule
def rule_hosts_hijack(ctx):
    hosts = ctx.get("hosts_file", {})
    if not hosts.get("available"):
        return None
    blocked = hosts.get("blocked") or []
    if not blocked:
        return None
    names = ", ".join(sorted({b["host"] for b in blocked})[:5])
    return Hypothesis(
        "hosts_hijack",
        "The hosts file is blocking update or security sites",
        f"{len(blocked)} {'entry' if len(blocked) == 1 else 'entries'} in the Windows hosts file "
        f"redirect security or update domains: {names}. Blocking exactly these is a standard "
        f"malware technique to stop a PC from being cleaned or patched.",
        confidence=85,
        severity="critical",
        evidence_keys=["hosts"],
        actions=[repair_action(
            "restore_hosts", {},
            title="Restore the default hosts file",
            reason="Stop the redirection. The current file is backed up first.")],
        advice=("Some ad-blocking tools legitimately write hosts entries -- but not for "
                "windowsupdate or antivirus domains. Follow this with a full malware scan."),
    )


@rule
def rule_weak_wifi(ctx):
    link = ctx.get("wifi_link", {})
    if not link.get("available"):
        return None
    signal = link.get("signal_pct")
    if signal is None or signal >= 45:
        return None
    band = link.get("band", "")
    return Hypothesis(
        "weak_wifi",
        "Low Wi-Fi signal may affect reliability",
        f"The link to \"{link.get('ssid', 'your network')}\" is at {signal}% signal"
        + (f" on {band}" if band else "")
        + ". Signal percentages vary by adapter. Repeated link quality or disconnection records are needed to establish that this is causing the symptom.",
        confidence=85,
        severity="high",
        evidence_keys=["wifi_link"],
        actions=[task_action("wlan_report", "Collect the Wi-Fi connection and disconnect history.")],
        advice=("Move closer to the router, or move the router away from metal and microwaves. "
                + ("5 GHz is faster but much weaker through walls -- at this distance the "
                   "2.4 GHz band would be more stable." if "5" in band else
                   "If the router offers a 5 GHz band and you are close to it, that band is faster.")),
        suppress=["reset_network", "deep_network_remediation"],
        suppress_reason=("Withheld because the measured signal is too weak for the connection to "
                         "work reliably regardless of software state. Fix the signal first, or "
                         "these resets will appear to fail."),
    )


@rule
def rule_rogue_dns(ctx):
    dns = ctx.get("dns_servers", {})
    if not dns.get("available"):
        return None
    unknown = dns.get("unrecognised") or []
    if not unknown:
        return None
    return Hypothesis(
        "rogue_dns",
        "Unrecognised DNS servers are configured",
        "DNS servers that are neither your router, a VPN, nor a well-known public resolver "
        f"have been set on this PC: {', '.join(sorted(set(unknown))[:4])}. DNS decides which "
        "server every website name points at, so a hijacked setting can redirect traffic "
        "invisibly.",
        confidence=60,
        severity="high",
        evidence_keys=["dns_config"],
        actions=[repair_action(
            "reset_dns_servers", {},
            title="Return DNS to automatic",
            reason="Use the router's DNS again. The current values are recorded so this can be undone.")],
        advice="If you set these deliberately (a family filter, a work resolver), skip this step.",
    )
