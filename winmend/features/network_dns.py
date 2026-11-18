"""WinMend features: network dns."""

from __future__ import annotations




# ---------------------------------------------------------------------------
# Public DNS providers
#
# Addresses taken from Chris Titus's WinUtil (config/dns.json), which is where
# they are kept current. Only resolvers a person might actually want are listed:
# each entry says plainly what it does, because "faster DNS" and "DNS that
# blocks things" are different decisions and the filtering ones can break sites.
# ---------------------------------------------------------------------------

DNS_PROVIDERS = [
    {"id": "cloudflare", "name": "Cloudflare",
     "detail": "Fast, privacy-focused. Blocks nothing.",
     "v4": ("1.1.1.1", "1.0.0.1"),
     "v6": ("2606:4700:4700::1111", "2606:4700:4700::1001"),
     "doh": "https://cloudflare-dns.com/dns-query"},
    {"id": "cloudflare_malware", "name": "Cloudflare — malware blocking",
     "detail": "Cloudflare, plus known malware domains refused.",
     "v4": ("1.1.1.2", "1.0.0.2"),
     "v6": ("2606:4700:4700::1112", "2606:4700:4700::1002"),
     "doh": "https://security.cloudflare-dns.com/dns-query"},
    {"id": "cloudflare_family", "name": "Cloudflare — malware + adult",
     "detail": "Also refuses adult content. Can block sites you wanted.",
     "v4": ("1.1.1.3", "1.0.0.3"),
     "v6": ("2606:4700:4700::1113", "2606:4700:4700::1003"),
     "doh": "https://family.cloudflare-dns.com/dns-query"},
    {"id": "google", "name": "Google Public DNS",
     "detail": "Fast and very widely used. Blocks nothing.",
     "v4": ("8.8.8.8", "8.8.4.4"),
     "v6": ("2001:4860:4860::8888", "2001:4860:4860::8844"),
     "doh": "https://dns.google/dns-query"},
    {"id": "quad9", "name": "Quad9",
     "detail": "Swiss non-profit; blocks malicious domains.",
     "v4": ("9.9.9.9", "149.112.112.112"),
     "v6": ("2620:fe::fe", "2620:fe::9"),
     "doh": "https://dns.quad9.net/dns-query"},
    {"id": "opendns", "name": "OpenDNS",
     "detail": "Cisco's resolver, with optional filtering via an account.",
     "v4": ("208.67.222.222", "208.67.220.220"),
     "v6": ("2620:119:35::35", "2620:119:53::53"),
     "doh": "https://doh.opendns.com/dns-query"},
    {"id": "adguard", "name": "AdGuard — ads + trackers",
     "detail": "Refuses ad and tracker domains network-wide.",
     "v4": ("94.140.14.14", "94.140.15.15"),
     "v6": ("2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"),
     "doh": "https://dns.adguard-dns.com/dns-query"},
    {"id": "adguard_family", "name": "AdGuard — ads, trackers + adult",
     "detail": "AdGuard filtering plus adult content. Most aggressive here.",
     "v4": ("94.140.14.15", "94.140.15.16"),
     "v6": ("2a10:50c0::bad1:ff", "2a10:50c0::bad2:ff"),
     "doh": "https://family.adguard-dns.com/dns-query"},
]


def dns_provider(provider_id):
    return next((p for p in DNS_PROVIDERS if p["id"] == provider_id), None)
