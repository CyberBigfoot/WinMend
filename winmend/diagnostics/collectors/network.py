"""WinMend diagnostics: collectors: network."""

from __future__ import annotations

from pathlib import Path
from winmend.diagnostics.helpers import _is_private_address
from winmend.diagnostics.reference import (
    KNOWN_DNS,
    PROTECTED_HOSTS,
    _VIRTUAL_ADAPTERS,
    _WINSOCK_STOCK,
)
import os
import re
import socket
import time
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


class ProbeNetworkMixin:
    """DeepProbe methods grouped by responsibility."""

    def hosts_file(self):
        """Non-comment hosts entries, flagging blocks of update/security domains."""
        path = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return {"available": False, "reason": str(exc)[:120]}
        entries = []
        blocked = []
        for line in text.splitlines():
            stripped = line.split("#", 1)[0].strip()
            if not stripped:
                continue
            parts = stripped.split()
            if len(parts) < 2:
                continue
            address = parts[0]
            for host in parts[1:]:
                entries.append({"address": address, "host": host})
                lowered = host.lower()
                if any(lowered == d or lowered.endswith("." + d) for d in PROTECTED_HOSTS):
                    blocked.append({"address": address, "host": host})
        return {
            "available": True,
            "path": str(path),
            "entries": len(entries),
            "blocked": blocked,
            "sample": entries[:12],
        }

    def proxy_settings(self):
        """A proxy the user does not know about is a classic 'no internet' cause."""
        if winreg is None:
            return {"available": False}
        result = {"available": True, "enabled": False, "server": "", "autoconfig": "",
                  "pac_or_proxy": False}
        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            ) as key:
                for name, field in (("ProxyEnable", "enabled"),
                                    ("ProxyServer", "server"),
                                    ("AutoConfigURL", "autoconfig")):
                    try:
                        value = winreg.QueryValueEx(key, name)[0]
                    except OSError:
                        continue
                    result[field] = bool(value) if field == "enabled" else str(value)
        except OSError:
            return {"available": False}
        result["pac_or_proxy"] = bool(
            (result["enabled"] and result["server"]) or result["autoconfig"])
        return result

    # Adapters that belong to a VPN client. The resolver a VPN hands out is the
    # VPN's business, and usually one no list of public resolvers could know.
    _VPN_ADAPTER_WORDS = ("vpn", "tap-windows", "wireguard", "wintun", "tailscale", "twingate",
                          "zerotier", "anyconnect", "globalprotect", "pangp", "fortinet",
                          "nordlynx", "warp", "zscaler", "hamachi")

    def dns_servers(self):
        """Configured DNS servers per active interface, with recognition.

        Each interface also records where its servers came from -- typed into
        this PC ("static") or handed out by the network ("dhcp") -- and whether
        it is a VPN's adapter. Only static, public, unknown servers count as
        unrecognised. The old check flagged a VPN's resolver (Twingate's
        100.95.0.x) as a hijack and offered "Return DNS to automatic", which
        cannot change a server the network hands out in the first place.
        """
        script = r'''
        Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.ServerAddresses.Count -gt 0 } | ForEach-Object {
                $source = 'unknown'; $desc = ''
                $a = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue
                if ($a) {
                    $desc = "$($a.InterfaceDescription)" -replace '\|', '/'
                    $k = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($a.InterfaceGuid)"
                    $p = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
                    if ($p) { $source = if ("$($p.NameServer)".Trim()) { 'static' } else { 'dhcp' } }
                }
                Write-Output ($_.InterfaceAlias + '|' + ($_.ServerAddresses -join ',') + '|' + $source + '|' + $desc)
            }
        '''
        rc, rows, err = self._ps_rows(script, timeout=25)
        if rc != 0 and not rows:
            return {"available": False, "reason": err[:200]}
        interfaces = []
        unknown = []
        from_network = []
        for row in rows:
            if len(row) < 2:
                continue
            alias = row[0].strip()
            source = row[2].strip() if len(row) > 2 else "unknown"
            description = row[3].strip() if len(row) > 3 else ""
            vpn = any(word in f"{alias} {description}".lower() for word in self._VPN_ADAPTER_WORDS)
            servers = [s.strip() for s in row[1].split(",") if s.strip()]
            named = []
            for server in servers:
                label = KNOWN_DNS.get(server)
                if label is None and not _is_private_address(server) and not vpn:
                    (from_network if source == "dhcp" else unknown).append(server)
                named.append({"address": server, "known": label or ""})
            interfaces.append({"interface": alias, "servers": named, "source": source,
                               "vpn": vpn, "description": description})
        return {"available": True, "interfaces": interfaces, "unrecognised": unknown,
                "from_network": from_network}

    def wifi_link(self):
        """Signal strength, band, and radio type for the active wireless link."""
        rc, out, _ = self._run(["netsh", "wlan", "show", "interfaces"], timeout=15)
        if rc != 0 or "SSID" not in out:
            return {"available": False}
        fields = {}
        for line in out.splitlines():
            name, sep, value = line.partition(":")
            if not sep:
                continue
            fields[name.strip().lower()] = value.strip()
        signal = fields.get("signal", "")
        percent = None
        match = re.search(r"(\d+)", signal)
        if match:
            percent = int(match.group(1))
        band = fields.get("band", "")
        channel = fields.get("channel", "")
        if not band and channel.isdigit():
            band = "2.4 GHz" if int(channel) <= 14 else "5 GHz"
        return {
            "available": True,
            "ssid": fields.get("ssid", ""),
            "signal_pct": percent,
            "band": band,
            "channel": channel,
            "radio": fields.get("radio type", ""),
            "rx_mbps": fields.get("receive rate (mbps)", ""),
            "tx_mbps": fields.get("transmit rate (mbps)", ""),
        }

    def network_config(self):
        """Addresses and default gateway, i.e. whether this PC has a route out.

        ``Get-NetIPConfiguration`` answers the same question and takes about
        five seconds; these two queries take well under one.
        """
        script = (
            "$wmErrors=@(); Get-NetRoute -DestinationPrefix @('0.0.0.0/0','::/0') -PolicyStore ActiveStore -ErrorAction SilentlyContinue -ErrorVariable +wmErrors | "
            "ForEach-Object { Write-Output ('GW|'+[string]$_.InterfaceIndex+'|'+$_.NextHop) };"
            "Get-NetIPAddress -ErrorAction SilentlyContinue -ErrorVariable +wmErrors | Where-Object AddressState -eq 'Preferred' | "
            "ForEach-Object { Write-Output ('IP|'+[string]$_.InterfaceIndex+'|'"
            "+($_.InterfaceAlias -replace '\\|',' ')+'|'+$_.IPAddress+'|'"
            "+[string]$_.PrefixOrigin) };"
            "if(@($wmErrors | Where-Object { $_.FullyQualifiedErrorId -notmatch 'CmdletizationQuery_NotFound' }).Count -eq 0){Write-Output ('done|1')}"
        )
        rc, rows, err = self._ps_rows(script, timeout=30)
        if not any(row[0] == "done" for row in rows):
            return {"available": False, "reason": (err or "")[:200]}
        gateways = {}
        for row in rows:
            if row[0] == "GW" and len(row) > 2 and row[2].strip():
                gateways.setdefault(row[1].strip(), row[2].strip())
        interfaces = []
        for row in rows:
            if row[0] != "IP" or len(row) < 4:
                continue
            address = row[3].strip()
            alias = row[2].strip()
            if address.startswith(("127.", "fe80:", "::1")) or alias.lower().startswith("loopback"):
                continue
            interfaces.append({
                "index": row[1].strip(),
                "interface": alias,
                "address": address,
                "origin": row[4].strip() if len(row) > 4 else "",
                "gateway": gateways.get(row[1].strip(), ""),
                # 169.254.x.x is what Windows assigns itself when DHCP got no
                # answer -- a working address that can reach nothing.
                "self_assigned": address.startswith("169.254."),
            })
        routed = [i for i in interfaces if i["gateway"]]
        return {
            "available": True,
            "interfaces": interfaces,
            "gateways": sorted(set(gateways.values())),
            "has_route": bool(routed),
            # Only a fault when *nothing* has a route. An unplugged second
            # Ethernet port sitting on a self-assigned address is normal, and
            # flagging it would put a permanent warning on any PC with two NICs.
            "self_assigned_only": bool(interfaces) and not routed
            and all(i["self_assigned"] for i in interfaces),
        }

    def adapter_health(self):
        """Link speed and the error and drop counters on each active adapter.

        These counters are cumulative since the last restart, so the rate
        matters and the raw number does not; a handful of errors over a month
        of uptime is a healthy adapter.
        """
        try:
            import psutil
        except Exception:
            return {"available": False}
        try:
            stats = psutil.net_if_stats()
            counters = psutil.net_io_counters(pernic=True)
        except Exception:
            return {"available": False}
        adapters = []
        for name, stat in stats.items():
            if not stat.isup or name.lower().startswith(("loopback", "isatap")):
                continue
            io = counters.get(name)
            if io is None:
                continue
            packets = (io.packets_sent or 0) + (io.packets_recv or 0)
            errors = (io.errin or 0) + (io.errout or 0)
            drops = (io.dropin or 0) + (io.dropout or 0)
            adapters.append({
                "name": name,
                "speed_mbps": int(stat.speed or 0),
                "packets": packets,
                "errors": errors,
                "drops": drops,
                # Below a decent packet count the ratio is meaningless, so it is
                # not computed rather than being computed and then distrusted.
                "error_pct": (round((errors + drops) / packets * 100, 2)
                              if packets >= 50000 else None),
            })
        if not adapters:
            return {"available": False}
        degraded = [a for a in adapters
                    if a["error_pct"] is not None and a["error_pct"] >= 0.5]
        return {"available": True, "adapters": adapters, "degraded": degraded}

    def time_sync(self, hosts=("time.windows.com", "pool.ntp.org"), timeout=2.5):
        """How far this PC's clock is from real time.

        Measured directly with an SNTP query rather than read out of
        ``w32tm``, whose output is localised. A clock that is wrong by more
        than a few minutes breaks HTTPS, Windows Update, and sign-in, and
        presents as half a dozen unrelated-looking symptoms.
        """
        # 1900-01-01 to 1970-01-01, the offset between the NTP and Unix epochs.
        era = 2208988800
        packet = b"\x1b" + 47 * b"\0"
        for host in hosts:
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(float(timeout))
                sent = time.time()
                sock.sendto(packet, (host, 123))
                data, _ = sock.recvfrom(512)
                received = time.time()
            except (OSError, socket.timeout):
                continue
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
            if len(data) < 48:
                continue
            seconds = int.from_bytes(data[40:44], "big")
            fraction = int.from_bytes(data[44:48], "big") / 2 ** 32
            if not seconds:
                continue
            server = seconds + fraction - era
            # Compare against the midpoint of the request, so the round trip
            # itself is not counted as clock error.
            offset = server - (sent + received) / 2
            return {
                "available": True,
                "source": host,
                "offset_seconds": round(offset, 2),
                "service": self.service_state("w32time"),
                "round_trip_ms": round((received - sent) * 1000, 1),
            }
        return {"available": False, "service": self.service_state("w32time")}

    # -- network reality ----------------------------------------------------

    def dns_resolution(self, names=("www.microsoft.com", "cloudflare.com"),
                       bogus="winmend-no-such-host-9f3a2b.invalid"):
        """Bounded public-name checks and a reserved .invalid negative control.

        An unexpected answer to the negative control needs investigation; it
        does not establish malicious tampering or justify changing resolvers.
        Arguments remain for compatibility; the probe uses fixed names only.
        """
        # Fixed public names only; command arguments never contain user text.
        # Resolve-DnsName is bounded by the subprocess timeout, unlike getaddrinfo.
        data = self._ps_json(r"""
            $rows=@();foreach($n in @('www.microsoft.com','cloudflare.com')) {
              $s=[Diagnostics.Stopwatch]::StartNew();
              try{$r=@(Resolve-DnsName -Name $n -DnsOnly -QuickTimeout -ErrorAction Stop);
                $rows+=@{name=$n;ok=(@($r|Where-Object IPAddress).Count -gt 0);ms=$s.Elapsed.TotalMilliseconds}}
              catch{$rows+=@{name=$n;ok=$false;ms=$s.Elapsed.TotalMilliseconds;error=$_.FullyQualifiedErrorId}}
            };
            $negative=@{tested=$false;answered=$null;address=''};
            try{$r=@(Resolve-DnsName -Name 'winmend-no-such-host-9f3a2b.invalid' -DnsOnly -QuickTimeout -ErrorAction Stop);
              $a=@($r|Where-Object IPAddress);
              if($a.Count -gt 0){$negative=@{tested=$true;answered=$true;address=[string]$a[0].IPAddress}}}
            catch{if($_.FullyQualifiedErrorId -match 'DNS_ERROR_RCODE_NAME_ERROR'){
              $negative=@{tested=$true;answered=$false;address=''}}};
            @{available=$true;results=$rows;negative=$negative}|ConvertTo-Json -Compress -Depth 4
        """, timeout=18)
        if not data.get('available'):
            return data
        results = data.get('results') or []
        resolved = sum(r.get('ok') is True for r in results)
        negative = data.get('negative') or {}
        timings = [r['ms'] for r in results if r.get('ok') and isinstance(r.get('ms'), (int, float))]
        slowest = max(timings, default=None)
        return {'available': True, 'results': results, 'resolved': resolved,
                'attempted': len(results), 'failed': len(results)-resolved,
                'slowest_ms': slowest, 'slow': slowest is not None and slowest >= 1000,
                'hijacked': negative.get('answered'),
                'wildcard_address': negative.get('address', ''),
                'wildcard_tested': negative.get('tested', False)}

    def network_profile(self):
        """Windows' own verdict on the connection, plus the two silent blockers.

        ``IPv4Connectivity`` is what the Network Connectivity Status Indicator
        already decided, so it costs no traffic of our own. A *metered*
        connection quietly stops Windows Update and Store downloads without
        reporting an error anywhere, and a connection stuck on the Public
        profile blocks file sharing and device discovery the same way.
        """
        script = (
            "Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object {"
            "$m='';try{$m=(Get-NetConnectionProfile -InterfaceIndex $_.InterfaceIndex)."
            "IPv4Connectivity}catch{};"
            "Write-Output ('NP|'+$_.InterfaceAlias+'|'+$_.NetworkCategory+'|'+"
            "$_.IPv4Connectivity+'|'+$_.IPv6Connectivity+'|'+$_.InterfaceIndex)}"
        )
        ready, rows, _ = self._ps_events(script, timeout=25)
        if not ready:
            return {"available": False}
        profiles = []
        for row in rows:
            if row[0] != "NP" or len(row) < 6:
                continue
            ipv4 = (row[3] or "").strip()
            profiles.append({
                "interface": row[1].strip(),
                "category": row[2].strip(),
                "ipv4": ipv4,
                "ipv6": (row[4] or "").strip(),
                "index": row[5].strip(),
                "internet": ipv4.lower() == "internet" or row[4].strip().lower() == "internet",
                # LocalNetwork means the LAN answers but the internet does not:
                # the signature of a captive portal or a dead upstream link.
                "local_only": (ipv4.lower() == "localnetwork" or row[4].strip().lower() == "localnetwork")
                              and ipv4.lower() != "internet" and row[4].strip().lower() != "internet",
            })
        # Whether a connection counts as metered is a registry policy rather
        # than a property of the profile, so it is read separately.
        metered = []
        if winreg is not None:
            try:
                base = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as key:
                    for name in ("Ethernet", "WiFi"):
                        try:
                            if int(winreg.QueryValueEx(key, name)[0]) == 2:
                                metered.append(name)
                        except (OSError, ValueError, TypeError):
                            continue
            except OSError:
                pass
        connected = [p for p in profiles if p["internet"]]
        return {
            "available": True,
            "profiles": profiles,
            "public": [p for p in profiles if p["category"].lower() == "public"],
            "local_only": [p for p in profiles if p["local_only"]],
            "internet": bool(connected),
            "metered": metered,
        }

    def winsock_health(self):
        """Third-party layers spliced into every socket this PC opens.

        A layered service provider sits between applications and the network
        stack. When one is left behind by an uninstalled VPN or filter, every
        program reports "connected" and nothing loads -- a fault with no error
        message anywhere and no other check that can see it.
        """
        rc, out, _ = self._run(["netsh", "winsock", "show", "catalog"], timeout=25)
        if rc != 0 or not out.strip():
            return {"available": False}
        paths = re.findall(r"Provider Path:\s*(.+)", out)
        entries = []
        for path in paths:
            path = path.strip()
            leaf = os.path.basename(path).lower()
            if leaf in _WINSOCK_STOCK:
                continue
            entries.append({"path": path, "module": leaf})
        seen = {}
        for entry in entries:
            seen.setdefault(entry["module"], entry)
        # A provider whose DLL is gone is the state that breaks everything: the
        # catalog still routes through a file that no longer exists.
        broken = []
        for entry in seen.values():
            expanded = os.path.expandvars(entry["path"])
            if expanded and not os.path.exists(expanded):
                broken.append(entry)
        return {
            "available": True,
            "total": len(paths),
            "third_party": sorted(seen.values(), key=lambda item: item["module"]),
            "broken": broken,
        }

    def interface_mtu(self):
        """Interfaces whose packet size has been changed away from standard.

        A too-small MTU makes big transfers crawl; a too-large one makes some
        sites hang forever while small ones load instantly -- the classic
        "half the internet works" complaint that no reachability test catches.
        """
        rc, out, _ = self._run(
            ["netsh", "interface", "ipv4", "show", "subinterfaces"], timeout=15)
        if rc != 0 or not out.strip():
            return {"available": False}
        rows = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 5 or not parts[0].isdigit():
                continue
            name = " ".join(parts[4:]).strip()
            mtu = int(parts[0])
            lowered = name.lower()
            if lowered.startswith("loopback"):
                continue
            rows.append({
                "interface": name,
                "mtu": mtu,
                # Tunnels legitimately run small (Tailscale ships 1280, PPPoE
                # 1492), so only a physical adapter off standard is a fault.
                "virtual": any(word in lowered for word in _VIRTUAL_ADAPTERS),
            })
        odd = [row for row in rows
               if not row["virtual"] and row["mtu"] not in (1500, 1492) and row["mtu"] < 9000]
        return {"available": True, "interfaces": rows, "nonstandard": odd}
