"""WinMend features: network."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from winmend.core.processes import _no_console_startupinfo, wm_run
from winmend.core.prompts import messagebox, simpledialog
from winmend.core.search import _wm_last_line
from winmend.features.network_dns import DNS_PROVIDERS, dns_provider
from winmend.features.office.helpers import service_state
import os
import re
import shutil
import subprocess
import time
import webbrowser


class NetworkTasks:
    """SystemCleanerGUI methods grouped by responsibility."""

    def reset_network_stack(self):
        """Reset Winsock catalog and TCP/IP stack to fix deep network issues"""
        label = "Reset Network Stack"
        self.queue.put(f"PROGRESS:{label}:Starting network stack reset...")
        self.queue.put(f"PROGRESS:{label}:This will reset Winsock and TCP/IP. A restart is required after.")

        try:
            reset_done = False
            self.queue.put(f"PROGRESS:{label}:Step 1: Resetting Winsock catalog...")
            rc, _ = self._run_live_command(['netsh', 'winsock', 'reset'], label, timeout=60)
            if rc == 0:
                reset_done = True
                self.queue.put(f"PROGRESS:{label}:Winsock catalog reset successfully")
            elif not self.cancel_event.is_set():
                self._report_failure(f"PROGRESS:{label}:Winsock reset failed (code {rc}).")

            self.queue.put(f"PROGRESS:{label}:Step 2: Resetting TCP/IP stack...")
            rc, _ = self._run_live_command(['netsh', 'int', 'ip', 'reset'], label, timeout=60)
            if rc == 0:
                reset_done = True
                self.queue.put(f"PROGRESS:{label}:TCP/IP stack reset successfully")
            elif not self.cancel_event.is_set():
                self._report_failure(f"PROGRESS:{label}:TCP/IP reset finished with code {rc} -- the lines "
                               f"above show which settings could not be reset.")

            self.queue.put(f"PROGRESS:{label}:Step 3: Resetting IPv6 stack...")
            rc, _ = self._run_live_command(['netsh', 'int', 'ipv6', 'reset'], label, timeout=60)
            if rc != 0 and not self.cancel_event.is_set():
                self._report_failure(f"PROGRESS:{label}:IPv6 reset failed (code {rc}).")

            self.queue.put(f"PROGRESS:{label}:Step 4: Flushing DNS cache...")
            rc, _ = self._run_live_command(['ipconfig', '/flushdns'], label, timeout=30)
            if rc != 0 and not self.cancel_event.is_set():
                self._report_failure(f"PROGRESS:{label}:DNS cache flush failed (code {rc}).")

            self.queue.put(f"PROGRESS:{label}:Network stack reset complete.")
            if reset_done:
                self.queue.put(f"REBOOTRECOMMEND:{label}:The network stack was reset; Windows "
                               f"only rebuilds it at the next restart.")

        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error resetting network stack: {str(e)}")

    def run_reset_hosts(self):
        """Resets the Windows Hosts file to its default state, keeping a backup."""
        label = "Reset Hosts File"
        self.queue.put(f"PROGRESS:{label}:Resetting Windows Hosts file to default...")
        try:
            hosts_path = os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'System32', 'drivers', 'etc', 'hosts')
            original_content = """# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
"""
            try:
                with open(hosts_path, 'r', encoding='utf-8', errors='replace') as f:
                    current = f.read()
            except FileNotFoundError:
                current = None

            def _entries(text):
                return [line.split() for line in (text or "").splitlines()
                        if line.strip() and not line.lstrip().startswith("#")]

            if current is not None and not _entries(current):
                self.queue.put(f"PROGRESS:{label}:The hosts file has no entries -- it is already "
                               f"at the Windows default. Nothing was changed.")
                return

            # Keep what was there. A hosts file also holds entries people add
            # on purpose -- development sites, ad blocking, work servers -- and
            # System Restore does not cover this file.
            if current is not None:
                backup_dir = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')),
                                          'WinMend', 'Backups')
                os.makedirs(backup_dir, exist_ok=True)
                backup = os.path.join(backup_dir, f"hosts_{time.strftime('%Y%m%d_%H%M%S')}.txt")
                shutil.copy2(hosts_path, backup)
                self.queue.put(f"PROGRESS:{label}:Backed up the current file ({len(_entries(current))} "
                               f"entries) to {backup}")

            try:
                with open(hosts_path, 'w', encoding='utf-8') as f:
                    f.write(original_content)
            except PermissionError:
                # Malware sometimes takes the file over so it cannot be reset.
                # Only then take ownership back for Administrators and retry.
                self.queue.put(f"PROGRESS:{label}:The file is locked against changes; taking "
                               f"ownership back for Administrators...")
                wm_run(['takeown', '/f', hosts_path, '/a'], capture_output=True,
                       startupinfo=_no_console_startupinfo())
                wm_run(['icacls', hosts_path, '/grant', 'Administrators:F'], capture_output=True,
                       startupinfo=_no_console_startupinfo())
                with open(hosts_path, 'w', encoding='utf-8') as f:
                    f.write(original_content)

            with open(hosts_path, 'r', encoding='utf-8', errors='replace') as f:
                if _entries(f.read()):
                    self._report_failure(f"PROGRESS:{label}:The hosts file still has entries after "
                                         f"the reset -- something rewrote it.")
                    return
            self.queue.put(f"PROGRESS:{label}:Hosts file reset to default")
            if current is not None:
                self.queue.put(f"PROGRESS:{label}:  Undo: copy the backup above over {hosts_path}")

            # Flush DNS after resetting hosts
            self.queue.put(f"PROGRESS:{label}:Flushing DNS cache...")
            wm_run(['ipconfig', '/flushdns'], capture_output=True, startupinfo=_no_console_startupinfo())

        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Failed to reset hosts file - {str(e)}")

    def run_export_wifi_passwords(self):
        # Never into a folder that syncs to the cloud: a plaintext password file
        # on a OneDrive Desktop uploads the moment it is written.
        export_dir = self._get_desktop_dir()
        if self._is_cloud_synced(export_dir):
            export_dir = os.path.expanduser("~")
        export_file = os.path.join(export_dir, "WiFi_Passwords_Export.txt")
        if not messagebox.askyesno(
            "Security Warning",
            "This operation can export saved Wi-Fi passwords in plain text.\n\n"
            "Only proceed on your own trusted machine and only when necessary.\n\n"
            f"The file will be saved on this PC only (not in OneDrive):\n{export_file}\n"
            "Delete it when you are done with it.\n\n"
            "Continue?"
        ):
            self._report_skip("PROGRESS:Wi-Fi Export:Export cancelled by user.")
            return

        gate_text = simpledialog.askstring(
            "Sensitive Operation Confirmation",
            "Type exactly:\nEXPORT WIFI PASSWORDS\n\nto unlock plaintext password export.",
            parent=self.root
        )
        allow_plaintext = bool(gate_text and gate_text.strip() == "EXPORT WIFI PASSWORDS")
        if not allow_plaintext:
            self.queue.put("PROGRESS:Wi-Fi Export:Plaintext export lock not satisfied. Exporting profile names only.")

        if not messagebox.askyesno(
            "Final Confirmation",
            "Final confirmation required.\n\n"
            "Proceed with Wi-Fi export now?"
        ):
            self._report_skip("PROGRESS:Wi-Fi Export:Final confirmation declined by user.")
            return

        self.queue.put(f"PROGRESS:Wi-Fi Export:Exporting saved Wi-Fi networks to {export_dir}...")
        try:
            res = wm_run(["netsh", "wlan", "show", "profiles"], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30, startupinfo=_no_console_startupinfo())
            if res.returncode != 0:
                self._report_failure(f"PROGRESS:Wi-Fi Export:Could not list Wi-Fi profiles (code {res.returncode}); no export was created.")
                return
            profiles = re.findall(r"All User Profile\s*:\s*(.*)", res.stdout)
            
            with open(export_file, "w", encoding="utf-8") as f:
                f.write("=== Saved Wi-Fi Passwords ===\n\n")
                f.write(f"Plaintext Password Export Enabled: {allow_plaintext}\n\n")
                if not profiles:
                    f.write("No Wi-Fi profiles found on this system.\n")
                
                for profile in profiles:
                    profile = profile.strip()
                    if allow_plaintext:
                        key_res = wm_run(
                            ["netsh", "wlan", "show", "profile", f'name={profile}', "key=clear"],
                            capture_output=True,
                            text=True, encoding='utf-8', errors='replace',
                            timeout=20,
                            startupinfo=_no_console_startupinfo()
                        )
                        key_match = re.search(r"Key Content\s*:\s*(.*)", key_res.stdout)
                        if key_res.returncode != 0:
                            self._report_failure(f"PROGRESS:Wi-Fi Export:Could not read the saved profile {profile} (code {key_res.returncode}).")
                            password = "[Unavailable] Windows could not read this profile"
                        else:
                            password = key_match.group(1).strip() if key_match else "No password returned by Windows"
                    else:
                        password = "[Locked] Type gate phrase to enable password export"
                    f.write(f"Network: {profile}\nPassword: {password}\n\n")
                    
            self.queue.put(f"PROGRESS:Wi-Fi Export:Successfully exported to {export_file}")
            self.queue.put("PROGRESS:Wi-Fi Export:Auto-open disabled for security hardening. Open the file manually if needed.")
        except Exception as e:
            self._report_failure(f"PROGRESS:Wi-Fi Export:Error during export: {str(e)}")

    def run_network_adapter_reset(self):
        """Disable and re-enable the connected physical network adapters."""
        label = "Network Adapter Reset"
        self.queue.put(f"PROGRESS:{label}:Resetting the connected network adapters...")
        self.queue.put(f"PROGRESS:{label}:The network will disconnect for a few seconds.")

        # Only physical adapters that are connected now. Adapters the user had
        # switched off must stay off -- the old script re-enabled everything
        # that read Disabled afterwards -- and VPN adapters belong to their
        # own apps, which do not expect them to vanish underneath them.
        ps_script = r'''
        $targets = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })
        if (-not $targets) { Write-Output 'WM_NONE'; exit 0 }
        foreach ($a in $targets) {
            Write-Output "Disabling: $($a.Name) ($($a.InterfaceDescription))"
            try { Disable-NetAdapter -Name $a.Name -Confirm:$false -ErrorAction Stop }
            catch { Write-Output "WM_FAIL|$($a.Name)|could not disable it: $($_.Exception.Message)" }
        }
        Start-Sleep -Seconds 3
        foreach ($a in $targets) {
            Write-Output "Re-enabling: $($a.Name)"
            try { Enable-NetAdapter -Name $a.Name -Confirm:$false -ErrorAction Stop }
            catch { Write-Output "WM_FAIL|$($a.Name)|could not re-enable it: $($_.Exception.Message)" }
        }
        $names = @($targets | ForEach-Object { $_.Name })
        $deadline = (Get-Date).AddSeconds(20)
        do {
            Start-Sleep -Seconds 2
            $now = @(Get-NetAdapter -Name $names -ErrorAction SilentlyContinue)
        } while (($now | Where-Object { $_.Status -ne 'Up' }) -and (Get-Date) -lt $deadline)
        foreach ($a in $now) { Write-Output "WM_STATE|$($a.Name)|$($a.Status)|$($a.LinkSpeed)" }
        '''
        try:
            lines = []
            rc, _ = self._run_live_command(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'RemoteSigned', '-Command', ps_script],
                label, timeout=60, output=lines)
            if self.cancel_event.is_set():
                return
            if "WM_NONE" in lines:
                self.queue.put(f"PROGRESS:{label}:No connected physical adapter was found -- nothing "
                               f"was reset.")
                return
            failures = [line.split("|", 2)[1:] for line in lines if line.startswith("WM_FAIL|")]
            for name, why in failures:
                self._report_failure(f"PROGRESS:{label}:{name}: {why}")
            for line in lines:
                if line.startswith("WM_STATE|"):
                    _, name, status, speed = (line.split("|") + ["", "", "", ""])[:4]
                    if status == "Up":
                        self.queue.put(f"PROGRESS:{label}:{name} is connected again ({speed}).")
                    else:
                        self.queue.put(f"PROGRESS:{label}:{name} is {status} -- Wi-Fi can take a minute "
                                       f"to reconnect; check the cable if it is wired.")
            if not failures:
                self.queue.put(f"PROGRESS:{label}:Network adapters reset.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {str(e)}")

    def run_ping_test(self):
        """Run a connectivity check against multiple targets"""
        self.queue.put("PROGRESS:Ping Test:Starting connectivity check...")

        targets = [
            ("Default Gateway", None),
            ("Google DNS", "8.8.8.8"),
            ("Cloudflare DNS", "1.1.1.1"),
            ("Google.com", "google.com"),
            ("Microsoft.com", "microsoft.com")
        ]

        try:
            # Get default gateway first
            self.queue.put("PROGRESS:Ping Test:Detecting default gateway...")
            result = wm_run(
                ['powershell', '-NoProfile', '-Command',
                 '(Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object -First 1).NextHop'],
                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=10,
                startupinfo=_no_console_startupinfo()
            )
            gateway = result.stdout.strip()
            if gateway:
                targets[0] = ("Default Gateway", gateway)
                self.queue.put(f"PROGRESS:Ping Test:Default gateway: {gateway}")
            else:
                self.queue.put("PROGRESS:Ping Test:Could not detect default gateway, skipping")
                targets = targets[1:]

            results_summary = []
            for name, addr in targets:
                if addr is None:
                    continue
                self.queue.put(f"PROGRESS:Ping Test:Pinging {name} ({addr})...")
                rc, _ = self._run_live_command(
                    ['ping', '-n', '4', '-w', '1000', addr],
                    'Ping Test', timeout=15)
                status = "PASS" if rc == 0 else "FAIL"
                results_summary.append(f"  {status}: {name} ({addr})")
                self.queue.put(f"PROGRESS:Ping Test:{status} - {name}")

            self.queue.put("PROGRESS:Ping Test:=== Results Summary ===")
            for line in results_summary:
                self.queue.put(f"PROGRESS:Ping Test:{line}")

        except Exception as e:
            self._report_failure(f"PROGRESS:Ping Test:Error: {str(e)}")

    def flush_dns_and_renew_ip(self):
        """Flush DNS and renew IP address"""
        self.queue.put("PROGRESS:Flush DNS and Renew IP:Starting DNS flush and IP renewal...")

        try:
            all_steps_ok = True

            # Step 1: Release IP
            self.queue.put("PROGRESS:Flush DNS and Renew IP:Step 1: Releasing IP address...")
            self.queue.put("PROGRESS:Flush DNS and Renew IP:Executing: ipconfig /release")
            rc, timed_out = self._run_live_command(['ipconfig', '/release'], 'Flush DNS and Renew IP', timeout=30)
            if timed_out:
                self.queue.put("PROGRESS:Flush DNS and Renew IP:IP release command timed out")
                all_steps_ok = False
            elif rc == 0:
                self.queue.put("PROGRESS:Flush DNS and Renew IP:IP address released successfully")
            else:
                self.queue.put(f"PROGRESS:Flush DNS and Renew IP:IP release failed (rc={rc})")
                all_steps_ok = False

            # Step 2: Renew IP
            self.queue.put("PROGRESS:Flush DNS and Renew IP:Step 2: Renewing IP address...")
            self.queue.put("PROGRESS:Flush DNS and Renew IP:Executing: ipconfig /renew")
            rc, timed_out = self._run_live_command(['ipconfig', '/renew'], 'Flush DNS and Renew IP', timeout=60)
            if timed_out:
                self.queue.put("PROGRESS:Flush DNS and Renew IP:IP renewal command timed out")
                all_steps_ok = False
            elif rc == 0:
                self.queue.put("PROGRESS:Flush DNS and Renew IP:IP address renewed successfully")
            else:
                self.queue.put(f"PROGRESS:Flush DNS and Renew IP:IP renewal failed (rc={rc})")
                all_steps_ok = False

            # Step 3: Flush DNS
            self.queue.put("PROGRESS:Flush DNS and Renew IP:Step 3: Flushing DNS...")
            self.queue.put("PROGRESS:Flush DNS and Renew IP:Executing: ipconfig /flushdns")
            rc, timed_out = self._run_live_command(['ipconfig', '/flushdns'], 'Flush DNS and Renew IP', timeout=30)
            if timed_out:
                self.queue.put("PROGRESS:Flush DNS and Renew IP:DNS flush command timed out")
                all_steps_ok = False
            elif rc == 0:
                self.queue.put("PROGRESS:Flush DNS and Renew IP:DNS flushed successfully")
            else:
                self.queue.put(f"PROGRESS:Flush DNS and Renew IP:DNS flush failed (rc={rc})")
                all_steps_ok = False

            if all_steps_ok:
                self.queue.put("PROGRESS:Flush DNS and Renew IP:DNS flush and IP renewal completed successfully!")
            elif not self.cancel_event.is_set():
                self._report_failure("PROGRESS:Flush DNS and Renew IP:At least one step failed; the lines "
                                     "above say which. (An adapter with a fixed IP address cannot "
                                     "release or renew -- that one is expected.)")

        except Exception as e:
            self._report_failure(f"PROGRESS:Flush DNS and Renew IP:Error in DNS flush and IP renewal: {str(e)}")

    def display_ip_config(self):
        """Display IP configuration using ipconfig /all"""
        self.queue.put("PROGRESS:Display IP Configuration:Retrieving IP configuration...")

        try:
            self.queue.put("PROGRESS:Display IP Configuration:Executing: ipconfig /all")
            result = wm_run(
                ['ipconfig', '/all'],
                capture_output=True,
                text=True, encoding='utf-8', errors='replace',
                check=False,
                timeout=30,
                startupinfo=_no_console_startupinfo()  # Hide console window
            )

            self.queue.put("PROGRESS:Display IP Configuration:IP configuration retrieved successfully")

            if result.stdout.strip():
                self.queue.put("PROGRESS:Display IP Configuration:=== IP Configuration ===")
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        self.queue.put(f"PROGRESS:Display IP Configuration:{line.strip()}")

            if result.stderr.strip():
                self.queue.put("PROGRESS:Display IP Configuration:Errors:")
                for line in result.stderr.strip().split('\n'):
                    if line.strip():
                        self.queue.put(f"PROGRESS:Display IP Configuration:  {line.strip()}")

            if result.returncode != 0 or not (result.stdout or '').strip():
                self._report_failure(f"PROGRESS:Display IP Configuration:IP configuration could not be read (code {result.returncode}).")
            else:
                self.queue.put("PROGRESS:Display IP Configuration:IP configuration display completed!")

        except subprocess.TimeoutExpired:
            self._report_failure("PROGRESS:Display IP Configuration:IP configuration command timed out")
        except Exception as e:
            self._report_failure(f"PROGRESS:Display IP Configuration:Error displaying IP configuration: {str(e)}")

    def change_dns_servers(self):
        """Point the internet-facing adapters at a chosen public DNS provider.

        Was hardcoded to 1.1.1.1/8.8.8.8 -- a pair from two different providers,
        which is not what either one intends. Now it asks, because "fast DNS"
        and "DNS that blocks ads or adult content" are different decisions, and
        offers the way back to the router's own DNS.
        """
        label = "Change DNS"
        options = [(p["id"], f"{p['name']}  —  {p['detail']}") for p in DNS_PROVIDERS]
        options.append(("dhcp", "Automatic (undo) — go back to the DNS your "
                                "router or ISP hands out"))
        choice = self._ui_radio_picker(
            "Change DNS", "Which DNS servers should this PC use?\n"
            "This applies to every connected physical network adapter. VPN and "
            "virtual adapters keep the DNS their own apps set.",
            options, default="cloudflare")
        if not choice:
            self._report_skip(f"PROGRESS:{label}:Cancelled — nothing was changed.")
            return
        if choice == "dhcp":
            self._reset_dns_to_automatic()
            return
        provider = dns_provider(choice)
        v4 = list(provider["v4"])
        v6 = list(provider.get("v6") or ())
        self.queue.put(f"PROGRESS:{label}:Setting DNS to {provider['name']} "
                       f"({', '.join(v4 + v6)})...")
        # IPv6 servers are set too: on a dual-stack network the router's IPv6
        # DNS otherwise stays in use beside the new IPv4 pair -- and a family
        # or malware filter chosen here is bypassed for every name Windows
        # happens to look up over IPv6.
        script = (self._DNS_TARGETS_PS + r'''
        foreach ($a in $targets) {
            $servers = @(%V4%)
            $v6on = (Get-NetAdapterBinding -Name $a.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue).Enabled
            if ($v6on) { $servers += @(%V6%) }
            try {
                Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $servers -ErrorAction Stop
                $now = @((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4).ServerAddresses)
                if ($now -contains '%P4%') { Write-Output ("OK|" + $a.Name + "|" + ($servers -join ', ')) }
                else { Write-Output ("FAIL|" + $a.Name + "|the new servers did not stick") }
            } catch { Write-Output ("FAIL|" + $a.Name + "|" + $_.Exception.Message) }
        }
        Clear-DnsClientCache -ErrorAction SilentlyContinue
        ''').replace("%V4%", ",".join(f"'{a}'" for a in v4)) \
            .replace("%V6%", ",".join(f"'{a}'" for a in v6) or "") \
            .replace("%P4%", v4[0])
        self._apply_dns_script(label, script, f"Now using {provider['name']}.")

    def _reset_dns_to_automatic(self):
        """Hand DNS back to DHCP -- the undo for the picker above."""
        label = "Change DNS"
        self.queue.put(f"PROGRESS:{label}:Returning DNS to automatic...")
        script = self._DNS_TARGETS_PS + r'''
        foreach ($a in $targets) {
            try {
                Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses -ErrorAction Stop
                Write-Output ("OK|" + $a.Name + "|automatic")
            } catch { Write-Output ("FAIL|" + $a.Name + "|" + $_.Exception.Message) }
        }
        Clear-DnsClientCache -ErrorAction SilentlyContinue
        '''
        self._apply_dns_script(label, script, "Adapters now use the DNS servers your router or ISP "
                                              "hands out.")

    # The adapters DNS changes apply to: every connected physical adapter, plus
    # a Hyper-V virtual adapter that carries the default route (a PC with an
    # external virtual switch reaches the internet through it). VPN and other
    # virtual adapters -- Twingate, Tailscale, WireGuard, VirtualBox -- are left
    # alone: their DNS is set by their own apps, and overriding it breaks name
    # lookups inside the VPN.
    _DNS_TARGETS_PS = r'''
        $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0', '::/0' -ErrorAction SilentlyContinue | ForEach-Object { $_.ifIndex })
        $targets = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })
        $targets += @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
            $_.Status -eq 'Up' -and $_.InterfaceDescription -like 'Hyper-V Virtual Ethernet*' -and $routes -contains $_.ifIndex })
        $ids = @($targets | ForEach-Object { $_.ifIndex })
        foreach ($s in @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and $ids -notcontains $_.ifIndex })) {
            Write-Output ("SKIP|" + $s.Name + "|" + $s.InterfaceDescription)
        }
        if (-not $targets) { Write-Output 'NONE' }
    '''

    def _apply_dns_script(self, label, script, done_message):
        """Run a DNS change built on _DNS_TARGETS_PS and report per adapter."""
        try:
            result = self._run_ps(script, timeout=120)
            lines = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
            if result.returncode != 0:
                self._report_failure(f"PROGRESS:{label}:DNS command failed: "
                                     f"{_wm_last_line(result.stderr) or result.returncode}")
            if "NONE" in lines:
                self._report_failure(f"PROGRESS:{label}:No connected physical network adapter was "
                                     f"found -- nothing was changed.")
                return
            changed = 0
            for line in lines:
                kind, _, rest = line.partition("|")
                name, _, detail = rest.partition("|")
                if kind == "OK":
                    changed += 1
                    self.queue.put(f"PROGRESS:{label}:  {name}: {detail}")
                elif kind == "FAIL":
                    self._report_failure(f"PROGRESS:{label}:  {name}: could not be changed -- {detail}")
                elif kind == "SKIP":
                    self.queue.put(f"PROGRESS:{label}:  {name} ({detail}): left alone -- VPN or "
                                   f"virtual adapter")
            if changed:
                self.queue.put(f"PROGRESS:{label}:{done_message}")
                self.queue.put(f"PROGRESS:{label}:You may need to restart your browser for it to "
                               f"take effect.")
            elif not getattr(self, "_task_failure", None):
                self._report_failure(f"PROGRESS:{label}:No adapter reported a successful DNS change; "
                                     "the change could not be verified.")
        except Exception as exc:
            self._report_failure(f"PROGRESS:{label}:Error changing DNS servers: {exc}")

    def run_deep_network_remediation(self):
        """Runs extensive network stack remediation commands and reports each result."""
        task_label = "deep_network_remediation"
        self.queue.put(f"PROGRESS:{task_label}:Starting Deep Network Stack Remediation...")

        # Resetting the firewall deletes every rule apps have added -- a VPN,
        # games, Remote Desktop, file sharing -- so it is its own decision.
        reset_firewall = messagebox.askyesno(
            "Also reset Windows Firewall?",
            "Deep Network Remediation can also reset Windows Firewall to its defaults.\n\n"
            "That deletes EVERY firewall rule your apps have added -- VPN clients, games, "
            "Remote Desktop, file sharing -- and they will ask for network access again, or "
            "stop working until reinstalled.\n\n"
            "Reset the firewall too? Choose No unless you suspect a broken firewall rule.")

        # (command, description, whether a failure means the remediation failed)
        commands = [
            (["ipconfig", "/release"], "Releasing IPv4 address...", False),
            (["ipconfig", "/flushdns"], "Flushing DNS resolver cache...", False),
            (["ipconfig", "/renew"], "Renewing IPv4 address...", False),
            (["netsh", "winsock", "reset"], "Resetting Winsock Catalog...", True),
            (["netsh", "int", "ip", "reset"], "Resetting TCP/IP stack...", False),
            (["nbtstat", "-R"], "Purging and reloading NBT remote cache name table...", False),
            (["nbtstat", "-RR"], "Sending Name Release packets to WINS...", False),
            (["netsh", "branchcache", "reset"], "Resetting BranchCache...", False),
            (["netsh", "interface", "ipv4", "reset"], "Resetting IPv4 interfaces...", False),
            (["netsh", "interface", "ipv6", "reset"], "Resetting IPv6 interfaces...", False),
            (["netsh", "interface", "tcp", "reset"], "Resetting TCP interfaces...", True),
            (["arp", "-d", "*"], "Clearing ARP cache...", False),
        ]
        if reset_firewall:
            commands.insert(5, (["netsh", "advfirewall", "reset"],
                                "Resetting Windows Firewall to defaults...", True))
        else:
            self.queue.put(f"PROGRESS:{task_label}:Firewall rules left as they are.")

        done = 0
        for cmd, desc, essential in commands:
            if self.cancel_event.is_set():
                return
            self.queue.put(f"PROGRESS:{task_label}:{desc}")
            try:
                lines = []
                rc, _ = self._run_live_command(cmd, task_label, encoding='utf-8', output=lines)
            except Exception as e:
                rc = -1
                detail = str(e)
            else:
                detail = _wm_last_line("\n".join(lines)) or f"exit code {rc}"
            if rc == 0:
                done += 1
                self.queue.put(f"PROGRESS:{task_label}:  done")
            elif self.cancel_event.is_set():
                return
            elif essential:
                self._report_failure(f"PROGRESS:{task_label}:  {' '.join(cmd)} failed: {detail}")
            else:
                # A PC with a fixed IP cannot release/renew, Home editions have
                # no BranchCache, and one protected key makes `int ip reset`
                # report an error while everything else resets. Worth saying,
                # not worth failing the run over.
                self.queue.put(f"PROGRESS:{task_label}:  not applied: {detail}")

        self.queue.put(f"PROGRESS:{task_label}:Deep network remediation finished: {done} of "
                       f"{len(commands)} steps applied.")
        if done:
            self.queue.put(f"REBOOTRECOMMEND:Deep Network Remediation:The network stack was reset; "
                           f"Windows only rebuilds it at the next restart.")

    def run_network_diagnostic_bundle(self):
        """Create a deep network diagnostic report and health score."""
        self.queue.put("PROGRESS:Network Diagnostic:Building deep network diagnostic bundle...")
        try:
            desktop = self._get_desktop_dir()
            ts = time.strftime("%Y%m%d_%H%M%S")
            report_path = os.path.join(desktop, f"Network_Diagnostic_Bundle_{ts}.txt")

            cmd_outputs = []
            checks = [
                (['ipconfig', '/all'], 'ipconfig /all'),
                (['route', 'print'], 'route print'),
                (['netsh', 'interface', 'ip', 'show', 'config'], 'netsh interface ip show config'),
                (['nslookup', 'google.com'], 'nslookup google.com'),
                (['ping', '-n', '2', '1.1.1.1'], 'ping 1.1.1.1'),
                (['ping', '-n', '2', '8.8.8.8'], 'ping 8.8.8.8'),
                (['ping', '-n', '2', 'google.com'], 'ping google.com'),
                (['powershell', '-NoProfile', '-Command',
                  'Get-NetAdapter | Select-Object Name, Status, LinkSpeed, MacAddress | Format-Table -AutoSize'],
                 'Get-NetAdapter')
            ]

            score = 100
            for cmd, label in checks:
                if self.cancel_event.is_set():
                    return
                self.queue.put(f"PROGRESS:Network Diagnostic:Checking {label}...")
                try:
                    lines = []
                    rc, _ = self._run_live_command(cmd, 'Network Diagnostic', encoding='utf-8', output=lines)
                    if self.cancel_event.is_set():
                        return
                    cmd_outputs.append(f"\n=== {label} ===\n")
                    cmd_outputs.append("\n".join(lines) + "\n")
                    self.queue.put(f"PROGRESS:Network Diagnostic:{label}: "
                                   f"{'check passed' if rc == 0 else 'check failed'} (exit code {rc}).")
                    if rc != 0:
                        score -= 10
                        cmd_outputs.append(f"\n(return code {rc})\n")
                except Exception as inner:
                    score -= 15
                    self._report_failure(f"PROGRESS:Network Diagnostic:{label}: Could not run check: {inner}")
                    cmd_outputs.append(f"\n=== {label} ===\nError: {str(inner)}\n")

            score = max(0, min(100, score))
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(f"EAWTECH Network Diagnostic Bundle\nGenerated: {datetime.now()}\nHealth Score: {score}/100\n")
                f.write("\n".join(cmd_outputs))

            self.queue.put(f"PROGRESS:Network Diagnostic:Report saved to {report_path}")
            self.queue.put(f"PROGRESS:Network Diagnostic:Computed health score: {score}/100")
        except Exception as e:
            self._report_failure(f"PROGRESS:Network Diagnostic:Error: {str(e)}")

    def run_dns_over_https(self):
        """Turn encrypted DNS (DoH) on or off for the internet-facing adapters."""
        label = "DNS-over-HTTPS"
        choice = self._ui_radio_picker(
            "DNS-over-HTTPS",
            "Encrypted DNS hides the websites you look up from your network and internet "
            "provider, and stops those lookups being redirected.\n\nIt applies to every connected "
            "physical network adapter; VPN adapters keep their own DNS.",
            [("on", "Turn on -- Cloudflare 1.1.1.1 and Google 8.8.8.8, encrypted"),
             ("off", "Turn off -- back to the automatic DNS your router or internet provider hands out")],
            default="on")
        if not choice:
            self._report_skip(f"PROGRESS:{label}:Cancelled -- nothing was changed.")
            return
        if choice == "off":
            self._doh_off(label)
            return

        servers = self._DOH_SERVERS
        templates = ";".join(f"{ip}={tpl}" for ip, tpl in servers)
        # Two layers: the DoH template for each server address, and -- what
        # Settings > Network > DNS over HTTPS "On (automatic template)" writes
        # -- the per-adapter DohFlags that make Windows use it on that adapter.
        # Strict: no fallback to plain DNS, so nothing leaks unencrypted.
        script = (r'''
        foreach ($pair in '%TEMPLATES%'.Split(';')) {
            $ip, $tpl = $pair.Split('=', 2)
            if (Get-DnsClientDohServerAddress -ServerAddress $ip -ErrorAction SilentlyContinue) {
                Set-DnsClientDohServerAddress -ServerAddress $ip -DohTemplate $tpl -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction SilentlyContinue | Out-Null
            } else {
                Add-DnsClientDohServerAddress -ServerAddress $ip -DohTemplate $tpl -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction SilentlyContinue | Out-Null
            }
        }
        ''' + self._DNS_TARGETS_PS + r'''
        foreach ($a in $targets) {
            $list = @('1.1.1.1', '8.8.8.8')
            $v6on = (Get-NetAdapterBinding -Name $a.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue).Enabled
            if ($v6on) { $list += @('2606:4700:4700::1111', '2001:4860:4860::8888') }
            $base = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$($a.InterfaceGuid)\DohInterfaceSettings"
            foreach ($ip in $list) {
                $sub = if ($ip.Contains(':')) { 'Doh6' } else { 'Doh' }
                $k = "$base\$sub\$ip"
                New-Item -Path $k -Force | Out-Null
                New-ItemProperty -Path $k -Name 'DohFlags' -PropertyType QWord -Value 1 -Force | Out-Null
            }
            try {
                Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $list -ErrorAction Stop
                Write-Output ("OK|" + $a.Name + "|" + ($list -join ', ') + ", encrypted")
            } catch { Write-Output ("FAIL|" + $a.Name + "|" + $_.Exception.Message) }
        }
        Clear-DnsClientCache -ErrorAction SilentlyContinue
        ''').replace("%TEMPLATES%", templates)
        self._apply_dns_script(label, script, "Encrypted DNS settings applied.")
        if getattr(self, "_task_failure", None) or self.cancel_event.is_set():
            return

        # Measure rather than assume: resolve two names, then look for the DNS
        # Client's own HTTPS connections to the resolvers.
        time.sleep(2)
        check = self._run_ps(r'''
        $ok = $true
        foreach ($n in 'www.microsoft.com', 'example.com') {
            try { Resolve-DnsName -Name $n -DnsOnly -ErrorAction Stop | Out-Null } catch { $ok = $false }
        }
        Write-Output "RESOLVES|$ok"
        $svc = Get-CimInstance Win32_Service -Filter "Name='Dnscache'" -ErrorAction SilentlyContinue
        $https = @(Get-NetTCPConnection -OwningProcess $svc.ProcessId -RemotePort 443 -ErrorAction SilentlyContinue |
                   Where-Object { $_.RemoteAddress -in '1.1.1.1', '8.8.8.8', '2606:4700:4700::1111', '2001:4860:4860::8888' })
        Write-Output "HTTPS|$($https.Count)"
        ''', timeout=90)
        out = check.stdout or ""
        if "RESOLVES|True" not in out:
            # Some networks (captive portals, workplaces) block DoH; with no
            # fallback that would leave the PC unable to look anything up.
            self.queue.put(f"PROGRESS:{label}:Name lookups stopped working over HTTPS on this network -- "
                           f"switching encrypted DNS back off.")
            self._doh_off(label)
            self._report_failure(f"PROGRESS:{label}:This network does not allow encrypted DNS, so it was "
                                 f"turned back off. Try again on another network.")
            return
        count = re.search(r"HTTPS\|(\d+)", out)
        if count and int(count.group(1)) > 0:
            self.queue.put(f"PROGRESS:{label}:Verified: Windows is sending DNS lookups over HTTPS.")
        else:
            self.queue.put(f"PROGRESS:{label}:Lookups work, but Windows has not opened an HTTPS "
                           f"connection to the resolvers yet -- it may only switch over after a "
                           f"restart. Settings > Network shows 'DNS over HTTPS: On' per adapter.")

    _DOH_SERVERS = (
        ("1.1.1.1", "https://cloudflare-dns.com/dns-query"),
        ("8.8.8.8", "https://dns.google/dns-query"),
        ("2606:4700:4700::1111", "https://cloudflare-dns.com/dns-query"),
        ("2001:4860:4860::8888", "https://dns.google/dns-query"),
    )

    def _doh_off(self, label):
        """Undo run_dns_over_https: DNS back to automatic, WinMend's DoH flags removed."""
        script = self._DNS_TARGETS_PS + r'''
        foreach ($a in $targets) {
            $base = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$($a.InterfaceGuid)\DohInterfaceSettings"
            foreach ($sub in 'Doh', 'Doh6') {
                foreach ($ip in '1.1.1.1', '8.8.8.8', '2606:4700:4700::1111', '2001:4860:4860::8888') {
                    Remove-Item -Path "$base\$sub\$ip" -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
            try {
                Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses -ErrorAction Stop
                Write-Output ("OK|" + $a.Name + "|automatic, unencrypted")
            } catch { Write-Output ("FAIL|" + $a.Name + "|" + $_.Exception.Message) }
        }
        foreach ($ip in '1.1.1.1', '8.8.8.8', '2606:4700:4700::1111', '2001:4860:4860::8888') {
            Set-DnsClientDohServerAddress -ServerAddress $ip -AutoUpgrade $false -ErrorAction SilentlyContinue | Out-Null
        }
        Clear-DnsClientCache -ErrorAction SilentlyContinue
        '''
        self._apply_dns_script(label, script, "Encrypted DNS is off; DNS is back to automatic.")

    def run_wifi_channel_analyzer(self):
        """Scan visible Wi-Fi networks and report every access point's channel and signal."""
        label = "Wi-Fi Analyzer"
        self.queue.put(f"PROGRESS:{label}:Scanning nearby Wi-Fi networks...")
        try:
            r = wm_run(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'], capture_output=True,
                       text=True, encoding='utf-8', errors='replace', startupinfo=_no_console_startupinfo())
            text = (r.stdout or "").strip()
            lowered = text.lower()
            if "no wireless interface" in lowered:
                self._report_skip(f"PROGRESS:{label}:This PC has no Wi-Fi adapter, so there is nothing to scan.")
                return
            if "location" in lowered and "permission" in lowered:
                # Windows 11 24H2 and later only let programs list nearby
                # networks while Location is on.
                self._report_failure(f"PROGRESS:{label}:Windows blocks Wi-Fi scans while Location is off. "
                                     f"Turn on Settings > Privacy & security > Location (and 'Let desktop "
                                     f"apps access your location'), then run this again.")
                return
            if not text:
                self._report_failure(f"PROGRESS:{label}:The WLAN service did not answer "
                                     f"({_wm_last_line(r.stderr) or r.returncode}).")
                return

            # One row per access point. A dual-band router or a mesh system
            # broadcasts the same network name from several radios, each on its
            # own channel; the old parser kept only the last one per name, so
            # it under-counted exactly the channels a user is trying to judge.
            aps = []
            ssid, ap = None, None
            for raw in text.splitlines():
                line = raw.strip()
                if re.match(r"^SSID\s+\d+\s*:", line, re.IGNORECASE):
                    ssid = line.split(":", 1)[1].strip() or "<hidden>"
                    ap = None
                elif re.match(r"^BSSID\s+\d+\s*:", line, re.IGNORECASE):
                    ap = {"ssid": ssid or "<hidden>", "bssid": line.split(":", 1)[1].strip(),
                          "signal": "?", "band": "?", "channel": "?"}
                    aps.append(ap)
                elif ap is not None and ":" in line:
                    key, value = (part.strip() for part in line.split(":", 1))
                    key = key.lower()
                    if key == "signal":
                        ap["signal"] = value
                    elif key == "band":
                        ap["band"] = value
                    elif key == "channel":
                        ap["channel"] = value

            if not aps:
                self.queue.put(f"PROGRESS:{label}:No networks visible.")
                return
            self.queue.put(f"PROGRESS:{label}:Found {len(aps)} access point(s) on "
                           f"{len({a['ssid'] for a in aps})} network(s):")
            for a in sorted(aps, key=lambda a: (a["band"], a["channel"], a["ssid"])):
                self.queue.put(f"PROGRESS:{label}:  Ch {a['channel']:>4}  {a['signal']:>5}  "
                               f"{a['band']:<8}  {a['ssid']}")
            busy = {}
            for a in aps:
                busy.setdefault((a["band"], a["channel"]), 0)
                busy[(a["band"], a["channel"])] += 1
            summary = ", ".join(f"ch {ch} ({band}): {n}" for (band, ch), n in
                                sorted(busy.items(), key=lambda kv: -kv[1])[:5])
            self.queue.put(f"PROGRESS:{label}:Busiest channels: {summary}")
            if any("2.4" in a["band"] for a in aps):
                quiet = min(("1", "6", "11"), key=lambda ch: sum(n for (band, c), n in busy.items()
                                                                if "2.4" in band and c == ch))
                self.queue.put(f"PROGRESS:{label}:Least crowded 2.4 GHz channel of 1/6/11: {quiet}")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")

    def run_wlan_report(self):
        """Run netsh wlan show wlanreport and open the resulting HTML report."""
        label = "Wireless Report"
        started = time.time()
        self.queue.put(f"PROGRESS:{label}:Generating wireless diagnostics report "
                       f"(netsh wlan show wlanreport)...")
        try:
            r = wm_run(
                ['netsh', 'wlan', 'show', 'wlanreport'],
                capture_output=True, text=True, encoding='utf-8', errors='replace',
                timeout=120, startupinfo=_no_console_startupinfo()
            )
            out = ((r.stdout or "") + "\n" + (r.stderr or "")).strip()

            # netsh prints where it wrote the report; parse that, then fall back
            # to the documented default location.
            report_path = None
            m = re.search(r'([A-Za-z]:\\[^\r\n"]*?wlan-report[^\r\n"]*?\.html)',
                          out, re.IGNORECASE)
            if m and os.path.exists(m.group(1).strip()):
                report_path = m.group(1).strip()
            else:
                fallback = os.path.join(
                    os.environ.get('ProgramData', r'C:\ProgramData'),
                    'Microsoft', 'Windows', 'WlanReport', 'wlan-report-latest.html')
                # Only trust the fallback if it was written by THIS run --
                # a stale file from an earlier run must not open as a success.
                if os.path.exists(fallback) and os.path.getmtime(fallback) >= started - 5:
                    report_path = fallback

            if report_path:
                self.queue.put(f"PROGRESS:{label}:Report saved to {report_path}")
                self.queue.put(f"PROGRESS:{label}:Opening report in your browser...")
                try:
                    webbrowser.open(Path(report_path).as_uri())
                except Exception as e:
                    self.queue.put(f"PROGRESS:{label}:Could not auto-open the report "
                                   f"({e}). Open it manually from the path above.")
            else:
                detail = out.splitlines()[-1].strip() if out else f"netsh returned {r.returncode}"
                if not self.admin_status:
                    detail += " -- this task needs administrator rights; restart WinMend as administrator"
                self._report_failure(f"PROGRESS:{label}:Report was not generated: {detail}")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")

    def run_time_sync_fix(self):
        """Start the Windows Time service and force a clock resync."""
        label = "Time Sync"
        self.queue.put(f"PROGRESS:{label}:Starting Windows Time service...")
        try:
            state = service_state("w32time")
            if state is None:
                self._report_failure(f"PROGRESS:{label}:The Windows Time service is missing from this PC.")
                return
            if state.get("start") == "disabled":
                # Switched off (a "debloat" favourite); Manual is its default.
                wm_run(['sc', 'config', 'w32time', 'start=', 'demand'], capture_output=True,
                       startupinfo=_no_console_startupinfo())
                self.queue.put(f"PROGRESS:{label}:Windows Time was switched off -- set back to Manual, "
                               f"its Windows default.")
            wm_run(['net', 'start', 'w32time'], capture_output=True, timeout=30,
                   startupinfo=_no_console_startupinfo())  # rc 2 if already running
            if (service_state("w32time") or {}).get("status") != "running":
                self._report_failure(f"PROGRESS:{label}:The Windows Time service would not start.")
                return
            self.queue.put(f"PROGRESS:{label}:Forcing time resync...")
            r = wm_run(['w32tm', '/resync'], capture_output=True, text=True,
                       encoding='utf-8', errors='replace', timeout=60,
                       startupinfo=_no_console_startupinfo())
            if r.returncode != 0:
                # No time data yet: rediscover sources and retry once.
                r = wm_run(['w32tm', '/resync', '/rediscover'], capture_output=True,
                           text=True, encoding='utf-8', errors='replace', timeout=60,
                           startupinfo=_no_console_startupinfo())
            msg = (r.stdout or r.stderr or '').strip().splitlines()
            if msg:
                self.queue.put(f"PROGRESS:{label}:{msg[0]}")
            q = wm_run(['w32tm', '/query', '/status'], capture_output=True, text=True,
                       encoding='utf-8', errors='replace', timeout=30,
                       startupinfo=_no_console_startupinfo())
            for line in (q.stdout or '').splitlines():
                if re.match(r'^(Source|Last Successful Sync Time|Stratum|Phase Offset)',
                            line.strip(), re.IGNORECASE):
                    self.queue.put(f"PROGRESS:{label}:{line.strip()}")
            if r.returncode != 0:
                self._report_failure(f"PROGRESS:{label}:Windows could not reach a time server "
                                     f"({_wm_last_line(r.stdout, r.stderr) or r.returncode}). Check the "
                                     f"internet connection; a firewall blocking UDP port 123 stops it too.")
        except Exception as e:
            self._report_failure(f"PROGRESS:{label}:Error: {e}")
