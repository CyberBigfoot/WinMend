"""WinMend reports: system tables."""

from __future__ import annotations

import html as _html


class ReportSystemTablesMixin:
    """PCReporter methods grouped by responsibility."""

    def _count_startup_items(self):
        """Count the total number of startup items"""
        count = 0
        if "startup_items" in self.report_data:
            startup_data = self.report_data["startup_items"]
            for category, items in startup_data.items():
                if isinstance(items, dict):
                    for subcategory, subitems in items.items():
                        if isinstance(subitems, dict):
                            count += len(subitems)
        return count

    def _generate_startup_items_table(self):
        """Generate HTML table for startup items"""
        if "startup_items" not in self.report_data or not self.report_data["startup_items"]:
            return "<p>No startup items information available.</p>"

        startup_data = self.report_data["startup_items"]
        html = ""

        for category, items in startup_data.items():
            if isinstance(items, dict):
                html += f"<h3>{_html.escape(str(category))}</h3>"
                for subcategory, subitems in items.items():
                    if isinstance(subitems, dict):
                        html += f"<h4>{_html.escape(str(subcategory))}</h4>"
                        html += "<table>"
                        html += "<tr><th>Name</th><th>Value/Path</th><th>Status</th></tr>"
                        for name, info in subitems.items():
                            if isinstance(info, dict):
                                value_path = info.get("Value", info.get("Path", "N/A"))
                                status = info.get("Status", "Unknown")
                                status_class = "startup-enabled" if status == "Enabled" else "startup-disabled" if status == "Disabled" else ""
                                html += (f"<tr><td>{_html.escape(str(name))}</td>"
                                         f"<td>{_html.escape(str(value_path))}</td>"
                                         f"<td class='{status_class}'>{_html.escape(str(status))}</td></tr>")
                        html += "</table>"

        return html

    def _generate_security_alerts(self):
        """Generate security alerts based on vulnerability information"""
        alerts = ""

        if "vulnerabilities" in self.report_data and self.report_data["vulnerabilities"]:
            vuln = self.report_data["vulnerabilities"]

            # Check for pending updates
            if vuln.get("Status") == "Updates Available":
                alerts += """
                        <div class="alert warning">
                            <div class="alert-icon">&#9888;&#65039;</div>
                            <div>
                                <strong>Security Updates Available</strong><br>
                                Your system has pending security updates. Please install them as soon as possible to protect against vulnerabilities.
                            </div>
                        </div>
                        """

            # Check for Windows support status
            if vuln.get("Windows Support Status") == "End of Life - Security Risk":
                alerts += """
                        <div class="alert danger">
                            <div class="alert-icon">ðŸ"´</div>
                            <div>
                                <strong>Unsupported Windows Version</strong><br>
                                Your Windows version is no longer supported by Microsoft. This means you won't receive security updates and are at high risk. Consider upgrading to a supported version.
                            </div>
                        </div>
                        """

            # Check for Windows Defender status
            if "Windows Defender" in vuln:
                defender = vuln["Windows Defender"]
                if isinstance(defender, dict):
                    if defender.get("RealTimeProtectionEnabled") == "False":
                        alerts += """
                                <div class="alert danger">
                                    <div class="alert-icon">ðŸ"´</div>
                                    <div>
                                        <strong>Real-time Protection Disabled</strong><br>
                                        Windows Defender real-time protection is disabled. Your system is not protected against malware in real-time.
                                    </div>
                                </div>
                                """
                    elif defender.get("AntivirusEnabled") == "False":
                        alerts += """
                                <div class="alert danger">
                                    <div class="alert-icon">ðŸ"´</div>
                                    <div>
                                        <strong>Antivirus Disabled</strong><br>
                                        Windows Defender antivirus is disabled. Your system is not protected against viruses and malware.
                                    </div>
                                </div>
                                """

            # Check for firewall status
            if "Windows Firewall" in vuln:
                firewall = vuln["Windows Firewall"]
                if isinstance(firewall, dict):
                    for profile, status in firewall.items():
                        if status.lower() == "off":
                            alerts += f"""
                                    <div class="alert danger">
                                        <div class="alert-icon">ðŸ"´</div>
                                        <div>
                                            <strong>Firewall Disabled</strong><br>
                                            Windows Firewall is turned off for the {profile} profile. Your system may be vulnerable to network attacks.
                                        </div>
                                    </div>
                                    """
                            break  # Only show one firewall alert

        return alerts

    def _generate_vulnerability_section(self):
        """Generate HTML for the vulnerability section"""
        if "vulnerabilities" not in self.report_data or not self.report_data["vulnerabilities"]:
            return "<p>No vulnerability information available.</p>"

        vuln = self.report_data["vulnerabilities"]
        rows = ""

        for key, value in vuln.items():
            if key == "Windows Defender" and isinstance(value, dict):
                rows += f"<tr><td class='key'>{key}</td><td class='value'><table class='nested-table'>"
                for sub_key, sub_value in value.items():
                    status = "success" if "True" in str(sub_value) else "danger" if "False" in str(
                        sub_value) else ""
                    badge = f" <span class='badge {status}'>{sub_value}</span>" if status else f" {sub_value}"
                    rows += f"<tr><td class='key'>{sub_key}</td><td class='value'>{badge}</td></tr>"
                rows += "</table></td></tr>"
            elif key == "Windows Firewall" and isinstance(value, dict):
                rows += f"<tr><td class='key'>{key}</td><td class='value'><table class='nested-table'>"
                for profile, status in value.items():
                    status_class = "success" if status.lower() == "on" else "danger" if status.lower() == "off" else ""
                    badge = f" <span class='badge {status_class}'>{status}</span>" if status_class else f" {status}"
                    rows += f"<tr><td class='key'>{profile}</td><td class='value'>{badge}</td></tr>"
                rows += "</table></td></tr>"
            elif key == "Status":
                status_class = "success" if value == "Up to Date" else "warning" if value == "Updates Available" else ""
                badge = f" <span class='badge {status_class}'>{value}</span>" if status_class else f" {value}"
                rows += f"<tr><td class='key'>{key}</td><td class='value'>{badge}</td></tr>"
            elif key == "Windows Support Status":
                status_class = "success" if value == "Supported" else "danger" if "End of Life" in value else ""
                badge = f" <span class='badge {status_class}'>{value}</span>" if status_class else f" {value}"
                rows += f"<tr><td class='key'>{key}</td><td class='value'>{badge}</td></tr>"
            else:
                rows += f"<tr><td class='key'>{key}</td><td class='value'>{value}</td></tr>"

        return f"<table>{rows}</table>"

    def _generate_updates_section(self):
        """Generate Windows updates section"""
        if "updates" in self.report_data and self.report_data["updates"]:
            return """
                    <div class="section">
                        <h2>Windows Updates <span class="badge">""" + str(len(self.report_data["updates"])) + """</span></h2>
                        <button type="button" class="collapsible">View Recent Updates</button>
                        <div class="content-collapsible">
                            <table>
                                """ + self._generate_updates_table(self.report_data["updates"]) + """
                            </table>
                        </div>
                    </div>
                    """
        return ""

    def _generate_updates_table(self, data):
        """Generate HTML table for Windows updates"""
        if isinstance(data, dict) and "Error" in data:
            return f"<tr><td colspan='3'>{data['Error']}</td></tr>"

        rows = "<tr><th>Hotfix ID</th><th>Installed On</th><th>Installed By</th></tr>"
        for update in data:
            rows += (f"<tr><td>{_html.escape(str(update.get('Hotfix ID', '')))}</td>"
                     f"<td>{_html.escape(str(update.get('Installed On', '')))}</td>"
                     f"<td>{_html.escape(str(update.get('Installed By', '')))}</td></tr>")

        return rows

    def _generate_hardware_tables(self):
        """Generate HTML tables for hardware information"""
        hardware_tables = ""
        for category, data in self.report_data["hardware"].items():
            if isinstance(data, dict):
                hardware_tables += f"<h3>{category}</h3>"
                if category == "Storage":
                    hardware_tables += self._generate_storage_table(data)
                elif category == "CPU" and "CPU Usage Per Core" in data:
                    hardware_tables += self._generate_cpu_table(data)
                else:
                    hardware_tables += self._generate_dict_table(data)
        return hardware_tables

    def _generate_cpu_table(self, data):
        """Generate HTML table for CPU information with per-core usage"""
        rows = ""
        for key, value in data.items():
            if key == "CPU Usage Per Core":
                rows += f"<tr><td class='key'>{key}</td><td class='value'>"
                for core, usage in value.items():
                    rows += f"<div style='margin-bottom: 5px;'>Core {core}: <span class='highlight'>{usage}%</span></div>"
                rows += "</td></tr>"
            else:
                rows += f"<tr><td class='key'>{key}</td><td class='value'>{value}</td></tr>"
        return rows

    def _generate_network_tables(self):
        """Generate HTML tables for network information"""
        network_tables = ""
        for category, data in self.report_data["network"].items():
            if category == "Interfaces":
                network_tables += "<h3>Network Interfaces</h3>"
                network_tables += self._generate_interfaces_table(data)
            elif category == "Active Connections":
                network_tables += "<h3>Active Connections</h3>"
                network_tables += self._generate_connections_table(data)
            elif category == "DNS Servers":
                network_tables += "<h3>DNS Servers</h3>"
                network_tables += self._generate_list_table(data, "DNS Server")
            else:
                network_tables += f"<h3>{category}</h3>"
                network_tables += self._generate_dict_table(data)
        return network_tables

    def _generate_list_table(self, data, label):
        """Generate HTML table from list data"""
        if not data:
            return "<tr><td>No data available</td></tr>"

        rows = ""
        for item in data:
            rows += f"<tr><td class='value'><div class='highlight'>{item}</div></td></tr>"

        return rows

    def _generate_connections_table(self, data):
        """Generate HTML table for active connections"""
        if not data:
            return "<tr><td colspan='4'>No active connections</td></tr>"

        rows = "<tr><th>Local Address</th><th>Remote Address</th><th>Status</th><th>PID</th></tr>"
        for conn in data:
            rows += f"<tr><td>{conn['Local Address']}</td><td>{conn['Remote Address']}</td><td>{conn['Status']}</td><td>{conn['PID']}</td></tr>"

        return rows

    def _generate_dict_table(self, data):
        """Generate HTML table from dictionary data"""
        if not data:
            return "<tr><td colspan='2'>No data available</td></tr>"

        rows = ""
        for key, value in data.items():
            if isinstance(value, dict):
                rows += f"<tr><td class='key'>{_html.escape(str(key))}</td><td class='value'><table class='nested-table'>"
                for sub_key, sub_value in value.items():
                    rows += f"<tr><td class='key'>{_html.escape(str(sub_key))}</td><td class='value'>{_html.escape(str(sub_value))}</td></tr>"
                rows += "</table></td></tr>"
            else:
                rows += f"<tr><td class='key'>{_html.escape(str(key))}</td><td class='value'>{_html.escape(str(value))}</td></tr>"

        return rows

    def _generate_storage_table(self, data):
        """Generate HTML table for storage information"""
        if not data:
            return "<tr><td colspan='2'>No storage information available</td></tr>"

        rows = ""
        for drive, info in data.items():
            rows += f"<tr><td class='key'>{drive}</td><td class='value'><table class='nested-table'>"
            for key, value in info.items():
                if key == "Percentage":
                    # Add a progress bar for percentage
                    rows += f"<tr><td class='key'>{key}</td><td class='value'>"
                    rows += f"<div class='progress-bar'><div class='progress' style='width:{value}'>{value}</div></div>"
                    rows += "</td></tr>"
                else:
                    rows += f"<tr><td class='key'>{key}</td><td class='value'>{value}</td></tr>"
            rows += "</table></td></tr>"

        return rows

    def _generate_interfaces_table(self, data):
        """Generate HTML table for network interfaces"""
        if not data:
            return "<tr><td colspan='2'>No network interface information available</td></tr>"

        rows = ""
        for interface, info in data.items():
            rows += f"<tr><td class='key'>{interface}</td><td class='value'><table class='nested-table'>"
            for key, value in info.items():
                if key == "IP Addresses" and isinstance(value, list):
                    rows += f"<tr><td class='key'>{key}</td><td class='value'>"
                    for ip in value:
                        rows += f"<div class='highlight'>{ip['Address']}</div> Netmask: {ip['Netmask']}<br>"
                    rows += "</td></tr>"
                else:
                    rows += f"<tr><td class='key'>{key}</td><td class='value'>{value}</td></tr>"
            rows += "</table></td></tr>"

        return rows

    def _generate_security_table(self, data):
        """Generate HTML table for security information"""
        if not data:
            return "<tr><td colspan='2'>No security information available</td></tr>"

        rows = ""
        for key, value in data.items():
            if isinstance(value, dict):
                rows += f"<tr><td class='key'>{key}</td><td class='value'><table class='nested-table'>"
                for sub_key, sub_value in value.items():
                    status = "success" if "Enabled" in str(sub_value) or "On" in str(
                        sub_value) else "danger" if "Disabled" in str(sub_value) or "Off" in str(sub_value) else ""
                    badge = f" <span class='badge {status}'>{sub_value}</span>" if status else f" {sub_value}"
                    rows += f"<tr><td class='key'>{sub_key}</td><td class='value'>{badge}</td></tr>"
                rows += "</table></td></tr>"
            else:
                rows += f"<tr><td class='key'>{key}</td><td class='value'>{value}</td></tr>"

        return rows

    def _generate_users_table(self, data):
        """Generate HTML table for user information"""
        if not data:
            return "<tr><td colspan='2'>No user information available</td></tr>"

        rows = ""
        for key, value in data.items():
            if key == "User Accounts" and isinstance(value, list):
                rows += f"<tr><td class='key'>{key}</td><td class='value'>"
                for user in value:
                    rows += f"<div class='highlight'>{user}</div>"
                rows += "</td></tr>"
            elif key == "User Groups" and isinstance(value, list):
                rows += f"<tr><td class='key'>{key}</td><td class='value'>"
                for group in value:
                    rows += f"<span class='badge'>{group}</span> "
                rows += "</td></tr>"
            else:
                rows += f"<tr><td class='key'>{key}</td><td class='value'>{value}</td></tr>"

        return rows

    def _generate_processes_table(self, data):
        """Generate HTML table for processes"""
        if not data:
            return "<tr><td colspan='6'>No process information available</td></tr>"

        rows = "<tr><th>PID</th><th>Name</th><th>User</th><th>CPU %</th><th>Memory %</th><th>Memory (MB)</th><th>Started</th></tr>"
        for process in data:
            rows += f"<tr><td>{process['PID']}</td><td>{process['Name']}</td><td>{process['User']}</td><td>{process['CPU %']}</td><td>{process['Memory %']}</td><td>{process['Memory (MB)']}</td><td>{process['Started']}</td></tr>"

        return rows

    def _generate_services_table(self, data):
        """Generate HTML table for services"""
        if not data:
            return "<tr><td colspan='5'>No service information available</td></tr>"

        # Determine headers based on the first service
        if data and isinstance(data[0], dict):
            headers = list(data[0].keys())
            rows = "<tr>" + "".join([f"<th>{h}</th>" for h in headers]) + "</tr>"

            for service in data:
                rows += "<tr>"
                for header in headers:
                    value = service.get(header, '')
                    if header == "State":
                        if "RUNNING" in value:
                            value = f"<span class='badge success'>{value}</span>"
                        elif "STOPPED" in value:
                            value = f"<span class='badge danger'>{value}</span>"
                        else:
                            value = f"<span class='badge warning'>{value}</span>"
                    rows += f"<td>{value}</td>"
                rows += "</tr>"

            return rows

        return "<tr><td colspan='5'>Invalid service data format</td></tr>"

    def _generate_devices_table(self, data):
        """Generate HTML table for devices"""
        if not data:
            return "<tr><td colspan='4'>No device information available</td></tr>"

        rows = "<tr><th>Name</th><th>Description</th><th>Manufacturer</th><th>Device ID</th></tr>"
        for device in data:
            if "Error" in device:
                rows += f"<tr><td colspan='4'>{_html.escape(str(device['Error']))}</td></tr>"
            else:
                rows += "<tr>" + "".join(
                    f"<td>{_html.escape(str(device.get(field, '')))}</td>"
                    for field in ("Name", "Description", "Manufacturer", "Device ID")) + "</tr>"

        return rows
