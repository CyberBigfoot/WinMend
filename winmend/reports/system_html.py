"""WinMend reports: system html."""

from __future__ import annotations

import html as _html


class ReportSystemHtmlMixin:
    """PCReporter methods grouped by responsibility."""

    def generate_html_report(self):
        """Generate HTML report from collected data"""
        html_content = """<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>PC System Report</title>
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }

                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                    line-height: 1.6;
                    color: #2c3e50;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    padding: 20px;
                }

                .container {
                    max-width: 1400px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 20px;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                    overflow: hidden;
                }

                header {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 40px;
                    text-align: center;
                }

                h1 {
                    font-size: 2.5rem;
                    font-weight: 700;
                    margin-bottom: 10px;
                    text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.2);
                }

                .subtitle {
                    font-size: 1.1rem;
                    opacity: 0.9;
                }

                .summary-cards {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 20px;
                    padding: 30px;
                    background: #f8f9fa;
                }

                .card {
                    background: white;
                    border-radius: 15px;
                    padding: 25px;
                    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08);
                    transition: transform 0.3s ease, box-shadow 0.3s ease;
                }

                .card:hover {
                    transform: translateY(-5px);
                    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.15);
                }

                .card h3 {
                    color: #667eea;
                    font-size: 1.1rem;
                    margin-bottom: 15px;
                    display: flex;
                    align-items: center;
                }

                .card h3::before {
                    content: '';
                    width: 4px;
                    height: 20px;
                    background: #667eea;
                    margin-right: 10px;
                    border-radius: 2px;
                }

                .card-value {
                    font-size: 1.8rem;
                    font-weight: 700;
                    color: #2c3e50;
                    margin-bottom: 5px;
                }

                .card-label {
                    color: #7f8c8d;
                    font-size: 0.9rem;
                }

                .content {
                    padding: 30px;
                }

                .section {
                    margin-bottom: 40px;
                }

                h2 {
                    color: #2c3e50;
                    font-size: 1.8rem;
                    margin-bottom: 20px;
                    padding-bottom: 10px;
                    border-bottom: 3px solid #667eea;
                    display: flex;
                    align-items: center;
                }

                h2::before {
                    content: '';
                    width: 8px;
                    height: 30px;
                    background: #667eea;
                    margin-right: 15px;
                    border-radius: 4px;
                }

                h3 {
                    color: #34495e;
                    font-size: 1.3rem;
                    margin-top: 25px;
                    margin-bottom: 15px;
                    padding-left: 15px;
                    border-left: 3px solid #667eea;
                }

                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 20px;
                    background: white;
                    border-radius: 10px;
                    overflow: hidden;
                    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
                }

                th, td {
                    padding: 15px;
                    text-align: left;
                    border-bottom: 1px solid #ecf0f1;
                }

                th {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    font-weight: 600;
                    text-transform: uppercase;
                    font-size: 0.85rem;
                    letter-spacing: 0.5px;
                }

                tr:nth-child(even) {
                    background: #f8f9fa;
                }

                tr:hover {
                    background: #e8f4fd;
                    transition: background 0.3s ease;
                }

                .key {
                    font-weight: 600;
                    color: #2c3e50;
                    width: 35%;
                }

                .value {
                    color: #34495e;
                    word-break: break-word;
                }

                .nested-table {
                    margin-left: 20px;
                    width: calc(100% - 20px);
                    margin-top: 10px;
                }

                .collapsible {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    cursor: pointer;
                    padding: 18px 25px;
                    width: 100%;
                    border: none;
                    text-align: left;
                    outline: none;
                    font-size: 1rem;
                    font-weight: 600;
                    border-radius: 10px;
                    margin-bottom: 10px;
                    transition: all 0.3s ease;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }

                .collapsible:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
                }

                .collapsible::after {
                    content: '+';
                    font-size: 1.5rem;
                    transition: transform 0.3s ease;
                }

                .collapsible.active::after {
                    transform: rotate(45deg);
                }

                .content-collapsible {
                    padding: 0;
                    display: none;
                    overflow: hidden;
                    background: white;
                    margin-bottom: 20px;
                    border-radius: 10px;
                    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
                }

                .progress-bar {
                    width: 100%;
                    background-color: #ecf0f1;
                    border-radius: 10px;
                    height: 25px;
                    margin-top: 8px;
                    overflow: hidden;
                }

                .progress {
                    height: 100%;
                    background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
                    border-radius: 10px;
                    text-align: center;
                    color: white;
                    line-height: 25px;
                    font-weight: 600;
                    font-size: 0.9rem;
                    transition: width 0.5s ease;
                }

                .badge {
                    display: inline-block;
                    padding: 4px 12px;
                    background: #667eea;
                    color: white;
                    border-radius: 20px;
                    font-size: 0.85rem;
                    font-weight: 600;
                    margin-left: 10px;
                }

                .badge.success {
                    background: #27ae60;
                }

                .badge.warning {
                    background: #f39c12;
                }

                .badge.danger {
                    background: #e74c3c;
                }

                .alert {
                    padding: 15px;
                    margin-bottom: 20px;
                    border-radius: 10px;
                    display: flex;
                    align-items: center;
                }

                .alert.danger {
                    background-color: #fdecea;
                    border-left: 5px solid #e74c3c;
                    color: #e74c3c;
                }

                .alert.warning {
                    background-color: #fef9e7;
                    border-left: 5px solid #f39c12;
                    color: #f39c12;
                }

                .alert.success {
                    background-color: #eafaf1;
                    border-left: 5px solid #27ae60;
                    color: #27ae60;
                }

                .alert-icon {
                    margin-right: 15px;
                    font-size: 1.5rem;
                }

                footer {
                    background: #2c3e50;
                    color: white;
                    text-align: center;
                    padding: 30px;
                    font-size: 0.9rem;
                }

                .highlight {
                    background: linear-gradient(120deg, #a8edea 0%, #fed6e3 100%);
                    padding: 2px 6px;
                    border-radius: 4px;
                    font-weight: 600;
                }

                .startup-enabled {
                    color: #27ae60;
                    font-weight: 600;
                }

                .startup-disabled {
                    color: #e74c3c;
                    font-weight: 600;
                }

                @media (max-width: 768px) {
                    .container {
                        border-radius: 0;
                    }

                    h1 {
                        font-size: 2rem;
                    }

                    .summary-cards {
                        grid-template-columns: 1fr;
                        padding: 20px;
                    }

                    .content {
                        padding: 20px;
                    }

                    table {
                        font-size: 0.9rem;
                    }

                    th, td {
                        padding: 10px;
                    }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <h1>PC System Report</h1>
                    <p class="subtitle">Generated on """ + _html.escape(str(self.report_data["system_info"]["Report Generated"])) + """</p>
                </header>

                <div class="summary-cards">
                    <div class="card">
                        <h3>System</h3>
                        <div class="card-value">""" + _html.escape(str(self.report_data["system_info"]["Operating System"])) + """</div>
                        <div class="card-label">Operating System</div>
                    </div>
                    <div class="card">
                        <h3>Processor</h3>
                        <div class="card-value">""" + _html.escape(str(self.report_data["hardware"]["CPU"]["Total Cores"])) + """</div>
                        <div class="card-label">CPU Cores</div>
                    </div>
                    <div class="card">
                        <h3>Memory</h3>
                        <div class="card-value">""" + _html.escape(str(self.report_data["hardware"]["Memory"]["Total Memory"])) + """</div>
                        <div class="card-label">Total RAM</div>
                    </div>
                    <div class="card">
                        <h3>Uptime</h3>
                        <div class="card-value">""" + _html.escape(str(self.report_data["system_info"]["System Uptime"]).split(',')[0]) + """</div>
                        <div class="card-label">System Running</div>
                    </div>
                </div>

                <div class="content">
                    """ + self._generate_security_alerts() + """

                    <div class="section">
                        <h2>System Information</h2>
                        <table>
                            """ + self._generate_dict_table(self.report_data["system_info"]) + """
                        </table>
                    </div>

                    <div class="section">
                        <h2>Hardware Information</h2>
                        """ + self._generate_hardware_tables() + """
                    </div>

                    <div class="section">
                        <h2>Software Information <span class="badge">""" + str(len(self.report_data["software"])) + """</span></h2>
                        <button type="button" class="collapsible">View Installed Software</button>
                        <div class="content-collapsible">
                            <table>
                                """ + self._generate_dict_table(self.report_data["software"]) + """
                            </table>
                        </div>
                    </div>

                    """ + self._generate_updates_section() + """

                    <div class="section">
                        <h2>Security Vulnerabilities</h2>
                        """ + self._generate_vulnerability_section() + """
                    </div>

                    <div class="section">
                        <h2>Network Information</h2>
                        """ + self._generate_network_tables() + """
                    </div>

                    <div class="section">
                        <h2>Security Information</h2>
                        <table>
                            """ + self._generate_security_table(self.report_data["security"]) + """
                        </table>
                    </div>

                    <div class="section">
                        <h2>User Information</h2>
                        <table>
                            """ + self._generate_users_table(self.report_data["users"]) + """
                        </table>
                    </div>

                    <div class="section">
                        <h2>Startup Items <span class="badge">""" + str(self._count_startup_items()) + """</span></h2>
                        <button type="button" class="collapsible">View Startup Items</button>
                        <div class="content-collapsible">
                            """ + self._generate_startup_items_table() + """
                        </div>
                    </div>

                    <div class="section">
                        <h2>Running Processes <span class="badge">""" + str(len(self.report_data["processes"])) + """</span></h2>
                        <table>
                            """ + self._generate_processes_table(self.report_data["processes"]) + """
                        </table>
                    </div>

                    <div class="section">
                        <h2>System Services <span class="badge">""" + str(len(self.report_data["services"])) + """</span></h2>
                        <button type="button" class="collapsible">View System Services</button>
                        <div class="content-collapsible">
                            <table>
                                """ + self._generate_services_table(self.report_data["services"]) + """
                            </table>
                        </div>
                    </div>

                    <div class="section">
                        <h2>Hardware Devices <span class="badge">""" + str(len(self.report_data["devices"])) + """</span></h2>
                        <button type="button" class="collapsible">View Hardware Devices</button>
                        <div class="content-collapsible">
                            <table>
                                """ + self._generate_devices_table(self.report_data["devices"]) + """
                            </table>
                        </div>
                    </div>

                    <div class="section">
                        <h2>Environment Variables <span class="badge">""" + str(len(self.report_data["environment"])) + """</span></h2>
                        <button type="button" class="collapsible">View Environment Variables</button>
                        <div class="content-collapsible">
                            <table>
                                """ + self._generate_dict_table(self.report_data["environment"]) + """
                            </table>
                        </div>
                    </div>
                </div>

                <footer>
                    <p>PC Reporter - Comprehensive System Analysis Tool</p>
                    <p>Report generated on """ + self.report_data["system_info"]["Report Generated"] + """</p>
                </footer>
            </div>

            <script>
                var coll = document.getElementsByClassName("collapsible");
                var i;

                for (i = 0; i < coll.length; i++) {
                    coll[i].addEventListener("click", function() {
                        this.classList.toggle("active");
                        var content = this.nextElementSibling;
                        if (content.style.display === "block") {
                            content.style.display = "none";
                        } else {
                            content.style.display = "block";
                        }
                    });
                }

                // Add smooth scroll behavior
                document.querySelectorAll('a[href^="#"]').forEach(anchor => {
                    anchor.addEventListener("click", function (e) {
                        e.preventDefault();
                        document.querySelector(this.getAttribute("href")).scrollIntoView({
                            behavior: "smooth"
                        });
                    });
                });
            </script>
        </body>
        </html>"""

        # Write to file with UTF-8 encoding
        try:
            with open(self.report_file, "w", encoding='utf-8') as f:
                f.write(html_content)
        except Exception as e:
            print(f"Error writing HTML file: {e}")
            # Fallback: try without encoding parameter
            with open(self.report_file, "w") as f:
                f.write(html_content)

        return self.report_file
