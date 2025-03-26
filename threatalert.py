import socket
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
from collections import defaultdict
from scapy.all import sniff, ARP, IP, TCP
import json
import requests
import csv
import pandas as pd
from fpdf import FPDF
from scapy.all import IP, TCP, UDP, ICMP, Raw


from constants import MATRIX_BG, MATRIX_GREEN, DARK_GREEN, ACCENT_GREEN
from login import get_db_connection

class ThreatAlertsView(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.alerts = []  # Stores all alerts
        self.packet_counts = defaultdict(int)  # Track packets per IP for DoS/DDoS
        self.arp_table = {}  # Track IP-MAC mappings for MitM detection
        self.port_scan_counts = defaultdict(set)  # Track unique ports per IP for port scanning
        self.blocked_ips = set()  # Track blocked IPs
        self.safe_ips = set()  # Track safe IPs
        self.ip_details = {}  # Store detailed information for each IP

        # Load Suricata alerts
        suricata_alerts = self.parse_suricata_alerts("/var/log/suricata/eve.json")
        for alert in suricata_alerts:
            self.add_alert((
                alert["timestamp"],
                alert["src_ip"],
                alert["signature"],
                alert["severity"],
                "Active"
            ))

        self.setup_ui()
        self.start_real_time_detection()  # Start real-time threat detection
        
        self.syn_counts = defaultdict(int)  # Track SYN packets for SYN flood detection
        self.udp_counts = defaultdict(int)  # Track UDP packets for UDP flood detection
        self.icmp_counts = defaultdict(int)  # Track ICMP packets for ICMP flood detection
        self.http_counts = defaultdict(int)  # Track HTTP requests for HTTP flood detection

    def show_alert_message(self, threat_type, ip, severity):
        """Show an alert message box with threat details."""
        alert_time = time.strftime("%H:%M:%S")
        message = f"Threat Detected!\n\nType: {threat_type}\nIP: {ip}\nTime: {alert_time}\nSeverity: {severity}"
        
        print(f"[ALERT] Showing alert box for threat: {message}")  # Debug statement
        
        # Show the message box
        response = messagebox.showwarning("Threat Alert", message, type=messagebox.OKCANCEL)
        
        # If the user clicks "OK" (or "Check"), check if they are logged in
        if response == "ok":
            if not self.parent.logged_in:
                messagebox.showinfo("Login Required", "Please log in to view details.")
                self.parent.open_login()
            else:
                self.log_threat_to_db(threat_type, ip, alert_time, severity)

    def log_threat_to_db(self, threat_type, ip, alert_time, severity):
        """Log the threat to the appropriate database table based on severity."""
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            # Convert alert_time to full timestamp if it's just time
            if len(alert_time.split(':')) == 3 and len(alert_time) == 8:  # If format is HH:MM:SS
                timestamp = time.strftime("%Y-%m-%d ") + alert_time
            else:
                timestamp = alert_time
            
            print(f"[DB] Attempting to log {severity.lower()} threat to database: {threat_type}, {ip}, {timestamp}, {severity}")
            
            if severity == "Low":
                cur.execute(
                    "INSERT INTO low_threats (threat_type, ip, time, severity) VALUES (%s, %s, %s, %s)",
                    (threat_type, ip, timestamp, severity)
                )
            elif severity == "Medium":
                cur.execute(
                    "INSERT INTO medium_threats (threat_type, ip, time, severity) VALUES (%s, %s, %s, %s)",
                    (threat_type, ip, timestamp, severity)
                )
            elif severity == "High":
                cur.execute(
                    "INSERT INTO high_threats (threat_type, ip, time, severity) VALUES (%s, %s, %s, %s)",
                    (threat_type, ip, timestamp, severity)
                )
            
            conn.commit()
            print(f"[DB SUCCESS] Threat successfully logged to database: {threat_type}, {ip}, {timestamp}, {severity}")
        except Exception as e:
            print(f"[DB ERROR] Failed to log threat to database: {e}")
        finally:
            cur.close()
            conn.close()

    def block_ip(self):
        """Block the selected IP."""
        selected_item = self.alert_tree.selection()
        if selected_item:
            ip = self.alert_tree.item(selected_item, "values")[1]
            print(f"[BLOCK] Attempting to block IP: {ip}")  # Debug statement
            self.blocked_ips.add(ip)
            self.alert_tree.item(selected_item, values=(*self.alert_tree.item(selected_item, "values")[:-1], "Blocked"))
            self.log_blocked_threat(ip, "admin")
            messagebox.showinfo("Block IP", f"IP {ip} has been blocked.")
        else:
            messagebox.showwarning("No Selection", "Please select a threat to block its IP.")

    def log_blocked_threat(self, ip, action_by):
        """Log the blocked threat to the database."""
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            # Get the threat details from the selected alert
            selected_item = self.alert_tree.selection()
            if selected_item:
                values = self.alert_tree.item(selected_item, "values")
                threat_type = values[2]
                severity = values[3]
                # Get current date and time for the timestamp
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                
                print(f"[DB] Attempting to log blocked threat: {threat_type}, {ip}, {timestamp}, {severity}, {action_by}")
                
                cur.execute(
                    "INSERT INTO threat_actions (time, action, ip, threat_type, severity, action_by) "
                    "VALUES (%s, %s, %s, %s, %s, %s)",
                    (timestamp, 'Blocked', ip, threat_type, severity, action_by)
                )
                
                conn.commit()
                print(f"[DB SUCCESS] Blocked threat successfully logged to database: {ip}")
        except Exception as e:
            print(f"[DB ERROR] Failed to log blocked threat to database: {e}")
        finally:
            cur.close()
            conn.close()

    def mark_safe(self):
        """Mark the selected IP as safe."""
        selected_item = self.alert_tree.selection()
        if selected_item:
            ip = self.alert_tree.item(selected_item, "values")[1]
            print(f"[SAFE] Attempting to mark IP as safe: {ip}")  # Debug statement
            self.safe_ips.add(ip)
            self.alert_tree.item(selected_item, values=(*self.alert_tree.item(selected_item, "values")[:-1], "Safe"))
            self.log_safe_threat(ip, "admin")
            messagebox.showinfo("Mark as Safe", f"IP {ip} has been marked as safe.")
        else:
            messagebox.showwarning("No Selection", "Please select a threat to mark its IP as safe.")

    def log_safe_threat(self, ip, action_by):
        """Log the safe threat to the database."""
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            # Get the threat details from the selected alert
            selected_item = self.alert_tree.selection()
            if selected_item:
                values = self.alert_tree.item(selected_item, "values")
                threat_type = values[2]
                severity = values[3]
                # Get current date and time for the timestamp
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                
                print(f"[DB] Attempting to log safe threat: {threat_type}, {ip}, {timestamp}, {severity}, {action_by}")
                
                cur.execute(
                    "INSERT INTO threat_actions (time, action, ip, threat_type, severity, action_by) "
                    "VALUES (%s, %s, %s, %s, %s, %s)",
                    (timestamp, 'Marked Safe', ip, threat_type, severity, action_by)
                )
                
                conn.commit()
                print(f"[DB SUCCESS] Safe threat successfully logged to database: {ip}")
        except Exception as e:
            print(f"[DB ERROR] Failed to log safe threat to database: {e}")
        finally:
            cur.close()
            conn.close()

    def parse_suricata_alerts(self, log_file):
        """Parse Suricata alerts from eve.json."""
        alerts = []
        try:
            with open(log_file, "r") as f:
                for line in f:
                    alert = json.loads(line)
                    if alert["event_type"] == "alert":
                        alerts.append({
                            "timestamp": alert["timestamp"],
                            "src_ip": alert["src_ip"],
                            "signature": alert["alert"]["signature"],
                            "severity": alert["alert"]["severity"]
                        })
        except Exception as e:
            print(f"Error parsing Suricata alerts: {e}")
        return alerts

    def setup_ui(self):
        """Setup the main UI components with improved Matrix theme styling."""
        # Configure the main frame
        self.configure(style="Matrix.TFrame")
        self.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Configure styles
        style = ttk.Style()
        style.configure("Matrix.TFrame", background=MATRIX_BG)
        style.configure("Matrix.TLabel", 
                       background=MATRIX_BG, 
                       foreground=MATRIX_GREEN,
                       font=("Consolas", 10))
        style.configure("Matrix.TButton",
                       background=DARK_GREEN,
                       foreground=MATRIX_GREEN,
                       font=("Consolas", 10),
                       borderwidth=0)
        style.map("Matrix.TButton",
                 background=[("active", ACCENT_GREEN)],
                 foreground=[("active", MATRIX_BG)])
        style.configure("Matrix.TLabelframe",
                       background=MATRIX_BG,
                       foreground=MATRIX_GREEN)
        style.configure("Matrix.TLabelframe.Label",
                       background=MATRIX_BG,
                       foreground=MATRIX_GREEN,
                       font=("Consolas", 12, "bold"))

        # Main title with Matrix effect
        title_frame = ttk.Frame(self, style="Matrix.TFrame")
        title_frame.pack(fill=tk.X, pady=(0, 20))

        title_label = ttk.Label(
            title_frame,
            text="REAL-TIME THREAT DETECTION",
            font=("Consolas", 24, "bold"),
            style="Matrix.TLabel"
        )
        title_label.pack(pady=5)

        # Status bar with Matrix styling
        status_frame = ttk.Frame(self, style="Matrix.TFrame")
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.status_label = ttk.Label(
            status_frame,
            text="MONITORING ACTIVE",
            font=("Consolas", 10),
            style="Matrix.TLabel"
        )
        self.status_label.pack(side=tk.LEFT)

        # Button Frame with Matrix styling
        button_frame = ttk.LabelFrame(self, text="ACTIONS", padding=10, style="Matrix.TLabelframe")
        button_frame.pack(fill=tk.X, padx=5, pady=(0, 10))

        # Create button groups with Matrix styling
        threat_management_frame = ttk.Frame(button_frame, style="Matrix.TFrame")
        threat_management_frame.pack(fill=tk.X, pady=5)
        ttk.Label(threat_management_frame, text="THREAT MANAGEMENT:", style="Matrix.TLabel").pack(side=tk.LEFT, padx=5)

        view_details_btn = ttk.Button(threat_management_frame, text="VIEW DETAILS", command=self.view_details, style="Matrix.TButton")
        view_details_btn.pack(side=tk.LEFT, padx=5)

        mark_resolved_btn = ttk.Button(threat_management_frame, text="MARK AS RESOLVED", command=self.mark_as_resolved, style="Matrix.TButton")
        mark_resolved_btn.pack(side=tk.LEFT, padx=5)

        delete_threat_btn = ttk.Button(threat_management_frame, text="DELETE THREAT", command=self.delete_threat, style="Matrix.TButton")
        delete_threat_btn.pack(side=tk.LEFT, padx=5)

        network_actions_frame = ttk.Frame(button_frame, style="Matrix.TFrame")
        network_actions_frame.pack(fill=tk.X, pady=5)
        ttk.Label(network_actions_frame, text="NETWORK ACTIONS:", style="Matrix.TLabel").pack(side=tk.LEFT, padx=5)

        block_ip_btn = ttk.Button(network_actions_frame, text="BLOCK IP", command=self.block_ip, style="Matrix.TButton")
        block_ip_btn.pack(side=tk.LEFT, padx=5)

        mark_safe_btn = ttk.Button(network_actions_frame, text="MARK AS SAFE", command=self.mark_safe, style="Matrix.TButton")
        mark_safe_btn.pack(side=tk.LEFT, padx=5)

        export_frame = ttk.Frame(button_frame, style="Matrix.TFrame")
        export_frame.pack(fill=tk.X, pady=5)
        ttk.Label(export_frame, text="EXPORT:", style="Matrix.TLabel").pack(side=tk.LEFT, padx=5)

        export_btn = ttk.Button(export_frame, text="EXPORT DATA", command=self.export_data, style="Matrix.TButton")
        export_btn.pack(side=tk.LEFT, padx=5)

        # Treeview frame with Matrix styling
        tree_frame = ttk.LabelFrame(self, text="THREAT ALERTS", padding=10, style="Matrix.TLabelframe")
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Configure Treeview style with Matrix theme
        style.configure(
            "Matrix.Treeview",
            background=MATRIX_BG,
            foreground=MATRIX_GREEN,
            fieldbackground=MATRIX_BG,
            rowheight=25
        )
        style.configure(
            "Matrix.Treeview.Heading",
            background=MATRIX_BG,
            foreground=MATRIX_GREEN,
            relief="flat",
            font=("Consolas", 10, "bold")
        )
        style.map("Matrix.Treeview.Heading",
                 background=[("active", MATRIX_BG)],
                 foreground=[("active", MATRIX_GREEN)])
        style.map("Matrix.Treeview",
                 background=[("selected", ACCENT_GREEN)],
                 foreground=[("selected", MATRIX_BG)])

        # Treeview with improved columns
        self.alert_tree = ttk.Treeview(
            tree_frame,
            columns=("Time", "IP", "Threat Type", "Severity", "Status"),
            show="headings",
            style="Matrix.Treeview"
        )

        # Configure columns with better widths and alignment
        self.alert_tree.heading("Time", text="TIME")
        self.alert_tree.heading("IP", text="IP ADDRESS")
        self.alert_tree.heading("Threat Type", text="THREAT TYPE")
        self.alert_tree.heading("Severity", text="SEVERITY")
        self.alert_tree.heading("Status", text="STATUS")

        self.alert_tree.column("Time", width=100, anchor="center")
        self.alert_tree.column("IP", width=150, anchor="center")
        self.alert_tree.column("Threat Type", width=200, anchor="w")
        self.alert_tree.column("Severity", width=100, anchor="center")
        self.alert_tree.column("Status", width=100, anchor="center")

        # Add scrollbars with Matrix styling
        y_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.alert_tree.yview)
        x_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.alert_tree.xview)
        self.alert_tree.configure(yscrollcommand=y_scrollbar.set, xscrollcommand=x_scrollbar.set)

        # Grid layout for treeview and scrollbars
        self.alert_tree.grid(row=0, column=0, sticky="nsew")
        y_scrollbar.grid(row=0, column=1, sticky="ns")
        x_scrollbar.grid(row=1, column=0, sticky="ew")

        # Configure grid weights
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)

        # Add hover effect for treeview items
        self.alert_tree.bind("<Motion>", self._on_tree_hover)
        self.hovered_item = None

    def _on_tree_hover(self, event):
        """Handle hover effect on treeview items."""
        try:
            item = self.alert_tree.identify_row(event.y)
            if item and item != self.hovered_item:
                # Reset previous hovered item
                if self.hovered_item:
                    self.alert_tree.item(self.hovered_item, tags=())
                
                # Set new hovered item
                self.hovered_item = item
                self.alert_tree.item(item, tags=("hover",))
        except Exception as e:
            print(f"Error in hover effect: {e}")

    def detect_dos_ddos(self, ip):
        """Detect DoS/DDoS attacks and classify severity based on packet count."""
        if ip in self.blocked_ips or ip in self.safe_ips:
            return  # Skip if IP is blocked or marked as safe

        # Increment packet counts
        self.packet_counts[ip] += 1

        # Classify severity based on packet count
        severity = self.classify_dos_severity(self.packet_counts[ip])

        if severity != "Low":  # Only alert for medium or high severity
            alert = (
                time.strftime("%H:%M:%S"),
                ip,
                f"DoS/DDoS Attack",
                severity,
                "Active"
            )
            self.alerts.append(alert)
            self.add_alert(alert)
            self.packet_counts[ip] = 0  # Reset count after detection

    def classify_dos_severity(self, packet_count):
        """Classify DoS/DDoS severity based on packet count."""
        if packet_count < 500:
            return "Low"
        elif 500 <= packet_count < 1000:
            return "Medium"
        else:
            return "High"

    def detect_syn_flood(self, ip):
        """Detect SYN flood attacks and classify severity."""
        if ip in self.blocked_ips or ip in self.safe_ips:
            return

        self.syn_counts[ip] += 1
        severity = self.classify_syn_flood_severity(self.syn_counts[ip])

        if severity != "Low":
            alert = (
                time.strftime("%H:%M:%S"),
                ip,
                f"SYN Flood Attack",
                severity,
                "Active"
            )
            self.alerts.append(alert)
            self.add_alert(alert)
            self.syn_counts[ip] = 0  # Reset count after detection

    def classify_syn_flood_severity(self, syn_count):
        """Classify SYN flood severity based on SYN packet count."""
        if syn_count < 500:
            return "Low"
        elif 500 <= syn_count < 1000:
            return "Medium"
        else:
            return "High"

    def detect_udp_flood(self, ip):
        """Detect UDP flood attacks and classify severity."""
        if ip in self.blocked_ips or ip in self.safe_ips:
            return

        self.udp_counts[ip] += 1
        severity = self.classify_udp_flood_severity(self.udp_counts[ip])

        if severity != "Low":
            alert = (
                time.strftime("%H:%M:%S"),
                ip,
                f"UDP Flood Attack",
                severity,
                "Active"
            )
            self.alerts.append(alert)
            self.add_alert(alert)
            self.udp_counts[ip] = 0  # Reset count after detection

    def classify_udp_flood_severity(self, udp_count):
        """Classify UDP flood severity based on UDP packet count."""
        if udp_count < 1000:
            return "Low"
        elif 1000 <= udp_count < 5000:
            return "Medium"
        else:
            return "High"

    def detect_icmp_flood(self, ip):
        """Detect ICMP flood attacks and classify severity."""
        if ip in self.blocked_ips or ip in self.safe_ips:
            return

        self.icmp_counts[ip] += 1
        severity = self.classify_icmp_flood_severity(self.icmp_counts[ip])

        if severity != "Low":
            alert = (
                time.strftime("%H:%M:%S"),
                ip,
                f"ICMP Flood Attack",
                severity,
                "Active"
            )
            self.alerts.append(alert)
            self.add_alert(alert)
            self.icmp_counts[ip] = 0  # Reset count after detection

    def classify_icmp_flood_severity(self, icmp_count):
        """Classify ICMP flood severity based on ICMP packet count."""
        if icmp_count < 500:
            return "Low"
        elif 500 <= icmp_count < 1000:
            return "Medium"
        else:
            return "High"

    def detect_http_flood(self, ip):
        """Detect HTTP flood attacks and classify severity."""
        if ip in self.blocked_ips or ip in self.safe_ips:
            return

        self.http_counts[ip] += 1
        severity = self.classify_http_flood_severity(self.http_counts[ip])

        if severity != "Low":
            alert = (
                time.strftime("%H:%M:%S"),
                ip,
                f"HTTP Flood Attack",
                severity,
                "Active"
            )
            self.alerts.append(alert)
            self.add_alert(alert)
            self.http_counts[ip] = 0  # Reset count after detection

    def classify_http_flood_severity(self, http_count):
        """Classify HTTP flood severity based on HTTP request count."""
        if http_count < 100:
            return "Low"
        elif 100 <= http_count < 200:
            return "Medium"
        else:
            return "High"

    def detect_mitm(self, packet):
        """Detect Man-in-the-Middle (MitM) attacks and classify severity."""
        if ARP in packet:
            arp = packet[ARP]
            if arp.op == 2:  # ARP reply
                ip = arp.psrc
                mac = arp.hwsrc

                if ip in self.arp_table:
                    if self.arp_table[ip] != mac:
                        severity = self.classify_mitm_severity(ip)
                        alert = (
                            time.strftime("%H:%M:%S"),
                            ip,
                            f"ARP Spoofing Detected (MitM)",
                            severity,
                            "Active"
                        )
                        self.alerts.append(alert)
                        self.add_alert(alert)
                else:
                    self.arp_table[ip] = mac

    def classify_mitm_severity(self, ip):
        """Classify MITM severity based on ARP spoofing frequency."""
        spoof_count = self.arp_table.get(ip, {}).get("spoof_count", 0)
        spoof_count += 1
        self.arp_table[ip]["spoof_count"] = spoof_count

        if spoof_count < 5:
            return "Low"
        elif 5 <= spoof_count < 10:
            return "Medium"
        else:
            return "High"

    def packet_callback(self, packet):
        """Callback function for packet sniffing."""
        if IP in packet:
            ip_src = packet[IP].src

            # Detect specific threats
            self.detect_dos_ddos(ip_src)
            self.detect_mitm(packet)

            if TCP in packet:
                port = packet[TCP].dport
                self.detect_port_scan(ip_src, port)
                if packet[TCP].flags == "S":  # SYN packet
                    self.detect_syn_flood(ip_src)

            if UDP in packet:
                self.detect_udp_flood(ip_src)

            if ICMP in packet:
                self.detect_icmp_flood(ip_src)

            if Raw in packet and b"HTTP" in packet[Raw].load:
                self.detect_http_flood(ip_src)

    def detect_port_scan(self, ip, port):
        """Detect port scanning by monitoring unique ports accessed by an IP."""
        if ip in self.blocked_ips or ip in self.safe_ips:
            return  # Skip if IP is blocked or marked as safe

        self.port_scan_counts[ip].add(port)

        if len(self.port_scan_counts[ip]) > 50:  # Threshold: 50 unique ports in a short time
            alert = (
                time.strftime("%H:%M:%S"),
                ip,
                "Port Scanning Detected",
                "High",
                "Active"
            )
            self.alerts.append(alert)
            self.add_alert(alert)
        self.port_scan_counts[ip] = set()

    def add_alert(self, alert):
        """Add a new alert to the treeview."""
        self.alert_tree.insert("", "end", values=alert)
        # Keep only the last 100 alerts
        if len(self.alert_tree.get_children()) > 100:
            self.alert_tree.delete(self.alert_tree.get_children()[0])

    def start_real_time_detection(self):
        """Start sniffing network traffic for real-time threat detection."""
        def start_sniffing():
            sniff(prn=self.packet_callback, store=0)

        # Start sniffing in a separate thread
        threading.Thread(target=start_sniffing, daemon=True).start()

    def check_ip_reputation(self, ip):
        """Check the reputation of an IP using VirusTotal."""
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": "eb7f8ebff6ec2a98a9e478ab8e0907c8ca08b2986bd0948e7a958c920f8f335e"}  # Replace with your API key
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Error querying VirusTotal: {e}")
            return None

    def view_details(self):
        selected_item = self.alert_tree.selection()
        if selected_item:
            ip = self.alert_tree.item(selected_item, "values")[1]
            details = self.get_ip_details(ip)

            # Add VirusTotal reputation to details
            vt_reputation = self.check_ip_reputation(ip)
            if vt_reputation:
                details["Threat Analysis"]["VirusTotal Reputation"] = vt_reputation

            self.show_ip_details(details)
        else:
            messagebox.showwarning("No Selection", "Please select a threat to view details.")

    def get_ip_details(self, ip):
        """Fetch detailed information about the selected IP."""
        details = {
            "General Information": {
                "IP Address": ip,
                "Hostname": self.resolve_hostname(ip),
                "Location": self.get_geolocation(ip),
                "MAC Address": self.arp_table.get(ip, "Unknown")
            },
            "Connection Details": {
                "First Seen": self.get_first_seen(ip),
                "Last Seen": time.strftime("%H:%M:%S"),
                "Connection Type": self.get_connection_type(ip),
                "Associated Ports": self.get_associated_ports(ip)
            },
            "Threat Analysis": {
                "Threat Level": "High",
                "Malicious Activity Detected": "DoS/DDoS, Port Scanning",
                "Blacklist Status": self.check_blacklist(ip)
            },
            "Traffic Statistics": {
                "Total Packets Sent/Received": self.packet_counts.get(ip, 0),
                "Total Data Transferred": "10 MB"
            },
            "Incident Reports": {
                "Alerts Generated": self.get_alerts_for_ip(ip),
                "Event Timestamps": [alert[0] for alert in self.alerts if alert[1] == ip],
                "Captured Packets": "Raw Packet Data"
            }
        }
        return details

    def resolve_hostname(self, ip):
        """Resolve the hostname for the given IP."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return "Unknown"

    def get_geolocation(self, ip):
        """Fetch geolocation data for the given IP using ipinfo.io API."""
        if ip.startswith(("10.", "172.", "192.168.", "239.")):
            return "Private/Multicast IP (No GeoIP data)"

        try:
            api_token = "c146aa543f265e"
            response = requests.get(f"https://ipinfo.io/{ip}?token={api_token}")
            response.raise_for_status()
            data = response.json()
            location = f"{data.get('city', 'Unknown')}, {data.get('region', 'Unknown')}, {data.get('country', 'Unknown')}, ISP: {data.get('org', 'Unknown')}"
            return location
        except Exception as e:
            return "Geolocation data unavailable"

    def check_blacklist(self, ip):
        """Check if the IP is blacklisted using AbuseIPDB API."""
        try:
            api_key = "cdcae2dc100a88a2fc43c6d5d85ea52a0ab60d19912301066ab6f178a8aee354645ea834b26ddb29"
            url = f"https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": api_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": "90"
            }
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()

            abuse_confidence_score = data["data"]["abuseConfidenceScore"]
            if abuse_confidence_score > 0:
                return f"Blacklisted (Confidence: {abuse_confidence_score}%)"
            else:
                return "Not Blacklisted"
        except Exception as e:
            return "Blacklist status unavailable"

    def get_first_seen(self, ip):
        """Get the first seen timestamp for the given IP."""
        for alert in self.alerts:
            if alert[1] == ip:
                return alert[0]
        return "Unknown"

    def get_alerts_for_ip(self, ip):
        """Get all alerts generated for the given IP."""
        return [alert[2] for alert in self.alerts if alert[1] == ip]

    def get_connection_type(self, ip):
        """Get the connection type (TCP/UDP) for the given IP."""
        return "TCP/UDP"

    def get_associated_ports(self, ip):
        """Get the associated ports for the given IP."""
        return "80, 443"

    def show_ip_details(self, details):
        """Display detailed information about the selected IP in a new window."""
        details_window = tk.Toplevel(self)
        details_window.title("IP Details")
        details_window.geometry("600x400")

        # Create a notebook for tabs
        notebook = ttk.Notebook(details_window)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Add tabs for each category
        for category, data in details.items():
            tab = ttk.Frame(notebook)
            notebook.add(tab, text=category)

            # Add data to the tab
            for key, value in data.items():
                label = ttk.Label(tab, text=f"{key}: {value}")
                label.pack(anchor=tk.W, padx=10, pady=5)

    def mark_as_resolved(self):
        selected_item = self.alert_tree.selection()
        if selected_item:
            self.alert_tree.item(selected_item, values=(*self.alert_tree.item(selected_item, "values")[:-1], "Resolved"))
        else:
            messagebox.showwarning("No Selection", "Please select a threat to mark as resolved.")

    def delete_threat(self):
        selected_item = self.alert_tree.selection()
        if selected_item:
            self.alert_tree.delete(selected_item)
        else:
            messagebox.showwarning("No Selection", "Please select a threat to delete.")

    def export_data(self):
        """Open a window to select export format and type."""
        export_window = tk.Toplevel(self)
        export_window.title("Export Data")
        export_window.geometry("300x150")

        # Format selection
        format_label = ttk.Label(export_window, text="Select Export Format:")
        format_label.pack(pady=5)
        format_var = tk.StringVar(value="CSV")
        format_menu = ttk.Combobox(export_window, textvariable=format_var, values=["CSV", "PDF", "Excel"])
        format_menu.pack(pady=5)

        # Type selection
        type_label = ttk.Label(export_window, text="Select Threat Type:")
        type_label.pack(pady=5)
        type_var = tk.StringVar(value="High")
        type_menu = ttk.Combobox(export_window, textvariable=type_var, values=["High", "Low", "Most Reoccurring"])
        type_menu.pack(pady=5)

        # Export button
        export_btn = ttk.Button(export_window, text="Export", command=lambda: self.perform_export(format_var.get(), type_var.get()))
        export_btn.pack(pady=10)

    def perform_export(self, format, type):
        """Perform the export based on the selected format and type."""
        if format == "Excel":
            file_types = [("Excel files", "*.xlsx")]
            defaultextension = ".xlsx"
        elif format == "CSV":
            file_types = [("CSV files", "*.csv")]
            defaultextension = ".csv"
        elif format == "PDF":
            file_types = [("PDF files", "*.pdf")]
            defaultextension = ".pdf"
        else:
            messagebox.showerror("Invalid Format", "Unsupported export format.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=defaultextension,
            filetypes=file_types
        )

        if file_path:
            data = []
            for child in self.alert_tree.get_children():
                values = self.alert_tree.item(child, "values")
                if type == "High" and values[3] == "High":
                    data.append(values)
                elif type == "Low" and values[3] == "Low":
                    data.append(values)
                elif type == "Most Reoccurring":
                    pass

            if format == "CSV":
                self.export_to_csv(file_path, data)
            elif format == "PDF":
                self.export_to_pdf(file_path, data)
            elif format == "Excel":
                self.export_to_excel(file_path, data)

            messagebox.showinfo("Export Successful", f"Data exported to {file_path}")

    def export_to_csv(self, file_path, data):
        """Export data to a CSV file."""
        with open(file_path, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["Time", "IP", "Threat Type", "Severity", "Status"])
            writer.writerows(data)

    def export_to_pdf(self, file_path, data):
        """Export data to a PDF file."""
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        headers = ["Time", "IP", "Threat Type", "Severity", "Status"]
        for header in headers:
            pdf.cell(40, 10, header, border=1)
        pdf.ln()

        for row in data:
            for item in row:
                pdf.cell(40, 10, item, border=1)
            pdf.ln()

        pdf.output(file_path)

    def export_to_excel(self, file_path, data):
        """Export data to an Excel file."""
        df = pd.DataFrame(data, columns=["Time", "IP", "Threat Type", "Severity", "Status"])
        df.to_excel(file_path, index=False, engine='openpyxl')

# Main application
if __name__ == "__main__":
    root = tk.Tk()
    app = ThreatAlertsView(root)
    root.mainloop()