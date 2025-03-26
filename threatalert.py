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
    def __init__(self, parent, role=None, first_name=None):
        super().__init__(parent)
        self.parent = parent
        self.role = role  # Store the role
        self.first_name = first_name  # Store the first name
        print(f"[DEBUG] Role received in ThreatAlertsView: {self.role}")
        print(f"[DEBUG] First name received in ThreatAlertsView: {self.first_name}")
        
        self.alerts = []  # Stores all alerts
        self.packet_counts = defaultdict(int)
        self.arp_table = {}
        self.port_scan_counts = defaultdict(set)
        self.blocked_ips = set()
        self.safe_ips = set()
        self.ip_details = {}
        self.is_detection_paused = False  # Add flag for pause state
        self.sniffing_thread = None  # Store the sniffing thread

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
            print(f"[BLOCK] Attempting to block IP: {ip}")
            self.blocked_ips.add(ip)
            self.alert_tree.item(selected_item, values=(*self.alert_tree.item(selected_item, "values")[:-1], "Blocked"))
            self.log_blocked_threat(ip)  # Call the updated logging method
            messagebox.showinfo("Block IP", f"IP {ip} has been blocked.")
        else:
            messagebox.showwarning("No Selection", "Please select a threat to block its IP.")

    def mark_safe(self):
        """Mark the selected IP as safe."""
        selected_item = self.alert_tree.selection()
        if selected_item:
            ip = self.alert_tree.item(selected_item, "values")[1]
            print(f"[SAFE] Attempting to mark IP as safe: {ip}")
            self.safe_ips.add(ip)
            self.alert_tree.item(selected_item, values=(*self.alert_tree.item(selected_item, "values")[:-1], "Safe"))
            
            # Use the stored user information
            if self.role and self.first_name:
                user_info = f"{self.first_name} ({self.role})"
            else:
                user_info = "Unknown User"
                
            self.log_safe_threat(ip, user_info)
            messagebox.showinfo("Mark as Safe", f"IP {ip} has been marked as safe.")
        else:
            messagebox.showwarning("No Selection", "Please select a threat to mark its IP as safe.")

    def log_blocked_threat(self, ip):
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
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                
                # Use the stored user information
                if self.role and self.first_name:
                    user_info = f"{self.first_name} ({self.role})"
                else:
                    user_info = "Unknown User"
                
                print(f"[DB] Attempting to log blocked threat: {threat_type}, {ip}, {timestamp}, {severity}, {user_info}")
                
                cur.execute(
                    "INSERT INTO threat_actions (time, action, ip, threat_type, severity, action_by) "
                    "VALUES (%s, %s, %s, %s, %s, %s)",
                    (timestamp, 'Blocked', ip, threat_type, severity, user_info)
                )
                
                conn.commit()
                print(f"[DB SUCCESS] Blocked threat successfully logged to database: {ip}")
        except Exception as e:
            print(f"[DB ERROR] Failed to log blocked threat to database: {e}")
        finally:
            cur.close()
            conn.close()

    def log_safe_threat(self, ip, user_info):
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
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                
                print(f"[DB] Attempting to log safe threat: {threat_type}, {ip}, {timestamp}, {severity}, {user_info}")
                
                cur.execute(
                    "INSERT INTO threat_actions (time, action, ip, threat_type, severity, action_by) "
                    "VALUES (%s, %s, %s, %s, %s, %s)",
                    (timestamp, 'Marked Safe', ip, threat_type, severity, user_info)
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

        # Add Pause/Resume button
        self.pause_button = ttk.Button(
            status_frame,
            text="PAUSE DETECTION",
            command=self.toggle_detection,
            style="Matrix.TButton"
        )
        self.pause_button.pack(side=tk.RIGHT, padx=5)

        # Add Filter Frame
        filter_frame = ttk.LabelFrame(self, text="FILTERS", padding=10, style="Matrix.TLabelframe")
        filter_frame.pack(fill=tk.X, padx=5, pady=(0, 10))

        # Create filter controls
        filter_controls_frame = ttk.Frame(filter_frame, style="Matrix.TFrame")
        filter_controls_frame.pack(fill=tk.X, pady=5)

        # Attack Type Filter
        attack_type_frame = ttk.Frame(filter_controls_frame, style="Matrix.TFrame")
        attack_type_frame.pack(side=tk.LEFT, padx=5)
        ttk.Label(attack_type_frame, text="ATTACK TYPE:", style="Matrix.TLabel").pack(side=tk.LEFT)
        
        self.attack_type_var = tk.StringVar(value="All")
        attack_type_menu = ttk.Combobox(attack_type_frame,
                                      textvariable=self.attack_type_var,
                                      values=["All", "DoS/DDoS Attack", "SYN Flood Attack", "UDP Flood Attack", 
                                             "ICMP Flood Attack", "HTTP Flood Attack", "Port Scanning Detected", 
                                             "ARP Spoofing Detected (MitM)"],
                                      state="readonly",
                                      width=20)
        attack_type_menu.pack(side=tk.LEFT, padx=5)
        attack_type_menu.bind('<<ComboboxSelected>>', self.apply_filters)

        # Severity Filter
        severity_frame = ttk.Frame(filter_controls_frame, style="Matrix.TFrame")
        severity_frame.pack(side=tk.LEFT, padx=5)
        ttk.Label(severity_frame, text="SEVERITY:", style="Matrix.TLabel").pack(side=tk.LEFT)
        
        self.severity_var = tk.StringVar(value="All")
        severity_menu = ttk.Combobox(severity_frame,
                                   textvariable=self.severity_var,
                                   values=["All", "Low", "Medium", "High"],
                                   state="readonly",
                                   width=15)
        severity_menu.pack(side=tk.LEFT, padx=5)
        severity_menu.bind('<<ComboboxSelected>>', self.apply_filters)

        # Clear Filters Button
        clear_btn = ttk.Button(filter_controls_frame,
                             text="CLEAR FILTERS",
                             command=self.clear_filters,
                             style="Matrix.TButton")
        clear_btn.pack(side=tk.RIGHT, padx=5)

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
        if packet_count < 1000:
            return "Low"
        elif 1000 <= packet_count < 2000:
            return "Medium"
        else:
            return "High"

    def detect_syn_flood(self, ip):
        """Detect SYN flood attacks and classify severity."""
        if ip in self.blocked_ips or ip in self.safe_ips:
            return

        self.syn_counts[ip] += 1
        severity = self.classify_syn_flood_severity(self.syn_counts[ip])

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
        if syn_count < 1000:
            return "Low"
        elif 1000 <= syn_count < 20000:
            return "Medium"
        else:
            return "High"

    def detect_udp_flood(self, ip):
        """Detect UDP flood attacks and classify severity."""
        if ip in self.blocked_ips or ip in self.safe_ips:
            return

        self.udp_counts[ip] += 1
        severity = self.classify_udp_flood_severity(self.udp_counts[ip])

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
        if self.is_detection_paused:
            return  # Skip packet processing if detection is paused

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
        """Add a new alert to the treeview if the IP hasn't been marked safe or blocked."""
        try:
            # Extract IP from alert tuple
            ip = alert[1]
            
            # Check if IP is already in memory
            if ip in self.blocked_ips or ip in self.safe_ips:
                print(f"[DEBUG] Skipping alert for blocked/safe IP: {ip}")
                return
                
            # Check database for IP status
            conn = get_db_connection()
            cur = conn.cursor()
            
            # Check both threat_actions and safe_ips tables
            cur.execute("""
                SELECT action FROM threat_actions 
                WHERE ip = %s AND (action = 'Blocked' OR action = 'Marked Safe')
                ORDER BY time DESC LIMIT 1
            """, (ip,))
            
            result = cur.fetchone()
            
            if result:
                action = result[0]
                if action == 'Blocked':
                    self.blocked_ips.add(ip)
                    print(f"[DEBUG] IP {ip} is blocked in database")
                elif action == 'Marked Safe':
                    self.safe_ips.add(ip)
                    print(f"[DEBUG] IP {ip} is marked safe in database")
                return  # Don't add the alert if IP is blocked or safe
            
            # Add alert to the alerts list
            print(f"[DEBUG] Adding new alert to memory: {alert}")
            self.alerts.append(alert)
            
            # Apply current filters
            self.apply_filters()
                
        except Exception as e:
            print(f"[ERROR] Failed to check IP status in database: {e}")
        finally:
            cur.close()
            conn.close()

    def start_real_time_detection(self):
        """Start sniffing network traffic for real-time threat detection."""
        def start_sniffing():
            self.sniffing_thread = sniff(prn=self.packet_callback, store=0)

        # Start sniffing in a separate thread
        self.sniffing_thread = threading.Thread(target=start_sniffing, daemon=True)
        self.sniffing_thread.start()

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
        # Get geolocation data
        geo_data = self.get_geolocation(ip)
        
        # Get threat analysis data
        threat_data = self.get_threat_analysis(ip)
        
        details = {
            "General Information": {
                "IP Address": ip,
                "Hostname": self.resolve_hostname(ip),
                "City": geo_data.get('city', 'Unknown'),
                "Region": geo_data.get('region', 'Unknown'),
                "Country": geo_data.get('country', 'Unknown'),
                "Location": geo_data.get('loc', 'Unknown'),
                "Organization": geo_data.get('org', 'Unknown'),
                "Postal Code": geo_data.get('postal', 'Unknown'),
                "Timezone": geo_data.get('timezone', 'Unknown')
            },
            "Threat Analysis": threat_data
        }
        return details

    def get_geolocation(self, ip):
        """Fetch geolocation data for the given IP using ipinfo.io API."""
        if ip.startswith(("10.", "172.", "192.168.", "239.")):
            return {
                'city': 'Private Network',
                'region': 'Private Network',
                'country': 'Private Network',
                'loc': 'N/A',
                'org': 'Private Network',
                'postal': 'N/A',
                'timezone': 'N/A'
            }

        try:
            api_token = "c146aa543f265e"
            response = requests.get(f"https://ipinfo.io/{ip}?token={api_token}")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Error fetching geolocation data: {e}")
            return {
                'city': 'Unknown',
                'region': 'Unknown',
                'country': 'Unknown',
                'loc': 'Unknown',
                'org': 'Unknown',
                'postal': 'Unknown',
                'timezone': 'Unknown'
            }

    def get_threat_analysis(self, ip):
        """Get accurate threat analysis data for the given IP."""
        threat_data = {
            "Threat Level": "Unknown",
            "Malicious Activity": [],
            "Blacklist Status": self.check_blacklist(ip),
            "VirusTotal Reputation": "Unknown"
        }

        # Get threat level based on alerts
        alerts_for_ip = [alert for alert in self.alerts if alert[1] == ip]
        if alerts_for_ip:
            # Determine threat level based on severity of alerts
            severities = [alert[3] for alert in alerts_for_ip]
            if "High" in severities:
                threat_data["Threat Level"] = "High"
            elif "Medium" in severities:
                threat_data["Threat Level"] = "Medium"
            else:
                threat_data["Threat Level"] = "Low"

            # Get unique threat types
            threat_data["Malicious Activity"] = list(set(alert[2] for alert in alerts_for_ip))

        # Get VirusTotal reputation
        vt_data = self.check_ip_reputation(ip)
        if vt_data and 'data' in vt_data:
            stats = vt_data['data'].get('attributes', {}).get('last_analysis_stats', {})
            malicious_count = stats.get('malicious', 0)
            if malicious_count > 0:
                threat_data["VirusTotal Reputation"] = f"Malicious ({malicious_count} detections)"
            else:
                threat_data["VirusTotal Reputation"] = "Clean"

        return threat_data

    def resolve_hostname(self, ip):
        """Resolve the hostname for the given IP."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return "Unknown"

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

    def show_ip_details(self, details):
        """Display detailed information about the selected IP in a new window."""
        details_window = tk.Toplevel(self)
        details_window.title("IP Details")
        details_window.geometry("800x600")

        # Configure styles
        style = ttk.Style()
        style.configure("Details.TLabel", 
                       background=MATRIX_BG, 
                       foreground=MATRIX_GREEN,
                       font=("Consolas", 10))
        style.configure("Details.TNotebook",
                       background=MATRIX_BG,
                       foreground=MATRIX_GREEN)
        style.configure("Details.TNotebook.Tab",
                       background=MATRIX_BG,
                       foreground=MATRIX_GREEN)

        # Create a notebook for tabs
        notebook = ttk.Notebook(details_window, style="Details.TNotebook")
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Add tabs for each category
        for category, data in details.items():
            tab = ttk.Frame(notebook, style="Matrix.TFrame")
            notebook.add(tab, text=category)

            # Create a frame for the content
            content_frame = ttk.Frame(tab, style="Matrix.TFrame", padding=10)
            content_frame.pack(fill=tk.BOTH, expand=True)

            # Add data to the tab
            for key, value in data.items():
                if isinstance(value, list):
                    # Handle list values (like Malicious Activity)
                    label = ttk.Label(content_frame, 
                                    text=f"{key}:",
                                    style="Details.TLabel")
                    label.pack(anchor=tk.W, padx=10, pady=(5,0))
                    
                    for item in value:
                        item_label = ttk.Label(content_frame,
                                             text=f"• {item}",
                                             style="Details.TLabel")
                        item_label.pack(anchor=tk.W, padx=20, pady=(0,2))
                else:
                    # Handle regular values
                    label = ttk.Label(content_frame,
                                    text=f"{key}: {value}",
                                    style="Details.TLabel")
                    label.pack(anchor=tk.W, padx=10, pady=5)

        # Center the window on the screen
        details_window.update_idletasks()
        width = details_window.winfo_width()
        height = details_window.winfo_height()
        x = (details_window.winfo_screenwidth() // 2) - (width // 2)
        y = (details_window.winfo_screenheight() // 2) - (height // 2)
        details_window.geometry(f'{width}x{height}+{x}+{y}')

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
        export_window.title("Export Threat Data")
        export_window.geometry("400x500")
        export_window.configure(bg=MATRIX_BG)
        
        # Configure styles for the export window
        style = ttk.Style()
        style.configure("Export.TLabel", 
                       background=MATRIX_BG, 
                       foreground=MATRIX_GREEN,
                       font=("Consolas", 10))
        style.configure("Export.TButton",
                       background=DARK_GREEN,
                       foreground=MATRIX_GREEN,
                       font=("Consolas", 10),
                       borderwidth=0)
        style.map("Export.TButton",
                 background=[("active", ACCENT_GREEN)],
                 foreground=[("active", MATRIX_BG)])
        style.configure("Export.TCombobox",
                       background=MATRIX_BG,
                       foreground=MATRIX_GREEN,
                       fieldbackground=MATRIX_BG,
                       selectbackground=ACCENT_GREEN,
                       selectforeground=MATRIX_BG)

        # Main container frame
        main_frame = ttk.Frame(export_window, style="Matrix.TFrame", padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = ttk.Label(main_frame, 
                              text="EXPORT THREAT DATA",
                              font=("Consolas", 16, "bold"),
                              style="Export.TLabel")
        title_label.pack(pady=(0, 20))

        # Format selection frame
        format_frame = ttk.LabelFrame(main_frame, text="EXPORT FORMAT", padding=10, style="Matrix.TLabelframe")
        format_frame.pack(fill=tk.X, pady=(0, 15))
        
        format_var = tk.StringVar(value="CSV")
        format_menu = ttk.Combobox(format_frame, 
                                 textvariable=format_var,
                                 values=["CSV", "PDF", "Excel"],
                                 state="readonly",
                                 style="Export.TCombobox",
                                 width=30)
        format_menu.pack(pady=5)

        # Threat Type selection frame
        type_frame = ttk.LabelFrame(main_frame, text="THREAT TYPE", padding=10, style="Matrix.TLabelframe")
        type_frame.pack(fill=tk.X, pady=(0, 15))
        
        type_var = tk.StringVar(value="High")
        type_menu = ttk.Combobox(type_frame,
                                textvariable=type_var,
                                values=["High", "Medium", "Low", "All"],
                                state="readonly",
                                style="Export.TCombobox",
                                width=30)
        type_menu.pack(pady=5)

        # Status selection frame
        status_frame = ttk.LabelFrame(main_frame, text="THREAT STATUS", padding=10, style="Matrix.TLabelframe")
        status_frame.pack(fill=tk.X, pady=(0, 15))
        
        status_var = tk.StringVar(value="All")
        status_menu = ttk.Combobox(status_frame,
                                 textvariable=status_var,
                                 values=["Active", "Resolved", "Blocked", "Safe", "All"],
                                 state="readonly",
                                 style="Export.TCombobox",
                                 width=30)
        status_menu.pack(pady=5)

        # Button frame
        button_frame = ttk.Frame(main_frame, style="Matrix.TFrame")
        button_frame.pack(fill=tk.X, pady=(20, 0))

        # Export button
        export_btn = ttk.Button(button_frame,
                              text="EXPORT DATA",
                              command=lambda: self.perform_export(format_var.get(), type_var.get(), status_var.get()),
                              style="Export.TButton")
        export_btn.pack(side=tk.RIGHT, padx=5)

        # Cancel button
        cancel_btn = ttk.Button(button_frame,
                              text="CANCEL",
                              command=export_window.destroy,
                              style="Export.TButton")
        cancel_btn.pack(side=tk.RIGHT, padx=5)

        # Center the window on the screen
        export_window.update_idletasks()
        width = export_window.winfo_width()
        height = export_window.winfo_height()
        x = (export_window.winfo_screenwidth() // 2) - (width // 2)
        y = (export_window.winfo_screenheight() // 2) - (height // 2)
        export_window.geometry(f'{width}x{height}+{x}+{y}')

    def perform_export(self, format, type, status):
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
                # Apply filters
                if (type == "All" or values[3] == type) and (status == "All" or values[4] == status):
                    data.append(values)

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
                pdf.cell(40, 10, str(item), border=1)
            pdf.ln()

        pdf.output(file_path)

    def export_to_excel(self, file_path, data):
        """Export data to an Excel file."""
        df = pd.DataFrame(data, columns=["Time", "IP", "Threat Type", "Severity", "Status"])
        df.to_excel(file_path, index=False, engine='openpyxl')

    def apply_filters(self, event=None):
        """Apply the current filters to the alert treeview."""
        print(f"[DEBUG] Applying filters - Attack Type: {self.attack_type_var.get()}, Severity: {self.severity_var.get()}")
        
        # Clear current display
        for item in self.alert_tree.get_children():
            self.alert_tree.delete(item)

        # Get filter values
        attack_type = self.attack_type_var.get()
        severity = self.severity_var.get()

        print(f"[DEBUG] Total alerts in memory: {len(self.alerts)}")

        # Re-add filtered alerts
        for alert in self.alerts:
            # Skip if IP is blocked or safe
            if alert[1] in self.blocked_ips or alert[1] in self.safe_ips:
                print(f"[DEBUG] Skipping blocked/safe IP: {alert[1]}")
                continue

            # Apply filters
            alert_attack_type = alert[2]
            alert_severity = alert[3]

            matches_attack = attack_type == "All" or alert_attack_type == attack_type
            matches_severity = severity == "All" or alert_severity == severity

            print(f"[DEBUG] Alert: {alert}")
            print(f"[DEBUG] Comparing - Attack Type: '{alert_attack_type}' with filter '{attack_type}'")
            print(f"[DEBUG] Matches - Attack: {matches_attack}, Severity: {matches_severity}")

            if matches_attack and matches_severity:
                print(f"[DEBUG] Adding alert to treeview: {alert}")
                self.alert_tree.insert("", "end", values=alert)

        # Update status label
        self.status_label.config(text=f"FILTERED: {attack_type} | {severity}")
        print(f"[DEBUG] Current alerts in treeview: {len(self.alert_tree.get_children())}")

    def clear_filters(self):
        """Clear all filters and show all alerts."""
        print("[DEBUG] Clearing all filters")
        self.attack_type_var.set("All")
        self.severity_var.set("All")
        self.apply_filters()
        self.status_label.config(text="MONITORING ACTIVE")

    def toggle_detection(self):
        """Toggle between pause and resume states for packet detection."""
        if self.is_detection_paused:
            self.resume_detection()
        else:
            self.pause_detection()

    def pause_detection(self):
        """Pause the packet detection."""
        self.is_detection_paused = True
        self.pause_button.config(text="RESUME DETECTION")
        self.status_label.config(text="DETECTION PAUSED")
        print("[DEBUG] Packet detection paused")

    def resume_detection(self):
        """Resume the packet detection."""
        self.is_detection_paused = False
        self.pause_button.config(text="PAUSE DETECTION")
        self.status_label.config(text="MONITORING ACTIVE")
        print("[DEBUG] Packet detection resumed")

# Main application
if __name__ == "__main__":
    root = tk.Tk()
    app = ThreatAlertsView(root)
    root.mainloop()