import socket
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
from collections import defaultdict
from scapy.all import sniff, ARP, IP, TCP
import json
import requests
import joblib
import csv
import pandas as pd
from fpdf import FPDF

from constants import MATRIX_BG, MATRIX_GREEN

class ThreatAlertsView(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.alerts = []  # Stores all alerts
        self.packet_counts = defaultdict(int)  # Track packets per IP for DoS/DDoS
        self.arp_table = {}  # Track IP-MAC mappings for MitM detection
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

        # Load pre-trained anomaly detection model
        self.model = joblib.load("anomaly_detection_model.pkl")

        self.setup_ui()
        self.start_real_time_detection()  # Start real-time threat detection

    def setup_ui(self):
        # Configure the main frame
        self.configure(style="Matrix.TFrame")
        self.pack(fill=tk.BOTH, expand=True)

        # Main title
        title_label = ttk.Label(
            self,
            text="Real-Time Threat Detection",
            font=("Consolas", 20, "bold"),
            background=MATRIX_BG,
            foreground=MATRIX_GREEN
        )
        title_label.pack(pady=10)

        # Button Frame at the Top
        button_frame = ttk.Frame(self)
        button_frame.pack(fill=tk.X, padx=20, pady=10)

        # Buttons for Threat Management
        view_details_btn = ttk.Button(button_frame, text="View Details", command=self.view_details)
        view_details_btn.pack(side=tk.LEFT, padx=5)

        mark_resolved_btn = ttk.Button(button_frame, text="Mark as Resolved", command=self.mark_as_resolved)
        mark_resolved_btn.pack(side=tk.LEFT, padx=5)

        delete_threat_btn = ttk.Button(button_frame, text="Delete Threat", command=self.delete_threat)
        delete_threat_btn.pack(side=tk.LEFT, padx=5)

        # Buttons for Network Response Actions
        block_ip_btn = ttk.Button(button_frame, text="Block IP", command=self.block_ip)
        block_ip_btn.pack(side=tk.LEFT, padx=5)

        mark_safe_btn = ttk.Button(button_frame, text="Mark as Safe", command=self.mark_safe)
        mark_safe_btn.pack(side=tk.LEFT, padx=5)

        # Buttons for Export & Reporting
        export_btn = ttk.Button(button_frame, text="Export", command=self.export_data)
        export_btn.pack(side=tk.LEFT, padx=5)

        # Treeview to display alerts
        self.alert_tree = ttk.Treeview(
            self,
            columns=("Time", "IP", "Threat Type", "Severity", "Status"),
            show="headings",
            style="Matrix.Treeview"
        )
        self.alert_tree.heading("Time", text="Time")
        self.alert_tree.heading("IP", text="IP")
        self.alert_tree.heading("Threat Type", text="Threat Type")
        self.alert_tree.heading("Severity", text="Severity")
        self.alert_tree.heading("Status", text="Status")
        self.alert_tree.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # Scrollbar for the treeview
        scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.alert_tree.yview)
        self.alert_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def detect_dos_ddos(self, ip):
        """Detect DoS/DDoS attacks based on packet count."""
        print(f"Checking DoS/DDoS for IP: {ip}")  # Debug statement
        if ip in self.blocked_ips or ip in self.safe_ips:
            return  # Skip if IP is blocked or marked as safe

        self.packet_counts[ip] += 1
        if self.packet_counts[ip] > 200:  # Threshold: 100 packets in a short time
            alert = (
                time.strftime("%H:%M:%S"),
                ip,
                "DoS/DDoS Attack",
                "High",
                "Active"
            )
            self.alerts.append(alert)
            self.add_alert(alert)
            self.packet_counts[ip] = 0  # Reset count after detection

    def detect_mitm(self, packet):
        """Detect Man-in-the-Middle (MitM) attacks using ARP spoofing detection."""
        if ARP in packet:
            arp = packet[ARP]
            if arp.op == 2:  # ARP reply
                ip = arp.psrc
                mac = arp.hwsrc

                # Check if the IP-MAC mapping has changed
                if ip in self.arp_table:
                    if self.arp_table[ip] != mac:
                        alert = (
                            time.strftime("%H:%M:%S"),
                            ip,
                            "ARP Spoofing Detected (MitM)",
                            "Critical",
                            "Active"
                        )
                        self.alerts.append(alert)
                        self.add_alert(alert)
                else:
                    # Store the new IP-MAC mapping
                    self.arp_table[ip] = mac

    def add_alert(self, alert):
        """Add a new alert to the treeview."""
        self.alert_tree.insert("", "end", values=alert)
        # Keep only the last 100 alerts
        if len(self.alert_tree.get_children()) > 100:
            self.alert_tree.delete(self.alert_tree.get_children()[0])

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
                            "dest_ip": alert["dest_ip"],
                            "signature": alert["alert"]["signature"],
                            "severity": alert["alert"]["severity"]
                        })
        except Exception as e:
            print(f"Error parsing Suricata alerts: {e}")
        return alerts

    def extract_features(self, packet):
        """Extract features from a packet."""
        if IP in packet:
            return [packet[IP].len]  # Example: Use packet size as a feature
        return None

    def detect_anomaly(self, packet):
        """Detect anomalies using the pre-trained model."""
        features = self.extract_features(packet)
        if features:
            prediction = self.model.predict([features])
            return prediction == -1  # -1 indicates an anomaly
        return False

    def packet_callback(self, packet):
        """Callback function for packet sniffing."""
        if IP in packet:
            ip_src = packet[IP].src

            # Signature-based detection (Suricata)
            self.detect_dos_ddos(ip_src)  # Check for DoS/DDoS
            self.detect_mitm(packet)  # Check for MitM

            # Anomaly-based detection
            if self.detect_anomaly(packet):
                alert = (
                    time.strftime("%H:%M:%S"),
                    ip_src,
                    "Anomaly Detected",
                    "Critical",
                    "Active"
                )
                self.alerts.append(alert)
                self.add_alert(alert)

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
                "Location": self.get_geolocation(ip),  # Real geolocation data
                "MAC Address": self.arp_table.get(ip, "Unknown")
            },
            "Connection Details": {
                "First Seen": self.get_first_seen(ip),
                "Last Seen": time.strftime("%H:%M:%S"),
                "Connection Type": self.get_connection_type(ip),  # Real connection type
                "Associated Ports": self.get_associated_ports(ip)  # Real associated ports
            },
            "Threat Analysis": {
                "Threat Level": "High",  # Placeholder
                "Malicious Activity Detected": "DoS/DDoS, Port Scanning",  # Placeholder
                "Blacklist Status": self.check_blacklist(ip)  # Real blacklist status
            },
            "Traffic Statistics": {
                "Total Packets Sent/Received": self.packet_counts.get(ip, 0),
                "Total Data Transferred": "10 MB"  # Placeholder
            },
            "Incident Reports": {
                "Alerts Generated": self.get_alerts_for_ip(ip),
                "Event Timestamps": [alert[0] for alert in self.alerts if alert[1] == ip],
                "Captured Packets": "Raw Packet Data"  # Placeholder
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
        # Skip GeoIP lookup for private or multicast IPs
        if ip.startswith(("10.", "172.", "192.168.", "239.")):
            return "Private/Multicast IP (No GeoIP data)"

        try:
            api_token = "c146aa543f265e"  # Replace with your actual API token
            response = requests.get(f"https://ipinfo.io/{ip}?token={api_token}")
            response.raise_for_status()  # Raise an exception for HTTP errors
            data = response.json()
            location = f"{data.get('city', 'Unknown')}, {data.get('region', 'Unknown')}, {data.get('country', 'Unknown')}, ISP: {data.get('org', 'Unknown')}"
            return location
        except Exception as e:
            print(f"Error fetching geolocation data: {e}")  # Debug statement
            return "Geolocation data unavailable"

    def check_blacklist(self, ip):
        """Check if the IP is blacklisted using AbuseIPDB API."""
        try:
            api_key = "cdcae2dc100a88a2fc43c6d5d85ea52a0ab60d19912301066ab6f178a8aee354645ea834b26ddb29"  # Replace with your actual AbuseIPDB API key
            url = f"https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": api_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": "90"  # Check reports from the last 90 days
            }
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()  # Raise an exception for HTTP errors
            data = response.json()

            # Extract blacklist status
            abuse_confidence_score = data["data"]["abuseConfidenceScore"]
            if abuse_confidence_score > 0:
                return f"Blacklisted (Confidence: {abuse_confidence_score}%)"
            else:
                return "Not Blacklisted"
        except Exception as e:
            print(f"Error fetching blacklist status: {e}")  # Debug statement
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
        # Placeholder logic: You can extend this to analyze packets for the IP
        return "TCP/UDP"

    def get_associated_ports(self, ip):
        """Get the associated ports for the given IP."""
        # Placeholder logic: You can extend this to analyze packets for the IP
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
        # Define the default file extension based on the format
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

        # Prompt the user to select a file path
        file_path = filedialog.asksaveasfilename(
            defaultextension=defaultextension,
            filetypes=file_types
        )

        if file_path:
            # Prepare data for export
            data = []
            for child in self.alert_tree.get_children():
                values = self.alert_tree.item(child, "values")
                if type == "High" and values[3] == "High":
                    data.append(values)
                elif type == "Low" and values[3] == "Low":
                    data.append(values)
                elif type == "Most Reoccurring":
                    # Logic to filter most reoccurring threats
                    pass

            # Perform the export
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

        # Add headers
        headers = ["Time", "IP", "Threat Type", "Severity", "Status"]
        for header in headers:
            pdf.cell(40, 10, header, border=1)
        pdf.ln()

        # Add data
        for row in data:
            for item in row:
                pdf.cell(40, 10, item, border=1)
            pdf.ln()

        pdf.output(file_path)

    def export_to_excel(self, file_path, data):
        """Export data to an Excel file."""
        df = pd.DataFrame(data, columns=["Time", "IP", "Threat Type", "Severity", "Status"])
        df.to_excel(file_path, index=False, engine='openpyxl')  # or engine='xlsxwriter'

    def block_ip(self):
        """Block the selected IP."""
        selected_item = self.alert_tree.selection()
        if selected_item:
            ip = self.alert_tree.item(selected_item, "values")[1]
            self.blocked_ips.add(ip)
            self.alert_tree.item(selected_item, values=(*self.alert_tree.item(selected_item, "values")[:-1], "Blocked"))
            messagebox.showinfo("Block IP", f"IP {ip} has been blocked.")
        else:
            messagebox.showwarning("No Selection", "Please select a threat to block its IP.")

    def mark_safe(self):
        """Mark the selected IP as safe."""
        selected_item = self.alert_tree.selection()
        if selected_item:
            ip = self.alert_tree.item(selected_item, "values")[1]
            self.safe_ips.add(ip)
            self.alert_tree.item(selected_item, values=(*self.alert_tree.item(selected_item, "values")[:-1], "Safe"))
            messagebox.showinfo("Mark as Safe", f"IP {ip} has been marked as safe.")
        else:
            messagebox.showwarning("No Selection", "Please select a threat to mark its IP as safe.")

# Main application
if __name__ == "__main__":
    root = tk.Tk()
    app = ThreatAlertsView(root)
    root.mainloop()