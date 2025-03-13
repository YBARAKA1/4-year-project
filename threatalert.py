import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import random
import time
import csv
import requests  # For geo-location API
from constants import MATRIX_BG, MATRIX_GREEN, DARK_GREEN, ACCENT_GREEN, RED, GREEN, BLUE, PURPLE

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
from collections import defaultdict
from scapy.all import sniff, ARP, IP, Ether

class ThreatAlertsView(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.alerts = []  # Stores all alerts
        self.packet_counts = defaultdict(int)  # Track packets per IP for DoS/DDoS
        self.arp_table = {}  # Track IP-MAC mappings for MitM detection
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
        title_label.pack(pady=20)

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

    def add_alert(self, alert):
        """Add a new alert to the treeview."""
        self.alert_tree.insert("", "end", values=alert)
        # Keep only the last 100 alerts
        if len(self.alert_tree.get_children()) > 100:
            self.alert_tree.delete(self.alert_tree.get_children()[0])

    def detect_dos_ddos(self, ip):
        """Detect DoS/DDoS attacks based on packet count."""
        self.packet_counts[ip] += 1
        if self.packet_counts[ip] > 100:  # Threshold: 100 packets in a short time
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
        """Detect Man-in-the-Middle attacks using ARP spoofing."""
        if ARP in packet and packet[ARP].op == 2:  # ARP response
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc
            if ip in self.arp_table:
                if self.arp_table[ip] != mac:
                    alert = (
                        time.strftime("%H:%M:%S"),
                        ip,
                        "Man-in-the-Middle Attack",
                        "Critical",
                        "Active"
                    )
                    self.alerts.append(alert)
                    self.add_alert(alert)
            else:
                self.arp_table[ip] = mac

    def packet_callback(self, packet):
        """Callback function for packet sniffing."""
        if IP in packet:
            ip_src = packet[IP].src
            self.detect_dos_ddos(ip_src)  # Check for DoS/DDoS
        self.detect_mitm(packet)  # Check for MitM

    def start_real_time_detection(self):
        """Start sniffing network traffic for real-time threat detection."""
        def start_sniffing():
            sniff(prn=self.packet_callback, store=0)

        # Start sniffing in a separate thread
        threading.Thread(target=start_sniffing, daemon=True).start()

# Main application
if __name__ == "__main__":
    root = tk.Tk()
    app = ThreatAlertsView(root)
    root.mainloop()