import tkinter as tk
from tkinter import ttk, messagebox
import datetime
import random
import threading
import time

class ThreatAlertPage:
    def __init__(self, root):
        self.root = root
        self.root.title("Threat Alert Dashboard")
        self.root.geometry("1000x600")
        
        # Header Label
        self.header = tk.Label(root, text="Network Threat Monitoring System", font=("Arial", 16, "bold"))
        self.header.pack(pady=10)
        
        # Table Setup
        self.tree = ttk.Treeview(root, columns=("Timestamp", "Source IP", "Destination IP", "Threat Type", "Severity", "Status"), show="headings")
        columns = ["Timestamp", "Source IP", "Destination IP", "Threat Type", "Severity", "Status"]
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150, anchor="center")
        
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Control Panel
        self.control_frame = tk.Frame(root)
        self.control_frame.pack(pady=10)
        
        self.block_button = tk.Button(self.control_frame, text="Block IP", command=self.block_ip, bg="red", fg="white", width=12)
        self.block_button.pack(side=tk.LEFT, padx=5)
        
        self.mark_safe_button = tk.Button(self.control_frame, text="Mark Safe", command=self.mark_safe, bg="green", fg="white", width=12)
        self.mark_safe_button.pack(side=tk.LEFT, padx=5)
        
        self.refresh_button = tk.Button(self.control_frame, text="Refresh Alerts", command=self.refresh_alerts, bg="blue", fg="white", width=12)
        self.refresh_button.pack(side=tk.LEFT, padx=5)
        
        self.start_monitoring_button = tk.Button(self.control_frame, text="Start Monitoring", command=self.start_monitoring, bg="purple", fg="white", width=15)
        self.start_monitoring_button.pack(side=tk.LEFT, padx=5)
        
        # Sample Data
        self.refresh_alerts()
        
    def block_ip(self):
        selected_item = self.tree.selection()
        if selected_item:
            for item in selected_item:
                values = self.tree.item(item, 'values')
                messagebox.showinfo("Blocked", f"Blocked IP: {values[1]}")
                self.tree.item(item, values=(values[0], values[1], values[2], values[3], values[4], "Blocked"))
    
    def mark_safe(self):
        selected_item = self.tree.selection()
        if selected_item:
            for item in selected_item:
                values = self.tree.item(item, 'values')
                messagebox.showinfo("Marked Safe", f"Marked as Safe: {values[1]}")
                self.tree.item(item, values=(values[0], values[1], values[2], values[3], values[4], "Safe"))
    
    def refresh_alerts(self):
        self.tree.delete(*self.tree.get_children())
        new_alerts = self.generate_mock_alerts()
        for alert in new_alerts:
            self.tree.insert("", tk.END, values=alert)
    
    def generate_mock_alerts(self):
        threat_types = ["DDoS Attack", "SQL Injection", "Malware", "Phishing Attempt", "Port Scanning", "Brute Force"]
        severities = ["Low", "Medium", "High", "Critical"]
        
        new_alerts = []
        for _ in range(random.randint(5, 10)):
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            source_ip = f"192.168.1.{random.randint(1, 255)}"
            destination_ip = f"192.168.1.{random.randint(1, 255)}"
            threat_type = random.choice(threat_types)
            severity = random.choice(severities)
            status = "Active"
            new_alerts.append((timestamp, source_ip, destination_ip, threat_type, severity, status))
        
        return new_alerts
    
    def start_monitoring(self):
        thread = threading.Thread(target=self.monitor_network)
        thread.daemon = True
        thread.start()
    
    def monitor_network(self):
        while True:
            time.sleep(random.randint(5, 15))
            new_alerts = self.generate_mock_alerts()
            for alert in new_alerts:
                self.tree.insert("", tk.END, values=alert)
            
if __name__ == "__main__":
    root = tk.Tk()
    app = ThreatAlertPage(root)
    root.mainloop()
