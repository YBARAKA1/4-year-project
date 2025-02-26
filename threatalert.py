import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import random
import time
import csv
import requests  # For geo-location API
from constants import MATRIX_BG, MATRIX_GREEN, DARK_GREEN, ACCENT_GREEN, RED, GREEN, BLUE, PURPLE

class ThreatAlertsView(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.alerts = []  # Stores all alerts
        self.users = {"admin": "admin123", "user": "user123"}  # Example user credentials
        self.current_user = None  # Track the logged-in user
        self.setup_ui()
        self.start_mock_alerts()  # Start generating mock alerts

    def setup_ui(self):
        # Configure the main frame
        self.configure(style="Matrix.TFrame")
        self.pack(fill=tk.BOTH, expand=True)

        # Main title
        title_label = ttk.Label(
            self,
            text="Threat Alert System",
            font=("Consolas", 20, "bold"),
            background=MATRIX_BG,
            foreground=MATRIX_GREEN
        )
        title_label.pack(pady=20)

        # Login frame
        self.login_frame = ttk.Frame(self, style="Matrix.TFrame")
        self.login_frame.pack(pady=20)

        ttk.Label(
            self.login_frame,
            text="Username:",
            style="Matrix.TLabel"
        ).grid(row=0, column=0, padx=10, pady=5)
        self.username_entry = ttk.Entry(self.login_frame, style="Matrix.TEntry")
        self.username_entry.grid(row=0, column=1, padx=10, pady=5)

        ttk.Label(
            self.login_frame,
            text="Password:",
            style="Matrix.TLabel"
        ).grid(row=1, column=0, padx=10, pady=5)
        self.password_entry = ttk.Entry(self.login_frame, show="*", style="Matrix.TEntry")
        self.password_entry.grid(row=1, column=1, padx=10, pady=5)

        ttk.Button(
            self.login_frame,
            text="Login",
            style="Matrix.TButton",
            command=self.authenticate_user
        ).grid(row=2, column=0, columnspan=2, pady=10)

        # Button panel (initially hidden)
        self.button_frame = ttk.Frame(self, style="Matrix.TFrame")
        self.button_frame.pack(fill=tk.X, padx=20, pady=10)

        # Color-coded buttons
        ttk.Button(
            self.button_frame,
            text="🔴 Block IP",
            style="Red.TButton",
            command=self.block_ip
        ).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(
            self.button_frame,
            text="🟢 Mark Safe",
            style="Green.TButton",
            command=self.mark_safe
        ).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(
            self.button_frame,
            text="🔄 Refresh Alerts",
            style="Blue.TButton",
            command=self.refresh_alerts
        ).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(
            self.button_frame,
            text="🟣 Start Monitoring",
            style="Purple.TButton",
            command=self.start_monitoring
        ).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(
            self.button_frame,
            text="📤 Export Logs",
            style="Blue.TButton",
            command=self.export_logs
        ).pack(side=tk.LEFT, padx=5, pady=5)

        # Treeview to display alerts
        self.alert_tree = ttk.Treeview(
            self,
            columns=("Time", "IP", "Threat Type", "Severity", "Status", "Location"),
            show="headings",
            style="Matrix.Treeview"
        )
        self.alert_tree.heading("Time", text="Time")
        self.alert_tree.heading("IP", text="IP")
        self.alert_tree.heading("Threat Type", text="Threat Type")
        self.alert_tree.heading("Severity", text="Severity")
        self.alert_tree.heading("Status", text="Status")
        self.alert_tree.heading("Location", text="Location")
        self.alert_tree.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # Scrollbar for the treeview
        scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.alert_tree.yview)
        self.alert_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Styling
        self.style = ttk.Style()
        self.style.configure("Matrix.TFrame", background=MATRIX_BG)
        self.style.configure("Matrix.TLabel", background=MATRIX_BG, foreground=MATRIX_GREEN, font=("Consolas", 12))
        self.style.configure("Matrix.TEntry", background=DARK_GREEN, foreground=MATRIX_GREEN, font=("Consolas", 12))
        self.style.configure("Matrix.TButton", background=DARK_GREEN, foreground=MATRIX_GREEN, font=("Consolas", 12), padding=10)
        self.style.configure("Matrix.Treeview", background=MATRIX_BG, foreground=MATRIX_GREEN, fieldbackground=DARK_GREEN, font=("Consolas", 12))
        self.style.map("Matrix.Treeview", background=[("selected", ACCENT_GREEN)])
        self.style.configure("Red.TButton", background=RED, foreground="white")
        self.style.configure("Green.TButton", background=GREEN, foreground="white")
        self.style.configure("Blue.TButton", background=BLUE, foreground="white")
        self.style.configure("Purple.TButton", background=PURPLE, foreground="white")

        # Disable buttons until login
        self.toggle_buttons(False)

    def authenticate_user(self):
        """Authenticate user and enable features based on role."""
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username in self.users and self.users[username] == password:
            self.current_user = username
            self.login_frame.pack_forget()  # Hide login frame
            self.toggle_buttons(True)  # Enable buttons
            messagebox.showinfo("Login Successful", f"Welcome, {username}!")
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

    def toggle_buttons(self, state):
        """Enable or disable buttons based on login state."""
        for child in self.button_frame.winfo_children():
            child.configure(state=tk.NORMAL if state else tk.DISABLED)

    def add_alert(self, alert):
        """Add a new alert to the treeview."""
        self.alert_tree.insert("", "end", values=alert)
        # Keep only the last 100 alerts
        if len(self.alert_tree.get_children()) > 100:
            self.alert_tree.delete(self.alert_tree.get_children()[0])
        # Send email/SMS notification for critical threats
        if alert[3] == "High":
            self.send_notification(alert)

    def send_notification(self, alert):
        """Send email/SMS notification for critical threats."""
        message = f"CRITICAL THREAT DETECTED!\nTime: {alert[0]}\nIP: {alert[1]}\nThreat Type: {alert[2]}\nSeverity: {alert[3]}"
        print(f"Sending notification: {message}")  # Replace with actual email/SMS API call

    def block_ip(self):
        """Block the selected IP."""
        selected_item = self.alert_tree.selection()
        if selected_item:
            ip = self.alert_tree.item(selected_item, "values")[1]
            self.alert_tree.item(selected_item, values=(*self.alert_tree.item(selected_item, "values")[:-1], "Blocked"))
            messagebox.showinfo("Block IP", f"IP {ip} has been blocked.")
        else:
            messagebox.showwarning("No Selection", "Please select an alert to block.")

    def mark_safe(self):
        """Mark the selected alert as safe."""
        selected_item = self.alert_tree.selection()
        if selected_item:
            ip = self.alert_tree.item(selected_item, "values")[1]
            self.alert_tree.item(selected_item, values=(*self.alert_tree.item(selected_item, "values")[:-1], "Safe"))
            messagebox.showinfo("Mark Safe", f"Alert for IP {ip} has been marked as safe.")
        else:
            messagebox.showwarning("No Selection", "Please select an alert to mark as safe.")

    def refresh_alerts(self):
        """Refresh the alerts table."""
        self.alert_tree.delete(*self.alert_tree.get_children())
        for alert in self.alerts:
            self.add_alert(alert)

    def start_monitoring(self):
        """Start monitoring for threats."""
        messagebox.showinfo("Monitoring", "Threat monitoring has been started.")
        self.start_mock_alerts()

    def export_logs(self):
        """Export threat logs to a CSV file."""
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if file_path:
            with open(file_path, mode="w", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(["Time", "IP", "Threat Type", "Severity", "Status", "Location"])
                for alert in self.alerts:
                    writer.writerow(alert)
            messagebox.showinfo("Export Successful", f"Logs exported to {file_path}")

    def get_geo_location(self, ip):
        """Get geo-location for an IP address using an external API."""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}")
            data = response.json()
            if data["status"] == "success":
                return f"{data['city']}, {data['country']}"
        except Exception as e:
            print(f"Error fetching geo-location: {e}")
        return "Unknown"

    def start_mock_alerts(self):
        """Simulate live alerts in the background."""
        def generate_mock_alerts():
            while True:
                threat_types = ["DDoS", "Malware", "SQL Injection", "Phishing", "Ransomware"]
                ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
                location = self.get_geo_location(ip)
                alert = (
                    time.strftime("%H:%M:%S"),
                    ip,
                    random.choice(threat_types),
                    random.choice(["Low", "Medium", "High"]),
                    "Active",
                    location
                )
                self.alerts.append(alert)
                self.add_alert(alert)
                time.sleep(random.randint(5, 10))  # Simulate random intervals

        threading.Thread(target=generate_mock_alerts, daemon=True).start()