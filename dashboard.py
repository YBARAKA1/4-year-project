import tkinter as tk
from tkinter import ttk, messagebox
from login_window import LoginWindow  
import psutil
import time
import scapy.all as scapy
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading
import queue
from collections import defaultdict
import platform
import math
import random
import subprocess
import psutil
import os
import signal
import math
from trafficanalysis import TrafficAnalysisView  
from constants import MATRIX_BG, MATRIX_GREEN, DARK_GREEN, ACCENT_GREEN
from trafficanalysis import TrafficAnalysisView
from administrator import AdminDashboard
from threatalert import ThreatAlertsView
from login_window import LoginWindow  
# ======================
# Welcome Screen
# ======================

class WelcomeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Welcome")
        self.root.geometry("1024x768")
        self.root.configure(bg="#1a1a1a")

        # Colors
        self.bg_color = "#1a1a1a"
        self.text_color = "#ffffff"
        self.accent_blue = "#00c0ff"
        self.glitch_colors = ["#ff0000", "#00ff00", "#ffff00", "#ff00ff"]  # Red, Green, Yellow, Purple

        # Create welcome label
        self.welcome_label = tk.Label(
            self.root,
            text="Network IDS",
            font=("Segoe UI", 48, "bold"),
            fg=self.accent_blue,
            bg=self.bg_color
        )
        self.welcome_label.place(relx=0.5, rely=0.4, anchor=tk.CENTER)

        # Start glitch effect
        self.root.after(500, self.glitch_effect)

    def glitch_effect(self, count=0):
        """Creates a more realistic glitch effect on 'Welcome'"""
        if count < 8:  # Run glitch effect 8 times
            glitch_text = "N3tw@rk 1D$  " if count % 2 == 0 else "n3tm07sk I96"
            self.welcome_label.config(text=glitch_text, fg=random.choice(self.glitch_colors))
            self.root.after(100, self.glitch_effect, count + 1)
        else:
            self.welcome_label.config(text="Welcome", fg=self.accent_blue)
            self.root.after(500, self.fade_to_black)

    def fade_to_black(self):
        """Turns the screen completely black before displaying hacking effect"""
        self.welcome_label.destroy()
        self.root.configure(bg="black")
        self.root.after(500, self.start_hacking_effect)

    def start_hacking_effect(self):
        """Creates a 'Matrix-style' scrolling green text effect"""
        self.hack_texts = []
        self.hack_canvas = tk.Canvas(self.root, bg="black", highlightthickness=0)
        self.hack_canvas.pack(fill=tk.BOTH, expand=True)

        # Generate 20+ lines of random 'hacking' text
        self.fake_hack_lines = [
            f"root@NIDS:~# {random.choice(['Monitoring traffic...', 'Analyzing packets...', 'Scanning for anomalies...', 'Detecting threats...'])}",
            f"ALERT [{random.randint(1000, 9999)}]: {random.choice(['Possible DDoS attack detected', 'Suspicious SSH brute-force attempt', 'Malicious payload signature identified', 'Unauthorized access attempt'])}",
            f"Packet Capture [{random.randint(1000, 9999)} packets] -> Logging to /var/log/nids.log...",
            f"Snort Rule Triggered: [{random.randint(1000, 9999)}] {random.choice(['SQL Injection', 'XSS Attempt', 'Port Scanning Detected', 'Malware Communication'])}",
            f"Source IP: {random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)} -> Destination IP: {random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
            f"Deep Packet Inspection -> {random.choice(['Suspicious payload found', 'No anomalies detected', 'Potential exploit detected'])}",
            f"Firewall Alert: {random.randint(10, 500)} blocked connections from {random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
            f"Real-time traffic analysis: {random.randint(500, 5000)} packets/sec | {random.randint(50, 500)} anomalies detected",
            f"Anomaly Score: {random.randint(1, 100)} | {random.choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])} risk",
            f"TCP SYN Flood detected: {random.randint(1000, 9999)} requests per second",
            f"Encrypted traffic analysis: {random.choice(['Possible TLS downgrade attack', 'Unusual SSL/TLS handshake', 'No anomalies found'])}",
            f"Botnet C&C Communication detected: {random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)} -> Flagging for further analysis...",
            f"New unauthorized MAC Address detected on network: {':'.join(['%02x' % random.randint(0, 255) for _ in range(6)])}",
            f"IDS Log: {random.randint(10000, 99999)} new security events recorded...",
            f"Port Scan Detected: {random.randint(20, 100)} open ports from IP {random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
            f"DNS Spoofing Attempt: Malicious DNS response from {random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
            f"ARP Spoofing detected: MAC Address mismatch for {random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
            f"Syslog Alert: Unusual activity on port {random.randint(1000, 9999)}",
            f"MITM Attack Warning: Duplicate ARP replies detected from {random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
        ] * 5  # Repeat for more lines

        self.hack_y = 10  # Start printing from the top
        self.type_hacking_text()

    def type_hacking_text(self):
        """Types out the fake hacking text, scrolling down"""
        if self.fake_hack_lines:
            text = self.fake_hack_lines.pop(0)
            hack_label = self.hack_canvas.create_text(20, self.hack_y, anchor="w", text=text, font=("Courier", 14), fill="green")
            self.hack_texts.append(hack_label)
            self.hack_y += 20  # Move down for next line

            # Scroll effect
            if len(self.hack_texts) > 30:
                self.hack_canvas.move("all", 0, -20)  # Shift all text up

            self.root.after(100, self.type_hacking_text)  # Delay between lines
        else:
            self.root.after(1500, self.transition_to_dashboard)  # Wait before switching

    def transition_to_dashboard(self):
        """Flashes the screen and transitions to the dashboard.py file"""
        self.hack_canvas.destroy()
        self.root.destroy()  # Close the welcome window

        # Launch the IDSDashboard
        root = tk.Tk()
        app = IDSDashboard(root)
        root.mainloop()




# ======================
# Detection Engine
# ======================

class IntrusionDetector:
    def __init__(self):
        self.thresholds = {
            'SYN_FLOOD': 50,
            'UDP_FLOOD': 200,
            'ARP_SPOOF': 3
        }
        self.syn_count = defaultdict(int)
        self.udp_count = defaultdict(int)
        self.arp_cache = {}
        self.last_reset = time.time()
        self.bandwidth = [0, 0]  # [incoming, outgoing]
        self.traffic_history = {'in': [], 'out': []}  # Store last 60 seconds

    def detect_attacks(self, packet):
        current_time = time.time()
        time_diff = current_time - self.last_reset

        # Update bandwidth stats
        if packet.haslayer(scapy.IP):
            pkt_size = len(packet)
            if packet[scapy.IP].dst == scapy.conf.iface.ip:
                self.bandwidth[0] += pkt_size
            else:
                self.bandwidth[1] += pkt_size

        if time_diff > 1:
            self.syn_count.clear()
            self.udp_count.clear()
            self.last_reset = current_time
            
            # Update traffic history (convert bytes to kilobytes)
            self.traffic_history['in'].append(self.bandwidth[0] / 1024)  # Convert to KB
            self.traffic_history['out'].append(self.bandwidth[1] / 1024)  # Convert to KB
            self.traffic_history['in'] = self.traffic_history['in'][-60:]
            self.traffic_history['out'] = self.traffic_history['out'][-60:]
            self.bandwidth = [0, 0]

        alert = None
        if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 'S':
            src = packet[scapy.IP].src
            self.syn_count[src] += 1
            if self.syn_count[src] > self.thresholds['SYN_FLOOD']:
                alert = ('SYN Flood', src, packet[scapy.IP].dst)
        
        elif packet.haslayer(scapy.UDP):
            src = packet[scapy.IP].src
            self.udp_count[src] += 1
            if self.udp_count[src] > self.thresholds['UDP_FLOOD']:
                alert = ('UDP Flood', src, packet[scapy.IP].dst)
        
        elif packet.haslayer(scapy.ARP):
            if packet[scapy.ARP].op == 2:  # ARP response
                ip = packet[scapy.ARP].psrc
                mac = packet[scapy.ARP].hwsrc
                if ip in self.arp_cache and self.arp_cache[ip] != mac:
                    alert = ('ARP Spoof', ip, mac)
                self.arp_cache[ip] = mac
                
            # Wireless-specific detection
        if packet.haslayer(scapy.Dot11):
            # Detect deauthentication attacks
            if packet.type == 0 and packet.subtype == 12:  # Deauthentication frame
                alert = ("Deauth Attack", packet.addr2, packet.addr1)
            
        return alert

# ======================
# Matrix-styled GUI
# ======================

class IDSDashboard:
    def __init__(self, root, role=None):
        self.root = root
        self.role = role  # Store the role
        print(f"[DEBUG] Role received in IDSDashboard: {self.role}")
        self.detector = IntrusionDetector()
        self.alert_queue = queue.Queue()
        self.packet_queue = queue.Queue()
        self.attack_stats = {"SYN Flood": 0, "UDP Flood": 0, "ARP Spoofing": 0}
        
        self.current_view = None
        self.views = {}  # Holds the different view frames
        self.logged_in = False  # Track login status
        
        # Initialize packet_tree and alert_tree
        self.packet_tree = None
        self.alert_tree = None
        
        # Update CyberGauge roles if role is provided
        if self.role:
            self.update_gauge_roles(self.role)
        
        # Add login button with theme styling
        self.login_button = tk.Button(
            root,
            text="Login",
            command=self.open_login,
            bg=DARK_GREEN,  # Background color
            fg=MATRIX_GREEN,  # Text color
            font=("Consolas", 10, "bold"),  # Font
            relief="flat",  # Remove button border
            activebackground=DARK_GREEN,  # Background color when clicked
            activeforeground=MATRIX_GREEN  # Text color when clicked
        )
        self.login_button.pack(side=tk.TOP, anchor=tk.NE, padx=10, pady=10)
        
        # Add hover effects to the login button
        self.login_button.bind("<Enter>", lambda e: self.login_button.config(bg=ACCENT_GREEN, fg=MATRIX_BG))
        self.login_button.bind("<Leave>", lambda e: self.login_button.config(bg=DARK_GREEN, fg=MATRIX_GREEN))
        
        self.setup_gui()
        self.setup_threads()
        

        
    def open_login(self):
        """Open the login window and handle login success."""
        # Check if a login window is already open
        if hasattr(self, 'login_window') and self.login_window.winfo_exists():
            return  # Do nothing if the login window is already open

        # Create the login window and pass a callback function
        self.login_window = LoginWindow(self.root, self.handle_login_success)
        self.root.wait_window(self.login_window)  # Wait for the login window to close
    
    def handle_login_success(self, role):
        """Handle successful login by updating the role and enabling admin features."""
        print(f"[DEBUG] Login successful. Role: {role}")
        self.logged_in = True
        self.role = role  # Set the role attribute
        self.login_button.config(text="Logout", command=self.logout)  # Change button to logout
        self.enable_sidebar_buttons()  # Enable all sidebar buttons
        self.update_gauge_roles(role)  # Update the role in CyberGauge instances
        messagebox.showinfo("Login Successful", "You have successfully logged in!")
        

    def update_gauge_roles(self, role):
        """Update the role in all CyberGauge instances."""
        if hasattr(self, 'cpu_gauge'):
            self.cpu_gauge.set_role(role)
        if hasattr(self, 'mem_gauge'):
            self.mem_gauge.set_role(role)
        print(f"[DEBUG] Updated CyberGauge roles to: {role}")  # Debug: Confirm role update
        
    def logout(self):
        """Log out the user and restrict access to other pages."""
        self.logged_in = False
        self.login_button.config(text="Login", command=self.open_login)  # Reset button to login
        self.disable_sidebar_buttons()  # Disable all sidebar buttons except Dashboard
        self.show_view("Dashboard")  # Switch back to the Dashboard
        messagebox.showinfo("Logged Out", "You have been logged out.")
        
    def disable_sidebar_buttons(self):
        """Disable all sidebar buttons except the Dashboard button."""
        for button in self.sidebar_buttons:
            if button["text"] != "Dashboard":
                button.config(state=tk.DISABLED)  # Disable the button
                
    def enable_sidebar_buttons(self):
        """Enable all sidebar buttons after successful login."""
        for button in self.sidebar_buttons:
            if button["text"] == "Administrator" and self.role != "admin":
                button.config(state=tk.DISABLED)  # Disable Administrator button for non-admin users
            else:
                button.config(state=tk.NORMAL)  # Enable all other buttons

    def show_view(self, view_name):
        """Show the specified view, but restrict access based on user role."""
        if view_name != "Dashboard" and not self.logged_in:
            messagebox.showinfo("Login Required", "Please log in to access this feature.")
            return

        # Restrict access to the Administrator page for non-admin users
        if view_name == "Administrator" and self.role != "admin":
            messagebox.showinfo("Access Denied", "You do not have permission to access the Administrator page.")
            return

        # Hide current view
        if self.current_view:
            self.current_view.pack_forget()

        # Create new view if not exists
        if view_name not in self.views:
            if view_name == "Dashboard":
                self.views[view_name] = self.create_dashboard_view()
            elif view_name == "PacketStream":
                self.views[view_name] = self.create_packet_stream_view()
            elif view_name == "TrafficAnalysis":
                self.views[view_name] = TrafficAnalysisView(self.container)
            elif view_name == "ThreatAlerts":
                self.views[view_name] = ThreatAlertsView(self.container)
            elif view_name == "Administrator":
                self.views[view_name] = AdminDashboard(self.container)
            elif view_name == "Terminal":
                from terminal import TerminalView  # Import the TerminalView
                self.views[view_name] = TerminalView(self.container)

        # Display the view
        self.current_view = self.views[view_name]
        self.current_view.pack(fill=tk.BOTH, expand=True)
    
    def show_terminal(self):
        """Show the Terminal view."""
        self.show_view("Terminal")
        
    def setup_threads(self):
        def sniff_packets():
            while True:
                try:
                    scapy.sniff(
                        prn=self.process_packet,
                        store=0,
                        filter="ip or arp or tcp or udp"  # Filter packets of interest
                    )
                except Exception as e:
                    print(f"Sniffing error: {e}. Reopening socket...")
                    time.sleep(1)  # Wait before reopening the socket

        sniff_thread = threading.Thread(target=sniff_packets, daemon=True)
        sniff_thread.start()

        # GUI update thread
        self.root.after(1000, self.update_gui)
        
        

    def show_view(self, view_name):
        """Show the specified view, but restrict access based on user role."""
        if view_name != "Dashboard" and not self.logged_in:
            messagebox.showinfo("Login Required", "Please log in to access this feature.")
            return

        # Restrict access to the Administrator page for non-admin users
        if view_name == "Administrator" and self.role != "admin":
            messagebox.showinfo("Access Denied", "You do not have permission to access the Administrator page.")
            return

        # Hide current view
        if self.current_view:
            self.current_view.pack_forget()

        # Create new view if not exists
        if view_name not in self.views:
            if view_name == "Dashboard":
                self.views[view_name] = self.create_dashboard_view()
            elif view_name == "PacketStream":
                self.views[view_name] = self.create_packet_stream_view()
            elif view_name == "TrafficAnalysis":
                self.views[view_name] = TrafficAnalysisView(self.container)
            elif view_name == "ThreatAlerts":
                self.views[view_name] = ThreatAlertsView(self.container)
            elif view_name == "Administrator":
                self.views[view_name] = AdminDashboard(self.container)
            elif view_name == "Terminal":
                from terminal import TerminalView  # Import the TerminalView
                self.views[view_name] = TerminalView(self.container)

        # Display the view
        self.current_view = self.views[view_name]
        self.current_view.pack(fill=tk.BOTH, expand=True)

    def setup_gui(self):
        self.root.title("MATRIX IDS 2.0")
        self.root.geometry("1400x900")
        self.root.configure(bg=MATRIX_BG)

        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure(".", background=MATRIX_BG, foreground=MATRIX_GREEN)
        self.style.configure("Header.TLabel", font=("Consolas", 14, "bold"))
        self.style.configure("Treeview", 
                            background=DARK_GREEN,
                            foreground=MATRIX_GREEN,
                            fieldbackground=DARK_GREEN,
                            borderwidth=0)
        self.style.map('Treeview', background=[('selected', '#001a00')])

        # Main paned window
        main_pane = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True)

        # Collapsible Sidebar
        self.sidebar = ttk.Frame(main_pane, width=200, style="Sidebar.TFrame")
        self.setup_sidebar(self.sidebar)
        main_pane.add(self.sidebar)

        # Main Content Container (replaces left and right panels)
        self.container = ttk.Frame(main_pane)
        main_pane.add(self.container, weight=1)  # Allow container to expand

        # Show default view
        self.show_view("Dashboard")
        
    def show_view(self, view_name):
        """Show the specified view, but restrict access based on user role."""
        if view_name != "Dashboard" and not self.logged_in:
            messagebox.showinfo("Login Required", "Please log in to access this feature.")
            return

        # Restrict access to the Administrator page for non-admin users
        if view_name == "Administrator" and self.role != "admin":
            messagebox.showinfo("Access Denied", "You do not have permission to access the Administrator page.")
            return

        # Hide current view
        if self.current_view:
            self.current_view.pack_forget()

        # Create new view if not exists
        if view_name not in self.views:
            if view_name == "Dashboard":
                self.views[view_name] = self.create_dashboard_view()
            elif view_name == "PacketStream":
                self.views[view_name] = self.create_packet_stream_view()
            elif view_name == "TrafficAnalysis":
                self.views[view_name] = TrafficAnalysisView(self.container)
            elif view_name == "ThreatAlerts":
                self.views[view_name] = ThreatAlertsView(self.container)
            elif view_name == "Administrator":
                self.views[view_name] = AdminDashboard(self.container)
            elif view_name == "Terminal":
                from terminal import TerminalView  # Import the TerminalView
                self.views[view_name] = TerminalView(self.container)

        # Display the view
        self.current_view = self.views[view_name]
        self.current_view.pack(fill=tk.BOTH, expand=True)
        
    def create_dashboard_view(self):
        """Dashboard view with system stats and traffic overview."""
        frame = ttk.Frame(self.container)
        
        # Left Panel - System Stats
        left_panel = ttk.Frame(frame, width=300)
        ttk.Label(left_panel, text="SYSTEM MONITOR", style="Header.TLabel").pack(pady=15)
        self.cpu_gauge = CyberGauge(left_panel, "\nCPU LOAD", width=300, height=330, bg=MATRIX_BG, fg=MATRIX_GREEN, role=self.role)  # Pass role
        self.cpu_gauge.pack(pady=10)
        self.mem_gauge = CyberGauge(left_panel, "\nMEMORY USAGE", width=300, height=330, bg=MATRIX_BG, fg=MATRIX_GREEN, role=self.role)  # Pass role
        self.mem_gauge.pack(pady=10)
        ttk.Label(left_panel, text="LIVE TRAFFIC", style="Header.TLabel").pack(pady=10)
        self.net_stats = ttk.Label(left_panel, text="IN: 0.00 MB/s\nOUT: 0.00 MB/s", font=("Consolas", 10))
        self.net_stats.pack()
        left_panel.pack(side=tk.LEFT, fill=tk.Y)

        # Right Panel - Traffic Overview
        right_panel = ttk.Frame(frame)
        self.setup_traffic_chart(right_panel)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        return frame

    def create_threat_alerts_view(self):
        frame = ttk.Frame(self.container)
        ttk.Label(frame, text="Threat Alerts", font=("Consolas", 16)).pack(pady=20)
        # Add threat alerts widgets here
        return frame

    def create_packet_stream_view(self):
        frame = ttk.Frame(self.container)
        self.setup_packet_table(frame)
        return frame

    def setup_sidebar(self, parent):
        # Sidebar styling
        self.style.configure("Sidebar.TFrame", background=DARK_GREEN)
        self.style.configure("Sidebar.TButton", 
                            background=DARK_GREEN, 
                            foreground=MATRIX_GREEN,
                            font=("Consolas", 10),
                            borderwidth=0)
        self.style.map("Sidebar.TButton", 
                    background=[('active', '#001a00')])

        # Toggle button to collapse/expand sidebar
        self.toggle_button = ttk.Button(parent, text="☰", style="Sidebar.TButton",
                                        command=self.toggle_sidebar)
        self.toggle_button.pack(pady=10, fill=tk.X)

        # Navigation buttons
        buttons = [
            ("Dashboard", self.show_dashboard),
            ("Packet Stream", self.show_packet_stream),
            ("Traffic Analysis", self.show_traffic_analysis),
            ("Threat Alerts", self.show_threat_alerts),
            ("Administrator", self.show_admin_page),
            ("Terminal", self.show_terminal),  # Add the Terminal button
        ]

        # Store sidebar buttons for enabling/disabling
        self.sidebar_buttons = []
        for text, command in buttons:
            button = ttk.Button(parent, text=text, style="Sidebar.TButton",
                                command=command)
            button.pack(pady=5, fill=tk.X)
            self.sidebar_buttons.append(button)

        # Initially disable all buttons except Dashboard
        self.disable_sidebar_buttons()
        self.sidebar_buttons[0].config(state=tk.NORMAL)  # Enable Dashboard button

        # Initially show the sidebar
        self.sidebar_visible = True
    
    

    def toggle_sidebar(self):
        if self.sidebar_visible:
            self.sidebar.pack_forget()  # Hide the sidebar
            self.sidebar_visible = False
            self.toggle_button.config(text="☰")  # Change button text
        else:
            self.sidebar.pack(side=tk.LEFT, fill=tk.Y)  # Show the sidebar
            self.sidebar_visible = True
            self.toggle_button.config(text="✕")  # Change button text
            
    

    def show_dashboard(self):
        self.show_view("Dashboard")

    def show_traffic_analysis(self):
        self.show_view("TrafficAnalysis")

    def show_threat_alerts(self):
        self.show_view("ThreatAlerts")

    def show_packet_stream(self):
        self.show_view("PacketStream")
        
    def show_admin_page(self):
        """Show the Admin Dashboard view."""
        self.root.title("Admin Dashboard")  # Set the window title
        self.show_view("Administrator")
        

    def setup_left_panel(self, parent):
        # System Monitoring
        ttk.Label(parent, text="SYSTEM MONITOR", style="Header.TLabel").pack(pady=15)
        
        self.cpu_gauge = CyberGauge(parent, "CPU LOAD", 
                                    width=250, height=250,
                                    bg=MATRIX_BG, fg=MATRIX_GREEN)
        self.cpu_gauge.pack(pady=10)

        self.mem_gauge = CyberGauge(parent, "MEMORY USAGE", 
                                    width=250, height=250,
                                    bg=MATRIX_BG, fg=MATRIX_GREEN)
        self.mem_gauge.pack(pady=10)

        # Network Stats
        ttk.Label(parent, text="LIVE TRAFFIC", style="Header.TLabel").pack(pady=10)
        self.net_stats = ttk.Label(parent, text="IN: 0.00 MB/s\nOUT: 0.00 MB/s",
                                    font=("Consolas", 10))
        self.net_stats.pack()

    def setup_right_panel(self, parent):
        notebook = ttk.Notebook(parent)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Packet Capture Tab
        packet_frame = ttk.Frame(notebook)
        self.setup_packet_table(packet_frame)
        notebook.add(packet_frame, text="Packet Stream")

        # Traffic Analysis Tab
        traffic_frame = ttk.Frame(notebook)
        self.setup_traffic_chart(traffic_frame)
        notebook.add(traffic_frame, text="Traffic Analysis")


    def setup_packet_table(self, parent):
        columns = ("Time", "Protocol", "Source", "Destination", "Size")
        self.packet_tree = ttk.Treeview(parent, columns=columns, show='headings', height=25)
        for col in columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=150)
        vsb = ttk.Scrollbar(parent, orient="vertical", command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=vsb.set)
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

    def setup_traffic_chart(self, parent):
        self.fig = Figure(figsize=(10, 4), dpi=100, facecolor=MATRIX_BG)  # Set figure background to black
        self.ax = self.fig.add_subplot(111, facecolor=MATRIX_BG)  # Set axes background to black
        
        # X-axis: Represents time progression over a 60-second window.
        self.ax.set_xlabel("Time Progression\n"
                        "(Seconds)", 
                        color=MATRIX_GREEN,  # Set label color to green
                        fontsize=10,
                        labelpad=10)
        
        # Y-axis: Represents network traffic in kilobytes per second (KB/s).
        self.ax.set_ylabel("Network Traffic (Kilobytes per Second)\n"
                        "(Incoming/Outgoing)", 
                        color=MATRIX_GREEN,  # Set label color to green
                        fontsize=10,
                        labelpad=10)
        
        # Configure axis spines and ticks
        self.ax.tick_params(axis='both', colors=MATRIX_GREEN)  # Set tick colors to green
        for spine in self.ax.spines.values():
            spine.set_color(MATRIX_GREEN)  # Set spine colors to green
        
        # Add subtle grid
        self.ax.grid(True, color=DARK_GREEN, linestyle=':', linewidth=0.7, alpha=0.5)
        
        self.canvas = FigureCanvasTkAgg(self.fig, master=parent)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def update_chart(self):
        self.ax.clear()
        
        # Set the background color of the axes to black
        self.ax.set_facecolor(MATRIX_BG)
        
        # Ensure both traffic history arrays have the same length
        min_length = min(len(self.detector.traffic_history['in']), len(self.detector.traffic_history['out']))
        
        if min_length > 0:
            # Create time axis labels (60 seconds -> now)
            seconds_ago = list(range(min_length, 0, -1))  # Ensure seconds_ago matches the length of traffic_history
            
            # Slice the traffic history arrays to match the minimum length
            incoming_traffic = self.detector.traffic_history['in'][-min_length:]
            outgoing_traffic = self.detector.traffic_history['out'][-min_length:]
            
            # Plot both directions with clear labels
            self.ax.plot(seconds_ago, incoming_traffic,
                        color=ACCENT_GREEN, 
                        linewidth=1.5, 
                        label='Incoming Traffic')
            self.ax.plot(seconds_ago, outgoing_traffic,
                        color=MATRIX_GREEN,
                        linestyle='--',
                        linewidth=1.5,
                        label='Outgoing Traffic')
            
            # Configure axis ranges and labels
            self.ax.set_xlim(left=60, right=0)  # Reverse x-axis for intuitive timeline
            self.ax.set_xticks([60, 45, 30, 15, 0])
            self.ax.set_xticklabels([
                '60s', 
                '45s', 
                '30s', 
                '15s', 
                '0s'
            ], color=MATRIX_GREEN)  # Set tick label color to green
            
            # Y-axis configuration
            max_traffic = max(max(incoming_traffic), max(outgoing_traffic))
            
            # Ensure the y-axis has a minimum range to avoid flat lines
            y_min = 0
            y_max = max_traffic if max_traffic > 0 else 1  # Ensure y_max is at least 1 if max_traffic is 0
            
            self.ax.set_ylim(bottom=y_min, top=y_max)
            
            # Set y-ticks dynamically based on the current traffic
            if y_max > 0:
                # Calculate dynamic y-ticks based on the range of traffic
                y_ticks = [y_min, y_max / 4, y_max / 2, y_max * 0.75, y_max]
                y_tick_labels = [
                    '0 KB/s', 
                    f'{y_max / 4:.1f} KB/s', 
                    f'{y_max / 2:.1f} KB/s', 
                    f'{y_max * 0.75:.1f} KB/s', 
                    f'{y_max:.1f} KB/s'
                ]
                
                self.ax.set_yticks(y_ticks)
                self.ax.set_yticklabels(y_tick_labels, color=MATRIX_GREEN)  # Set tick label color to green
            else:
                self.ax.set_yticks([y_min, y_max])
                self.ax.set_yticklabels([
                    '0 KB/s', 
                    '0 KB/s'
                ], color=MATRIX_GREEN)  # Set tick label color to green
            
            # Reapply styling after clear
            self.ax.set_xlabel("Time Progression (60 Second Window)\n"
                        "Left (60s ago) → Right (Current Moment)", 
                        color=MATRIX_GREEN,  # Set label color to green
                        fontsize=10,
                        labelpad=10)
            
            self.ax.set_ylabel("Network Traffic (Kilobytes per Second)\n"
                        "Volume of Data Transferred (Incoming/Outgoing)", 
                        color=MATRIX_GREEN,  # Set label color to green
                        fontsize=10,
                        labelpad=10)
        
            self.ax.tick_params(axis='both', colors=MATRIX_GREEN)
            for spine in self.ax.spines.values():
                spine.set_color(MATRIX_GREEN)
            
            # Add subtle grid
            self.ax.grid(True, color=DARK_GREEN, linestyle=':', linewidth=0.7, alpha=0.5)
            
            # Add legend with improved visibility
            legend = self.ax.legend(
                facecolor=MATRIX_BG,  # Set legend background to black
                edgecolor=MATRIX_GREEN,  # Set legend border color to green
                labelcolor=MATRIX_GREEN,  # Set legend text color to green
                loc='upper left',
                bbox_to_anchor=(0, 1),
                fontsize=8  # Adjust font size for better readability
            )
            
            self.canvas.draw()



    def update_gui(self):
        # Update system metrics
        self.cpu_gauge.set_value(psutil.cpu_percent())
        self.mem_gauge.set_value(psutil.virtual_memory().percent)
        
        # Update network stats (convert to KB/s)
        net_in = self.detector.traffic_history['in'][-1] if self.detector.traffic_history['in'] else 0
        net_out = self.detector.traffic_history['out'][-1] if self.detector.traffic_history['out'] else 0
        self.net_stats.config(text=f"IN: {net_in:.2f} KB/s\nOUT: {net_out:.2f} KB/s")
        
        # Process packets and alerts
        self.process_queues()
        
        # Update the chart
        self.update_chart()
        
        self.root.after(1000, self.update_gui)
    
    def process_queues(self):
        # Process alerts
        while not self.alert_queue.empty():
            alert = self.alert_queue.get()
            if "ThreatAlerts" in self.views:  # Check if ThreatAlerts view exists
                self.views["ThreatAlerts"].add_alert(alert)
            self.attack_stats[alert[1]] += 1
        
        # Process packets
        while not self.packet_queue.empty():
            packet = self.packet_queue.get()
            if self.packet_tree:  # Check if packet_tree exists
                self.packet_tree.insert("", "end", values=packet)
                # Keep last 1000 packets
                if len(self.packet_tree.get_children()) > 1000:
                    self.packet_tree.delete(self.packet_tree.get_children()[0])


    def process_packet(self, packet):
        try:
            # Detection logic
            result = self.detector.detect_attacks(packet)
            if result:
                alert_time = time.strftime("%H:%M:%S")
                self.alert_queue.put((alert_time, *result))
            
            # Packet capture (handle both IP and 802.11 frames)
            if packet.haslayer(scapy.IP):
                proto = packet[scapy.IP].proto
                protocol = {
                    1: "ICMP",
                    6: "TCP",
                    17: "UDP"
                }.get(proto, "Other")
                
                pkt_time = time.strftime("%H:%M:%S")
                source = packet[scapy.IP].src
                dest = packet[scapy.IP].dst
                size = len(packet)
                
                self.packet_queue.put((pkt_time, protocol, source, dest, size))
            elif packet.haslayer(scapy.Dot11):  # Handle 802.11 wireless frames
                pkt_time = time.strftime("%H:%M:%S")
                protocol = "802.11"
                source = packet.addr2 if packet.addr2 else "Unknown"
                dest = packet.addr1 if packet.addr1 else "Unknown"
                size = len(packet)
                
                self.packet_queue.put((pkt_time, protocol, source, dest, size))
            elif packet.haslayer(scapy.ARP):  # Handle ARP packets
                pkt_time = time.strftime("%H:%M:%S")
                protocol = "ARP"
                source = packet[scapy.ARP].psrc
                dest = packet[scapy.ARP].pdst
                size = len(packet)
                
                self.packet_queue.put((pkt_time, protocol, source, dest, size))
        except Exception as e:
            print(f"Error processing packet: {e}")

# ======================
# Cyber-styled Gauge
# ======================

class CyberGauge(tk.Canvas):
    def __init__(self, parent, title, bg, fg, role=None, **kwargs):
        super().__init__(parent, bg=bg, **kwargs)
        self.title = title
        self.value = 0
        self.bg = bg
        self.fg = fg
        self.role = role  # Store the role
        self.bind("<Configure>", self.draw_gauge)
        self.bind("<Button-1>", self.show_processes)  # Left-click to show processes
        self.bind("<Button-3>", self.show_context_menu)  # Right-click for context menu
        self.context_menu = None  # Track the context menu
        self.process_window = None  # Track the process window

    def set_role(self, role):
        """Update the role dynamically."""
        self.role = role
        print(f"[DEBUG] Role updated in CyberGauge: {self.role}")  # Debug: Confirm role update

    def show_context_menu(self, event):
        """Display a context menu with process management options."""
        print(f"[DEBUG] Role in context menu: {self.role}") 
        # Close the existing context menu if it's open
        self.close_context_menu()

        # Get the item under the cursor
        item = self.process_tree.identify_row(event.y)
        if not item:
            return  # Do nothing if no row is under the cursor

        # Select the row
        self.process_tree.selection_set(item)
        pid = self.process_tree.item(item, "values")[0]
        
        # Debug: Print the role in the context menu
        print(f"[DEBUG] Role in context menu: {self.role}")

        # Create a context menu with Matrix theme
        self.context_menu = tk.Menu(self, tearoff=0, bg=DARK_GREEN, fg=MATRIX_GREEN)
        
        # Check if the user is an admin
        if self.role == 'admin':
            print("[DEBUG] Admin access granted in context menu")  # Debug: Confirm admin access
            # Add process management options for admin
            self.context_menu.add_command(label="Stop", command=lambda: self.manage_process(pid, "stop"))
            self.context_menu.add_command(label="Kill", command=lambda: self.manage_process(pid, "kill"))
            self.context_menu.add_command(label="Terminate", command=lambda: self.manage_process(pid, "terminate"))
            
            # Add priority submenu with Matrix theme
            priority_menu = tk.Menu(self.context_menu, tearoff=0, bg=DARK_GREEN, fg=MATRIX_GREEN)
            priority_menu.add_command(label="High", command=lambda: self.set_priority(pid, -10))
            priority_menu.add_command(label="Medium", command=lambda: self.set_priority(pid, 0))
            priority_menu.add_command(label="Low", command=lambda: self.set_priority(pid, 10))
            self.context_menu.add_cascade(label="Priority", menu=priority_menu)
        else:
            print("[DEBUG] Non-admin access in context menu")  # Debug: Confirm non-admin access
            # If the user is not an admin, show a message
            self.context_menu.add_command(
                label="Actions restricted",
                command=lambda: messagebox.showinfo(
                    "Admin Only",
                    "These actions are only available to the administrator. Please log in as an administrator."
                )
            )
        
        # Show the context menu at the cursor position
        self.context_menu.post(event.x_root, event.y_root)

    def draw_gauge(self, event=None):
        self.delete("all")
        w = self.winfo_width()
        h = self.winfo_height()
        size = min(w, h) - 20
        
        # Create gradient effect
        for i in range(0, 270, 5):
            self.create_arc(10, 10, 10+size, 10+size,
                            start=45+i, extent=5,
                            outline=self.fade_color(i/270),
                            width=3, style="arc")
        
        # Value indicator (fixed line continuation)
        angle = 45 + (270 * (self.value / 100))
        self.create_line(w/2, h/2,
                        w/2 + (size/2)*0.8 * math.cos(math.radians(angle)),
                        h/2 + (size/2)*0.8 * math.sin(math.radians(angle)),
                        fill="#ff3300", width=3)
        # Center text
        self.create_text(w/2, h/2, text=f"{self.value}%", 
                        fill=self.fg, font=("Consolas", 14, "bold"))
        self.create_text(w/2, h-15, text=self.title,
                        fill=self.fg, font=("Consolas", 10))

    def fade_color(self, progress):
        r = int(0x00 * (1 - progress) + 0x00 * progress)
        g = int(0xcc * (1 - progress) + 0xff * progress)
        b = int(0x00 * (1 - progress) + 0x00 * progress)
        return f"#{r:02x}{g:02x}{b:02x}"

    def set_value(self, value):
        self.value = min(max(value, 0), 100)
        self.draw_gauge()

    def show_processes(self, event):
        """Display a table of processes when the gauge is clicked."""
        # Check if the process window is already open
        if self.process_window and self.process_window.winfo_exists():
            self.process_window.lift()  # Bring the existing window to the front
            return  # Exit the method to prevent opening a new window

        # If no window is open, create a new one
        processes = self.get_processes()
        self.process_window = tk.Toplevel(self)
        self.process_window.title(f"{self.title} Processes")
        self.process_window.configure(bg=MATRIX_BG)  # Matrix theme
        
        # Create a treeview to display processes
        columns = ("PID", "Name", "CPU %", "Memory %", "RSS")
        self.process_tree = ttk.Treeview(self.process_window, columns=columns, show='headings')
        for col in columns:
            self.process_tree.heading(col, text=col)
            self.process_tree.column(col, width=100)
        
        # Populate the treeview with process data
        for proc in processes:
            self.process_tree.insert("", "end", values=proc)
        
        self.process_tree.pack(fill=tk.BOTH, expand=True)
        
        # Bind right-click to show context menu
        self.process_tree.bind("<Button-3>", self.show_context_menu)
        
        # Bind left-click to close context menu
        self.process_tree.bind("<Button-1>", self.close_context_menu)
        
        # Bind window close event to close context menu
        self.process_window.protocol("WM_DELETE_WINDOW", self.close_process_window)

    def get_processes(self):
        """Get a list of processes with their details."""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'memory_info']):
            try:
                processes.append((
                    proc.info['pid'],
                    proc.info['name'],
                    proc.info['cpu_percent'],
                    proc.info['memory_percent'],
                    proc.info['memory_info'].rss // 1024  # Convert to KB
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return processes



    def close_context_menu(self, event=None):
        """Close the context menu if it is open."""
        if self.context_menu:
            self.context_menu.destroy()
            self.context_menu = None

    def close_process_window(self):
        """Close the process window and context menu."""
        self.close_context_menu()
        if self.process_window:
            self.process_window.destroy()
            self.process_window = None  # Reset the process_window variable

    def manage_process(self, pid, action):
        """Manage a process based on the selected action."""
        try:
            pid = int(pid)  # Convert pid to an integer
            process = psutil.Process(pid)
            if action == "stop":
                process.suspend()
                messagebox.showinfo("Success", f"Process {pid} has been stopped.")
            elif action == "kill":
                process.kill()
                messagebox.showinfo("Success", f"Process {pid} has been killed.")
            elif action == "terminate":
                process.terminate()
                messagebox.showinfo("Success", f"Process {pid} has been terminated.")
        except psutil.NoSuchProcess:
            messagebox.showerror("Error", f"Process {pid} no longer exists.")
        except psutil.AccessDenied:
            messagebox.showerror("Error", "Permission denied. Try running as administrator.")
        except ValueError:
            messagebox.showerror("Error", f"Invalid PID: {pid}")
        finally:
            self.close_context_menu()

    def set_priority(self, pid, priority):
        """Set the priority of a process."""
        try:
            pid = int(pid)  # Convert pid to an integer
            process = psutil.Process(pid)
            process.nice(priority)
            messagebox.showinfo("Success", f"Priority of process {pid} has been set to {priority}.")
        except psutil.NoSuchProcess:
            messagebox.showerror("Error", f"Process {pid} no longer exists.")
        except psutil.AccessDenied:
            messagebox.showerror("Error", "Permission denied. Try running as administrator.")
        except ValueError:
            messagebox.showerror("Error", f"Invalid PID: {pid}")
        finally:
            self.close_context_menu()

# ======================
# Launch Application
# ======================

if __name__ == "__main__":
    root = tk.Tk()
    welcome_app = WelcomeApp(root)  
    root.mainloop()