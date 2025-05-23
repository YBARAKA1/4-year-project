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
        # Set window to start maximized in a cross-platform way
        if platform.system() == 'Windows':
            self.root.state('zoomed')
        else:
            # For Linux and other systems, get screen dimensions and set window size
            screen_width = self.root.winfo_screenwidth()
            screen_height = self.root.winfo_screenheight()
            self.root.geometry(f"{screen_width}x{screen_height}+0+0")
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
    def __init__(self, root, role=None, first_name=None):
        self.root = root
        self.role = role  # Store the role
        self.first_name = first_name  # Store the first name
        print(f"[DEBUG] Role received in IDSDashboard: {self.role}")
        print(f"[DEBUG] First name received in IDSDashboard: {self.first_name}")
        
        # Colors
        self.bg_color = "#1a1a1a"
        self.text_color = "#ffffff"
        self.accent_blue = "#00c0ff"
        self.glitch_colors = ["#ff0000", "#00ff00", "#ffff00", "#ff00ff"]  # Red, Green, Yellow, Purple
        
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
        
        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Set window to start maximized in a cross-platform way
        if platform.system() == 'Windows':
            self.root.state('zoomed')
        else:
            # For Linux and other systems, get screen dimensions and set window size
            screen_width = self.root.winfo_screenwidth()
            screen_height = self.root.winfo_screenheight()
            self.root.geometry(f"{screen_width}x{screen_height}+0+0")

    def setup_gui(self):
        """Set up the main GUI components."""
        self.root.title("MATRIX IDS 2.0")
        self.root.configure(bg=MATRIX_BG)

        # Configure styles with modern look
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure base styles
        self.style.configure(".", 
                           background=MATRIX_BG, 
                           foreground=MATRIX_GREEN,
                           font=("Segoe UI", 10))
        
        # Configure header style
        self.style.configure("Header.TLabel", 
                           font=("Segoe UI", 14, "bold"),
                           background=MATRIX_BG,
                           foreground=MATRIX_GREEN,
                           padding=10)
        
        # Configure Treeview with modern look
        self.style.configure("Treeview", 
                            background=DARK_GREEN,
                            foreground=MATRIX_GREEN,
                            fieldbackground=DARK_GREEN,
                           borderwidth=0,
                           rowheight=25)
        
        # Configure Treeview headings
        self.style.configure("Treeview.Heading",
                           background=DARK_GREEN,
                           foreground=MATRIX_GREEN,
                           font=("Segoe UI", 10, "bold"))
        
        # Configure Treeview selection
        self.style.map('Treeview', 
                      background=[('selected', ACCENT_GREEN)],
                      foreground=[('selected', MATRIX_BG)])
        
        # Configure Button styles
        self.style.configure("Sidebar.TButton",
                           background=DARK_GREEN,
                           foreground=MATRIX_GREEN,
                           font=("Segoe UI", 10),
                           padding=10,
                            borderwidth=0)
        
        self.style.map("Sidebar.TButton",
                      background=[('active', ACCENT_GREEN)],
                      foreground=[('active', MATRIX_BG)])

        # Top frame for toggle button with modern styling
        self.top_frame = ttk.Frame(self.root)
        self.top_frame.pack(fill=tk.X, padx=5, pady=5)

        # Modern toggle button
        self.toggle_button = ttk.Button(
            self.top_frame, 
            text="☰", 
            style="Sidebar.TButton",
            command=self.toggle_sidebar,
            width=3
        )
        self.toggle_button.pack(side=tk.LEFT)

        # Main container with fixed layout
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill=tk.BOTH, expand=True)

        # Sidebar with modern styling
        self.sidebar = ttk.Frame(self.main_container, width=200, style="Sidebar.TFrame")
        self.setup_sidebar(self.sidebar)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)

        # Main content area with padding
        self.container = ttk.Frame(self.main_container)
        self.container.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Initialize status label
        self.status_label = ttk.Label(
            self.top_frame,
            text="Not logged in",
            style="Header.TLabel"
        )
        self.status_label.pack(side=tk.RIGHT, padx=10)

        # Show default view
        self.show_view("Dashboard")
        
        # Initialize CyberGauge instances if they don't exist
        if not hasattr(self, 'cpu_gauge'):
            self.cpu_gauge = CyberGauge(self.container, "CPU LOAD", MATRIX_BG, MATRIX_GREEN, role=self.role)
        if not hasattr(self, 'mem_gauge'):
            self.mem_gauge = CyberGauge(self.container, "MEMORY USAGE", MATRIX_BG, MATRIX_GREEN, role=self.role)

    def on_closing(self):
        """Handle window closing with animation."""
        self.start_closing_animation()
        
    def start_closing_animation(self):
        """Start the closing animation sequence."""
        # Safely hide all current widgets
        for widget in self.root.winfo_children():
            try:
                if hasattr(widget, 'pack_forget'):
                    widget.pack_forget()
                elif hasattr(widget, 'grid_forget'):
                    widget.grid_forget()
                elif hasattr(widget, 'place_forget'):
                    widget.place_forget()
            except Exception:
                continue
            
        # Create canvas for closing animation
        self.close_canvas = tk.Canvas(self.root, bg="black", highlightthickness=0)
        self.close_canvas.pack(fill=tk.BOTH, expand=True)
        
        # Generate fake hack lines for closing
        self.close_hack_lines = [
            f"root@NIDS:~# {random.choice(['Shutting down monitoring...', 'Closing connections...', 'Saving logs...', 'Terminating processes...'])}",
            f"ALERT [{random.randint(1000, 9999)}]: {random.choice(['System shutdown initiated', 'Backing up configurations', 'Clearing temporary files', 'Closing network interfaces'])}",
            f"Packet Capture [{random.randint(1000, 9999)} packets] -> Saving to /var/log/nids.log...",
            f"Snort Rule Triggered: [{random.randint(1000, 9999)}] {random.choice(['Final system check', 'Security audit complete', 'Network interfaces down', 'System shutdown in progress'])}",
            f"Source IP: {random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)} -> Destination IP: {random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
            f"Deep Packet Inspection -> {random.choice(['Final security check', 'System shutdown complete', 'All processes terminated'])}",
            f"Firewall Alert: {random.randint(10, 500)} connections closed from {random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
            f"Real-time traffic analysis: {random.randint(500, 5000)} packets/sec | {random.randint(50, 500)} final checks",
            f"Anomaly Score: {random.randint(1, 100)} | {random.choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])} risk",
            f"TCP SYN Flood detected: {random.randint(1000, 9999)} requests per second",
            f"Encrypted traffic analysis: {random.choice(['Final security check', 'System shutdown in progress', 'All processes terminated'])}",
            f"Botnet C&C Communication detected: {random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)} -> Final analysis...",
            f"New unauthorized MAC Address detected on network: {':'.join(['%02x' % random.randint(0, 255) for _ in range(6)])}",
            f"IDS Log: {random.randint(10000, 99999)} final security events recorded...",
            f"Port Scan Detected: {random.randint(20, 100)} open ports from IP {random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
            f"DNS Spoofing Attempt: Final check from {random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
            f"ARP Spoofing detected: MAC Address mismatch for {random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
            f"Syslog Alert: Final activity check on port {random.randint(1000, 9999)}",
            f"MITM Attack Warning: Final check from {random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
        ] * 5  # Repeat for more lines
        
        self.close_hack_y = 10
        self.type_closing_text()
        
    def type_closing_text(self):
        """Types out the closing animation text."""
        if self.close_hack_lines:
            text = self.close_hack_lines.pop(0)
            self.close_canvas.create_text(20, self.close_hack_y, anchor="w", text=text, font=("Courier", 14), fill="green")
            self.close_hack_y += 20
            
            # Scroll effect
            if self.close_hack_y > self.root.winfo_height():
                self.close_canvas.move("all", 0, -20)
                
            self.root.after(100, self.type_closing_text)
        else:
            self.root.after(500, self.start_glitch_effect)
            
    def start_glitch_effect(self):
        """Start the glitch effect before closing."""
        self.close_canvas.delete("all")
        self.glitch_label = tk.Label(
            self.close_canvas,
            text="Network IDS",
            font=("Segoe UI", 48, "bold"),
            fg=self.accent_blue,
            bg="black"
        )
        self.glitch_label.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
        self.glitch_count = 0
        self.glitch_effect()
        
    def glitch_effect(self):
        """Creates a glitch effect before closing."""
        if self.glitch_count < 8:
            glitch_text = "N3tw@rk 1D$  " if self.glitch_count % 2 == 0 else "n3tm07sk I96"
            self.glitch_label.config(text=glitch_text, fg=random.choice(self.glitch_colors))
            self.glitch_count += 1
            self.root.after(100, self.glitch_effect)
        else:
            self.root.after(500, self.fade_to_black)
            
    def fade_to_black(self):
        """Fade to black before closing."""
        self.glitch_label.destroy()
        self.close_canvas.configure(bg="black")
        self.root.after(500, self.root.destroy)
        
    def open_login(self):
        """Open the login window and handle login success."""
        # Check if a login window is already open
        if hasattr(self, 'login_window') and self.login_window.winfo_exists():
            return  # Do nothing if the login window is already open

        # Create the login window and pass a callback function
        self.login_window = LoginWindow(self.root, self.handle_login_success)
        self.root.wait_window(self.login_window)  # Wait for the login window to close
    
    def handle_login_success(self, role, first_name):
        """Handle successful login."""
        print(f"[DEBUG] Login successful. Role: {role}, First Name: {first_name}")
        self.logged_in = True
        self.role = role
        self.first_name = first_name
        
        # Update role in CyberGauge instances safely
        try:
            if hasattr(self, 'cpu_gauge'):
                self.cpu_gauge.set_role(role)
                print(f"[DEBUG] Updated CPU gauge role: {role}")
            if hasattr(self, 'mem_gauge'):
                self.mem_gauge.set_role(role)
                print(f"[DEBUG] Updated memory gauge role: {role}")
        except Exception as e:
            print(f"[ERROR] Failed to update gauge roles: {e}")
        
        # Update user section safely
        try:
            if hasattr(self, 'user_section_label') and self.user_section_label.winfo_exists():
                self.user_section_label.config(text=f"{self.first_name}'s Section")
            else:
                # Create user section label if it doesn't exist
                self.user_section_label = ttk.Label(
                    self.top_frame,
                    text=f"{self.first_name}'s Section",
                    style="Header.TLabel"
                )
                self.user_section_label.pack(side=tk.LEFT, padx=10)
        except Exception as e:
            print(f"[ERROR] Failed to update user section: {e}")
        
        # Enable/disable buttons based on role
        self.enable_sidebar_buttons()
        
        # Update status label
        if hasattr(self, 'status_label'):
            self.status_label.config(text=f"Logged in as {self.first_name} ({self.role})")
        
        # Update login button
        self.login_button.config(text="Logout", command=self.logout)
        
        # Show success message
        messagebox.showinfo("Success", f"Welcome back, {self.first_name}!")

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
        if hasattr(self, 'user_section_label'):
            self.user_section_label.destroy()  # Remove the user section label
        if hasattr(self, 'status_label'):
            self.status_label.config(text="Not logged in")  # Reset status label
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
                # Pass the user information to ThreatAlertsView
                self.views[view_name] = ThreatAlertsView(self.container, self.role, self.first_name)
            elif view_name == "Administrator":
                self.views[view_name] = AdminDashboard(self.container)
            elif view_name == "Terminal":
                from terminal import TerminalView
                self.views[view_name] = TerminalView(self.container)
            elif view_name == "PortScanner":
                from port_scanner import PortScannerView
                self.views[view_name] = PortScannerView(self.container)

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

    def create_packet_stream_view(self):
        """Create the packet stream view."""
        frame = ttk.Frame(self.container)
        self.setup_packet_table(frame)
        return frame

    def setup_sidebar(self, parent):
        # Sidebar styling with modern look
        self.style.configure("Sidebar.TFrame", 
                            background=DARK_GREEN, 
                            borderwidth=0)
        
        # Add a header to the sidebar
        header_frame = ttk.Frame(parent, style="Sidebar.TFrame")
        header_frame.pack(fill=tk.X, pady=(10, 20))
        
        header_label = ttk.Label(header_frame, 
                               text="MATRIX IDS",
                               style="Header.TLabel",
                               background=DARK_GREEN)
        header_label.pack(pady=5)
        
        # Navigation buttons with modern styling
        buttons = [
            ("Dashboard", self.show_dashboard),
            ("Packet Stream", self.show_packet_stream),
            ("Traffic Analysis", self.show_traffic_analysis),
            ("Threat Alerts", self.show_threat_alerts),
            ("Port Scanner", self.show_port_scanner),
            ("Administrator", self.show_admin_page),
            ("Terminal", self.show_terminal),
        ]

        # Store sidebar buttons for enabling/disabling
        self.sidebar_buttons = []
        for text, command in buttons:
            button = ttk.Button(parent, 
                              text=text, 
                              style="Sidebar.TButton",
                                command=command)
            button.pack(pady=2, fill=tk.X, padx=5)
            self.sidebar_buttons.append(button)

        # Initially disable all buttons except Dashboard
        self.disable_sidebar_buttons()
        self.sidebar_buttons[0].config(state=tk.NORMAL)  # Enable Dashboard button

        # Initially show the sidebar
        self.sidebar_visible = True

    def toggle_sidebar(self):
        """Toggle the sidebar visibility."""
        if self.sidebar_visible:
            self.sidebar.pack_forget()  # Hide the sidebar
            self.sidebar_visible = False
            self.toggle_button.config(text="☰")  # Change button text
        else:
            # Always pack the sidebar on the left side
            self.sidebar.pack(side=tk.LEFT, fill=tk.Y, before=self.container)
            self.sidebar_visible = True
            self.toggle_button.config(text="✕")  # Change button text

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
        
    def show_port_scanner(self):
        """Show the Port Scanner view."""
        self.show_view("PortScanner")

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
        """Create an enhanced packet stream view with modern styling."""
        # Create main container frame with padding
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create top control panel with modern styling
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))

        # Add filter controls with modern look
        filter_frame = ttk.LabelFrame(control_frame, 
                                    text="Packet Filter", 
                                    padding=10)
        filter_frame.pack(side=tk.LEFT, padx=4)

        # Protocol filter with modern styling
        ttk.Label(filter_frame, 
                 text="Protocol:", 
                 style="Header.TLabel").pack(side=tk.LEFT, padx=5)
        
        self.protocol_var = tk.StringVar(value="All")
        protocol_combo = ttk.Combobox(filter_frame, 
                                    textvariable=self.protocol_var, 
                                    values=["All", "TCP", "UDP", "ICMP", "ARP", "802.11"],
                                    state="readonly", 
                                    width=10,
                                    style="Sidebar.TButton")
        protocol_combo.pack(side=tk.LEFT, padx=5)

        # Add clear button with modern styling
        clear_btn = ttk.Button(control_frame, 
                             text="Clear", 
                             command=self.clear_packet_table,
                             style="Sidebar.TButton")
        clear_btn.pack(side=tk.RIGHT, padx=5)

        # Create packet table with modern scrollbars
        table_frame = ttk.Frame(main_frame)
        table_frame.pack(fill=tk.BOTH, expand=True)

        # Configure style for the treeview
        style = ttk.Style()
        style.configure("Packet.Treeview",
                       background=DARK_GREEN,
                       foreground=MATRIX_GREEN,
                       fieldbackground=DARK_GREEN,
                       rowheight=25)
        
        style.map("Packet.Treeview",
                 background=[("selected", ACCENT_GREEN)],
                 foreground=[("selected", MATRIX_BG)])

        # Create treeview with columns
        columns = ("Time", "Protocol", "Source", "Destination", "Size", "Info")
        self.packet_tree = ttk.Treeview(table_frame, 
                                      columns=columns, 
                                      show='headings', 
                                      style="Packet.Treeview",
                                      height=20)

        # Configure columns with modern widths
        column_widths = {
            "Time": 100,
            "Protocol": 80,
            "Source": 150,
            "Destination": 150,
            "Size": 80,
            "Info": 200
        }

        for col in columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=column_widths.get(col, 100))

        # Add modern scrollbars
        y_scrollbar = ttk.Scrollbar(table_frame, 
                                  orient="vertical", 
                                  command=self.packet_tree.yview,
                                  style="Vertical.TScrollbar")
        x_scrollbar = ttk.Scrollbar(table_frame, 
                                  orient="horizontal", 
                                  command=self.packet_tree.xview,
                                  style="Horizontal.TScrollbar")
        
        self.packet_tree.configure(yscrollcommand=y_scrollbar.set,
                                 xscrollcommand=x_scrollbar.set)

        # Grid layout for table and scrollbars
        self.packet_tree.grid(row=0, column=0, sticky="nsew")
        y_scrollbar.grid(row=0, column=1, sticky="ns")
        x_scrollbar.grid(row=1, column=0, sticky="ew")

        # Configure grid weights
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)

        # Add status bar with modern styling
        self.status_bar = ttk.Label(main_frame, 
                                  text="Ready", 
                                  style="Header.TLabel")
        self.status_bar.pack(fill=tk.X, pady=(5, 0))

        # Bind events
        self.packet_tree.bind("<Double-1>", self.show_packet_details)
        protocol_combo.bind("<<ComboboxSelected>>", self.filter_packets)

    def clear_packet_table(self):
        """Clear all entries from the packet table."""
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        self.status_bar.config(text="Packet table cleared")

    def filter_packets(self, event=None):
        """Filter packets based on selected protocol."""
        protocol = self.protocol_var.get()
        for item in self.packet_tree.get_children():
            values = self.packet_tree.item(item)["values"]
            if protocol == "All" or values[1] == protocol:
                self.packet_tree.reattach(item, "", "end")
            else:
                self.packet_tree.detach(item)
        self.status_bar.config(text=f"Filtered packets by protocol: {protocol}")

    def show_packet_details(self, event):
        """Show detailed information about a selected packet."""
        selected_item = self.packet_tree.selection()
        if not selected_item:
            return

        values = self.packet_tree.item(selected_item[0])["values"]
        
        # Create details window
        details_window = tk.Toplevel(self.root)
        details_window.title("Packet Details")
        details_window.geometry("600x400")
        details_window.configure(bg=MATRIX_BG)

        # Create text widget with custom styling
        text_widget = tk.Text(details_window, bg=DARK_GREEN, fg=MATRIX_GREEN,
                            font=("Consolas", 10), wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Format and display packet details
        details = f"""Packet Details:
{'='*50}
Time: {values[0]}
Protocol: {values[1]}
Source: {values[2]}
Destination: {values[3]}
Size: {values[4]} bytes
Info: {values[5] if len(values) > 5 else 'N/A'}
{'='*50}"""

        text_widget.insert(tk.END, details)
        text_widget.config(state=tk.DISABLED)  # Make read-only

    def setup_traffic_chart(self, parent):
        """Create a modern traffic chart with enhanced styling."""
        # Create a frame for the chart with padding
        chart_frame = ttk.Frame(parent)
        chart_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create figure with modern styling
        self.fig = Figure(figsize=(10, 4), dpi=100, facecolor=MATRIX_BG)
        self.ax = self.fig.add_subplot(111, facecolor=MATRIX_BG)
        
        # Configure chart styling
        self.ax.set_xlabel("Time Progression (60 Second Window)", 
                        color=MATRIX_GREEN,
                        fontsize=10,
                        labelpad=10,
                        fontweight='bold')
        
        self.ax.set_ylabel("Network Traffic (KB/s)\n"
                        "Volume of Data Transferred", 
                        color=MATRIX_GREEN,
                        fontsize=10,
                        labelpad=10,
                        fontweight='bold')
        
        # Configure axis styling
        self.ax.tick_params(axis='both', 
                          colors=MATRIX_GREEN,
                          grid_color=DARK_GREEN,
                          grid_linestyle=':',
                          grid_alpha=0.3)
        
        # Style the spines
        for spine in self.ax.spines.values():
            spine.set_color(MATRIX_GREEN)
            spine.set_linewidth(1)
        
        # Add subtle grid
        self.ax.grid(True, 
                    color=DARK_GREEN, 
                    linestyle=':', 
                    linewidth=0.7, 
                    alpha=0.3)
        
        # Create canvas with modern styling
        self.canvas = FigureCanvasTkAgg(self.fig, master=chart_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def update_chart(self):
        """Update the traffic chart with modern styling."""
        self.ax.clear()
        
        # Set the background color
        self.ax.set_facecolor(MATRIX_BG)
        
        # Ensure both traffic history arrays have the same length
        min_length = min(len(self.detector.traffic_history['in']), 
                        len(self.detector.traffic_history['out']))
        
        if min_length > 0:
            # Create time axis labels
            seconds_ago = list(range(min_length, 0, -1))
            
            # Slice the traffic history arrays
            incoming_traffic = self.detector.traffic_history['in'][-min_length:]
            outgoing_traffic = self.detector.traffic_history['out'][-min_length:]
            
            # Plot with modern styling
            self.ax.plot(seconds_ago, incoming_traffic,
                        color=ACCENT_GREEN, 
                        linewidth=2, 
                        label='Incoming Traffic',
                        alpha=0.8)
            
            self.ax.plot(seconds_ago, outgoing_traffic,
                        color=MATRIX_GREEN,
                        linestyle='--',
                        linewidth=2,
                        label='Outgoing Traffic',
                        alpha=0.8)
            
            # Configure axis ranges and labels
            self.ax.set_xlim(left=60, right=0)
            self.ax.set_xticks([60, 45, 30, 15, 0])
            self.ax.set_xticklabels(['60s', '45s', '30s', '15s', '0s'], 
                                  color=MATRIX_GREEN,
                                  fontweight='bold')
            
            # Y-axis configuration
            max_traffic = max(max(incoming_traffic), max(outgoing_traffic))
            y_min = 0
            y_max = max_traffic if max_traffic > 0 else 1
            
            self.ax.set_ylim(bottom=y_min, top=y_max)
            
            # Set y-ticks with modern formatting
            if y_max > 0:
                y_ticks = [y_min, y_max / 4, y_max / 2, y_max * 0.75, y_max]
                y_tick_labels = [
                    '0 KB/s', 
                    f'{y_max / 4:.1f} KB/s', 
                    f'{y_max / 2:.1f} KB/s', 
                    f'{y_max * 0.75:.1f} KB/s', 
                    f'{y_max:.1f} KB/s'
                ]
                
                self.ax.set_yticks(y_ticks)
                self.ax.set_yticklabels(y_tick_labels, 
                                      color=MATRIX_GREEN,
                                      fontweight='bold')
            
            # Reapply styling
            self.ax.set_xlabel("Time Progression (60 Second Window)", 
                            color=MATRIX_GREEN,
                        fontsize=10,
                            labelpad=10,
                            fontweight='bold')
            
            self.ax.set_ylabel("Network Traffic (KB/s)\n"
                            "Volume of Data Transferred", 
                            color=MATRIX_GREEN,
                        fontsize=10,
                            labelpad=10,
                            fontweight='bold')
            
            # Style the spines and grid
            self.ax.tick_params(axis='both', 
                              colors=MATRIX_GREEN,
                              grid_color=DARK_GREEN,
                              grid_linestyle=':',
                              grid_alpha=0.3)
            
            for spine in self.ax.spines.values():
                spine.set_color(MATRIX_GREEN)
                spine.set_linewidth(1)
            
            self.ax.grid(True, 
                        color=DARK_GREEN, 
                        linestyle=':', 
                        linewidth=0.7, 
                        alpha=0.3)
            
            # Add modern legend
            legend = self.ax.legend(
                facecolor=MATRIX_BG,
                edgecolor=MATRIX_GREEN,
                labelcolor=MATRIX_GREEN,
                loc='upper left',
                bbox_to_anchor=(0, 1),
                fontsize=9,
                framealpha=0.8
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
            pkt_time = time.strftime("%H:%M:%S")
            protocol = "Unknown"
            source = "Unknown"
            dest = "Unknown"
            size = len(packet)
            info = ""

            if packet.haslayer(scapy.IP):
                proto = packet[scapy.IP].proto
                protocol = {
                    1: "ICMP",
                    6: "TCP",
                    17: "UDP"
                }.get(proto, "Other")
                
                source = packet[scapy.IP].src
                dest = packet[scapy.IP].dst

                # Add detailed protocol information
                if packet.haslayer(scapy.TCP):
                    info = f"Port {packet[scapy.TCP].sport} → {packet[scapy.TCP].dport}"
                    if packet[scapy.TCP].flags & 0x02:  # SYN flag
                        info += " [SYN]"
                    elif packet[scapy.TCP].flags & 0x01:  # FIN flag
                        info += " [FIN]"
                    elif packet[scapy.TCP].flags & 0x10:  # ACK flag
                        info += " [ACK]"
                elif packet.haslayer(scapy.UDP):
                    info = f"Port {packet[scapy.UDP].sport} → {packet[scapy.UDP].dport}"
                elif packet.haslayer(scapy.ICMP):
                    info = f"Type: {packet[scapy.ICMP].type}, Code: {packet[scapy.ICMP].code}"

            elif packet.haslayer(scapy.Dot11):  # Handle 802.11 wireless frames
                protocol = "802.11"
                source = packet.addr2 if packet.addr2 else "Unknown"
                dest = packet.addr1 if packet.addr1 else "Unknown"
                info = f"Type: {packet.type}, Subtype: {packet.subtype}"
                if packet.haslayer(scapy.Dot11Beacon):
                    info += " [Beacon]"
                elif packet.haslayer(scapy.Dot11ProbeReq):
                    info += " [Probe Request]"
                elif packet.haslayer(scapy.Dot11ProbeResp):
                    info += " [Probe Response]"

            elif packet.haslayer(scapy.ARP):  # Handle ARP packets
                protocol = "ARP"
                source = packet[scapy.ARP].psrc
                dest = packet[scapy.ARP].pdst
                info = f"Operation: {'Request' if packet[scapy.ARP].op == 1 else 'Reply'}"

            # Add packet to queue with all information
            self.packet_queue.put((pkt_time, protocol, source, dest, size, info))

        except Exception as e:
            print(f"Error processing packet: {e}")

    def update_user_section(self):
        """Update the user section with the logged-in user's first name."""
        if hasattr(self, 'user_section_label'):
            self.user_section_label.config(text=f"{self.first_name}'s Section")
        else:
            # Create user section label if it doesn't exist
            self.user_section_label = tk.Label(
                self.top_frame,
                text=f"{self.first_name}'s Section",
                font=("Segoe UI", 14, "bold"),
                bg=MATRIX_BG,
                fg=MATRIX_GREEN
            )
            self.user_section_label.pack(side=tk.LEFT, padx=10)

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
        self.role = role
        self.bind("<Configure>", self.draw_gauge)
        self.bind("<Button-1>", self.show_processes)
        self.bind("<Button-3>", self.show_context_menu)
        self.context_menu = None
        self.process_window = None
        
        # Add hover effect
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        self.hover = False

    def on_enter(self, event):
        """Handle mouse enter event."""
        self.hover = True
        self.draw_gauge()

    def on_leave(self, event):
        """Handle mouse leave event."""
        self.hover = False
        self.draw_gauge()

    def draw_gauge(self, event=None):
        """Draw the gauge with modern styling."""
        self.delete("all")
        w = self.winfo_width()
        h = self.winfo_height()
        size = min(w, h) - 20
        
        # Create gradient effect with hover enhancement
        for i in range(0, 270, 5):
            color = self.fade_color(i/270)
            if self.hover:
                # Enhance colors on hover
                color = self.enhance_color(color)
            self.create_arc(10, 10, 10+size, 10+size,
                          start=45+i, extent=5,
                          outline=color,
                          width=3, style="arc")
        
        # Value indicator with modern styling
        angle = 45 + (270 * (self.value / 100))
        self.create_line(w/2, h/2,
                        w/2 + (size/2)*0.8 * math.cos(math.radians(angle)),
                        h/2 + (size/2)*0.8 * math.sin(math.radians(angle)),
                        fill=ACCENT_GREEN if self.hover else "#ff3300",
                        width=3)
        
        # Center text with modern styling
        self.create_text(w/2, h/2, 
                        text=f"{self.value}%", 
                        fill=self.fg,
                        font=("Segoe UI", 16, "bold"))
        
        # Title with modern styling
        self.create_text(w/2, h-15, 
                        text=self.title,
                        fill=self.fg,
                        font=("Segoe UI", 10))

    def enhance_color(self, color):
        """Enhance color brightness on hover."""
        # Convert hex to RGB
        r = int(color[1:3], 16)
        g = int(color[3:5], 16)
        b = int(color[5:7], 16)
        
        # Increase brightness
        r = min(255, r + 30)
        g = min(255, g + 30)
        b = min(255, b + 30)
        
        # Convert back to hex
        return f"#{r:02x}{g:02x}{b:02x}"

    def fade_color(self, progress):
        """Create a smooth color gradient."""
        r = int(0x00 * (1 - progress) + 0x00 * progress)
        g = int(0xcc * (1 - progress) + 0xff * progress)
        b = int(0x00 * (1 - progress) + 0x00 * progress)
        return f"#{r:02x}{g:02x}{b:02x}"

    def set_value(self, value):
        self.value = min(max(value, 0), 100)
        self.draw_gauge()

    def set_role(self, role):
        """Update the role dynamically."""
        self.role = role
        print(f"[DEBUG] Role updated in CyberGauge: {self.role}")

    def show_context_menu(self, event):
        """Display a context menu with process management options."""
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
        self.context_menu = tk.Menu(self.process_window, tearoff=0, bg=DARK_GREEN, fg=MATRIX_GREEN)
        
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
        
        # Track cursor position and menu state
        self.menu_visible = True
        self.check_cursor_position()

    def check_cursor_position(self):
        """Check if cursor is over the context menu or any submenus and close if not."""
        if not self.context_menu:
            return

        try:
            # Get the main menu's position and size
            menu_x = self.context_menu.winfo_rootx()
            menu_y = self.context_menu.winfo_rooty()
            menu_width = self.context_menu.winfo_width()
            menu_height = self.context_menu.winfo_height()

            # Get current cursor position
            cursor_x = self.process_window.winfo_pointerx()
            cursor_y = self.process_window.winfo_pointery()

            # Check if cursor is within main menu bounds
            if (menu_x <= cursor_x <= menu_x + menu_width and 
                menu_y <= cursor_y <= menu_y + menu_height):
                self.menu_visible = True
            else:
                # Check if any submenus are open and if cursor is over them
                submenu_visible = False
                for menu in self.context_menu.winfo_children():
                    if isinstance(menu, tk.Menu) and menu.winfo_viewable():
                        submenu_x = menu.winfo_rootx()
                        submenu_y = menu.winfo_rooty()
                        submenu_width = menu.winfo_width()
                        submenu_height = menu.winfo_height()
                        
                        if (submenu_x <= cursor_x <= submenu_x + submenu_width and 
                            submenu_y <= cursor_y <= submenu_y + submenu_height):
                            submenu_visible = True
                            break
                
                if not submenu_visible:
                    self.menu_visible = False
                    self.close_context_menu()
                    return
                else:
                    self.menu_visible = True

            # Schedule next check
            if self.menu_visible:
                self.process_window.after(100, self.check_cursor_position)
        except tk.TclError:
            # Menu was destroyed
            self.close_context_menu()

    def close_context_menu(self, event=None):
        """Close the context menu if it is open."""
        if self.context_menu:
            self.context_menu.destroy()
            self.context_menu = None
            self.menu_visible = False

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

    def close_process_window(self):
        """Close the process window and context menu."""
        self.close_context_menu()
        if self.process_window:
            self.process_window.destroy()
            self.process_window = None  # Reset the process_window variable

# ======================
# Launch Application
# ======================

if __name__ == "__main__":
    root = tk.Tk()
    welcome_app = WelcomeApp(root)  
    root.mainloop()