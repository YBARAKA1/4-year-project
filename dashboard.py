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
from constants import (
    ACCENT_GREEN,
    BORDER,
    BUTTON_BG,
    BUTTON_FG,
    CHART_IN,
    CHART_OUT,
    DARK_GREEN,
    mono_font,
    ui_font,
    MATRIX_BG,
    MATRIX_GREEN,
    MUTED,
    SURFACE,
    AMBER,
)
from theme import apply_theme
from trafficanalysis import TrafficAnalysisView
from threatalert import ThreatAlertsView
from login_window import LoginWindow  
# ======================
# Welcome Screen
# ======================

class WelcomeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network IDS")
        self.root.configure(bg=MATRIX_BG)
        self.root.geometry("760x480")
        self.root.resizable(False, False)
        self.center_window()

        self.capture_ok = hasattr(os, "geteuid") and os.geteuid() == 0
        host = platform.node() or "localhost"
        self.lines = [
            "nids sensor console",
            f"host {host}",
            "link layer capture " + ("available" if self.capture_ok else "unavailable without root"),
            "detector SYN flood / UDP flood / ARP spoof",
            "opening operations view",
        ]
        self.line_index = 0
        self.char_index = 0

        frame = tk.Frame(self.root, bg=DARK_GREEN, highlightbackground=BORDER, highlightthickness=1)
        frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER, width=560, height=320)
        tk.Frame(frame, bg=ACCENT_GREEN, height=3).pack(fill=tk.X)

        tk.Label(
            frame,
            text="NIDS",
            font=mono_font(22, bold=True),
            fg=ACCENT_GREEN,
            bg=DARK_GREEN,
        ).pack(anchor="w", padx=28, pady=(22, 0))
        tk.Label(
            frame,
            text="network intrusion detection",
            font=mono_font(10),
            fg=MUTED,
            bg=DARK_GREEN,
        ).pack(anchor="w", padx=28, pady=(0, 12))

        self.log = tk.Text(
            frame,
            bg=DARK_GREEN,
            fg=ACCENT_GREEN,
            font=mono_font(11),
            height=8,
            relief="flat",
            highlightthickness=0,
            wrap="none",
        )
        self.log.pack(fill=tk.BOTH, expand=True, padx=28, pady=(0, 18))
        self.log.configure(state="disabled")
        self.root.after(180, self.type_next)

    def center_window(self):
        self.root.update_idletasks()
        width, height = 760, 480
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def type_next(self):
        if self.line_index >= len(self.lines):
            self.root.after(500, self.transition_to_dashboard)
            return
        line = self.lines[self.line_index]
        self.log.configure(state="normal")
        if self.char_index == 0:
            self.log.insert(tk.END, "> ")
        self.log.insert(tk.END, line[self.char_index])
        self.log.configure(state="disabled")
        self.log.see(tk.END)
        self.char_index += 1
        if self.char_index >= len(line):
            self.log.configure(state="normal")
            self.log.insert(tk.END, "\n")
            self.log.configure(state="disabled")
            self.line_index += 1
            self.char_index = 0
            self.root.after(160, self.type_next)
        else:
            self.root.after(18, self.type_next)

    def transition_to_dashboard(self):
        self.root.destroy()
        root = tk.Tk()
        IDSDashboard(root)
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
        
        self.detector = IntrusionDetector()
        self.alert_queue = queue.Queue()
        self.packet_queue = queue.Queue()
        self.attack_stats = {"SYN Flood": 0, "UDP Flood": 0, "ARP Spoofing": 0}
        
        self.current_view = None
        self.views = {}  # Holds the different view frames
        self.logged_in = True
        self.role = role or "admin"
        self.first_name = first_name or "Operator"
        self.sidebar_visible = True
        self.capture_ok = False
        self.sensor_pulse = False
        
        # Initialize packet_tree and alert_tree
        self.packet_tree = None
        self.alert_tree = None
        
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
        self.root.title("NIDS — host sensor")
        apply_theme(self.root)
        self.style = ttk.Style()

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

        self.status_dot = tk.Canvas(self.top_frame, width=12, height=12, bg=MATRIX_BG, highlightthickness=0)
        self.status_dot.pack(side=tk.RIGHT, padx=(0, 8))
        self.status_label = ttk.Label(
            self.top_frame,
            text="sensor idle",
            style="Muted.TLabel"
        )
        self.status_label.pack(side=tk.RIGHT, padx=10)
        self.pulse_sensor()

        # Show default view
        self.show_view("Dashboard")
        
        # Initialize CyberGauge instances if they don't exist
        if not hasattr(self, 'cpu_gauge'):
            self.cpu_gauge = CyberGauge(self.container, "CPU LOAD", MATRIX_BG, MATRIX_GREEN, role=self.role)
        if not hasattr(self, 'mem_gauge'):
            self.mem_gauge = CyberGauge(self.container, "MEMORY USAGE", MATRIX_BG, MATRIX_GREEN, role=self.role)

    def pulse_sensor(self):
        """Pulse the sensor indicator. Color reflects real capture state."""
        self.sensor_pulse = not self.sensor_pulse
        color = ACCENT_GREEN if self.capture_ok and self.sensor_pulse else (AMBER if not self.capture_ok else SURFACE)
        if self.capture_ok:
            color = ACCENT_GREEN if self.sensor_pulse else SURFACE
        else:
            color = AMBER if self.sensor_pulse else SURFACE
        self.status_dot.delete("all")
        self.status_dot.create_oval(2, 2, 10, 10, fill=color, outline="")
        self.root.after(700, self.pulse_sensor)

    def on_closing(self):
        """Close the application."""
        self.root.destroy()
        
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
        self.login_button.config(text="Sign out", command=self.logout)
        
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
        self.login_button.config(text="Sign in", command=self.open_login)
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
            button.config(state=tk.NORMAL)

    def show_view(self, view_name):
        """Show the specified view."""
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
            elif view_name == "Terminal":
                from terminal import TerminalView
                self.views[view_name] = TerminalView(self.container)
            elif view_name == "PortScanner":
                from port_scanner import PortScannerView
                self.views[view_name] = PortScannerView(self.container)

        # Display the view
        self.current_view = self.views[view_name]
        self.current_view.pack(fill=tk.BOTH, expand=True)
        self._set_active_nav(view_name)
        
    def show_terminal(self):
        """Show the Terminal view."""
        self.show_view("Terminal")
        
    def setup_threads(self):
        def note_capture(_packet):
            if not self.capture_ok:
                self.capture_ok = True
                self.root.after(0, lambda: self.status_label.config(text="sensor live"))
            self.process_packet(_packet)

        def sniff_packets():
            try:
                scapy.sniff(
                    prn=note_capture,
                    store=0,
                    filter="ip or arp or tcp or udp"
                )
            except PermissionError:
                print("Packet capture unavailable without root. Live traffic will stay at zero.")
                self.root.after(0, lambda: self.status_label.config(text="sensor idle — capture needs root"))
            except Exception as e:
                print(f"Packet capture stopped: {e}")

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
        self.net_stats = ttk.Label(left_panel, text="Inbound  0.00 KB/s\nOutbound 0.00 KB/s", font=mono_font(11))
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
                               text="NIDS",
                               style="SidebarHeader.TLabel")
        header_label.pack(pady=(8, 0))
        ttk.Label(header_frame, text="host sensor", style="SidebarMuted.TLabel").pack(pady=(0, 8))
        
        # Navigation buttons with modern styling
        buttons = [
            ("Dashboard", self.show_dashboard),
            ("Packet Stream", self.show_packet_stream),
            ("Traffic Analysis", self.show_traffic_analysis),
            ("Threat Alerts", self.show_threat_alerts),
            ("Port Scanner", self.show_port_scanner),
            ("Terminal", self.show_terminal),
        ]

        # Store sidebar buttons for enabling/disabling
        self.sidebar_buttons = []
        self.nav_by_view = {}
        view_keys = {
            "Dashboard": "Dashboard",
            "Packet Stream": "PacketStream",
            "Traffic Analysis": "TrafficAnalysis",
            "Threat Alerts": "ThreatAlerts",
            "Port Scanner": "PortScanner",
            "Terminal": "Terminal",
        }
        for text, command in buttons:
            button = ttk.Button(parent, 
                              text=text, 
                              style="Sidebar.TButton",
                                command=command)
            button.pack(pady=2, fill=tk.X, padx=12)
            self.sidebar_buttons.append(button)
            self.nav_by_view[view_keys[text]] = button

        self.enable_sidebar_buttons()

        # Initially show the sidebar
        self.sidebar_visible = True

    def _set_active_nav(self, view_name):
        """Highlight the navigation item for the current view."""
        for name, button in getattr(self, "nav_by_view", {}).items():
            button.configure(style="SidebarActive.TButton" if name == view_name else "Sidebar.TButton")

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
            button.config(state=tk.NORMAL)

    def show_dashboard(self):
        self.show_view("Dashboard")

    def show_traffic_analysis(self):
        self.show_view("TrafficAnalysis")

    def show_threat_alerts(self):
        self.show_view("ThreatAlerts")

    def show_packet_stream(self):
        self.show_view("PacketStream")
        
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
                                    font=ui_font(10))
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
                            font=ui_font(10), wrap=tk.WORD)
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
            spine.set_color(BORDER)
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
                        color=CHART_IN, 
                        linewidth=2, 
                        label='Incoming Traffic',
                        alpha=0.8)
            
            self.ax.plot(seconds_ago, outgoing_traffic,
                        color=CHART_OUT,
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
                spine.set_color(BORDER)
                spine.set_linewidth(1)
            
            self.ax.grid(True, 
                        color=DARK_GREEN, 
                        linestyle=':', 
                        linewidth=0.7, 
                        alpha=0.3)
            
            # Add modern legend
            legend = self.ax.legend(
                facecolor=MATRIX_BG,
                edgecolor=BORDER,
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
        if not self.capture_ok and net_in == 0 and net_out == 0:
            self.net_stats.config(text="Inbound  —\nOutbound —\nno capture socket")
        else:
            self.net_stats.config(text=f"Inbound  {net_in:.2f} KB/s\nOutbound {net_out:.2f} KB/s")
        
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
                font=ui_font(14, bold=True),
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
        self.sweep = 0
        self.bind("<Configure>", self.draw_gauge)
        self.after(80, self.animate_sweep)
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
        """Draw a host-resource instrument. The arc length matches the measured value."""
        self.delete("all")
        w = max(self.winfo_width(), 40)
        h = max(self.winfo_height(), 40)
        size = min(w, h) - 24
        x0 = (w - size) / 2
        y0 = 12
        value = min(max(self.value, 0), 100)
        fill = ACCENT_GREEN if value < 80 else AMBER

        self.create_arc(
            x0, y0, x0 + size, y0 + size,
            start=225, extent=-270,
            outline=SURFACE, width=10, style="arc",
        )
        if value > 0:
            self.create_arc(
                x0, y0, x0 + size, y0 + size,
                start=225, extent=-270 * (value / 100),
                outline=fill, width=10, style="arc",
            )

        cx = w / 2
        cy = y0 + size / 2
        sweep_angle = math.radians(225 - self.sweep)
        radius = size / 2 - 8
        self.create_line(
            cx, cy,
            cx + radius * math.cos(sweep_angle),
            cy - radius * math.sin(sweep_angle),
            fill=BORDER, width=1,
        )
        cy = y0 + size / 2
        self.create_text(cx, cy - 6, text=f"{value:.0f}%", fill=self.fg, font=mono_font(16, bold=True))
        self.create_text(cx, h - 16, text=self.title.strip(), fill=MUTED, font=mono_font(9))

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
        r = int(0x1E * (1 - progress) + 0x3B * progress)
        g = int(0x3A * (1 - progress) + 0x82 * progress)
        b = int(0x5F * (1 - progress) + 0xF6 * progress)
        return f"#{r:02x}{g:02x}{b:02x}"

    def animate_sweep(self):
        """Keep a faint scan tick moving so the instrument feels live."""
        self.sweep = (self.sweep + 6) % 270
        self.draw_gauge()
        self.after(80, self.animate_sweep)

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