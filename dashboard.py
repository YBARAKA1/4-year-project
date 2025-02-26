import tkinter as tk
from tkinter import ttk, messagebox
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
from trafficanalysis import TrafficAnalysisView  
from constants import MATRIX_BG, MATRIX_GREEN, DARK_GREEN, ACCENT_GREEN
from trafficanalysis import TrafficAnalysisView
from threatalert import ThreatAlertsView
import tkinter as tk
import random
import subprocess


#===================
#welcome
#====================





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
            
            # Update traffic history
            self.traffic_history['in'].append(self.bandwidth[0]/(1024*1024))
            self.traffic_history['out'].append(self.bandwidth[1]/(1024*1024))
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
    def __init__(self, root):
        self.root = root
        self.detector = IntrusionDetector()
        self.alert_queue = queue.Queue()
        self.packet_queue = queue.Queue()
        self.attack_stats = {"SYN Flood": 0, "UDP Flood": 0, "ARP Spoofing": 0}
        
        self.current_view = None
        self.views = {}  # Holds the different view frames
        
        # Initialize packet_tree and alert_tree
        self.packet_tree = None
        self.alert_tree = None
        
        self.setup_gui()
        self.setup_threads()
        
    # Add to IDSDashboard class
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

        # Display the view
        self.current_view = self.views[view_name]
        self.current_view.pack(fill=tk.BOTH, expand=True)
        
    def create_dashboard_view(self):
        """Dashboard view with system stats and traffic overview."""
        frame = ttk.Frame(self.container)
        
        # Left Panel - System Stats
        left_panel = ttk.Frame(frame, width=300)
        ttk.Label(left_panel, text="SYSTEM MONITOR", style="Header.TLabel").pack(pady=15)
        self.cpu_gauge = CyberGauge(left_panel, "\nCPU LOAD", width=300, height=330, bg=MATRIX_BG, fg=MATRIX_GREEN)
        self.cpu_gauge.pack(pady=10)
        self.mem_gauge = CyberGauge(left_panel, "\nMEMORY USAGE", width=300, height=330, bg=MATRIX_BG, fg=MATRIX_GREEN)
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
        ]

        for text, command in buttons:
            button = ttk.Button(parent, text=text, style="Sidebar.TButton",
                                command=command)
            button.pack(pady=5, fill=tk.X)

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
        self.ax.set_xlabel("Time Progression (60 Second Window)\n"
                        "Left (60s ago) → Right (Current Moment)", 
                        color=MATRIX_GREEN,  # Set label color to green
                        fontsize=10,
                        labelpad=10)
        
        # Y-axis: Represents network traffic in megabytes per second (MB/s).
        self.ax.set_ylabel("Network Traffic (Megabytes per Second)\n"
                        "Volume of Data Transferred (Incoming/Outgoing)", 
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
                self.ax.set_yticks([y_min, y_max / 2, y_max])
                self.ax.set_yticklabels([
                    '0 MB/s', 
                    f'{y_max / 2:.1f} MB/s\n(Moderate Traffic)', 
                    f'{y_max:.1f} MB/s\n(Peak Traffic)'
                ], color=MATRIX_GREEN)  # Set tick label color to green
            else:
                self.ax.set_yticks([y_min, y_max])
                self.ax.set_yticklabels([
                    '0 MB/s', 
                    '0 MB/s'
                ], color=MATRIX_GREEN)  # Set tick label color to green
            
            # Reapply styling after clear
            self.ax.set_xlabel("Time Progression (60 Second Window)", 
                            color=MATRIX_GREEN)
            self.ax.set_ylabel("Network Traffic (Megabytes per Second)",
                            color=MATRIX_GREEN)
            self.ax.tick_params(axis='both', colors=MATRIX_GREEN)
            for spine in self.ax.spines.values():
                spine.set_color(MATRIX_GREEN)
            self.ax.grid(True, color=DARK_GREEN, linestyle=':', linewidth=0.7, alpha=0.5)
            
            # Add legend with improved visibility
            legend = self.ax.legend(
                facecolor=MATRIX_BG,  # Set legend background to black
                edgecolor=MATRIX_GREEN,  # Set legend border color to green
                labelcolor=MATRIX_GREEN,  # Set legend text color to green
                loc='upper left',
                bbox_to_anchor=(0, 1)
            )
            
            self.canvas.draw()



    def update_gui(self):
        # Update system metrics
        self.cpu_gauge.set_value(psutil.cpu_percent())
        self.mem_gauge.set_value(psutil.virtual_memory().percent)
        
        # Update network stats
        net_in = self.detector.traffic_history['in'][-1] if self.detector.traffic_history['in'] else 0
        net_out = self.detector.traffic_history['out'][-1] if self.detector.traffic_history['out'] else 0
        self.net_stats.config(text=f"IN: {net_in:.2f} MB/s\nOUT: {net_out:.2f} MB/s")
        
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
    def __init__(self, parent, title, bg, fg, **kwargs):
        super().__init__(parent, bg=bg, **kwargs)
        self.title = title
        self.value = 0
        self.bg = bg
        self.fg = fg
        self.bind("<Configure>", self.draw_gauge)

# Fix the CyberGauge drawing method
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

# ======================
# Launch Application
# ======================

if __name__ == "__main__":
    root = tk.Tk()
    app = IDSDashboard(root)
    root.mainloop()