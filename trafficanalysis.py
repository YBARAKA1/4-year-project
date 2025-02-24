import threading
import tkinter as tk
from tkinter import ttk
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from collections import defaultdict
import time
import geoip2.database
from geopy.geocoders import Nominatim
import folium
from folium.plugins import HeatMap
import io
import scapy.all as scapy
from PIL import Image, ImageTk
from constants import MATRIX_BG, MATRIX_GREEN, DARK_GREEN, ACCENT_GREEN

class TrafficAnalysisView(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.style = ttk.Style()
        self.configure_style()
        self.setup_ui()

        # Initialize packet capture data
        self.packet_data = {
            "traffic_volume": defaultdict(int),
            "protocol_breakdown": defaultdict(int),
            "top_talkers": defaultdict(int),
            "geolocation": defaultdict(int),
        }

        # Load GeoIP database
        self.geoip_reader = geoip2.database.Reader("GeoLite2-City.mmdb")

        # Start packet capture thread
        self.start_packet_capture()
        
    def configure_style(self):
        """Configure the Matrix theme for the Traffic Analysis page."""
        self.style.configure("TrafficAnalysis.TFrame", background=MATRIX_BG)
        self.style.configure("TrafficAnalysis.TLabel", background=MATRIX_BG, foreground=MATRIX_GREEN, font=("Consolas", 12))
        self.style.configure("TrafficAnalysis.TButton", background=DARK_GREEN, foreground=MATRIX_GREEN, font=("Consolas", 10))

    def setup_ui(self):
        """Set up the Traffic Analysis page UI."""
        self.pack(fill=tk.BOTH, expand=True)

        # Notebook for multiple tabs
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Traffic Volume Trends Tab
        traffic_trends_frame = ttk.Frame(notebook)
        self.setup_traffic_trends(traffic_trends_frame)
        notebook.add(traffic_trends_frame, text="Traffic Trends")

        # Protocol Breakdown Tab
        protocol_frame = ttk.Frame(notebook)
        self.setup_protocol_breakdown(protocol_frame)
        notebook.add(protocol_frame, text="Protocol Breakdown")

        # Top Talkers Tab
        top_talkers_frame = ttk.Frame(notebook)
        self.setup_top_talkers(top_talkers_frame)
        notebook.add(top_talkers_frame, text="Top Talkers")

        # Geolocation Tab
        geolocation_frame = ttk.Frame(notebook)
        self.setup_geolocation(geolocation_frame)
        notebook.add(geolocation_frame, text="Geolocation")

        # Packet Inspection Tab
        packet_inspection_frame = ttk.Frame(notebook)
        self.setup_packet_inspection(packet_inspection_frame)
        notebook.add(packet_inspection_frame, text="Packet Inspection")
        
    def start_packet_capture(self):
        """Start a thread to capture packets in real-time."""
        def capture_packets():
            scapy.sniff(prn=self.process_packet, store=False)

        capture_thread = threading.Thread(target=capture_packets, daemon=True)
        capture_thread.start()
        
    def process_packet(self, packet):
        """Process each captured packet and update analysis data."""
        try:
            if packet.haslayer(scapy.IP):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                protocol = packet[scapy.IP].proto
                size = len(packet)
                headers = str(packet.summary())

                # Add packet to the packet list
                self.packet_tree.insert("", "end", values=(
                    time.strftime("%H:%M:%S"),
                    src_ip,
                    dst_ip,
                    protocol,
                    size,
                    headers
                ))

                # Update analysis data
                self.update_analysis_data(src_ip, dst_ip, protocol, size)
        except Exception as e:
            print(f"Error processing packet: {e}")
        

    def setup_traffic_trends(self, parent):
        """Set up the Traffic Volume Trends tab."""
        ttk.Label(parent, text="Traffic Volume Trends", style="TrafficAnalysis.TLabel").pack(pady=10)

        # Example data for traffic trends
        self.traffic_data = {
            "Hourly": [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200],
            "Daily": [5000, 6000, 7000, 8000, 9000, 10000, 11000],
            "Weekly": [30000, 35000, 40000, 45000, 50000]
        }

        # Dropdown to select time range
        self.time_range_var = tk.StringVar(value="Hourly")
        time_range_dropdown = ttk.Combobox(parent, textvariable=self.time_range_var, values=["Hourly", "Daily", "Weekly"])
        time_range_dropdown.pack(pady=5)
        time_range_dropdown.bind("<<ComboboxSelected>>", self.update_traffic_trends)

        # Matplotlib figure for traffic trends
        self.traffic_fig = Figure(figsize=(8, 4), dpi=100, facecolor=MATRIX_BG)
        self.traffic_ax = self.traffic_fig.add_subplot(111, facecolor=MATRIX_BG)
        self.traffic_ax.tick_params(axis='both', colors=MATRIX_GREEN)
        self.traffic_ax.set_xlabel("Time", color=MATRIX_GREEN)
        self.traffic_ax.set_ylabel("Traffic Volume (MB)", color=MATRIX_GREEN)

        self.traffic_canvas = FigureCanvasTkAgg(self.traffic_fig, master=parent)
        self.traffic_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Initial plot
        self.update_traffic_trends()
        
    def update_analysis_data(self, src_ip, dst_ip, protocol, size):
        """Update traffic volume, protocol breakdown, and top talkers."""
        hour = time.strftime("%H")
        self.packet_data["traffic_volume"][hour] += size

        if protocol == 6:
            self.packet_data["protocol_breakdown"]["TCP"] += size
        elif protocol == 17:
            self.packet_data["protocol_breakdown"]["UDP"] += size
        elif protocol == 1:
            self.packet_data["protocol_breakdown"]["ICMP"] += size
        else:
            self.packet_data["protocol_breakdown"]["Other"] += size

        self.packet_data["top_talkers"][(src_ip, dst_ip)] += size

        # Update geolocation
        self.update_geolocation(src_ip)
        self.update_geolocation(dst_ip)

        # Update UI
        self.update_ui()


    def update_traffic_trends(self, event=None):
        """Update the traffic trends chart based on the selected time range."""
        time_range = self.time_range_var.get()
        data = self.traffic_data[time_range]

        self.traffic_ax.clear()
        self.traffic_ax.plot(data, color=MATRIX_GREEN, marker='o')
        self.traffic_ax.set_title(f"{time_range} Traffic Trends", color=MATRIX_GREEN)
        self.traffic_ax.grid(True, color=DARK_GREEN, linestyle=':', linewidth=0.7, alpha=0.5)
        self.traffic_canvas.draw()

    def setup_protocol_breakdown(self, parent):
        """Set up the Protocol Breakdown tab."""
        ttk.Label(parent, text="Protocol Breakdown", style="TrafficAnalysis.TLabel").pack(pady=10)

        # Example data for protocol breakdown
        self.protocol_data = {
            "TCP": 60,
            "UDP": 30,
            "ICMP": 5,
            "Other": 5
        }

        # Matplotlib figure for protocol breakdown
        self.protocol_fig = Figure(figsize=(6, 6), dpi=100, facecolor=MATRIX_BG)
        self.protocol_ax = self.protocol_fig.add_subplot(111, facecolor=MATRIX_BG)
        self.protocol_ax.tick_params(axis='both', colors=MATRIX_GREEN)

        self.protocol_canvas = FigureCanvasTkAgg(self.protocol_fig, master=parent)
        self.protocol_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Initial plot
        self.update_protocol_breakdown()

    def update_protocol_breakdown(self):
        """Update the protocol breakdown pie chart."""
        labels = self.protocol_data.keys()
        sizes = self.protocol_data.values()
        colors = [MATRIX_GREEN, ACCENT_GREEN, DARK_GREEN, "#00FF77"]

        self.protocol_ax.clear()
        self.protocol_ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        self.protocol_ax.set_title("Protocol Usage", color=MATRIX_GREEN)
        self.protocol_canvas.draw()

    def setup_top_talkers(self, parent):
        """Set up the Top Talkers tab."""
        ttk.Label(parent, text="Top Talkers", style="TrafficAnalysis.TLabel").pack(pady=10)

        # Example data for top talkers
        self.top_talkers_data = [
            ("192.168.1.1", "192.168.1.2", 1000),
            ("192.168.1.3", "192.168.1.4", 800),
            ("192.168.1.5", "192.168.1.6", 600)
        ]

        # Treeview for top talkers
        columns = ("Source IP", "Destination IP", "Traffic (MB)")
        self.top_talkers_tree = ttk.Treeview(parent, columns=columns, show='headings')
        for col in columns:
            self.top_talkers_tree.heading(col, text=col)
            self.top_talkers_tree.column(col, width=150)
        self.top_talkers_tree.pack(fill=tk.BOTH, expand=True)

        # Populate treeview
        for row in self.top_talkers_data:
            self.top_talkers_tree.insert("", "end", values=row)

    def setup_geolocation(self, parent):
        """Set up the Geolocation tab."""
        ttk.Label(parent, text="Geolocation of Traffic", style="TrafficAnalysis.TLabel").pack(pady=10)

        # Example data for geolocation
        self.geolocation_data = [
            ("192.168.1.1", "New York, USA"),
            ("192.168.1.2", "London, UK"),
            ("192.168.1.3", "Tokyo, Japan")
        ]

        # Treeview for geolocation
        columns = ("IP Address", "Location")
        self.geolocation_tree = ttk.Treeview(parent, columns=columns, show='headings')
        for col in columns:
            self.geolocation_tree.heading(col, text=col)
            self.geolocation_tree.column(col, width=150)
        self.geolocation_tree.pack(fill=tk.BOTH, expand=True)

        # Populate treeview
        for row in self.geolocation_data:
            self.geolocation_tree.insert("", "end", values=row)
            
    def update_geolocation(self, ip):
        """Map an IP address to a location using GeoIP."""
        try:
            response = self.geoip_reader.city(ip)
            location = f"{response.city.name}, {response.country.name}"
            self.packet_data["geolocation"][ip] = location
        except Exception as e:
            print(f"GeoIP lookup failed for {ip}: {e}")

    def setup_packet_inspection(self, parent):
        """Set up the Packet Inspection tab."""
        ttk.Label(parent, text="Packet Inspection", style="TrafficAnalysis.TLabel").pack(pady=10)

        # Treeview for packet inspection
        columns = ("Time", "Source IP", "Destination IP", "Protocol", "Size", "Headers")
        self.packet_tree = ttk.Treeview(parent, columns=columns, show='headings')
        for col in columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=100)
        self.packet_tree.pack(fill=tk.BOTH, expand=True)

        # Scrollbar for the Treeview
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Text widget for detailed packet inspection
        self.packet_text = tk.Text(parent, wrap=tk.WORD, bg=MATRIX_BG, fg=MATRIX_GREEN, font=("Consolas", 10))
        self.packet_text.pack(fill=tk.BOTH, expand=True)

        # Bind Treeview selection event to show packet details
        self.packet_tree.bind("<<TreeviewSelect>>", self.show_packet_details)
        
    def show_packet_details(self, event):
        """Display detailed packet information when a packet is selected."""
        selected_item = self.packet_tree.selection()
        if selected_item:
            packet_details = self.packet_tree.item(selected_item, "values")
            self.packet_text.delete(1.0, tk.END)
            self.packet_text.insert(tk.END, f"Time: {packet_details[0]}\n")
            self.packet_text.insert(tk.END, f"Source IP: {packet_details[1]}\n")
            self.packet_text.insert(tk.END, f"Destination IP: {packet_details[2]}\n")
            self.packet_text.insert(tk.END, f"Protocol: {packet_details[3]}\n")
            self.packet_text.insert(tk.END, f"Size: {packet_details[4]} bytes\n")
            self.packet_text.insert(tk.END, f"Headers: {packet_details[5]}\n")
            
    def update_ui(self):
        """Update the UI with the latest packet data."""
        self.update_traffic_trends()
        self.update_protocol_breakdown()
        self.update_top_talkers()
        self.update_geolocation_map()