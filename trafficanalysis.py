import datetime
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
        print("Initializing TrafficAnalysisView...")
        self.parent = parent
        self.style = ttk.Style()
        self.configure_style()

        # Initialize packet capture data
        self.packet_data = {
            "traffic_volume": {
                "second": defaultdict(int),
                "minute": defaultdict(int),
                "hour": defaultdict(int),
                "day": defaultdict(int),
                "week": defaultdict(int),
                "month": defaultdict(int),
            },
            "protocol_breakdown": defaultdict(int),
            "top_talkers": defaultdict(int),
            "geolocation": defaultdict(int),
        }
        print("Packet data initialized.")

        # Load GeoIP database
        self.geoip_reader = geoip2.database.Reader("GeoLite2-City.mmdb")
        print("GeoIP database loaded.")

        # Set up the UI
        self.setup_ui()
        print("UI setup complete.")

        # Start packet capture thread
        self.start_packet_capture()
        print("Packet capture started.")

        # Update traffic trends after initialization
        self.update_traffic_trends()
        print("Traffic trends updated.")
        
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

        # Dropdown to select time range
        self.time_range_var = tk.StringVar(value="Second")
        time_range_dropdown = ttk.Combobox(
            parent,
            textvariable=self.time_range_var,
            values=["Second", "Minute", "Hour", "Day", "Week", "Month"]
        )
        time_range_dropdown.pack(pady=5)
        time_range_dropdown.bind("<<ComboboxSelected>>", self.update_traffic_trends)

        # Matplotlib figure for traffic trends
        self.traffic_fig = Figure(figsize=(8, 4), dpi=100, facecolor=MATRIX_BG)
        self.traffic_ax = self.traffic_fig.add_subplot(111, facecolor=MATRIX_BG)
        self.traffic_ax.tick_params(axis='both', colors=MATRIX_GREEN)

        self.traffic_canvas = FigureCanvasTkAgg(self.traffic_fig, master=parent)
        self.traffic_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Initial plot
        self.update_traffic_trends()
        
    def format_timestamps(self, timestamps, time_range):
        """Format timestamps based on the selected time range."""
        formatted_timestamps = []
        for ts in timestamps:
            if time_range == " Seconds":
                # Format: %Y-%m-%d %H:%M:%S -> %H:%M:%S
                formatted_ts = time.strftime("%H:%M:%S", time.strptime(ts, "%Y-%m-%d %H:%M:%S"))
            elif time_range == "Minute":
                # Format: %Y-%m-%d %H:%M -> %H:%M
                formatted_ts = time.strftime("%H:%M", time.strptime(ts, "%Y-%m-%d %H:%M"))
            elif time_range == "Hour":
                # Format: %Y-%m-%d %H -> %H:00
                formatted_ts = time.strftime("%H:00", time.strptime(ts, "%Y-%m-%d %H"))
            elif time_range == "Day":
                # Format: %Y-%m-%d -> %Y-%m-%d
                formatted_ts = ts  # Already in the correct format
            elif time_range == "Week":
                # Format: %Y-%U -> Week %U, %Y
                year, week = ts.split("-")
                formatted_ts = f"Week {week}, {year}"
            elif time_range == "Month":
                # Format: %Y-%m -> %Y-%m
                formatted_ts = ts  # Already in the correct format
            else:
                formatted_ts = ts  # Fallback to raw timestamp
            formatted_timestamps.append(formatted_ts)
        return formatted_timestamps
        
    def update_analysis_data(self, src_ip, dst_ip, protocol, size):
        """Update traffic volume, protocol breakdown, and top talkers."""
        current_time = time.time()
        time_struct = time.localtime(current_time)

        
        # Update traffic volume by 30 seconds
        timestamp = int(time.mktime(time_struct))  # Convert time to seconds since epoch
        rounded_timestamp = timestamp - (timestamp % 30)  # Round to nearest 30-second interval
        second_key = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(rounded_timestamp))

        self.packet_data["traffic_volume"]["second"][second_key] += size


        # Update traffic volume by minute
        minute_key = time.strftime("%Y-%m-%d %H:%M", time_struct)
        self.packet_data["traffic_volume"]["minute"][minute_key] += size

        # Update traffic volume by hour
        hour_key = time.strftime("%Y-%m-%d %H", time_struct)
        self.packet_data["traffic_volume"]["hour"][hour_key] += size

        # Update traffic volume by day
        day_key = time.strftime("%Y-%m-%d", time_struct)
        self.packet_data["traffic_volume"]["day"][day_key] += size

        # Update traffic volume by week
        week_key = time.strftime("%Y-%U", time_struct)  # %U is the week number of the year
        self.packet_data["traffic_volume"]["week"][week_key] += size

        # Update traffic volume by month
        month_key = time.strftime("%Y-%m", time_struct)
        self.packet_data["traffic_volume"]["month"][month_key] += size

        # Update protocol breakdown
        if protocol == 6:
            self.packet_data["protocol_breakdown"]["TCP"] += size
        elif protocol == 17:
            self.packet_data["protocol_breakdown"]["UDP"] += size
        elif protocol == 1:
            self.packet_data["protocol_breakdown"]["ICMP"] += size
        else:
            self.packet_data["protocol_breakdown"]["Other"] += size

        # Update top talkers
        self.packet_data["top_talkers"][(src_ip, dst_ip)] += size

        # Update geolocation
        self.update_geolocation(src_ip)
        self.update_geolocation(dst_ip)

        # Update UI
        self.update_ui()

    def update_traffic_trends(self, event=None):
        """Update the traffic trends chart based on the selected time range."""
        time_range = self.time_range_var.get()
        data = self.packet_data["traffic_volume"][time_range.lower()]

        # Prepare data for plotting
        timestamps = sorted(data.keys())
        formatted_timestamps = self.format_timestamps(timestamps, time_range)
        traffic_volumes = [data[timestamp] for timestamp in timestamps]

        # Clear the previous plot
        self.traffic_ax.clear()

        # Plot the data (if available)
        if timestamps:
            self.traffic_ax.plot(formatted_timestamps, traffic_volumes, color=MATRIX_GREEN, marker='o')
        else:
            self.traffic_ax.text(0.5, 0.5, "No data available", color=MATRIX_GREEN, ha="center")

        self.traffic_ax.set_title(f"{time_range} Traffic Trends", color=MATRIX_GREEN)
        self.traffic_ax.set_xlabel("Time", color=MATRIX_GREEN)
        self.traffic_ax.set_ylabel("Traffic Volume (Bytes)", color=MATRIX_GREEN)
        self.traffic_ax.grid(True, color=DARK_GREEN, linestyle=':', linewidth=0.7, alpha=0.5)

        # Rotate x-axis labels for better readability
        plt.setp(self.traffic_ax.get_xticklabels(), rotation=45, ha="right")

        # Redraw the canvas
        self.traffic_canvas.draw()

    def setup_protocol_breakdown(self, parent):
        """Set up the Protocol Breakdown tab."""
        ttk.Label(parent, text="Protocol Breakdown", style="TrafficAnalysis.TLabel").pack(pady=10)

        # Help text to explain the protocols
        help_text = (
            "Protocol Breakdown:\n"
            "- TCP: Transmission Control Protocol (Reliable, connection-oriented)\n"
            "- UDP: User Datagram Protocol (Fast, connectionless)\n"
            "- ICMP: Internet Control Message Protocol (Used for diagnostics)\n"
            "- Other: All other protocols"
        )
        help_label = ttk.Label(parent, text=help_text, style="TrafficAnalysis.TLabel", justify=tk.LEFT)
        help_label.pack(pady=10)

        # Matplotlib figure for protocol breakdown
        self.protocol_fig = Figure(figsize=(6, 6), dpi=100, facecolor=MATRIX_BG)
        self.protocol_ax = self.protocol_fig.add_subplot(111, facecolor=MATRIX_BG)
        self.protocol_ax.tick_params(axis='both', colors=MATRIX_GREEN)

        self.protocol_canvas = FigureCanvasTkAgg(self.protocol_fig, master=parent)
        self.protocol_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Add hover tooltips
        self.protocol_canvas.mpl_connect("motion_notify_event", self.on_hover_protocol_chart)

        # Initial plot
        self.update_protocol_breakdown()

    def update_protocol_breakdown(self):
        """Update the protocol breakdown pie chart."""
        # Use the protocol breakdown data from packet_data
        labels = list(self.packet_data["protocol_breakdown"].keys())
        sizes = list(self.packet_data["protocol_breakdown"].values())
        colors = [MATRIX_GREEN, ACCENT_GREEN, DARK_GREEN, "#00FF77"]

        # Clear the previous plot
        self.protocol_ax.clear()

        # Plot the data (if available)
        if sizes:
            wedges, texts, autotexts = self.protocol_ax.pie(
                sizes,
                labels=labels,
                colors=colors,
                autopct='%1.1f%%',
                startangle=90,
                textprops={'color': MATRIX_GREEN}
            )

            # Add tooltips to wedges
            for wedge in wedges:
                wedge.set_edgecolor(MATRIX_BG)  # Set edge color to match background
        else:
            self.protocol_ax.text(0.5, 0.5, "No data available", color=MATRIX_GREEN, ha="center")

        self.protocol_ax.set_title("Protocol Usage", color=MATRIX_GREEN)
        self.protocol_canvas.draw()
        
    def on_hover_protocol_chart(self, event):
        """Display tooltips when hovering over the pie chart."""
        if event.inaxes == self.protocol_ax:
            for wedge in self.protocol_ax.patches:
                if wedge.contains_point((event.x, event.y)):
                    # Get the label and percentage for the hovered wedge
                    label = wedge.get_label()
                    percentage = wedge.get_height() / sum(self.packet_data["protocol_breakdown"].values()) * 100
                    tooltip_text = f"{label}: {percentage:.1f}%"
                    
                    # Display the tooltip
                    self.protocol_ax.set_title(tooltip_text, color=MATRIX_GREEN)
                    self.protocol_canvas.draw()
                    break
            else:
                # Reset the title if not hovering over any wedge
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
            
    def update_top_talkers(self):
        """Update the Top Talkers tab with the latest data."""
        # Clear the existing data in the treeview
        for row in self.top_talkers_tree.get_children():
            self.top_talkers_tree.delete(row)

        # Sort the top talkers by traffic volume (descending order)
        sorted_top_talkers = sorted(
            self.packet_data["top_talkers"].items(),
            key=lambda x: x[1],
            reverse=True
        )

        # Add the top talkers to the treeview
        for (src_ip, dst_ip), traffic_volume in sorted_top_talkers:
            self.top_talkers_tree.insert("", "end", values=(src_ip, dst_ip, traffic_volume))

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
    
    def update_geolocation_map(self):
        """Update the Geolocation tab with the latest data."""
        # Clear the existing data in the treeview
        for row in self.geolocation_tree.get_children():
            self.geolocation_tree.delete(row)

        # Add the geolocation data to the treeview
        for ip, location in self.packet_data["geolocation"].items():
            self.geolocation_tree.insert("", "end", values=(ip, location))

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
            self.packet_text.delete(1.0, tk.END)  # Clear previous content

            # Extract packet details
            time_stamp = packet_details[0]
            src_ip = packet_details[1]
            dst_ip = packet_details[2]
            protocol = packet_details[3]
            size = packet_details[4]
            headers = packet_details[5]

            # Display basic packet information
            self.packet_text.insert(tk.END, f"Time: {time_stamp}\n")
            self.packet_text.insert(tk.END, f"Source IP: {src_ip}\n")
            self.packet_text.insert(tk.END, f"Destination IP: {dst_ip}\n")
            self.packet_text.insert(tk.END, f"Protocol: {protocol}\n")
            self.packet_text.insert(tk.END, f"Size: {size} bytes\n\n")

            # Add detailed protocol stack and interpretation
            self.packet_text.insert(tk.END, "1. Protocol Stack\n")
            self.packet_text.insert(tk.END, "   Ethernet → Ethernet (Layer 2 - Data Link Layer)\n")
            self.packet_text.insert(tk.END, "   IP → Internet Protocol (Layer 3 - Network Layer)\n")

            # Map protocol numbers to their names
            protocol_map = {
                1: "ICMP",
                2: "IGMP",
                6: "TCP",
                17: "UDP",
                41: "IPv6",
                50: "ESP",
                51: "AH",
                89: "OSPF",
                132: "SCTP",
                255: "Reserved"
            }

            # Get protocol name
            protocol_name = protocol_map.get(int(protocol), f"Unknown Protocol ({protocol})")

            # Add protocol-specific details
            self.packet_text.insert(tk.END, f"   {protocol_name} → {self.get_protocol_description(protocol_name)}\n\n")

            # Add source and destination IP details
            self.packet_text.insert(tk.END, "2. Source and Destination IPs\n")
            self.packet_text.insert(tk.END, f"   {src_ip} → Source IP\n")
            self.packet_text.insert(tk.END, f"   {dst_ip} → Destination IP\n\n")

            # Add protocol-specific interpretation
            self.packet_text.insert(tk.END, "3. Protocol-Specific Details\n")
            self.packet_text.insert(tk.END, f"{self.get_protocol_interpretation(protocol_name, src_ip, dst_ip)}\n\n")

            # Add raw payload details
            self.packet_text.insert(tk.END, "4. Raw\n")
            self.packet_text.insert(tk.END, "   Indicates that the packet contains raw payload data.\n\n")

            # Final interpretation
            self.packet_text.insert(tk.END, "Final Interpretation:\n")
            self.packet_text.insert(tk.END, f"Your computer ({src_ip}) is sending a packet to {dst_ip} using {protocol_name}. {self.get_final_interpretation(protocol_name, src_ip, dst_ip)}\n")

    def get_protocol_description(self, protocol_name):
        """Return a description of the protocol."""
        descriptions = {
            "ICMP": "Internet Control Message Protocol (Layer 3 - Network Layer)",
            "IGMP": "Internet Group Management Protocol (Layer 3 - Network Layer)",
            "TCP": "Transmission Control Protocol (Layer 4 - Transport Layer)",
            "UDP": "User Datagram Protocol (Layer 4 - Transport Layer)",
            "IPv6": "Internet Protocol Version 6 (Layer 3 - Network Layer)",
            "ESP": "Encapsulating Security Payload (Layer 3 - Network Layer)",
            "AH": "Authentication Header (Layer 3 - Network Layer)",
            "OSPF": "Open Shortest Path First (Layer 3 - Network Layer)",
            "SCTP": "Stream Control Transmission Protocol (Layer 4 - Transport Layer)",
            "Reserved": "Reserved Protocol",
        }
        return descriptions.get(protocol_name, f"Unknown Protocol ({protocol_name})")

    def get_protocol_interpretation(self, protocol_name, src_ip, dst_ip):
        """Return protocol-specific details and interpretation."""
        interpretations = {
            "ICMP": "This packet is an ICMP message, commonly used for diagnostic or control purposes (e.g., ping).",
            "IGMP": "This packet is an IGMP message, used for managing multicast group memberships.",
            "TCP": "This packet is part of a TCP connection, which is a reliable, connection-oriented communication.",
            "UDP": "This packet is a UDP datagram, which is fast, connectionless, and commonly used for real-time applications.",
            "IPv6": "This packet uses IPv6, the next-generation Internet Protocol.",
            "ESP": "This packet contains an Encapsulating Security Payload, used for secure communication.",
            "AH": "This packet contains an Authentication Header, used for secure communication.",
            "OSPF": "This packet is part of the OSPF routing protocol, used for dynamic routing in networks.",
            "SCTP": "This packet is part of an SCTP connection, which provides reliable, message-oriented communication.",
            "Reserved": "This packet uses a reserved protocol, which may have a specific purpose in certain contexts.",
        }
        return interpretations.get(protocol_name, f"This packet uses an unknown protocol ({protocol_name}). Further analysis is required.")

    def get_final_interpretation(self, protocol_name, src_ip, dst_ip):
        """Return a final interpretation of the packet's purpose."""
        interpretations = {
            "ICMP": f"The computer ({src_ip}) is sending an ICMP message to {dst_ip}, likely for diagnostic purposes (e.g., ping).",
            "IGMP": f"The computer ({src_ip}) is sending an IGMP message to {dst_ip}, likely for managing multicast group memberships.",
            "TCP": f"The computer ({src_ip}) is communicating with {dst_ip} using TCP, which is reliable and connection-oriented.",
            "UDP": f"The computer ({src_ip}) is sending a UDP datagram to {dst_ip}, which is fast and connectionless.",
            "IPv6": f"The computer ({src_ip}) is communicating with {dst_ip} using IPv6, the next-generation Internet Protocol.",
            "ESP": f"The computer ({src_ip}) is sending an encrypted packet to {dst_ip} using ESP for secure communication.",
            "AH": f"The computer ({src_ip}) is sending an authenticated packet to {dst_ip} using AH for secure communication.",
            "OSPF": f"The computer ({src_ip}) is sending an OSPF packet to {dst_ip}, likely for dynamic routing purposes.",
            "SCTP": f"The computer ({src_ip}) is communicating with {dst_ip} using SCTP, which provides reliable, message-oriented communication.",
            "Reserved": f"The computer ({src_ip}) is sending a packet to {dst_ip} using a reserved protocol, which may have a specific purpose.",
        }
        return interpretations.get(protocol_name, f"The computer ({src_ip}) is sending a packet to {dst_ip} using an unknown protocol. Further analysis is required.")

    def update_ui(self):
        """Update the UI with the latest packet data."""
        self.update_traffic_trends()
        self.update_protocol_breakdown()
        self.update_top_talkers()
        self.update_geolocation_map()