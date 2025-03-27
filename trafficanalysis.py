import datetime
import threading
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
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
import psycopg2
import scapy.all as scapy
import pandas as pd
from fpdf import FPDF
import tempfile
import os
import webbrowser
from datetime import datetime
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

        # Add pause states
        self.geolocation_paused = False
        self.top_talkers_paused = False

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
        
        # Database connection
        self.db_connection = self.get_db_connection()
        
        # Create tables if they don't exist
        self.create_tables()
        
        # Start the periodic update thread
        self.start_periodic_updates()
        
        
    def get_db_connection(self):
        """Establish a database connection."""
        try:
            return psycopg2.connect(
                dbname="ids_db",
                user="postgres",
                password="1221",
                host="localhost",
                port="5432"
            )
        except Exception as e:
            print(f"Database connection error: {e}")
            return None
            
    def create_tables(self):
        """Create database tables if they don't exist."""
        if not self.db_connection:
            return
            
        try:
            with self.db_connection.cursor() as cursor:
                # Create top_talkers table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS top_talkers (
                        id SERIAL PRIMARY KEY,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        source_ip VARCHAR(45),
                        destination_ip VARCHAR(45),
                        traffic_volume BIGINT,
                        UNIQUE(timestamp, source_ip, destination_ip)
                    )
                """)
                
                # Create geolocation table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS geolocation (
                        id SERIAL PRIMARY KEY,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        ip_address VARCHAR(45),
                        location TEXT,
                        UNIQUE(timestamp, ip_address)
                    )
                """)
                self.db_connection.commit()
        except Exception as e:
            print(f"Error creating tables: {e}")
            self.db_connection.rollback()
            
    
    def get_filtered_top_talkers(self):
        """Return top talkers data filtered by selected category."""
        category = self.top_talkers_category_var.get()
        data = []
        
        for (src_ip, dst_ip), traffic_volume in self.packet_data["top_talkers"].items():
            protocol = self.get_protocol_for_ip_pair(src_ip, dst_ip)
            is_internal = self.is_internal_ip(src_ip) or self.is_internal_ip(dst_ip)
            
            # Apply filters based on category
            if category == "All Traffic":
                data.append((src_ip, dst_ip, protocol, traffic_volume, is_internal))
            elif category == "By Source IP" and src_ip:
                data.append((src_ip, dst_ip, protocol, traffic_volume, is_internal))
            elif category == "By Destination IP" and dst_ip:
                data.append((src_ip, dst_ip, protocol, traffic_volume, is_internal))
            elif category == "By Protocol" and protocol:
                data.append((src_ip, dst_ip, protocol, traffic_volume, is_internal))
            elif category == "High Volume (>1MB)" and traffic_volume > 1000000:
                data.append((src_ip, dst_ip, protocol, traffic_volume, is_internal))
            elif category == "Internal Traffic" and is_internal:
                data.append((src_ip, dst_ip, protocol, traffic_volume, is_internal))
        
        return data
        
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

                # Update analysis data (but don't trigger UI updates here)
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
        
    def start_periodic_updates(self):
        """Start a thread to periodically update database and UI."""
        def update_task():
            while True:
                time.sleep(10)  # Wait for 10 seconds
                self.store_data_in_db()
                self.update_ui()
                
        update_thread = threading.Thread(target=update_task, daemon=True)
        update_thread.start()
        
    def store_data_in_db(self):
        """Store top talkers and geolocation data in the database."""
        if not self.db_connection:
            return
            
        try:
            with self.db_connection.cursor() as cursor:
                # Store top talkers
                for (src_ip, dst_ip), traffic_volume in self.packet_data["top_talkers"].items():
                    cursor.execute("""
                        INSERT INTO top_talkers (source_ip, destination_ip, traffic_volume)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (timestamp, source_ip, destination_ip) 
                        DO UPDATE SET traffic_volume = EXCLUDED.traffic_volume
                    """, (src_ip, dst_ip, traffic_volume))
                
                # Store geolocation data
                for ip, location in self.packet_data["geolocation"].items():
                    cursor.execute("""
                        INSERT INTO geolocation (ip_address, location)
                        VALUES (%s, %s)
                        ON CONFLICT (timestamp, ip_address) 
                        DO UPDATE SET location = EXCLUDED.location
                    """, (ip, location))
                
                self.db_connection.commit()
        except Exception as e:
            print(f"Error storing data in database: {e}")
            self.db_connection.rollback()

    def setup_protocol_breakdown(self, parent):
        """Set up the Protocol Breakdown tab."""
        # Create main container with padding
        main_container = ttk.Frame(parent)
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Title with custom styling
        title_label = ttk.Label(
            main_container,
            text="Protocol Distribution",
            style="TrafficAnalysis.TLabel",
            font=("Consolas", 16, "bold")
        )
        title_label.pack(pady=(0, 20))

        # Create frame for chart and legend
        chart_container = ttk.Frame(main_container)
        chart_container.pack(fill=tk.BOTH, expand=True)

        # Matplotlib figure for protocol breakdown with dark theme
        self.protocol_fig = Figure(figsize=(8, 6), dpi=100, facecolor=MATRIX_BG)
        self.protocol_ax = self.protocol_fig.add_subplot(111, facecolor=MATRIX_BG)
        self.protocol_ax.tick_params(axis='both', colors=MATRIX_GREEN)
        self.protocol_ax.set_facecolor(MATRIX_BG)

        # Create canvas with custom styling
        self.protocol_canvas = FigureCanvasTkAgg(self.protocol_fig, master=chart_container)
        self.protocol_canvas.get_tk_widget().pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Create legend frame
        legend_frame = ttk.Frame(chart_container)
        legend_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(20, 0))

        # Add legend labels with hover effect
        self.legend_labels = {}
        protocols = {
            "TCP": "Transmission Control Protocol - Reliable, connection-oriented protocol for data transmission",
            "UDP": "User Datagram Protocol - Fast, connectionless protocol for real-time applications",
            "ICMP": "Internet Control Message Protocol - Used for network diagnostics and error reporting",
            "ARP": "Address Resolution Protocol - Maps IP addresses to MAC addresses",
            "802.11": "IEEE 802.11 - Wireless LAN protocol for wireless communication"
        }

        for i, (protocol, description) in enumerate(protocols.items()):
            label = ttk.Label(
                legend_frame,
                text=protocol,
                style="TrafficAnalysis.TLabel",
                cursor="hand2"
            )
            label.pack(anchor=tk.W, pady=5)
            label.bind("<Enter>", lambda e, desc=description: self.show_protocol_tooltip(e, desc))
            label.bind("<Leave>", self.hide_protocol_tooltip)
            self.legend_labels[protocol] = label

        # Add hover tooltips
        self.protocol_canvas.mpl_connect("motion_notify_event", self.on_hover_protocol_chart)

        # Create tooltip label
        self.tooltip_label = ttk.Label(
            main_container,
            text="",
            style="TrafficAnalysis.TLabel",
            wraplength=400,
            justify=tk.LEFT
        )
        self.tooltip_label.pack(pady=(20, 0))

        # Initial plot
        self.update_protocol_breakdown()

    def show_protocol_tooltip(self, event, description):
        """Show tooltip with protocol description."""
        self.tooltip_label.config(text=description)
        self.tooltip_label.configure(foreground=ACCENT_GREEN)

    def hide_protocol_tooltip(self, event):
        """Hide protocol tooltip."""
        self.tooltip_label.config(text="")
        self.tooltip_label.configure(foreground=MATRIX_GREEN)

    def update_protocol_breakdown(self):
        """Update the protocol breakdown pie chart."""
        # Define protocols and their colors
        protocols = {
            "TCP": "#00FF00",  # Bright green
            "UDP": "#00CC00",  # Medium green
            "ICMP": "#009900",  # Dark green
            "ARP": "#006600",   # Very dark green
            "802.11": "#003300" # Darkest green
        }

        # Get data for each protocol
        sizes = []
        labels = []
        colors = []
        
        for protocol, color in protocols.items():
            if protocol == "TCP":
                size = self.packet_data["protocol_breakdown"].get("TCP", 0)
            elif protocol == "UDP":
                size = self.packet_data["protocol_breakdown"].get("UDP", 0)
            elif protocol == "ICMP":
                size = self.packet_data["protocol_breakdown"].get("ICMP", 0)
            elif protocol == "ARP":
                size = self.packet_data["protocol_breakdown"].get("ARP", 0)
            elif protocol == "802.11":
                size = self.packet_data["protocol_breakdown"].get("802.11", 0)

            if size > 0:
                sizes.append(size)
                labels.append(protocol)
                colors.append(color)

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
                textprops={'color': MATRIX_GREEN},
                wedgeprops={'edgecolor': MATRIX_BG, 'linewidth': 2}
            )

            # Style the percentage labels
            for autotext in autotexts:
                autotext.set_color(MATRIX_BG)
                autotext.set_weight('bold')
        else:
            self.protocol_ax.text(0.5, 0.5, "No data available", color=MATRIX_GREEN, ha="center")

        # Set title with custom styling
        self.protocol_ax.set_title("Protocol Distribution", color=MATRIX_GREEN, pad=20, fontsize=12)
        
        # Add grid
        self.protocol_ax.grid(True, color=DARK_GREEN, linestyle=':', linewidth=0.7, alpha=0.3)

        # Redraw the canvas
        self.protocol_canvas.draw()
        
    def on_hover_protocol_chart(self, event):
        """Display tooltips when hovering over the pie chart."""
        if not hasattr(self, 'protocol_ax') or not hasattr(self, 'protocol_canvas'):
            return
            
        if event.inaxes == self.protocol_ax:
            for wedge in self.protocol_ax.patches:
                if wedge.contains_point((event.x, event.y)):
                    try:
                        # Get the label and percentage for the hovered wedge
                        label = wedge.get_label()
                        # Calculate percentage based on wedge's theta values
                        theta1, theta2 = wedge.theta1, wedge.theta2
                        percentage = (theta2 - theta1) / 360 * 100
                        
                        # Get protocol description
                        descriptions = {
                            "TCP": "Transmission Control Protocol - Reliable, connection-oriented protocol for data transmission",
                            "UDP": "User Datagram Protocol - Fast, connectionless protocol for real-time applications",
                            "ICMP": "Internet Control Message Protocol - Used for network diagnostics and error reporting",
                            "ARP": "Address Resolution Protocol - Maps IP addresses to MAC addresses",
                            "802.11": "IEEE 802.11 - Wireless LAN protocol for wireless communication"
                        }
                        
                        description = descriptions.get(label, "")
                        
                        # Display the tooltip
                        self.tooltip_label.config(text=f"{label}: {percentage:.1f}%\n{description}")
                        self.tooltip_label.configure(foreground=ACCENT_GREEN)
                        self.protocol_canvas.draw_idle()
                    except Exception as e:
                        print(f"Error updating tooltip: {e}")
                    break
            else:
                try:
                    # Reset the tooltip if not hovering over any wedge
                    self.tooltip_label.config(text="")
                    self.tooltip_label.configure(foreground=MATRIX_GREEN)
                    self.protocol_canvas.draw_idle()
                except Exception as e:
                    print(f"Error resetting tooltip: {e}")

    def setup_top_talkers(self, parent):
        """Set up the Top Talkers tab."""
        ttk.Label(parent, text="Top Talkers", style="TrafficAnalysis.TLabel").pack(pady=10)
        
        # Add export/print controls frame
        controls_frame = ttk.Frame(parent)
        controls_frame.pack(fill=tk.X, pady=5)
        
        # Categorization dropdown
        self.top_talkers_category_var = tk.StringVar(value="All Traffic")
        categories = ["All Traffic", "By Source IP", "By Destination IP", "By Protocol", "High Volume (>1MB)", "Internal Traffic"]
        ttk.Label(controls_frame, text="Categorize by:", style="TrafficAnalysis.TLabel").pack(side=tk.LEFT, padx=5)
        category_dropdown = ttk.Combobox(
            controls_frame,
            textvariable=self.top_talkers_category_var,
            values=categories,
            state="readonly"
        )
        category_dropdown.pack(side=tk.LEFT, padx=5)
        category_dropdown.bind("<<ComboboxSelected>>", self.update_top_talkers)
        
        # Add pause/resume button
        self.top_talkers_pause_button = ttk.Button(
            controls_frame,
            text="Pause",
            command=self.toggle_top_talkers_pause
        )
        self.top_talkers_pause_button.pack(side=tk.LEFT, padx=5)
        
        # Export buttons
        ttk.Button(controls_frame, text="Export PDF", command=lambda: self.export_top_talkers("pdf")).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Export CSV", command=lambda: self.export_top_talkers("csv")).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Export Excel", command=lambda: self.export_top_talkers("excel")).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Print", command=self.print_top_talkers).pack(side=tk.LEFT, padx=5)

        # Treeview for top talkers
        columns = ("Source IP", "Destination IP", "Traffic (MB)")
        self.top_talkers_tree = ttk.Treeview(parent, columns=columns, show='headings')
        for col in columns:
            self.top_talkers_tree.heading(col, text=col)
            self.top_talkers_tree.column(col, width=150)
        self.top_talkers_tree.pack(fill=tk.BOTH, expand=True)

    def update_top_talkers(self, event=None):
        """Update the Top Talkers tab with the latest data."""
        if self.top_talkers_paused:
            return
            
        try:
            # Clear the existing data in the treeview
            for row in self.top_talkers_tree.get_children():
                try:
                    self.top_talkers_tree.delete(row)
                except tk.TclError:
                    # Item no longer exists, skip it
                    continue

            # Sort the top talkers by traffic volume (descending order)
            sorted_top_talkers = sorted(
                self.packet_data["top_talkers"].items(),
                key=lambda x: x[1],
                reverse=True
            )

            # Add the top talkers to the treeview
            for (src_ip, dst_ip), traffic_volume in sorted_top_talkers:
                try:
                    self.top_talkers_tree.insert("", "end", values=(src_ip, dst_ip, traffic_volume))
                except tk.TclError:
                    # Treeview was destroyed, stop updating
                    break
        except Exception as e:
            print(f"Error updating top talkers: {e}")

    def setup_geolocation(self, parent):
        """Set up the Geolocation tab."""
        ttk.Label(parent, text="Geolocation of Traffic", style="TrafficAnalysis.TLabel").pack(pady=10)
        
        # Add export/print controls frame
        controls_frame = ttk.Frame(parent)
        controls_frame.pack(fill=tk.X, pady=5)
        
        # Categorization dropdown
        self.geo_category_var = tk.StringVar(value="All Locations")
        categories = ["All Locations", "By Country", "By City", "Internal vs External", "High Traffic Locations", "Suspicious Locations"]
        ttk.Label(controls_frame, text="Categorize by:", style="TrafficAnalysis.TLabel").pack(side=tk.LEFT, padx=5)
        category_dropdown = ttk.Combobox(
            controls_frame,
            textvariable=self.geo_category_var,
            values=categories,
            state="readonly"
        )
        category_dropdown.pack(side=tk.LEFT, padx=5)
        category_dropdown.bind("<<ComboboxSelected>>", self.update_geolocation_map)
        
        # Add pause/resume button
        self.geo_pause_button = ttk.Button(
            controls_frame,
            text="Pause",
            command=self.toggle_geolocation_pause
        )
        self.geo_pause_button.pack(side=tk.LEFT, padx=5)
        
        # Export buttons
        ttk.Button(controls_frame, text="Export PDF", command=lambda: self.export_geolocation("pdf")).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Export CSV", command=lambda: self.export_geolocation("csv")).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Export Excel", command=lambda: self.export_geolocation("excel")).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Print", command=self.print_geolocation).pack(side=tk.LEFT, padx=5)

        # Treeview for geolocation
        columns = ("IP Address", "Location")
        self.geolocation_tree = ttk.Treeview(parent, columns=columns, show='headings')
        for col in columns:
            self.geolocation_tree.heading(col, text=col)
            self.geolocation_tree.column(col, width=150)
        self.geolocation_tree.pack(fill=tk.BOTH, expand=True)

    def update_geolocation(self, ip):
        """Map an IP address to a location using GeoIP."""
        try:
            response = self.geoip_reader.city(ip)
            location = f"{response.city.name}, {response.country.name}"
            self.packet_data["geolocation"][ip] = location
        except Exception as e:
            print(f"GeoIP lookup failed for {ip}: {e}")

    def toggle_geolocation_pause(self):
        """Toggle pause/resume state for geolocation updates."""
        self.geolocation_paused = not self.geolocation_paused
        self.geo_pause_button.config(text="Resume" if self.geolocation_paused else "Pause")
        if not self.geolocation_paused:
            self.update_geolocation_map()

    def update_geolocation_map(self):
        """Update the Geolocation tab with the latest data."""
        if self.geolocation_paused:
            return
            
        try:
            # Clear the existing data in the treeview
            for row in self.geolocation_tree.get_children():
                try:
                    self.geolocation_tree.delete(row)
                except tk.TclError:
                    # Item no longer exists, skip it
                    continue

            # Get filtered data based on selected category
            filtered_data = self.get_filtered_geolocation()

            # Add the filtered geolocation data to the treeview
            for item in filtered_data:
                try:
                    # Extract IP and location from the filtered data
                    ip = item[0]
                    location = item[1]
                    self.geolocation_tree.insert("", "end", values=(ip, location))
                except tk.TclError:
                    # Treeview was destroyed, stop updating
                    break
        except Exception as e:
            print(f"Error updating geolocation map: {e}")
            
            
    def get_filtered_geolocation(self):
        """Return geolocation data filtered by selected category."""
        category = self.geo_category_var.get()
        data = []
        
        for ip, location in self.packet_data["geolocation"].items():
            country = location.split(",")[-1].strip() if "," in location else "Unknown"
            city = location.split(",")[0].strip() if "," in location else location
            is_internal = self.is_internal_ip(ip)
            traffic_volume = sum(size for (src_ip, dst_ip), size in self.packet_data["top_talkers"].items() 
                          if src_ip == ip or dst_ip == ip)
            is_suspicious = self.is_suspicious_location(location)
            
            # Apply filters based on category
            if category == "All Locations":
                data.append((ip, location, country, city, traffic_volume, is_internal, is_suspicious))
            elif category == "By Country":
                data.append((ip, location, country, city, traffic_volume, is_internal, is_suspicious))
            elif category == "By City":
                data.append((ip, location, country, city, traffic_volume, is_internal, is_suspicious))
            elif category == "Internal vs External":
                data.append((ip, location, country, city, traffic_volume, is_internal, is_suspicious))
            elif category == "High Traffic Locations" and traffic_volume > 1000000:
                data.append((ip, location, country, city, traffic_volume, is_internal, is_suspicious))
            elif category == "Suspicious Locations" and is_suspicious:
                data.append((ip, location, country, city, traffic_volume, is_internal, is_suspicious))
        
        return data
    
    def export_top_talkers(self, format_type):
        """Export top talkers data in the specified format."""
        data = self.get_filtered_top_talkers()
        if not data:
            messagebox.showwarning("No Data", "No data to export for the selected category")
            return
        
        df = pd.DataFrame(data, columns=["Source IP", "Destination IP", "Protocol", "Traffic Volume", "Is Internal"])
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"top_talkers_{self.top_talkers_category_var.get().lower().replace(' ', '_')}_{timestamp}"
        
        try:
            if format_type == "pdf":
                self.export_to_pdf(df, filename, "Top Talkers Analysis")
            elif format_type == "csv":
                df.to_csv(f"{filename}.csv", index=False)
                messagebox.showinfo("Success", f"Data exported to {filename}.csv")
            elif format_type == "excel":
                df.to_excel(f"{filename}.xlsx", index=False)
                messagebox.showinfo("Success", f"Data exported to {filename}.xlsx")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export data: {str(e)}")
    
    def export_geolocation(self, format_type):
        """Export geolocation data in the specified format."""
        data = self.get_filtered_geolocation()
        if not data:
            messagebox.showwarning("No Data", "No data to export for the selected category")
            return
        
        df = pd.DataFrame(data, columns=["IP Address", "Location", "Country", "City", "Traffic Volume", "Is Internal", "Is Suspicious"])
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"geolocation_{self.geo_category_var.get().lower().replace(' ', '_')}_{timestamp}"
        
        try:
            if format_type == "pdf":
                self.export_to_pdf(df, filename, "Geolocation Analysis")
            elif format_type == "csv":
                df.to_csv(f"{filename}.csv", index=False)
                messagebox.showinfo("Success", f"Data exported to {filename}.csv")
            elif format_type == "excel":
                df.to_excel(f"{filename}.xlsx", index=False)
                messagebox.showinfo("Success", f"Data exported to {filename}.xlsx")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export data: {str(e)}")
    
    def export_to_pdf(self, df, filename, title):
        """Export DataFrame to PDF."""
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=10)
        
        # Add title
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(200, 10, txt=title, ln=1, align='C')
        pdf.set_font("Arial", size=10)
        
        # Add filters/category info
        pdf.cell(200, 10, txt=f"Category: {self.top_talkers_category_var.get() if 'talkers' in filename else self.geo_category_var.get()}", ln=1)
        pdf.cell(200, 10, txt=f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1)
        pdf.ln(5)
        
        # Add table headers
        col_widths = [pdf.get_string_width(col) + 6 for col in df.columns]
        for i, col in enumerate(df.columns):
            pdf.cell(col_widths[i], 10, txt=col, border=1)
        pdf.ln()
        
        # Add table rows
        for _, row in df.iterrows():
            for i, col in enumerate(df.columns):
                pdf.cell(col_widths[i], 10, txt=str(row[col]), border=1)
            pdf.ln()
        
        # Save to temp file and open
        temp_file = os.path.join(tempfile.gettempdir(), f"{filename}.pdf")
        pdf.output(temp_file)
        webbrowser.open(temp_file)
        messagebox.showinfo("Success", f"PDF exported to {temp_file}")
    
    def print_top_talkers(self):
        """Print top talkers data."""
        data = self.get_filtered_top_talkers()
        if not data:
            messagebox.showwarning("No Data", "No data to print for the selected category")
            return
        
        # Create HTML content for printing
        html = f"""
        <html>
        <head>
            <title>Top Talkers Report</title>
            <style>
                body {{ font-family: Arial; margin: 20px; }}
                h1 {{ color: #333; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .footer {{ margin-top: 20px; font-size: 0.8em; color: #666; }}
            </style>
        </head>
        <body>
            <h1>Top Talkers Report</h1>
            <p><strong>Category:</strong> {self.top_talkers_category_var.get()}</p>
            <p><strong>Generated on:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <table>
                <tr>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Protocol</th>
                    <th>Traffic Volume</th>
                    <th>Internal</th>
                </tr>
        """
        
        for item in data:
            html += f"""
                <tr>
                    <td>{item[0]}</td>
                    <td>{item[1]}</td>
                    <td>{item[2]}</td>
                    <td>{item[3]}</td>
                    <td>{'Yes' if item[4] else 'No'}</td>
                </tr>
            """
        
        html += """
            </table>
            <div class="footer">Network Traffic Analysis Report - Generated by IDS</div>
        </body>
        </html>
        """
        
        self.print_html(html, "Top Talkers Report")
    
    def print_geolocation(self):
        """Print geolocation data."""
        data = self.get_filtered_geolocation()
        if not data:
            messagebox.showwarning("No Data", "No data to print for the selected category")
            return
        
        # Create HTML content for printing
        html = f"""
        <html>
        <head>
            <title>Geolocation Report</title>
            <style>
                body {{ font-family: Arial; margin: 20px; }}
                h1 {{ color: #333; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .footer {{ margin-top: 20px; font-size: 0.8em; color: #666; }}
            </style>
        </head>
        <body>
            <h1>Geolocation Report</h1>
            <p><strong>Category:</strong> {self.geo_category_var.get()}</p>
            <p><strong>Generated on:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Location</th>
                    <th>Country</th>
                    <th>City</th>
                    <th>Traffic Volume</th>
                    <th>Internal</th>
                    <th>Suspicious</th>
                </tr>
        """
        
        for item in data:
            html += f"""
                <tr>
                    <td>{item[0]}</td>
                    <td>{item[1]}</td>
                    <td>{item[2]}</td>
                    <td>{item[3]}</td>
                    <td>{item[4]}</td>
                    <td>{'Yes' if item[5] else 'No'}</td>
                    <td>{'Yes' if item[6] else 'No'}</td>
                </tr>
            """
        
        html += """
            </table>
            <div class="footer">Network Traffic Analysis Report - Generated by IDS</div>
        </body>
        </html>
        """
        
        self.print_html(html, "Geolocation Report")
    
    def print_html(self, html, title):
        """Print HTML content."""
        temp_file = os.path.join(tempfile.gettempdir(), f"{title.replace(' ', '_')}.html")
        with open(temp_file, "w") as f:
            f.write(html)
        webbrowser.open(temp_file)
    
    # Helper methods
    def get_protocol_for_ip_pair(self, src_ip, dst_ip):
        """Determine the most common protocol between two IPs."""
        protocols = []
        for packet in self.packet_tree.get_children():
            values = self.packet_tree.item(packet, "values")
            if values[1] == src_ip and values[2] == dst_ip:
                protocols.append(values[3])
        return max(set(protocols), key=protocols.count) if protocols else "Unknown"
    
    def is_internal_ip(self, ip):
        """Check if an IP is internal (RFC 1918)."""
        if ip.startswith("10.") or ip.startswith("192.168."):
            return True
        if ip.startswith("172."):
            second_octet = int(ip.split(".")[1])
            return 16 <= second_octet <= 31
        return False
    
    def is_suspicious_location(self, location):
        """Check if a location is considered suspicious."""
        suspicious_countries = ["RU", "CN", "KP", "IR", "SY"]  # Example list
        country = location.split(",")[-1].strip() if "," in location else ""
        return any(c in country for c in suspicious_countries)

    def setup_packet_inspection(self, parent):
        """Set up the Packet Inspection tab."""
        ttk.Label(parent, text="Packet Inspection", style="TrafficAnalysis.TLabel").pack(pady=10)
        
        # Add export/print controls frame
        controls_frame = ttk.Frame(parent)
        controls_frame.pack(fill=tk.X, pady=5)
        
        # Categorization dropdown
        self.packet_category_var = tk.StringVar(value="All Packets")
        categories = [
            "All Packets",
            "By Protocol",
            "By Source IP",
            "By Destination IP",
            "Large Packets (>1KB)",
            "Suspicious Traffic",
            "Internal Traffic",
            "External Traffic",
            "TCP Only",
            "UDP Only",
            "ICMP Only"
        ]
        ttk.Label(controls_frame, text="Filter by:", style="TrafficAnalysis.TLabel").pack(side=tk.LEFT, padx=5)
        category_dropdown = ttk.Combobox(
            controls_frame,
            textvariable=self.packet_category_var,
            values=categories,
            state="readonly"
        )
        category_dropdown.pack(side=tk.LEFT, padx=5)
        category_dropdown.bind("<<ComboboxSelected>>", self.update_packet_display)
        
        # Export buttons
        ttk.Button(controls_frame, text="Export PDF", command=lambda: self.export_packets("pdf")).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Export CSV", command=lambda: self.export_packets("csv")).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Export Excel", command=lambda: self.export_packets("excel")).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Print", command=self.print_packets).pack(side=tk.LEFT, padx=5)

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
        
    def get_protocol_name(self, protocol):
        """Convert protocol number to name."""
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
        try:
            protocol_num = int(protocol)
            return protocol_map.get(protocol_num, f"Unknown Protocol ({protocol})")
        except (ValueError, TypeError):
            return f"Unknown Protocol ({protocol})"

    def get_filtered_packets(self):
        """Return packet data filtered by selected category."""
        category = self.packet_category_var.get()
        filtered_packets = []
        
        for item in self.packet_tree.get_children():
            values = self.packet_tree.item(item, "values")
            if not values:
                continue
                
            time_stamp, src_ip, dst_ip, protocol, size, headers = values
            size_int = int(size) if size.isdigit() else 0
            protocol_name = self.get_protocol_name(protocol)
            
            # Apply filters based on category
            if category == "All Packets":
                filtered_packets.append(values)
            elif category == "By Protocol" and protocol_name:
                filtered_packets.append(values)
            elif category == "By Source IP" and src_ip:
                filtered_packets.append(values)
            elif category == "By Destination IP" and dst_ip:
                filtered_packets.append(values)
            elif category == "Large Packets (>1KB)" and size_int > 1024:
                filtered_packets.append(values)
            elif category == "Suspicious Traffic" and self.is_suspicious_packet(src_ip, dst_ip, protocol_name):
                filtered_packets.append(values)
            elif category == "Internal Traffic" and (self.is_internal_ip(src_ip) or self.is_internal_ip(dst_ip)):
                filtered_packets.append(values)
            elif category == "External Traffic" and not (self.is_internal_ip(src_ip) and self.is_internal_ip(dst_ip)):
                filtered_packets.append(values)
            elif category == "TCP Only" and protocol_name == "TCP":
                filtered_packets.append(values)
            elif category == "UDP Only" and protocol_name == "UDP":
                filtered_packets.append(values)
            elif category == "ICMP Only" and protocol_name == "ICMP":
                filtered_packets.append(values)
        
        return filtered_packets

    def get_ip_location(self, ip):
        """Get location information for an IP address."""
        try:
            # Check if it's an internal IP first
            if self.is_internal_ip(ip):
                return "Internal Network"
            
            # Try to get location from GeoIP database
            response = self.geoip_reader.city(ip)
            if response and response.city and response.country:
                return f"{response.city.name}, {response.country.name}"
            return "Unknown Location"
        except Exception as e:
            print(f"Error getting location for IP {ip}: {e}")
            return "Unknown Location"

    def is_suspicious_packet(self, src_ip, dst_ip, protocol):
        """Check if a packet is considered suspicious."""
        try:
            # Example checks - expand based on your security needs
            suspicious_ports = [22, 23, 3389, 5900]  # SSH, Telnet, RDP, VNC
            
            # Check for suspicious ports in destination
            if protocol == "TCP" and any(f":{port}" in dst_ip for port in suspicious_ports):
                return True
                
            # Check source location
            src_location = self.get_ip_location(src_ip)
            if self.is_suspicious_location(src_location):
                return True
                
            # Check destination location
            dst_location = self.get_ip_location(dst_ip)
            if self.is_suspicious_location(dst_location):
                return True
                
            return False
        except Exception as e:
            print(f"Error checking suspicious packet: {e}")
            return False

    def export_packets(self, format_type):
        """Export packet data in the specified format."""
        data = self.get_filtered_packets()
        if not data:
            messagebox.showwarning("No Data", "No packets to export for the selected category")
            return
        
        df = pd.DataFrame(data, columns=["Time", "Source IP", "Destination IP", "Protocol", "Size", "Headers"])
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"packets_{self.packet_category_var.get().lower().replace(' ', '_')}_{timestamp}"
        
        try:
            if format_type == "pdf":
                self.export_packets_to_pdf(df, filename)
            elif format_type == "csv":
                df.to_csv(f"{filename}.csv", index=False)
                messagebox.showinfo("Success", f"Data exported to {filename}.csv")
            elif format_type == "excel":
                df.to_excel(f"{filename}.xlsx", index=False)
                messagebox.showinfo("Success", f"Data exported to {filename}.xlsx")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export packets: {str(e)}")

    def export_packets_to_pdf(self, df, filename):
        """Export packet data to PDF with detailed formatting."""
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=10)
        
        # Add title
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(200, 10, txt="Packet Inspection Report", ln=1, align='C')
        pdf.set_font("Arial", size=10)
        
        # Add metadata
        pdf.cell(200, 10, txt=f"Filter: {self.packet_category_var.get()}", ln=1)
        pdf.cell(200, 10, txt=f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1)
        pdf.cell(200, 10, txt=f"Total Packets: {len(df)}", ln=1)
        pdf.ln(5)
        
        # Add summary statistics
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(200, 10, txt="Summary Statistics", ln=1)
        pdf.set_font("Arial", size=10)
        
        # Calculate stats
        protocols = df["Protocol"].value_counts().to_dict()
        top_sources = df["Source IP"].value_counts().head(5).to_dict()
        top_dests = df["Destination IP"].value_counts().head(5).to_dict()
        avg_size = df["Size"].astype(int).mean()
        
        pdf.cell(200, 10, txt=f"Protocol Distribution: {', '.join([f'{k} ({v})' for k, v in protocols.items()])}", ln=1)
        pdf.cell(200, 10, txt=f"Top Sources: {', '.join([f'{k} ({v})' for k, v in top_sources.items()])}", ln=1)
        pdf.cell(200, 10, txt=f"Top Destinations: {', '.join([f'{k} ({v})' for k, v in top_dests.items()])}", ln=1)
        pdf.cell(200, 10, txt=f"Average Packet Size: {avg_size:.2f} bytes", ln=1)
        pdf.ln(10)
        
        # Add table
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(200, 10, txt="Packet Details", ln=1)
        pdf.set_font("Arial", size=8)
        
        # Table headers
        col_widths = [30, 30, 30, 20, 15, 75]  # Adjust based on your needs
        headers = ["Time", "Source IP", "Dest IP", "Protocol", "Size", "Headers"]
        for i, header in enumerate(headers):
            pdf.cell(col_widths[i], 10, txt=header, border=1)
        pdf.ln()
        
        # Table rows
        for _, row in df.iterrows():
            for i, col in enumerate(headers):
                # Truncate long headers for display
                value = str(row[col])
                if col == "Headers" and len(value) > 50:
                    value = value[:50] + "..."
                pdf.cell(col_widths[i], 10, txt=value, border=1)
            pdf.ln()
        
        # Save to temp file and open
        temp_file = os.path.join(tempfile.gettempdir(), f"{filename}.pdf")
        pdf.output(temp_file)
        webbrowser.open(temp_file)
        messagebox.showinfo("Success", f"PDF exported to {temp_file}")

    def print_packets(self):
        """Print packet data."""
        data = self.get_filtered_packets()
        if not data:
            messagebox.showwarning("No Data", "No packets to print for the selected category")
            return
        
        # Create HTML content for printing
        html = f"""
        <html>
        <head>
            <title>Packet Inspection Report</title>
            <style>
                body {{ font-family: Arial; margin: 20px; }}
                h1 {{ color: #333; }}
                .summary {{ margin-bottom: 20px; }}
                table {{ border-collapse: collapse; width: 100%; font-size: 0.9em; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .footer {{ margin-top: 20px; font-size: 0.8em; color: #666; }}
            </style>
        </head>
        <body>
            <h1>Packet Inspection Report</h1>
            <div class="summary">
                <p><strong>Filter:</strong> {self.packet_category_var.get()}</p>
                <p><strong>Generated on:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Total Packets:</strong> {len(data)}</p>
            </div>
            <table>
                <tr>
                    <th>Time</th>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Protocol</th>
                    <th>Size</th>
                    <th>Headers</th>
                </tr>
        """
        
        for row in data:
            html += f"""
                <tr>
                    <td>{row[0]}</td>
                    <td>{row[1]}</td>
                    <td>{row[2]}</td>
                    <td>{row[3]}</td>
                    <td>{row[4]}</td>
                    <td>{row[5][:100]}{'...' if len(row[5]) > 100 else ''}</td>
                </tr>
            """
        
        html += """
            </table>
            <div class="footer">Network Traffic Analysis Report - Generated by IDS</div>
        </body>
        </html>
        """
        
        self.print_html(html, "Packet Inspection Report")

    def update_packet_display(self, event=None):
        """Update the packet display based on the selected filter."""
        # This would be called when the filter dropdown changes
        # In a real implementation, you would filter the displayed packets
        pass
        
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

            # Final Interpretation
            self.packet_text.insert(tk.END, "Final Interpretation:\n")
            self.packet_text.insert(
                tk.END,
                #f"The captured packet represents a {protocol_name} communication from {src_ip} to {dst_ip}. "
                f"{self.get_final_interpretation(protocol_name, src_ip, dst_ip, size)}\n"
            )

            
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

    def get_protocol_interpretation(self, protocol_name, src_ip, dst_ip,):
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

    def get_final_interpretation(self, protocol_name, src_ip, dst_ip, size):
        """Return a structured final interpretation of the packet's purpose."""
        interpretations = {
            "ICMP": f"The captured packet represents an ICMP communication from {src_ip} to {dst_ip}, typically used for network diagnostics like ping or traceroute. If expected, this is a normal operation; however, unexpected ICMP traffic could indicate network probing or a reconnaissance attempt.",
            "IGMP": f"The captured packet represents an IGMP communication from {src_ip} to {dst_ip}, likely for managing multicast group memberships. This is commonly used for streaming services and efficient network broadcasting.",
            "TCP": f"The captured packet represents a TCP communication from {src_ip} to {dst_ip}, indicating an attempt to establish a reliable connection. Since TCP is connection-oriented, this could be part of a legitimate session or an unauthorized access attempt. Given the packet size of {size} bytes, it might be a control message such as a SYN request or ACK response. If unexpected, this traffic could indicate a potential intrusion or port scanning attempt, requiring further investigation.",
            "UDP": f"The captured packet represents a UDP communication from {src_ip} to {dst_ip}, which is a connectionless protocol often used for fast data transmission. Since UDP lacks reliability checks, this packet might be part of normal traffic such as DNS queries or VoIP, but if unexpected, it could indicate a scanning attempt or potential DDoS activity.",
            "IPv6": f"The captured packet represents an IPv6 communication from {src_ip} to {dst_ip}, using the next-generation Internet Protocol. If expected, this is normal network activity, but unexpected IPv6 traffic might indicate a misconfiguration or an attempt to bypass security filters.",
            "ESP": f"The captured packet represents an encrypted ESP (Encapsulating Security Payload) communication from {src_ip} to {dst_ip}, used in IPsec for secure data transmission. If expected, this is part of a secure VPN or encrypted communication, but unexpected ESP packets could indicate unauthorized tunneling attempts.",
            "AH": f"The captured packet represents an authenticated AH (Authentication Header) communication from {src_ip} to {dst_ip}, ensuring integrity and authentication in an IPsec security framework. If this is unexpected, it could indicate an attempt to manipulate secure network traffic.",
            "OSPF": f"The captured packet represents an OSPF (Open Shortest Path First) communication from {src_ip} to {dst_ip}, which is used for dynamic routing. If this traffic is unexpected, it could indicate unauthorized routing updates or a network misconfiguration.",
            "SCTP": f"The captured packet represents an SCTP communication from {src_ip} to {dst_ip}, commonly used in telecommunications for reliable and message-oriented data transmission. If unexpected, it could indicate an unauthorized connection attempt.",
            "Reserved": f"The captured packet represents a communication from {src_ip} to {dst_ip} using a reserved protocol. This might be part of a specialized service, but if unexpected, further analysis is required to determine its purpose."
        }
        
        return interpretations.get(protocol_name, f"The captured packet represents a communication from {src_ip} to {dst_ip} using an unknown protocol. Further analysis is required to determine its intent.")
    
    def update_ui(self):
        """Update the UI with the latest packet data."""
        # This will now only be called every 10 seconds by the periodic update thread
        self.update_traffic_trends()
        self.update_protocol_breakdown()
        self.update_top_talkers()
        self.update_geolocation_map()
        
    def destroy(self):
        """Clean up resources when the view is destroyed."""
        if hasattr(self, 'db_connection') and self.db_connection:
            self.db_connection.close()
        super().destroy()

    def toggle_top_talkers_pause(self):
        """Toggle pause/resume state for top talkers updates."""
        self.top_talkers_paused = not self.top_talkers_paused
        self.top_talkers_pause_button.config(text="Resume" if self.top_talkers_paused else "Pause")
        if not self.top_talkers_paused:
            self.update_top_talkers()