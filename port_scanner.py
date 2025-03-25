import nmap
import tkinter as tk
from tkinter import ttk, messagebox
import schedule
import time
import threading
import csv
import json
import socket
from constants import MATRIX_BG, MATRIX_GREEN, DARK_GREEN, ACCENT_GREEN

def get_local_ip():
    """Get the local IP address."""
    try:
        # Create a socket connection to get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

def scan_ports(target, ports, scan_type, output_format):
    """Scans specified ports on the target IP or hostname with various options and saves the results."""
    nm = nmap.PortScanner()
    result = {}
    
    try:
        print(f"Starting scan on {target} for ports: {ports}")
        
        # Construct the scan arguments based on user input
        scan_args = "-O -sV -A --traceroute" if scan_type == "Aggressive Scan" else "-O -sV"
        
        # Perform the scan with OS, version, and other options
        nm.scan(hosts=target, ports=ports, arguments=scan_args)
        
        for host in nm.all_hosts():
            result[host] = {
                "hostname": nm[host].hostname(),
                "state": nm[host].state(),
                "os": nm[host].get('osmatch', 'Unknown'),
                "ports": {}
            }
            for protocol in nm[host].all_protocols():
                for port in nm[host][protocol].keys():
                    port_info = nm[host][protocol][port]
                    result[host]["ports"][port] = {
                        "state": port_info['state'],
                        "service": port_info.get('name', 'Unknown')
                    }
        
        # Save the results based on the chosen output format
        if output_format == "CSV":
            save_to_csv(result)
        elif output_format == "JSON":
            save_to_json(result)
        
        messagebox.showinfo("Scan Complete", "Scan completed and results saved.")
        
    except Exception as e:
        print(f"Error: {e}")
        messagebox.showerror("Error", f"An error occurred: {e}")

def save_to_csv(result):
    """Saves scan results to a CSV file."""
    with open("scan_results.csv", mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Host", "Port", "State", "Service", "OS"])
        
        for host, details in result.items():
            for port, port_info in details["ports"].items():
                writer.writerow([host, port, port_info['state'], port_info['service'], details['os']])

def save_to_json(result):
    """Saves scan results to a JSON file."""
    with open("scan_results.json", mode='w') as file:
        json.dump(result, file, indent=4)

def schedule_scan(target, ports, scan_type, output_format, interval):
    """Schedules a scan at a specified interval."""
    schedule.every(interval).minutes.do(lambda: scan_ports(target, ports, scan_type, output_format))

    while True:
        schedule.run_pending()
        time.sleep(1)

def start_scan_thread(target, ports, scan_type, output_format):
    """Runs the scan in a separate thread."""
    scan_thread = threading.Thread(target=scan_ports, args=(target, ports, scan_type, output_format))
    scan_thread.start()

def run_gui():
    """Runs the Tkinter GUI for user input and options."""
    def start_scan():
        target = target_entry.get()
        ports = ports_entry.get()
        scan_type = scan_type_var.get()
        output_format = output_format_var.get()

        if not target or not ports:
            messagebox.showerror("Input Error", "Target and Ports are required.")
            return

        if schedule_check_var.get():
            interval = int(interval_entry.get())
            threading.Thread(target=schedule_scan, args=(target, ports, scan_type, output_format, interval)).start()
        else:
            start_scan_thread(target, ports, scan_type, output_format)

    # Create GUI window
    root = tk.Tk()
    root.title("Nmap Port Scanner")

    # Target and Ports Input
    tk.Label(root, text="Target (IP or Hostname):").pack()
    target_entry = tk.Entry(root, width=30)
    target_entry.pack()

    tk.Label(root, text="Ports (e.g., 22,80,443 or 1-1000):").pack()
    ports_entry = tk.Entry(root, width=30)
    ports_entry.pack()

    # Scan Type
    scan_type_var = tk.StringVar(value="Aggressive Scan")
    tk.Label(root, text="Select Scan Type:").pack()
    tk.Radiobutton(root, text="Aggressive Scan", variable=scan_type_var, value="Aggressive Scan").pack()
    tk.Radiobutton(root, text="Standard Scan", variable=scan_type_var, value="Standard Scan").pack()

    # Output Format
    output_format_var = tk.StringVar(value="CSV")
    tk.Label(root, text="Select Output Format:").pack()
    tk.Radiobutton(root, text="CSV", variable=output_format_var, value="CSV").pack()
    tk.Radiobutton(root, text="JSON", variable=output_format_var, value="JSON").pack()

    # Schedule Option
    schedule_check_var = tk.BooleanVar()
    tk.Checkbutton(root, text="Schedule scan every X minutes", variable=schedule_check_var).pack()

    tk.Label(root, text="Interval in minutes:").pack()
    interval_entry = tk.Entry(root, width=10)
    interval_entry.pack()

    # Start Scan Button
    start_button = tk.Button(root, text="Start Scan", command=start_scan)
    start_button.pack()

    # Run GUI
    root.mainloop()

class PortScannerView(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.local_ip = get_local_ip()
        self.setup_gui()
        
    def setup_gui(self):
        # Main container with padding
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title_label = ttk.Label(
            main_frame,
            text="PORT SCANNER",
            style="Header.TLabel"
        )
        title_label.pack(pady=(0, 20))
        
        # Input frame with modern styling
        input_frame = ttk.LabelFrame(
            main_frame,
            text="Scan Configuration",
            padding=15
        )
        input_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Target display
        target_frame = ttk.Frame(input_frame)
        target_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(
            target_frame,
            text="Target IP:",
            style="Header.TLabel"
        ).pack(side=tk.LEFT, padx=5)
        
        target_label = ttk.Label(
            target_frame,
            text=self.local_ip,
            style="Header.TLabel"
        )
        target_label.pack(side=tk.LEFT, padx=5)
        
        # Port range frame
        port_frame = ttk.Frame(input_frame)
        port_frame.pack(fill=tk.X)
        
        ttk.Label(
            port_frame,
            text="Port Range:",
            style="Header.TLabel"
        ).pack(side=tk.LEFT, padx=5)
        
        self.start_port_var = tk.StringVar(value="1")
        self.end_port_var = tk.StringVar(value="1024")
        
        self.start_port_entry = ttk.Entry(
            port_frame,
            textvariable=self.start_port_var,
            width=6,
            style="Sidebar.TEntry"
        )
        self.start_port_entry.pack(side=tk.LEFT, padx=2)
        
        ttk.Label(
            port_frame,
            text="-",
            style="Header.TLabel"
        ).pack(side=tk.LEFT)
        
        self.end_port_entry = ttk.Entry(
            port_frame,
            textvariable=self.end_port_var,
            width=6,
            style="Sidebar.TEntry"
        )
        self.end_port_entry.pack(side=tk.LEFT, padx=2)
        
        # Scan button
        self.scan_button = ttk.Button(
            input_frame,
            text="Start Scan",
            command=self.start_scan,
            style="Sidebar.TButton",
            width=15
        )
        self.scan_button.pack(side=tk.RIGHT, padx=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(
            main_frame,
            text="Scan Results",
            padding=15
        )
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create Treeview for results
        columns = ("Port", "Status", "Service")
        self.results_tree = ttk.Treeview(
            results_frame,
            columns=columns,
            show='headings',
            style="Packet.Treeview",
            height=15
        )
        
        # Configure columns
        self.results_tree.heading("Port", text="Port")
        self.results_tree.heading("Status", text="Status")
        self.results_tree.heading("Service", text="Service")
        
        self.results_tree.column("Port", width=100)
        self.results_tree.column("Status", width=100)
        self.results_tree.column("Service", width=200)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(
            results_frame,
            orient="vertical",
            command=self.results_tree.yview,
            style="Vertical.TScrollbar"
        )
        
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack the Treeview and scrollbar
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = ttk.Label(
            main_frame,
            textvariable=self.status_var,
            style="Header.TLabel"
        )
        self.status_bar.pack(fill=tk.X, pady=(10, 0))
            
    def start_scan(self):
        """Start the port scanning process."""
        try:
            start_port = int(self.start_port_var.get())
            end_port = int(self.end_port_var.get())
            
            if start_port < 1 or end_port > 65535:
                messagebox.showerror("Error", "Port range must be between 1 and 65535")
                return
                
            if start_port > end_port:
                messagebox.showerror("Error", "Start port must be less than end port")
                return
            
            # Clear previous results
            for item in self.results_tree.get_children():
                self.results_tree.delete(item)
            
            # Disable scan button
            self.scan_button.config(state=tk.DISABLED)
            self.status_var.set("Scanning...")
            
            # Start scanning in a separate thread
            thread = threading.Thread(
                target=self.scan_ports,
                args=(self.local_ip, start_port, end_port)
            )
            thread.daemon = True
            thread.start()
            
        except ValueError:
            messagebox.showerror("Error", "Please enter valid port numbers")
            self.scan_button.config(state=tk.NORMAL)
            self.status_var.set("Ready")
    
    def scan_ports(self, target, start_port, end_port):
        """Perform the actual port scanning."""
        try:
            for port in range(start_port, end_port + 1):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    
                    if result == 0:
                        try:
                            service = socket.getservbyport(port)
                        except:
                            service = "Unknown"
                        
                        # Update UI in the main thread
                        self.after(0, self.add_result, port, "Open", service)
                    
                    sock.close()
                    
                except:
                    continue
            
            # Re-enable scan button and update status
            self.after(0, self.scan_complete)
            
        except Exception as e:
            self.after(0, self.scan_error, str(e))
    
    def add_result(self, port, status, service):
        """Add a result to the Treeview."""
        self.results_tree.insert("", "end", values=(port, status, service))
        self.results_tree.yview_moveto(1)
    
    def scan_complete(self):
        """Handle scan completion."""
        self.scan_button.config(state=tk.NORMAL)
        self.status_var.set("Scan complete")
    
    def scan_error(self, error_message):
        """Handle scan errors."""
        self.scan_button.config(state=tk.NORMAL)
        self.status_var.set("Scan failed")
        messagebox.showerror("Error", error_message)

if __name__ == "__main__":
    run_gui()
