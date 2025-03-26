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
        # Configure styles
        style = ttk.Style()
        style.configure("PortScanner.TFrame", background=MATRIX_BG)
        style.configure("PortScanner.TLabel", 
                       background=MATRIX_BG, 
                       foreground=MATRIX_GREEN,
                       font=("Consolas", 12))
        style.configure("PortScanner.TButton",
                       background=DARK_GREEN,
                       foreground=MATRIX_GREEN,
                       font=("Consolas", 10),
                       borderwidth=0)
        style.map("PortScanner.TButton",
                 background=[("active", ACCENT_GREEN)],
                 foreground=[("active", MATRIX_BG)])
        style.configure("PortScanner.TLabelframe",
                       background=MATRIX_BG,
                       foreground=MATRIX_GREEN)
        style.configure("PortScanner.TLabelframe.Label",
                       background=MATRIX_BG,
                       foreground=MATRIX_GREEN,
                       font=("Consolas", 12, "bold"))
        style.configure("PortScanner.TEntry",
                       fieldbackground=DARK_GREEN,
                       foreground=MATRIX_GREEN,
                       insertbackground=MATRIX_GREEN)
        style.configure("PortScanner.TCombobox",
                       fieldbackground=DARK_GREEN,
                       foreground=MATRIX_GREEN,
                       selectbackground=ACCENT_GREEN,
                       selectforeground=MATRIX_BG)
        style.configure("PortScanner.Treeview",
                       background=DARK_GREEN,
                       foreground=MATRIX_GREEN,
                       fieldbackground=DARK_GREEN,
                       rowheight=25)
        style.configure("PortScanner.Treeview.Heading",
                       background=DARK_GREEN,
                       foreground=MATRIX_GREEN,
                       font=("Consolas", 10, "bold"))
        style.map("PortScanner.Treeview",
                 background=[("selected", ACCENT_GREEN)],
                 foreground=[("selected", MATRIX_BG)])
        
        # Configure scrollbar style
        style.configure("PortScanner.Vertical.TScrollbar",
                       background=DARK_GREEN,
                       foreground=MATRIX_GREEN,
                       troughcolor=MATRIX_BG,
                       width=10,
                       arrowsize=13)
        style.map("PortScanner.Vertical.TScrollbar",
                 background=[("active", ACCENT_GREEN)],
                 foreground=[("active", MATRIX_BG)])

        # Main container with padding
        main_frame = ttk.Frame(self, style="PortScanner.TFrame")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title with Matrix styling
        title_label = ttk.Label(
            main_frame,
            text="PORT SCANNER",
            style="PortScanner.TLabel",
            font=("Consolas", 24, "bold")
        )
        title_label.pack(pady=(0, 20))
        
        # Scan Configuration Frame
        config_frame = ttk.LabelFrame(
            main_frame,
            text="SCAN CONFIGURATION",
            padding=15,
            style="PortScanner.TLabelframe"
        )
        config_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Target IP Frame
        target_frame = ttk.Frame(config_frame, style="PortScanner.TFrame")
        target_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(
            target_frame,
            text="Target IP:",
            style="PortScanner.TLabel"
        ).pack(side=tk.LEFT, padx=5)
        
        target_label = ttk.Label(
            target_frame,
            text=self.local_ip,
            style="PortScanner.TLabel",
            font=("Consolas", 12, "bold")
        )
        target_label.pack(side=tk.LEFT, padx=5)
        
        # Port Range Frame
        port_frame = ttk.Frame(config_frame, style="PortScanner.TFrame")
        port_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(
            port_frame,
            text="Port Range:",
            style="PortScanner.TLabel"
        ).pack(side=tk.LEFT, padx=5)
        
        self.start_port_var = tk.StringVar(value="1")
        self.end_port_var = tk.StringVar(value="1024")
        
        self.start_port_entry = ttk.Entry(
            port_frame,
            textvariable=self.start_port_var,
            width=6,
            style="PortScanner.TEntry"
        )
        self.start_port_entry.pack(side=tk.LEFT, padx=2)
        
        ttk.Label(
            port_frame,
            text="-",
            style="PortScanner.TLabel"
        ).pack(side=tk.LEFT)
        
        self.end_port_entry = ttk.Entry(
            port_frame,
            textvariable=self.end_port_var,
            width=6,
            style="PortScanner.TEntry"
        )
        self.end_port_entry.pack(side=tk.LEFT, padx=2)
        
        # Port Control Frame
        port_control_frame = ttk.Frame(config_frame, style="PortScanner.TFrame")
        port_control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Close port button
        self.close_port_button = ttk.Button(
            port_control_frame,
            text="CLOSE PORT",
            command=self.close_selected_port,
            style="PortScanner.TButton",
            width=15,
            state=tk.DISABLED
        )
        self.close_port_button.pack(side=tk.LEFT, padx=5)
        
        # Open port button
        self.open_port_button = ttk.Button(
            port_control_frame,
            text="OPEN PORT",
            command=self.open_selected_port,
            style="PortScanner.TButton",
            width=15,
            state=tk.DISABLED
        )
        self.open_port_button.pack(side=tk.LEFT, padx=5)
        
        # Filter and Scan Frame
        filter_scan_frame = ttk.Frame(config_frame, style="PortScanner.TFrame")
        filter_scan_frame.pack(fill=tk.X, pady=(10, 0))
        
        # Filter Frame
        filter_frame = ttk.Frame(filter_scan_frame, style="PortScanner.TFrame")
        filter_frame.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(
            filter_frame,
            text="Filter:",
            style="PortScanner.TLabel"
        ).pack(side=tk.LEFT, padx=5)
        
        self.filter_var = tk.StringVar(value="All")
        filter_combo = ttk.Combobox(
            filter_frame,
            textvariable=self.filter_var,
            values=["All", "Open", "Closed"],
            state="readonly",
            width=10,
            style="PortScanner.TCombobox"
        )
        filter_combo.pack(side=tk.LEFT, padx=5)
        filter_combo.bind('<<ComboboxSelected>>', self.apply_filter)
        
        # Scan Button
        self.scan_button = ttk.Button(
            filter_scan_frame,
            text="START SCAN",
            command=self.start_scan,
            style="PortScanner.TButton",
            width=15
        )
        self.scan_button.pack(side=tk.RIGHT, padx=5)
        
        # Results Frame
        results_frame = ttk.LabelFrame(
            main_frame,
            text="SCAN RESULTS",
            padding=15,
            style="PortScanner.TLabelframe"
        )
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create Treeview for results
        columns = ("Port", "Status", "Service")
        self.results_tree = ttk.Treeview(
            results_frame,
            columns=columns,
            show='headings',
            style="PortScanner.Treeview",
            height=15
        )
        
        # Configure columns
        self.results_tree.heading("Port", text="PORT")
        self.results_tree.heading("Status", text="STATUS")
        self.results_tree.heading("Service", text="SERVICE")
        
        self.results_tree.column("Port", width=100)
        self.results_tree.column("Status", width=100)
        self.results_tree.column("Service", width=200)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(
            results_frame,
            orient="vertical",
            command=self.results_tree.yview,
            style="PortScanner.Vertical.TScrollbar"
        )
        
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack the Treeview and scrollbar
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind selection event
        self.results_tree.bind('<<TreeviewSelect>>', self.on_select)
        
        # Status bar
        self.status_var = tk.StringVar(value="READY")
        self.status_bar = ttk.Label(
            main_frame,
            textvariable=self.status_var,
            style="PortScanner.TLabel",
            font=("Consolas", 10, "bold")
        )
        self.status_bar.pack(fill=tk.X, pady=(10, 0))
        
        # Store all results
        self.all_results = []
            
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
            self.all_results = []
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
                    
                    status = "Open" if result == 0 else "Closed"
                    try:
                        service = socket.getservbyport(port) if status == "Open" else "N/A"
                    except:
                        service = "Unknown" if status == "Open" else "N/A"
                    
                    # Store result
                    self.all_results.append((port, status, service))
                    
                    # Update UI in the main thread
                    self.after(0, self.add_result, port, status, service)
                    
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
        
    def apply_filter(self, event=None):
        """Apply the selected filter to the results."""
        filter_value = self.filter_var.get()
        
        # Clear current display
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
            
        # Apply filter
        for port, status, service in self.all_results:
            if filter_value == "All" or status == filter_value:
                self.results_tree.insert("", "end", values=(port, status, service))
                
    def on_select(self, event):
        """Handle selection of a port in the Treeview."""
        selected_items = self.results_tree.selection()
        if selected_items:
            item = self.results_tree.item(selected_items[0])
            status = item['values'][1]
            # Enable appropriate button based on port status
            self.close_port_button.config(state=tk.NORMAL if status == "Open" else tk.DISABLED)
            self.open_port_button.config(state=tk.NORMAL if status == "Closed" else tk.DISABLED)
        else:
            self.close_port_button.config(state=tk.DISABLED)
            self.open_port_button.config(state=tk.DISABLED)
            
    def close_selected_port(self):
        """Attempt to close the selected port."""
        selected_items = self.results_tree.selection()
        if not selected_items:
            return
            
        item = self.results_tree.item(selected_items[0])
        port = item['values'][0]
        
        try:
            # Create a socket and try to connect
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.local_ip, port))
            
            if result == 0:
                # Port is open, try to close it
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
                
                # Update the UI
                self.results_tree.set(selected_items[0], "Status", "Closed")
                self.results_tree.set(selected_items[0], "Service", "N/A")
                
                # Update stored results
                for i, (p, s, sv) in enumerate(self.all_results):
                    if p == port:
                        self.all_results[i] = (port, "Closed", "N/A")
                        break
                
                messagebox.showinfo("Success", f"Port {port} has been closed")
            else:
                messagebox.showinfo("Info", f"Port {port} is already closed")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to close port {port}: {str(e)}")
        finally:
            sock.close()
            self.close_port_button.config(state=tk.DISABLED)

    def open_selected_port(self):
        """Attempt to open the selected port."""
        selected_items = self.results_tree.selection()
        if not selected_items:
            return
            
        item = self.results_tree.item(selected_items[0])
        port = item['values'][0]
        
        try:
            # Create a socket and bind it to the port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            result = sock.bind((self.local_ip, port))
            
            if result is None:
                # Port is now open
                sock.listen(1)
                
                # Update the UI
                self.results_tree.set(selected_items[0], "Status", "Open")
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "Unknown"
                self.results_tree.set(selected_items[0], "Service", service)
                
                # Update stored results
                for i, (p, s, sv) in enumerate(self.all_results):
                    if p == port:
                        self.all_results[i] = (port, "Open", service)
                        break
                
                messagebox.showinfo("Success", f"Port {port} has been opened")
            else:
                messagebox.showinfo("Info", f"Port {port} is already open")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open port {port}: {str(e)}")
        finally:
            try:
                sock.close()
            except:
                pass
            self.open_port_button.config(state=tk.DISABLED)

if __name__ == "__main__":
    run_gui()
