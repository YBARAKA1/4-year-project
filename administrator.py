import tkinter as tk
from tkinter import ttk, messagebox
from constants import MATRIX_BG, MATRIX_GREEN, DARK_GREEN, ACCENT_GREEN

class AdministratorView(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.setup_ui()

    def setup_ui(self):
        # Configure the frame
        self.configure(style="Sidebar.TFrame")
        self.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = ttk.Label(
            self,
            text="ADMINISTRATOR PANEL",
            style="Header.TLabel",
            font=("Consolas", 16, "bold")
        )
        title_label.pack(pady=20)

        # Login Frame
        self.login_frame = ttk.Frame(self, style="Sidebar.TFrame")
        self.login_frame.pack(pady=20)

        # Username
        ttk.Label(self.login_frame, text="Username:", style="Sidebar.TLabel").grid(row=0, column=0, padx=10, pady=10)
        self.username_entry = ttk.Entry(self.login_frame, font=("Consolas", 12), width=20)
        self.username_entry.grid(row=0, column=1, padx=10, pady=10)

        # Password
        ttk.Label(self.login_frame, text="Password:", style="Sidebar.TLabel").grid(row=1, column=0, padx=10, pady=10)
        self.password_entry = ttk.Entry(self.login_frame, font=("Consolas", 12), width=20, show="*")
        self.password_entry.grid(row=1, column=1, padx=10, pady=10)

        # Login Button
        login_button = ttk.Button(
            self.login_frame,
            text="Login",
            style="Sidebar.TButton",
            command=self.authenticate_admin
        )
        login_button.grid(row=2, column=0, columnspan=2, pady=20)

        # Admin Controls Frame (hidden until login)
        self.admin_controls_frame = ttk.Frame(self, style="Sidebar.TFrame")

        # User Requests Table
        ttk.Label(self.admin_controls_frame, text="User Access Requests", style="Header.TLabel").pack(pady=10)
        self.requests_tree = ttk.Treeview(
            self.admin_controls_frame,
            columns=("Username", "Request", "Status"),
            show="headings",
            height=10
        )
        self.requests_tree.heading("Username", text="Username")
        self.requests_tree.heading("Request", text="Request")
        self.requests_tree.heading("Status", text="Status")
        self.requests_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Approve/Deny Buttons
        button_frame = ttk.Frame(self.admin_controls_frame, style="Sidebar.TFrame")
        button_frame.pack(pady=10)

        approve_button = ttk.Button(
            button_frame,
            text="Approve",
            style="Sidebar.TButton",
            command=self.approve_request
        )
        approve_button.pack(side=tk.LEFT, padx=10)

        deny_button = ttk.Button(
            button_frame,
            text="Deny",
            style="Sidebar.TButton",
            command=self.deny_request
        )
        deny_button.pack(side=tk.LEFT, padx=10)

    def authenticate_admin(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        # Placeholder authentication logic
        if username == "admin" and password == "admin123":
            self.login_frame.pack_forget()
            self.admin_controls_frame.pack(fill=tk.BOTH, expand=True)
            self.load_user_requests()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    def load_user_requests(self):
        # Placeholder data for user requests
        requests = [
            ("user1", "Access Threat Analysis", "Pending"),
            ("user2", "Access Packet Stream", "Pending"),
            ("user3", "Access Traffic Analysis", "Pending")
        ]

        # Clear existing data
        for row in self.requests_tree.get_children():
            self.requests_tree.delete(row)

        # Add new data
        for request in requests:
            self.requests_tree.insert("", tk.END, values=request)

    def approve_request(self):
        selected_item = self.requests_tree.selection()
        if selected_item:
            self.requests_tree.set(selected_item, "Status", "Approved")
            messagebox.showinfo("Approved", "Request has been approved.")
        else:
            messagebox.showwarning("No Selection", "Please select a request to approve.")

    def deny_request(self):
        selected_item = self.requests_tree.selection()
        if selected_item:
            self.requests_tree.set(selected_item, "Status", "Denied")
            messagebox.showinfo("Denied", "Request has been denied.")
        else:
            messagebox.showwarning("No Selection", "Please select a request to deny.")
            
