import tkinter as tk
from tkinter import messagebox
import psycopg2
from constants import MATRIX_BG, MATRIX_GREEN, DARK_GREEN, ACCENT_GREEN, BUTTON_BG, BUTTON_FG, RED, GREEN
from login_window import LoginWindow, send_email_async 
# Database connection
def get_db_connection():
    return psycopg2.connect(
        dbname="ids_db",
        user="postgres",
        password="1221",
        host="localhost",
        port="5432"
    )

# Admin Dashboard with Matrix Theme
class AdminDashboard(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.configure(bg=MATRIX_BG)

        # Configure styles
        label_style = {"bg": MATRIX_BG, "fg": MATRIX_GREEN, "font": ("Consolas", 12)}
        button_style = {"bg": BUTTON_BG, "fg": BUTTON_FG, "font": ("Consolas", 10, "bold"), "relief": "flat"}
        listbox_style = {"bg": DARK_GREEN, "fg": MATRIX_GREEN, "font": ("Consolas", 10), "selectbackground": ACCENT_GREEN}
        entry_style = {"bg": DARK_GREEN, "fg": MATRIX_GREEN, "font": ("Consolas", 10), "insertbackground": MATRIX_GREEN}

        # Main container with padding
        main_container = tk.Frame(self, bg=MATRIX_BG)
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Title and Search Frame
        title_frame = tk.Frame(main_container, bg=MATRIX_BG)
        title_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(title_frame, text="Admin Dashboard - User Management", **label_style).pack(side=tk.LEFT)

        # Search Frame
        search_frame = tk.Frame(main_container, bg=MATRIX_BG)
        search_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(search_frame, text="Search:", **label_style).pack(side=tk.LEFT, padx=(0, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.apply_filters)
        self.search_entry = tk.Entry(search_frame, textvariable=self.search_var, width=30, **entry_style)
        self.search_entry.pack(side=tk.LEFT, padx=5)

        # Filters Frame
        filters_frame = tk.Frame(main_container, bg=MATRIX_BG)
        filters_frame.pack(fill=tk.X, pady=(0, 10))

        # Status Filter
        status_frame = tk.Frame(filters_frame, bg=MATRIX_BG)
        status_frame.pack(side=tk.LEFT, padx=5)
        tk.Label(status_frame, text="Status:", **label_style).pack(side=tk.LEFT)
        self.status_var = tk.StringVar(value="All")
        self.status_var.trace('w', self.apply_filters)
        statuses = ["All", "Pending", "Approved", "Rejected"]
        self.status_menu = tk.OptionMenu(status_frame, self.status_var, *statuses)
        self.status_menu.config(bg=DARK_GREEN, fg=MATRIX_GREEN, font=("Consolas", 10))
        self.status_menu.pack(side=tk.LEFT, padx=5)

        # Purpose Filter
        purpose_frame = tk.Frame(filters_frame, bg=MATRIX_BG)
        purpose_frame.pack(side=tk.LEFT, padx=5)
        tk.Label(purpose_frame, text="Purpose:", **label_style).pack(side=tk.LEFT)
        self.purpose_var = tk.StringVar(value="All")
        self.purpose_var.trace('w', self.apply_filters)
        self.purpose_menu = tk.OptionMenu(purpose_frame, self.purpose_var, "All")  # Will be populated dynamically
        self.purpose_menu.config(bg=DARK_GREEN, fg=MATRIX_GREEN, font=("Consolas", 10))
        self.purpose_menu.pack(side=tk.LEFT, padx=5)

        # Listbox with Scrollbar
        listbox_frame = tk.Frame(main_container, bg=MATRIX_BG)
        listbox_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        scrollbar = tk.Scrollbar(listbox_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.pending_listbox = tk.Listbox(listbox_frame, width=120, height=20, yscrollcommand=scrollbar.set, **listbox_style)
        self.pending_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar.config(command=self.pending_listbox.yview)

        # Buttons Frame
        button_frame = tk.Frame(main_container, bg=MATRIX_BG)
        button_frame.pack(fill=tk.X, pady=10)

        self.approve_button = tk.Button(button_frame, text="Approve", command=self.approve_user, **button_style)
        self.approve_button.pack(side=tk.LEFT, padx=5)

        self.reject_button = tk.Button(button_frame, text="Reject", command=self.reject_user, **button_style)
        self.reject_button.pack(side=tk.LEFT, padx=5)

        self.refresh_button = tk.Button(button_frame, text="Refresh", command=self.load_pending_signups, **button_style)
        self.refresh_button.pack(side=tk.LEFT, padx=5)

        # Add hover effects
        for button in [self.approve_button, self.reject_button, self.refresh_button]:
            button.bind("<Enter>", lambda e, b=button: b.config(bg=ACCENT_GREEN, fg=MATRIX_BG))
            button.bind("<Leave>", lambda e, b=button: b.config(bg=BUTTON_BG, fg=BUTTON_FG))

        # Load initial data
        self.load_pending_signups()

    def apply_filters(self, *args):
        """Apply filters to the listbox items."""
        search_term = self.search_var.get().lower()
        purpose_filter = self.purpose_var.get()
        status_filter = self.status_var.get()

        self.pending_listbox.delete(0, tk.END)
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            # Get unique purposes from all tables
            purpose_query = """
                SELECT DISTINCT purpose FROM pending
                UNION
                SELECT DISTINCT purpose FROM rejected
                UNION
                SELECT DISTINCT purpose FROM users
                ORDER BY purpose
            """
            cur.execute(purpose_query)
            purposes = ["All"] + [row[0] for row in cur.fetchall()]

            # Update purpose dropdown if needed
            if purposes != self.purpose_var.get():
                self.purpose_var.set("All")
                self.purpose_menu['menu'].delete(0, 'end')
                for purpose in purposes:
                    self.purpose_menu['menu'].add_command(label=purpose, command=lambda p=purpose: self.purpose_var.set(p))

            # Base query parts
            base_fields = "id, first_name, last_name, email, purpose"
            
            # Determine which table to query based on status
            if status_filter == "Pending":
                table = "pending"
                query = f"SELECT {base_fields} FROM {table} WHERE 1=1"
            elif status_filter == "Rejected":
                table = "rejected"
                query = f"SELECT {base_fields} FROM {table} WHERE 1=1"
            elif status_filter == "Approved":
                table = "users"
                query = f"SELECT {base_fields} FROM {table} WHERE status = 'approved'"
            else:  # "All" status
                # Union all tables
                query = f"""
                    SELECT {base_fields} FROM pending
                    UNION ALL
                    SELECT {base_fields} FROM rejected
                    UNION ALL
                    SELECT {base_fields} FROM users WHERE status = 'approved'
                """
                table = None

            params = []

            # Add search filter
            if search_term:
                if table:
                    query += " AND (LOWER(email) LIKE %s OR LOWER(first_name) LIKE %s OR LOWER(last_name) LIKE %s)"
                else:
                    query = f"""
                        SELECT * FROM (
                            {query}
                        ) AS combined_results 
                        WHERE LOWER(email) LIKE %s OR LOWER(first_name) LIKE %s OR LOWER(last_name) LIKE %s
                    """
                search_pattern = f"%{search_term}%"
                params.extend([search_pattern, search_pattern, search_pattern])

            # Add purpose filter
            if purpose_filter != "All":
                if table:
                    query += " AND purpose = %s"
                else:
                    query = f"""
                        SELECT * FROM (
                            {query}
                        ) AS combined_results 
                        WHERE purpose = %s
                    """
                params.append(purpose_filter)

            # Execute the main query
            cur.execute(query, params)
            filtered_users = cur.fetchall()

            if not filtered_users:
                self.pending_listbox.insert(tk.END, "No matching sign-ups found.")
                return

            # Display results with status indicator
            for user in filtered_users:
                user_id, first_name, last_name, email, purpose = user
                status_indicator = "✓" if status_filter == "Approved" else "✗" if status_filter == "Rejected" else "⏳"
                display_text = f"{status_indicator} ID: {user_id:4} | Name: {first_name:15} {last_name:15} | Email: {email:30} | Purpose: {purpose:10}"
                self.pending_listbox.insert(tk.END, display_text)

        except Exception as e:
            print(f"[ERROR] Failed to apply filters: {e}")
            self.pending_listbox.insert(tk.END, "Error applying filters.")
        finally:
            cur.close()
            conn.close()

    def load_pending_signups(self):
        """Load pending sign-ups from the pending table into the listbox."""
        self.apply_filters()  # This will handle the initial load with current filters

    def approve_user(self):
        """Approve the selected user."""
        selected = self.pending_listbox.curselection()
        if not selected:
            messagebox.showerror("Error", "Please select a user to approve.", parent=self)
            return

        selected_text = self.pending_listbox.get(selected)
        user_id = selected_text.split("|")[0].split(":")[1].strip()  # Extract user ID

        try:
            conn = get_db_connection()
            cur = conn.cursor()

            # Fetch user details from pending table
            cur.execute("SELECT * FROM pending WHERE id = %s", (user_id,))
            user = cur.fetchone()

            if not user:
                messagebox.showerror("Error", "User not found.", parent=self)
                return

            # Insert into users table
            cur.execute(
                "INSERT INTO users (first_name, last_name, email, dob, purpose, status) "
                "VALUES (%s, %s, %s, %s, %s, 'approved')",
                (user[1], user[2], user[3], user[4], user[5]))
            
            # Delete from pending table
            cur.execute("DELETE FROM pending WHERE id = %s", (user_id,))
            conn.commit()

            # Send approval email
            send_email_async(user[3], "Account Approved", "Your account has been approved. You can now log in.")

            messagebox.showinfo("Success", "User approved successfully!", parent=self)
            self.load_pending_signups()  # Refresh the list

        except Exception as e:
            print(f"[ERROR] Failed to approve user: {e}")
            messagebox.showerror("Error", "Failed to approve user.", parent=self)
        finally:
            cur.close()
            conn.close()

    def reject_user(self):
        """Reject the selected user."""
        selected = self.pending_listbox.curselection()
        if not selected:
            messagebox.showerror("Error", "Please select a user to reject.", parent=self)
            return

        selected_text = self.pending_listbox.get(selected)
        user_id = selected_text.split("|")[0].split(":")[1].strip()  # Extract user ID

        try:
            conn = get_db_connection()
            cur = conn.cursor()

            # Fetch user details from pending table
            cur.execute("SELECT * FROM pending WHERE id = %s", (user_id,))
            user = cur.fetchone()

            if not user:
                messagebox.showerror("Error", "User not found.", parent=self)
                return

            # Insert into rejected table
            cur.execute(
                "INSERT INTO rejected (first_name, last_name, email, dob, purpose, token) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (user[1], user[2], user[3], user[4], user[5], user[6]))
            
            # Delete from pending table
            cur.execute("DELETE FROM pending WHERE id = %s", (user_id,))
            conn.commit()

            # Send rejection email
            send_email_async(user[3], "Account Rejected", " Sorry bruhv, Your account has been rejected. Please contact support for more details. Naah we messing, don't call us.")

            messagebox.showinfo("Success", "User rejected successfully!", parent=self)
            self.load_pending_signups()  # Refresh the list

        except Exception as e:
            print(f"[ERROR] Failed to reject user: {e}")
            messagebox.showerror("Error", "Failed to reject user.", parent=self)
        finally:
            cur.close()
            conn.close()

# Admin Login Window with Matrix Theme
class AdminLoginWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("Admin Login")
        self.geometry("400x300")
        self.configure(bg=MATRIX_BG)

        # Configure styles
        label_style = {"bg": MATRIX_BG, "fg": MATRIX_GREEN, "font": ("Consolas", 12)}
        entry_style = {"bg": DARK_GREEN, "fg": MATRIX_GREEN, "font": ("Consolas", 12), "insertbackground": MATRIX_GREEN}
        button_style = {"bg": BUTTON_BG, "fg": BUTTON_FG, "font": ("Consolas", 12, "bold"), "relief": "flat"}

        # Username Label and Entry
        tk.Label(self, text="Username:", **label_style).pack(pady=10)
        self.username_entry = tk.Entry(self, **entry_style)
        self.username_entry.pack(pady=10)

        # Password Label and Entry
        tk.Label(self, text="Password:", **label_style).pack(pady=10)
        self.password_entry = tk.Entry(self, show="*", **entry_style)
        self.password_entry.pack(pady=10)

        # Login Button
        self.login_button = tk.Button(self, text="Login", command=self.login, **button_style)
        self.login_button.pack(pady=20)

        # Add hover effects
        self.login_button.bind("<Enter>", lambda e: self.login_button.config(bg=ACCENT_GREEN, fg=MATRIX_BG))
        self.login_button.bind("<Leave>", lambda e: self.login_button.config(bg=BUTTON_BG, fg=BUTTON_FG))

    def open_login(self):
        """Open the login window and handle login success."""
        login_window = LoginWindow(self.root)
        self.root.wait_window(login_window)  # Wait for the login window to close

        # Check if login was successful
        if login_window.logged_in:
            self.logged_in = True
            self.role = login_window.role  # Store the user's role
            self.login_button.config(text="Logout", command=self.logout)  # Change button to logout
            self.enable_sidebar_buttons()  # Enable all sidebar buttons
            messagebox.showinfo("Login Successful", "You have successfully logged in!")
        else:
            self.logged_in = False
            self.login_button.config(text="Login", command=self.open_login)  # Reset button to login
            self.disable_sidebar_buttons()  # Disable all sidebar buttons except Dashboard