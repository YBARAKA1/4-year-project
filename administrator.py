import tkinter as tk
from tkinter import messagebox
import psycopg2
from constants import MATRIX_BG, MATRIX_GREEN, DARK_GREEN, ACCENT_GREEN, BUTTON_BG, BUTTON_FG, RED, GREEN

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
        self.title("Admin Dashboard")
        self.geometry("1000x600")
        self.configure(bg=MATRIX_BG)  # Matrix background

        # Configure styles
        label_style = {"bg": MATRIX_BG, "fg": MATRIX_GREEN, "font": ("Consolas", 12)}
        button_style = {"bg": BUTTON_BG, "fg": BUTTON_FG, "font": ("Consolas", 10, "bold"), "relief": "flat"}
        listbox_style = {"bg": DARK_GREEN, "fg": MATRIX_GREEN, "font": ("Consolas", 10), "selectbackground": ACCENT_GREEN}

        # Title Label
        tk.Label(self, text="Admin Dashboard - Pending Sign-Ups", **label_style).pack(pady=10)

        # Listbox to display pending sign-ups
        self.pending_listbox = tk.Listbox(self, width=120, height=20, **listbox_style)
        self.pending_listbox.pack(pady=10, padx=10)

        # Buttons for approval/rejection
        button_frame = tk.Frame(self, bg=MATRIX_BG)
        button_frame.pack(pady=10)

        self.approve_button = tk.Button(button_frame, text="Approve", command=self.approve_user, **button_style)
        self.approve_button.pack(side=tk.LEFT, padx=10)

        self.reject_button = tk.Button(button_frame, text="Reject", command=self.reject_user, **button_style)
        self.reject_button.pack(side=tk.LEFT, padx=10)

        # Refresh Button
        self.refresh_button = tk.Button(button_frame, text="Refresh", command=self.load_pending_signups, **button_style)
        self.refresh_button.pack(side=tk.LEFT, padx=10)

        # Load pending sign-ups
        self.load_pending_signups()

    def load_pending_signups(self):
        """Load pending sign-ups from the database into the listbox."""
        self.pending_listbox.delete(0, tk.END)  # Clear existing items
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT id, first_name, last_name, email, purpose FROM users WHERE status = 'pending'")
            pending_users = cur.fetchall()

            if not pending_users:
                self.pending_listbox.insert(tk.END, "No pending sign-ups found.")
                return

            for user in pending_users:
                user_id, first_name, last_name, email, purpose = user
                display_text = f"ID: {user_id} | Name: {first_name} {last_name} | Email: {email} | Purpose: {purpose}"
                self.pending_listbox.insert(tk.END, display_text)

        except Exception as e:
            print(f"[ERROR] Failed to load pending sign-ups: {e}")
            self.pending_listbox.insert(tk.END, "Error loading pending sign-ups.")
        finally:
            cur.close()
            conn.close()

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
            cur.execute("UPDATE users SET status = 'approved' WHERE id = %s", (user_id,))
            conn.commit()
            print(f"[DEBUG] Approved user with ID: {user_id}")
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
            cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
            conn.commit()
            print(f"[DEBUG] Rejected user with ID: {user_id}")
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

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        # Hardcoded admin credentials (replace with secure authentication)
        if username == "admin" and password == "admin123":
            self.destroy()
            AdminDashboard(self.parent)  # Open the admin dashboard
        else:
            messagebox.showerror("Error", "Invalid username or password.", parent=self)