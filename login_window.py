# login_window.py
import tkinter as tk
from tkinter import messagebox
import psycopg2
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import string
from dotenv import load_dotenv
import os
import threading
from constants import MATRIX_BG, MATRIX_GREEN, DARK_GREEN, ACCENT_GREEN, BUTTON_BG, BUTTON_FG
from login import EMAIL_HOST, EMAIL_PASSWORD, EMAIL_PORT, EMAIL_USER, SignUpWindow

# Load environment variables
load_dotenv()

# Database connection
def get_db_connection():
    return psycopg2.connect(
        dbname="ids_db",
        user="postgres",
        password="1221",
        host="localhost",
        port="5432"
    )

# Generate alphanumeric token
def generate_token():
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choices(chars, k=8))

# Send email in background to prevent GUI freezing
def send_email_async(to_email, subject, body):
    def send_task():
        print(f"[DEBUG] Starting email send to {to_email}")
        try:
            msg = MIMEMultipart()
            msg['From'] = EMAIL_USER
            msg['To'] = to_email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))

            server = smtplib.SMTP_SSL(EMAIL_HOST, EMAIL_PORT)
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_USER, to_email, msg.as_string())
            server.quit()
            print(f"[DEBUG] Email sent successfully to {to_email}")
        except Exception as e:
            print(f"[ERROR] Failed to send email to {to_email}: {e}")

    threading.Thread(target=send_task, daemon=True).start()

# Login Window
class LoginWindow(tk.Toplevel):
    def __init__(self, parent, on_login_success):
        super().__init__(parent)
        self.parent = parent
        self.on_login_success = on_login_success
        self.title("Login")
        self.geometry("400x500")
        self.configure(bg=MATRIX_BG)
        self.logged_in = False
        self.role = None
        self.first_name = None
        
        # Make window resizable
        self.resizable(False, False)
        
        # Center the window
        self.center_window()
        
        # Configure styles
        title_style = {"bg": MATRIX_BG, "fg": MATRIX_GREEN, "font": ("Consolas", 16, "bold")}
        label_style = {"bg": MATRIX_BG, "fg": MATRIX_GREEN, "font": ("Consolas", 12)}
        entry_style = {"bg": DARK_GREEN, "fg": MATRIX_GREEN, "font": ("Consolas", 12), "insertbackground": MATRIX_GREEN}
        button_style = {"bg": BUTTON_BG, "fg": BUTTON_FG, "font": ("Consolas", 12, "bold"), "relief": "flat", "width": 20}

        # Create main frame with padding
        self.main_frame = tk.Frame(self, bg=MATRIX_BG, padx=40, pady=40)
        self.main_frame.pack(expand=True, fill="both")

        # Title
        self.title_label = tk.Label(self.main_frame, text="Welcome Back", **title_style)
        self.title_label.pack(pady=(0, 30))

        # Email Frame
        self.email_frame = tk.Frame(self.main_frame, bg=MATRIX_BG)
        self.email_frame.pack(fill="x", pady=10)
        
        # Email Label and Entry
        self.email_label = tk.Label(self.email_frame, text="Email:", **label_style)
        self.email_label.pack(anchor="w")
        self.email_entry = tk.Entry(self.email_frame, **entry_style)
        self.email_entry.pack(fill="x", pady=(5, 0))

        # Token Frame (initially hidden)
        self.token_frame = tk.Frame(self.main_frame, bg=MATRIX_BG)
        self.token_label = tk.Label(self.token_frame, text="Token:", **label_style)
        self.token_entry = tk.Entry(self.token_frame, **entry_style)
        
        # Pack token widgets (but keep frame hidden initially)
        self.token_label.pack(anchor="w")
        self.token_entry.pack(fill="x", pady=(5, 0))
        self.token_frame.pack_forget()  # Hide the token frame initially

        # Buttons Frame
        self.buttons_frame = tk.Frame(self.main_frame, bg=MATRIX_BG)
        self.buttons_frame.pack(pady=30)

        # Login Button
        self.login_button = tk.Button(self.buttons_frame, text="Next", command=self.check_email, **button_style)
        self.login_button.pack(pady=5)

        # Sign Up Button
        self.signup_button = tk.Button(self.buttons_frame, text="Sign Up", command=self.open_signup, **button_style)
        self.signup_button.pack(pady=5)

        # Add hover effects
        self.login_button.bind("<Enter>", lambda e: self.login_button.config(bg=ACCENT_GREEN, fg=MATRIX_BG))
        self.login_button.bind("<Leave>", lambda e: self.login_button.config(bg=BUTTON_BG, fg=BUTTON_FG))
        self.signup_button.bind("<Enter>", lambda e: self.signup_button.config(bg=ACCENT_GREEN, fg=MATRIX_BG))
        self.signup_button.bind("<Leave>", lambda e: self.signup_button.config(bg=BUTTON_BG, fg=BUTTON_FG))

        # Make window modal
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def center_window(self):
        """Center the window on the screen."""
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')

    def login(self):
        email = self.email_entry.get()
        entered_token = self.token_entry.get()
        print(f"[DEBUG] Attempting login for {email} with token: {entered_token}")

        if not email or not entered_token:
            messagebox.showerror("Error", "Please enter both email and token.")
            return

        try:
            conn = get_db_connection()
            cur = conn.cursor()
            print("[DEBUG] Verifying token in database")

            # First check if the user exists and is approved
            cur.execute("SELECT status FROM users WHERE email = %s", (email,))
            status_result = cur.fetchone()
            
            if not status_result:
                print(f"[AUTH] Email not found: {email}")
                messagebox.showerror("Error", "Email not found. Please sign up or use correct details.")
                return

            if status_result[0] != 'approved':
                print(f"[AUTH] Account not approved: {email}")
                messagebox.showerror("Error", "Your account is not approved yet. Please wait for admin approval.")
                return

            # Now verify the token
            cur.execute("SELECT token, role, first_name FROM users WHERE email = %s", (email,))
            result = cur.fetchone()

            if not result:
                print(f"[AUTH] User details not found: {email}")
                messagebox.showerror("Error", "User details not found.")
                return

            stored_token = result[0]
            if not stored_token:
                print(f"[AUTH] No token found for user: {email}")
                messagebox.showerror("Error", "No token found. Please request a new token.")
                return

            if stored_token != entered_token:
                print(f"[AUTH] Invalid token for {email}. Expected: {stored_token}, Got: {entered_token}")
                messagebox.showerror("Error", "Invalid token. Please request a new token.")
                return

            print("[AUTH] Login successful")
            self.logged_in = True
            self.role = result[1]  # Set the role attribute
            self.first_name = result[2]  # Set the first name attribute

            # Call the callback function with the role and first name
            if self.on_login_success:
                self.on_login_success(self.role, self.first_name)
            
            self.destroy()  # Close the login window after callback

        except Exception as e:
            print(f"[ERROR] Login failed: {str(e)}")
            print(f"[ERROR] Error type: {type(e)}")
            import traceback
            print(f"[ERROR] Traceback: {traceback.format_exc()}")
            messagebox.showerror("Error", f"Login failed: {str(e)}")
        finally:
            try:
                cur.close()
                conn.close()
                print("[DEBUG] Database connection closed")
            except Exception as e:
                print(f"[ERROR] Error closing database connection: {e}")

    def check_email(self):
        email = self.email_entry.get()
        print(f"[DEBUG] Checking email: {email}")

        if not email:
            messagebox.showerror("Error", "Please enter your email.")
            return

        try:
            conn = get_db_connection()
            cur = conn.cursor()
            print("[DEBUG] Database connection established")

            # Check if user exists and is approved in the users table
            cur.execute("SELECT status FROM users WHERE email = %s", (email,))
            result = cur.fetchone()

            if not result:
                messagebox.showerror("Error", "Email not found. Please sign up or use correct details.")
                return

            status = result[0]
            if status != 'approved':
                messagebox.showinfo("Pending Approval", "Your account is still pending approval. Please wait for admin approval.")
                return

            # Generate and store token
            token = generate_token()
            print(f"[DEBUG] Generated token: {token}")
            cur.execute("UPDATE users SET token = %s, token_created_at = NOW() WHERE email = %s",
                        (token, email))
            conn.commit()
            print("[DEBUG] Token stored in database")

            # Show token fields
            self.token_frame.pack(fill="x", pady=10, before=self.buttons_frame)
            self.login_button.config(text="Login", command=self.login)

            # Send token via email in background
            send_email_async(email, "Your Login Token", f"Your token is: {token}")

        except Exception as e:
            print(f"[ERROR] Database error: {str(e)}")
            messagebox.showerror("Error", "Database operation failed")
        finally:
            cur.close()
            conn.close()
            print("[DEBUG] Database connection closed")
    
    def on_close(self):
        """Handle the window close event."""
        self.destroy()

    def open_signup(self):
        self.withdraw()
        SignUpWindow(self)