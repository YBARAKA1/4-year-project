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
        self.on_login_success = on_login_success  # Callback function for successful login
        self.title("Login")
        self.geometry("300x300")
        self.configure(bg=MATRIX_BG)
        self.logged_in = False
        self.role = None

        # Configure styles
        label_style = {"bg": MATRIX_BG, "fg": MATRIX_GREEN, "font": ("Consolas", 10)}
        entry_style = {"bg": DARK_GREEN, "fg": MATRIX_GREEN, "font": ("Consolas", 10), "insertbackground": MATRIX_GREEN}
        button_style = {"bg": BUTTON_BG, "fg": BUTTON_FG, "font": ("Consolas", 10, "bold"), "relief": "flat"}

        # Email Label and Entry
        tk.Label(self, text="Email:", **label_style).pack(pady=5)
        self.email_entry = tk.Entry(self, **entry_style)
        self.email_entry.pack(pady=5)

        # Token Label and Entry (initially hidden)
        self.token_label = tk.Label(self, text="Token:", **label_style)
        self.token_entry = tk.Entry(self, **entry_style)

        # Login Button
        self.login_button = tk.Button(self, text="Next", command=self.check_email, **button_style)
        self.login_button.pack(pady=10)

        # Sign Up Button
        self.signup_button = tk.Button(self, text="Sign Up", command=self.open_signup, **button_style)
        self.signup_button.pack(pady=10)

        # Pack token fields after email entry (but keep them hidden initially)
        self.token_label.pack_forget()
        self.token_entry.pack_forget()

        # Add hover effects
        self.login_button.bind("<Enter>", lambda e: self.login_button.config(bg=ACCENT_GREEN, fg=MATRIX_BG))
        self.login_button.bind("<Leave>", lambda e: self.login_button.config(bg=BUTTON_BG, fg=BUTTON_FG))
        self.signup_button.bind("<Enter>", lambda e: self.signup_button.config(bg=ACCENT_GREEN, fg=MATRIX_BG))
        self.signup_button.bind("<Leave>", lambda e: self.signup_button.config(bg=BUTTON_BG, fg=BUTTON_FG))

        print("[DEBUG] LoginWindow initialized")

    def login(self):
        email = self.email_entry.get()
        entered_token = self.token_entry.get()
        print(f"[DEBUG] Attempting login for {email} with token: {entered_token}")

        if not email or not entered_token:
            messagebox.showerror("Error", "Please enter both email and token.")
            self.grab_set()
            return

        try:
            conn = get_db_connection()
            cur = conn.cursor()
            print("[DEBUG] Verifying token in database")

            # Fetch user details including role
            cur.execute("SELECT token, role FROM users WHERE email = %s", (email,))
            result = cur.fetchone()

            if not result or result[0] != entered_token:
                print(f"[AUTH] Invalid token for {email}")
                messagebox.showerror("Error", "Invalid token.")
                self.grab_set()
                return

            print("[AUTH] Login successful")
            self.logged_in = True
            self.role = result[1]  # Set the role attribute
            self.destroy()  # Close the login window

            # Call the callback function with the role
            if self.on_login_success:
                self.on_login_success(self.role)

        except Exception as e:
            print(f"[ERROR] Login failed: {str(e)}")
            messagebox.showerror("Error", "Login failed")
            self.grab_set()
        finally:
            cur.close()
            conn.close()
            print("[DEBUG] Database connection closed")

    def check_email(self):
        email = self.email_entry.get()
        print(f"[DEBUG] Checking email: {email}")

        if not email:
            messagebox.showerror("Error", "Please enter your email.")
            self.grab_set()
            return

        try:
            conn = get_db_connection()
            cur = conn.cursor()
            print("[DEBUG] Database connection established")

            # Check if user exists and is approved in the users table
            cur.execute("SELECT status FROM users WHERE email = %s", (email,))
            result = cur.fetchone()

            if not result:
                messagebox.showerror("Error", "My guy, you know i know that this isn't right. Email not found. Please sign up or use correct details.")
                self.grab_set()
                return

            status = result[0]
            if status != 'approved':
                messagebox.showinfo("Pending Approval", "Relax my G, Your account is still pending approval. Please wait for admin approval.")
                self.grab_set()
                return

            # Generate and store token
            token = generate_token()
            print(f"[DEBUG] Generated token: {token}")
            cur.execute("UPDATE users SET token = %s, token_created_at = NOW() WHERE email = %s",
                        (token, email))
            conn.commit()
            print("[DEBUG] Token stored in database")

            # Show token fields below the email entry and above the "Next" button
            self.token_label.pack(pady=5, before=self.login_button)
            self.token_entry.pack(pady=5, before=self.login_button)
            self.login_button.config(text="Login", command=self.login)

            # Send token via email in background
            send_email_async(email, "Your Login Token", f"Yooo, My guy your token is: {token}")

        except Exception as e:
            print(f"[ERROR] Database error: {str(e)}")
            messagebox.showerror("Error", "Database operation failed")
            self.grab_set()
        finally:
            cur.close()
            conn.close()
            print("[DEBUG] Database connection closed")

    def open_signup(self):
        self.withdraw()
        SignUpWindow(self)