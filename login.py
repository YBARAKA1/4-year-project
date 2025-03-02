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
from constants import MATRIX_BG, MATRIX_GREEN, DARK_GREEN, ACCENT_GREEN, BUTTON_BG, BUTTON_FG  # Import theme colors

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

# Email configuration
EMAIL_HOST = os.getenv("EMAIL_HOST")
EMAIL_PORT = int(os.getenv("EMAIL_PORT"))
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# Generate OTP
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

# Send OTP via email
def send_otp_email(email, otp):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_USER
        msg['To'] = email
        msg['Subject'] = "Your One-Time Password (OTP)"
        body = f"Your OTP is: {otp}"
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_USER, email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

# Login Window
class LoginWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("Login")
        self.geometry("500x500")
        self.configure(bg=MATRIX_BG)  # Set background color

        # Configure styles
        label_style = {"bg": MATRIX_BG, "fg": MATRIX_GREEN, "font": ("Consolas", 10)}
        entry_style = {"bg": DARK_GREEN, "fg": MATRIX_GREEN, "font": ("Consolas", 10), "insertbackground": MATRIX_GREEN}
        button_style = {"bg": BUTTON_BG, "fg": BUTTON_FG, "font": ("Consolas", 10, "bold"), "relief": "flat"}

        # Email Label and Entry
        tk.Label(self, text="Email:", **label_style).pack(pady=5)
        self.email_entry = tk.Entry(self, **entry_style)
        self.email_entry.pack(pady=5)

        # OTP Label and Entry (initially hidden)
        self.otp_label = tk.Label(self, text="OTP:", **label_style)
        self.otp_entry = tk.Entry(self, **entry_style)

        # Login Button
        self.login_button = tk.Button(self, text="Next", command=self.check_email, **button_style)
        self.login_button.pack(pady=10)

        # Sign Up Button
        self.signup_button = tk.Button(self, text="Sign Up", command=self.open_signup, **button_style)
        self.signup_button.pack(pady=10)

        # Add hover effects
        self.login_button.bind("<Enter>", lambda e: self.login_button.config(bg=ACCENT_GREEN, fg=MATRIX_BG))
        self.login_button.bind("<Leave>", lambda e: self.login_button.config(bg=BUTTON_BG, fg=BUTTON_FG))
        self.signup_button.bind("<Enter>", lambda e: self.signup_button.config(bg=ACCENT_GREEN, fg=MATRIX_BG))
        self.signup_button.bind("<Leave>", lambda e: self.signup_button.config(bg=BUTTON_BG, fg=BUTTON_FG))

    def check_email(self):
        email = self.email_entry.get()

        if not email:
            messagebox.showerror("Error", "Please enter your email.")
            return

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT status FROM users WHERE email = %s", (email,))
        result = cur.fetchone()

        if not result:
            messagebox.showerror("Error", "Email not found. Please sign up or use correct details.")
            return

        status = result[0]
        if status != 'approved':
            messagebox.showinfo("Pending Approval", "Your account is still pending approval. Please wait for admin approval.")
            return

        # If approved, show OTP fields
        self.otp_label.pack(pady=5)
        self.otp_entry.pack(pady=5)
        self.login_button.config(text="Login", command=self.login)

        # Send OTP
        self.otp = generate_otp()
        if not send_otp_email(email, self.otp):
            messagebox.showerror("Error", "Failed to send OTP. Please try again.")

    def login(self):
        email = self.email_entry.get()
        otp = self.otp_entry.get()

        if not email or not otp:
            messagebox.showerror("Error", "Please enter both email and OTP.")
            return

        if otp != self.otp:
            messagebox.showerror("Error", "Invalid OTP.")
            return

        messagebox.showinfo("Success", "Logged in successfully!")
        self.parent.logged_in = True  # Update login status
        self.destroy()

    def open_signup(self):
        SignUpWindow(self)

# Sign-Up Window
class SignUpWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Sign Up")
        self.geometry("400x300")
        self.configure(bg=MATRIX_BG)  # Set background color

        # Configure styles
        label_style = {"bg": MATRIX_BG, "fg": MATRIX_GREEN, "font": ("Consolas", 10)}
        entry_style = {"bg": DARK_GREEN, "fg": MATRIX_GREEN, "font": ("Consolas", 10), "insertbackground": MATRIX_GREEN}
        button_style = {"bg": BUTTON_BG, "fg": BUTTON_FG, "font": ("Consolas", 10, "bold"), "relief": "flat"}

        # First Name Label and Entry
        tk.Label(self, text="First Name:", **label_style).pack(pady=5)
        self.first_name_entry = tk.Entry(self, **entry_style)
        self.first_name_entry.pack(pady=5)

        # Last Name Label and Entry
        tk.Label(self, text="Last Name:", **label_style).pack(pady=5)
        self.last_name_entry = tk.Entry(self, **entry_style)
        self.last_name_entry.pack(pady=5)

        # Email Label and Entry
        tk.Label(self, text="Email:", **label_style).pack(pady=5)
        self.email_entry = tk.Entry(self, **entry_style)
        self.email_entry.pack(pady=5)

        # Date of Birth Label and Entry
        tk.Label(self, text="Date of Birth (YYYY-MM-DD):", **label_style).pack(pady=5)
        self.dob_entry = tk.Entry(self, **entry_style)
        self.dob_entry.pack(pady=5)

        # Purpose Label and Entry
        tk.Label(self, text="Purpose of Using IDS:", **label_style).pack(pady=5)
        self.purpose_entry = tk.Entry(self, **entry_style)
        self.purpose_entry.pack(pady=5)

        # Sign Up Button
        self.signup_button = tk.Button(self, text="Sign Up", command=self.signup, **button_style)
        self.signup_button.pack(pady=10)

    
    def signup(self):
        first_name = self.first_name_entry.get()
        last_name = self.last_name_entry.get()
        email = self.email_entry.get()
        dob = self.dob_entry.get()
        purpose = self.purpose_entry.get()

        if not all([first_name, last_name, email, dob, purpose]):
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO users (first_name, last_name, email, dob, purpose, status) VALUES (%s, %s, %s, %s, %s, 'pending')",
                (first_name, last_name, email, dob, purpose)
            )
            conn.commit()

            # Notify admin
            admin_email = "admin@example.com"
            subject = "New User Sign-Up"
            body = f"New user: {first_name} {last_name}\nEmail: {email}\nPurpose: {purpose}"
            send_otp_email(admin_email, body)

            messagebox.showinfo("Success", "Sign-up successful! Please wait for admin approval.")
            self.destroy()
        except psycopg2.IntegrityError:
            messagebox.showerror("Error", "Email already exists.")
        finally:
            cur.close()
            conn.close()