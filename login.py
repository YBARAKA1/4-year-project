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
import threading  # For background email sending
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

# Generate alphanumeric token
def generate_token():
    chars = string.ascii_uppercase + string.digits  # Combine letters and numbers
    return ''.join(random.choices(chars, k=8))  # 8-character token

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

            server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_USER, to_email, msg.as_string())
            server.quit()
            print(f"[DEBUG] Email sent successfully to {to_email}")
        except Exception as e:
            print(f"[ERROR] Failed to send email to {to_email}: {e}")

    # Run email sending in a separate thread
    threading.Thread(target=send_task, daemon=True).start()

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

        # Token Label and Entry (initially hidden)
        self.token_label = tk.Label(self, text="Token:", **label_style)
        self.token_entry = tk.Entry(self, **entry_style)

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

        print("[DEBUG] LoginWindow initialized")

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

            # Check if user exists and is approved
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
            self.token_label.pack(pady=5)
            self.token_entry.pack(pady=5)
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

            cur.execute("SELECT token FROM users WHERE email = %s", (email,))
            result = cur.fetchone()

            if not result or result[0] != entered_token:
                print(f"[AUTH] Invalid token for {email}")
                messagebox.showerror("Error", "Invalid token.")
                return

            print("[AUTH] Login successful")
            messagebox.showinfo("Success", "Logged in successfully!")
            self.parent.logged_in = True  # Update login status
            self.destroy()

        except Exception as e:
            print(f"[ERROR] Login failed: {str(e)}")
            messagebox.showerror("Error", "Login failed")
        finally:
            cur.close()
            conn.close()
            print("[DEBUG] Database connection closed")

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
        print(f"[DEBUG] Attempting signup for {email}")

        if not all([first_name, last_name, email, dob, purpose]):
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        try:
            conn = get_db_connection()
            cur = conn.cursor()
            print("[DEBUG] Starting database insert")

            # Generate initial token
            token = generate_token()
            print(f"[DEBUG] Generated signup token: {token}")

            cur.execute(
                "INSERT INTO users (first_name, last_name, email, dob, purpose, status, token) "
                "VALUES (%s, %s, %s, %s, %s, 'pending', %s)",
                (first_name, last_name, email, dob, purpose, token)
            )
            conn.commit()
            print("[DEBUG] User record created")

            # Send notifications
            admin_msg = f"New user: {first_name} {last_name}\nEmail: {email}\nToken: {token}"
            send_email_async("jeff@integral.co.ke", "New Signup Request", admin_msg)
            send_email_async(email, "Your Account Pending", "Your account is awaiting approval")

            print("[DEBUG] Signup process completed")
            messagebox.showinfo("Success", "Sign-up successful! Awaiting admin approval.")
            self.destroy()

        except psycopg2.IntegrityError:
            print("[ERROR] Duplicate email attempt")
            messagebox.showerror("Error", "Email already exists")
        except Exception as e:
            print(f"[ERROR] Signup failed: {str(e)}")
            messagebox.showerror("Error", "Signup failed")
        finally:
            cur.close()
            conn.close()
            print("[DEBUG] Database connection closed")

# Main Application
class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.logged_in = False
        self.title("IDS Login System")
        self.geometry("600x400")
        LoginWindow(self)

if __name__ == "__main__":
    app = Application()
    app.mainloop()