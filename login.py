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
from constants import MATRIX_BG, MATRIX_GREEN, DARK_GREEN, ACCENT_GREEN, BUTTON_BG, BUTTON_FG

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

            server = smtplib.SMTP_SSL(EMAIL_HOST, EMAIL_PORT)  # Use SMTP_SSL for port 465
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_USER, to_email, msg.as_string())
            server.quit()
            print(f"[DEBUG] Email sent successfully to {to_email}")
        except Exception as e:
            print(f"[ERROR] Failed to send email to {to_email}: {e}")

    threading.Thread(target=send_task, daemon=True).start()

# SignUp Window
class SignUpWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent  # Store the parent (LoginWindow) reference
        self.title("Sign Up")
        self.geometry("500x400")
        self.configure(bg=MATRIX_BG)  # Set background color

        # Configure styles
        label_style = {"bg": MATRIX_BG, "fg": MATRIX_GREEN, "font": ("Consolas", 10)}
        entry_style = {"bg": DARK_GREEN, "fg": MATRIX_GREEN, "font": ("Consolas", 10), "insertbackground": MATRIX_GREEN}
        button_style = {"bg": BUTTON_BG, "fg": BUTTON_FG, "font": ("Consolas", 10, "bold"), "relief": "flat"}

        # Back Button (top-left corner)
        self.back_button = tk.Button(self, text="← Back", command=self.go_back, **button_style)
        self.back_button.place(x=10, y=10)  # Position the button at the top-left

        # First Name Label and Entry
        tk.Label(self, text="First Name:", **label_style).pack(pady=5)
        self.first_name_entry = tk.Entry(self, **entry_style)
        self.first_name_entry.pack(pady=5)
        self.first_name_entry.bind("<FocusIn>", lambda e: self.reset_highlight(self.first_name_entry))

        # Last Name Label and Entry
        tk.Label(self, text="Last Name:", **label_style).pack(pady=5)
        self.last_name_entry = tk.Entry(self, **entry_style)
        self.last_name_entry.pack(pady=5)
        self.last_name_entry.bind("<FocusIn>", lambda e: self.reset_highlight(self.last_name_entry))

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

    def validate_name(self, name):
        """Check if the name contains only letters."""
        return name.isalpha()

    def highlight_error(self, entry_widget):
        """Highlight the entry widget with a red line to indicate an error."""
        entry_widget.config(highlightbackground="red", highlightcolor="red", highlightthickness=1)
        entry_widget.focus_set()  # Set focus to the incorrect field

    def reset_highlight(self, entry_widget):
        """Reset the highlight of the entry widget."""
        entry_widget.config(highlightbackground=DARK_GREEN, highlightcolor=DARK_GREEN, highlightthickness=1)

    def signup(self):
        first_name = self.first_name_entry.get()
        last_name = self.last_name_entry.get()
        email = self.email_entry.get()
        dob = self.dob_entry.get()
        purpose = self.purpose_entry.get()
        print(f"[DEBUG] Attempting signup for {email}")

        # Validate first name and last name
        if not self.validate_name(first_name):
            messagebox.showerror("Error", "First name should contain only letters.")
            self.highlight_error(self.first_name_entry)
            return

        if not self.validate_name(last_name):
            messagebox.showerror("Error", "Last name should contain only letters.")
            self.highlight_error(self.last_name_entry)
            return

        # Validate all fields are filled
        if not all([first_name, last_name, email, dob, purpose]):
            messagebox.showerror("Error", "Please fill in all fields.")
            return  # Exit the method without closing the window

        try:
            conn = get_db_connection()
            cur = conn.cursor()
            print("[DEBUG] Starting database insert")

            # Generate initial token
            token = generate_token()
            print(f"[DEBUG] Generated signup token: {token}")

            # Insert into the pending table
            cur.execute(
                "INSERT INTO pending (first_name, last_name, email, dob, purpose, token) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (first_name, last_name, email, dob, purpose, token)
            )
            conn.commit()
            print("[DEBUG] User record created in pending table")

            # Debug: Print the role (if applicable)
            cur.execute("SELECT role FROM users WHERE email = %s", (email,))
            result = cur.fetchone()
            if result:
                print(f"[DEBUG] Role for {email}: {result[0]}")

            # Send notifications
            admin_msg = f"New user: {first_name} {last_name}\nEmail: {email}\nToken: {token}"
            send_email_async("jeff@integral.co.ke", "New Signup Request", admin_msg)
            send_email_async(email, "Your Account Pending", "Your account is awaiting approval")

            print("[DEBUG] Signup process completed")
            messagebox.showinfo("Success", "Sign-up successful! Awaiting admin approval.")
            self.destroy()  # Close the signup window only after successful signup

            # Restore the LoginWindow
            self.parent.deiconify()

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

    def go_back(self):
        """Close the signup window and reopen the login window."""
        self.destroy()  # Close the signup window
        self.parent.deiconify()  # Show the parent (LoginWindow) again


# Main Application
if __name__ == "__main__":
    from login_window import LoginWindow  # Import LoginWindow from login_window.py

    root = tk.Tk()
    login_window = LoginWindow(root)  # Create the LoginWindow
    root.mainloop()