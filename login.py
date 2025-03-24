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
        self.parent = parent
        self.title("Sign Up")
        self.geometry("500x700")
        self.configure(bg=MATRIX_BG)

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
        main_frame = tk.Frame(self, bg=MATRIX_BG, padx=40, pady=40)
        main_frame.pack(expand=True, fill="both")

        # Title
        title_label = tk.Label(main_frame, text="Create New Account", **title_style)
        title_label.pack(pady=(0, 30))

        # Back Button (top-left corner)
        self.back_button = tk.Button(main_frame, text="← Back", command=self.go_back, **button_style)
        self.back_button.pack(anchor="w", pady=(0, 20))

        # Create a frame for the form fields
        form_frame = tk.Frame(main_frame, bg=MATRIX_BG)
        form_frame.pack(fill="x", pady=10)

        # First Name Frame
        first_name_frame = tk.Frame(form_frame, bg=MATRIX_BG)
        first_name_frame.pack(fill="x", pady=5)
        tk.Label(first_name_frame, text="First Name:", **label_style).pack(anchor="w")
        self.first_name_entry = tk.Entry(first_name_frame, **entry_style)
        self.first_name_entry.pack(fill="x", pady=(5, 0))
        self.first_name_entry.bind("<FocusIn>", lambda e: self.reset_highlight(self.first_name_entry))

        # Last Name Frame
        last_name_frame = tk.Frame(form_frame, bg=MATRIX_BG)
        last_name_frame.pack(fill="x", pady=5)
        tk.Label(last_name_frame, text="Last Name:", **label_style).pack(anchor="w")
        self.last_name_entry = tk.Entry(last_name_frame, **entry_style)
        self.last_name_entry.pack(fill="x", pady=(5, 0))
        self.last_name_entry.bind("<FocusIn>", lambda e: self.reset_highlight(self.last_name_entry))

        # Email Frame
        email_frame = tk.Frame(form_frame, bg=MATRIX_BG)
        email_frame.pack(fill="x", pady=5)
        tk.Label(email_frame, text="Email:", **label_style).pack(anchor="w")
        self.email_entry = tk.Entry(email_frame, **entry_style)
        self.email_entry.pack(fill="x", pady=(5, 0))

        # Date of Birth Frame
        dob_frame = tk.Frame(form_frame, bg=MATRIX_BG)
        dob_frame.pack(fill="x", pady=5)
        tk.Label(dob_frame, text="Date of Birth (YYYY-MM-DD):", **label_style).pack(anchor="w")
        self.dob_entry = tk.Entry(dob_frame, **entry_style)
        self.dob_entry.pack(fill="x", pady=(5, 0))

        # Purpose Frame
        purpose_frame = tk.Frame(form_frame, bg=MATRIX_BG)
        purpose_frame.pack(fill="x", pady=5)
        tk.Label(purpose_frame, text="Purpose of Using IDS:", **label_style).pack(anchor="w")
        self.purpose_entry = tk.Entry(purpose_frame, **entry_style)
        self.purpose_entry.pack(fill="x", pady=(5, 0))

        # Sign Up Button
        self.signup_button = tk.Button(main_frame, text="Sign Up", command=self.signup, **button_style)
        self.signup_button.pack(pady=30)

        # Add hover effects
        self.back_button.bind("<Enter>", lambda e: self.back_button.config(bg=ACCENT_GREEN, fg=MATRIX_BG))
        self.back_button.bind("<Leave>", lambda e: self.back_button.config(bg=BUTTON_BG, fg=BUTTON_FG))
        self.signup_button.bind("<Enter>", lambda e: self.signup_button.config(bg=ACCENT_GREEN, fg=MATRIX_BG))
        self.signup_button.bind("<Leave>", lambda e: self.signup_button.config(bg=BUTTON_BG, fg=BUTTON_FG))

    def center_window(self):
        """Center the window on the screen."""
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')

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