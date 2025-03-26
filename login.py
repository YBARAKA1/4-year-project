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
import tkcalendar  # Add tkcalendar import

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
        tk.Label(dob_frame, text="Date of Birth:", **label_style).pack(anchor="w")
        
        # Create a frame for the calendar and entry
        calendar_frame = tk.Frame(dob_frame, bg=MATRIX_BG)
        calendar_frame.pack(fill="x", pady=(5, 0))
        
        # Create the entry field
        self.dob_entry = tk.Entry(calendar_frame, **entry_style)
        self.dob_entry.pack(side="left", fill="x", expand=True)
        
        # Create calendar button
        self.calendar_button = tk.Button(calendar_frame, text="📅", command=self.show_calendar, 
                                       bg=BUTTON_BG, fg=BUTTON_FG, font=("Consolas", 12))
        self.calendar_button.pack(side="right", padx=(5, 0))
        
        # Create calendar popup window (initially hidden)
        self.calendar_window = None
        self.calendar_widget = None

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
        try:
            if entry_widget and entry_widget.winfo_exists():
                entry_widget.config(highlightbackground="red", highlightcolor="red", highlightthickness=1)
                entry_widget.focus_set()  # Set focus to the incorrect field
        except tk.TclError:
            # Widget was destroyed, ignore the error
            pass

    def reset_highlight(self, entry_widget):
        """Reset the highlight of the entry widget."""
        entry_widget.config(highlightbackground=DARK_GREEN, highlightcolor=DARK_GREEN, highlightthickness=1)

    def show_calendar(self):
        """Show the calendar popup window."""
        # If calendar window already exists, just show it
        if self.calendar_window and self.calendar_window.winfo_exists():
            self.calendar_window.deiconify()
            self.calendar_window.lift()
            return

        # Create a new calendar window
        self.calendar_window = tk.Toplevel(self)
        self.calendar_window.title("Select Date")
        self.calendar_window.configure(bg=MATRIX_BG)
        
        # Create calendar widget
        self.calendar_widget = tkcalendar.Calendar(
            self.calendar_window,
            selectmode='day',
            year=2000,  # Default year
            month=1,    # Default month
            day=1,      # Default day
            background=MATRIX_BG,
            foreground=MATRIX_GREEN,
            selectbackground=ACCENT_GREEN,
            selectforeground=MATRIX_BG,
            normalbackground=MATRIX_BG,
            normalforeground=MATRIX_GREEN,
            weekendbackground=MATRIX_BG,
            weekendforeground=MATRIX_GREEN,
            othermonthbackground=MATRIX_BG,
            othermonthforeground=DARK_GREEN,
            othermonthwebackground=MATRIX_BG,
            othermonthweforeground=DARK_GREEN,
            bordercolor=MATRIX_GREEN,
            font=("Consolas", 10)
        )
        self.calendar_widget.pack(padx=10, pady=10)
        
        # Add select button
        select_button = tk.Button(
            self.calendar_window,
            text="Select",
            command=self.select_date,
            bg=BUTTON_BG,
            fg=BUTTON_FG,
            font=("Consolas", 12, "bold"),
            relief="flat",
            width=10
        )
        select_button.pack(pady=10)
        
        # Center the calendar window
        self.calendar_window.update_idletasks()
        width = self.calendar_window.winfo_width()
        height = self.calendar_window.winfo_height()
        x = (self.calendar_window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.calendar_window.winfo_screenheight() // 2) - (height // 2)
        self.calendar_window.geometry(f'{width}x{height}+{x}+{y}')
        
        # Make window modal
        self.calendar_window.transient(self)
        self.calendar_window.grab_set()
        
        # Add hover effect to select button
        select_button.bind("<Enter>", lambda e: select_button.config(bg=ACCENT_GREEN, fg=MATRIX_BG))
        select_button.bind("<Leave>", lambda e: select_button.config(bg=BUTTON_BG, fg=BUTTON_FG))
        
        # Add window close handler
        self.calendar_window.protocol("WM_DELETE_WINDOW", self.close_calendar)
        
        # Bind focus out event only to the main window, not the calendar
        self.bind("<FocusOut>", self.handle_calendar_focus_out)

    def close_calendar(self):
        """Close the calendar window and clean up."""
        if self.calendar_window and self.calendar_window.winfo_exists():
            self.calendar_window.grab_release()
            self.calendar_window.destroy()
            self.calendar_window = None
            self.calendar_widget = None

    def handle_calendar_focus_out(self, event):
        """Handle focus out event for calendar window."""
        if self.calendar_window and self.calendar_window.winfo_exists():
            # Only close if focus is lost to something outside both windows
            if event.widget == self and not self.calendar_window.focus_get():
                self.close_calendar()

    def select_date(self):
        """Handle date selection from calendar."""
        if self.calendar_widget:
            selected_date = self.calendar_widget.get_date()  # Returns "MM/DD/YYYY"
            # Convert the date string to the required format YYYY-MM-DD
            month, day, year = selected_date.split('/')
            # Pad month and day with leading zeros if needed
            month = month.zfill(2)
            day = day.zfill(2)
            # Ensure year is 4 digits
            if len(year) == 2:
                year = "20" + year
            formatted_date = f"{year}-{month}-{day}"
            self.dob_entry.delete(0, tk.END)
            self.dob_entry.insert(0, formatted_date)
            self.close_calendar()  # Use close_calendar instead of withdraw

    def signup(self):
        try:
            first_name = self.first_name_entry.get()
            last_name = self.last_name_entry.get()
            email = self.email_entry.get()
            dob = self.dob_entry.get()
            purpose = self.purpose_entry.get()
            print(f"[DEBUG] Attempting signup for {email}")

            # Validate first name and last name
            if not self.validate_name(first_name):
                messagebox.showerror("Error", "Please fill in your first name correctly.")
                if self.first_name_entry.winfo_exists():
                    self.highlight_error(self.first_name_entry)
                return

            if not self.validate_name(last_name):
                messagebox.showerror("Error", "Please fill in your last name correctly.")
                if self.last_name_entry.winfo_exists():
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
        except tk.TclError:
            # Window was destroyed, ignore the error
            pass

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