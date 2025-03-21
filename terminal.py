import tkinter as tk
from tkinter import ttk
import subprocess
import threading

class TerminalView(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.process = None  # To store the running subprocess
        self.setup_terminal()

    def setup_terminal(self):
        # Create a text widget to display terminal output
        self.terminal_output = tk.Text(
            self,
            bg="black",
            fg="green",
            font=("Consolas", 12),
            wrap=tk.WORD,
            insertbackground="green"  # Cursor color
        )
        self.terminal_output.pack(fill=tk.BOTH, expand=True)

        # Create an entry widget for user input
        self.terminal_input = ttk.Entry(
            self,
            font=("Consolas", 12)
        )
        self.terminal_input.pack(fill=tk.X, pady=5)
        self.terminal_input.bind("<Return>", self.execute_command)

        # Add a label for instructions
        ttk.Label(
            self,
            text="Enter commands below (e.g., 'ping google.com', 'netstat', etc.):",
            font=("Consolas", 10)
        ).pack(pady=5)

        # Add a "Stop" button to terminate the running process
        self.stop_button = ttk.Button(
            self,
            text="Stop",
            command=self.stop_command
        )
        self.stop_button.pack(pady=5)

    def execute_command(self, event):
        """Execute the command entered by the user."""
        command = self.terminal_input.get()
        if command.strip():  # Ensure the command is not empty
            self.terminal_output.insert(tk.END, f"\n$ {command}\n")  # Display the command
            self.terminal_input.delete(0, tk.END)  # Clear the input field

            # Run the command in a separate thread to avoid freezing the GUI
            threading.Thread(
                target=self.run_command,
                args=(command,),
                daemon=True
            ).start()

    def run_command(self, command):
        """Run the command and capture its output in real-time."""
        try:
            # Use subprocess.Popen to run the command and capture output
            self.process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Read output line by line and display it in the terminal
            while True:
                output = self.process.stdout.readline()
                if output == '' and self.process.poll() is not None:
                    break
                if output:
                    self.terminal_output.insert(tk.END, output)
                    self.terminal_output.see(tk.END)  # Scroll to the end

            # Capture any remaining output after the process ends
            stderr = self.process.stderr.read()
            if stderr:
                self.terminal_output.insert(tk.END, stderr)
                self.terminal_output.see(tk.END)

        except Exception as e:
            self.terminal_output.insert(tk.END, f"Error: {e}\n")
            self.terminal_output.see(tk.END)

    def stop_command(self):
        """Terminate the running subprocess."""
        if self.process and self.process.poll() is None:  # Check if the process is running
            self.process.terminate()  # Terminate the process
            self.process = None
            self.terminal_output.insert(tk.END, "\nProcess stopped by user.\n")
            self.terminal_output.see(tk.END)

# Example usage
if __name__ == "__main__":
    root = tk.Tk()
    root.title("Terminal Emulator")
    root.geometry("800x600")
    terminal = TerminalView(root)
    terminal.pack(fill=tk.BOTH, expand=True)
    root.mainloop()