import tkinter as tk
from tkinter import ttk
import subprocess
import threading
from queue import Queue, Empty

class TerminalView(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.process = None  # To store the running subprocess
        self.command_history = []  # Store command history
        self.history_index = -1  # Current position in command history
        self.output_queue = Queue()  # Queue for thread-safe communication
        self.setup_terminal()
        self.check_queue()  # Start checking the queue for updates

    def setup_terminal(self):
        # Create main container with padding
        self.configure(padding=10)

        # Create a frame for the terminal output with scrollbar
        output_frame = ttk.Frame(self)
        output_frame.pack(fill=tk.BOTH, expand=True)

        # Create scrollbar for terminal output
        scrollbar = ttk.Scrollbar(output_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Create a text widget to display terminal output
        self.terminal_output = tk.Text(
            output_frame,
            bg="#1e1e1e",  # Dark background
            fg="#00ff00",  # Bright green text
            font=("Consolas", 12),
            wrap=tk.WORD,
            insertbackground="#00ff00",  # Cursor color
            yscrollcommand=scrollbar.set
        )
        self.terminal_output.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.terminal_output.yview)

        # Create a frame for input area
        input_frame = ttk.Frame(self)
        input_frame.pack(fill=tk.X, pady=5)

        # Create an entry widget for user input
        self.terminal_input = ttk.Entry(
            input_frame,
            font=("Consolas", 12)
        )
        self.terminal_input.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.terminal_input.bind("<Return>", self.execute_command)
        self.terminal_input.bind("<Up>", self.navigate_history)
        self.terminal_input.bind("<Down>", self.navigate_history)

        # Add a "Stop" button to terminate the running process
        self.stop_button = ttk.Button(
            input_frame,
            text="Stop",
            command=self.stop_command,
            style="Accent.TButton"
        )
        self.stop_button.pack(side=tk.RIGHT, padx=5)

        # Add a "Clear" button to clear the terminal
        self.clear_button = ttk.Button(
            input_frame,
            text="Clear",
            command=self.clear_terminal,
            style="Accent.TButton"
        )
        self.clear_button.pack(side=tk.RIGHT, padx=5)

        # Add a label for instructions
        ttk.Label(
            self,
            text="Enter commands below (use ↑↓ arrows for command history):",
            font=("Consolas", 10),
            foreground="#888888"
        ).pack(pady=5)

        # Configure styles
        style = ttk.Style()
        style.configure("Accent.TButton", padding=5)

    def check_queue(self):
        """Check the queue for new output and update the terminal."""
        try:
            while True:
                output = self.output_queue.get_nowait()
                self.terminal_output.insert(tk.END, output)
                self.terminal_output.see(tk.END)
        except Empty:
            pass
        finally:
            self.after(100, self.check_queue)  # Check again after 100ms

    def navigate_history(self, event):
        """Navigate through command history using up/down arrows."""
        if not self.command_history:
            return

        if event.keysym == "Up":
            if self.history_index < len(self.command_history) - 1:
                self.history_index += 1
                self.terminal_input.delete(0, tk.END)
                self.terminal_input.insert(0, self.command_history[self.history_index])
        elif event.keysym == "Down":
            if self.history_index > 0:
                self.history_index -= 1
                self.terminal_input.delete(0, tk.END)
                self.terminal_input.insert(0, self.command_history[self.history_index])
            else:
                self.history_index = -1
                self.terminal_input.delete(0, tk.END)

    def execute_command(self, event):
        """Execute the command entered by the user."""
        command = self.terminal_input.get()
        if command.strip():  # Ensure the command is not empty
            # Add command to history if it's different from the last command
            if not self.command_history or command != self.command_history[-1]:
                self.command_history.append(command)
                self.history_index = -1

            self.output_queue.put(f"\n$ {command}\n")  # Display the command
            self.terminal_input.delete(0, tk.END)  # Clear the input field

            # Run the command in a separate thread to avoid freezing the GUI
            threading.Thread(
                target=self.run_command,
                args=(command,),
                daemon=True
            ).start()

    def clear_terminal(self):
        """Clear the terminal output."""
        self.terminal_output.delete(1.0, tk.END)
        self.output_queue.put("Terminal cleared.\n")

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
                    self.output_queue.put(output)

            # Capture any remaining output after the process ends
            stderr = self.process.stderr.read()
            if stderr:
                self.output_queue.put(stderr)

        except Exception as e:
            self.output_queue.put(f"Error: {e}\n")

    def stop_command(self):
        """Terminate the running subprocess."""
        if self.process and self.process.poll() is None:  # Check if the process is running
            self.process.terminate()  # Terminate the process
            self.process = None
            self.output_queue.put("\nProcess stopped by user.\n")

# Example usage
if __name__ == "__main__":
    root = tk.Tk()
    root.title("Terminal Emulator")
    root.geometry("800x600")
    terminal = TerminalView(root)
    terminal.pack(fill=tk.BOTH, expand=True)
    root.mainloop()