import tkinter as tk
from tkinter import scrolledtext
import subprocess
import threading

def execute_command(event=None):
    command = entry.get()
    if command.lower() == "exit":
        root.quit()
        return
    
    output_text.insert(tk.END, f"> {command}\n", "command")
    entry.delete(0, tk.END)
    
    def run_command():
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, universal_newlines=True)
            for line in process.stdout:
                output_text.insert(tk.END, line, "output")
                output_text.yview(tk.END)
            for line in process.stderr:
                output_text.insert(tk.END, line, "error")
                output_text.yview(tk.END)
            process.stdout.close()
            process.stderr.close()
        except Exception as e:
            output_text.insert(tk.END, f"Error: {str(e)}\n", "error")
            output_text.yview(tk.END)
    
    threading.Thread(target=run_command, daemon=True).start()

# Initialize GUI
root = tk.Tk()
root.title("Python GUI Terminal")

output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=20, width=80, font=("Courier", 12))
output_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
output_text.tag_config("command", foreground="blue")
output_text.tag_config("output", foreground="black")
output_text.tag_config("error", foreground="red")

entry = tk.Entry(root, font=("Courier", 12))
entry.pack(padx=10, pady=5, fill=tk.X)
entry.bind("<Return>", execute_command)

entry.focus()
root.mainloop()
