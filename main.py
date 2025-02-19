import tkinter as tk
import random
import subprocess

class WelcomeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Welcome")
        self.root.geometry("1024x768")
        self.root.configure(bg="#1a1a1a")

        # Colors
        self.bg_color = "#1a1a1a"
        self.text_color = "#ffffff"
        self.accent_blue = "#00c0ff"
        self.glitch_colors = ["#ff0000", "#00ff00", "#ffff00", "#ff00ff"]  # Red, Green, Yellow, Purple

        # Create welcome label
        self.welcome_label = tk.Label(
            self.root,
            text="Welcome",
            font=("Segoe UI", 48, "bold"),
            fg=self.accent_blue,
            bg=self.bg_color
        )
        self.welcome_label.place(relx=0.5, rely=0.4, anchor=tk.CENTER)

        # Start glitch effect
        self.root.after(500, self.glitch_effect)

    def glitch_effect(self, count=0):
        """Creates a more realistic glitch effect on 'Welcome'"""
        if count < 8:  # Run glitch effect 8 times
            glitch_text = "Welc0m3" if count % 2 == 0 else "W3lc@me"
            self.welcome_label.config(text=glitch_text, fg=random.choice(self.glitch_colors))
            self.root.after(100, self.glitch_effect, count + 1)
        else:
            self.welcome_label.config(text="Welcome", fg=self.accent_blue)
            self.root.after(500, self.fade_to_black)

    def fade_to_black(self):
        """Turns the screen completely black before displaying hacking effect"""
        self.welcome_label.destroy()
        self.root.configure(bg="black")
        self.root.after(500, self.start_hacking_effect)

    def start_hacking_effect(self):
        """Creates a 'Matrix-style' scrolling green text effect"""
        self.hack_texts = []
        self.hack_canvas = tk.Canvas(self.root, bg="black", highlightthickness=0)
        self.hack_canvas.pack(fill=tk.BOTH, expand=True)

        # Generate 20+ lines of random 'hacking' text
        self.fake_hack_lines = [
            f"root@server:~# {random.choice(['Scanning...', 'Decrypting...', 'Accessing...', 'Override Sequence...'])}",
            f"0x{random.randint(100000, 999999):X} [{random.choice(['OK', 'FAILED', 'RUNNING'])}]",
            f"sys.log -> {random.randint(1000, 9999)} entries processed...",
            f"kernel32.dll -> {random.choice(['Access Granted', 'Access Denied'])}",
            f"fetching /etc/passwd...",
            f"sudo chmod +x hack.sh",
            f"mkdir /root/secrets/",
            f"rm -rf /var/logs/",
            f"Initializing rootkit...",
            f"PORT SCAN: {random.randint(1000, 9999)} open",
        ] * 5  # Repeat the list for more lines

        self.hack_y = 10  # Start printing from the top
        self.type_hacking_text()

    def type_hacking_text(self):
        """Types out the fake hacking text, scrolling down"""
        if self.fake_hack_lines:
            text = self.fake_hack_lines.pop(0)
            hack_label = self.hack_canvas.create_text(20, self.hack_y, anchor="w", text=text, font=("Courier", 14), fill="green")
            self.hack_texts.append(hack_label)
            self.hack_y += 20  # Move down for next line

            # Scroll effect
            if len(self.hack_texts) > 30:
                self.hack_canvas.move("all", 0, -20)  # Shift all text up

            self.root.after(100, self.type_hacking_text)  # Delay between lines
        else:
            self.root.after(1500, self.transition_to_dashboard)  # Wait before switching

    def transition_to_dashboard(self):
        """Flashes the screen and transitions to the dashboard.py file"""
        self.hack_canvas.destroy()
        self.root.destroy()  # Close the welcome window

        # Run the dashboard.py script
        subprocess.Popen(["python", "dashboard.py"])

if __name__ == "__main__":
    root = tk.Tk()
    app = WelcomeApp(root)
    root.mainloop()
