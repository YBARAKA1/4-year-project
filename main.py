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
            f"root@NIDS:~# {random.choice(['Monitoring traffic...', 'Analyzing packets...', 'Scanning for anomalies...', 'Detecting threats...'])}",
            f"ALERT [{random.randint(1000, 9999)}]: {random.choice(['Possible DDoS attack detected', 'Suspicious SSH brute-force attempt', 'Malicious payload signature identified', 'Unauthorized access attempt'])}",
            f"Packet Capture [{random.randint(1000, 9999)} packets] -> Logging to /var/log/nids.log...",
            f"Snort Rule Triggered: [{random.randint(1000, 9999)}] {random.choice(['SQL Injection', 'XSS Attempt', 'Port Scanning Detected', 'Malware Communication'])}",
            f"Source IP: {random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)} -> Destination IP: {random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
            f"Deep Packet Inspection -> {random.choice(['Suspicious payload found', 'No anomalies detected', 'Potential exploit detected'])}",
            f"Firewall Alert: {random.randint(10, 500)} blocked connections from {random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
            f"Real-time traffic analysis: {random.randint(500, 5000)} packets/sec | {random.randint(50, 500)} anomalies detected",
            f"Anomaly Score: {random.randint(1, 100)} | {random.choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])} risk",
            f"TCP SYN Flood detected: {random.randint(1000, 9999)} requests per second",
            f"Encrypted traffic analysis: {random.choice(['Possible TLS downgrade attack', 'Unusual SSL/TLS handshake', 'No anomalies found'])}",
            f"Botnet C&C Communication detected: {random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)} -> Flagging for further analysis...",
            f"New unauthorized MAC Address detected on network: {':'.join(['%02x' % random.randint(0, 255) for _ in range(6)])}",
            f"IDS Log: {random.randint(10000, 99999)} new security events recorded...",
            f"Port Scan Detected: {random.randint(20, 100)} open ports from IP {random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
            f"DNS Spoofing Attempt: Malicious DNS response from {random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
            f"ARP Spoofing detected: MAC Address mismatch for {random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
            f"Syslog Alert: Unusual activity on port {random.randint(1000, 9999)}",
            f"MITM Attack Warning: Duplicate ARP replies detected from {random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
        ] * 5  # Repeat for more lines


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
