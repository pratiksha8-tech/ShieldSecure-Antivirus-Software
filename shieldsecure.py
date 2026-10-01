import customtkinter as ctk
import antvirus  
import quarantine
import ThreatLog
import json
import os

class ShieldSecureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ShieldSecure Antivirus")
        self.root.geometry("900x550")
        self.load_dashboard()  

    def get_protection_status(self):
        # Try to read real-time protection state from a file or global state
        # For now, check if a marker file exists
        marker = os.path.join(os.path.expanduser("~"), "ShieldSecureData", "realtime_on.marker")
        return os.path.exists(marker)

    def get_threat_count(self):
        log_path = os.path.join(os.path.expanduser("~"), "ShieldSecureData", "threatlog.json")
        if os.path.exists(log_path):
            try:
                with open(log_path, "r") as f:
                    data = json.load(f)
                return len(data)
            except Exception:
                return 0
        return 0

    def get_system_health(self, protection_on, threat_count):
        if not protection_on:
            return ("Attention Needed", "#D32F2F", "Real-time protection is OFF.")
        if threat_count > 0:
            return ("Threats Present", "#D32F2F", f"{threat_count} threats need attention.")
        return ("Good", "#388E3C", "Your system is running optimally.")

    def load_dashboard(self):
        """ Loads the main Dashboard UI. """
        for widget in self.root.winfo_children():
            widget.destroy()  

        # Top Navigation Bar
        nav_bar = ctk.CTkFrame(self.root, fg_color="#23272A", height=56)
        nav_bar.pack(fill="x")
        nav_title = ctk.CTkLabel(nav_bar, text="🛡️ ShieldSecure", font=("Arial", 22, "bold"), text_color="#1976D2")
        nav_title.pack(side="left", padx=20, pady=10)

        # Main Content Frame
        main_frame = ctk.CTkFrame(self.root, fg_color="#181A1B")
        main_frame.pack(fill="both", expand=True, padx=0, pady=0)

        # Get real status
        protection_on = self.get_protection_status()
        threat_count = self.get_threat_count()
        health_text, health_color, health_sub = self.get_system_health(protection_on, threat_count)

        # Left Panel (Protection Status)
        left_panel = ctk.CTkFrame(main_frame, width=600, height=350, fg_color="#23272A", corner_radius=12)
        left_panel.pack(side="left", padx=30, pady=30, fill="y")

        ctk.CTkLabel(left_panel, text="Protection Status", font=("Arial", 16, "bold"), text_color="#B0B3B8").pack(anchor="w", padx=20, pady=10)

        def create_status_box(text, subtext, icon="✔", color="#388E3C"):
            frame = ctk.CTkFrame(left_panel, fg_color="#23272A", border_width=2, border_color="#33373B", corner_radius=8)
            frame.pack(fill="x", pady=8, padx=10)
            ctk.CTkLabel(frame, text=text, font=("Arial", 14, "bold"), text_color=color).pack(side="left", padx=12, pady=8)
            ctk.CTkLabel(frame, text=icon, font=("Arial", 14, "bold"), text_color=color).pack(side="right", padx=12)
            ctk.CTkLabel(frame, text=subtext, font=("Arial", 12), text_color="#B0B3B8").pack(anchor="w", padx=12, pady=(0, 8))

        # Dynamic status boxes
        create_status_box(
            f"Protection: {'Active' if protection_on else 'Inactive'}",
            "Real-time protection is ON." if protection_on else "Real-time protection is OFF.",
            "✔" if protection_on else "⛔", "#388E3C" if protection_on else "#D32F2F"
        )
        create_status_box(
            f"Threats Detected: {threat_count}",
            "No threats found." if threat_count == 0 else f"{threat_count} threats found.",
            "" if threat_count == 0 else "⚠️", "#1976D2" if threat_count == 0 else "#D32F2F"
        )
        create_status_box(
            f"System Health: {health_text}",
            health_sub,
            "❤️" if health_text == "Good" else "⚠️", health_color
        )

        # Right Panel 
        right_panel = ctk.CTkFrame(main_frame, width=250, height=350, fg_color="#23272A", corner_radius=12)
        right_panel.pack(side="right", padx=30, pady=30, fill="y")

        ctk.CTkLabel(right_panel, text="Quick Actions", font=("Arial", 15, "bold"), text_color="#B0B3B8").pack(pady=18)

        actions = [
            ("Scan Now", self.open_antivirus, "#1976D2", "#1565C0"),
            ("Threat Logs", self.open_threatlog, "#424242", "#33373B"),
            ("Quarantine", self.open_quarantine, "#424242", "#33373B"),
        ]

        for action, command, color, hover in actions:
            ctk.CTkButton(right_panel, text=action, fg_color=color, hover_color=hover, text_color="#fff", font=("Arial", 13, "bold"), corner_radius=8, command=command).pack(fill="x", padx=24, pady=8)

        # Footer
        ctk.CTkLabel(self.root, text="Last Update: 5 minutes ago   |   System Health: {}".format(health_text), font=("Arial", 12), text_color="#B0B3B8").pack(side="bottom", pady=8)

    def open_antivirus(self):
        """ Clears the UI and loads the antivirus scanning UI inside the same window. """
        for widget in self.root.winfo_children():
            widget.destroy()  # Clear the window
        antvirus.start_antivirus_ui(self.root, self.load_dashboard) 
        # Load Antivirus UI and allow back navigation

    def open_quarantine(self):
        """ Clears the UI and loads the Quarantine UI inside the same window. """
        for widget in self.root.winfo_children():
            widget.destroy() 
        quarantine.start_quarantine_ui(self.root, self.load_dashboard)  # Load quarantine UI and allow back navigation

    def open_threatlog(self):
        """ Clears the UI and loads the Threatlog UI inside the same window. """
        for widget in self.root.winfo_children():
            widget.destroy()  
        ThreatLog.start_threatlog_ui(self.root, self.load_dashboard)

if __name__ == "__main__":
    root = ctk.CTk()
    app = ShieldSecureApp(root)
    root.mainloop()
