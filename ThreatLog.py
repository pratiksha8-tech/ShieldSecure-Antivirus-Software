import os
import json
import customtkinter as ctk
import time
# Set up GUI
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# Paths
USER_DATA_DIR = os.path.join(os.path.expanduser("~"), "ShieldSecureData")
THREAT_LOG_FILE = os.path.join(USER_DATA_DIR, "threatlog.json")

# Ensure directory and log file exist
os.makedirs(USER_DATA_DIR, exist_ok=True)
if not os.path.exists(THREAT_LOG_FILE):
    with open(THREAT_LOG_FILE, "w") as f:
        json.dump([], f)

class ThreatLogApp:
    def __init__(self, root, back_callback=None):
        self.root = root
        self.back_callback = back_callback
        self.root.title("ShieldSecure Antivirus - Threat Logs")
        self.root.geometry("800x500")
        self.root.minsize(600, 400)

        # Header/Nav Bar (build once)
        header_frame = ctk.CTkFrame(root, fg_color="#222", height=60)
        header_frame.pack(fill="x")
        ctk.CTkLabel(header_frame, text="🛡️ ShieldSecure Threat Logs", font=("Arial", 22, "bold"), text_color="#03A9F4").pack(side="left", padx=20, pady=10)
        if self.back_callback:
            back_btn = ctk.CTkButton(header_frame, text="⬅️ Back to Home", fg_color="#333", hover_color="#555", text_color="white", command=self.back_callback, width=140)
            back_btn.pack(side="right", padx=20, pady=10)

        # Content Frame (black background)
        self.content_frame = ctk.CTkFrame(root, fg_color="black")
        self.content_frame.pack(expand=True, fill="both", padx=20, pady=10)

        self.scrollable_frame = None
        self.show_threat_logs()

    def build_ui(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def load_json(self, file):
        if not os.path.exists(file):
            return []
        try:
            with open(file, "r") as f:
                return json.load(f)
        except:
            return []

    def show_threat_logs(self):
        self.build_ui()
        # Title label in a gray frame at the top of the content area
        title_frame = ctk.CTkFrame(self.content_frame, fg_color="#222", corner_radius=10)
        title_frame.pack(pady=(10, 0), padx=10, fill="x")
        title_label = ctk.CTkLabel(title_frame, text="Threat Logs", font=("Arial", 18, "bold"), text_color="#fff")
        title_label.pack(pady=5)
        self.scrollable_frame = ctk.CTkScrollableFrame(self.content_frame, width=750, height=400)
        self.scrollable_frame.pack(expand=True, fill="both", padx=10, pady=5)
        self.display_threats(self.load_json(THREAT_LOG_FILE))

    def display_threats(self, threats):
        if not threats:
            # Center the empty message
            empty_frame = ctk.CTkFrame(self.scrollable_frame, fg_color="#222", corner_radius=12)
            empty_frame.pack(expand=True, fill="both", padx=100, pady=60)
            empty_label = ctk.CTkLabel(empty_frame, text="No threats found in logs.", font=("Arial", 16, "bold"), text_color="#888")
            empty_label.place(relx=0.5, rely=0.5, anchor="center")
            return

        for threat in threats:
            frame = ctk.CTkFrame(self.scrollable_frame, fg_color="#171616", corner_radius=10)
            frame.pack(fill="x", padx=10, pady=5)

            # Top row: Threat name and delete button
            top_row = ctk.CTkFrame(frame, fg_color="transparent")
            top_row.pack(fill="x")
            name = threat.get("file_name", "Unknown")
            name_label = ctk.CTkLabel(top_row, text=f"Threat: {name}", font=("Arial", 14, "bold"))
            name_label.pack(side="left", padx=10, pady=2)
            delete_button = ctk.CTkButton(top_row, text="❌", width=30, fg_color="#D32F2F", hover_color="#B71C1C", text_color="white", command=lambda t=threat: self.confirm_delete_threat_log(t))
            delete_button.pack(side="right", padx=10, pady=2)

            path = threat.get("original_path", "Unknown")
            quarantined_path = threat.get("quarantined_path", "Unknown")
            found_time = threat.get("found_time", "Unknown")
            threat_report = threat.get("threat_report", "No threat report available.")

            ctk.CTkLabel(frame, text=f"Original Path: {path}", font=("Arial", 12)).pack(anchor="w", padx=10)
            ctk.CTkLabel(frame, text=f"Quarantined Path: {quarantined_path}", font=("Arial", 12)).pack(anchor="w", padx=10)
            ctk.CTkLabel(frame, text=f"Found Date & Time: {found_time}", font=("Arial", 12)).pack(anchor="w", padx=10)

            button_frame = ctk.CTkFrame(frame, fg_color="transparent")
            button_frame.pack(pady=5, padx=10, anchor="e")

            report_button = ctk.CTkButton(button_frame, text="View Report", command=lambda t=threat: self.view_report(t))
            report_button.pack(side="left", padx=5)

    def view_report(self, threat):
        """Opens a popup with the threat report info."""
        report = threat.get("threat_report", {})

        # Extract and format the data
        threat_id = report.get("id", "Unknown")
        sha256 = report.get("sha256", "Unknown")
        last_analysis_date = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(report.get("last_analysis_date", 0)))
        last_analysis_stats = report.get("last_analysis_stats", {})
        names = "\n  - " + "\n  - ".join(report.get("names", [])) if report.get("names") else "  None"
        known_distributors = "\n  - " + "\n  - ".join(report.get("known_distributors", [])) if report.get("known_distributors") else "  None"
        file_conditions = report.get("filecondis", {})

        # Build a beautified report string
        report_text = f"""
    ====================[ Threat Summary ]====================

    🆔  Threat ID         : {threat_id}
    🔒 SHA256            : {sha256}
    🕒 Last Analysis     : {last_analysis_date}

    ==================[ Analysis Statistics ]==================

    🔴 Malicious        : {last_analysis_stats.get("malicious", 0)}
    🟠 Suspicious       : {last_analysis_stats.get("suspicious", 0)}
    🟢 Undetected       : {last_analysis_stats.get("undetected", 0)}
    ⚪ Harmless         : {last_analysis_stats.get("harmless", 0)}
    ⏱️ Timeout          : {last_analysis_stats.get("timeout", 0)}
    ⏳ Confirmed Timeout: {last_analysis_stats.get("confirmed-timeout", 0)}
    ❌ Failure          : {last_analysis_stats.get("failure", 0)}
    ❓ Unsupported Type : {last_analysis_stats.get("type-unsupported", 0)}

    ==================[ Associated Names ]==================

    {names}

    =================[ Known Distributors ]=================

    {known_distributors}

    ===================[ File Conditions ]==================

    🔗 dhash    : {file_conditions.get("dhash", "Unknown")}
    🧬 raw_md5  : {file_conditions.get("raw_md5", "Unknown")}
    """

        # Create the popup window
        popup = ctk.CTkToplevel(self.root)
        popup.title("Threat Report")
        popup.geometry("700x500")

        popup.lift()
        popup.attributes('-topmost', True)
        popup.after(100, lambda: popup.attributes('-topmost', False))  # Restore normal stacking after 100ms
        
        ctk.CTkLabel(popup, text="🧾 Threat Report", font=("Arial", 18, "bold")).pack(pady=10)

        textbox = ctk.CTkTextbox(popup, wrap="word", font=("Consolas", 12))
        textbox.insert("1.0", report_text)
        textbox.configure(state="disabled")
        textbox.pack(expand=True, fill="both", padx=10, pady=10)


    def clear_frame(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def center_popup(self, popup, width=400, height=180):
        self.root.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (width // 2)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (height // 2)
        popup.geometry(f"{width}x{height}+{x}+{y}")

    def confirm_delete_threat_log(self, threat):
        name = threat.get("file_name", "Unknown")
        popup = ctk.CTkToplevel(self.root)
        popup.title("Delete Threat Log")
        self.center_popup(popup, 400, 180)
        popup.lift()
        popup.attributes('-topmost', True)
        popup.after(100, lambda: popup.attributes('-topmost', False))
        ctk.CTkLabel(popup, text=f"Are you sure you want to delete this threat log:\n{name}?", font=("Arial", 14)).pack(pady=20)
        button_frame = ctk.CTkFrame(popup, fg_color="transparent")
        button_frame.pack(pady=10)
        confirm_btn = ctk.CTkButton(button_frame, text="Yes, Delete", fg_color="#D32F2F", hover_color="#B71C1C", command=lambda: self.delete_threat_log(threat, popup))
        confirm_btn.pack(side="left", padx=10)
        cancel_btn = ctk.CTkButton(button_frame, text="Cancel", fg_color="#A0A0A0", hover_color="#5E5E5E", text_color="black", command=popup.destroy)
        cancel_btn.pack(side="left", padx=10)

    def delete_threat_log(self, threat, popup):
        # Remove the threat from the JSON file
        data = self.load_json(THREAT_LOG_FILE)
        data = [t for t in data if t != threat]
        with open(THREAT_LOG_FILE, "w") as f:
            json.dump(data, f, indent=4)

        # Remove from quarantine.json if present
        quarantine_file = os.path.join(os.path.expanduser("~"), "ShieldSecureData", "quarantine.json")
        if os.path.exists(quarantine_file):
            try:
                with open(quarantine_file, "r") as fq:
                    quarantine_data = json.load(fq)
            except Exception:
                quarantine_data = []
            # Remove matching entry (by quarantined_path or file_name)
            quarantine_data = [q for q in quarantine_data if q.get("quarantined_path") != threat.get("quarantined_path") and q.get("file_name") != threat.get("file_name")]
            with open(quarantine_file, "w") as fq:
                json.dump(quarantine_data, fq, indent=4)

        # Delete the actual quarantined file if it exists
        quarantined_path = threat.get("quarantined_path")
        if quarantined_path and os.path.exists(quarantined_path):
            try:
                os.remove(quarantined_path)
            except Exception as e:
                print(f"Error deleting quarantined file: {e}")

        popup.destroy()
        self.show_threat_logs()

def start_threatlog_ui(root, back_callback=None):
    ThreatLogApp(root, back_callback)

if __name__ == "__main__":
    root = ctk.CTk()
    app = ThreatLogApp(root)
    root.mainloop()
