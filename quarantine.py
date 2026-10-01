import os
import json
import shutil
import customtkinter as ctk
from send2trash import send2trash

# Set up GUI
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")



#storing quarantine data in user's home directory
USER_DATA_DIR = os.path.join(os.path.expanduser("~"), "ShieldSecureData")
QUARANTINE_FILE = os.path.join(USER_DATA_DIR, "quarantine.json")
QUARANTINE_FOLDER = os.path.join(USER_DATA_DIR, "quarantine")
THREAT_LOG_FILE = os.path.join(USER_DATA_DIR, "threatlog.json")


# Creating folders if they don't exist
os.makedirs(USER_DATA_DIR, exist_ok=True)
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)

# Creating an empty JSON file if it doesn't exist
if not os.path.exists(QUARANTINE_FILE):
    with open(QUARANTINE_FILE, "w") as f:
        json.dump([], f)


class ShieldSecureApp:
    def __init__(self, root,back_callback=None):
        self.root = root
        self.back_callback = back_callback 
        self.root.title("ShieldSecure Antivirus")
        self.root.geometry("800x500")
        self.root.minsize(600, 400)
        self.build_ui()
    
   

        # Header
        self.header = ctk.CTkLabel(root, text="🛡️ ShieldSecure", font=("Arial", 20, "bold"))
        self.header.pack(pady=10)

        # Navigation Buttons
        self.nav_frame = ctk.CTkFrame(root, fg_color="black")
        self.nav_frame.pack(fill="x", padx=10, pady=5)

        self.quarantine_btn = ctk.CTkButton(self.nav_frame, text="Quarantine",fg_color="#A0A0A0", hover_color="#5E5E5E", text_color="black", command=self.show_quarantine)
        self.quarantine_btn.pack(side="left", padx=5)

        # Frame for content (Scrollable)
        self.content_frame = ctk.CTkFrame(root, fg_color="black")
        self.content_frame.pack(expand=True, fill="both")

        
        self.scrollable_frame = None 

        self.show_quarantine()  # Show quarantine first
    
    def build_ui(self):
        """ Builds the UI elements. """
        for widget in self.root.winfo_children():
            widget.destroy()  # Clears the existing UI

        # Header/Nav Bar
        header_frame = ctk.CTkFrame(self.root, fg_color="#222", height=60)
        header_frame.pack(fill="x")
        ctk.CTkLabel(header_frame, text="🛡️ ShieldSecure Quarantine", font=("Arial", 22, "bold"), text_color="#03A9F4").pack(side="left", padx=20, pady=10)
        if self.back_callback:
            back_btn = ctk.CTkButton(header_frame, text="⬅️ Back to Home", fg_color="#333", hover_color="#555", text_color="white", command=self.back_callback, width=140)
            back_btn.pack(side="right", padx=20, pady=10)

        # Main Content Frame
        main_frame = ctk.CTkFrame(self.root, fg_color="#181818")
        main_frame.pack(expand=True, fill="both", padx=20, pady=10)

        self.content_frame = ctk.CTkFrame(main_frame, fg_color="black")
        self.content_frame.pack(expand=True, fill="both")

        self.scrollable_frame = None
        self.show_quarantine()

    def load_json(self, file):
        """Loads JSON data, returns empty list if file is missing or corrupted."""
        if not os.path.exists(file):
            return []
        try:
            with open(file, "r") as f:
                data = json.load(f)
            # Filter out entries whose files do not exist
            if file == QUARANTINE_FILE:
                filtered = [t for t in data if os.path.exists(t.get("quarantined_path", ""))]
                # If any were removed, update the file
                if len(filtered) != len(data):
                    with open(file, "w") as fw:
                        json.dump(filtered, fw, indent=4)
                return filtered
            return data
        except:
            return []

    def update_json(self, file, data, remove=False):
        """Writes data to a JSON file. If remove=True, removes specific data by absolute, case-insensitive quarantined_path."""
        current_data = self.load_json(file)
        if remove:
            qpath = os.path.abspath(data.get("quarantined_path", "")).lower()
            current_data = [t for t in current_data if os.path.abspath(t.get("quarantined_path", "")).lower() != qpath]
        else:
            current_data.append(data)
        with open(file, "w") as f:
            json.dump(current_data, f, indent=4)

    def show_quarantine(self):
        self.clear_frame()
        # Explicitly destroy old scrollable_frame if it exists
        if hasattr(self, 'scrollable_frame') and self.scrollable_frame is not None:
            try:
                self.scrollable_frame.destroy()
            except Exception:
                pass
        self.scrollable_frame = ctk.CTkScrollableFrame(self.content_frame, width=750, height=400)
        self.scrollable_frame.pack(expand=True, fill="both", padx=10, pady=5)
        self.display_threats(self.load_json(QUARANTINE_FILE), self.restore_threat, "Restore", "Quarantine",
                             self.move_to_recycle_bin, "Move to Recycle Bin")
        self.root.update_idletasks()

    def display_threats(self, threats, action_function, button_text, section_title, secondary_action=None,
                        secondary_text=None):
        """Displays a list of threats with action buttons inside the scrollable frame."""
        title_label = ctk.CTkLabel(self.scrollable_frame, text=section_title, font=("Arial", 18, "bold"))
        title_label.pack(pady=5)

        if not threats:
            empty_label = ctk.CTkLabel(self.scrollable_frame, text=f"No threats in {section_title}.", font=("Arial", 14))
            empty_label.pack(pady=10)
            return

        for threat in threats:
            frame = ctk.CTkFrame(self.scrollable_frame, fg_color="#808080", corner_radius=10)
            frame.pack(fill="x", padx=10, pady=5)

            threat_name = ctk.CTkLabel(frame, text=f"Threat: {threat['file_name']}", font=("Arial", 14, "bold"))
            threat_name.pack(anchor="w", padx=10, pady=2)

            path_label = ctk.CTkLabel(frame, text=f"Path: {threat['original_path']}", font=("Arial", 12))
            path_label.pack(anchor="w", padx=10)

            button_frame = ctk.CTkFrame(frame, fg_color="transparent")
            button_frame.pack(pady=5, padx=10, anchor="e")

            action_button = ctk.CTkButton(button_frame, text=button_text, command=lambda t=threat: action_function(t))
            action_button.pack(side="left", padx=5)

            if secondary_action and secondary_text:
                secondary_button = ctk.CTkButton(button_frame, text=secondary_text, fg_color="red",
                                                 command=lambda t=threat: secondary_action(t))
                secondary_button.pack(side="left", padx=5)

    def center_popup(self, popup, width=400, height=180):
        self.root.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (width // 2)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (height // 2)
        popup.geometry(f"{width}x{height}+{x}+{y}")

    def restore_threat(self, threat):
        """Show confirmation popup before restoring the threat from Quarantine to its original location."""
        file_name = threat.get("file_name", "Unknown")
        popup = ctk.CTkToplevel(self.root)
        popup.title("Restore Threat")
        self.center_popup(popup, 400, 180)
        popup.lift()
        popup.attributes('-topmost', True)
        popup.after(100, lambda: popup.attributes('-topmost', False))
        ctk.CTkLabel(popup, text=f"Are you sure you want to restore this file to its original location?\n{file_name}", font=("Arial", 14)).pack(pady=20)
        button_frame = ctk.CTkFrame(popup, fg_color="transparent")
        button_frame.pack(pady=10)
        confirm_btn = ctk.CTkButton(button_frame, text="Yes, Restore", fg_color="#1976D2", hover_color="#1565C0", command=lambda: self._do_restore_threat(threat, popup))
        confirm_btn.pack(side="left", padx=10)
        cancel_btn = ctk.CTkButton(button_frame, text="Cancel", fg_color="#A0A0A0", hover_color="#5E5E5E", text_color="black", command=popup.destroy)
        cancel_btn.pack(side="left", padx=10)

    def _do_restore_threat(self, threat, popup):
        original_path = threat["original_path"]
        quarantined_path = threat["quarantined_path"]
        print(f"[DEBUG] Attempting to restore: {quarantined_path} -> {original_path}")
        file_path = threat["quarantined_path"]
        threatlog_data = self.load_json(THREAT_LOG_FILE)
        updated_threatlog = [
            {**item, "quarantined_path": "not in quarantine"}
            if item.get("quarantined_path") == file_path
            else item
            for item in threatlog_data
        ]
        with open(THREAT_LOG_FILE, "w") as f:
            json.dump(updated_threatlog, f, indent=4)
        if os.path.exists(quarantined_path):
            try:
                shutil.move(quarantined_path, original_path)
                print(f"[DEBUG] Restored file to: {original_path}")
                self.update_json(QUARANTINE_FILE, threat, remove=True)
            except Exception as e:
                print(f"Error restoring file: {e}")
        else:
            print(f"[DEBUG] Quarantined file does not exist: {quarantined_path}")
        popup.destroy()
        self.build_ui()

    def move_to_recycle_bin(self, threat):
        """Show confirmation popup before moving threat to Recycle Bin."""
        file_name = threat.get("file_name", "Unknown")
        popup = ctk.CTkToplevel(self.root)
        popup.title("Move to Recycle Bin")
        self.center_popup(popup, 400, 180)
        popup.lift()
        popup.attributes('-topmost', True)
        popup.after(100, lambda: popup.attributes('-topmost', False))
        ctk.CTkLabel(popup, text=f"Are you sure you want to move this file to the Recycle Bin?\n{file_name}", font=("Arial", 14)).pack(pady=20)
        button_frame = ctk.CTkFrame(popup, fg_color="transparent")
        button_frame.pack(pady=10)
        confirm_btn = ctk.CTkButton(button_frame, text="Yes, Move", fg_color="#D32F2F", hover_color="#B71C1C", command=lambda: self._do_move_to_recycle_bin(threat, popup))
        confirm_btn.pack(side="left", padx=10)
        cancel_btn = ctk.CTkButton(button_frame, text="Cancel", fg_color="#A0A0A0", hover_color="#5E5E5E", text_color="black", command=popup.destroy)
        cancel_btn.pack(side="left", padx=10)

    def _do_move_to_recycle_bin(self, threat, popup):
        file_path = threat["quarantined_path"]
        print(f"[DEBUG] Attempting to move to recycle bin: {file_path}")
        threatlog_data = self.load_json(THREAT_LOG_FILE)
        updated_threatlog = [
            {**item, "quarantined_path": "not in quarantine"}
            if item.get("file_name") == threat.get("file_name")
            else item
            for item in threatlog_data
        ]
        with open(THREAT_LOG_FILE, "w") as f:
            json.dump(updated_threatlog, f, indent=4)
        if os.path.exists(file_path):
            try:
                send2trash(file_path)
                print(f"[DEBUG] Sent to recycle bin: {file_path}")
                self.update_json(QUARANTINE_FILE, threat, remove=True)
            except Exception as e:
                print(f"Error moving to Recycle Bin: {e}")
        else:
            print(f"[DEBUG] Quarantined file does not exist: {file_path}")
            self.update_json(QUARANTINE_FILE, threat, remove=True)
        popup.destroy()
        self.build_ui()

    def clear_frame(self):
        """Clears the content frame."""
        for widget in self.content_frame.winfo_children():
            widget.destroy()
    
def start_quarantine_ui(root, back_callback=None):
    """ Replaces the current UI with the antivirus UI. """
    ShieldSecureApp(root, back_callback) 

if __name__ == "__main__":
    root = ctk.CTk()
    app = ShieldSecureApp(root)
    root.mainloop()
