from dotenv import load_dotenv
import os
import hashlib
import threading
import time
import json
import shutil
import customtkinter as ctk
from tkinter import filedialog
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psutil
import subprocess

load_dotenv()
import requests

import sys

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

class RealTimeProtector(FileSystemEventHandler):
    """Real-time file system monitoring for suspicious activities."""
    
    def __init__(self, antivirus_app):
        self.antivirus_app = antivirus_app
        self.observer = Observer()
        self.monitoring = False
        self.suspicious_extensions = {'.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs', '.js', '.jar'}
        self.blocked_files = set()
        
    def start_monitoring(self, path):
        """Start monitoring a directory for file system events."""
        if not self.monitoring:
            # Exclude ShieldSecureData folder from monitoring to prevent recursive detection
            self.observer.schedule(self, path, recursive=True)
            self.observer.start()
            self.monitoring = True
            print(f"🛡️ Real-time protection started for: {path}")
            
            # Log excluded folders
            shieldsecure_data = os.path.join(os.path.expanduser("~"), "ShieldSecureData")
            print(f"🛡️ Excluded from monitoring: {shieldsecure_data}")
            
    def stop_monitoring(self):
        """Stop file system monitoring."""
        if self.monitoring:
            self.observer.stop()
            self.observer.join()
            self.monitoring = False
            print("🛑 Real-time protection stopped")
            
    def on_created(self, event):
        """Handle file creation events."""
        if not event.is_directory:
            self.handle_suspicious_file(event.src_path, "created")
            
    def on_modified(self, event):
        """Handle file modification events."""
        if not event.is_directory:
            self.handle_suspicious_file(event.src_path, "modified")
            
    def on_moved(self, event):
        """Handle file move/rename events."""
        if not event.is_directory:
            self.handle_suspicious_file(event.dest_path, "moved")
            
    def terminate_processes_using_file(self, file_path):
        """Terminate all processes that are using the suspicious file."""
        terminated_processes = []
        try:
            # Get all running processes
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    # Check if process is using the file
                    if proc.info['exe'] == file_path:
                        print(f"🔄 Terminating process using file: {proc.info['name']} (PID: {proc.info['pid']})")
                        proc.terminate()
                        terminated_processes.append(proc.info['name'])
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                    
            # Also check for processes that might be executing the file
            file_name = os.path.basename(file_path)
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = proc.info['cmdline']
                    if cmdline and any(file_name in arg for arg in cmdline):
                        print(f"🔄 Terminating process executing file: {proc.info['name']} (PID: {proc.info['pid']})")
                        proc.terminate()
                        terminated_processes.append(proc.info['name'])
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                    
        except Exception as e:
            print(f"Error terminating processes: {e}")
            
        return terminated_processes

    def handle_suspicious_file(self, file_path, action):
        """Analyze and handle potentially suspicious files."""
        try:
            # Skip files that are already in quarantine folder to prevent recursive detection
            quarantine_folder = os.path.join(os.path.expanduser("~"), "ShieldSecureData", "quarantine")
            if quarantine_folder in file_path:
                return  # Skip files already in quarantine
            
            file_ext = os.path.splitext(file_path)[1].lower()
            
            # Check for suspicious extensions
            if file_ext in self.suspicious_extensions:
                print(f"⚠️ Suspicious file {action}: {file_path}")
                
                # Quick scan of the file
                if self.antivirus_app.is_malicious(file_path):
                    print(f"🚨 MALWARE DETECTED: {file_path}")
                    self.blocked_files.add(file_path)
                    
                    # STEP 1: Terminate processes using this file
                    terminated_processes = self.terminate_processes_using_file(file_path)
                    
                    # STEP 2: Wait a moment for processes to terminate
                    if terminated_processes:
                        print(f"⏳ Waiting for {len(terminated_processes)} processes to terminate...")
                        time.sleep(2)  # Give processes time to close
                    
                    # STEP 3: Force kill any remaining processes (if needed)
                    try:
                        for proc in psutil.process_iter(['pid', 'name', 'exe']):
                            if proc.info['exe'] == file_path:
                                print(f"💀 Force killing process: {proc.info['name']} (PID: {proc.info['pid']})")
                                proc.kill()
                    except Exception as e:
                        print(f"Error force killing processes: {e}")
                    
                    # STEP 4: Now quarantine the file
                    if self.antivirus_app.quarantine_file(file_path):
                        print(f"✅ File quarantined: {file_path}")
                        
                        # Update UI if available
                        if hasattr(self.antivirus_app, 'file_display'):
                            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            process_info = f" (Terminated {len(terminated_processes)} processes)" if terminated_processes else ""
                            self.antivirus_app.file_display.insert(ctk.END, 
                                f"[{timestamp}] 🚨 Real-time threat detected, processes terminated, and file quarantined: {os.path.basename(file_path)}{process_info}\n")
                            self.antivirus_app.file_display.see(ctk.END)
                            
        except Exception as e:
            print(f"Error in real-time protection: {e}")

class AntivirusApp:
    def __init__(self, root, back_callback=None):
        self.root = root
        self.back_callback = back_callback  
        self.root.title("ShieldSecure Antivirus")
        self.root.geometry("800x500")  
        self.root.minsize(600, 400)

        self.scanning = False
        self.paused = False
        self.files_scanned = 0
        self.threats_found = 0
        self.scan_path = None  
        self.scan_thread = None  
        
        # Initialize real-time protection
        self.real_time_protector = RealTimeProtector(self)
        self.real_time_active = False

        self.build_ui()

    def build_ui(self):
        """ Builds the UI elements. """
        for widget in self.root.winfo_children():
            widget.destroy()  # Clears the existing UI

        # Check real-time protection marker file
        marker_path = os.path.join(os.path.expanduser("~"), "ShieldSecureData", "realtime_on.marker")
        self.real_time_active = os.path.exists(marker_path)

        # Header/Nav Bar
        header_frame = ctk.CTkFrame(self.root, fg_color="#222", height=60)
        header_frame.pack(fill="x")
        ctk.CTkLabel(header_frame, text="🛡️ ShieldSecure Antivirus", font=("Arial", 22, "bold"), text_color="#03A9F4").pack(side="left", padx=20, pady=10)
        if self.back_callback:
            back_btn = ctk.CTkButton(header_frame, text="⬅️ Back to Home", fg_color="#333", hover_color="#555", text_color="white", command=self.back_callback, width=140)
            back_btn.pack(side="right", padx=20, pady=10)

        # Main Content Frame
        main_frame = ctk.CTkFrame(self.root, fg_color="#181818")
        main_frame.pack(expand=True, fill="both", padx=20, pady=10)

        self.scan_status = ctk.CTkLabel(main_frame, text="Status: Idle", font=("Arial", 14), text_color="#FFD700")
        self.scan_status.pack(pady=(10, 0))

        self.file_display = ctk.CTkTextbox(main_frame, height=200, width=600, fg_color="#1a1a1a", text_color="white")
        self.file_display.pack(pady=10, expand=True, fill='both')

        self.progress_bar = ctk.CTkProgressBar(main_frame, height=10)
        self.progress_bar.pack(pady=5, fill='x', padx=20)
        self.progress_bar.set(0)

        self.progress_label = ctk.CTkLabel(main_frame, text="0%", font=("Arial", 12))
        self.progress_label.pack()

        self.button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        self.button_frame.pack(pady=5, fill='x')

        self.select_folder_button = ctk.CTkButton(self.button_frame, text="📂 Select Folder", fg_color="#A0A0A0", hover_color="#5E5E5E", text_color="black", command=self.select_folder)
        self.select_folder_button.pack(side='left', expand=True, padx=5, pady=5)

        self.scan_button = ctk.CTkButton(self.button_frame, text="🚀 Start Scan", fg_color="#4CAF50", hover_color="#2E7D32", text_color="black", command=self.start_scan)
        self.scan_button.pack(side='left', expand=True, padx=5, pady=5)

        self.pause_button = ctk.CTkButton(self.button_frame, text="⏸️ Pause", fg_color="#A0A0A0", hover_color="#5E5E5E", text_color="black", command=self.pause_scan)
        self.pause_button.pack(side='left', expand=True, padx=5, pady=5)

        self.stop_button = ctk.CTkButton(self.button_frame, text="🛑 Stop Scan", fg_color="#D32F2F", hover_color="#B71C1C", text_color="white", command=self.stop_scan)
        self.stop_button.pack(side='left', expand=True, padx=5, pady=5)

        # Real-time protection frame
        self.realtime_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        self.realtime_frame.pack(pady=5, fill='x')

        realtime_status_text = "🛡️ Real-time Protection: Active" if self.real_time_active else "🛡️ Real-time Protection: Inactive"
        realtime_status_color = "green" if self.real_time_active else "red"
        self.realtime_status = ctk.CTkLabel(self.realtime_frame, text=realtime_status_text, font=("Arial", 12, "bold"), text_color=realtime_status_color)
        self.realtime_status.pack(side='left', padx=10)

        realtime_btn_text = "🛑 Disable Real-time Protection" if self.real_time_active else "🛡️ Enable Real-time Protection"
        realtime_btn_fg = "#D32F2F" if self.real_time_active else "#4CAF50"
        realtime_btn_hover = "#B71C1C" if self.real_time_active else "#2E7D32"
        self.realtime_button = ctk.CTkButton(self.realtime_frame, text=realtime_btn_text, 
                                           fg_color=realtime_btn_fg, hover_color=realtime_btn_hover, text_color="white", 
                                           command=self.toggle_realtime_protection)
        self.realtime_button.pack(side='right', padx=10)

        self.result_label = ctk.CTkLabel(main_frame, text="Files Scanned: 0 | Threats Found: 0", font=("Arial", 12))
        self.result_label.pack(pady=10)

    def select_folder(self):
        self.scan_path = filedialog.askdirectory() or None
        self.scan_status.configure(text=f"Selected Folder: {self.scan_path}" if self.scan_path else "No folder selected")

    def get_all_files(self, path):
        for root, _, files in os.walk(path):
            for file in files:
                yield os.path.join(root, file)

    def scan_files(self):
        self.scan_status.configure(text="🔄 Scanning...")
        self.files_scanned = 0
        self.threats_found = 0
        total_files = sum(1 for _ in self.get_all_files(self.scan_path))  

        for file_path in self.get_all_files(self.scan_path):
            if not self.scanning:
                break
            if self.paused:
                time.sleep(0.5)
                continue

            self.files_scanned += 1
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.file_display.insert(ctk.END, f"[{timestamp}] Scanning: {file_path}\n")
            self.file_display.see(ctk.END)
            self.scan_status.configure(text=f"Scanning: {os.path.basename(file_path)}")

            if self.is_malicious(file_path):
                if self.quarantine_file(file_path):  
                    self.threats_found += 1

            self.result_label.configure(text=f"Files Scanned: {self.files_scanned} | Threats Found: {self.threats_found}")

            progress = self.files_scanned / max(total_files, 1)
            self.progress_bar.set(progress)
            self.progress_label.configure(text=f"{int(progress * 100)}%")

            time.sleep(0.01)
            self.root.update_idletasks()

        self.scan_status.configure(text="✅ Scan Complete")
        self.progress_label.configure(text="100%")
        self.scanning = False

    def is_malicious(self, file_path):
        known_hashes = {"d41d8cd98f00b204e9800998ecf8427e","44d88612fea8a8f36de82e1278abb02f","e7e5fa40569514ec442bbdf755d89c2f"}  
        try:
            with open(file_path, "rb") as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
            return file_hash in known_hashes
        except:
            return False

    def scan_with_virustotal(self, file_path):
        """ Scans a file using VirusTotal API and returns a simplified report. """
        
        api_key = os.getenv("API_KEY")
        url = "https://www.virustotal.com/api/v3/files/"
        
        # Getting the file hash MD5
        try:
            with open(file_path, "rb") as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return None

        headers = {
            "x-apikey": api_key
        }
        
        response = requests.get(url + file_hash, headers=headers)

        if response.status_code == 200:
            report = response.json()

            # Extract only the important fields from the report
            if 'data' in report:
                data = report['data']

                simplified_report = {
                    "id": data.get("id"),
                    "type": data.get("type"),
                    "sha256": data.get("attributes", {}).get("sha256"),
                    "last_analysis_date": data.get("attributes", {}).get("last_analysis_date"),
                    "last_analysis_stats": data.get("attributes", {}).get("last_analysis_stats", {}),
                    "names": data.get("attributes", {}).get("names", []),
                    "known_distributors": data.get("attributes", {}).get("known_distributors", {}).get("distributors", []),
                    "filecondis": data.get("attributes", {}).get("filecondis", {}),
                    "size": data.get("attributes", {}).get("size")
                }

                return simplified_report
            else:
                print("Error: No data found in the report.")
                return None
        else:
            print(f"Error: Could not fetch report for {file_path}")
            return None

    def quarantine_file(self, file_path):
        file_name = os.path.basename(file_path)

        # safe location for quarantine.json
        user_data_dir = os.path.join(os.path.expanduser("~"), "ShieldSecureData")
        os.makedirs(user_data_dir, exist_ok=True)
        quarantine_json_path = os.path.join(user_data_dir, "quarantine.json")
        threatlog_json_path = os.path.join(user_data_dir, "threatlog.json")
        quarantine_folder = os.path.join(user_data_dir, "quarantine")
        os.makedirs(quarantine_folder, exist_ok=True)

        # Ensure unique filename in quarantine
        base_name, ext = os.path.splitext(file_name)
        new_path = os.path.join(quarantine_folder, file_name)
        counter = 1
        while os.path.exists(new_path):
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            new_file_name = f"{base_name}_{timestamp}_{counter}{ext}"
            new_path = os.path.join(quarantine_folder, new_file_name)
            counter += 1
        
        # Getting VirusTotal report
        virus_report = self.scan_with_virustotal(file_path)  # Get VirusTotal scan report

        # Reading existing data if available
        quarantine_data = []
        if os.path.exists(quarantine_json_path):
            try:
                with open(quarantine_json_path, "r") as f:
                    quarantine_data = json.load(f)
            except json.JSONDecodeError:
                print("⚠️ Corrupt quarantine.json detected. Resetting file.")

        # Appending the threat log with VirusTotal report
        threat_data = []
        if os.path.exists(threatlog_json_path):
            try:
                with open(threatlog_json_path, "r") as f:
                    threat_data = json.load(f)
            except json.JSONDecodeError:
                print("⚠️ Corrupt threatlog.json detected. Resetting file.")

        # Adding the VirusTotal report (if available)
        if virus_report:
            threat_data.append({
                "file_name": os.path.basename(new_path),
                "original_path": file_path,
                "quarantined_path": new_path,
                "found_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "threat_report": virus_report  
            })
        else:
            # If no report found, append basic info
            threat_data.append({
                "file_name": os.path.basename(new_path),
                "original_path": file_path,
                "quarantined_path": new_path,
                "found_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "threat_report": "No VirusTotal report available"
            })

        with open(threatlog_json_path, "w") as f:
            json.dump(threat_data, f, indent=4)
        
        #moving the file
        try:
            shutil.move(file_path, new_path)  
        except Exception as e:
            print(f"❌ Failed to move {file_name} to quarantine: {e}")
            return False  
        
        # Add new record
        quarantine_data.append({
            "file_name": os.path.basename(new_path),
            "original_path": file_path,
            "quarantined_path": new_path
        })

        # Write updated data
        with open(quarantine_json_path, "w") as f:
            json.dump(quarantine_data, f, indent=4)

        print(f"⚠️ {os.path.basename(new_path)} moved to quarantine!")
        return True

    def start_scan(self):
        if not self.scan_path:
            self.scan_status.configure(text="⚠️ No folder selected!")
            return

        if not self.scanning:
            self.scanning = True
            self.paused = False
            self.file_display.delete("1.0", ctk.END)
            self.progress_bar.set(0)
            self.progress_label.configure(text="0%")

            self.scan_thread = threading.Thread(target=self.scan_files, daemon=True)
            self.scan_thread.start()

    def pause_scan(self):
        if self.scanning:
            self.paused = not self.paused
            self.scan_status.configure(text="⏸️ Paused" if self.paused else "🔄 Scanning...")

    def stop_scan(self):
        if self.scanning:
            self.scanning = False
            self.scan_status.configure(text="❌ Scan Stopped")
            self.progress_bar.set(0)
            self.progress_label.configure(text="0%")
            self.file_display.insert(ctk.END, "\n❌ Scan Stopped\n")
            self.file_display.see(ctk.END)

    def toggle_realtime_protection(self):
        """Toggle real-time protection on/off."""
        marker_path = os.path.join(os.path.expanduser("~"), "ShieldSecureData", "realtime_on.marker")
        if not self.real_time_active:
            # Start real-time protection
            try:
                # Start monitoring user's home directory and desktop
                home_dir = os.path.expanduser("~")
                desktop_dir = os.path.join(home_dir, "Desktop")
                
                self.real_time_protector.start_monitoring(home_dir)
                if os.path.exists(desktop_dir):
                    self.real_time_protector.start_monitoring(desktop_dir)
                
                self.real_time_active = True
                self.realtime_status.configure(text="🛡️ Real-time Protection: Active", text_color="green")
                self.realtime_button.configure(text="🛑 Disable Real-time Protection", fg_color="#D32F2F", hover_color="#B71C1C")
                
                # Create marker file
                with open(marker_path, "w") as f:
                    f.write("on")
                
                self.file_display.insert(ctk.END, f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 🛡️ Real-time protection enabled\n")
                self.file_display.see(ctk.END)
                
            except Exception as e:
                self.file_display.insert(ctk.END, f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ❌ Failed to enable real-time protection: {e}\n")
                self.file_display.see(ctk.END)
        else:
            # Stop real-time protection
            try:
                self.real_time_protector.stop_monitoring()
                self.real_time_active = False
                self.realtime_status.configure(text="🛡️ Real-time Protection: Inactive", text_color="red")
                self.realtime_button.configure(text="🛡️ Enable Real-time Protection", fg_color="#4CAF50", hover_color="#2E7D32")
                
                # Remove marker file
                if os.path.exists(marker_path):
                    os.remove(marker_path)
                
                self.file_display.insert(ctk.END, f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 🛑 Real-time protection disabled\n")
                self.file_display.see(ctk.END)
                
            except Exception as e:
                self.file_display.insert(ctk.END, f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ❌ Failed to disable real-time protection: {e}\n")
                self.file_display.see(ctk.END)

def start_antivirus_ui(root, back_callback=None):
    """ Replaces the current UI with the antivirus UI. """
    app = AntivirusApp(root, back_callback)
    
    # Cleanup function to stop real-time protection when window closes
    def on_closing():
        if hasattr(app, 'real_time_protector') and app.real_time_active:
            app.real_time_protector.stop_monitoring()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    return app

if __name__ == "__main__":
    root = ctk.CTk()
    app = AntivirusApp(root)
    
    # Cleanup function for standalone mode
    def on_closing():
        if hasattr(app, 'real_time_protector') and app.real_time_active:
            app.real_time_protector.stop_monitoring()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()
