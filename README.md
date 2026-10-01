
# 🛡️ ShieldSecure Antivirus Software

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)

![Platform](https://img.shields.io/badge/Platform-Windows-informational?logo=windows)

![Status](https://img.shields.io/badge/Status-Active-brightgreen)

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](./LICENSE)



🖥️ A Python-based desktop antivirus that performs real-time scanning, threat logging, and quarantine management using a clean GUI built with `customtkinter`.




## ✨ Recent Improvements

- **Real-Time Protection:** Monitors your system in real time for suspicious files and automatically quarantines threats as they appear, using the `watchdog` library.
- **Process Termination:** Uses `psutil` to safely terminate processes using suspicious files before quarantine.
- **Robust Quarantine Handling:** Prevents recursive quarantine, ensures unique filenames, and keeps quarantine and logs in sync.
- **Dynamic Dashboard:** Displays real-time protection status, threat count, and system health dynamically.
- **UI/UX Enhancements:** Consistent "ShieldSecure" branding, professional modern UI, centered confirmation popups, and instant UI updates after actions.
- **Testing Suite:** All test scripts and documentation are now organized in a `tests/` folder. Safe test scripts simulate malware detection without risk.
- **.venv in .gitignore:** Ensures the virtual environment is not committed to the repository.

## 🧩 Features


- ⚡ Quick Scan & Full Scan options   
- 🧼 Quarantine and Restore functionality  
- 📝 JSON-based Threat Logs  
- 🎨 User-friendly Python GUI with `customtkinter`  
- 🧠 Uses extension and hash-based threat detection
- 🛡️ **Real-Time Protection** (auto quarantine of threats as they appear)
- 🔒 **Process Termination** before quarantine
- 📊 **Dynamic Dashboard** with real-time status and health
- 🗃️ **Robust Quarantine** (prevents recursion, unique filenames, instant UI updates)
- 🧪 **Safe Testing Suite** in `tests/` folder

## 🚀 Getting Started

### 🧾 Clone the Repository  
    
    git clone https://github.com/yourusername/shieldguard-antivirus.git
    cd shieldguard-antivirus
    

## 📦 Libraries Installation

To install the required libraries for running this project, use the following command:

```bash
pip install python-dotenv customtkinter
```

### 🖥️ Launch the Antivirus Dashboard

To start the ShieldGuard Antivirus application with the GUI, run:

```bash
python shieldsecure.py
```
This will open the main dashboard built with `customtkinter`.

## 📦 Built With

- [Python 3.x](https://www.python.org/) – Core language used
- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) – Modern Python UI framework
- Standard Libraries:
  - `os`
  - `hashlib`
  - `json`
  - `datetime`
  - `threading`
  - `tkinter`

## 🧪 Detection Capabilities

This antivirus tool is designed for demonstration and educational purposes. It detects:

- 🗂️ **Empty files** (0-byte) as suspicious.
- 💣 **EICAR Standard Test File** — a safe test string used to simulate virus detection.

To test with Empty File:

1. Open **Notepad** (or any text editor).
2. Without typing anything, click **File** → **Save As**.
3. Save the file with any name (e.g., `empty.txt`).
4. Run the antivirus scan — the tool should flag this file as suspicious due to its empty content.

>⚠️ This is a basic test used to simulate scanning behavior. Empty files are treated as suspicious for demonstration purposes.

To test EICAR detection:

1. Open **Notepad**.
2. Paste the following line exactly:

    ```
    X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
    ```

3. Save it as `testvirus.txt`.
4. Run the antivirus scan — the tool should flag this file as suspicious.

> 🛡️ This test file is **not harmful** and is widely used to verify antivirus functionality without risk.

> 🧪 **Testing Suite:**
> - All test scripts and documentation are now in the `tests/` folder.
> - Safe test scripts simulate malware detection and can be used without risk to your system.

## 📸  ShieldSecure GUI Screenshots

<table>
  <tr>
    <td align="center">
      <img src="https://github.com/user-attachments/assets/4b6b357f-d3fc-4314-9362-6dca2b0e4228" width="400"/><br/>
      <strong>GUI Dashboard</strong>
    </td>
    <td align="center">
      <img src="https://github.com/user-attachments/assets/b619c358-ee54-4a09-b7d9-cac58263c20a" width="400"/><br/>
      <strong>Real-Time Protection</strong>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="https://github.com/user-attachments/assets/c8c1a1ef-7af7-4219-aa67-5c5ea6c3d8a5" width="400"/><br/>
      <strong>Quarantine Section</strong>
    </td>
    <td align="center">
      <img src="https://github.com/user-attachments/assets/668fb1e2-e9d5-4f97-99c8-4dbb433e828b" width="400"/><br/>
      <strong>Threat Logs</strong>
    </td>
  </tr>
  <tr>
    <td align="center" colspan="2">
      <img src="https://github.com/user-attachments/assets/44b59fb5-ca85-43e9-824f-0b8675153099" width="400"/><br/>
      <strong>Threat Report</strong>
    </td>
  </tr>
</table>


---



## 🧩 API Reference

### 🔍 VirusTotal Public API

This project integrates the [VirusTotal Public API](https://www.virustotal.com/gui/home/search) to enhance malware detection capabilities by scanning file hashes against a large virus signature database.

To use the API:

1. Create a free account at [virustotal.com](https://www.virustotal.com).
2. Go to your profile > API key.
3. Copy the key and store it in a `.env` file as:
   ```env
   API_KEY=your_api_key_here
   ```
4. The app will automatically load this key using `python-dotenv`.
> ⚠️ Note: VirusTotal has rate limits for free users (4 requests per minute).


## 🧪 Future Improvements

- 🧠 AI-based threat detection (ML integration)
- 🌐 Cloud upload of logs
- 📊 Detailed scanning analytics dashboard


## 🤝 Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you'd like to change.
## 📜 License

This project is licensed under the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html) – see the [LICENSE](LICENSE) file for details.
