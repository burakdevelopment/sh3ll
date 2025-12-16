# SH3LL: IP Camera Discovery and Security Analysis Tool

![Version](https://img.shields.io/badge/version-v2.0-blue.svg) ![License](https://img.shields.io/badge/license-MIT-green.svg) ![Python](https://img.shields.io/badge/python-3.8+-brightgreen.svg) ![Platform](https://img.shields.io/badge/platform-Linux%20|%20Windows%20(WSL)-orange.svg)

**SH3LL** is an all-in-one security tool that not only discovers IP cameras and similar IoT devices on your network but also proactively analyzes their security posture. Leveraging an asynchronous architecture for high-speed scanning, it performs vulnerability analysis and penetration testing operations on the devices it finds.

![image](https://github.com/user-attachments/assets/81cebc3e-7cb6-44d9-9414-79e051cb2ae9)

## 📑 Table of Contents
- [Purpose of the Tool](#-purpose-of-the-tool)
- [Key Features](#-key-features)
- [Legal and Ethical Disclaimer](#️-legal-and-ethical-disclaimer)
- [Installation](#-installation)
  - [Prerequisites](#prerequisites)
  - [Installation on Linux (Debian/Ubuntu)](#installation-on-linux-debianubuntu)
  - [Installation on Windows (Recommended via WSL)](#installation-on-windows-recommended-via-wsl)
- [Usage](#️-usage)
  - [First Run](#first-run)
  - [Menu Options](#menu-options)
- [Modularity and Extensibility](#-modularity-and-extensibility)
- [Contributing](#-contributing)
- [License](#-license)

## 🎯 Purpose of the Tool
This tool is developed for network administrators, penetration testers, and cybersecurity enthusiasts. Its primary purpose is to quickly and efficiently detect IP cameras and similar devices on a network and to reveal how vulnerable these devices are to known security flaws. CamSpector goes far beyond a simple port scanner by combining service detection, CVE (Common Vulnerabilities and Exposures) analysis, and modular exploit capabilities under a single roof.

## ✨ Key Features
-   ⚡ **High-Speed Asynchronous Scanning:** Scans hundreds of IP addresses in minutes, thanks to Python's `asyncio`.
-   📡 **Multi-Protocol Discovery:** Goes beyond port scanning with smart discovery via `SSDP (UPnP)`, `SNMP`, `ONVIF`, `RTSP`, and `HTTP` protocols.
-   🛡️ **Automatic CVE Checking:** Automatically queries the **National Vulnerability Database (NVD)** for known vulnerabilities (CVEs) based on the detected service information (e.g., Server header).
-   💥 **Modular Exploit System:** Provides the ability to attempt simple exploits for discovered vulnerabilities. You can easily extend the tool by adding your own exploit functions to the `exploits.py` file.
-   🔐 **Hydra Integration:** Can automatically launch brute-force attacks against HTTP interfaces using popular lists like `usernames.txt` and `rockyou.txt`.
-   🖥️ **Modern TUI:** Features a user-friendly command-line interface with progress bars, aesthetic tables, and colors, powered by the `rich` library.
-   💾 **Save Results:** Allows you to save all detailed scan results in `JSON` format for later analysis.

## ⚠️ Legal and Ethical Disclaimer
> **DISCLAIMER:** This tool is designed for **educational purposes** and for performing security audits on networks you are **legally authorized to test**. The use of this tool on systems for which you do not have permission is illegal and may lead to serious legal consequences. The developer is not responsible for any illegal or malicious use of this tool. **Use your power responsibly.**

## 🚀 Installation
### Prerequisites
- Python 3.8+
- `pip`
- `git`
- `hydra` (for brute-force attacks)
- `vlc` (optional, for opening RTSP streams)

### Installation on Linux (Debian/Ubuntu)
Linux is the recommended platform for using all features of this tool seamlessly.

1.  **Install Required Packages:**
    ```bash
    sudo apt update && sudo apt install -y python3 python3-pip git hydra vlc
    ```

2.  **Clone the Project:**
    ```bash
    git clone https://github.com/burakdevelopment/sh3ll
    cd sh3ll
    ```

3.  **Install Python Dependencies:**
    Inside the project directory, create a `requirements.txt` file with the following content:
    ```
    requests
    onvif_zeep
    rich
    aiohttp
    pysnmp
    zeep
    ```
    Then, run the installation:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Set Up the Configuration File:**
    Copy the example configuration file for your NVD API key and edit it.
    ```bash
    cp config.json.example config.json
    nano config.json
    ```
    Replace the placeholder `ENTER_YOUR_NVD_API_KEY_HERE` inside the file with your actual API key.

5.  **Set Up the Configuration File 2:**
    You also need to enter the NVD API Key in the cve_checker.py file.
    ```bash
    nano cve_checker.py
    ```
    Replace the line 9 `api-key` inside the file with your actual API key.

### Installation on Windows (Recommended via WSL)
Since native installation of tools like `hydra` on Windows can be challenging, using the **Windows Subsystem for Linux (WSL)** is highly recommended for the most stable and seamless experience.

1.  **Install WSL:**
    Open PowerShell as an administrator and run the command:
    ```powershell
    wsl --install
    ```
    After the installation is complete, restart your computer and set up a Linux distribution (e.g., Ubuntu).

2.  **Follow the Linux Steps:**
    Open the WSL terminal and follow steps 2, 3, and 4 from the **Installation on Linux** section above.

## 🛠️ Usage
### First Run
After completing all the necessary installations, you can start the program with the following command in the tool's directory:
```bash
python3 sh3ll.py
```

### Menu Options
#### Main Menu:
- **1. Scan Local Network:** Automatically scans the `/24` subnet the tool is running on (e.g., 192.168.1.0/24).
- **2. Scan Custom IP Range:** Scans a specific range you provide in CIDR format (e.g., 192.168.1.0/24).
- **3. Exit:** Terminates the program.

#### Post-Scan Action Menu:
After the scan is complete and devices are listed, you can perform the following actions based on the discovered services:
- **HTTP Brute-Force Attack:** Uses `hydra` to attempt to guess passwords for the target's HTTP interface. (Requires `usernames.txt` and `rockyou.txt`.)
- **Interact with ONVIF:** Attempts to retrieve information (model, manufacturer, RTSP URL) from the selected ONVIF device.
- **Open RTSP Stream:** Attempts to open the camera's stream using `vlc`.
- **View and Exploit Vulnerabilities:**
  - Lists the CVEs found on the NVD for the selected device.
  - If an exploit function is defined for a CVE in `exploits.py`, it notifies you and provides an option to attempt the exploit.

## 🧩 Modularity and Extensibility
sh3ll is designed with a modular structure for easy extension.

- **`config.json`**: Keeps sensitive and configuration data like API keys separate from the code.
- **`cve_checker.py`**: Contains all the NVD API communication logic. If you want to add a different vulnerability database (e.g., Exploit-DB API) in the future, you only need to modify this file.
- **`exploits.py`**: This is the heart of the tool's exploitation capabilities. To add a new exploit:
  1. Write an `async` function containing the exploit logic in the `exploits.py` file.
  2. Add your new function to the `EXPLOIT_REGISTRY` dictionary, mapping it to the target CVE ID.
  3. That's it! The tool will automatically flag this CVE as "Exploitable!" on the next scan and provide the option to run it.

## 🤝 Contributing
Contributions make the open-source community an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**. Feel free to fork the repo and submit a pull request. For bug reports or feature requests, please open an "Issue".

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📜 License
This project is distributed under the MIT License. See the `LICENSE` file for more information.
