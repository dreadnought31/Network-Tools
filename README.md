# Windows Network Tools GUI

A PowerShell GUI toolkit for rapid network and firewall diagnostics, management, and troubleshooting.  
**Created by Alan O'Brien**

---

## Features

- **Host Tools**: Ping, Traceroute, Nmap, Test-NetConnection, Nslookup
- **Local Tools**: Interface checks, routes, event logs, DNS cache, ARP, TCP/UDP connections, network shares, and more
- **Firewall Tools**: View status, enable/disable, rule management, export/import, logging, ICMP controls—all PowerShell native
- **Tooltips and friendly UI**
- **No admin install required—just run in an elevated PowerShell terminal**
Run in PowerShell (from the repo folder): powershell -ExecutionPolicy Bypass -File .\network-tools.ps1

---

## Requirements

- Windows 10/11 (PowerShell 5.1+) or Windows Server 2016+
- PowerShell execution policy:  
  `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser`
- **Optional:** [Nmap](https://nmap.org/download.html) in your PATH for Nmap features
- Run as Administrator for firewall changes and some local network commands

---

## Usage

1. **Clone or Download**
   ```sh
   git clone https://github.com/YOURNAME/windows-network-tools-gui.git

Enjoy!

Note: Some buttons (especially on the Firewall tab) require admin privileges to take effect.

![image](https://github.com/user-attachments/assets/a226c60e-6fed-4cee-bdbf-590c57f25e4c)

![image](https://github.com/user-attachments/assets/d4da4862-6ff7-462f-a9b8-0c188bc020e6)

![image](https://github.com/user-attachments/assets/60ba1f93-f305-49c7-a5c6-9804dd77537b)
