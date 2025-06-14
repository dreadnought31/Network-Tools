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

![image](https://github.com/user-attachments/assets/41a4e727-9b1a-4d3f-874e-2ae69d38a554)

![image](https://github.com/user-attachments/assets/bf2fe1c9-8a5a-4a5f-a626-25ebb2a63246)

![image](https://github.com/user-attachments/assets/937af3f6-f31f-4240-aea1-54ff56ee8d95)

![image](https://github.com/user-attachments/assets/ea352495-39d9-4066-84ca-7c2099fb06bb)

![image](https://github.com/user-attachments/assets/40ba02cf-6f2b-4787-b8f4-c9530fa95032)

