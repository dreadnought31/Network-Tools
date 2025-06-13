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
Run in PowerShell (from the repo folder):

powershell -ExecutionPolicy Bypass -File .\network-tools.ps1
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

