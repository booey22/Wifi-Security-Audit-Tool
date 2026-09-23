# WiFi Security Auditor

A cross-platform Python WiFi and local network security auditing tool for Windows and Termux on Android.

The project is currently under active development.

## Features

- Display current WiFi connection information
- Scan nearby WiFi networks
- Analyse WiFi security settings
- Detect channel congestion and overlapping networks
- Configure and validate the local LAN
- Discover devices using ICMP and fixed TCP service checks
- Analyse individual network devices
- Analyse the router or gateway
- Identify common network services
- Perform safe HTTP and HTTPS inspection
- Inspect TLS versions and certificates
- Identify certificate SAN/IP mismatches
- Detect authentication-related web interfaces
- Identify common device types such as routers, printers, IP cameras, game consoles, Proxmox and TrueNAS
- Track devices across network audits
- Detect service and port changes
- Compare audits against a saved network baseline
- Perform password strength checks
- Generate security findings and reports
- Support local device labels

## Supported Platforms

- Windows 10 and Windows 11
- Termux on Android

The same `wifi_auditor.py` codebase is used on both platforms.

## Windows

Check that Python is installed:

```powershell
python --version
Clone the repository:
Git clone https://github.com/booey22/Wifi-Security-Audit-Tool.git
cd Wifi-Security-Audit-Tool
python wifi_auditor.py

Windows Notes
Windows WiFi information is collected using built-in Windows networking tools.
Depending on the WiFi driver, some details such as channel width, WPS state or PMF state may not be reported by Windows. When information is unavailable, the auditor reports it as unknown rather than guessing.

## Termux/Android 

Check that Python is installed:

'''shell
python
Install the required packages:
pkg update
pkg install python git termux-api iproute2
Clone the repository:
git clone https://github.com/booey22/Wifi-Security-Audit-Tool.git
cd Wifi-Security-Audit-Tool
python wifi_auditor.py

Android Notes
Recent Android versions restrict access to some routing, ARP and network interface information.
Because of this, the auditor may ask you to manually provide:
- Local network CIDR, for example 192.168.1.0/24
- Router or gateway IPv4 address, for example 192.168.1.1
Use values supplied by your own router or network configuration. Do not guess the subnet.
Some device MAC-address information may also be restricted by Android.


## Data
The auditor may create local runtime files including:
- wifi_auditor_baseline.json
- wifi_auditor_history.json
- wifi_auditor_lan_config.json
- wifi_auditor_device_labels.json

Safety and Authorised Use
Use this tool only on networks and devices that you own or are explicitly authorised to audit.
The project focuses on defensive network inspection and does not perform automatic password guessing, credential stuffing, authentication bypass or exploitation.
Development Status
This project is under active development.
Current builds have been tested on:
- Windows
- Termux on Android


Development by Boeey22 Aka Bug-a-Boo Cybersecurity Professional build out of Curiosity 