# WiFi Security Auditor

A Python-based WiFi and local network security auditing tool designed to run in Termux on Android.

The project is currently under active development.

## Features

- Display current WiFi connection information
- Scan nearby WiFi networks
- Analyse WiFi security settings
- Detect channel congestion and overlapping networks
- Configure and validate the local LAN
- Discover devices on the local network
- Perform TCP service discovery
- Analyse individual network devices
- Analyse the router/gateway
- Identify common network services
- Perform safe HTTP and HTTPS inspection
- Inspect TLS versions and certificates
- Identify certificate SAN/IP mismatches
- Detect authentication-related web interfaces
- Identify devices such as routers, Proxmox, TrueNAS and other network equipment
- Track devices across network audits
- Detect service and port changes
- Compare audits against a saved network baseline
- Perform password strength checks
- Generate security findings and reports

## Requirements

The auditor is designed for Termux on Android.

Install the required Termux packages:

```bash
pkg update
pkg install python termux-api iproute2
