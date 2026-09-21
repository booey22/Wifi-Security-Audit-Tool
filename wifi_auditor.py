#!/usr/bin/env python3

"""
WiFi Security Auditor Development
Termux / Android Edition

Authorised defensive network auditing tool.

V3.4:
    - Preserves V3.3.1 LAN and WiFi auditing behaviour
    - Adds contextual service exposure assessment
    - Adds WiFi channel observations
    - Integrates saved baseline comparison into full audits
    - Stores structured full-audit data for richer reports
    - Groups findings cleanly by category and severity
    - Persistent LAN configuration across upgrades
    - Supports migration from earlier V3.2/V3.3 configuration
    - Requires saved LAN configuration confirmation each session
    - Improved HTTP versus HTTPS management assessment
    - Separates primary device role from hosted applications
    - Improved Proxmox / FileBrowser identification
    - Improved ASUS / TrueNAS / TP-Link identification
    - Shows strongest approximately overlapping WiFi APs
    - Cleaner consolidated findings
    - TCP-only LAN discovery
    - Safe GET requests only
    - No credential submission
    - No brute forcing or exploitation
"""

import concurrent.futures
import datetime
import getpass
import html
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

from collections import Counter, defaultdict
from html.parser import HTMLParser


VERSION = "development"

# Keep this name stable in future versions.
LAN_CONFIG_FILE = "wifi_auditor_lan_config.json"

# Earlier possible configuration files.
LEGACY_CONFIG_FILES = [
    "wifi_auditor_lan_config_v33.json",
    "wifi_auditor_lan_config_v32.json",
]

BASELINE_FILE = "wifi_auditor_baseline.json"
HISTORY_FILE = "wifi_auditor_history.json"
LEGACY_BASELINES = [
    "wifi_auditor_baseline_v33.json",
]

REPORT_PREFIX = "wifi_audit"

DISCOVERY_PASSES = 2
DISCOVERY_TIMEOUT = 0.30
PORT_TIMEOUT = 0.50
HTTP_TIMEOUT = 4
MAX_DISCOVERY_HOSTS = 1024
MAX_HTTP_BYTES = 512 * 1024


SERVICE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    554: "RTSP",
    631: "IPP",
    1883: "MQTT",
    2869: "UPnP",
    3389: "RDP",
    5000: "HTTP",
    5001: "HTTPS",
    5900: "VNC",
    8000: "HTTP",
    8006: "HTTPS",
    8080: "HTTP",
    8081: "HTTP",
    8443: "HTTPS",
    9000: "HTTP",
    9100: "Printer",
}


DISCOVERY_PORTS = sorted(SERVICE_PORTS)

HTTPS_PORTS = {
    443,
    5001,
    8006,
    8443,
}

WEB_PORTS = {
    80,
    443,
    5000,
    5001,
    8000,
    8006,
    8080,
    8081,
    8443,
    9000,
}

RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

SESSION_LAN = None
AUDIT_FINDINGS = []
LAST_AUDIT = None


# ============================================================
# DISPLAY
# ============================================================

def version_display_name():
    if str(VERSION).lower() == "development":
        return "DEVELOPMENT"
    return f"V{VERSION}"


def heading(text):
    print()
    print("=" * 72)
    print(text)
    print("=" * 72)


def subheading(text):
    print()
    print(text)
    print("-" * len(text))


def now_string():
    return datetime.datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def timestamp_filename():
    return datetime.datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )


# ============================================================
# AUDIT_FINDINGS
# ============================================================

def clear_findings():
    global AUDIT_FINDINGS
    AUDIT_FINDINGS = []
LAST_AUDIT = None


def add_finding(level, category, message, device=None):

    finding = {
        "level": level.upper(),
        "category": category,
        "message": message,
        "device": device,
    }

    identity = (
        finding["level"],
        finding["category"],
        finding["message"],
        finding["device"],
    )

    for existing in AUDIT_FINDINGS:

        existing_identity = (
            existing["level"],
            existing["category"],
            existing["message"],
            existing["device"],
        )

        if existing_identity == identity:
            return

    AUDIT_FINDINGS.append(finding)


def show_findings():

    heading("SECURITY FINDINGS")

    if not AUDIT_FINDINGS:
        print("No findings were recorded.")
        return

    level_order = {
        "CAUTION": 0,
        "INFO": 1,
        "OK": 2,
    }

    categories = {}

    for finding in AUDIT_FINDINGS:
        categories.setdefault(
            finding["category"],
            [],
        ).append(finding)

    for category in sorted(categories):

        print()
        print(category)
        print("-" * len(category))

        findings = sorted(
            categories[category],
            key=lambda item: (
                level_order.get(item["level"], 9),
                item["device"] or "",
                item["message"],
            ),
        )

        for finding in findings:

            target = ""

            if finding["device"]:
                target = f"{finding['device']}: "

            print(
                f"[{finding['level']}] "
                f"{target}{finding['message']}"
            )


# ============================================================
# COMMAND HELPERS
# ============================================================

def command_exists(command):
    return shutil.which(command) is not None


def run_command(args, timeout=15):

    try:

        result = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )

        return {
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode,
            "timeout": False,
        }

    except subprocess.TimeoutExpired:

        return {
            "stdout": "",
            "stderr": "Command timed out",
            "returncode": 124,
            "timeout": True,
        }

    except Exception as exc:

        return {
            "stdout": "",
            "stderr": str(exc),
            "returncode": -1,
            "timeout": False,
        }


def run_json_command(args, timeout=20):

    result = run_command(
        args,
        timeout,
    )

    if result["timeout"]:
        return None, "Command timed out"

    output = result["stdout"].strip()

    if not output:
        return None, result["stderr"] or "No output returned"

    try:
        data = json.loads(output)

    except json.JSONDecodeError:
        return None, "Command returned invalid JSON"

    # Termux API can return {"error": "..."} with exit code 0.
    if isinstance(data, dict) and data.get("error"):
        return None, str(data["error"])

    return data, None


def is_android():

    return bool(
        os.environ.get("ANDROID_ROOT")
        or os.environ.get("ANDROID_DATA")
        or os.path.exists("/system/build.prop")
    )


def is_termux():

    prefix = os.environ.get("PREFIX", "")

    return (
        "com.termux" in prefix
        or "/data/data/com.termux/" in prefix
    )


# ============================================================
# IP VALIDATION
# ============================================================

def valid_ipv4(value):

    try:
        ipaddress.IPv4Address(value)
        return True

    except Exception:
        return False


def private_ipv4(value):

    try:
        address = ipaddress.IPv4Address(value)

    except Exception:
        return False

    return any(
        address in network
        for network in RFC1918_NETWORKS
    )


def private_network(network):

    return any(
        network.subnet_of(private)
        for private in RFC1918_NETWORKS
    )


def valid_mac(mac):

    if not mac:
        return False

    if mac.lower() == "02:00:00:00:00:00":
        return False

    return bool(
        re.fullmatch(
            r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}",
            mac,
        )
    )


# ============================================================
# WIFI FREQUENCY
# ============================================================

def frequency_to_channel(freq):

    try:
        freq = int(freq)

    except Exception:
        return None

    if freq == 2484:
        return 14

    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5

    if 5000 <= freq <= 5895:
        return (freq - 5000) // 5

    if freq == 5935:
        return 2

    if 5955 <= freq <= 7115:
        return (freq - 5950) // 5

    return None


def frequency_to_band(freq):

    try:
        freq = int(freq)

    except Exception:
        return "Unknown"

    if 2400 <= freq < 2500:
        return "2.4 GHz"

    if 4900 <= freq < 5925:
        return "5 GHz"

    if 5925 <= freq <= 7125:
        return "6 GHz"

    return "Unknown"


def signal_quality(rssi):

    try:
        rssi = int(rssi)

    except Exception:
        return "Unknown"

    if rssi >= -50:
        return "Excellent"

    if rssi >= -60:
        return "Very good"

    if rssi >= -67:
        return "Good"

    if rssi >= -75:
        return "Fair"

    if rssi >= -85:
        return "Weak"

    return "Very weak"


# ============================================================
# WIFI SECURITY
# ============================================================

def classify_wifi_security(capabilities):

    caps = (capabilities or "").upper()

    result = {
        "security": "Unknown",
        "enterprise": False,
        "wps": "[WPS]" in caps,
        "pmf_required": "MFPR" in caps,
        "pmf_capable": "MFPC" in caps,
        "cipher": "Unknown",
    }

    if "GCMP-256" in caps:
        result["cipher"] = "GCMP-256"

    elif "CCMP" in caps:
        result["cipher"] = "CCMP/AES"

    elif "TKIP" in caps:
        result["cipher"] = "TKIP"

    has_sae = "SAE" in caps
    has_psk = "PSK" in caps
    has_eap = "EAP" in caps

    if has_eap:

        result["enterprise"] = True

        if has_sae:
            result["security"] = "WPA3-Enterprise/Mixed"

        else:
            result["security"] = "WPA2-Enterprise"

    elif has_sae and has_psk:

        result["security"] = "WPA2/WPA3-Personal"

    elif has_sae:

        result["security"] = "WPA3-Personal"

    elif has_psk:

        if "WPA2" in caps or "RSN" in caps:
            result["security"] = "WPA2-Personal"

        else:
            result["security"] = "WPA-Personal"

    elif "WEP" in caps:

        result["security"] = "WEP"

    elif (
        "[ESS]" in caps
        and "WPA" not in caps
        and "RSN" not in caps
        and "SAE" not in caps
        and "PSK" not in caps
        and "EAP" not in caps
        and "WEP" not in caps
    ):

        result["security"] = (
            "Open (no WPA/RSN advertised)"
        )

    return result


# ============================================================
# TERMUX WIFI API
# ============================================================

def get_wifi_connection():

    if not command_exists("termux-wifi-connectioninfo"):

        return None, (
            "termux-wifi-connectioninfo is not installed"
        )

    data, error = run_json_command(
        ["termux-wifi-connectioninfo"],
        timeout=15,
    )

    if error:
        return None, error

    if not isinstance(data, dict):
        return None, "Unexpected WiFi information"

    return data, None


def scan_nearby_wifi():

    if not command_exists("termux-wifi-scaninfo"):

        return None, (
            "termux-wifi-scaninfo is not installed"
        )

    data, error = run_json_command(
        ["termux-wifi-scaninfo"],
        timeout=25,
    )

    if error:
        return None, error

    if not isinstance(data, list):
        return None, "Unexpected WiFi scan result"

    return data, None


# ============================================================
# CURRENT WIFI
# ============================================================

def show_current_wifi():

    heading("CURRENT WIFI CONNECTION")

    data, error = get_wifi_connection()

    if error:

        print(
            f"WiFi information unavailable: {error}"
        )

        return None

    ssid = data.get("ssid") or "<Hidden/Unknown>"
    bssid = data.get("bssid") or "Unknown"
    ip = data.get("ip") or "Unknown"
    state = str(data.get("supplicant_state", "Unknown"))
    freq = data.get("frequency_mhz")
    rssi = data.get("rssi")
    speed = data.get("link_speed_mbps")
    hidden = data.get("ssid_hidden", False)

    channel = frequency_to_channel(freq)

    print(f"SSID              : {ssid}")
    print(f"BSSID             : {bssid}")
    print(f"IPv4              : {ip}")
    print(f"Supplicant state  : {state}")
    print(f"Frequency         : {freq or 'Unknown'} MHz")
    print(f"Band              : {frequency_to_band(freq)}")
    print(f"Channel           : {channel or 'Unknown'}")

    print(
        f"RSSI              : "
        f"{rssi if rssi is not None else 'Unknown'} dBm"
    )

    print(
        f"Signal quality    : {signal_quality(rssi)}"
    )

    print(
        f"Link speed        : {speed or 'Unknown'} Mbps"
    )

    print(
        f"Hidden SSID       : {'Yes' if hidden else 'No'}"
    )

    mac = data.get("mac_address")

    if valid_mac(mac):
        print(f"Device WiFi MAC   : {mac}")

    else:
        print(
            "Device WiFi MAC   : Restricted by Android"
        )

    return data


# ============================================================
# WIFI RECORDS
# ============================================================

def normalise_scan_record(record):

    security = classify_wifi_security(
        record.get("capabilities", "")
    )

    freq = record.get("frequency_mhz")

    try:
        bandwidth = int(
            record.get("channel_bandwidth_mhz", 20)
        )

    except Exception:
        bandwidth = 20

    try:
        center = int(
            record.get("center_frequency_mhz")
        )

    except Exception:

        try:
            center = int(freq)

        except Exception:
            center = None

    return {
        "ssid": record.get("ssid", ""),
        "bssid": record.get("bssid", ""),
        "frequency": freq,
        "channel": frequency_to_channel(freq),
        "band": frequency_to_band(freq),
        "rssi": record.get("rssi"),
        "signal": signal_quality(record.get("rssi")),
        "bandwidth": bandwidth,
        "center_frequency": center,
        "capabilities": record.get("capabilities", ""),
        "security": security["security"],
        "cipher": security["cipher"],
        "wps": security["wps"],
        "enterprise": security["enterprise"],
        "pmf_required": security["pmf_required"],
        "pmf_capable": security["pmf_capable"],
    }


# ============================================================
# APPROXIMATE RF OVERLAP
# ============================================================

def occupied_frequency_range(ap):

    center = ap.get("center_frequency")
    width = ap.get("bandwidth", 20)

    try:
        center = float(center)
        width = float(width)

    except Exception:
        return None

    half = width / 2.0

    return (
        center - half,
        center + half,
    )


def frequency_ranges_overlap(first, second):

    if not first or not second:
        return False

    return max(
        first[0],
        second[0],
    ) < min(
        first[1],
        second[1],
    )


def calculate_connected_overlap(records, connected_bssid):

    connected = None

    for ap in records:

        if (
            connected_bssid
            and ap["bssid"].lower()
            == connected_bssid.lower()
        ):

            connected = ap
            break

    if not connected:
        return None

    connected_range = occupied_frequency_range(
        connected
    )

    overlapping = []

    for ap in records:

        if ap is connected:
            continue

        if ap["band"] != connected["band"]:
            continue

        ap_range = occupied_frequency_range(ap)

        if frequency_ranges_overlap(
            connected_range,
            ap_range,
        ):

            overlapping.append(ap)

    overlapping.sort(
        key=lambda ap: (
            ap["rssi"]
            if isinstance(ap["rssi"], int)
            else -999
        ),
        reverse=True,
    )

    return {
        "connected": connected,
        "range": connected_range,
        "overlapping": overlapping,
    }


# ============================================================
# WIFI DISPLAY
# ============================================================

def print_wifi_ap(ap, connected=False, same_ssid=False):

    ssid = ap["ssid"] or "<Hidden SSID>"

    label = ""

    if connected:
        label = "  [YOUR CONNECTED AP]"

    elif same_ssid:
        label = "  [SAME SSID]"

    print(f"{ssid}{label}")

    print(
        f"    BSSID      : {ap['bssid'] or 'Unknown'}"
    )

    print(
        f"    Signal     : "
        f"{ap['rssi'] if ap['rssi'] is not None else 'Unknown'} "
        f"dBm ({ap['signal']})"
    )

    print(f"    Band       : {ap['band']}")

    print(
        f"    Channel    : {ap['channel'] or 'Unknown'}"
    )

    print(
        f"    Width      : {ap['bandwidth']} MHz"
    )

    print(
        f"    Security   : {ap['security']}"
    )

    print(
        f"    Cipher     : {ap['cipher']}"
    )

    print(
        f"    WPS        : "
        f"{'Enabled' if ap['wps'] else 'Not advertised'}"
    )

    if ap["pmf_required"]:
        pmf = "Required"

    elif ap["pmf_capable"]:
        pmf = "Capable"

    else:
        pmf = "Not advertised"

    print(f"    PMF        : {pmf}")


def show_nearby_wifi():

    heading("NEARBY WIFI NETWORKS")

    data, error = scan_nearby_wifi()

    if error:

        print(
            f"Nearby WiFi scan unavailable: {error}"
        )

        return []

    connection, _ = get_wifi_connection()

    connected_bssid = ""
    connected_ssid = ""

    if connection:

        connected_bssid = str(
            connection.get("bssid", "")
        ).lower()

        connected_ssid = str(
            connection.get("ssid", "")
        )

    records = []
    seen = set()

    for raw in data:

        if not isinstance(raw, dict):
            continue

        record = normalise_scan_record(raw)

        identity = (
            record["bssid"].lower(),
            record["frequency"],
        )

        if identity in seen:
            continue

        seen.add(identity)
        records.append(record)

    records.sort(
        key=lambda item: (
            item["rssi"]
            if isinstance(item["rssi"], int)
            else -999
        ),
        reverse=True,
    )

    print(
        f"Access points detected: {len(records)}"
    )

    connected_record = None

    for ap in records:

        if (
            connected_bssid
            and ap["bssid"].lower()
            == connected_bssid
        ):

            connected_record = ap
            break

    if connected_record:

        heading(
            "YOUR CONNECTED WIFI ACCESS POINT"
        )

        print_wifi_ap(
            connected_record,
            connected=True,
        )

    heading("NEARBY WIFI ACCESS POINTS")

    for number, ap in enumerate(records, 1):

        connected = bool(
            connected_bssid
            and ap["bssid"].lower()
            == connected_bssid
        )

        same_ssid = bool(
            connected_ssid
            and ap["ssid"] == connected_ssid
            and not connected
        )

        print()
        print(f"[{number}] ", end="")

        print_wifi_ap(
            ap,
            connected=connected,
            same_ssid=same_ssid,
        )

    analyse_wifi_environment(
        records,
        connected_bssid,
    )

    return records


def analyse_wifi_environment(records, connected_bssid=""):

    heading("WIFI ENVIRONMENT ANALYSIS")

    open_networks = [
        ap
        for ap in records
        if ap["security"].startswith("Open")
    ]

    wep_networks = [
        ap
        for ap in records
        if ap["security"] == "WEP"
    ]

    wps_networks = [
        ap
        for ap in records
        if ap["wps"]
    ]

    hidden_networks = [
        ap
        for ap in records
        if not ap["ssid"]
    ]

    channel_counts = Counter()
    ssid_groups = defaultdict(list)

    connected_ap = None

    for ap in records:

        if (
            connected_bssid
            and ap["bssid"].lower()
            == connected_bssid.lower()
        ):

            connected_ap = ap

        if ap["channel"]:

            channel_counts[
                (
                    ap["band"],
                    ap["channel"],
                )
            ] += 1

        if ap["ssid"]:
            ssid_groups[ap["ssid"]].append(ap)

    print(
        f"Total access points : {len(records)}"
    )

    print(
        f"Open networks       : {len(open_networks)}"
    )

    print(
        f"WEP networks        : {len(wep_networks)}"
    )

    print(
        f"WPS advertised      : {len(wps_networks)}"
    )

    print(
        f"Hidden SSIDs        : {len(hidden_networks)}"
    )

    if connected_ap:

        subheading("Your connected network")

        print(
            f"SSID       : {connected_ap['ssid']}"
        )

        print(
            f"BSSID      : {connected_ap['bssid']}"
        )

        print(
            f"Security   : {connected_ap['security']}"
        )

        print(
            f"Cipher     : {connected_ap['cipher']}"
        )

        print(
            f"WPS        : "
            f"{'Enabled' if connected_ap['wps'] else 'Not advertised'}"
        )

        print(
            f"Signal     : "
            f"{connected_ap['rssi']} dBm "
            f"({connected_ap['signal']})"
        )

        add_finding(
            "INFO",
            "Your WiFi",
            (
                f"{connected_ap['security']} with "
                f"{connected_ap['cipher']}; signal "
                f"{connected_ap['rssi']} dBm "
                f"({connected_ap['signal']})."
            ),
        )

        if connected_ap["wps"]:

            add_finding(
                "INFO",
                "Your WiFi",
                (
                    "WPS is advertised. If you do not "
                    "use WPS, consider disabling it."
                ),
            )

        if not (
            connected_ap["pmf_required"]
            or connected_ap["pmf_capable"]
        ):

            add_finding(
                "INFO",
                "Your WiFi",
                (
                    "Protected Management Frames were "
                    "not advertised."
                ),
            )

    subheading("Nearby security observations")

    if open_networks:

        print(
            f"{len(open_networks)} nearby AP(s) advertise "
            "no WPA/RSN link-layer protection."
        )

        print(
            "These are environmental observations, "
            "not findings against your own network."
        )

    else:

        print(
            "No nearby APs without WPA/RSN "
            "protection were detected."
        )

    if wep_networks:

        print(
            f"{len(wep_networks)} nearby WEP "
            "network(s) detected."
        )

    subheading("Primary channel usage")

    for (
        band,
        channel,
    ), count in sorted(
        channel_counts.items(),
        key=lambda item: (
            item[0][0],
            item[0][1],
        ),
    ):

        print(
            f"{band:8} "
            f"Channel {channel:>3}: "
            f"{count} AP(s)"
        )

    overlap = calculate_connected_overlap(
        records,
        connected_bssid,
    )

    subheading(
        "Approximate channel-width overlap"
    )

    if not overlap:

        print(
            "Connected AP could not be correlated "
            "with the WiFi scan."
        )

    else:

        connected = overlap["connected"]
        overlapping = overlap["overlapping"]

        strong_overlap = [
            ap
            for ap in overlapping
            if isinstance(ap["rssi"], int)
            and ap["rssi"] >= -70
        ]

        print(
            f"Connected AP: {connected['band']} "
            f"channel {connected['channel']} "
            f"({connected['bandwidth']} MHz)"
        )

        print(
            "Other APs with approximately "
            f"overlapping spectrum: {len(overlapping)}"
        )

        print(
            "Overlap APs at -70 dBm or stronger: "
            f"{len(strong_overlap)}"
        )

        if overlapping:

            print()
            print(
                "Strongest overlapping APs:"
            )

            for ap in overlapping[:8]:

                ssid = (
                    ap["ssid"]
                    or "<Hidden SSID>"
                )

                print(
                    f"  {ssid:24} "
                    f"{ap['rssi']:>4} dBm  "
                    f"Ch {str(ap['channel']):>3}  "
                    f"{ap['bandwidth']} MHz  "
                    f"{ap['bssid']}"
                )

            add_finding(
                "INFO",
                "WiFi environment",
                (
                    f"{len(overlapping)} same-band AP(s) "
                    "approximately overlap the connected "
                    "AP's occupied spectrum, including "
                    f"{len(strong_overlap)} at -70 dBm "
                    "or stronger. This is an RF estimate, "
                    "not proof of interference."
                ),
            )

    subheading("Repeated SSIDs")

    repeated = {
        ssid: aps
        for ssid, aps in ssid_groups.items()
        if len(aps) > 1
    }

    if not repeated:

        print(
            "No repeated visible SSIDs detected."
        )

    else:

        for ssid, aps in sorted(
            repeated.items()
        ):

            bands = sorted(
                {
                    ap["band"]
                    for ap in aps
                }
            )

            print(
                f"{ssid}: {len(aps)} APs across "
                f"{', '.join(bands)}"
            )


# ============================================================
# ROUTE DETECTION
# ============================================================

def parse_ip_route():

    if not command_exists("ip"):
        return None

    result = run_command(
        [
            "ip",
            "-4",
            "route",
            "get",
            "1.1.1.1",
        ],
        timeout=5,
    )

    if not result["stdout"]:
        return None

    text = result["stdout"]

    info = {}

    match = re.search(
        r"\bsrc\s+(\d+\.\d+\.\d+\.\d+)",
        text,
    )

    if match:
        info["src"] = match.group(1)

    match = re.search(
        r"\bdev\s+(\S+)",
        text,
    )

    if match:
        info["interface"] = match.group(1)

    match = re.search(
        r"\bvia\s+(\d+\.\d+\.\d+\.\d+)",
        text,
    )

    if match:
        info["gateway"] = match.group(1)

    return info


def get_interface_network(interface):

    if not interface or not command_exists("ip"):
        return None

    result = run_command(
        [
            "ip",
            "-4",
            "addr",
            "show",
            "dev",
            interface,
        ],
        timeout=5,
    )

    match = re.search(
        r"\binet\s+"
        r"(\d+\.\d+\.\d+\.\d+)/(\d+)",
        result["stdout"],
    )

    if not match:
        return None

    try:

        return ipaddress.IPv4Network(
            f"{match.group(1)}/{match.group(2)}",
            strict=False,
        )

    except Exception:
        return None


# ============================================================
# LAN CONFIGURATION
# ============================================================

def load_json_file(filename):

    try:

        with open(
            filename,
            "r",
            encoding="utf-8",
        ) as handle:

            data = json.load(handle)

        return data

    except Exception:
        return None


def save_json_file(filename, data):

    try:

        with open(
            filename,
            "w",
            encoding="utf-8",
        ) as handle:

            json.dump(
                data,
                handle,
                indent=2,
            )

        return True

    except Exception as exc:

        print(
            f"Unable to save {filename}: {exc}"
        )

        return False


def normalise_config_database(data):

    if not isinstance(data, dict):
        return {}

    # New structure.
    if isinstance(data.get("networks"), dict):
        return data

    # Earlier V3.3 structure was a direct dictionary.
    converted = {
        "format": 1,
        "networks": {},
    }

    for key, value in data.items():

        if not isinstance(value, dict):
            continue

        ssid = value.get("ssid")

        if not ssid:

            if str(key).startswith("ssid:"):
                ssid = str(key)[5:]

        if not ssid:
            continue

        converted["networks"][ssid] = {
            "ssid": ssid,
            "last_bssid": value.get(
                "last_bssid"
            ),
            "network": value.get(
                "network"
            ),
            "gateway": value.get(
                "gateway"
            ),
        }

    return converted


def load_lan_configs():

    # First use permanent current file.

    data = load_json_file(
        LAN_CONFIG_FILE
    )

    if data is not None:

        normalised = normalise_config_database(
            data
        )

        # Save converted structure if needed.
        if "networks" not in data:
            save_json_file(
                LAN_CONFIG_FILE,
                normalised,
            )

        return normalised

    # Try older files.

    for filename in LEGACY_CONFIG_FILES:

        data = load_json_file(
            filename
        )

        if data is None:
            continue

        normalised = normalise_config_database(
            data
        )

        if normalised.get("networks"):

            save_json_file(
                LAN_CONFIG_FILE,
                normalised,
            )

            print(
                f"Migrated LAN configuration "
                f"from {filename}."
            )

            return normalised

    return {
        "format": 1,
        "networks": {},
    }


def save_lan_configs(configs):

    configs["format"] = 1

    return save_json_file(
        LAN_CONFIG_FILE,
        configs,
    )


def get_saved_config(
    configs,
    connection,
):

    ssid = str(
        connection.get("ssid")
        or ""
    ).strip()

    if not ssid:
        return None

    networks = configs.get(
        "networks",
        {},
    )

    if ssid in networks:
        return networks[ssid]

    # Compatibility with old BSSID keys if one survived.

    bssid = str(
        connection.get("bssid")
        or ""
    ).lower()

    for key, value in networks.items():

        if not isinstance(value, dict):
            continue

        if str(
            value.get("last_bssid", "")
        ).lower() == bssid:

            return value

    return None


def validate_manual_lan(
    ip_string,
    cidr_string,
    gateway_string=None,
):

    try:

        current_ip = ipaddress.IPv4Address(
            ip_string
        )

        network = ipaddress.IPv4Network(
            cidr_string,
            strict=False,
        )

    except ValueError as exc:

        return None, (
            f"Invalid network information: {exc}"
        )

    if not private_ipv4(
        str(current_ip)
    ):

        return None, (
            "Current WiFi address is not "
            "RFC1918 private."
        )

    if not private_network(network):

        return None, (
            "Entered network is not completely "
            "inside an RFC1918 private range."
        )

    if current_ip not in network:

        return None, (
            f"This device ({current_ip}) does "
            f"not belong to {network}."
        )

    if network.num_addresses > 4096:

        return None, (
            "The network contains more than "
            "4096 addresses."
        )

    gateway = None

    if gateway_string:

        try:

            gateway = ipaddress.IPv4Address(
                gateway_string
            )

        except ValueError:

            return None, (
                "Gateway is not a valid IPv4 address."
            )

        if not private_ipv4(
            str(gateway)
        ):

            return None, (
                "Gateway is not RFC1918 private."
            )

        if gateway not in network:

            return None, (
                f"Gateway {gateway} does not "
                f"belong to {network}."
            )

        if gateway in (
            network.network_address,
            network.broadcast_address,
            current_ip,
        ):

            return None, (
                "Gateway cannot be the network address, "
                "broadcast address or this device."
            )

    return {
        "network": network,
        "gateway": (
            str(gateway)
            if gateway
            else None
        ),
    }, None


def activate_saved_lan(
    connection,
    saved,
):

    global SESSION_LAN

    validated, error = validate_manual_lan(
        connection.get("ip"),
        saved.get("network", ""),
        saved.get("gateway"),
    )

    if error:
        return None, error

    SESSION_LAN = {
        "confirmed": True,
        "ssid": connection.get("ssid"),
        "bssid": connection.get("bssid"),
        "ip": connection.get("ip"),
        "interface": None,
        "gateway": validated["gateway"],
        "network": validated["network"],
        "source": (
            "Saved configuration confirmed this session"
        ),
        "reason": (
            "Private LAN validated against current "
            "WiFi address."
        ),
    }

    return SESSION_LAN, None


def configure_lan():

    global SESSION_LAN

    heading("LAN CONFIGURATION")

    connection, error = get_wifi_connection()

    if error:

        print(
            f"WiFi information unavailable: {error}"
        )

        return None

    state = str(
        connection.get("supplicant_state", "")
    ).upper()

    if state != "COMPLETED":

        print(
            "A completed WiFi connection is required."
        )

        return None

    current_ip = connection.get("ip")

    if not private_ipv4(current_ip):

        print(
            "Current WiFi IPv4 address is not "
            "an RFC1918 private address."
        )

        return None

    print(
        f"SSID  : {connection.get('ssid')}"
    )

    print(
        f"BSSID : {connection.get('bssid')}"
    )

    print(
        f"IPv4  : {current_ip}"
    )

    configs = load_lan_configs()

    saved = get_saved_config(
        configs,
        connection,
    )

    if saved:

        print()
        print(
            "Saved LAN configuration:"
        )

        print(
            f"  Network : {saved.get('network')}"
        )

        print(
            f"  Gateway : "
            f"{saved.get('gateway') or 'Not configured'}"
        )

        print()
        print(
            "1. Use saved configuration"
        )

        print(
            "2. Enter / update configuration"
        )

        print(
            "3. Delete saved configuration"
        )

        print(
            "4. Cancel"
        )

        choice = input(
            "\nChoose an option: "
        ).strip()

        if choice == "1":

            lan, error = activate_saved_lan(
                connection,
                saved,
            )

            if error:

                print(
                    f"Saved configuration rejected: {error}"
                )

                return None

            print()
            print(
                "LAN configuration activated "
                "for this session."
            )

            return lan

        if choice == "3":

            ssid = str(
                connection.get("ssid")
                or ""
            )

            networks = configs.get(
                "networks",
                {},
            )

            if ssid in networks:
                del networks[ssid]

            save_lan_configs(
                configs
            )

            SESSION_LAN = None

            print(
                "Saved LAN configuration deleted."
            )

            return None

        if choice == "4":
            return None

        if choice != "2":

            print(
                "Invalid option."
            )

            return None

    print()
    print(
        "Enter the CIDR supplied by your router "
        "or network configuration."
    )

    print(
        "Do not guess the subnet."
    )

    print()

    cidr = input(
        "Local network CIDR: "
    ).strip()

    if not cidr:
        return None

    gateway = input(
        "Router/gateway IPv4 (optional): "
    ).strip()

    validated, error = validate_manual_lan(
        current_ip,
        cidr,
        gateway or None,
    )

    if error:

        print(
            f"Configuration rejected: {error}"
        )

        return None

    SESSION_LAN = {
        "confirmed": True,
        "ssid": connection.get("ssid"),
        "bssid": connection.get("bssid"),
        "ip": current_ip,
        "interface": None,
        "gateway": validated["gateway"],
        "network": validated["network"],
        "source": "Manual session configuration",
        "reason": (
            "Private WiFi LAN manually validated."
        ),
    }

    print()
    print(
        "Configuration validated:"
    )

    print(
        f"  Network : {validated['network']}"
    )

    print(
        f"  Gateway : "
        f"{validated['gateway'] or 'Not configured'}"
    )

    answer = input(
        "\nSave permanently for this WiFi SSID? [Y/n]: "
    ).strip().lower()

    if answer in (
        "",
        "y",
        "yes",
    ):

        ssid = str(
            connection.get("ssid")
            or ""
        )

        configs.setdefault(
            "networks",
            {},
        )

        configs["networks"][ssid] = {
            "ssid": ssid,
            "last_bssid": connection.get(
                "bssid"
            ),
            "network": str(
                validated["network"]
            ),
            "gateway": validated["gateway"],
        }

        if save_lan_configs(
            configs
        ):

            print(
                "LAN configuration saved."
            )

    return SESSION_LAN


# ============================================================
# LAN DETECTION
# ============================================================

def detect_lan():

    global SESSION_LAN

    connection, error = get_wifi_connection()

    result = {
        "confirmed": False,
        "reason": "",
        "ssid": None,
        "bssid": None,
        "ip": None,
        "interface": None,
        "gateway": None,
        "network": None,
        "source": None,
    }

    if error:

        result["reason"] = (
            "WiFi connection could not be confirmed: "
            f"{error}"
        )

        return result

    state = str(
        connection.get("supplicant_state", "")
    ).upper()

    if state != "COMPLETED":

        result["reason"] = (
            "WiFi supplicant is not in COMPLETED state."
        )

        return result

    current_ip = connection.get("ip")

    result["ssid"] = connection.get("ssid")
    result["bssid"] = connection.get("bssid")
    result["ip"] = current_ip

    if not private_ipv4(current_ip):

        result["reason"] = (
            "Connected WiFi IPv4 address is not "
            "RFC1918 private."
        )

        return result

    # Automatic route detection where Android permits it.

    route = parse_ip_route()

    if route:

        interface = route.get("interface")
        gateway = route.get("gateway")

        network = get_interface_network(
            interface
        )

        if gateway and network:

            try:

                current_address = (
                    ipaddress.IPv4Address(
                        current_ip
                    )
                )

                gateway_address = (
                    ipaddress.IPv4Address(
                        gateway
                    )
                )

                if (
                    private_network(network)
                    and current_address in network
                    and gateway_address in network
                    and network.num_addresses <= 4096
                ):

                    return {
                        "confirmed": True,
                        "reason": (
                            "Private WiFi LAN "
                            "automatically confirmed."
                        ),
                        "ssid": connection.get("ssid"),
                        "bssid": connection.get("bssid"),
                        "ip": current_ip,
                        "interface": interface,
                        "gateway": gateway,
                        "network": network,
                        "source": "Automatic",
                    }

            except Exception:
                pass

    # Session configuration is trusted only after validation.

    if SESSION_LAN:

        try:

            same_ssid = (
                SESSION_LAN.get("ssid")
                == connection.get("ssid")
            )

            current_address = (
                ipaddress.IPv4Address(
                    current_ip
                )
            )

            inside_network = (
                current_address
                in SESSION_LAN["network"]
            )

            if same_ssid and inside_network:

                result = dict(
                    SESSION_LAN
                )

                result["ip"] = current_ip
                result["bssid"] = connection.get(
                    "bssid"
                )

                return result

        except Exception:
            pass

    result["reason"] = (
        "WiFi is connected, but Android blocked "
        "automatic subnet/gateway detection. "
        "Activate the validated saved LAN "
        "configuration for this session."
    )

    return result


def ensure_lan():

    lan = detect_lan()

    if lan["confirmed"]:
        return lan

    print()
    print(
        "A confirmed LAN configuration is required."
    )

    answer = input(
        "Open LAN configuration now? [Y/n]: "
    ).strip().lower()

    if answer not in (
        "",
        "y",
        "yes",
    ):

        return lan

    configured = configure_lan()

    if configured:
        return configured

    return detect_lan()


# ============================================================
# NETWORK INFORMATION
# ============================================================

def show_network_information():

    heading(
        "DEVICE NETWORK INFORMATION"
    )

    lan = detect_lan()

    print(
        f"Auditor version   : {VERSION}"
    )

    print(
        f"Platform          : "
        f"{'Android' if is_android() else sys.platform}"
    )

    print(
        f"Hostname          : {socket.gethostname()}"
    )

    print(
        f"WiFi SSID         : "
        f"{lan['ssid'] or 'Not available'}"
    )

    print(
        f"WiFi BSSID        : "
        f"{lan['bssid'] or 'Not available'}"
    )

    print(
        f"Detected IPv4     : "
        f"{lan['ip'] or 'Not available'}"
    )

    print(
        f"Interface         : "
        f"{lan['interface'] or 'Restricted by Android'}"
    )

    print(
        f"Gateway           : "
        f"{lan['gateway'] or 'Not configured'}"
    )

    print(
        f"Network           : "
        f"{lan['network'] or 'Not configured'}"
    )

    print(
        f"Configuration     : "
        f"{lan['source'] or 'None active'}"
    )

    print(
        f"Local LAN         : "
        f"{'Confirmed' if lan['confirmed'] else 'Not confirmed'}"
    )

    print(
        f"Reason            : {lan['reason']}"
    )

    return lan


def show_interfaces():

    heading("NETWORK INTERFACES")

    if command_exists("ip"):

        result = run_command(
            [
                "ip",
                "-brief",
                "addr",
            ],
            timeout=5,
        )

        if result["stdout"]:

            print(
                result["stdout"]
            )

            return

        if "Permission denied" in result["stderr"]:

            print(
                "Android denied netlink interface access."
            )

    try:

        interfaces = socket.if_nameindex()

        if interfaces:

            print(
                "Interface names visible through Python:"
            )

            for index, name in interfaces:

                print(
                    f"{index:>3}  {name}"
                )

            return

    except Exception:
        pass

    print(
        "Detailed interface information unavailable."
    )


# ============================================================
# TCP DISCOVERY
# ============================================================

def tcp_open(
    ip,
    port,
    timeout=PORT_TIMEOUT,
):

    try:

        with socket.create_connection(
            (ip, port),
            timeout=timeout,
        ):

            return True

    except Exception:
        return False


def reverse_dns(ip):

    try:

        hostname, _, _ = socket.gethostbyaddr(
            ip
        )

        return hostname

    except Exception:
        return "Unknown"


def discover_host(ip):

    open_ports = []

    for port in DISCOVERY_PORTS:

        if tcp_open(
            ip,
            port,
            DISCOVERY_TIMEOUT,
        ):

            open_ports.append(port)

    if not open_ports:
        return None

    return {
        "ip": ip,
        "hostname": reverse_dns(ip),
        "open_ports": open_ports,
    }


def discover_devices():

    heading("LOCAL DEVICE DISCOVERY")

    lan = ensure_lan()

    if not lan["confirmed"]:

        print(
            "Active LAN discovery is disabled."
        )

        print(
            f"Reason: {lan['reason']}"
        )

        return [], lan

    network = lan["network"]

    hosts = list(
        network.hosts()
    )

    if len(hosts) > MAX_DISCOVERY_HOSTS:

        hosts = hosts[
            :MAX_DISCOVERY_HOSTS
        ]

    print(f"Network      : {network}")

    print(
        f"Gateway      : "
        f"{lan['gateway'] or 'Not configured'}"
    )

    print(f"This device  : {lan['ip']}")
    print(f"Configuration: {lan['source']}")
    print(f"Hosts tested : {len(hosts)}")
    print(f"Passes       : {DISCOVERY_PASSES}")

    print()
    print(
        "Discovery uses TCP connection checks. "
        "Devices exposing none of the tested "
        "services may not appear."
    )

    discovered = {}

    for pass_number in range(
        1,
        DISCOVERY_PASSES + 1,
    ):

        print()
        print(
            f"Discovery pass "
            f"{pass_number}/{DISCOVERY_PASSES}..."
        )

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=64
        ) as executor:

            futures = {
                executor.submit(
                    discover_host,
                    str(ip),
                ): str(ip)
                for ip in hosts
            }

            for future in (
                concurrent.futures.as_completed(
                    futures
                )
            ):

                try:
                    result = future.result()

                except Exception:
                    continue

                if not result:
                    continue

                ip = result["ip"]

                if ip not in discovered:

                    discovered[ip] = {
                        "ip": ip,
                        "hostname": result[
                            "hostname"
                        ],
                        "open_ports": set(),
                        "seen": 0,
                    }

                discovered[ip]["seen"] += 1

                discovered[ip][
                    "open_ports"
                ].update(
                    result["open_ports"]
                )

                if (
                    discovered[ip]["hostname"]
                    == "Unknown"
                    and result["hostname"]
                    != "Unknown"
                ):

                    discovered[ip]["hostname"] = (
                        result["hostname"]
                    )

    results = []

    for item in discovered.values():

        item["open_ports"] = sorted(
            item["open_ports"]
        )

        results.append(item)

    results.sort(
        key=lambda item:
        ipaddress.IPv4Address(
            item["ip"]
        )
    )

    print()

    for item in results:

        ip = item["ip"]

        if ip == lan["ip"]:
            role = "THIS DEVICE"

        elif (
            lan["gateway"]
            and ip == lan["gateway"]
        ):
            role = "ROUTER"

        else:
            role = "ACTIVE"

        ports = ", ".join(
            str(port)
            for port in item["open_ports"]
        )

        print(
            f"{ip:15} "
            f"{role:11} "
            f"{item['hostname'][:25]:25} "
            f"Seen {item['seen']}/{DISCOVERY_PASSES} "
            f"Ports: {ports}"
        )

    add_finding(
        "INFO",
        "LAN",
        (
            f"{len(results)} responding device(s) "
            "were discovered using TCP service checks."
        ),
    )

    return results, lan


# ============================================================
# BANNERS
# ============================================================

def grab_banner(ip, port):

    try:

        with socket.create_connection(
            (ip, port),
            timeout=1.2,
        ) as sock:

            sock.settimeout(1.2)

            if port in (
                80,
                8000,
                8080,
                8081,
                9000,
            ):

                request = (
                    "HEAD / HTTP/1.0\r\n"
                    f"Host: {ip}\r\n"
                    "Connection: close\r\n\r\n"
                )

                sock.sendall(
                    request.encode()
                )

            data = sock.recv(2048)

            if not data:
                return None

            return data.decode(
                "utf-8",
                errors="replace",
            ).strip()

    except Exception:
        return None


# ============================================================
# HTML FINGERPRINTING
# ============================================================

class FingerprintParser(HTMLParser):

    def __init__(self):

        super().__init__()

        self.title = []
        self.in_title = False

        self.visible_text = []

        self.script_blocks = []
        self.current_script = []
        self.in_script = False
        self.in_style = False

        self.forms = []
        self.password_inputs = 0
        self.inputs = 0
        self.buttons = 0
        self.links = []

        self.meta_refresh = []

    def handle_starttag(
        self,
        tag,
        attrs,
    ):

        attrs = dict(attrs)

        if tag == "title":
            self.in_title = True

        elif tag == "script":

            self.in_script = True
            self.current_script = []

            src = attrs.get("src")

            if src:
                self.links.append(src)

        elif tag == "style":

            self.in_style = True

        elif tag == "form":

            self.forms.append(
                {
                    "action": attrs.get(
                        "action",
                        "",
                    ),
                    "method": attrs.get(
                        "method",
                        "GET",
                    ).upper(),
                }
            )

        elif tag == "input":

            self.inputs += 1

            if (
                attrs.get(
                    "type",
                    "",
                ).lower()
                == "password"
            ):

                self.password_inputs += 1

        elif tag == "button":

            self.buttons += 1

        elif tag == "a":

            href = attrs.get("href")

            if href:
                self.links.append(href)

        elif tag == "meta":

            http_equiv = str(
                attrs.get(
                    "http-equiv",
                    "",
                )
            ).lower()

            content = str(
                attrs.get(
                    "content",
                    "",
                )
            )

            if http_equiv == "refresh":

                self.meta_refresh.append(
                    content
                )

    def handle_endtag(
        self,
        tag,
    ):

        if tag == "title":

            self.in_title = False

        elif tag == "script":

            self.in_script = False

            content = "".join(
                self.current_script
            )

            if content.strip():

                self.script_blocks.append(
                    content
                )

            self.current_script = []

        elif tag == "style":

            self.in_style = False

    def handle_data(
        self,
        data,
    ):

        if self.in_title:

            self.title.append(data)

        elif self.in_script:

            self.current_script.append(
                data
            )

        elif not self.in_style:

            cleaned = " ".join(
                data.split()
            )

            if cleaned:

                self.visible_text.append(
                    cleaned
                )


# ============================================================
# HTTP
# ============================================================

class NoRedirectHandler(
    urllib.request.HTTPRedirectHandler
):

    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl,
    ):

        return None


def fetch_url(
    url,
    follow_redirects=True,
):

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent":
            f"WiFi-Security-Auditor/{VERSION}"
        },
        method="GET",
    )

    context = ssl.create_default_context()

    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    handlers = [
        urllib.request.HTTPSHandler(
            context=context
        )
    ]

    if not follow_redirects:

        handlers.append(
            NoRedirectHandler()
        )

    opener = urllib.request.build_opener(
        *handlers
    )

    try:

        with opener.open(
            request,
            timeout=HTTP_TIMEOUT,
        ) as response:

            body = response.read(
                MAX_HTTP_BYTES
            )

            return {
                "requested_url": url,
                "url": response.geturl(),
                "status": response.status,
                "headers": dict(
                    response.headers
                ),
                "body": body,
                "error": None,
            }

    except urllib.error.HTTPError as exc:

        try:
            body = exc.read(
                MAX_HTTP_BYTES
            )

        except Exception:
            body = b""

        return {
            "requested_url": url,
            "url": url,
            "status": exc.code,
            "headers": dict(
                exc.headers
            ),
            "body": body,
            "error": None,
        }

    except Exception as exc:

        return {
            "requested_url": url,
            "url": url,
            "status": None,
            "headers": {},
            "body": b"",
            "error": str(exc),
        }


def decode_body(data):

    try:
        return data.decode("utf-8")

    except Exception:

        return data.decode(
            "latin-1",
            errors="replace",
        )


def web_url(ip, port):

    scheme = (
        "https"
        if port in HTTPS_PORTS
        else "http"
    )

    if (
        scheme == "http"
        and port == 80
    ) or (
        scheme == "https"
        and port == 443
    ):

        return f"{scheme}://{ip}/"

    return (
        f"{scheme}://{ip}:{port}/"
    )


# ============================================================
# JAVASCRIPT
# ============================================================

def analyse_javascript(script):

    functions = list(
        dict.fromkeys(
            re.findall(
                r"\bfunction\s+"
                r"([A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
                script,
                re.I,
            )
        )
    )

    endpoints = list(
        dict.fromkeys(
            re.findall(
                r"""["']([^"']+\.(?:cgi|php|asp|aspx|json)(?:\?[^"']*)?)["']""",
                script,
                re.I,
            )
        )
    )

    paths = list(
        dict.fromkeys(
            re.findall(
                r"""["']((?:/|\./)[A-Za-z0-9_.?=&%/\-]{2,200})["']""",
                script,
            )
        )
    )

    lower = script.lower()

    switch_clues = []

    terms = [
        "managed switch",
        "smart switch",
        "port status",
        "port statistics",
        "port configuration",
        "storm control",
        "spanning tree",
        "802.1q",
        "link aggregation",
        "lacp",
        "poe",
    ]

    for term in terms:

        if term in lower:
            switch_clues.append(term)

    secure_redirect_clues = []

    for match in re.findall(
        r"""https://[^"' \t\r\n<>]+""",
        script,
        re.I,
    ):

        secure_redirect_clues.append(
            match
        )

    return {
        "functions": functions,
        "endpoints": endpoints,
        "paths": paths,
        "switch_clues": switch_clues,
        "https_clues": list(
            dict.fromkeys(
                secure_redirect_clues
            )
        ),
    }


# ============================================================
# WEB ANALYSIS
# ============================================================

def identify_web_application(
    title,
    server,
    visible,
    scripts,
    port,
):

    combined = (
        f"{title} {server} "
        f"{visible} {scripts}"
    ).lower()

    applications = []

    if (
        "proxmox" in combined
        or "pve-api-daemon" in combined
    ):

        applications.append(
            {
                "name": "Proxmox VE",
                "type": "Virtualisation management",
                "port": port,
            }
        )

    if (
        "filebrowser" in combined
        or "filebrowser quantum" in combined
    ):

        applications.append(
            {
                "name": "FileBrowser",
                "type": "File management application",
                "port": port,
            }
        )

    if "truenas" in combined:

        applications.append(
            {
                "name": "TrueNAS Web UI",
                "type": "NAS management",
                "port": port,
            }
        )

    return applications


def analyse_web_service(
    ip,
    port,
    verbose=True,
):

    url = web_url(
        ip,
        port,
    )

    raw = fetch_url(
        url,
        follow_redirects=False,
    )

    followed = fetch_url(
        url,
        follow_redirects=True,
    )

    if followed["error"]:

        if verbose:

            print()
            print(url)

            print(
                f"Request failed: "
                f"{followed['error']}"
            )

        return {
            "port": port,
            "url": url,
            "scheme": (
                "https"
                if port in HTTPS_PORTS
                else "http"
            ),
            "error": followed["error"],
            "auth": False,
            "redirect": None,
            "secure_redirect": False,
            "text": "",
            "server": "",
            "title": "",
            "applications": [],
            "js_info": {},
        }

    body = followed["body"]
    text = decode_body(body)

    parser = FingerprintParser()

    try:
        parser.feed(text)

    except Exception:
        pass

    title = " ".join(
        parser.title
    ).strip()

    visible = html.unescape(
        " ".join(
            parser.visible_text
        )
    )

    server = (
        followed["headers"].get("Server")
        or followed["headers"].get("server")
        or ""
    )

    content_type = (
        followed["headers"].get("Content-Type")
        or followed["headers"].get("content-type")
        or ""
    )

    location = (
        raw["headers"].get("Location")
        or raw["headers"].get("location")
    )

    redirect = None

    if (
        raw["status"]
        in (301, 302, 303, 307, 308)
        and location
    ):

        redirect = urllib.parse.urljoin(
            url,
            location,
        )

    elif followed["url"] != url:

        redirect = followed["url"]

    scripts = "\n".join(
        parser.script_blocks
    )

    js_info = analyse_javascript(
        scripts
    )

    secure_redirect = bool(
        redirect
        and redirect.lower().startswith(
            "https://"
        )
    )

    # Look for meta refresh to HTTPS.

    if not secure_redirect:

        for refresh in parser.meta_refresh:

            if "https://" in refresh.lower():

                secure_redirect = True
                break

    # JavaScript HTTPS references are only clues.
    # They are not treated as proof of a redirect.

    combined = (
        f"{title} "
        f"{visible} "
        f"{scripts}"
    ).lower()

    auth_evidence = []

    if parser.password_inputs:

        auth_evidence.append(
            "HTML password field detected"
        )

    for form in parser.forms:

        action = form.get(
            "action",
            "",
        )

        if any(
            word in action.lower()
            for word in (
                "login",
                "logon",
                "auth",
            )
        ):

            auth_evidence.append(
                f"Authentication form: {action}"
            )

    for endpoint in js_info[
        "endpoints"
    ]:

        if any(
            word in endpoint.lower()
            for word in (
                "login",
                "logon",
                "auth",
            )
        ):

            auth_evidence.append(
                f"Authentication endpoint: {endpoint}"
            )

    for clue in (
        "login",
        "logon",
        "username",
        "password",
        "authentication",
    ):

        if clue in combined:

            auth_evidence.append(
                f"Authentication clue: {clue}"
            )

    auth_evidence = list(
        dict.fromkeys(
            auth_evidence
        )
    )

    applications = (
        identify_web_application(
            title,
            server,
            visible,
            scripts,
            port,
        )
    )

    response_headers = {
        str(key).lower(): str(value)
        for key, value in followed.get("headers", {}).items()
    }
    security_headers = {
        "hsts": response_headers.get("strict-transport-security"),
        "csp": response_headers.get("content-security-policy"),
        "x_content_type_options": response_headers.get("x-content-type-options"),
        "x_frame_options": response_headers.get("x-frame-options"),
        "referrer_policy": response_headers.get("referrer-policy"),
        "permissions_policy": response_headers.get("permissions-policy"),
    }
    set_cookie = response_headers.get("set-cookie", "")
    cookie_flags = {
        "present": bool(set_cookie),
        "secure": "secure" in set_cookie.lower(),
        "httponly": "httponly" in set_cookie.lower(),
        "samesite": "samesite=" in set_cookie.lower(),
    }

    if verbose:

        print()
        print("HTTP FINGERPRINT")
        print(url)

        print(
            f"Status       : {followed['status']}"
        )

        print(
            f"Body size    : {len(body)} bytes"
        )

        print(
            f"Title        : "
            f"{title or 'Not detected'}"
        )

        print(
            f"Server       : "
            f"{server or 'Not disclosed'}"
        )

        print(
            f"Content-Type : "
            f"{content_type or 'Not disclosed'}"
        )

        if redirect:

            print(
                f"Redirect     : {redirect}"
            )

        if secure_redirect:

            print(
                "HTTPS redirect: Detected"
            )

        print()
        print("HTTP security headers:")
        print(f"  HSTS               : {'Present' if security_headers['hsts'] else 'Not observed'}")
        print(f"  CSP                : {'Present' if security_headers['csp'] else 'Not observed'}")
        print(f"  X-Content-Type     : {'Present' if security_headers['x_content_type_options'] else 'Not observed'}")
        print(f"  Frame protection   : {'Present' if security_headers['x_frame_options'] or security_headers['csp'] and 'frame-ancestors' in security_headers['csp'].lower() else 'Not observed'}")
        if cookie_flags['present']:
            print(f"  Cookie Secure      : {'Yes' if cookie_flags['secure'] else 'No'}")
            print(f"  Cookie HttpOnly    : {'Yes' if cookie_flags['httponly'] else 'No'}")
            print(f"  Cookie SameSite    : {'Yes' if cookie_flags['samesite'] else 'No'}")

        if applications:

            print()
            print("Application identification:")

            for application in applications:

                print(
                    f"  {application['name']} "
                    f"({application['type']})"
                )

        if auth_evidence:

            print()
            print(
                "Authentication-related evidence:"
            )

            for evidence in auth_evidence[:12]:

                print(
                    f"  {evidence}"
                )

    return {
        "port": port,
        "url": url,
        "final_url": followed["url"],
        "scheme": (
            "https"
            if port in HTTPS_PORTS
            else "http"
        ),
        "status": followed["status"],
        "server": server,
        "title": title,
        "redirect": redirect,
        "secure_redirect": secure_redirect,
        "auth": bool(auth_evidence),
        "auth_evidence": auth_evidence,
        "applications": applications,
        "text": (
            f"{title} "
            f"{visible} "
            f"{server} "
            f"{scripts}"
        ),
        "js_info": js_info,
        "headers": response_headers,
        "security_headers": security_headers,
        "cookie_flags": cookie_flags,
        "error": None,
    }


# ============================================================
# TLS
# ============================================================

def _decode_peer_certificate(der_bytes):
    """Decode a peer certificate using Python's bundled SSL helpers."""
    if not der_bytes:
        return {}
    path = None
    try:
        pem = ssl.DER_cert_to_PEM_cert(der_bytes)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="ascii", suffix=".pem", delete=False
        ) as handle:
            handle.write(pem)
            path = handle.name
        return ssl._ssl._test_decode_cert(path) or {}
    except Exception:
        return {}
    finally:
        if path:
            try:
                os.unlink(path)
            except Exception:
                pass


def _certificate_name(parts):
    values = []
    for group in parts or ():
        for key, value in group:
            if key in ("commonName", "organizationName") and value:
                values.append(str(value))
    return " / ".join(dict.fromkeys(values))


def get_tls_information(ip, port, verbose=True):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as tls:
                cipher = tls.cipher()
                cert = _decode_peer_certificate(
                    tls.getpeercert(binary_form=True)
                )

                subject = _certificate_name(cert.get("subject"))
                issuer = _certificate_name(cert.get("issuer"))
                not_before = cert.get("notBefore")
                not_after = cert.get("notAfter")
                san = [
                    value for kind, value in cert.get("subjectAltName", ())
                    if kind in ("DNS", "IP Address")
                ]

                days_remaining = None
                expired = None
                if not_after:
                    try:
                        expiry = datetime.datetime.fromtimestamp(
                            ssl.cert_time_to_seconds(not_after),
                            tz=datetime.timezone.utc,
                        )
                        now = datetime.datetime.now(datetime.timezone.utc)
                        days_remaining = (expiry - now).days
                        expired = expiry <= now
                    except Exception:
                        pass

                result = {
                    "protocol": tls.version(),
                    "cipher": cipher[0] if cipher else None,
                    "bits": cipher[2] if cipher else None,
                    "certificate_subject": subject,
                    "certificate_issuer": issuer,
                    "certificate_not_before": not_before,
                    "certificate_not_after": not_after,
                    "certificate_san": san,
                    "certificate_days_remaining": days_remaining,
                    "certificate_expired": expired,
                }

                if verbose:
                    heading(f"TLS INFORMATION : {ip}:{port}")
                    print(f"Protocol : {result['protocol'] or 'Unknown'}")
                    print(f"Cipher   : {result['cipher'] or 'Unknown'}")
                    print(f"Bits     : {result['bits'] or 'Unknown'}")
                    if subject or issuer or not_after:
                        print(f"Subject  : {subject or 'Not disclosed'}")
                        print(f"Issuer   : {issuer or 'Not disclosed'}")
                        print(f"Valid to : {not_after or 'Unknown'}")
                        if days_remaining is not None:
                            print(f"Days left: {days_remaining}")
                        if san:
                            print("SAN      : " + ", ".join(san[:8]))

                return result

    except Exception as exc:
        if verbose:
            print(f"TLS inspection failed: {exc}")
        return None


# ============================================================
# DEVICE IDENTIFICATION
# ============================================================

def identify_device(
    ip,
    hostname,
    open_ports,
    web_results,
    gateway=None,
):

    combined = " ".join(
        result.get("text", "")
        for result in web_results
    )

    combined = (
        f"{hostname} {combined}"
    )

    lower = combined.lower()

    manufacturer = "Unknown"
    device_type = "Network device"
    product = "Unknown"
    model = "Unknown"
    confidence = "Low"

    evidence = []
    applications = []

    for result in web_results:

        for application in result.get(
            "applications",
            [],
        ):

            identity = (
                application["name"],
                application["port"],
            )

            if not any(
                (
                    existing["name"],
                    existing["port"],
                ) == identity
                for existing in applications
            ):

                applications.append(
                    application
                )

    # ASUS router patterns.

    asus_match = re.search(
        r"\b("
        r"RT-(?:AC|AX|BE)[A-Z0-9\-]+"
        r"|GT-(?:AC|AX|BE)[A-Z0-9\-]+"
        r")\b",
        combined,
        re.I,
    )

    if asus_match:

        manufacturer = "ASUS"
        model = asus_match.group(1)
        confidence = "High"

        evidence.append(
            f"Recognised ASUS model pattern: {model}"
        )

    if (
        "asus" in lower
        or "asuswrt" in lower
        or "zenwifi" in lower
    ):

        manufacturer = "ASUS"

        evidence.append(
            "ASUS indicator detected"
        )

    # Proxmox requires actual management evidence
    # rather than port 8006 alone.

    proxmox_evidence = any(
        (
            "proxmox" in result.get(
                "text",
                "",
            ).lower()
            or "pve-api-daemon" in result.get(
                "text",
                "",
            ).lower()
        )
        for result in web_results
    )

    if proxmox_evidence:

        manufacturer = "Proxmox"
        device_type = "Virtualisation host"
        product = "Proxmox VE"
        confidence = "High"

        evidence.append(
            "Proxmox web management indicators detected"
        )

    # TrueNAS.

    truenas_evidence = (
        "truenas" in lower
        or hostname.lower().startswith(
            "truenas"
        )
    )

    if truenas_evidence:

        manufacturer = "iXsystems / TrueNAS"
        device_type = "NAS / storage server"
        product = "TrueNAS"
        confidence = "High"

        evidence.append(
            "TrueNAS hostname/web indicator detected"
        )

    # TP-Link.

    if (
        "tp-link" in lower
        or "tp link" in lower
        or "tp-link corporation" in lower
    ):

        manufacturer = "TP-Link"

        if confidence == "Low":
            confidence = "Medium"

        evidence.append(
            "TP-Link branding detected"
        )

    tp_match = re.search(
        r"\b("
        r"TL-(?:SG|SX|SL|SF|ER)"
        r"[A-Z0-9\-]+"
        r")\b",
        combined,
        re.I,
    )

    if tp_match:

        manufacturer = "TP-Link"
        model = tp_match.group(1)
        confidence = "High"

        evidence.append(
            f"TP-Link model identifier detected: {model}"
        )

    # Do not call something a switch merely because
    # TP-Link manufactured it.

    switch_clues = []

    for result in web_results:

        switch_clues.extend(
            result.get(
                "js_info",
                {},
            ).get(
                "switch_clues",
                [],
            )
        )

    switch_clues = list(
        dict.fromkeys(
            switch_clues
        )
    )

    if switch_clues:

        device_type = "Managed network switch"

        evidence.append(
            "Switch-management indicators: "
            + ", ".join(
                switch_clues[:5]
            )
        )

        confidence = (
            "High"
            if manufacturer != "Unknown"
            else "Medium"
        )

    # Gateway role has priority.

    if (
        gateway
        and ip == gateway
    ):

        device_type = "Router / gateway"

        evidence.append(
            "Address matches confirmed LAN gateway"
        )

        if manufacturer != "Unknown":
            confidence = "High"

    elif (
        manufacturer != "Unknown"
        and device_type == "Network device"
        and any(
            port in open_ports
            for port in WEB_PORTS
        )
    ):

        device_type = (
            "Web-managed network device"
        )

        if confidence == "Low":
            confidence = "Medium"

    return {
        "manufacturer": manufacturer,
        "device_type": device_type,
        "product": product,
        "model": model,
        "confidence": confidence,
        "applications": applications,
        "evidence": list(
            dict.fromkeys(
                evidence
            )
        ),
    }


# ============================================================
# MANAGEMENT TRANSPORT
# ============================================================

def analyse_management_transport(
    ip,
    web_results,
):

    http_results = [
        result
        for result in web_results
        if (
            not result.get("error")
            and result.get("scheme") == "http"
        )
    ]

    https_results = [
        result
        for result in web_results
        if (
            not result.get("error")
            and result.get("scheme") == "https"
        )
    ]

    http_auth = [
        result
        for result in http_results
        if result.get("auth")
    ]

    https_auth = [
        result
        for result in https_results
        if result.get("auth")
    ]

    secure_redirects = [
        result
        for result in http_results
        if result.get("secure_redirect")
    ]

    if http_auth:

        if secure_redirects:

            add_finding(
                "INFO",
                "Management interfaces",
                (
                    "HTTP authentication-related content "
                    "redirects towards HTTPS."
                ),
                ip,
            )

        elif https_results:

            add_finding(
                "CAUTION",
                "Management interfaces",
                (
                    "Authentication-related content is accessible over HTTP "
                    "and no redirect to HTTPS was observed. HTTPS is available "
                    "separately. No credentials were submitted, so the transport "
                    "used by an actual login submission was not verified."
                ),
                ip,
            )

        else:

            add_finding(
                "CAUTION",
                "Management interfaces",
                (
                    "Authentication-related content was "
                    "detected over HTTP and no HTTPS "
                    "management service was detected."
                ),
                ip,
            )

    elif http_results and https_results:

        add_finding(
            "INFO",
            "Management interfaces",
            (
                "HTTP and HTTPS web services are both "
                "available. No credential submission "
                "was attempted."
            ),
            ip,
        )

    elif http_results:

        add_finding(
            "INFO",
            "Management interfaces",
            "HTTP web service detected.",
            ip,
        )

    elif https_results:

        add_finding(
            "INFO",
            "Management interfaces",
            "HTTPS web service detected.",
            ip,
        )

    return {
        "http": bool(http_results),
        "https": bool(https_results),
        "http_auth": bool(http_auth),
        "https_auth": bool(https_auth),
        "secure_redirect": bool(secure_redirects),
    }


# ============================================================
# DEVICE ANALYSIS
# ============================================================

def certificate_covers_target(tls_info, target):
    """Return True/False when certificate SAN coverage can be assessed."""
    if not tls_info:
        return None
    sans = tls_info.get("certificate_san") or []
    if not sans:
        return None
    target_text = str(target).strip().lower()
    return any(str(value).strip().lower() == target_text for value in sans)


def print_application_transport_security(ip, identity, web_results, tls_results):
    """Print transport evidence per identified web application."""
    applications = identity.get("applications") or []
    if not applications:
        return False

    heading("APPLICATION TRANSPORT SECURITY")

    web_by_port = {
        item.get("port"): item
        for item in web_results
        if item and not item.get("error")
    }

    for app in applications:
        name = app.get("name", "Web application")
        port = app.get("port")
        web = web_by_port.get(port) or {}
        scheme = web.get("scheme") or ("https" if port in HTTPS_PORTS else "http")
        auth = web_service_auth_evidence(web)

        print(name)
        print(f"  Port             : {port}")
        print(f"  Transport        : {scheme.upper()}")

        if scheme == "https":
            tls = tls_results.get(port) or {}
            print(f"  TLS              : {tls.get('protocol') or 'Not determined'}")
            coverage = certificate_covers_target(tls, ip)
            if coverage is True:
                print(f"  Certificate IP   : {ip} covered by SAN")
            elif coverage is False:
                print(f"  Certificate IP   : {ip} not listed in SAN")
            else:
                print("  Certificate IP   : Coverage not determined")
            print("  Assessment       : INFO")
        else:
            print(f"  Auth evidence    : {'Yes' if auth else 'No'}")
            redirect = web_service_secure_redirect(web)
            print(f"  HTTPS redirect   : {'Detected' if redirect else 'Not detected'}")
            if auth and not redirect:
                print("  Assessment       : CAUTION")
            else:
                print("  Assessment       : INFO")

        print()

    return True


def analyse_device_engine(
    ip,
    lan,
    known_ports=None,
    verbose=True,
):

    hostname = reverse_dns(ip)

    if known_ports is None:

        open_ports = []

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=40
        ) as executor:

            futures = {
                executor.submit(
                    tcp_open,
                    ip,
                    port,
                    PORT_TIMEOUT,
                ): port
                for port in SERVICE_PORTS
            }

            for future in (
                concurrent.futures.as_completed(
                    futures
                )
            ):

                port = futures[future]

                try:

                    if future.result():
                        open_ports.append(port)

                except Exception:
                    pass

        open_ports.sort()

    else:

        open_ports = sorted(
            set(known_ports)
        )

    banners = {}

    if verbose:

        heading(
            f"DEVICE ANALYSIS : {ip}"
        )

        print(
            f"Hostname : {hostname}"
        )

        heading(
            "SERVICE DISCOVERY"
        )

    for port in open_ports:

        if verbose:

            print(
                f"[OPEN] {port:<5} "
                f"{SERVICE_PORTS.get(port, 'Unknown')}"
            )

        if port in (
            21,
            22,
            23,
        ):

            banner = grab_banner(
                ip,
                port,
            )

            if banner:

                banners[port] = banner

                if verbose:

                    print(
                        "       Banner: "
                        + banner.splitlines()[
                            0
                        ][:200]
                    )

    web_results = []

    for port in open_ports:

        if port in WEB_PORTS:

            web_results.append(
                analyse_web_service(
                    ip,
                    port,
                    verbose=verbose,
                )
            )

    tls_results = {}

    for port in open_ports:

        if port in HTTPS_PORTS:

            tls_results[port] = (
                get_tls_information(
                    ip,
                    port,
                    verbose=verbose,
                )
            )

    identity = identify_device(
        ip,
        hostname,
        open_ports,
        web_results,
        gateway=lan.get("gateway"),
    )

    transport = analyse_management_transport(
        ip,
        web_results,
    )

    # Useful OS evidence without claiming exact OS
    # unless the banner actually states it.

    os_evidence = []

    ssh_banner = banners.get(
        22,
        "",
    )

    if ssh_banner:

        os_evidence.append(
            f"SSH: {ssh_banner.splitlines()[0][:180]}"
        )

    if verbose:

        heading(
            "DEVICE IDENTIFICATION"
        )

        print(
            f"Manufacturer : {identity['manufacturer']}"
        )

        print(
            f"Device type  : {identity['device_type']}"
        )

        print(
            f"Product      : {identity['product']}"
        )

        print(
            f"Model        : {identity['model']}"
        )

        print(
            f"Confidence   : {identity['confidence']}"
        )

        if identity["applications"]:

            print()
            print(
                "Hosted applications:"
            )

            for application in identity[
                "applications"
            ]:

                print(
                    f"  {application['name']} "
                    f"on port {application['port']} "
                    f"({application['type']})"
                )

        if os_evidence:

            print()
            print(
                "OS / service evidence:"
            )

            for evidence in os_evidence:

                print(
                    f"  {evidence}"
                )

        if identity["evidence"]:

            print()
            print("Identification evidence:")

            for evidence in identity[
                "evidence"
            ]:

                print(
                    f"  {evidence}"
                )

        app_transport_printed = print_application_transport_security(
            ip, identity, web_results, tls_results
        )

        if not app_transport_printed:
            heading(
                "MANAGEMENT SECURITY"
            )

            print(
                f"HTTP available     : "
                f"{'Yes' if transport['http'] else 'No'}"
            )

            print(
                f"HTTPS available    : "
                f"{'Yes' if transport['https'] else 'No'}"
            )

            print(
                f"HTTP auth evidence : "
                f"{'Yes' if transport['http_auth'] else 'No'}"
            )

            print(
                f"HTTPS redirect     : "
                f"{'Detected' if transport['secure_redirect'] else 'Not detected'}"
            )

    return {
        "ip": ip,
        "hostname": hostname,
        "open_ports": open_ports,
        "banners": banners,
        "web_results": web_results,
        "tls": tls_results,
        "identity": identity,
        "transport": transport,
        "os_evidence": os_evidence,
    }


# ============================================================
# INTERACTIVE DEVICE ANALYSIS
# ============================================================

def analyse_local_device():

    lan = ensure_lan()

    if not lan["confirmed"]:

        print(
            "A confirmed LAN is required."
        )

        return None

    ip = input(
        "Enter local device IPv4 address: "
    ).strip()

    try:
        target = ipaddress.IPv4Address(ip)

    except Exception:

        print(
            "Invalid IPv4 address."
        )

        return None

    if target not in lan["network"]:

        print(
            "Target rejected. Analysis is restricted "
            "to the confirmed local network."
        )

        return None

    return analyse_device_engine(
        ip,
        lan,
        verbose=True,
    )


def analyse_router():

    lan = ensure_lan()

    if not lan["confirmed"]:

        print(
            "A confirmed LAN is required."
        )

        return

    if not lan["gateway"]:

        print(
            "No router/gateway has been configured."
        )

        return

    analyse_device_engine(
        lan["gateway"],
        lan,
        verbose=True,
    )


# ============================================================
# AUTOMATIC ANALYSIS
# ============================================================

def analyse_discovered_devices(
    devices,
    lan,
):

    heading(
        "AUTOMATIC DEVICE ANALYSIS"
    )

    results = []

    if not devices:

        print(
            "No responding devices to analyse."
        )

        return results

    for number, device in enumerate(
        devices,
        1,
    ):

        print()
        print(
            f"[{number}/{len(devices)}] "
            f"Analysing {device['ip']}..."
        )

        result = analyse_device_engine(
            device["ip"],
            lan,
            known_ports=device["open_ports"],
            verbose=False,
        )

        results.append(result)

        identity = result["identity"]

        ports = ", ".join(
            str(port)
            for port in result["open_ports"]
        )

        print(
            f"  Host         : {result['hostname']}"
        )

        print(
            f"  Type         : {identity['device_type']}"
        )

        print(
            f"  Manufacturer : {identity['manufacturer']}"
        )

        print(
            f"  Product      : {identity['product']}"
        )

        print(
            f"  Model        : {identity['model']}"
        )

        print(
            f"  Confidence   : {identity['confidence']}"
        )

        print(
            f"  Ports        : {ports}"
        )

        if identity["applications"]:

            print(
                "  Applications :"
            )

            for application in identity[
                "applications"
            ]:

                print(
                    f"      {application['name']} "
                    f"on port {application['port']}"
                )

    return results


# ============================================================
# CONSOLIDATED LAN AUDIT_FINDINGS
# ============================================================

def build_lan_findings(
    analysed,
):

    for result in analysed:

        ip = result["ip"]
        identity = result["identity"]

        description = (
            identity["product"]
            if identity["product"] != "Unknown"
            else identity["device_type"]
        )

        if identity["model"] != "Unknown":

            description += (
                f" ({identity['model']})"
            )

        add_finding(
            "INFO",
            "LAN devices",
            description,
            ip,
        )

        for application in identity[
            "applications"
        ]:

            add_finding(
                "INFO",
                "Applications",
                (
                    f"{application['name']} is available "
                    f"on port {application['port']}."
                ),
                ip,
            )

        if 23 in result["open_ports"]:

            add_finding(
                "CAUTION",
                "Services",
                "Telnet service detected.",
                ip,
            )

        if 21 in result["open_ports"]:

            add_finding(
                "INFO",
                "Services",
                "FTP service detected.",
                ip,
            )

        for port, tls in result[
            "tls"
        ].items():

            if not tls:
                continue

            add_finding(
                "INFO",
                "TLS",
                (
                    f"Port {port} negotiated "
                    f"{tls.get('protocol') or 'unknown TLS'} "
                    f"using {tls.get('cipher') or 'unknown cipher'}."
                ),
                ip,
            )


# ============================================================
# V3.5 APPLICATION-SPECIFIC WEB TRANSPORT ASSESSMENT
# ============================================================

def web_service_auth_evidence(web):
    """Return conservative authentication evidence for one web service."""

    if not web:
        return False

    parser = web.get("parser")
    js = web.get("javascript") or {}

    if parser:
        if getattr(parser, "password_inputs", 0):
            return True

        for form in getattr(parser, "forms", []):
            action = str(form.get("action") or "").lower()
            if any(word in action for word in ("login", "logon", "auth", "signin")):
                return True

    for endpoint in js.get("endpoints", []):
        endpoint = str(endpoint).lower()
        if any(word in endpoint for word in ("login", "logon", "auth", "signin")):
            return True

    combined = " ".join(
        [
            str(web.get("title") or ""),
            str(web.get("text") or ""),
            str(js.get("text") or ""),
        ]
    ).lower()

    return any(
        word in combined
        for word in (
            "login",
            "logon",
            "username",
            "password",
            "authentication",
            "sign in",
        )
    )


def web_service_secure_redirect(web):
    """Check whether this exact HTTP service was observed moving to HTTPS."""

    if not web:
        return False

    # Support the field names used by the existing V3.3/V3.4 analyser.
    for key in (
        "redirects_to_https",
        "redirect_to_https",
        "https_redirect",
        "meta_refresh_https",
    ):
        if web.get(key):
            return True

    location = str(
        web.get("location")
        or web.get("redirect")
        or web.get("final_url")
        or ""
    ).lower()

    if location.startswith("https://"):
        return True

    followed = str(web.get("followed_url") or "").lower()
    return followed.startswith("https://")


def suppress_redundant_management_findings(analysed):
    """
    Remove the older device-wide HTTP/HTTPS authentication wording when
    identified applications on that host have been assessed independently.
    """
    app_hosts = set()

    for result in analysed:
        identity = result.get("identity", {})
        if identity.get("applications"):
            app_hosts.add(result.get("ip"))

    if not app_hosts:
        return

    kept = []

    for finding in AUDIT_FINDINGS:
        device = finding.get("device")
        category = finding.get("category", "")
        message = finding.get("message", "")

        redundant = (
            device in app_hosts
            and category == "Management interfaces"
            and
            "Authentication-related content is visible over HTTP and HTTPS is also available"
            in message
        )

        if not redundant:
            kept.append(finding)

    AUDIT_FINDINGS[:] = kept


def assess_application_web_transport(analysed):
    """
    V3.5.1: assess each identified web application independently.

    Uses the existing safe GET-only web analyser. It does not submit forms,
    credentials or POST requests. HTTPS on another application/port is not
    treated as protection for an HTTP application.
    """

    for result in analysed:
        ip = result["ip"]
        identity = result["identity"]

        for app in identity.get("applications", []):
            name = app.get("name", "Web application")
            port = app.get("port")

            if not isinstance(port, int):
                continue

            scheme = "https" if port in HTTPS_PORTS else "http"

            try:
                web = analyse_web_service(
                    ip,
                    port,
                    scheme,
                )
            except Exception:
                web = None

            if not web:
                continue

            auth = web_service_auth_evidence(web)

            if scheme == "https":
                add_finding(
                    "INFO",
                    "Application transport",
                    (
                        f"{name} on port {port} is served over HTTPS. "
                        "No credentials were submitted."
                    ),
                    ip,
                )
                continue

            if web_service_secure_redirect(web):
                add_finding(
                    "OK",
                    "Application transport",
                    (
                        f"{name} on HTTP port {port} was observed "
                        "redirecting to HTTPS."
                    ),
                    ip,
                )
                continue

            if auth:
                add_finding(
                    "CAUTION",
                    "Application transport",
                    (
                        f"{name} on port {port} exposes authentication-related "
                        "content over HTTP and no secure redirect was observed "
                        "for this application. No credentials were submitted."
                    ),
                    ip,
                )
            else:
                add_finding(
                    "INFO",
                    "Application transport",
                    (
                        f"{name} is available over HTTP on port {port}. "
                        "No authentication transport was verified."
                    ),
                    ip,
                )


def wifi_5ghz_block(channel):
    """Return the common 80 MHz 5 GHz block containing a primary channel."""

    blocks = (
        (36, 40, 44, 48),
        (52, 56, 60, 64),
        (100, 104, 108, 112),
        (116, 120, 124, 128),
        (132, 136, 140, 144),
        (149, 153, 157, 161),
    )

    for block in blocks:
        if channel in block:
            return block

    return None


def build_v35_channel_guidance(records, connected_bssid):
    """
    Add channel-block observations without automatically changing settings
    or claiming that a different channel will necessarily perform better.
    """

    connected = None

    for ap in records or []:
        if str(ap.get("bssid") or "").lower() == str(connected_bssid or "").lower():
            connected = ap
            break

    if not connected or connected.get("band") != "5 GHz":
        return

    channel = connected.get("channel")
    width = connected.get("bandwidth")
    block = wifi_5ghz_block(channel)

    if not block:
        return

    current_block_aps = []
    other_block_aps = {}

    for ap in records:
        if ap is connected or ap.get("band") != "5 GHz":
            continue

        ap_channel = ap.get("channel")
        ap_block = wifi_5ghz_block(ap_channel)

        if not ap_block:
            continue

        if ap_block == block:
            current_block_aps.append(ap)
        else:
            other_block_aps.setdefault(ap_block, []).append(ap)

    strong_current = [
        ap for ap in current_block_aps
        if isinstance(ap.get("rssi"), int) and ap["rssi"] >= -70
    ]

    if not strong_current:
        return

    message = (
        f"The connected AP is using the 5 GHz 80 MHz block "
        f"{block[0]}-{block[-1]}. Changing only between primary channels "
        f"{'/'.join(str(c) for c in block)} would remain inside the same "
        "80 MHz block and would not avoid those overlapping networks."
    )

    add_finding(
        "INFO",
        "WiFi channel guidance",
        message,
    )

    candidates = []

    for candidate_block, aps in other_block_aps.items():
        signals = [
            ap["rssi"]
            for ap in aps
            if isinstance(ap.get("rssi"), int)
        ]

        strongest = max(signals) if signals else -999
        candidates.append(
            (strongest, candidate_block, len(aps))
        )

    if candidates:
        candidates.sort()
        strongest, candidate_block, count = candidates[0]

        dfs_note = ""

        if candidate_block[0] in (52, 100, 116, 132):
            dfs_note = (
                " This block can be subject to DFS/regulatory requirements "
                "and client/router compatibility should be checked before "
                "changing settings."
            )

        add_finding(
            "INFO",
            "WiFi channel guidance",
            (
                f"In this scan the {candidate_block[0]}-{candidate_block[-1]} "
                f"80 MHz block had {count} visible AP(s); its strongest "
                f"observed signal was {strongest} dBm. This is a snapshot, "
                "not an automatic channel recommendation."
                + dfs_note
            ),
        )

# ============================================================
# V3.4 SERVICE AND WIFI ASSESSMENT
# ============================================================

SERVICE_CONTEXT = {
    21: ("FTP", "Legacy clear-text file transfer unless separately protected."),
    22: ("SSH", "Encrypted remote administration service."),
    23: ("Telnet", "Legacy clear-text remote administration."),
    53: ("DNS", "Name-resolution service. Expected on many routers."),
    80: ("HTTP", "Unencrypted web service. Authentication exposure is assessed separately."),
    139: ("NetBIOS", "Legacy Windows/SMB discovery and sharing service."),
    443: ("HTTPS", "Encrypted web service."),
    445: ("SMB", "File-sharing service. Keep restricted to trusted LAN clients."),
    554: ("RTSP", "Streaming service commonly used by cameras and media devices."),
    631: ("IPP", "Network printing service."),
    1883: ("MQTT", "Common unencrypted MQTT service unless application-layer protection is configured."),
    2869: ("UPnP", "UPnP-related service. Exposure should normally remain local."),
    3389: ("RDP", "Remote desktop administration service."),
    5000: ("HTTP", "Alternate unencrypted web service."),
    5001: ("HTTPS", "Alternate encrypted web service."),
    5900: ("VNC", "Remote desktop service. Security depends on server configuration."),
    8000: ("HTTP", "Alternate unencrypted web/application service."),
    8006: ("HTTPS", "Common Proxmox VE management service when identified as Proxmox."),
    8080: ("HTTP", "Alternate unencrypted web/application service."),
    8081: ("HTTP", "Alternate unencrypted web/application service."),
    8443: ("HTTPS", "Alternate encrypted web/management service."),
    9000: ("HTTP", "Alternate web/application service."),
    9100: ("Printer", "Raw network printing service."),
}


def assess_discovery_consistency(devices):
    """
    Report devices that answered inconsistently across discovery passes.
    This is an observation, not a security verdict.
    """

    for device in devices:
        seen = (
            device.get("seen")
            or device.get("seen_count")
            or device.get("passes_seen")
        )
        total = (
            device.get("passes")
            or device.get("pass_count")
            or DISCOVERY_PASSES
        )

        try:
            seen = int(seen)
            total = int(total)
        except (TypeError, ValueError):
            continue

        if 0 < seen < total:
            ports = device.get("open_ports", [])
            port_text = (
                ", ".join(str(p) for p in ports)
                if ports else "none retained"
            )

            add_finding(
                "INFO",
                "Discovery consistency",
                (
                    f"Intermittent response: seen in {seen}/{total} "
                    f"discovery passes. Observed TCP port(s): {port_text}. "
                    "This can occur when a device sleeps, disconnects or "
                    "temporarily changes service state."
                ),
                device.get("ip"),
            )



def assess_web_and_tls_security(analysed):
    """Add conservative web-header and certificate observations."""
    for result in analysed:
        ip = result.get("ip")
        for web in result.get("web_results", []):
            if not web or web.get("error"):
                continue
            port = web.get("port")
            scheme = web.get("scheme")
            headers = web.get("security_headers") or {}
            cookies = web.get("cookie_flags") or {}

            if scheme == "https":
                missing = []
                if not headers.get("hsts"):
                    missing.append("HSTS")
                if not headers.get("x_content_type_options"):
                    missing.append("X-Content-Type-Options")
                frame_ok = bool(
                    headers.get("x_frame_options")
                    or (headers.get("csp") and "frame-ancestors" in headers.get("csp", "").lower())
                )
                if not frame_ok:
                    missing.append("frame protection")
                if missing:
                    add_finding(
                        "INFO", "HTTP security headers",
                        f"HTTPS port {port} did not advertise {', '.join(missing)} in the observed response. Internal appliance interfaces do not always use every browser security header.",
                        ip,
                    )
            elif web.get("secure_redirect"):
                add_finding(
                    "INFO", "HTTP redirects",
                    f"HTTP port {port} redirects towards HTTPS.", ip,
                )

            if cookies.get("present"):
                missing_cookie = []
                if scheme == "https" and not cookies.get("secure"):
                    missing_cookie.append("Secure")
                if not cookies.get("httponly"):
                    missing_cookie.append("HttpOnly")
                if not cookies.get("samesite"):
                    missing_cookie.append("SameSite")
                if missing_cookie:
                    add_finding(
                        "INFO", "Cookie security",
                        f"Port {port} returned a cookie without observed {', '.join(missing_cookie)} attribute(s). This is based only on the sampled response.",
                        ip,
                    )

        for port, tls in result.get("tls", {}).items():
            if not tls:
                continue
            days = tls.get("certificate_days_remaining")
            if tls.get("certificate_expired") is True:
                add_finding("CAUTION", "TLS certificates", f"Port {port} presented an expired TLS certificate.", ip)
            elif isinstance(days, int) and days < 30:
                add_finding("CAUTION", "TLS certificates", f"Port {port} certificate expires in approximately {days} day(s).", ip)
            elif isinstance(days, int):
                add_finding("INFO", "TLS certificates", f"Port {port} certificate has approximately {days} day(s) remaining.", ip)

            coverage = certificate_covers_target(tls, ip)
            if coverage is True:
                add_finding(
                    "INFO", "TLS certificates",
                    f"Port {port} certificate SAN explicitly covers management address {ip}.", ip
                )
            elif coverage is False:
                add_finding(
                    "INFO", "TLS certificates",
                    f"Port {port} certificate SAN does not list management address {ip}. A client connecting by IP may report a name mismatch.", ip
                )

            subject = str(tls.get("certificate_subject") or "").strip()
            issuer = str(tls.get("certificate_issuer") or "").strip()
            if subject and issuer and subject == issuer:
                add_finding(
                    "INFO", "TLS certificates",
                    f"Port {port} certificate appears self-issued because the observed subject and issuer are the same.", ip
                )

def assess_service_exposure(analysed):

    for result in analysed:

        ip = result["ip"]
        identity = result["identity"]

        for port in result["open_ports"]:

            service, explanation = SERVICE_CONTEXT.get(
                port,
                (
                    SERVICE_PORTS.get(port, "Unknown"),
                    "Detected TCP service.",
                ),
            )

            level = "INFO"

            if port in (23,):
                level = "CAUTION"

            add_finding(
                level,
                "Service exposure",
                f"Port {port} ({service}): {explanation}",
                ip,
            )

        # Add context without claiming a vulnerability.
        if (
            identity["product"] == "Proxmox VE"
            and 8006 in result["open_ports"]
        ):
            add_finding(
                "INFO",
                "Service exposure",
                "Proxmox VE management was identified on HTTPS port 8006.",
                ip,
            )

        if (
            identity["product"] == "TrueNAS"
            and 445 in result["open_ports"]
        ):
            add_finding(
                "INFO",
                "Service exposure",
                "SMB is exposed by the identified TrueNAS host on the local LAN.",
                ip,
            )


def build_wifi_channel_observations(records, connected_bssid):

    if not records or not connected_bssid:
        return

    overlap = calculate_connected_overlap(
        records,
        connected_bssid,
    )

    if not overlap:
        return

    connected = overlap["connected"]
    overlapping = overlap["overlapping"]

    strong = [
        ap
        for ap in overlapping
        if isinstance(ap.get("rssi"), int)
        and ap["rssi"] >= -70
    ]

    if strong:

        strongest = strong[0]

        add_finding(
            "INFO",
            "WiFi channel assessment",
            (
                f"The connected {connected['band']} AP uses channel "
                f"{connected['channel']} at {connected['bandwidth']} MHz. "
                f"{len(strong)} overlapping AP(s) were observed at "
                f"-70 dBm or stronger. The strongest was "
                f"{strongest['ssid'] or '<Hidden SSID>'} on channel "
                f"{strongest['channel']} at {strongest['rssi']} dBm. "
                "This scan is an RF observation, not proof that changing "
                "channel will improve performance."
            ),
        )

    else:

        add_finding(
            "OK",
            "WiFi channel assessment",
            (
                "No approximately overlapping same-band AP was observed "
                "at -70 dBm or stronger during this scan."
            ),
        )


def compare_baseline_data(old, current, lan, record_findings=True):

    result = {
        "available": bool(old),
        "compatible": True,
        "created": old.get("created") if isinstance(old, dict) else None,
        "new": [],
        "missing": [],
        "changed": [],
    }

    if not old:
        result["compatible"] = False
        return result

    old_network = old.get("network")

    if old_network and old_network != str(lan["network"]):
        result["compatible"] = False
        return result

    old_map = {
        item["ip"]: item
        for item in old.get("devices", [])
        if isinstance(item, dict) and item.get("ip")
    }

    current_map = {
        item["ip"]: item
        for item in current
        if isinstance(item, dict) and item.get("ip")
    }

    for ip in sorted(
        set(current_map) - set(old_map),
        key=ipaddress.IPv4Address,
    ):

        item = {
            "ip": ip,
            "hostname": current_map[ip].get("hostname", "Unknown"),
        }

        result["new"].append(item)

        if record_findings:
            add_finding(
                "INFO",
                "Baseline changes",
                "Newly observed responding device compared with the saved baseline. "
"This is a change observation, not evidence of malicious activity.",
                ip,
            )

    for ip in sorted(
        set(old_map) - set(current_map),
        key=ipaddress.IPv4Address,
    ):

        item = {
            "ip": ip,
            "hostname": old_map[ip].get("hostname", "Unknown"),
        }

        result["missing"].append(item)

        if record_findings:
            add_finding(
                "INFO",
                "Baseline changes",
                (
                    "Device in the baseline did not respond to this "
                    "TCP discovery scan."
                ),
                ip,
            )

    for ip in sorted(
        set(old_map) & set(current_map),
        key=ipaddress.IPv4Address,
    ):

        before = old_map[ip]
        after = current_map[ip]

        old_ports = set(before.get("open_ports", []))
        new_ports = set(after.get("open_ports", []))

        opened = sorted(new_ports - old_ports)
        closed = sorted(old_ports - new_ports)

        if opened or closed:

            change = {
                "ip": ip,
                "opened": opened,
                "closed": closed,
            }

            result["changed"].append(change)

            if record_findings and opened:
                add_finding(
                    "INFO",
                    "Baseline changes",
                    f"Newly detected TCP port(s): {opened}.",
                    ip,
                )

            if record_findings and closed:
                add_finding(
                    "INFO",
                    "Baseline changes",
                    (
                        "Previously detected TCP port(s) were not "
                        f"detected in this scan: {closed}."
                    ),
                    ip,
                )

    if (
        record_findings
        and not result["new"]
        and not result["missing"]
        and not result["changed"]
    ):
        add_finding(
            "OK",
            "Baseline changes",
            (
                "No device or TCP service changes were detected "
                "compared with the saved baseline."
            ),
        )

    return result


def print_integrated_baseline(result):

    heading("AUTOMATIC BASELINE COMPARISON")

    if not result["available"]:
        print(
            "No saved baseline exists. Use option 10 to create one."
        )
        return

    if not result["compatible"]:
        print(
            "A saved baseline exists but it is for a different "
            "network, so it was not compared."
        )
        return

    print(
        f"Baseline created : "
        f"{result.get('created') or 'Unknown'}"
    )

    print(
        f"New devices      : {len(result['new'])}"
    )

    print(
        f"Missing devices  : {len(result['missing'])}"
    )

    print(
        f"Changed devices  : {len(result['changed'])}"
    )

    for item in result["new"]:
        print(
            f"[NEW] {item['ip']} {item['hostname']}"
        )

    for item in result["missing"]:
        print(
            f"[MISSING] {item['ip']} {item['hostname']}"
        )

    for item in result["changed"]:

        if item["opened"]:
            print(
                f"[CHANGED] {item['ip']} "
                f"new ports: {item['opened']}"
            )

        if item["closed"]:
            print(
                f"[CHANGED] {item['ip']} "
                f"ports no longer detected: {item['closed']}"
            )

    if (
        not result["new"]
        and not result["missing"]
        and not result["changed"]
    ):
        print(
            "No changes detected compared with the saved baseline."
        )


def serialise_audit_device(result):

    identity = result["identity"]

    return {
        "ip": result["ip"],
        "hostname": result["hostname"],
        "open_ports": result["open_ports"],
        "manufacturer": identity["manufacturer"],
        "device_type": identity["device_type"],
        "product": identity["product"],
        "model": identity["model"],
        "confidence": identity["confidence"],
        "applications": identity["applications"],
        "os_evidence": result["os_evidence"],
        "tls": result["tls"],
        "transport": result["transport"],
    }

# ============================================================
# BASELINE
# ============================================================

def load_baseline():

    data = load_json_file(
        BASELINE_FILE
    )

    if data is not None:
        return data

    for filename in LEGACY_BASELINES:

        data = load_json_file(
            filename
        )

        if data is not None:

            save_json_file(
                BASELINE_FILE,
                data,
            )

            return data

    return None


def save_baseline():

    devices, lan = discover_devices()

    if not lan["confirmed"]:
        return

    if not devices:

        print(
            "No responding devices. "
            "Baseline was not saved."
        )

        return

    baseline = {
        "version": VERSION,
        "created": now_string(),
        "network": str(
            lan["network"]
        ),
        "gateway": lan["gateway"],
        "devices": [
            {
                "ip": device["ip"],
                "hostname": device["hostname"],
                "open_ports": device["open_ports"],
            }
            for device in devices
        ],
    }

    if save_json_file(
        BASELINE_FILE,
        baseline,
    ):

        print(
            f"Baseline saved to "
            f"{BASELINE_FILE}"
        )


def compare_baseline():

    old = load_baseline()

    if not old:

        print(
            "No saved baseline exists."
        )

        return

    current, lan = discover_devices()

    if not lan["confirmed"]:
        return

    old_map = {
        item["ip"]: item
        for item in old.get(
            "devices",
            [],
        )
    }

    current_map = {
        item["ip"]: item
        for item in current
    }

    changes = 0

    heading(
        "BASELINE COMPARISON"
    )

    for ip in sorted(
        set(current_map) - set(old_map),
        key=ipaddress.IPv4Address,
    ):

        changes += 1

        print(
            f"[NEW] {ip} "
            f"{current_map[ip]['hostname']}"
        )

        add_finding(
            "INFO",
            "Baseline changes",
            (
                "New responding device compared "
                "with the saved baseline."
            ),
            ip,
        )

    for ip in sorted(
        set(old_map) - set(current_map),
        key=ipaddress.IPv4Address,
    ):

        changes += 1

        print(
            f"[MISSING] {ip} "
            f"{old_map[ip].get('hostname', 'Unknown')}"
        )

        add_finding(
            "INFO",
            "Baseline changes",
            (
                "Device in the baseline did not "
                "respond to this TCP discovery scan."
            ),
            ip,
        )

    for ip in sorted(
        set(old_map) & set(current_map),
        key=ipaddress.IPv4Address,
    ):

        before = old_map[ip]
        after = current_map[ip]

        old_ports = set(
            before.get(
                "open_ports",
                [],
            )
        )

        new_ports = set(
            after.get(
                "open_ports",
                [],
            )
        )

        opened = sorted(
            new_ports - old_ports
        )

        closed = sorted(
            old_ports - new_ports
        )

        if opened:

            changes += 1

            print(
                f"[CHANGED] {ip} "
                f"new ports: {opened}"
            )

        if closed:

            changes += 1

            print(
                f"[CHANGED] {ip} "
                f"ports no longer detected: {closed}"
            )

    if not changes:

        print(
            "No changes detected compared "
            "with the saved baseline."
        )

        add_finding(
            "OK",
            "Baseline changes",
            (
                "No device or TCP service changes "
                "were detected compared with baseline."
            ),
        )


def baseline_menu():

    while True:

        heading(
            "NETWORK BASELINE AND CHANGES"
        )

        print(
            "1. Create / replace baseline"
        )

        print(
            "2. Compare with baseline"
        )

        print(
            "3. Back"
        )

        choice = input(
            "\nChoose an option: "
        ).strip()

        if choice == "1":
            save_baseline()

        elif choice == "2":
            compare_baseline()

        elif choice == "3":
            return

        else:
            print(
                "Invalid option."
            )


# ============================================================
# PASSWORD STRENGTH
# ============================================================

def password_strength():

    heading(
        "PASSWORD STRENGTH CHECK"
    )

    print(
        "The password is assessed locally "
        "and is not saved."
    )

    password = getpass.getpass(
        "Enter password to assess: "
    )

    if not password:

        print(
            "No password entered."
        )

        return

    score = 0
    observations = []

    length = len(password)

    if length >= 16:
        score += 4

    elif length >= 12:
        score += 3

    elif length >= 10:
        score += 2

    elif length >= 8:
        score += 1

    else:

        observations.append(
            "Password is shorter than 8 characters."
        )

    if re.search(
        r"[a-z]",
        password,
    ):
        score += 1

    else:
        observations.append(
            "No lowercase letters detected."
        )

    if re.search(
        r"[A-Z]",
        password,
    ):
        score += 1

    else:
        observations.append(
            "No uppercase letters detected."
        )

    if re.search(
        r"\d",
        password,
    ):
        score += 1

    else:
        observations.append(
            "No digits detected."
        )

    if re.search(
        r"[^A-Za-z0-9]",
        password,
    ):
        score += 1

    common = (
        "password",
        "qwerty",
        "123456",
        "admin",
        "letmein",
        "welcome",
    )

    if any(
        item in password.lower()
        for item in common
    ):

        score -= 3

        observations.append(
            "Common password pattern detected."
        )

    if score >= 8:
        rating = "Strong"

    elif score >= 6:
        rating = "Good"

    elif score >= 4:
        rating = "Moderate"

    else:
        rating = "Weak"

    print()
    print(f"Length : {length}")
    print(f"Rating : {rating}")

    if observations:

        print()
        print("Observations:")

        for observation in observations:

            print(
                f"  {observation}"
            )


def credential_menu():

    while True:

        heading(
            "CREDENTIAL SECURITY"
        )

        print(
            "1. Check password strength"
        )

        print(
            "2. Saved WiFi credential status"
        )

        print(
            "3. Back"
        )

        choice = input(
            "\nChoose an option: "
        ).strip()

        if choice == "1":

            password_strength()

        elif choice == "2":

            heading(
                "SAVED WIFI CREDENTIAL ACCESS"
            )

            print(
                "Android protects saved WiFi "
                "credentials from ordinary applications."
            )

            print()
            print(
                "This auditor does not bypass "
                "Android security controls."
            )

        elif choice == "3":

            return

        else:

            print(
                "Invalid option."
            )



# ============================================================
# PERSISTENT DEVICE HISTORY
# ============================================================

def load_device_history():
    try:
        if not os.path.exists(HISTORY_FILE):
            return {"schema_version": 2, "audit_count": 0, "devices": {}, "wifi_snapshots": []}
        with open(HISTORY_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            raise ValueError("history root is not an object")
        data.setdefault("schema_version", 1)
        data["schema_version"] = max(int(data.get("schema_version", 1)), 2)
        data.setdefault("audit_count", 0)
        data.setdefault("devices", {})
        data.setdefault("wifi_snapshots", [])
        if not isinstance(data["devices"], dict):
            data["devices"] = {}
        return data
    except Exception as exc:
        print(f"[WARNING] Could not read {HISTORY_FILE}: {exc}")
        return {"schema_version": 2, "audit_count": 0, "devices": {}, "wifi_snapshots": []}


def save_device_history(history):
    tmp = HISTORY_FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(history, handle, indent=2, sort_keys=True)
        os.replace(tmp, HISTORY_FILE)
        return True
    except Exception as exc:
        print(f"[WARNING] Could not save {HISTORY_FILE}: {exc}")
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        return False


def update_device_history(analysed):
    history = load_device_history()
    now = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
    audit_number = int(history.get("audit_count", 0)) + 1
    history["audit_count"] = audit_number
    current_ips = set()
    changes = []

    for result in analysed or []:
        ip = str(result.get("ip") or "").strip()
        if not ip:
            continue
        current_ips.add(ip)
        ports = sorted(set(int(p) for p in result.get("open_ports", []) if str(p).isdigit()))
        identity = result.get("identity") or {}

        entry = history["devices"].setdefault(ip, {
            "first_seen": now,
            "last_seen": now,
            "audits_seen": 0,
            "last_audit_seen": audit_number,
            "ports_seen": {},
            "last_ports": [],
            "hostname": "",
            "identity": "",
            "manufacturer": "",
            "device_type": "",
            "confidence": "",
            "service_changes": [],
        })

        previous = set(int(p) for p in entry.get("last_ports", []) if str(p).isdigit())
        current = set(ports)
        if int(entry.get("audits_seen", 0)) > 0 and previous != current:
            added = sorted(current - previous)
            removed = sorted(previous - current)
            entry.setdefault("service_changes", []).append({
                "time": now,
                "audit": audit_number,
                "added_ports": added,
                "removed_ports": removed,
            })
            entry["service_changes"] = entry["service_changes"][-50:]
            changes.append((ip, added, removed))

        entry["last_seen"] = now
        entry["audits_seen"] = int(entry.get("audits_seen", 0)) + 1
        entry["last_audit_seen"] = audit_number
        entry["last_ports"] = ports

        for port in ports:
            key = str(port)
            entry.setdefault("ports_seen", {})[key] = int(entry["ports_seen"].get(key, 0)) + 1

        hostname = result.get("hostname") or result.get("host") or ""
        if hostname and str(hostname).lower() != "unknown":
            entry["hostname"] = str(hostname)

        label = identity.get("product") or identity.get("device_type") or ""
        if label and str(label).lower() != "unknown":
            entry["identity"] = str(label)
        manufacturer = identity.get("manufacturer") or ""
        if manufacturer and str(manufacturer).lower() != "unknown":
            entry["manufacturer"] = str(manufacturer)
        device_type = identity.get("device_type") or ""
        if device_type and str(device_type).lower() != "unknown":
            entry["device_type"] = str(device_type)
        confidence = identity.get("confidence") or ""
        if confidence:
            entry["confidence"] = str(confidence)

    history["last_updated"] = now
    history["last_snapshot_ips"] = sorted(current_ips)
    saved = save_device_history(history)
    return history, changes, saved


def record_history_snapshot(analysed, connection=None, wifi_records=None):
    history, changes, saved = update_device_history(analysed)
    if saved and connection is not None:
        history = load_device_history()
        bssid = str(connection.get("bssid") or "")
        overlap = calculate_connected_overlap(wifi_records or [], bssid)
        strong = 0
        overlapping = 0
        width = None
        if overlap:
            overlapping = len(overlap.get("overlapping", []))
            strong = sum(1 for ap in overlap.get("overlapping", []) if isinstance(ap.get("rssi"), int) and ap.get("rssi") >= -70)
            width = overlap.get("connected", {}).get("bandwidth")
        history.setdefault("wifi_snapshots", []).append({
            "audit": history.get("audit_count", 0),
            "time": history.get("last_updated"),
            "ssid": connection.get("ssid"),
            "bssid": connection.get("bssid"),
            "rssi": connection.get("rssi"),
            "link_speed_mbps": connection.get("link_speed_mbps"),
            "frequency_mhz": connection.get("frequency_mhz"),
            "channel": frequency_to_channel(connection.get("frequency_mhz")),
            "width_mhz": width,
            "nearby_aps": len(wifi_records or []),
            "overlapping_aps": overlapping,
            "strong_overlapping_aps": strong,
        })
        history["wifi_snapshots"] = history["wifi_snapshots"][-100:]
        saved = save_device_history(history)
    if saved:
        add_finding(
            "INFO",
            "Device history",
            f"Recorded audit snapshot {history.get('audit_count', 0)} in {HISTORY_FILE}."
        )
        for ip, added, removed in changes:
            parts = []
            if added:
                parts.append("new TCP service(s): " + ", ".join(map(str, added)))
            if removed:
                parts.append("service(s) no longer observed: " + ", ".join(map(str, removed)))
            if parts:
                add_finding(
                    "INFO",
                    "Device history",
                    f"{ip}: " + "; ".join(parts) +
                    ". This is a history change observation, not evidence of malicious activity.",
                    device=ip,
                )


def show_device_history():
    history = load_device_history()
    heading("DEVICE HISTORY")
    total = int(history.get("audit_count", 0))
    devices = history.get("devices", {})
    print(f"Recorded audit snapshots : {total}")
    print(f"Known device addresses   : {len(devices)}")

    if not devices:
        print()
        print("No device history has been recorded yet.")
        print("Run a full network audit to create the first history snapshot.")
        return

    def ip_key(value):
        try:
            return tuple(int(part) for part in value.split("."))
        except Exception:
            return (999, 999, 999, 999)

    for ip in sorted(devices, key=ip_key):
        entry = devices[ip]
        seen = int(entry.get("audits_seen", 0))
        last_audit = int(entry.get("last_audit_seen", 0))
        status = "Present in latest audit" if last_audit == total else "Not seen in latest audit"
        if total >= 2 and seen < total:
            status += " / Intermittent"

        ports_seen = entry.get("ports_seen", {})
        typical = sorted(int(p) for p in ports_seen if str(p).isdigit())

        print()
        print(ip)
        if entry.get("hostname"):
            print(f"  Hostname       : {entry['hostname']}")
        if entry.get("identity"):
            print(f"  Identity       : {entry['identity']}")
        if entry.get("manufacturer"):
            print(f"  Manufacturer   : {entry['manufacturer']}")
        if entry.get("device_type"):
            print(f"  Device type    : {entry['device_type']}")
        if entry.get("confidence"):
            print(f"  Confidence     : {entry['confidence']}")
        print(f"  First seen     : {entry.get('first_seen', 'Unknown')}")
        print(f"  Last seen      : {entry.get('last_seen', 'Unknown')}")
        print(f"  Audits seen    : {seen}/{total}")
        print(f"  Observed ports : {', '.join(map(str, typical)) if typical else 'None recorded'}")
        print(f"  Latest ports   : {', '.join(map(str, entry.get('last_ports', []))) or 'None'}")
        print(f"  Status         : {status}")

        events = entry.get("service_changes", [])
        if events:
            event = events[-1]
            parts = []
            if event.get("added_ports"):
                parts.append("added " + ",".join(map(str, event["added_ports"])))
            if event.get("removed_ports"):
                parts.append("removed " + ",".join(map(str, event["removed_ports"])))
            if parts:
                print(f"  Last change    : {'; '.join(parts)}")


    wifi_snapshots = history.get("wifi_snapshots", [])
    if wifi_snapshots:
        latest = wifi_snapshots[-1]
        print()
        subheading("Latest WiFi history")
        print(f"  Recorded samples : {len(wifi_snapshots)}")
        print(f"  SSID             : {latest.get('ssid') or 'Unknown'}")
        print(f"  RSSI             : {latest.get('rssi') if latest.get('rssi') is not None else 'Unknown'} dBm")
        print(f"  Link speed       : {latest.get('link_speed_mbps') if latest.get('link_speed_mbps') is not None else 'Unknown'} Mbps")
        print(f"  Channel          : {latest.get('channel') or 'Unknown'}")
        print(f"  Width            : {latest.get('width_mhz') if latest.get('width_mhz') is not None else 'Unknown'} MHz")
        print(f"  Nearby APs       : {latest.get('nearby_aps', 0)}")
        print(f"  Overlapping APs  : {latest.get('overlapping_aps', 0)}")
        print(f"  Strong overlaps  : {latest.get('strong_overlapping_aps', 0)}")


# ============================================================
# FULL AUDIT
# ============================================================

def full_audit():

    global LAST_AUDIT

    clear_findings()
    LAST_AUDIT = None

    heading(
        "FULL NETWORK SECURITY AUDIT"
    )

    started = now_string()

    print(
        f"Started: {started}"
    )

    connection = show_current_wifi()

    wifi_records = show_nearby_wifi()

    connected_bssid = ""

    if connection:
        connected_bssid = str(
            connection.get("bssid") or ""
        )

    build_wifi_channel_observations(
        wifi_records,
        connected_bssid,
    )

    build_v35_channel_guidance(
        wifi_records,
        connected_bssid,
    )

    lan = ensure_lan()

    if not lan["confirmed"]:

        print()
        print(
            "Active LAN audit skipped."
        )

        print(
            f"Reason: {lan['reason']}"
        )

        show_findings()

        return

    devices, lan = discover_devices()

    analysed = analyse_discovered_devices(
        devices,
        lan,
    )

    build_lan_findings(
        analysed
    )

    assess_discovery_consistency(
        devices
    )

    assess_service_exposure(
        analysed
    )

    assess_application_web_transport(
        analysed
    )

    assess_web_and_tls_security(
        analysed
    )

    suppress_redundant_management_findings(
        analysed
    )

    heading(
        "LAN DEVICE SUMMARY"
    )

    for result in analysed:

        identity = result["identity"]

        description = (
            identity["product"]
            if identity["product"] != "Unknown"
            else identity["device_type"]
        )

        if identity["model"] != "Unknown":

            description += (
                f" ({identity['model']})"
            )

        ports = ",".join(
            str(port)
            for port in result["open_ports"]
        )

        print(
            f"{result['ip']:15} "
            f"{description:35} "
            f"Ports {ports}"
        )

        for application in identity[
            "applications"
        ]:

            print(
                f"{'':15} "
                f"  App: {application['name']} "
                f"on port {application['port']}"
            )

    # Record persistent device history after successful device analysis.
    record_history_snapshot(analysed, connection, wifi_records)

    old_baseline = load_baseline()

    baseline_result = compare_baseline_data(
        old_baseline,
        devices,
        lan,
        record_findings=True,
    )

    print_integrated_baseline(
        baseline_result
    )

    show_findings()

    finished = now_string()

    heading(
        "AUDIT SUMMARY"
    )

    print(
        f"Finished        : {finished}"
    )

    print(
        f"Nearby WiFi APs : {len(wifi_records)}"
    )

    print(
        f"LAN devices     : {len(devices)}"
    )

    print(
        f"Devices analysed: {len(analysed)}"
    )

    print(
        f"Network         : {lan['network']}"
    )

    print(
        f"Gateway         : "
        f"{lan['gateway'] or 'Not configured'}"
    )

    LAST_AUDIT = {
        "version": VERSION,
        "started": started,
        "finished": finished,
        "wifi_connection": connection,
        "wifi_records": wifi_records,
        "lan": {
            "confirmed": lan["confirmed"],
            "ssid": lan["ssid"],
            "bssid": lan["bssid"],
            "ip": lan["ip"],
            "interface": lan["interface"],
            "gateway": lan["gateway"],
            "network": str(lan["network"]),
            "source": lan["source"],
            "reason": lan["reason"],
        },
        "devices": [
            serialise_audit_device(result)
            for result in analysed
        ],
        "baseline": baseline_result,
        "findings": [
            dict(finding)
            for finding in AUDIT_FINDINGS
        ],
    }


# ============================================================
# REPORT
# ============================================================

def save_report():

    heading("SAVE REPORT")

    filename = (
        f"{REPORT_PREFIX}_"
        f"{timestamp_filename()}.txt"
    )

    audit = LAST_AUDIT

    if audit is None:

        print(
            "No completed full audit is stored in this session."
        )

        print(
            "Run option 9 first for a complete V3.4 report."
        )

        return

    lan = audit["lan"]
    connection = audit.get("wifi_connection") or {}

    lines = [
        ("WiFi Security Auditor Development" if VERSION == "development" else f"WiFi Security Auditor {version_display_name()}"),
        f"Generated: {now_string()}",
        f"Audit started: {audit['started']}",
        f"Audit finished: {audit['finished']}",
        "",
        "NETWORK",
        "=" * 72,
        f"SSID: {lan.get('ssid') or 'Unknown'}",
        f"BSSID: {lan.get('bssid') or 'Unknown'}",
        f"IPv4: {lan.get('ip') or 'Unknown'}",
        f"Network: {lan.get('network') or 'Unknown'}",
        f"Gateway: {lan.get('gateway') or 'Unknown'}",
        f"Configuration: {lan.get('source') or 'None'}",
        "",
        "CURRENT WIFI",
        "=" * 72,
        f"Frequency: {connection.get('frequency_mhz') or 'Unknown'} MHz",
        f"Channel: {frequency_to_channel(connection.get('frequency_mhz')) or 'Unknown'}",
        f"RSSI: {connection.get('rssi') if connection.get('rssi') is not None else 'Unknown'} dBm",
        f"Link speed: {connection.get('link_speed_mbps') or 'Unknown'} Mbps",
        f"Nearby APs detected: {len(audit.get('wifi_records', []))}",
        "",
        "DEVICE INVENTORY",
        "=" * 72,
    ]

    for device in audit["devices"]:

        lines.extend(
            [
                "",
                f"IP: {device['ip']}",
                f"Hostname: {device['hostname']}",
                f"Type: {device['device_type']}",
                f"Manufacturer: {device['manufacturer']}",
                f"Product: {device['product']}",
                f"Model: {device['model']}",
                f"Confidence: {device['confidence']}",
                (
                    "Open ports: "
                    + ", ".join(
                        str(port)
                        for port in device["open_ports"]
                    )
                ),
            ]
        )

        if device["applications"]:

            lines.append("Applications:")

            for application in device["applications"]:

                lines.append(
                    f"  {application['name']} "
                    f"on port {application['port']}"
                )

        if device["os_evidence"]:

            lines.append("OS / service evidence:")

            for evidence in device["os_evidence"]:
                lines.append(f"  {evidence}")

        if device["tls"]:

            lines.append("TLS:")

            for port, tls in device["tls"].items():

                if not tls:
                    continue

                lines.append(
                    f"  Port {port}: "
                    f"{tls.get('protocol') or 'Unknown'}, "
                    f"{tls.get('cipher') or 'Unknown'}, "
                    f"{tls.get('bits') or 'Unknown'} bits"
                )
                if tls.get("certificate_subject"):
                    lines.append(f"    Subject: {tls.get('certificate_subject')}")
                if tls.get("certificate_issuer"):
                    lines.append(f"    Issuer: {tls.get('certificate_issuer')}")
                if tls.get("certificate_not_after"):
                    lines.append(f"    Valid to: {tls.get('certificate_not_after')}")
                if tls.get("certificate_days_remaining") is not None:
                    lines.append(f"    Days remaining: {tls.get('certificate_days_remaining')}")

    baseline = audit.get("baseline") or {}

    lines.extend(
        [
            "",
            "BASELINE COMPARISON",
            "=" * 72,
        ]
    )

    if not baseline.get("available"):

        lines.append("No saved baseline was available.")

    elif not baseline.get("compatible"):

        lines.append(
            "Saved baseline was for a different network."
        )

    else:

        lines.append(
            f"Baseline created: "
            f"{baseline.get('created') or 'Unknown'}"
        )

        lines.append(
            f"New devices: {len(baseline.get('new', []))}"
        )

        lines.append(
            f"Missing devices: {len(baseline.get('missing', []))}"
        )

        lines.append(
            f"Changed devices: {len(baseline.get('changed', []))}"
        )

        for item in baseline.get("new", []):
            lines.append(
                f"  NEW: {item['ip']} {item['hostname']}"
            )

        for item in baseline.get("missing", []):
            lines.append(
                f"  MISSING: {item['ip']} {item['hostname']}"
            )

        for item in baseline.get("changed", []):

            if item["opened"]:
                lines.append(
                    f"  CHANGED {item['ip']}: "
                    f"new ports {item['opened']}"
                )

            if item["closed"]:
                lines.append(
                    f"  CHANGED {item['ip']}: "
                    f"ports no longer detected {item['closed']}"
                )

    lines.extend(
        [
            "",
            "SECURITY FINDINGS",
            "=" * 72,
        ]
    )

    level_order = {
        "CAUTION": 0,
        "INFO": 1,
        "OK": 2,
    }

    findings = sorted(
        audit["findings"],
        key=lambda item: (
            item["category"],
            level_order.get(item["level"], 9),
            item["device"] or "",
        ),
    )

    current_category = None

    for finding in findings:

        if finding["category"] != current_category:

            current_category = finding["category"]
            lines.extend(
                [
                    "",
                    current_category,
                    "-" * len(current_category),
                ]
            )

        target = ""

        if finding["device"]:
            target = f"{finding['device']}: "

        lines.append(
            f"[{finding['level']}] "
            f"{target}{finding['message']}"
        )

    lines.extend(
        [
            "",
            "NOTES",
            "=" * 72,
            (
                "Discovery is based on TCP connection checks. "
                "Devices exposing none of the tested services may "
                "not appear."
            ),
            (
                "WiFi overlap observations are estimates based on "
                "the access points visible during the scan and do "
                "not prove interference."
            ),
            (
                "Application-specific HTTP/HTTPS findings take precedence over "
                "device-wide management observations when multiple web "
                "applications use different ports."
            ),
            (
                "No credential submission, brute forcing or "
                "exploitation is performed."
            ),
        ]
    )

    try:

        with open(
            filename,
            "w",
            encoding="utf-8",
        ) as handle:

            handle.write(
                "\n".join(lines)
            )

        print(
            "Complete V3.4 report saved to:"
        )

        print(filename)

    except Exception as exc:

        print(
            f"Unable to save report: {exc}"
        )


# ============================================================
# STARTUP
# ============================================================

def environment_check():

    heading("STARTUP CHECK")

    print(
        ("WiFi Security Auditor Development" if VERSION == "development" else f"WiFi Security Auditor {version_display_name()}")
    )

    print(
        f"Android           : "
        f"{'Yes' if is_android() else 'No'}"
    )

    print(
        f"Termux            : "
        f"{'Yes' if is_termux() else 'No'}"
    )

    api_available = (
        command_exists(
            "termux-wifi-connectioninfo"
        )
        and command_exists(
            "termux-wifi-scaninfo"
        )
    )

    print(
        f"Termux WiFi API   : "
        f"{'Available' if api_available else 'Missing'}"
    )

    connection, error = (
        get_wifi_connection()
    )

    if error:

        print(
            f"WiFi API status   : {error}"
        )

        return

    print(
        "WiFi API status   : Working"
    )

    print(
        f"Connected SSID    : "
        f"{connection.get('ssid') or 'Unknown'}"
    )

    configs = load_lan_configs()

    saved = get_saved_config(
        configs,
        connection,
    )

    if saved:

        print(
            "Saved LAN config  : Available"
        )

        print(
            f"Saved network     : "
            f"{saved.get('network')}"
        )

        print(
            f"Saved gateway     : "
            f"{saved.get('gateway') or 'Not configured'}"
        )

        print(
            "LAN activation    : "
            "Requires confirmation this session"
        )

    else:

        print(
            "Saved LAN config  : None"
        )


# ============================================================
# MENU
# ============================================================

def menu():

    while True:

        print()
        print("=" * 72)

        print(
            f" WIFI SECURITY AUDITOR {version_display_name()}"
        )

        print(
            " TERMUX / ANDROID EDITION"
        )

        print("=" * 72)

        print(
            "Use only on networks you own "
            "or are authorised to audit."
        )

        print()

        print(
            "1. Current WiFi connection"
        )

        print(
            "2. Device network information"
        )

        print(
            "3. LAN configuration"
        )

        print(
            "4. Network interfaces"
        )

        print(
            "5. Scan nearby WiFi networks"
        )

        print(
            "6. Discover devices on connected LAN"
        )

        print(
            "7. Analyse local device"
        )

        print(
            "8. Analyse router"
        )

        print(
            "9. Full network audit"
        )

        print(
            "10. Network baseline and changes"
        )

        print(
            "11. Credential security"
        )

        print(
            "12. Show security findings"
        )

        print(
            "13. Save report"
        )

        print(
            "14. Device history"
        )

        print(
            "15. Exit"
        )

        choice = input(
            "\nChoose an option: "
        ).strip()

        if choice == "1":

            show_current_wifi()

        elif choice == "2":

            show_network_information()

        elif choice == "3":

            configure_lan()

        elif choice == "4":

            show_interfaces()

        elif choice == "5":

            show_nearby_wifi()

        elif choice == "6":

            discover_devices()

        elif choice == "7":

            analyse_local_device()

        elif choice == "8":

            analyse_router()

        elif choice == "9":

            full_audit()

        elif choice == "10":

            baseline_menu()

        elif choice == "11":

            credential_menu()

        elif choice == "12":

            show_findings()

        elif choice == "13":

            save_report()

        elif choice == "14":

            show_device_history()

        elif choice == "15":

            print()
            print(
                "Exiting WiFi Security Auditor."
            )

            break

        else:

            print(
                "Invalid option."
            )


# ============================================================
# MAIN
# ============================================================


def show_development_capabilities():
    print_header("DEVELOPMENT CAPABILITIES")
    print("Current development priorities:")
    print("  Device identification evidence and confidence")
    print("  Device/service history across audits")
    print("  Intermittent-device tracking")
    print("  Application-specific HTTP/HTTPS analysis")
    print("  TLS certificate and expiry inspection")
    print("  SMB/service fingerprinting")
    print("  Network troubleshooting diagnostics")
    print("  WiFi observation history")
    print("  JSON audit export")
    print("  Owner-controlled credential recovery from supplied configuration/backup files")
    print()
    print("Credential recovery will not automatically guess passwords,")
    print("bypass authentication or submit credentials to discovered devices.")



def main():

    try:

        environment_check()

        menu()

    except KeyboardInterrupt:

        print()
        print()
        print(
            "Audit stopped by user."
        )

    except Exception as exc:

        print()
        print(
            f"Unexpected error: {exc}"
        )


if __name__ == "__main__":
    main()
