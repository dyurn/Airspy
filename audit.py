import sys
import argparse
import asyncio
import pywifi
from pywifi import const
from bleak import BleakScanner
import subprocess
import json
import time
import select
import requests
import re
import csv
from datetime import datetime
import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)

from color import *

def get_mac_vendor(mac_address):
    url = f"https://api.macvendors.com/{mac_address}"
    try:
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            return f"{Color.GREEN}{Style.BRIGHT}{response.text.strip()}{Style.RESET_ALL}"
        else:
            return f"{Color.RED}{Style.BRIGHT}Unknown{Style.RESET_ALL}"
    except requests.RequestException:
        return f"{Color.RED}{Style.BRIGHT}Unknown{Style.RESET_ALL}"

###### AUDIT PART ######

AUDIT_FILE = "audit.txt"
AUDIT_TIME = 30

def save_to_audit(data):
    """Saves scan results to audit.txt"""
    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(f"\n\n=== {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")
        f.write(data + "\n")

def scan_wifi_A(timeout): 
    """Scans Wi-Fi networks and writes results to audit.txt"""
    #print(f"\n{Color.GREEN}{Style.BRIGHT}[*]{Style.RESET_ALL} Scanning Wi-Fi networks for {timeout}s...")

    csv_file = "/tmp/airodump-01.csv"

    process = subprocess.Popen(
        ["sudo", "airodump-ng", "wlan0mon", "--write", "/tmp/airodump", "--output-format", "csv"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    time.sleep(timeout)
    process.terminate()
    process.wait()

    try:
        with open(csv_file, "r", encoding="ISO-8859-1") as file:
            reader = csv.reader(file)
            rows = list(reader)
    except FileNotFoundError:
        wifi_results = "Wi-Fi Scan Results:\n-------------------\nNo networks detected. Ensure your Wi-Fi adapter is in monitor mode.\n"
        save_to_audit(wifi_results)
        return

    ap_list = []
    client_list = []
    parsing_clients = False

    for row in rows:
        if len(row) < 2:
            continue
        if "Station MAC" in row[0]:  
            parsing_clients = True
            continue

        if not parsing_clients:
            if len(row) > 13: 
                try:
                    bssid = row[0].strip()
                    signal = int(row[8].strip()) if row[8].strip().lstrip('-').isdigit() else -100  
                    security = row[5].strip() 
                    cipher = row[6].strip() if row[6].strip() else "Unknown"  
                    auth = row[7].strip() if row[7].strip() else "Unknown"  
                    essid = row[13].strip()

                    ap_list.append({"BSSID": bssid, "Signal": signal, "Security": f"{security} {cipher} {auth}", "ESSID": essid})
                except ValueError:
                    continue
        else:
            if len(row) > 6:
                try:
                    station_mac = row[0].strip()
                    associated_bssid = row[5].strip()
                    signal = int(row[3].strip()) if row[3].strip().lstrip('-').isdigit() else -100  

                    client_list.append({"Station": station_mac, "BSSID": associated_bssid, "Signal": signal})
                except ValueError:
                    continue

    ap_list.sort(key=lambda x: x["Signal"], reverse=True)

    # Prepare audit report
    wifi_results = f"\n=== Wi-Fi Scan Results ===\nScan Duration: {timeout}s\n{'-'*50}\n"

    for ap in ap_list:
        if ap['ESSID']:
            wifi_results += f"\nSSID: {ap['ESSID']}\n"
            wifi_results += f"   - BSSID: {ap['BSSID']} -> {get_mac_vendor(ap['BSSID'])}\n"
            wifi_results += f"   - Signal Strength: {ap['Signal']} dBm\n"
            wifi_results += f"   - Security: {ap['Security']}\n"

            associated_clients = [c for c in client_list if c["BSSID"] == ap["BSSID"]]
            if associated_clients:
                wifi_results += "   +- Connected Devices:\n"
                for client in associated_clients:
                    wifi_results += f"      - Device: {client['Station']} -> {get_mac_vendor(client['Station'])} (Signal: {client['Signal']} dBm)\n"

    if not ap_list:
        wifi_results += "No Wi-Fi networks detected.\n"

    save_to_audit(wifi_results)

    # Clean up
    subprocess.run("sudo rm /tmp/airodump-01.csv", shell=True)


async def scan_bluetooth_A(timeout):
    """Scans Bluetooth devices and writes results to audit.txt"""
    #print(f"\n{Color.GREEN}{Style.BRIGHT}[*]{Style.RESET_ALL} Scanning Bluetooth for {timeout}s...")
    from bleak import BleakScanner

    devices = await asyncio.wait_for(BleakScanner.discover(), timeout=timeout)
    bluetooth_results = "Bluetooth Scan Results:\n----------------------\n"
    
    if devices:
        for dev in devices:
            bluetooth_results += f"{dev.address} ({get_mac_vendor(dev.address)}) - {dev.name or 'Unknown'} (RSSI: {dev.rssi} dBm)\n"
    else:
        bluetooth_results += "No Bluetooth devices found.\n"

    save_to_audit(bluetooth_results)

def scan_rtl433_A(timeout, frequency):
    """Scans radio signals with rtl_433 at a given frequency and writes results to audit.txt"""
    #print(f"\n{Color.GREEN}{Style.BRIGHT}[*]{Style.RESET_ALL} Scanning radio signals at {frequency} MHz for {timeout}s...")

    process = subprocess.Popen(
        ["rtl_433", "-d", "soapy", "-f", frequency, "-F", "json"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1
    )

    results = []
    start_time = time.time()

    try:
        while time.time() - start_time < timeout:
            rlist, _, _ = select.select([process.stdout], [], [], 0.5)
            if rlist:
                line = process.stdout.readline().strip()
                if line:
                    try:
                        data = json.loads(line)
                        results.append(data)
                    except json.JSONDecodeError:
                        continue
    except KeyboardInterrupt:
        pass
    finally:
        process.terminate()
        process.wait()

    # Prepare audit report
    rtl_results = f"\n=== RTL433 Scan Results ({frequency} MHz) ===\n"
    rtl_results += f"Scan Duration: {timeout}s\n"
    rtl_results += "-" * 50 + "\n"

    if results:
        for device in results[:10]:  # Limit to 10 results for brevity
            rtl_results += f"\n--> Device Model: {device.get('model', 'Unknown')}\n"
            for key, value in device.items():
                if key != "model":
                    rtl_results += f"   - {key}: {value}\n"
    else:
        rtl_results += "No devices detected.\n"

    # Save to audit file
    save_to_audit(rtl_results)

    
async def audit_scan():
    """Performs a full audit scan (Wi-Fi, Bluetooth, RTL433) and logs results"""
    print(f"\n{Color.GREEN}{Style.BRIGHT}[*]{Style.RESET_ALL} Starting full audit...")

    # Reset audit file
    with open(AUDIT_FILE, "w", encoding="utf-8") as f:
        f.write(f"=== Full Audit Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")


    scan_wifi_A(10)
    await scan_bluetooth_A(10)
    scan_rtl433_A(AUDIT_TIME, "433.92M")
    scan_rtl433_A(AUDIT_TIME, "868M")

    print(f"\n{Color.GREEN}{Style.BRIGHT}[*]{Style.RESET_ALL} Audit completed. Results saved in {AUDIT_FILE}")

###### END AUDIT PART ######