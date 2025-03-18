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

async def scan_bluetooth(timeout):
    print(f"\n{Color.GREEN}{Style.BRIGHT}[*]{Style.RESET_ALL} Scanning Bluetooth devices...")
    try:
        devices = await asyncio.wait_for(BleakScanner.discover(), timeout=timeout)
    except asyncio.TimeoutError:
        print(f"{Color.RED}{Style.BRIGHT}[!]{Style.RESET_ALL} Bluetooth scan interrupted (timeout)")
        return

    results = []
    for dev in devices:
        vendor = get_mac_vendor(dev.address)
        results.append({
            "Name": dev.name or dev.address,
            "Address": dev.address,
            "Vendor": vendor,
            "RSSI": dev.rssi
        })

    results.sort(key=lambda x: x["RSSI"], reverse=True)

    print(f"\n{Color.GREEN}{Style.BRIGHT}=== DETECTED BLUETOOTH DEVICES ==={Style.RESET_ALL}")
    for dev in results:
        print(f"Name: {dev['Name']} | BSSID: {dev['Address']} -> {dev['Vendor']} | Signal: {dev['RSSI']} dBm")