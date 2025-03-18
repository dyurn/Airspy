# -*- coding: utf-8 -*-
import sys
sys.stdout.reconfigure(encoding='utf-8')
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

from audit import *
from color import *
from wifi import *
from bluetooth import *
from rtl import *

def display_banner():
    banner = """
     ¦    ¦¦¦¦¦¦   ¦¦¦¦¦¦   ¦¦¦¦¦¦   ¦¦¦¦¦¦   ¦¦   ¦¦  
    ¦ ¦     ¦¦     ¦¦   ¦¦  ¦¦       ¦¦   ¦¦   ¦¦ ¦¦   
   ¦   ¦    ¦¦     ¦¦¦¦¦¦   ¦¦       ¦¦¦¦¦¦     ¦¦¦    
  ¦¦¦¦¦¦¦   ¦¦     ¦¦   ¦¦  ¦¦¦¦¦¦   ¦¦          ¦     
 ¦       ¦  ¦¦     ¦¦   ¦¦       ¦¦  ¦¦          ¦     
¦         ¦ ¦¦¦¦   ¦¦   ¦¦  ¦¦¦¦¦¦   ¦¦          ¦     

           - AIRSPY -
      Multi-Protocol Scanner
              v1.0 

    """
    print(f"{Color.CYAN}{Style.BRIGHT}{banner}{Style.RESET_ALL}")


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

async def main():
    display_banner()
    parser = argparse.ArgumentParser(description="Multi-protocol scanner: Wi-Fi, Bluetooth, RTL433, Deauth Attack")
    ## wi-fi ##
    parser.add_argument("-w", "--wifi", action="store_true", help="Scan Wi-Fi networks")
    parser.add_argument("-d", "--deauth", action="store_true", help="Send deauthentication packets")#
    parser.add_argument("-a", "--bssid", type=str, help="BSSID (AP MAC) for deauth attack")#
    parser.add_argument("-c", "--station", type=str, help="Station (Client MAC) for deauth attack (optional)")#
    parser.add_argument("--filter-ssid", type=str, help="Filter by specific SSID")
    parser.add_argument("--filter-channel", type=str, help="Filter by channel range (e.g., 1-6)")
    parser.add_argument("--min-signal", type=int, help="Filter networks by minimum signal strength (e.g., -50 dBm)")
    parser.add_argument("--wifi-channels", action="store_true", help="Analyze Wi-Fi channels and recommend the best one")
    
    ## BT ##
    parser.add_argument("-b", "--bluetooth", action="store_true", help="Scan Bluetooth devices")
    
    ## radio ##
    parser.add_argument("-f", "--frequency", type=str, nargs="?", const="433.92M", default=None,
                    help="Enable RTL433 scan (default: 433.92M if no value given)")
    parser.add_argument("--gain", type=str, help="RTL433 gain (e.g., auto, 40)")
    parser.add_argument("--protocol", type=str, help="Enable specific decoding protocol (e.g., 40 for Acurite)")
    parser.add_argument("--output", type=str, choices=["json", "csv", "log", "mqtt", "influx"], default="json",
                        help="Output format (default: json)")
    parser.add_argument("--live-sdr", action="store_true", help="Enable live monitoring mode (only works with -f)")

    ## general ##
    parser.add_argument("-T", "--timeout", type=int, default=10, help="Maximum scan/deauth time (in seconds)")
    parser.add_argument("--audit", action="store_true", help="Run a full audit (Wi-Fi, Bluetooth, RTL433 at 433 & 868 MHz)")
    


    args = parser.parse_args()

    if not any(vars(args).values()):
        print("[!] Please specify at least one option (-w, -b, -f, -d)")
        parser.print_help()
        sys.exit(1)

    if args.audit:
        await audit_scan()
        sys.exit(0)

    if args.wifi:
        scan_wifi(args.timeout, args.filter_ssid, args.filter_channel, args.min_signal, args.wifi_channels)
    
    if args.bluetooth:
        await scan_bluetooth(args.timeout)
        
    if args.live_sdr and not args.frequency:
        print(f"{Color.RED}{Style.BRIGHT}[!]{Style.RESET_ALL} {Color.CYAN}{Style.BRIGHT}--live-sdr{Style.RESET_ALL} requires -f to be specified.")
        sys.exit(1)
    elif args.live_sdr and args.frequency:
        scan_rtl433_live(args.frequency, args.gain, args.protocol, args.output)
    elif args.frequency:
        scan_rtl433(args.timeout, args.frequency, args.gain, args.protocol, args.output)

    
    if args.deauth:
        if not args.bssid:
            print(f"{Color.RED}{Style.BRIGHT}[!]{Style.RESET_ALL} You must specify a BSSID with `-a <BSSID>` for the deauth attack.")
            sys.exit(1)
        deauth(args.bssid, args.station, args.timeout)

if __name__ == "__main__":
    asyncio.run(main())