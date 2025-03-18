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

def scan_rtl433(timeout, frequency="433.92M", gain=None, protocol=None, output_format="json"):

    print(f"\n{Color.GREEN}{Style.BRIGHT}[*]{Style.RESET_ALL} Scanning at {frequency}Hz for {timeout}s...")

    command = ["rtl_433", "-d", "soapy", "-f", frequency, "-F", output_format]

    if gain:
        command.extend(["-g", gain])

    if protocol:
        command.extend(["-R", protocol])

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1
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

    print(f"\n{Color.GREEN}{Style.BRIGHT}=== DETECTED TRANSMISSIONS ==={Style.RESET_ALL}")
    if results:
        for device in results:
            print(f"\n{Color.MAGENTA}{Style.BRIGHT}--> {device.get('model', 'Unknown Device')}{Style.RESET_ALL}")
            for x, y in device.items(): 
                if x != "model":
                    print(f"   - {x} : {y}")
    else:
        print(f"{Color.RED}{Style.BRIGHT}[!]{Style.RESET_ALL} No devices detected.")

            
            


def scan_rtl433_live(frequency="433.92M", gain=None, protocol=None, output_format="json"):
 
    print(f"\n{Color.GREEN}{Style.BRIGHT}[*]{Style.RESET_ALL} Monitoring at {frequency}Hz... (Press CTRL+C to stop)")

    command = ["rtl_433", "-d", "soapy", "-f", frequency, "-F", output_format]

    if gain:
        command.extend(["-g", gain])

    if protocol:
        command.extend(["-R", protocol])

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1
    )

    try:
        while True:
            rlist, _, _ = select.select([process.stdout], [], [], 0.5)
            if rlist:
                line = process.stdout.readline().strip()
                if line:
                    try:
                        data = json.loads(line)
                        print(f"\n{Color.MAGENTA}{Style.BRIGHT}--> {data.get('model', 'Unknown Device')}{Style.RESET_ALL}")
                        for x, y in data.items():
                            if x != "model":
                                print(f"   - {x} : {y}")
                    except json.JSONDecodeError:
                        continue

    except KeyboardInterrupt:
        print(f"\n{Color.YELLOW}{Style.BRIGHT}[!] Monitoring stopped by user.{Style.RESET_ALL}")

    finally:
        process.terminate()
        process.wait()

  