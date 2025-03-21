# **Airspy - Multi-Protocol Scanner**

## **Description**

Airspy is a multi-protocol scanner designed for monitoring surrounding radio signals. This command-line tool detects and displays Wi-Fi, Bluetooth, and ISM band devices (e.g., 433 MHz, 868 MHz) via `rtl_433`. It also supports Wi-Fi deauthentication attacks.

Additionally, a graphical version called **AirspyGUI.py** is available, providing an intuitive interface for executing deauthentication attacks and capturing Wi-Fi handshakes.

## **Features**

- **Wi-Fi Scanning**: Detects Wi-Fi networks and connected clients, displaying detailed information (BSSID, signal strength, channel, security type, manufacturer).
- **Bluetooth Scanning**: Detects Bluetooth devices and resolves MAC addresses to identify manufacturers.
- **Radio Scanning (RTL-SDR)**: Captures and analyzes signals in ISM bands using `rtl_433`.
- **Deauthentication Attack**: Sends deauthentication packets to disconnect a client from a Wi-Fi network.
- **Audit Mode**: Conducts a full scan across all supported technologies.
- **Graphical Interface (AirspyGUI.py)**: Provides a GUI for performing Wi-Fi deauthentication attacks and capturing handshakes.

## **Installation**

### **Prerequisites**

- Python 3.x
- Pip
- A Wi-Fi adapter that supports monitor mode (for Wi-Fi scanning and deauthentication attacks)
- An RTL-SDR receiver (for capturing radio signals)

### **Install Dependencies**

Clone this repository and install the required dependencies:

```bash
git clone https://github.com/dyurn/Airspy.git
cd Airspy
pip install -r requirements.txt
```

## **Usage**

Run the tool with the desired options:

```bash
python Airspy.py -w        # Scan Wi-Fi
python Airspy.py -b        # Scan Bluetooth
python Airspy.py -f        # Scan radio (default 433.92 MHz)
python Airspy.py -d -a <BSSID> [-c <STATION>]  # Deauthentication attack
python Airspy.py --audit   # Full audit
python AirspyGUI.py        # Launch graphical interface
```

### **Options**

```
-w, --wifi               Scan Wi-Fi
-b, --bluetooth          Scan Bluetooth
-f, --frequency [FREQ]   Scan radio with RTL433 (default: 433.92M)
--gain <value>           RTL433 gain (e.g., auto, 40)
--protocol <id>          Specify RTL433 decoding protocol
--live-sdr               Enable real-time monitoring mode
-d, --deauth             Send deauthentication packets
-a, --bssid <BSSID>      Target BSSID for deauthentication attack
-c, --station <STATION>  Target client MAC address
--audit                  Perform a full scan (Wi-Fi, Bluetooth, RTL433)
-T, --timeout <sec>      Maximum scan time (default: 10s)
```

## **Usage Examples**

### **Wi-Fi Scan**

```bash
python Airspy.py -w --filter-ssid "MyNetwork" --min-signal -50
```

### **Bluetooth Scan**

```bash
python Airspy.py -b -T 15
```

### **Live Radio Scan on 868 MHz**

```bash
python Airspy.py -f 868M --live-sdr
```

### **Complete Audit**

```bash
python Airspy.py --audit
```

### **Launching the GUI**

```bash
python AirspyGUI.py
```

## **Notes**

- For Wi-Fi scanning and deauthentication attacks, ensure your Wi-Fi adapter is in monitor mode (`airmon-ng start wlan0`).
- The use of deauthentication attacks must comply with applicable laws.

## **Contributions**

Contributions are welcome! Feel free to suggest improvements or report bugs via GitHub issues.

