import tkinter as tk  # For building the GUI.
import tkinter
import requests
import nmap  # For performing network scans.
import re  # To validate IP range format
import threading  # To run the network scan in a background thread.
import time  # For tracking time elapsed.

from tkinter import simpledialog, Text, Toplevel, WORD, messagebox, Label  # GUI related imports

smart_device_vendors = [
    "Amazon", "Google", "Samsung", "Apple", "Nest", "Xiaomi", "TP-Link", "Sonos", "Philips", "Ring", "Eufy", "Arlo", "Wyze", "Ecobee", "LG", "Netatmo", "Tuya", "D-Link", "Blink", "August", "Honeywell", "Meross", "CHINA DRAGON"
]

def validate_ip_range(ip_range):
    """Validate the format of the provided IP range."""
    regex = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$'
    return re.match(regex, ip_range)

def get_vendor(mac_address):
    """Fetch vendor information from an online OUI database."""
    mac_prefix = mac_address.upper()[:8].replace(":", "-")  # Normalize MAC format

    try:
        # Query an OUI database (web scraping method)
        url = f"https://www.macvendorlookup.com/api/v2/{mac_prefix}"
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            data = response.json()
            if data and isinstance(data, list) and "company" in data[0]:
                vendor = data[0]["company"]
                
                # Check if the vendor is in the smart device vendors list
                is_smart_device = "Yes" if any(v in vendor for v in smart_device_vendors) else "Maybe"
                return f"{vendor} (Smart Device: {is_smart_device})"
        
        return "Unknown Vendor"

    except Exception as e:
        return f"Error fetching vendor: {str(e)}"
        
def scan_network(ip_range, output_text, status_label, spinner_label, time_label, device_listbox):
    """Scan the network quickly and gather basic device info (IP, MAC, Vendor)."""
    if not validate_ip_range(ip_range):
        messagebox.showerror("Invalid Input", "The IP range you entered is not valid. Please try again with a valid CIDR range.")
        return

    try:
        # Initialize the Nmap scanner
        scanner = nmap.PortScanner()

        # Clear previous output and show the waiting message
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, "Scanning network for devices...\n", "info")
        
        # Show scanning status message and spinner
        status_label.config(text="Scanning, please wait...")
        spinner_label.config(text="🔄 Scanning...")  # Added text to spinner for clarity
        spinner_label.pack(pady=5)

        start_time = time.time()  # Record the start time

        # Perform a quick scan to identify devices
        def scan_thread():
            # -sn argument is for Ping scan to just detect live hosts
            scanner.scan(hosts=ip_range, arguments='-sn -T4')

            # Hide the spinner after scan completion
            spinner_label.pack_forget()
            status_label.config(text="Scan Completed")

            # Final elapsed time after the scan
            elapsed_time = time.time() - start_time
            time_label.config(text=f"Time Elapsed: {elapsed_time:.2f} seconds")

            # Clear the waiting message and print the results
            output_text.delete("1.0", tk.END)

            # Check if any hosts are found
            if not scanner.all_hosts():
                output_text.insert(tk.END, f"No devices found in the network range {ip_range}.\n", "error")
            else:
                # Display devices found and populate the listbox
                output_text.insert(tk.END, "Devices Found:\n", "header")
                device_listbox.delete(0, tk.END)  # Clear any previous list

                for host in scanner.all_hosts():
                    mac = scanner[host]['addresses'].get('mac', 'Unknown')
                    vendor = get_vendor(mac) if mac != 'Unknown' else 'Unknown'
                    device_info = f"IP: {host}, MAC: {mac}, Vendor: {vendor}"

                    output_text.insert(tk.END, f"\n📌 {device_info}\n", "highlight")
                    device_listbox.insert(tk.END, device_info)  # Add device to the listbox

                output_text.insert(tk.END, "-" * 50 + "\n", "separator")

        # Start the scanning thread
        threading.Thread(target=scan_thread, daemon=True).start()

    except Exception as e:
        spinner_label.pack_forget()
        status_label.config(text="Error during scan")
        messagebox.showerror("Error", f"An error occurred during the scan: {str(e)}")
