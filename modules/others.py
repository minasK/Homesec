import nmap
import subprocess
import time
import threading
import os
import signal
import re
import tkinter as tk

from tkinter import simpledialog, Text, Toplevel, WORD, messagebox
from modules.utils import validate_ip_range, get_vendor, scan_network

DEFAULT_NETWORK = "192.168.1.0/24"

def update_text(output_text, message, tag):
    """Update the text widget from the main thread."""
    try:
        output_text.insert(tk.END, message, tag)
    except Exception as e:
        print(f"Error updating text widget: {e}")

def start_capture(output_text, root):
    """Start packet capture and save to a .pcap file and a .csv file."""
    output_pcap_file = "/tmp/more_captured_traffic.pcap"  # Maybe change to a writable location if necessary
    output_csv_file = "/home/kali/Desktop/capstone/captured_traffic.csv"  # Change to a writable location
    update_text(output_text, f"Starting packet capture. Saving to '{output_pcap_file}' and '{output_csv_file}'...\n", "info")

    # Remove the previous CSV file if it exists
    try:
        os.remove(output_csv_file)
        update_text(output_text, f"Removed previous CSV file: {output_csv_file}\n", "info")
    except FileNotFoundError:
        update_text(output_text, f"No previous CSV file found: {output_csv_file}\n", "info")

    # Start capturing packets with elevated privileges for PCAP
    pcap_command = ['sudo', 'dumpcap', '-i', 'eth0', '-w', output_pcap_file]   # change eth0 into your own adapter
    
    # Command for capturing CSV data
    csv_command = [
        'sudo', 'tshark', '-i', 'eth0', #change the eth0 into your own adapter
        '-T', 'fields', 
        '-e', 'frame.number', 
        '-e', 'frame.time', 
        '-e', 'ip.src', 
        '-e', 'ip.dst', 
        '-e', 'eth.src', 
        '-e', 'eth.dst', 
        '-e', 'ip.proto',
        '-E', 'separator=,', 
        '-E', 'quote=d', 
        '-E', 'header=y',
        '-Y', '' #filter
    ]

    # Start subprocess for PCAP capture
    capture_process = subprocess.Popen(pcap_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)

    # Start subprocess for CSV capture:
    # We want to keep this process running, so don't use with statement here.
    csvfile = open(output_csv_file, 'w')  # Open in write mode
    csv_process = subprocess.Popen(csv_command, stdout=csvfile, stderr=subprocess.DEVNULL)

    def on_exit():
        """Ensure the capture process is terminated when the window is closed."""
        try:
            os.killpg(os.getpgid(capture_process.pid), signal.SIGTERM)
            os.killpg(os.getpgid(csv_process.pid), signal.SIGTERM)
            csvfile.close()  # Close the CSV file properly
            update_text(output_text, "Packet capture stopped.\n", "info")
        except Exception as e:
            update_text(output_text, f"Error stopping packet capture: {str(e)}\n", "error")

    # Link the window close event to on_exit
    root.protocol("WM_DELETE_WINDOW", lambda: [on_exit(), root.quit()])

def start_scan(output_text, status_label, spinner_label, time_label, device_listbox):
    """Prompt the user to choose the default or custom network range and start the scan."""
    response = messagebox.askyesno(
        "Network Scan",
        f"Do you want to scan the default network ({DEFAULT_NETWORK})?"
    )
    if response:
        ip_range = DEFAULT_NETWORK
        # Run the scan in a separate thread to avoid freezing the GUI
        threading.Thread(target=scan_network, args=(ip_range, output_text, status_label, spinner_label, time_label, device_listbox), daemon=True).start()
    else:
        # Prompt for custom network range until valid input is provided or user exits
        while True:
            ip_range = simpledialog.askstring(
                "Input",
                "Enter the IP range to scan (e.g., 192.168.1.0/24):",
                initialvalue="192.168.1.0/24"
            )
            if ip_range:
                if validate_ip_range(ip_range):
                    # Run the scan in a separate thread
                    threading.Thread(target=scan_network, args=(ip_range, output_text, status_label, spinner_label, time_label, device_listbox), daemon=True).start()
                    break
                else:
                    messagebox.showwarning("Invalid Network", "The IP range format is invalid. Please use CIDR format (e.g., 192.168.1.0/24).",)
            else:
                messagebox.showinfo("Exit", "You have chosen to exit the scan process.")
                break
        
def analyze_packet(packet_number, output_text, root):
    """Analyze a specific packet in real-time and display its contents with filtering options."""
    try:
        # Sanity check for packet number
        if packet_number <= 0:
            messagebox.showerror("Invalid Input", "Packet number must be a positive integer.")
            return

        # Create a new Toplevel window for showing packet analysis
        analysis_window = tk.Toplevel()
        analysis_window.title(f"Packet #{packet_number} Analysis")
        analysis_window.geometry("800x600")

        # Insert a message that the packet analysis is starting
        analysis_text = tk.Text(analysis_window, wrap=tk.WORD, height=30, width=100)
        analysis_text.pack(pady=10, padx=10)

        # Filter entry and buttons
        filter_frame = tk.Frame(analysis_window)
        filter_frame.pack(pady=5)

        filter_label = tk.Label(filter_frame, text="Filter (e.g., tcp, ip.src == 192.168.1.1):")
        filter_label.pack(side=tk.LEFT, padx=5)

        filter_entry = tk.Entry(filter_frame, width=40)
        filter_entry.pack(side=tk.LEFT, padx=5)

        def apply_filter():
            """Apply the user-defined filter and re-run the analysis."""
            filter_string = filter_entry.get().strip()
            if not filter_string:
                messagebox.showwarning("Invalid Filter", "Please enter a valid filter.")
                return
            
            run_tshark_analysis(filter_string)

        filter_button = tk.Button(filter_frame, text="Apply Filter", command=apply_filter)
        filter_button.pack(side=tk.LEFT, padx=5)

        # Prepare to invoke tshark for reading the specific packet from the PCAP file
        output_pcap_file = "/tmp/more_captured_traffic.pcap"  # Change this to the location of your pcap file

        def run_tshark_analysis(filter_string=None):
            """Run tshark with or without a filter."""
            analysis_text.delete("1.0", tk.END)  # Clear previous output

            tshark_command = [
                "tshark", "-r", output_pcap_file, "-Y",
                f"frame.number == {packet_number}" if not filter_string else filter_string, "-V"
            ]

            # Use subprocess.Popen without blocking and suppress stderr warnings
            process = subprocess.Popen(
                tshark_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,  # Suppress all warnings from stderr
                bufsize=1,
                universal_newlines=True
            )

            def read_output():
                """Non-blocking function to read stdout and update the UI."""
                for line in process.stdout:
                    analysis_text.insert(tk.END, line)
                    analysis_text.yview(tk.END)  # Scroll to the bottom

                process.stdout.close()
                process.wait()

            # Run the output reading in a separate thread to prevent lag
            root.after(100, read_output)

        # Initial analysis (without a filter)
        run_tshark_analysis()

    except Exception as e:
        messagebox.showerror("Error", f"Error analyzing packet: {str(e)}")

def scan_device_details(device_info, output_text, status_label, spinner_label, time_label):
    """Perform a detailed scan (ports and OS fingerprinting) for the selected device."""
    ip_address = device_info.split(",")[0].split(":")[1].strip()  # Extract IP from device info

    try:
        # Initialize the Nmap scanner
        scanner = nmap.PortScanner()

        # Clear previous output and show the waiting message
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, f"Scanning {ip_address} for open ports and OS...\n", "info")
        
        # Show scanning status message and spinner
        status_label.config(text=f"Scanning {ip_address}, please wait...")
        spinner_label.config(text="🔄 Scanning...")  # Added text to spinner for clarity
        spinner_label.pack(pady=5)

        start_time = time.time()  # Record the start time

        # Perform a detailed scan (ports and OS fingerprinting)
        def scan_thread():
            scanner.scan(hosts=ip_address, arguments='-sS -sV -O -T4')

            # Hide the spinner after scan completion
            spinner_label.pack_forget()
            status_label.config(text="Scan Completed")

            # Final elapsed time after the scan
            elapsed_time = time.time() - start_time
            time_label.config(text=f"Time Elapsed: {elapsed_time:.2f} seconds")

            # Clear the waiting message and print the results
            output_text.delete("1.0", tk.END)

            # Display detailed results for the device
            output_text.insert(tk.END, f"Results for {ip_address}:\n", "header")

            # Scan for open ports and services
            if 'tcp' in scanner[ip_address]:
                output_text.insert(tk.END, "\n🌐 Open Ports and Services:\n", "header")
                for port in scanner[ip_address]['tcp']:
                    service = scanner[ip_address]['tcp'][port].get('name', 'Unknown Service')
                    version = scanner[ip_address]['tcp'][port].get('version', 'N/A')
                    output_text.insert(tk.END, f"Port {port}: {service} (Version: {version})\n", "normal")
            else:
                output_text.insert(tk.END, "No open ports found.\n", "normal")

            # Perform OS detection (Device Fingerprinting)
            if 'osmatch' in scanner[ip_address]:
                output_text.insert(tk.END, f"🖥️ OS Fingerprint: {scanner[ip_address]['osmatch'][0]['name']}\n", "normal")
            else:
                output_text.insert(tk.END, "OS fingerprinting failed.\n", "normal")

            output_text.insert(tk.END, "-" * 50 + "\n", "separator")

        # Start the detailed scan thread
        threading.Thread(target=scan_thread, daemon=True).start()

    except Exception as e:
        spinner_label.pack_forget()
        status_label.config(text="Error during scan")
        messagebox.showerror("Error", f"An error occurred during the scan: {str(e)}")
