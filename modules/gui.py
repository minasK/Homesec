import nmap
import datetime
import requests
import os
import re   
import time  
import subprocess
import threading
import tempfile
import queue
import openai
import replicate 
import tkinter as tk

from tkinter import simpledialog, Text, Toplevel, WORD, messagebox 
from tkinter import messagebox as tkMessageBox 
from scapy.all import Ether, IP, TCP, wrpcap, rdpcap, sniff

from modules.utils import validate_ip_range, get_vendor, scan_network
from modules.others import update_text, start_capture, start_scan, analyze_packet, scan_device_details  
from modules.hydra import launch_hydra_window
from modules.metasploit import launch_metasploit_window
from modules.nikto import launch_nikto_window 
from modules.packetCapture import packet_capture

os.environ["REPLICATE_API_TOKEN"] = "enter your API key here"  #here you enter the api token that replicate generated

# Initialize packet counter
packet_counter = 1

# Queue to safely pass data between threads
packet_queue = queue.Queue()  

def create_gui():
    """Creating the GUI for the framework."""
    if os.geteuid() != 0:
        messagebox.showerror("Permission Error", "Please run this script as superuser (sudo).")
        return

    # Initialize the main window
    root = tk.Tk()
    root.title("Penetration Testing Framework")

    # Maximize the window using geometry
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    root.geometry(f"{screen_width}x{screen_height}+0+0")  # Set to full screen

    # Set minimum size for window (in case of manual resizing)
    root.minsize(1000, 700)

    # Title label
    title_label = tk.Label(root, text="HOMESEC", font=("Helvetica", 18, "bold"))
    title_label.pack(pady=20)

    # Output text box
    output_text = tk.Text(root, wrap=tk.WORD, height=25, width=120)
    output_text.tag_configure("header", font=("Helvetica", 12, "bold"), foreground="blue")
    output_text.tag_configure("highlight", font=("Helvetica", 10, "bold"), foreground="dark green")
    output_text.tag_configure("info", font=("Helvetica", 10, "italic"), foreground="gray")
    output_text.tag_configure("separator", font=("Helvetica", 10), foreground="black")
    output_text.tag_configure("normal", font=("Helvetica", 10))
    output_text.tag_configure("error", font=("Helvetica", 10, "italic"), foreground="red")
    output_text.pack(pady=15, padx=20)

    # Status Label
    status_label = tk.Label(root, text="Welcome to the Penetration Testing Framework", font=("Helvetica", 14))
    status_label.pack(pady=10)

    # Spinner label
    spinner_label = tk.Label(root, text="🔄", font=("Helvetica", 24))

    # Time elapsed label
    time_label = tk.Label(root, text="Time Elapsed: 0.00 seconds", font=("Helvetica", 12))
    time_label.pack(pady=10)

    # Listbox to display devices found
    device_listbox = tk.Listbox(root, height=10, width=100)
    device_listbox.pack(pady=10)

    # Button to perform detailed scan on selected device
    scan_device_button = tk.Button(
        root, text="Scan Selected Device",
        command=lambda: scan_device_details(device_listbox.get(tk.ACTIVE), output_text, status_label, spinner_label, time_label),
        bg="light blue", height=2, width=30
    )
    scan_device_button.pack(pady=10)

    # Buttons with more space between them
    scan_button = tk.Button(
        root, text="Scan Network for Devices",
        command=lambda: start_scan(output_text, status_label, spinner_label, time_label, device_listbox),
        bg="light blue", height=2, width=30
    )
    scan_button.pack(pady=15)

    # Frame to hold packet capture and exploit tool buttons
    packet_capture_frame = tk.Frame(root)
    packet_capture_frame.pack(pady=15)

    packet_capture_button = tk.Button(
        packet_capture_frame, text="Start Packet Capture",
        command=lambda: [packet_capture(output_text)],
        bg="light green", height=2, width=18
    )
    packet_capture_button.pack(side=tk.LEFT, padx=5)

    # Launch Metasploit button
    metasploit_button = tk.Button(
        packet_capture_frame, text="Launch Metasploit",
        command=launch_metasploit_window,
        bg="orange", height=2, width=18
    )
    metasploit_button.pack(side=tk.LEFT, padx=5)

    # Launch nikto button
    nikto_button = tk.Button(
        packet_capture_frame, text="Launch Nikto",
        command=launch_nikto_window,
        bg="orange", height=2, width=18
    )
    nikto_button.pack(side=tk.LEFT, padx=5)

    # Launch Hydra button
    hydra_button = tk.Button(
        packet_capture_frame, text="Launch Hydra",
        command=launch_hydra_window,
        bg="orange", height=2, width=18
    )
    hydra_button.pack(side=tk.LEFT, padx=5)

    # Input field for packet number
    packet_number_label = tk.Label(root, text="Enter Packet Number to Analyze:", font=("Helvetica", 12))
    packet_number_label.pack(pady=10)

    packet_number_entry = tk.Entry(root, font=("Helvetica", 12), width=10)
    packet_number_entry.pack(pady=5)

    analyze_packet_button = tk.Button(
        root, text="Analyze Packet",
        command=lambda: analyze_packet(
            int(packet_number_entry.get()),  # Get packet number from entry
            output_text,
            root
        ),
        bg="light yellow", height=1, width=30
    )
    analyze_packet_button.pack(pady=15)

    exit_button = tk.Button(root, text="Exit", command=root.quit, bg="light coral", height=1, width=30)
    exit_button.pack(pady=1)

    # Start packet capture in the background
    start_capture(output_text, root)

    # Set window close behavior
    root.protocol("WM_DELETE_WINDOW", lambda: [on_exit(), root.quit()])
    root.mainloop()
