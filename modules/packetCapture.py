import tkinter as tk  # For building the GUI.
import threading  # For background processing of captured packets.
import subprocess  # To run the tshark command for packet capture.

from tkinter import messagebox  # For error alerts.

def packet_capture(output_text):
    """Display a popup showing real-time captured packets."""
    try:
        # Protocol mapping for common numbers
        protocol_map = {
            "1": "ICMP", "2": "IGMP", "6": "TCP", "8": "EGP", "17": "UDP", "41": "IPv6", "47": "GRE",
            "50": "ESP", "51": "AH", "53": "DNS", "67": "DHCP", "80": "HTTP", "110": "POP3", "123": "NTP",
            "143": "IMAP", "161": "SNMP", "194": "IRC", "443": "HTTPS", "445": "Microsoft-DS", "500": "ISAKMP",
            "514": "Syslog", "520": "RIP", "631": "IPP", "1080": "SOCKS", "1433": "MSSQL", "1723": "PPTP",
            "3306": "MySQL", "3389": "RDP", "5060": "SIP", "5140": "SonicWall", "636": "LDAPS", "993": "IMAPS",
            "995": "POP3S", "132": "SCTP", "255": "Reserved"
        }

        # Create a popup window
        capture_window = tk.Toplevel()
        capture_window.title("Packet Capture")
        capture_window.geometry("1080x600")  # Increased window width for better readability

        # Add a label
        capture_label = tk.Label(capture_window, text="Captured Packets", font=("Helvetica", 14, "bold"))
        capture_label.pack(pady=10)

        # Add a text widget to display captured packets
        capture_text = tk.Text(capture_window, wrap=tk.WORD, height=30, width=100)
        capture_text.tag_configure("header", font=("Helvetica", 12, "bold"), foreground="blue")
        capture_text.tag_configure("normal", font=("Helvetica", 10))
        capture_text.pack(pady=10, padx=10)

        # Add column headers with more space between columns
        headers = f"{'Packet #':<12}{'Source IP':<25}{'Destination IP':<25}{'Source MAC':<25}{'Dest MAC':<25}{'Protocol':<20}\n"
        capture_text.insert(tk.END, headers, "header")
        capture_text.insert(tk.END, "-" * 140 + "\n", "normal")

        # Command to capture packets with tshark
        network_interface = "eth0"  # Replace with your actual interface
        tshark_command = [
            "tshark", "-i", network_interface, "-T", "fields",
            "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst",
            "-e", "eth.src", "-e", "eth.dst", "-e", "ip.proto"
        ]

        process = subprocess.Popen(tshark_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

        # Create a scrollbar and link it to the text widget
        scrollbar = tk.Scrollbar(capture_window, command=capture_text.yview)
        capture_text.config(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Flag to stop the thread when the window is closed
        stop_thread = threading.Event()

        def on_close():
            """Handle the window close event."""
            stop_thread.set()
            process.terminate()
            capture_window.destroy()

        capture_window.protocol("WM_DELETE_WINDOW", on_close)

        def analyze_packet_in_background():
            """Analyze captured packets in the background to avoid blocking the UI."""
            while not stop_thread.is_set():
                output = process.stdout.readline()
                if not output:
                    break
                fields = output.strip().split("\t")
                
                # Assigning values, using "N/A" for any missing fields
                packet_number = fields[0] if len(fields) > 0 else "N/A"
                src_ip = fields[1] if len(fields) > 1 and fields[1] else "N/A"
                dest_ip = fields[2] if len(fields) > 2 and fields[2] else "N/A"
                src_mac = fields[3] if len(fields) > 3 and fields[3] else "N/A"
                dest_mac = fields[4] if len(fields) > 4 and fields[4] else "N/A"
                protocol = protocol_map.get(fields[5], fields[5]) if len(fields) > 5 else "Unknown"
                
                # Ensure the window is still open before updating the UI
                if capture_window.winfo_exists():
                    # Update UI safely
                    capture_text.insert(tk.END, f"{packet_number:<12}{src_ip:<25}{dest_ip:<25}{src_mac:<25}{dest_mac:<25}{protocol:<20}\n", "normal")
                    capture_text.see(tk.END)  # Automatically scroll to the bottom

        threading.Thread(target=analyze_packet_in_background, daemon=True).start()

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")
