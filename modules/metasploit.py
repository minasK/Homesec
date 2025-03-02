import tkinter as tk  # For building the GUI.
import re  # To strip ANSI color codes 
import subprocess  # to run external commands
import threading  # For handling background thread processing.
import replicate # replicate AI api

from tkinter import Toplevel, Text, WORD  # For specific GUI elements.

def launch_metasploit_window():
    def strip_ansi_codes(text):
        """Strips ANSI color codes from the given text."""
        ansi_escape = re.compile(r'\x1B\[[0-?9;]*[mG]')
        return ansi_escape.sub('', text)

    def start_metasploit():
        """Starts Metasploit with predefined commands and captures output."""
        target_device = target_entry.get().strip()

        if not target_device:
            log_text.insert(tk.END, "Please enter a target device.\n", "error")
            return

        log_text.insert(tk.END, f"[*] Running Metasploit against {target_device}...\n", "highlight")
        log_text.insert(tk.END, "----------------------------------------------------\n", "separator")

        commands = [
            "use auxiliary/scanner/portscan/tcp",
            f"set RHOSTS {target_device}",
            "run",
            "vulns",
            "search type:exploit name:http",
            "search type:exploit name:ssh",
            "search type:exploit name:ftp",
        ]

        global process
        process = subprocess.Popen(
            ["msfconsole", "-q", "-x", ";".join(commands)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )

        def read_output():
            """Reads Metasploit output and updates the log window."""
            metasploit_output = []
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    cleaned_output = strip_ansi_codes(output)
                    metasploit_output.append(cleaned_output)
                    log_text.insert(tk.END, cleaned_output)
                    log_text.see(tk.END)

            log_text.insert(tk.END, "\n[!] Metasploit execution completed.\n", "highlight")
            process.stdout.close()

        output_thread = threading.Thread(target=read_output)
        output_thread.start()

    def exit_metasploit():
        """Exit the Metasploit process."""
        if process:
            process.terminate()
            log_text.insert(tk.END, "[!] Metasploit process terminated.\n", "highlight")
        else:
            log_text.insert(tk.END, "[!] No Metasploit process found.\n", "error")

    def save_report():
        """Saves the contents of the log_text to a file and asks for the top vulnerabilities."""
        report_file_path = "/home/kali/Desktop/metasploit_vulnerability_report.txt"
        
        try:
            # Save the content of log_text to the file
            with open(report_file_path, "w") as report_file:
                report_file.write(log_text.get("1.0", tk.END))  # Save all text from the log_text widget
                log_text.insert(tk.END, f"[+] Report saved to {report_file_path}\n", "highlight")
            
            # Now read the content of the saved file
            with open(report_file_path, "r") as report_file:
                file_content = report_file.read()

            # Limit the size of the content sent to Replicate
            max_content_length = 13000  # Adjusted to a higher character limit for Replicate

            if len(file_content) > max_content_length:
                file_content = file_content[:max_content_length]  # Truncate content if it's too long

            prompt = f"Given the following Metasploit scan output, identify all of the critical vulnerabilities of the device and provide their corresponding cvss score. Explain please how we can avoid those vulnerabilities in a few words:\n\n{file_content}"

            # Start a new thread for making the API call to Replicate to prevent freezing the UI
            def call_replicate():
                try:
                    # Call Replicate with the API token and ensure we wait for the response
                    response = replicate.run(
                        "meta/llama-2-7b-chat",
                        input={"prompt": prompt, "max_tokens": 5000}
                    )

                    if response:
                        ai_response = "".join(response)  # Ensure the response is joined properly
                        # Save the top 5 vulnerabilities into the same file
                        with open(report_file_path, "a") as report_file:
                            report_file.write("\nAI can only read 13000 characters and based on them it will create a valid response of vulnerabilities found.\n\nVulnerabilities found:\n")
                            report_file.write(ai_response)

                        log_text.insert(tk.END, "\n[+] Vulnerabilities have been added to the report file.\n", "highlight")
                    else:
                        log_text.insert(tk.END, "[!] No response from Replicate for top 5 vulnerabilities.\n", "error")

                except Exception as e:
                    log_text.insert(tk.END, f"[!] Error communicating with Replicate: {str(e)}\n", "error")

            # Run the Replicate call in a separate thread
            replicate_thread = threading.Thread(target=call_replicate)
            replicate_thread.start()

        except Exception as e:
            log_text.insert(tk.END, f"[!] Error saving the report: {str(e)}\n", "error")

    # Create a new pop-up window for Metasploit
    metasploit_window = tk.Toplevel()
    metasploit_window.title("Metasploit Automation")
    metasploit_window.geometry("900x500")

    tk.Label(metasploit_window, text="Target Device IP/MAC:").pack(pady=5)
    target_entry = tk.Entry(metasploit_window, width=30)
    target_entry.pack(pady=5)

    start_button = tk.Button(metasploit_window, text="Start Vulnerability Scan", command=start_metasploit, bg="green")
    start_button.pack(pady=10)

    global log_text  # Make log_text accessible to start_metasploit and analyze_vulnerabilities
    log_text = tk.Text(metasploit_window, wrap=tk.WORD, height=15, width=80)
    log_text.pack(pady=10)

    # "Show Report" Button 
    show_report_button = tk.Button(metasploit_window, text="Show Report", command=save_report, bg="lightblue")
    show_report_button.pack(pady=10)

    # "Exit Metasploit" Button 
    exit_button = tk.Button(metasploit_window, text="Exit Metasploit", command=exit_metasploit, bg="lightcoral")
    exit_button.pack(pady=10)

    log_text.tag_configure("highlight", font=("Helvetica", 10, "bold"), foreground="blue")
    log_text.tag_configure("error", font=("Helvetica", 10, "italic"), foreground="red")
    log_text.tag_configure("separator", font=("Helvetica", 10), foreground="black")

    metasploit_window.mainloop()
