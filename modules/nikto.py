import tkinter as tk  # For building the GUI.
import re  # To strip ANSI color codes from Nikto output.
import subprocess  # To run the Nikto command.
import threading  # For handling background thread processing.
import replicate # replicate AI api

from tkinter import Toplevel, Text, WORD  # For specific GUI elements.

def launch_nikto_window():
    def strip_ansi_codes(text):
        """Strips ANSI color codes from the given text."""
        ansi_escape = re.compile(r'\x1B\[[0-?9;]*[mG]')
        return ansi_escape.sub('', text)

    def start_nikto():
        """Starts Nikto with predefined scan commands and captures output."""
        target_device = target_entry.get().strip()

        if not target_device:
            log_text.insert(tk.END, "Please enter a target device.\n", "error")
            return

        log_text.insert(tk.END, f"[*] Running Nikto scan against {target_device}...\n", "highlight")
        log_text.insert(tk.END, "----------------------------------------------------\n", "separator")

        # Nikto command for scanning the target
        command = ["nikto", "-h", target_device, "-Tuning", "x 6"]

        global process
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )

        def read_output():
            """Reads Nikto output and updates the log window."""
            nikto_output = []
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    cleaned_output = strip_ansi_codes(output)
                    nikto_output.append(cleaned_output)
                    log_text.insert(tk.END, cleaned_output)
                    log_text.see(tk.END)

            log_text.insert(tk.END, "\n[!] Nikto scan completed.\n", "highlight")
            process.stdout.close()

            # Save the Nikto output to a global variable for later use
            global nikto_output_data
            nikto_output_data = nikto_output

        output_thread = threading.Thread(target=read_output)
        output_thread.start()

    def save_report():
        """Saves the contents of the log_text to a file and asks for the top vulnerabilities."""
        report_file_path = "/home/kali/Desktop/nikto_vulnerability_report.txt"

        try:
            # Save the Nikto output to the report file
            with open(report_file_path, "w") as report_file:
                report_file.write("\n".join(nikto_output_data))  # Save the output from Nikto
                log_text.insert(tk.END, f"[+] Report saved to {report_file_path}\n", "highlight")

            # Now read the content of the saved file
            with open(report_file_path, "r") as report_file:
                file_content = report_file.read()

            # Limit the size of the content sent to Replicate
            max_content_length = 7000  # Adjusted to a lower character limit for Replicate

            if len(file_content) > max_content_length:
                file_content = file_content[:max_content_length]  # Truncate content if it's too long

            prompt = f"Given the following Nikto scan output, identify all of the critical vulnerabilities of the device and provide their corresponding cvss score. Explain please how we can avoid those vulnerabilities in a few words:\n\n{file_content}"

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
                        # Save the top vulnerabilities into the same file
                        with open(report_file_path, "a") as report_file:
                            report_file.write("\nAI can only read 7000 characters and based on them it will create a valid response of vulnerabilities found.\n\nVulnerabilities found:\n")
                            report_file.write(ai_response)

                        log_text.insert(tk.END, "\n[+] Top Vulnerabilities have been added to the report file.\n", "highlight")
                    else:
                        log_text.insert(tk.END, "[!] No response from Replicate for top vulnerabilities.\n", "error")

                except Exception as e:
                    log_text.insert(tk.END, f"[!] Error communicating with Replicate: {str(e)}\n", "error")

            # Run the Replicate call in a separate thread
            replicate_thread = threading.Thread(target=call_replicate)
            replicate_thread.start()

        except Exception as e:
            log_text.insert(tk.END, f"[!] Error saving the report: {str(e)}\n", "error")

    def exit_nikto():
        """Exit the Nikto process."""
        if process:
            process.terminate()
            log_text.insert(tk.END, "[!] Nikto process terminated.\n", "highlight")
        else:
            log_text.insert(tk.END, "[!] No Nikto process found.\n", "error")

    # Create a new pop-up window for Nikto
    nikto_window = tk.Toplevel()
    nikto_window.title("Nikto Web Scanner")
    nikto_window.geometry("900x500")

    tk.Label(nikto_window, text="Target Device IP:").pack(pady=5)
    target_entry = tk.Entry(nikto_window, width=30)
    target_entry.pack(pady=5)

    start_button = tk.Button(nikto_window, text="Start Web Vulnerability Scan", command=start_nikto, bg="green")
    start_button.pack(pady=10)

    global log_text  # Make log_text accessible to start_nikto and analyze_vulnerabilities
    log_text = tk.Text(nikto_window, wrap=tk.WORD, height=15, width=80)
    log_text.pack(pady=10)

    # "Show Report" Button 
    show_report_button = tk.Button(nikto_window, text="Show Report", command=save_report, bg="lightblue")
    show_report_button.pack(pady=10)
    
    # "Exit Nikto" Button 
    exit_button = tk.Button(nikto_window, text="Exit Nikto", command=exit_nikto, bg="lightcoral")
    exit_button.pack(pady=10)

    log_text.tag_configure("highlight", font=("Helvetica", 10, "bold"), foreground="blue")
    log_text.tag_configure("error", font=("Helvetica", 10, "italic"), foreground="red")
    log_text.tag_configure("separator", font=("Helvetica", 10), foreground="black")

    nikto_window.mainloop()
