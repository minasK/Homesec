import re  # To strip ANSI codes.
import subprocess  # To run the Hydra command.
import threading  # For threading the output reading.
import tkinter as tk  # For building the GUI.
from tkinter import simpledialog, Text, Toplevel, WORD, messagebox  # For GUI components.
import replicate # replicate AI api

def launch_hydra_window():
    def strip_ansi_codes(text):
        """Strips ANSI color codes from the given text."""
        ansi_escape = re.compile(r'\x1B\[[0-?9;]*[mG]')
        return ansi_escape.sub('', text)

    def start_hydra():
        """Starts Hydra with predefined attack commands and captures output."""
        global process  # Declare process as global to manage it across functions
        target_device = target_entry.get().strip()
        username = username_entry.get().strip()
        password_file = password_file_entry.get().strip() or "/usr/share/wordlists/rockyou.txt.gz"
        service = service_var.get().strip()

        common_services = ["ssh", "ftp", "http-post-form", "smb", "rdp", "telnet", "http-get"]
        services_to_try = [service] if service else common_services

        if not target_device or not username:
            log_text.insert(tk.END, "Please enter at least Target and Username fields.\n", "error")
            return

        log_text.insert(tk.END, f"[*] Running Hydra brute-force attack on {target_device}...\n", "highlight")
        log_text.insert(tk.END, "----------------------------------------------------\n", "separator")
        
        for srv in services_to_try:
            log_text.insert(tk.END, f"[*] Trying service: {srv}\n", "highlight")
            command = [
                "hydra", "-I", "-l", username, "-P", password_file, f"{srv}://{target_device}"
            ]

            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            def read_output():
                """Reads Hydra output and updates the log window."""
                try:
                    for line in iter(process.stdout.readline, ''):
                        if line:
                            cleaned_output = strip_ansi_codes(line)
                            log_text.insert(tk.END, cleaned_output + "\n")
                            log_text.see(tk.END)

                    for error_line in iter(process.stderr.readline, ''):
                        if error_line:
                            cleaned_error = strip_ansi_codes(error_line)
                            log_text.insert(tk.END, cleaned_error + "\n", "error")
                            log_text.see(tk.END)

                except Exception as e:
                    log_text.insert(tk.END, f"[!] Error while reading process output: {str(e)}\n", "error")
                finally:
                    log_text.insert(tk.END, "\n[!] Hydra attack completed.\n", "highlight")

            output_thread = threading.Thread(target=read_output)
            output_thread.start()

    def stop_process():
        """Terminates the Hydra process."""
        global process
        if process:
            process.terminate()
            process = None

    def save_report():
        """Saves the contents of the log_text to a file and interacts with the Replicate API."""
        report_file_path = "/home/kali/Desktop/hydra_vulnerability_report.txt"
        
        def handle_replicate_response(file_content):
            """Handles the Replicate response and appends it to the report."""
            prompt = f"Given the following Hydra scan output, identify all of the critical vulnerabilities of the device and provide their corresponding cvss score. Explain please how we can avoid those vulnerabilities in a few words:\n\n{file_content}"
            try:
                response = replicate.run(
                    "meta/llama-2-7b-chat",
                    input={"prompt": prompt, "max_tokens": 5000}
                )

                if response:
                    ai_response = "".join(response)
                    with open(report_file_path, "a") as report_file:
                        report_file.write("\n[+] Device Vulnerabilities:\n")
                        report_file.write(ai_response)

                    log_text.insert(tk.END, "\n[+] Top vulnerabilities have been added to the report file.\n", "highlight")
                else:
                    log_text.insert(tk.END, "[!] No response from Replicate for top vulnerabilities.\n", "error")

            except Exception as e:
                log_text.insert(tk.END, f"[!] Error communicating with Replicate: {str(e)}\n", "error")

        try:
            # Save the initial content to the file
            with open(report_file_path, "w") as report_file:
                report_file.write(log_text.get("1.0", tk.END))
                log_text.insert(tk.END, f"[+] Report saved to {report_file_path}\n", "highlight")

            with open(report_file_path, "r") as report_file:
                file_content = report_file.read()

            # Create a new thread to handle the Replicate request and response processing
            replicate_thread = threading.Thread(target=handle_replicate_response, args=(file_content,))
            replicate_thread.start()

        except Exception as e:
            log_text.insert(tk.END, f"[!] Error saving the report: {str(e)}\n", "error")

    def exit_hydra():
        """Stops the process and closes the window."""
        stop_process()
        hydra_window.destroy()

    hydra_window = tk.Toplevel()
    hydra_window.title("Hydra Brute-Force Attack")
    hydra_window.geometry("1800x800")

    # Center the window on the screen
    hydra_window.update_idletasks()
    screen_width = hydra_window.winfo_screenwidth()
    screen_height = hydra_window.winfo_screenheight()
    window_width = 1800
    window_height = 800
    x_position = (screen_width // 2) - (window_width // 2)
    y_position = (screen_height // 2) - (window_height // 2)
    hydra_window.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")

    tk.Label(hydra_window, text="Target Device IP:").pack(pady=5)
    target_entry = tk.Entry(hydra_window, width=30)
    target_entry.pack(pady=5)

    tk.Label(hydra_window, text="Username:").pack(pady=5)
    username_entry = tk.Entry(hydra_window, width=30)
    username_entry.pack(pady=5)

    tk.Label(hydra_window, text="Password File (default: rockyou.txt.gz):").pack(pady=5)
    password_file_entry = tk.Entry(hydra_window, width=50)
    password_file_entry.pack(pady=5)

    tk.Label(hydra_window, text="Service (leave blank to try multiple services):").pack(pady=5)
    service_var = tk.Entry(hydra_window, width=20)
    service_var.pack(pady=5)

    start_button = tk.Button(hydra_window, text="Start Brute-Force Attack", command=start_hydra, bg="green")
    start_button.pack(pady=10)

    log_text = tk.Text(hydra_window, wrap=tk.WORD, height=15, width=80)
    log_text.pack(pady=10)

    show_report_button = tk.Button(hydra_window, text="Show Report", command=save_report, bg="lightblue")
    show_report_button.pack(pady=10)

    # Exit button to properly terminate Hydra and close the window
    exit_button = tk.Button(hydra_window, text="Exit", command=exit_hydra, bg="lightcoral")
    exit_button.pack(pady=10)

    log_text.tag_configure("highlight", font=("Helvetica", 10, "bold"), foreground="blue")
    log_text.tag_configure("error", font=("Helvetica", 10, "italic"), foreground="red")
    log_text.tag_configure("separator", font=("Helvetica", 10), foreground="black")

    hydra_window.protocol("WM_DELETE_WINDOW", exit_hydra)

    hydra_window.mainloop()
