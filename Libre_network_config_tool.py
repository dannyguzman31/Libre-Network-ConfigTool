import csv
import paramiko
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from tkinter import ttk
import os
import sys

# Mapping from subnet mask to CIDR notation
subnet_to_cidr = {
    '255.0.0.0': 8,
    '255.128.0.0': 9,
    '255.192.0.0': 10,
    '255.224.0.0': 11,
    '255.240.0.0': 12,
    '255.248.0.0': 13,
    '255.252.0.0': 14,
    '255.254.0.0': 15,
    '255.255.0.0': 16,
    '255.255.128.0': 17,
    '255.255.192.0': 18,
    '255.255.224.0': 19,
    '255.255.240.0': 20,
    '255.255.248.0': 21,
    '255.255.252.0': 22,
    '255.255.254.0': 23,
    '255.255.255.0': 24,
    '255.255.255.128': 25,
    '255.255.255.192': 26,
    '255.255.255.224': 27,
    '255.255.255.240': 28,
    '255.255.255.248': 29,
    '255.255.255.252': 30,
    '255.255.255.254': 31,
    '255.255.255.255': 32
}

# Get the directory of the current script or executable
if getattr(sys, 'frozen', False):
    # Running in a bundle
    application_path = os.path.dirname(sys.executable)
else:
    # Running in a normal Python environment
    application_path = os.path.dirname(os.path.abspath(__file__))

# Initialize log file
log_file_path = os.path.join(application_path, 'network_config_log.txt')

# Global variable to store the selected CSV file path
selected_csv_path = None

def get_cidr_from_subnet(subnet):
    return subnet_to_cidr.get(subnet, None)

def log_message(message, log_area):
    log_area.insert(tk.END, message + '\n')
    log_area.see(tk.END)
    try:
        with open(log_file_path, 'a') as log_file:
            log_file.write(message + '\n')
    except Exception as e:
        log_area.insert(tk.END, f"Failed to write to log file: {e}\n")

def change_network_config(ssh, master,  old_ip, old_subnet, old_gateway, new_ip, new_subnet, new_gateway, log_area):
    log_message("##########################################################", log_area)
    log_message(f"{master} Before Change:", log_area)
    log_message("Updating old network configuration...", log_area)
    log_message(f"Old IP Address: {old_ip}", log_area)
    log_message(f"Old Subnet Mask: {old_subnet}", log_area)
    log_message(f"Old Gateway: {old_gateway}", log_area)

    cidr = get_cidr_from_subnet(new_subnet)
    if cidr is None:
        log_message(f"Invalid subnet mask: {new_subnet}", log_area)
        return
    
    new_ip_cidr = f"{new_ip}/{cidr}"
    new_config = f"auto eth0\n"
    new_config += f"iface eth0 inet static\n"
    new_config += f"    address {new_ip_cidr}\n"
    new_config += f"    netmask {new_subnet}\n"
    new_config += f"    gateway {new_gateway}\n"
    new_config += f"iface eth0 inet dhcp\n"
    new_config += f"iface eth0 inet6 dhcp\n"

    stdin, stdout, stderr = ssh.exec_command(f"echo \"{new_config}\" | sudo tee /etc/network/interfaces.d/eth0")
    stderr_output = stderr.read().decode('utf-8')
    if stderr_output:
        log_message(f"Error writing network config: {stderr_output}", log_area)
        return

    stdin, stdout, stderr = ssh.exec_command("cat /etc/network/interfaces.d/eth0")
    file_content = stdout.read().decode('utf-8')
    log_message("*************************************************", log_area)
    log_message("Content of /etc/network/interfaces.d/eth0 after writing:", log_area)
    log_message(file_content, log_area)
    log_message("*************************************************", log_area)
    log_message(f"Successfully updated {master} Network settings...", log_area)
    log_message(f"New IP Address: {new_ip_cidr}", log_area)
    log_message(f"New Subnet Mask: {new_subnet}", log_area)
    log_message(f"New Gateway: {new_gateway}", log_area)

def run_restart_master_script(ssh, log_area):
    stdin, stdout, stderr = ssh.exec_command('sudo ./restart_master.sh')
    output = stdout.read().decode('utf-8')
    stderr_output = stderr.read().decode('utf-8')
    if stderr_output:
        log_message(f"Error running restart_master.sh: {stderr_output}", log_area)
        return
    log_message("Output from restart_master.sh:", log_area)
    log_message(output, log_area)

def reboot_libre_os(ssh, log_area):
    log_message("Rebooting Libre OS...", log_area)
    ssh.exec_command('sudo reboot')

def process_csv(file_path, log_area):
    with open(file_path, 'r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            master = row['master']
            hostname = row['hostname']
            port = int(row['port'])
            username = row['username']
            password = row['password']
            old_ip = row['old_ip']
            old_subnet = row['old_subnet']
            old_gateway = row['old_gateway']
            new_ip = row['new_ip']
            new_subnet = row['new_subnet']
            new_gateway = row['new_gateway']
            
            try:
                with paramiko.SSHClient() as ssh:
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(hostname, port, username, password)
                    
                    change_network_config(ssh, master, old_ip, old_subnet, old_gateway, new_ip, new_subnet, new_gateway, log_area)
                    run_restart_master_script(ssh, log_area)
                    reboot_libre_os(ssh, log_area)
            except Exception as e:
                log_message("*************************************************", log_area)
                log_message(f"Failed to update {master} : {hostname}: {e}", log_area)

def select_csv(log_area):
    global selected_csv_path
    file_path = filedialog.askopenfilename(title="Select CSV File", filetypes=[("CSV files", "*.csv")])
    if file_path:
        selected_csv_path = file_path
        log_message(f"Selected CSV file: {file_path}", log_area)

def reconfigure(log_area):
    if selected_csv_path:
        process_csv(selected_csv_path, log_area)
    else:
        log_message("No CSV file selected. Please select a CSV file first.", log_area)

def create_gui():
    root = tk.Tk()
    root.title("Libre Network Configuration Tool")
    
    frame = ttk.Frame(root, padding="10")
    frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    
    select_button = ttk.Button(frame, text="Select CSV File", command=lambda: select_csv(log_area))
    select_button.grid(row=0, column=0, pady=10)
    
    reconfigure_button = ttk.Button(frame, text="Re-configure Libres", command=lambda: reconfigure(log_area))
    reconfigure_button.grid(row=0, column=1, pady=10)

    # Add a label below the buttons
    message_label = tk.Label(root, text="Select the CSV File and then click Re-configure to update the Libre network settings")
    message_label.grid(row=1, column=0, columnspan=2)
    
    log_area = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=80, height=20)
    log_area.grid(row=1, column=0, columnspan=2, pady=10)
    
    # Log the application path
    log_message(f"Application path: {application_path}", log_area)
    log_message(f"Log file path: {log_file_path}", log_area)
    
    root.mainloop()

if __name__ == "__main__":
    create_gui()
