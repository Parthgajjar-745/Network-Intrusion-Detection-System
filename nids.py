"""
============================================================
 PROJECT TITLE : Network Intrusion Detection System (NIDS)
 LANGUAGE       : Python 3
 AUTHOR         : Parth Gajjar
 DESCRIPTION    : This program simulates network traffic and
                  analyzes it to detect two common types of
                  network attacks:
                      1. DDoS (Distributed Denial of Service)
                      2. Port Scanning

                  The program supports two modes:
                      1. Simulation Mode - generates random
                         traffic automatically and detects
                         attacks in real time.
                      2. Manual Check Mode - lets the user
                         enter any IP address and port to
                         test it directly.

 NOTE: This is a SIMULATION-based project built for academic
 and educational purposes. No real network, device, or system
 is scanned, accessed, or attacked. All IP addresses used are
 private/fake addresses generated only for demonstration.
============================================================
"""

import random
import time
from datetime import datetime
from collections import defaultdict




REQUEST_LIMIT = 5           
TIME_WINDOW = 3              
PORT_SCAN_LIMIT = 4          

LOG_FILE = "alerts_log.txt"
NORMAL_IPS = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
ATTACKER_IP = "192.168.1.99"




ip_request_log = defaultdict(list)      
ip_port_log = defaultdict(set)          
already_alerted_ddos = set()            
already_alerted_portscan = set()        



def generate_fake_packet():
    """
    Simulates a single network packet arriving at the system.

    In a real NIDS, this data would come from a live network
    interface (captured using a library like Scapy). For this
    project, traffic is simulated so the system can be safely
    demonstrated without needing real network access.

    Returns:
        tuple: (source_ip, destination_port)
    """
    chance = random.random()  

    if chance < 0.3:
        
        ip = ATTACKER_IP
        port = random.randint(1, 100)
    else:
        ip = random.choice(NORMAL_IPS)
        port = 80

    return ip, port



def get_severity(count, limit):
    """
    Classifies how serious a detected alert is, based on how far
    past the configured limit the observed count is.

    Args:
        count (int): The observed value (requests or ports).
        limit (int): The configured threshold for that check.

    Returns:
        str: "LOW", "MEDIUM", or "HIGH"
    """
    excess = count - limit

    if excess >= 6:
        return "HIGH"
    elif excess >= 3:
        return "MEDIUM"
    else:
        return "LOW"



def log_alert(ip, attack_type, details, severity):
    """
    Records a security alert to both the console and a log file.
    Includes basic error handling so the program does not crash
    if the log file cannot be written for any reason.

    Args:
        ip (str): The source IP address that triggered the alert.
        attack_type (str): The category of attack detected.
        details (str): Extra information about the detection.
        severity (str): Severity level - LOW, MEDIUM, or HIGH.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = (
        f"[{timestamp}] ALERT - Type: {attack_type} | Severity: {severity} "
        f"| IP: {ip} | Details: {details}"
    )

    print(message)

    
    try:
        with open(LOG_FILE, "a") as log_file:
            log_file.write(message + "\n")
    except OSError as error:
        print(f"  [WARNING] Could not write to log file: {error}")



def check_ddos(ip):
    """
    Detects DDoS-like behavior by tracking how many requests
    an IP address has made within the defined TIME_WINDOW.

    Logic:
        - Every time a packet arrives, its timestamp is stored.
        - Old timestamps (outside TIME_WINDOW) are discarded.
        - If the number of recent requests exceeds REQUEST_LIMIT,
          the IP is flagged as a possible DDoS source.

    Args:
        ip (str): The source IP address to check.

    Returns:
        bool: True if a DDoS attack is detected, False otherwise.
    """
    now = time.time()
    ip_request_log[ip].append(now)

    ip_request_log [ip] = [
        timestamp for timestamp in ip_request_log[ip]
        if now - timestamp <= TIME_WINDOW
    ]

    request_count = len(ip_request_log[ip])

    if request_count > REQUEST_LIMIT:
        if ip not in already_alerted_ddos:
            severity = get_severity(request_count, REQUEST_LIMIT)
            log_alert(
                ip,
                "DDoS Attack",
                f"{request_count} requests within {TIME_WINDOW} seconds",
                severity
            )
            already_alerted_ddos.add(ip)
        return True

    return False



def check_port_scan(ip, port):
    """
    Detects port scanning behavior by tracking how many unique
    ports a single IP address has tried to access.

    Logic:
        - Each accessed port is added to a set for that IP
          (a set automatically ignores duplicate ports).
        - If the number of unique ports exceeds PORT_SCAN_LIMIT,
          the IP is flagged as a possible port scanner.

    Args:
        ip (str): The source IP address to check.
        port (int): The destination port being accessed.

    Returns:
        bool: True if port scanning is detected, False otherwise.
    """
    ip_port_log[ip].add(port)
    port_count = len(ip_port_log[ip])

    if port_count > PORT_SCAN_LIMIT:
        if ip not in already_alerted_portscan:
            severity = get_severity(port_count, PORT_SCAN_LIMIT)
            log_alert(
                ip,
                "Port Scanning",
                f"{port_count} different ports accessed",
                severity
            )
            already_alerted_portscan.add(ip)
        return True

    return False



def run_simulation(duration_seconds=20):
    """
    Runs the full NIDS simulation for a given duration.

    For each simulated packet, both detection checks (DDoS and
    Port Scanning) are run. A summary report is printed once
    monitoring is complete.

    Args:
        duration_seconds (int): How long the simulation should run, in seconds.
    """
    print("=" * 60)
    print(" NETWORK INTRUSION DETECTION SYSTEM (NIDS) - STARTED")
    print("=" * 60)
    print(f"Monitoring simulated network traffic for {duration_seconds} seconds...\n")

    start_time = time.time()
    total_packets = 0
    total_alerts = 0

    while time.time() - start_time < duration_seconds:
        ip, port = generate_fake_packet()
        total_packets += 1

        ddos_detected = check_ddos(ip)
        port_scan_detected = check_port_scan(ip, port)

        if not ddos_detected and not port_scan_detected:
            print(f"Packet #{total_packets} -> IP: {ip}, Port: {port} (Normal)")
        else:
            total_alerts += 1

        time.sleep(0.3)  

    print("\n" + "=" * 60)
    print(" MONITORING COMPLETE - SUMMARY REPORT")
    print("=" * 60)
    print(f"Total Packets Analyzed : {total_packets}")
    print(f"Total Alerts Triggered : {total_alerts}")
    print(f"Alerts saved in        : {LOG_FILE}")
    print("=" * 60)



def run_manual_check():
    """
    Lets the user manually enter an IP address and port to test
    it against the same detection logic used in the simulation.
    Includes input validation so invalid entries do not crash
    the program.
    """
    print("=" * 60)
    print(" NIDS - MANUAL IP CHECKER")
    print("=" * 60)
    print("Enter an IP address and port to check for suspicious activity.")
    print("Type 'exit' as the IP address to return to the main menu.\n")

    while True:
        ip = input("Enter IP address: ").strip()

        if ip.lower() == "exit":
            break

        if ip == "":
            print("Please enter a valid IP address.\n")
            continue

        port_input = input(f"Enter port number accessed by {ip} (e.g. 80): ").strip()

        try:
            port = int(port_input)
        except ValueError:
            print("Invalid port number. Please enter a whole number.\n")
            continue

        is_ddos = check_ddos(ip)
        is_port_scan = check_port_scan(ip, port)

        request_count = len(ip_request_log[ip])
        port_count = len(ip_port_log[ip])

        print("-" * 60)
        print(f"Checking IP: {ip}")
        print(f"  -> Requests in last {TIME_WINDOW} seconds : {request_count}")
        print(f"  -> Unique ports accessed so far          : {port_count}")

        if is_ddos or is_port_scan:
            print(f"  RESULT: SUSPICIOUS activity detected for {ip}")
        else:
            print(f"  RESULT: NORMAL - no suspicious activity detected for {ip}")

        print("-" * 60 + "\n")



def main():
    """
    Displays the main menu and lets the user choose between
    running the automatic simulation or manually checking IPs.
    """
    while True:
        print("\n" + "=" * 60)
        print(" NETWORK INTRUSION DETECTION SYSTEM (NIDS)")
        print("=" * 60)
        print("1. Run Automatic Simulation")
        print("2. Manually Check an IP Address")
        print("3. Exit")

        choice = input("\nSelect an option (1/2/3): ").strip()

        if choice == "1":
            run_simulation(duration_seconds=20)
        elif choice == "2":
            run_manual_check()
        elif choice == "3":
            print("Exiting NIDS. Goodbye!")
            break
        else:
            print("Invalid option. Please enter 1, 2, or 3.")



if __name__ == "__main__":
    main()