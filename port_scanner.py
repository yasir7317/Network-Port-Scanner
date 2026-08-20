"""
Basic Network Port Scanner
--------------------------
A beginner-friendly TCP port scanner written in pure Python using the built-in `socket` module.
Scans a target host across a specified range of ports and reports open ports.
"""

import socket
import sys
import time
from datetime import datetime

# Default connection timeout in seconds (adjust if scanning over a slow network)
DEFAULT_TIMEOUT = 0.5


def get_target_ip(host_input: str) -> tuple[str, str] | None:
    """
    Resolves the provided hostname or IP address to a valid IPv4 address.
    Returns a tuple of (resolved_ip, hostname_or_ip) or None if resolution fails.
    """
    host_clean = host_input.strip()
    if not host_clean:
        print("[!] Error: Target cannot be empty.")
        return None

    try:
        # Resolve hostname (e.g., 'scanme.nmap.org' or 'localhost') to an IPv4 address
        ip_address = socket.gethostbyname(host_clean)
        return ip_address, host_clean
    except socket.gaierror:
        print(f"[!] Error: Hostname '{host_clean}' could not be resolved. Please check the address.")
        return None
    except socket.error as err:
        print(f"[!] Error: Could not connect to host. Details: {err}")
        return None


def get_port_range() -> tuple[int, int] | None:
    """
    Prompts the user for starting and ending port numbers and validates the range.
    Valid port numbers are between 1 and 65535.
    """
    try:
        start_input = input("Enter Starting Port (1-65535): ").strip()
        end_input = input("Enter Ending Port (1-65535): ").strip()

        start_port = int(start_input)
        end_port = int(end_input)

        # Validate bounds
        if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
            print("[!] Error: Port numbers must be between 1 and 65535.")
            return None

        if start_port > end_port:
            print("[!] Error: Starting port cannot be greater than ending port.")
            return None

        return start_port, end_port

    except ValueError:
        print("[!] Error: Please enter valid integer numbers for ports.")
        return None


def get_service_name(port: int) -> str:
    """
    Attempts to identify the common service name for a given TCP port.
    Returns 'Unknown' if standard service is not mapped.
    """
    try:
        return socket.getservbyport(port, "tcp").upper()
    except (OSError, socket.error):
        return "UNKNOWN"


def scan_ports(target_ip: str, target_name: str, start_port: int, end_port: int, timeout: float = DEFAULT_TIMEOUT):
    """
    Scans TCP ports from start_port to end_port on the target_ip.
    """
    total_ports = end_port - start_port + 1
    open_ports = []

    print("\n" + "=" * 60)
    print(f" Target Host   : {target_name} ({target_ip})")
    print(f" Port Range    : {start_port} - {end_port} ({total_ports} total ports)")
    print(f" Scan Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f" Timeout       : {timeout}s per port")
    print("=" * 60 + "\n")

    start_time = time.time()

    try:
        for index, port in enumerate(range(start_port, end_port + 1), start=1):
            # Calculate and display progress in real-time
            progress = (index / total_ports) * 100
            print(f"\r[*] Scanning port {port} ({index}/{total_ports}) [{progress:5.1f}%]...", end="", flush=True)

            # Create a TCP socket
            # AF_INET = IPv4, SOCK_STREAM = TCP
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)

                # connect_ex returns 0 on success (port open) or an error code if closed/filtered
                result = sock.connect_ex((target_ip, port))

                if result == 0:
                    service = get_service_name(port)
                    # Clear the current progress line and print the open port
                    print(f"\r[+] Port {port:<5} OPEN  ({service})".ljust(60))
                    open_ports.append((port, service))

    except KeyboardInterrupt:
        print("\n\n[!] Scan paused/interrupted by user (Ctrl+C). Showing partial results...")
    except socket.error as err:
        print(f"\n[!] Socket error encountered: {err}")

    elapsed_time = time.time() - start_time

    # Display final summary
    print("\n" + "=" * 60)
    print(" SCAN SUMMARY")
    print("=" * 60)
    print(f" Target           : {target_name} ({target_ip})")
    print(f" Total Ports      : {total_ports}")
    print(f" Open Ports Found : {len(open_ports)}")
    print(f" Time Taken       : {elapsed_time:.2f} seconds")

    if open_ports:
        print("\n Discovered Open Ports:")
        print(" ----------------------------------------")
        print(f" {'PORT':<10} {'STATE':<10} {'SERVICE':<15}")
        print(" ----------------------------------------")
        for port, service in open_ports:
            print(f" {port:<10} {'OPEN':<10} {service:<15}")
        print(" ----------------------------------------")
    else:
        print("\n No open ports were detected in the specified range.")

    print("=" * 60 + "\n")


def main():
    """Main entry point of the script."""
    print("=" * 60)
    print("       PYTHON BASIC TCP NETWORK PORT SCANNER")
    print("=" * 60)

    # Allow CLI arguments: python port_scanner.py <target> <start_port> <end_port>
    if len(sys.argv) == 4:
        target_input = sys.argv[1]
        try:
            start_port = int(sys.argv[2])
            end_port = int(sys.argv[3])
            if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535) or (start_port > end_port):
                print("[!] Error: Invalid port range provided in arguments.")
                sys.exit(1)
        except ValueError:
            print("[!] Error: Port arguments must be integers.")
            sys.exit(1)
    else:
        # 1. Ask for Target IP or Hostname interactively
        target_input = input("Enter target IP address or hostname (e.g., 127.0.0.1 or localhost): ")

    target_info = get_target_ip(target_input)
    if target_info is None:
        sys.exit(1)

    target_ip, target_name = target_info

    # 2. Ask for Port Range interactively if not provided via arguments
    if len(sys.argv) != 4:
        port_range = get_port_range()
        if port_range is None:
            sys.exit(1)
        start_port, end_port = port_range

    # 3. Perform Port Scan
    scan_ports(target_ip, target_name, start_port, end_port)


if __name__ == "__main__":
    main()

