import socket
import concurrent.futures
import ipaddress

def scan_port(ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            print(f"Port {port} ({socket.getservbyport(port)}): OPEN")
    except (socket.timeout, socket.error, OSError):
        pass

def scan_ports(ip, start_port, end_port, timeout):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(scan_port, ip, port, timeout) for port in range(start_port, end_port + 1)]
        open_ports.extend(filter(None, concurrent.futures.as_completed(futures)))

    return open_ports

def get_ip_details(ip):
    print(f"\nDetails for IP {ip}:\nIP Version: IPv{ipaddress.IPv4Address(ip).version}\nNetwork Address: {ipaddress.IPv4Network(ip, strict=False).network_address}\nHost Address: {ipaddress.IPv4Network(ip, strict=False).hostmask}")

def parse_ip_range(ip_range_str):
    return list(ipaddress.IPv4Network(ip_range_str.split('-')[0] + '-' + ip_range_str.split('-')[1], strict=False)) if '-' in ip_range_str else [ip_range_str]

if __name__ == "__main__":
    target_ips = parse_ip_range(input("Enter the target IP address or range (e.g., 192.168.1.1 or 192.168.1.1-10): "))
    start_port, end_port, timeout = int(input("Enter the starting port: ")), int(input("Enter the ending port: ")), 1.5

    print("\nScanning ports...\n")

    for ip in target_ips:
        open_ports = scan_ports(str(ip), start_port, end_port, timeout)
        print(f"\nOpen ports on {ip}:\n{', '.join(map(str, open_ports))}" if open_ports else f"\nNo open ports found on {ip}")
        get_ip_details(ip)

    print("\nScan completed successfully.")
