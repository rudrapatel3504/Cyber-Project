"""
Port Scanner Module
Scans a range of TCP ports on a target using threading for speed.
"""

import socket
import concurrent.futures
from CTF_Recon.utils import print_section, success, error, info, warning

# Common port-to-service mapping
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}

class PortScanner:
    def __init__(self, target: str, start_port: int = 1, end_port: int = 1024, timeout: float = 0.5, threads: int = 100):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.threads = threads
        self.open_ports = []

    def _resolve_target(self) -> str | None:
        try:
            ip = socket.gethostbyname(self.target)
            return ip
        except socket.gaierror:
            error(f"Could not resolve hostname: {self.target}")
            return None

    def _scan_port(self, port: int) -> int | None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((self.target, port))
                if result == 0:
                    return port
        except Exception:
            pass
        return None

    def run(self):
        print_section(f"Port Scanner → {self.target}")
        ip = self._resolve_target()
        if not ip:
            return

        info(f"Resolved to: {ip}")
        info(f"Scanning ports {self.start_port}–{self.end_port} with {self.threads} threads...\n")

        ports = range(self.start_port, self.end_port + 1)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = executor.map(self._scan_port, ports)

        self.open_ports = [p for p in results if p is not None]

        if self.open_ports:
            print(f"{'PORT':<10} {'SERVICE':<15} {'STATE'}")
            print("-" * 35)
            for port in sorted(self.open_ports):
                service = COMMON_PORTS.get(port, "Unknown")
                success(f"{port:<10} {service:<15} OPEN")
            print(f"\n[*] {len(self.open_ports)} open port(s) found.")
        else:
            warning("No open ports found in the given range.")
