"""
WHOIS / IP Lookup Module
Performs WHOIS lookup and IP geolocation using python-whois and ip-api.com.
"""

import socket
import json
import urllib.request
import whois
from CTF_Recon.utils import print_section, success, error, info, warning

class WhoisLookup:
    def __init__(self, target: str):
        self.target = target.strip()

    def _is_ip(self) -> bool:
        try:
            socket.inet_aton(self.target)
            return True
        except socket.error:
            return False

    def _resolve_ip(self) -> str | None:
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            error(f"Could not resolve: {self.target}")
            return None

    def _geo_lookup(self, ip: str):
        """Use ip-api.com (free, no key needed) for IP geolocation."""
        try:
            url = f"http://ip-api.com/json/{ip}"
            with urllib.request.urlopen(url, timeout=5) as resp:
                data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                print(f"\n{'IP Geolocation':}")
                print("-" * 40)
                fields = ["country", "regionName", "city", "zip", "isp", "org", "as"]
                for field in fields:
                    val = data.get(field, "N/A")
                    if val:
                        success(f"{field.capitalize():<12}: {val}")
            else:
                warning("Geolocation lookup failed (private/reserved IP?).")
        except Exception as e:
            warning(f"Geolocation unavailable: {e}")

    def _whois_lookup(self):
        """Perform WHOIS lookup using python-whois."""
        try:
            w = whois.whois(self.target)
            print(f"\n{'WHOIS Info':}")
            print("-" * 40)
            fields = {
                "Domain Name": w.domain_name,
                "Registrar": w.registrar,
                "Creation Date": w.creation_date,
                "Expiration Date": w.expiration_date,
                "Updated Date": w.updated_date,
                "Name Servers": w.name_servers,
                "Status": w.status,
                "Emails": w.emails,
                "Org": w.org,
            }
            for label, value in fields.items():
                if value:
                    # Handle lists
                    if isinstance(value, list):
                        value = ", ".join(str(v) for v in value[:3])
                    success(f"{label:<18}: {value}")
        except Exception as e:
            warning(f"WHOIS lookup failed: {e}")

    def run(self):
        print_section(f"WHOIS / IP Lookup → {self.target}")

        ip = self.target if self._is_ip() else self._resolve_ip()
        if not ip:
            return

        if not self._is_ip():
            info(f"Resolved IP: {ip}")

        # Always do geo lookup on the IP
        self._geo_lookup(ip)

        # WHOIS works better on domain names
        if not self._is_ip():
            self._whois_lookup()
        else:
            info("Target is an IP — skipping WHOIS domain query.")
