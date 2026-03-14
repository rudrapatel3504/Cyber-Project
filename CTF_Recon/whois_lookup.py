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
    def __init__(self, target: str, quiet: bool = False):
        self.target = target.strip()
        self.quiet = quiet
        self.geo_data = {}
        self.whois_data = {}

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
            if not self.quiet:
                error(f"Could not resolve: {self.target}")
            return None

    def _geo_lookup(self, ip: str):
        """Use ip-api.com (free, no key needed) for IP geolocation."""
        try:
            url = f"http://ip-api.com/json/{ip}"
            with urllib.request.urlopen(url, timeout=5) as resp:
                data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                fields = ["country", "regionName", "city", "zip", "isp", "org", "as"]
                for field in fields:
                    if data.get(field):
                        self.geo_data[field] = data.get(field)

                if not self.quiet:
                    print(f"\n{'IP Geolocation':}")
                    print("-" * 40)
                    for k, v in self.geo_data.items():
                        success(f"{k.capitalize():<12}: {v}")
            else:
                if not self.quiet:
                    warning("Geolocation lookup failed (private/reserved IP?).")
        except Exception as e:
            if not self.quiet:
                warning(f"Geolocation unavailable: {e}")

    def _whois_lookup(self):
        """Perform WHOIS lookup using python-whois."""
        try:
            w = whois.whois(self.target)
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
                    if isinstance(value, list):
                        value = ", ".join(str(v) for v in value[:3])
                    self.whois_data[label] = value

            if not self.quiet:
                print(f"\n{'WHOIS Info':}")
                print("-" * 40)
                for k, v in self.whois_data.items():
                    success(f"{k:<18}: {v}")
        except Exception as e:
            if not self.quiet:
                warning(f"WHOIS lookup failed: {e}")

    def run(self):
        if not self.quiet:
            print_section(f"WHOIS / IP Lookup → {self.target}")

        ip = self.target if self._is_ip() else self._resolve_ip()
        if not ip:
            return

        if not self._is_ip() and not self.quiet:
            info(f"Resolved IP: {ip}")

        # Always do geo lookup on the IP
        self._geo_lookup(ip)

        # WHOIS works better on domain names
        if not self._is_ip():
            self._whois_lookup()
        else:
            if not self.quiet:
                info("Target is an IP — skipping WHOIS domain query.")
