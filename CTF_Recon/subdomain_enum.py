"""
Subdomain Enumerator Module
DNS-based subdomain brute-forcing using a wordlist and threading.
"""

import socket
import concurrent.futures
from CTF_Recon.utils import print_section, success, error, info, warning

class SubdomainEnumerator:
    def __init__(self, domain: str, wordlist_path: str, threads: int = 50):
        self.domain = domain.strip().lower()
        self.wordlist_path = wordlist_path
        self.threads = threads
        self.found = []

    def _load_wordlist(self) -> list[str]:
        try:
            with open(self.wordlist_path, "r") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            error(f"Wordlist not found: {self.wordlist_path}")
            return []

    def _check_subdomain(self, word: str) -> tuple[str, str] | None:
        subdomain = f"{word}.{self.domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            return (subdomain, ip)
        except socket.gaierror:
            return None

    def run(self):
        print_section(f"Subdomain Enumerator → {self.domain}")
        words = self._load_wordlist()
        if not words:
            return

        info(f"Loaded {len(words)} words from wordlist.")
        info(f"Enumerating subdomains with {self.threads} threads...\n")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = executor.map(self._check_subdomain, words)

        self.found = [r for r in results if r is not None]

        if self.found:
            print(f"{'SUBDOMAIN':<40} {'IP ADDRESS'}")
            print("-" * 60)
            for subdomain, ip in sorted(self.found):
                success(f"{subdomain:<40} {ip}")
            print(f"\n[*] {len(self.found)} subdomain(s) discovered.")
        else:
            warning("No subdomains found. Try a larger wordlist.")
