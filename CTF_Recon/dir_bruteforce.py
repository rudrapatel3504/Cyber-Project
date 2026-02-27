"""
Directory Brute-Forcer Module
Discovers hidden directories/files on a web server using a wordlist and threading.
"""

import urllib.request
import urllib.error
import concurrent.futures
from CTF_Recon.utils import print_section, success, error, info, warning

# HTTP status codes worth reporting
INTERESTING_CODES = {
    200: "OK",
    201: "Created",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found (Redirect)",
    401: "Unauthorized",
    403: "Forbidden",
    405: "Method Not Allowed",
    500: "Internal Server Error",
}

class DirBruteforcer:
    def __init__(self, base_url: str, wordlist_path: str, threads: int = 30, extensions: list[str] = None):
        self.base_url = base_url.rstrip("/")
        self.wordlist_path = wordlist_path
        self.threads = threads
        # Optionally probe for file extensions too
        self.extensions = extensions or ["", ".php", ".html", ".txt", ".bak"]
        self.found = []

    def _load_wordlist(self) -> list[str]:
        try:
            with open(self.wordlist_path, "r") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            error(f"Wordlist not found: {self.wordlist_path}")
            return []

    def _probe(self, path: str) -> tuple[str, int] | None:
        """Send a HEAD request (faster than GET) and return (url, status)."""
        url = f"{self.base_url}/{path}"
        try:
            req = urllib.request.Request(url, method="HEAD")
            req.add_header("User-Agent", "CTFRecon/1.0")
            with urllib.request.urlopen(req, timeout=5) as resp:
                code = resp.status
                if code in INTERESTING_CODES:
                    return (url, code)
        except urllib.error.HTTPError as e:
            if e.code in INTERESTING_CODES:
                return (url, e.code)
        except Exception:
            pass
        return None

    def _build_targets(self, words: list[str]) -> list[str]:
        """Expand wordlist with configured extensions."""
        targets = []
        for word in words:
            for ext in self.extensions:
                targets.append(f"{word}{ext}")
        return targets

    def run(self):
        print_section(f"Directory Brute-Forcer → {self.base_url}")
        words = self._load_wordlist()
        if not words:
            return

        targets = self._build_targets(words)
        info(f"Loaded {len(words)} words × {len(self.extensions)} extension(s) = {len(targets)} probes.")
        info(f"Running with {self.threads} threads...\n")

        print(f"{'STATUS':<10} {'MEANING':<25} {'URL'}")
        print("-" * 80)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = executor.map(self._probe, targets)

        for result in results:
            if result:
                url, code = result
                meaning = INTERESTING_CODES.get(code, "?")
                self.found.append(result)
                if code == 200:
                    success(f"{code:<10} {meaning:<25} {url}")
                else:
                    warning(f"{code:<10} {meaning:<25} {url}")

        print(f"\n[*] {len(self.found)} interesting path(s) found.")
