import threading
import time
from CTF_Recon.port_scanner import PortScanner
from CTF_Recon.subdomain_enum import SubdomainEnumerator
from CTF_Recon.whois_lookup import WhoisLookup
from CTF_Recon.dir_bruteforce import DirBruteforcer
from CTF_Recon.report_generator import generate_pdf_report
from CTF_Recon.utils import print_section, info, success, warning, error

class FullRecon:
    def __init__(self, target: str):
        self.target = target.strip()
        self.report = {"target": self.target}
        
    def run(self):
        print_section(f"Full Automated Recon → {self.target}")
        info("Initializing Port Scanner, Subdomain Enumerator, WHOIS Lookup, and Directory Brute-Forcer...")
        info("This may take some time. Running scans simultaneously in the background...\n")

        start_time = time.time()

        # Initialize tools in quiet mode
        # Assuming port scan 1-1024, default wordlists
        ps = PortScanner(self.target, 1, 1024, timeout=0.5, threads=100, quiet=True)
        # Using a default placeholder for subdomain wordlist, usually passed from main
        se = SubdomainEnumerator(self.target, wordlist_path="CTF_Recon/wordlists/subdomains.txt", threads=50, quiet=True)
        wh = WhoisLookup(self.target, quiet=True)
        db = DirBruteforcer(f"http://{self.target}", wordlist_path="CTF_Recon/wordlists/dirs.txt", threads=30, quiet=True)

        # Create threads
        threads = []
        tools = [
            (ps, "Port Scanner"),
            (se, "Subdomain Enumerator"),
            (wh, "WHOIS Lookup"),
            (db, "Directory Brute-Forcer")
        ]

        for tool, name in tools:
            t = threading.Thread(target=tool.run, name=name)
            threads.append(t)
            t.start()
            info(f"Started thread: {name}")

        # Wait for all to finish
        for t in threads:
            t.join()

        elapsed = time.time() - start_time
        success(f"\nAll scans completed in {elapsed:.2f} seconds.")

        # Aggregate Results
        self.report["port_scan"] = ps.open_ports
        self.report["subdomains"] = se.found
        self.report["whois"] = {"geo_data": wh.geo_data, "whois_data": wh.whois_data}
        self.report["directories"] = db.found

        # Save Report
        report_file = f"full_recon_report_{self.target.replace('.', '_')}.pdf"
        
        try:
            generate_pdf_report(self.report, report_file)
            success(f"Full report saved to: {report_file}")
        except Exception as e:
            error(f"Failed to generate PDF report: {e}")

        # Print a brief summary
        print("\n--- Recon Summary ---")
        print(f"Open Ports       : {len(ps.open_ports)}")
        print(f"Subdomains Found : {len(se.found)}")
        print(f"Interesting Dirs : {len(db.found)}")
        if wh.geo_data:
            print(f"Geolocation      : {wh.geo_data.get('country', 'Unknown')}, {wh.geo_data.get('city', 'Unknown')}")
        print("---------------------\n")
