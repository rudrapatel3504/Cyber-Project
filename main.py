#!/usr/bin/env python3
"""
CTF Recon Tool - Main Entry Point
Supports both CLI (argparse) and interactive menu modes.
"""

import argparse
import sys
from CTF_Recon.port_scanner import PortScanner
from CTF_Recon.subdomain_enum import SubdomainEnumerator
from CTF_Recon.whois_lookup import WhoisLookup
from CTF_Recon.dir_bruteforce import DirBruteforcer
from CTF_Recon.utils import banner, print_section

def run_interactive():
    """Launch an interactive menu for the recon tool."""
    banner()
    while True:
        print("\n[*] Select a module:")
        print("  1. Port Scanner")
        print("  2. Subdomain Enumerator")
        print("  3. WHOIS / IP Lookup")
        print("  4. Directory Brute-Forcer")
        print("  0. Exit")

        choice = input("\n> ").strip()

        if choice == "1":
            target = input("Enter target IP/hostname: ").strip()
            port_range = input("Port range (e.g. 1-1024) [default: 1-1024]: ").strip() or "1-1024"
            start, end = map(int, port_range.split("-"))
            scanner = PortScanner(target, start, end)
            scanner.run()

        elif choice == "2":
            domain = input("Enter domain (e.g. example.com): ").strip()
            wordlist = input("Wordlist path [default: CTF_Recon/wordlists/subdomains.txt]: ").strip() or "CTF_Recon/wordlists/subdomains.txt"
            enumerator = SubdomainEnumerator(domain, wordlist)
            enumerator.run()

        elif choice == "3":
            target = input("Enter domain or IP: ").strip()
            lookup = WhoisLookup(target)
            lookup.run()

        elif choice == "4":
            url = input("Enter target URL (e.g. http://example.com): ").strip()
            wordlist = input("Wordlist path [default: CTF_Recon/wordlists/dirs.txt]: ").strip() or "CTF_Recon/wordlists/dirs.txt"
            bruteforcer = DirBruteforcer(url, wordlist)
            bruteforcer.run()

        elif choice == "0":
            print("\n[*] Exiting. Good luck on your CTF!\n")
            sys.exit(0)

        else:
            print("[-] Invalid choice. Try again.")


def run_cli():
    """Parse CLI arguments and run the selected module."""
    banner()
    parser = argparse.ArgumentParser(
        description="CTF Recon Tool - All-in-one reconnaissance suite",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="module", help="Module to run")

    # Port Scanner
    ps = subparsers.add_parser("portscan", help="Scan open ports on a target")
    ps.add_argument("target", help="Target IP or hostname")
    ps.add_argument("--start", type=int, default=1, help="Start port (default: 1)")
    ps.add_argument("--end", type=int, default=1024, help="End port (default: 1024)")

    # Subdomain Enum
    se = subparsers.add_parser("subdomain", help="Enumerate subdomains")
    se.add_argument("domain", help="Target domain (e.g. example.com)")
    se.add_argument("--wordlist", default="CTF_Recon/wordlists/subdomains.txt", help="Path to wordlist")

    # WHOIS
    wh = subparsers.add_parser("whois", help="WHOIS and IP info lookup")
    wh.add_argument("target", help="Domain or IP address")

    # Dir Brute-force
    db = subparsers.add_parser("dirbrute", help="Brute-force directories on a web server")
    db.add_argument("url", help="Target URL (e.g. http://example.com)")
    db.add_argument("--wordlist", default="CTF_Recon/wordlists/dirs.txt", help="Path to wordlist")

    args = parser.parse_args()

    if not args.module:
        parser.print_help()
        sys.exit(1)

    if args.module == "portscan":
        PortScanner(args.target, args.start, args.end).run()
    elif args.module == "subdomain":
        SubdomainEnumerator(args.domain, args.wordlist).run()
    elif args.module == "whois":
        WhoisLookup(args.target).run()
    elif args.module == "dirbrute":
        DirBruteforcer(args.url, args.wordlist).run()


if __name__ == "__main__":
    # If no arguments given, launch interactive menu
    if len(sys.argv) == 1:
        run_interactive()
    else:
        run_cli()
