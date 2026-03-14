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
from CTF_Recon.pdf_unlocker import PdfUnlocker
from CTF_Recon.wordlist_generator import WordlistGenerator
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
        print("  5. PDF Unlocker")
        print("  6. Wordlist Generator")
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

        elif choice == "5":
            pdf_path = input("Enter path to encrypted PDF: ").strip()
            output_path = input("Output path [leave blank for auto]: ").strip() or None
            unlocker = PdfUnlocker(pdf_path, output_path)
            unlocker.run()

        elif choice == "6":
            names_input = input("Enter target name(s) separated by space: ").strip()
            names = names_input.split() if names_input else []
            y_from = input("Year FROM [default: 1980]: ").strip()
            y_to = input("Year TO [default: 2010]: ").strip()
            brute = input("Include 4-digit brute force (y/n)? [default: y]: ").strip().lower()
            output = input("Output path [leave blank for auto]: ").strip() or None

            y_from = int(y_from) if y_from.isdigit() else 1980
            y_to = int(y_to) if y_to.isdigit() else 2010
            include_brute = brute != 'n'

            generator = WordlistGenerator(names, y_from, y_to, include_brute, output)
            generator.run()

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

    # PDF Unlocker
    pu = subparsers.add_parser("pdfunlock", help="Unlock a password-protected PDF using date-based brute-force")
    pu.add_argument("pdf", help="Path to the encrypted PDF file")
    pu.add_argument("--output", default=None, help="Output path for unlocked PDF (default: <name>_unlocked.pdf)")

    # Wordlist Generator
    wg = subparsers.add_parser("wordlist", help="Generate targeted wordlists")
    wg.add_argument("names", nargs="+", help="Target name(s)")
    wg.add_argument("--year-from", type=int, default=1980, help="Start year (default: 1980)")
    wg.add_argument("--year-to", type=int, default=2010, help="End year (default: 2010)")
    wg.add_argument("--no-brute", action="store_true", help="Skip 4-digit brute-force patterns")
    wg.add_argument("--output", default=None, help="Output path")

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
    elif args.module == "pdfunlock":
        PdfUnlocker(args.pdf, args.output).run()
    elif args.module == "wordlist":
        WordlistGenerator(args.names, args.year_from, args.year_to, not args.no_brute, args.output).run()


if __name__ == "__main__":
    # If no arguments given, launch interactive menu
    if len(sys.argv) == 1:
        run_interactive()
    else:
        run_cli()
