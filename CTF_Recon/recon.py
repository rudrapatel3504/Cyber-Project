#!/usr/bin/env python3

import sys
from datetime import datetime

# Import scans directly from the package
from scans import run_nmap, run_dns, run_web


def banner(title):
    print("\n" + "=" * 60)
    print(f"[+] {title}")
    print("=" * 60)


def is_ip(target):
    parts = target.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def web_detected(nmap_output):
    return "80/tcp" in nmap_output or "443/tcp" in nmap_output


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 recon.py <target>")
        sys.exit(1)

    target = sys.argv[1]

    banner("CTF Recon Automation Started")
    print(f"Target     : {target}")
    print(f"Start Time : {datetime.now()}")

    # 1️⃣ Nmap scan (always run)
    nmap_output = run_nmap(target)

    # 2️⃣ DNS scan (only if target is a domain)
    if not is_ip(target):
        banner("DNS Enumeration")
        run_dns(target)

    # 3️⃣ Web scan (only if HTTP/HTTPS detected)
    if web_detected(nmap_output):
        banner("Web Enumeration")
        run_web(target)
    else:
        print("[!] No web service detected, skipping web scan")

    banner("Recon Completed")
    print("📁 Results saved in the 'output/' directory")


if __name__ == "__main__":
    main()