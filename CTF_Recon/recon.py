#!/usr/bin/env python3

import argparse
import logging
import json
import os
from datetime import datetime
from scans import run_nmap, run_dns, run_web, run_http_analysis


# -----------------------------
# Banner
# -----------------------------
def banner(title):
    print("\n" + "=" * 60)
    print(f"[+] {title}")
    print("=" * 60)


# -----------------------------
# IP Validation
# -----------------------------
def is_ip(target):
    parts = target.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


# -----------------------------
# Detect Web Services
# -----------------------------
def web_detected(nmap_output):
    return "80/tcp" in nmap_output or "443/tcp" in nmap_output


# -----------------------------
# Setup Logging
# -----------------------------
def setup_logging():
    os.makedirs("output", exist_ok=True)

    logging.basicConfig(
        filename="output/recon.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )


# -----------------------------
# Main Execution
# -----------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Recon Automation Framework"
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target domain or IP address"
    )

    args = parser.parse_args()
    target = args.target

    setup_logging()

    banner("Recon Automation Framework Started")
    print(f"Target     : {target}")
    print(f"Start Time : {datetime.now()}")

    logging.info(f"Recon started for target: {target}")

    report = {
        "target": target,
        "start_time": str(datetime.now()),
        "nmap": None,
        "dns": None,
        "web": None
    }

    # -----------------------------
    # Nmap Scan
    # -----------------------------
    try:
        banner("Nmap Scan")
        logging.info("Running Nmap scan")
        nmap_output = run_nmap(target)
        report["nmap"] = nmap_output
    except Exception as e:
        logging.error(f"Nmap scan failed: {e}")
        print(f"[!] Nmap scan failed: {e}")
        nmap_output = ""

    # -----------------------------
    # DNS Scan
    # -----------------------------
    if not is_ip(target):
        try:
            banner("DNS Enumeration")
            logging.info("Running DNS scan")
            dns_output = run_dns(target)
            report["dns"] = dns_output
        except Exception as e:
            logging.error(f"DNS scan failed: {e}")
            print(f"[!] DNS scan failed: {e}")
    else:
        logging.info("Target is IP. Skipping DNS scan.")

    # -----------------------------
    # Web Scan
    # -----------------------------
    if web_detected(nmap_output):
        try:
            banner("Web Enumeration")
            logging.info("Running Web scan")
            web_output = run_web(target)
            report["web"] = web_output
        except Exception as e:
            logging.error(f"Web scan failed: {e}")
            print(f"[!] Web scan failed: {e}")
    else:
        print("[!] No web service detected, skipping web scan")
        logging.info("No web service detected")

    # -----------------------------
    # Save JSON Report
    # -----------------------------
    report["end_time"] = str(datetime.now())

    with open("output/report.json", "w") as f:
        json.dump(report, f, indent=4)

    logging.info("Recon completed successfully")
    banner("Recon Completed")
    print("📁 Results saved in the 'output/' directory")
    print("📄 Structured report saved as output/report.json")


if __name__ == "__main__":
    main()