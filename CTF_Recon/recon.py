#!/usr/bin/env python3

import argparse
import logging
import json
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

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
# Main
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

    parser.add_argument(
        "--fast",
        action="store_true",
        help="Run fast Nmap scan (top ports only)"
    )

    args = parser.parse_args()
    target = args.target
    fast_mode = args.fast

    setup_logging()

    banner("Recon Automation Framework Started")
    print(f"Target     : {target}")
    print(f"Start Time : {datetime.now()}")
    print(f"Scan Mode  : {'FAST' if fast_mode else 'FULL'}")

    logging.info(f"Recon started for target: {target}")
    logging.info(f"Scan mode: {'FAST' if fast_mode else 'FULL'}")

    report = {
        "target": target,
        "scan_mode": "FAST" if fast_mode else "FULL",
        "start_time": str(datetime.now()),
        "nmap": None,
        "dns": None,
        "web": None,
        "http_headers": None
    }

    # -----------------------------
    # Nmap Scan
    # -----------------------------
    try:
        banner("Nmap Scan")
        nmap_output = run_nmap(target, fast_mode)
        report["nmap"] = nmap_output
    except Exception as e:
        logging.error(f"Nmap failed: {e}")
        print(f"[!] Nmap failed: {e}")
        nmap_output = ""

    # -----------------------------
    # Parallel DNS + Web
    # -----------------------------
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = []

        if not is_ip(target):
            futures.append(("dns", executor.submit(run_dns, target)))

        if web_detected(nmap_output):
            futures.append(("web", executor.submit(run_web, target)))

        for name, future in futures:
            try:
                result = future.result()
                report[name] = result
            except Exception as e:
                logging.error(f"{name} scan failed: {e}")

    # -----------------------------
    # HTTP Header Analysis
    # -----------------------------
    try:
        banner("HTTP Header Analysis")
        headers = run_http_analysis(target)
        report["http_headers"] = headers
    except Exception as e:
        logging.error(f"HTTP analysis failed: {e}")

    # -----------------------------
    # Save JSON Report
    # -----------------------------
    report["end_time"] = str(datetime.now())

    with open("output/report.json", "w") as f:
        json.dump(report, f, indent=4)

    logging.info("Recon completed successfully")

    banner("Recon Completed")
    print("📁 Results saved in 'output/' directory")
    print("📄 Structured report saved as output/report.json")


if __name__ == "__main__":
    main()