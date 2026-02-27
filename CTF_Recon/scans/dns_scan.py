import subprocess
import os
import logging

WORDLIST = "Wordlists/subdomains.txt"
OUTPUT_DIR = "Output"


def run_dns(target):
    print("[+] Running DNS / Subdomain scan...")
    logging.info("Starting DNS enumeration")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    try:
        result = subprocess.run(
            [
                "gobuster",
                "dns",
                "--domain", target,
                "--wordlist", WORDLIST,
                "--threads", "50",
                "--quiet"
            ],
            capture_Output=True,
            text=True,
            timeout=300
        )

        Output = result.stdout

        with open(f"{OUTPUT_DIR}/dns.txt", "w") as f:
            f.write(Output)

        logging.info("DNS scan completed successfully")
        return Output

    except subprocess.TimeoutExpired:
        logging.error("DNS scan timed out")
        print("[!] DNS scan timed out")
        return ""

    except FileNotFoundError:
        logging.error("Gobuster not installed")
        print("[!] Gobuster not installed or not in PATH")
        return ""

    except Exception as e:
        logging.error(f"DNS scan failed: {e}")
        print(f"[!] DNS scan failed: {e}")
        return ""