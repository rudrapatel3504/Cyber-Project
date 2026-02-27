import subprocess
import os
import logging

OUTPUT_DIR = "output"


def run_nmap(target):
    print("[+] Running Nmap scan...")
    logging.info("Starting Nmap scan")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    try:
        result = subprocess.run(
            ["nmap", "-p-", "-sC", "-sV", target],
            capture_output=True,
            text=True,
            timeout=300
        )

        output = result.stdout

        with open(f"{OUTPUT_DIR}/nmap.txt", "w") as f:
            f.write(output)

        logging.info("Nmap scan completed successfully")
        return output

    except subprocess.TimeoutExpired:
        logging.error("Nmap scan timed out")
        print("[!] Nmap scan timed out")
        return ""

    except Exception as e:
        logging.error(f"Nmap scan failed: {e}")
        print(f"[!] Nmap scan failed: {e}")
        return ""