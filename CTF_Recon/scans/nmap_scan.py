import subprocess
import os
import logging

OUTPUT_DIR = "Output"


def run_nmap(target, fast_mode=False):
    print("[+] Running Nmap scan...")
    logging.info("Starting Nmap scan")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    if fast_mode:
        logging.info("Running FAST Nmap scan")
        cmd = ["nmap", "-T4", "-F", "-sC", target]
    else:
        logging.info("Running FULL Nmap scan")
        cmd = ["nmap", "-p-", "-sC", "-sV", target]

    try:
        result = subprocess.run(
            cmd,
            capture_Output=True,
            text=True,
            timeout=300
        )

        Output = result.stdout

        with open(f"{OUTPUT_DIR}/nmap.txt", "w") as f:
            f.write(Output)

        logging.info("Nmap scan completed successfully")
        return Output

    except subprocess.TimeoutExpired:
        logging.error("Nmap scan timed out")
        print("[!] Nmap scan timed out")
        return ""

    except FileNotFoundError:
        logging.error("Nmap not installed")
        print("[!] Nmap not installed or not in PATH")
        return ""

    except Exception as e:
        logging.error(f"Nmap scan failed: {e}")
        print(f"[!] Nmap scan failed: {e}")
        return ""