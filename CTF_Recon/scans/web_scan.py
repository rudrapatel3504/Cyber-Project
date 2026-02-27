import subprocess
import os
import logging

WORDLIST = "wordlists/directories.txt"
OUTPUT_DIR = "output"


def run_web(target):
    print("[+] Running Web directory scan...")
    logging.info("Starting web enumeration")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Try HTTPS first, then fallback to HTTP
    urls_to_try = [
        f"https://{target}",
        f"http://{target}"
    ]

    for url in urls_to_try:
        try:
            logging.info(f"Trying URL: {url}")

            result = subprocess.run(
                [
                    "gobuster",
                    "dir",
                    "-u", url,
                    "-w", WORDLIST,
                    "-t", "50",             # threads
                    "-x", "php,html,txt",   # common extensions
                    "-q"
                ],
                capture_output=True,
                text=True,
                timeout=300
            )

            output = result.stdout

            if output:
                with open(f"{OUTPUT_DIR}/web.txt", "w") as f:
                    f.write(f"Target URL: {url}\n\n")
                    f.write(output)

                logging.info(f"Web scan successful on {url}")
                return output

        except subprocess.TimeoutExpired:
            logging.error(f"Web scan timed out for {url}")
            print(f"[!] Web scan timed out for {url}")

        except FileNotFoundError:
            logging.error("Gobuster not installed")
            print("[!] Gobuster not installed or not in PATH")
            return ""

        except Exception as e:
            logging.error(f"Web scan failed for {url}: {e}")
            print(f"[!] Web scan failed for {url}: {e}")

    logging.info("Web scan completed with no findings")
    print("[!] Web scan completed but no directories found")
    return ""