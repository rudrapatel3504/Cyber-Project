import subprocess
import os

WORDLIST = "wordlists/subdomains.txt"
OUTPUT_DIR = "output"

def run_dns(target):
    print("[+] Running DNS / Subdomain scan...")

    cmd = f"gobuster dns -d {target} -w {WORDLIST} -q"
    try:
        output = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.DEVNULL, text=True
        )
    except subprocess.CalledProcessError:
        output = ""

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(f"{OUTPUT_DIR}/dns.txt", "w") as f:
        f.write(output)

    return output