import subprocess
import os

WORDLIST = "wordlists/directories.txt"
OUTPUT_DIR = "output"

def run_web(target):
    print("[+] Running Web directory scan...")

    cmd = f"gobuster dir -u http://{target} -w {WORDLIST} -q"
    try:
        output = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.DEVNULL, text=True
        )
    except subprocess.CalledProcessError:
        output = ""

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(f"{OUTPUT_DIR}/web.txt", "w") as f:
        f.write(output)

    return output