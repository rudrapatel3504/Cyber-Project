import subprocess
import os

OUTPUT_DIR = "output"

def run_nmap(target):
    print("[+] Running Nmap scan...")

    cmd = f"nmap -p- -sC -sV {target}"
    try:
        output = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.DEVNULL, text=True
        )
    except subprocess.CalledProcessError:
        output = ""

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(f"{OUTPUT_DIR}/nmap.txt", "w") as f:
        f.write(output)

    return output