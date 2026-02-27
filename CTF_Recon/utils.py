"""
Shared utilities: banner, colored output, section headers.
"""

from datetime import datetime

# ANSI color codes
class Color:
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def banner():
    print(f"""
{Color.CYAN}{Color.BOLD}
  ██████╗████████╗███████╗    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██╔════╝╚══██╔══╝██╔════╝    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██║        ██║   █████╗      ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██║        ██║   ██╔══╝      ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ╚██████╗   ██║   ██║         ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═════╝   ╚═╝   ╚═╝         ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{Color.RESET}
{Color.YELLOW}  CTF Recon Tool | Port Scan | Subdomain Enum | WHOIS | Dir Brute{Color.RESET}
  {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
""")

def print_section(title: str):
    print(f"\n{Color.BOLD}{Color.CYAN}{'='*50}")
    print(f"  {title}")
    print(f"{'='*50}{Color.RESET}")

def success(msg: str):
    print(f"{Color.GREEN}[+] {msg}{Color.RESET}")

def warning(msg: str):
    print(f"{Color.YELLOW}[!] {msg}{Color.RESET}")

def error(msg: str):
    print(f"{Color.RED}[-] {msg}{Color.RESET}")

def info(msg: str):
    print(f"[*] {msg}")
