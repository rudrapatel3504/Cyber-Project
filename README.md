# 🛡️ CTF Recon Tool

A modular, multi-threaded reconnaissance suite built for CTF competitions and ethical security research.

## Features

| Module | Description |
|--------|-------------|
| 🔍 Port Scanner | Fast TCP port scan with service detection |
| 🌐 Subdomain Enumerator | DNS brute-force subdomain discovery |
| 📋 WHOIS / IP Lookup | WHOIS data + IP geolocation |
| 📁 Directory Brute-Forcer | Hidden path/file discovery on web servers |

## Installation

```bash
git clone https://github.com/rudrapatel3504/Cyber-Project
cd Cyber-Project
pip install -r requirements.txt
```

## Usage

### Interactive Menu (no arguments)
```bash
python main.py
```

### CLI Mode

```bash
# Port scan
python main.py portscan <target> --start 1 --end 1024

# Subdomain enumeration
python main.py subdomain example.com --wordlist CTF_Recon/wordlists/subdomains.txt

# WHOIS / IP lookup
python main.py whois example.com

# Directory brute-force
python main.py dirbrute http://example.com --wordlist CTF_Recon/wordlists/dirs.txt
```

## Project Structure

```
Cyber-Project/
├── main.py                        # Entry point (CLI + interactive menu)
├── requirements.txt
├── CTF_Recon/
│   ├── __init__.py
│   ├── utils.py                   # Shared helpers (colors, banner, etc.)
│   ├── port_scanner.py            # Threaded TCP port scanner
│   ├── subdomain_enum.py          # DNS subdomain brute-forcer
│   ├── whois_lookup.py            # WHOIS + IP geolocation
│   ├── dir_bruteforce.py          # HTTP directory brute-forcer
│   └── wordlists/
│       ├── subdomains.txt
│       └── dirs.txt
```

## ⚠️ Legal Disclaimer

This tool is intended **only** for use on systems you own or have explicit written permission to test. Unauthorized scanning is illegal. Use responsibly.
