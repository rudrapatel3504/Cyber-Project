"""
PDF Unlocker Module
Brute-forces password-protected PDFs using DDMMYYYY date-based passwords.
Requires system tools: pdfcrack, qpdf
"""

import subprocess
import os
import re
from datetime import date, timedelta
from CTF_Recon.utils import print_section, success, error, info, warning

YEARS_BACK = 120
WORDLIST_PATH = "/tmp/pdf_dates_wordlist.txt"


class PdfUnlocker:
    def __init__(self, pdf_path: str, output_path: str = None, years: int = YEARS_BACK):
        self.pdf_path = pdf_path
        self.output_path = output_path or self._default_output(pdf_path)
        self.years = years

    @staticmethod
    def _default_output(pdf_path: str) -> str:
        base, ext = os.path.splitext(pdf_path)
        return f"{base}_unlocked{ext}"

    def _check_dependencies(self) -> bool:
        missing = []
        for tool in ("pdfcrack", "qpdf"):
            if subprocess.run(["which", tool], capture_output=True).returncode != 0:
                missing.append(tool)
        if missing:
            error(f"Missing system tools: {', '.join(missing)}")
            warning(f"Install with: sudo apt install {' '.join(missing)}")
            return False
        return True

    def _build_wordlist(self) -> str:
        if os.path.exists(WORDLIST_PATH):
            info(f"Using existing wordlist: {WORDLIST_PATH}")
            return WORDLIST_PATH

        info(f"Generating {self.years}-year date wordlist (DDMMYYYY)...")
        end_date = date.today()
        start_date = end_date - timedelta(days=self.years * 365 + 30)

        with open(WORDLIST_PATH, "w") as f:
            cur = end_date
            while cur >= start_date:
                f.write(cur.strftime("%d%m%Y") + "\n")
                cur -= timedelta(days=1)

        count = sum(1 for _ in open(WORDLIST_PATH))
        success(f"{count:,} date passwords generated.")
        return WORDLIST_PATH

    def _crack_pdf(self, wordlist: str) -> str | None:
        info(f"Running pdfcrack on '{os.path.basename(self.pdf_path)}'...")
        result = subprocess.run(
            ["pdfcrack", "-f", self.pdf_path, "-w", wordlist],
            capture_output=True, text=True
        )
        match = re.search(r"found user-password:\s*'([^']*)'", result.stdout)
        return match.group(1) if match else None

    def _decrypt_pdf(self, password: str) -> bool:
        result = subprocess.run(
            ["qpdf", f"--password={password}", "--decrypt",
             self.pdf_path, self.output_path],
            capture_output=True, text=True
        )
        return result.returncode == 0

    def run(self):
        print_section(f"PDF Unlocker → {os.path.basename(self.pdf_path)}")

        if not os.path.exists(self.pdf_path):
            error(f"File not found: {self.pdf_path}")
            return

        if not self._check_dependencies():
            return

        wordlist = self._build_wordlist()
        password = self._crack_pdf(wordlist)

        if password is None:
            warning("Password not found. Not a DDMMYYYY date in the last 120 years.")
            return

        success(f"Password found: {password}")
        info(f"Decrypting to: {self.output_path}")

        if self._decrypt_pdf(password):
            success(f"Unlocked PDF saved: {self.output_path}")
        else:
            error(f"Password found ('{password}') but decryption failed.")
