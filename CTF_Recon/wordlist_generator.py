"""
Wordlist Generator Module
Generates targeted wordlists based on names and year ranges.
"""

import os
from CTF_Recon.utils import print_section, success, error, info, warning

SPECIALS = ['@', '#', '$']

def build_years(year_from, year_to):
    return [str(y) for y in range(year_from, year_to + 1)]

def build_ddmm():
    return [f"{d:02d}{m:02d}" for d in range(1, 32) for m in range(1, 13)]

def build_mmdd():
    return [f"{m:02d}{d:02d}" for m in range(1, 13) for d in range(1, 32)]

def build_dddd():
    return [f"{d1:02d}{d2:02d}" for d1 in range(1, 32) for d2 in range(1, 32)]

def build_mmmm():
    return [f"{m1:02d}{m2:02d}" for m1 in range(1, 13) for m2 in range(1, 13)]

def date_patterns(name, cap, tokens):
    """
    For each token generates 8 variants:
      name+token, Name+token
      name+@+token, Name+@+token
      name+token+@, Name+token+@
    """
    entries = []
    for t in tokens:
        entries.append(name + t)
        entries.append(cap  + t)
        for sp in SPECIALS:
            entries.append(name + sp + t)
            entries.append(cap  + sp + t)
            entries.append(name + t  + sp)
            entries.append(cap  + t  + sp)
    return entries

def brute_patterns(name, cap):
    """4-digit brute force 0000-9999 with specials."""
    entries = []
    for sp in SPECIALS:
        for i in range(10000):
            n = f"{i:04d}"
            entries.append(name + sp + n)
            entries.append(cap  + sp + n)
    for i in range(10000):
        entries.append(name + f"{i:04d}")
    for sp in SPECIALS:
        for i in range(10000):
            entries.append(name + f"{i:04d}" + sp)
    return entries

class WordlistGenerator:
    def __init__(self, names: list[str], year_from: int = 1980, year_to: int = 2010, include_brute: bool = True, output_path: str = None):
        self.names = [n.lower() for n in names if n]
        self.year_from = year_from
        self.year_to = year_to
        self.include_brute = include_brute
        self.output_path = output_path or self._default_output()

    def _default_output(self) -> str:
        names_str = '_'.join(self.names)
        return f"{names_str}_wordlist.txt" if names_str else "wordlist.txt"

    def generate_words(self) -> list[str]:
        seen = set()
        result = []

        def add(entries):
            for w in entries:
                if w not in seen:
                    seen.add(w)
                    result.append(w)

        years = build_years(self.year_from, self.year_to)
        ddmm  = build_ddmm()
        mmdd  = build_mmdd()
        dddd  = build_dddd()
        mmmm  = build_mmmm()

        for name in self.names:
            cap = name.capitalize()
            add(date_patterns(name, cap, years))
            add(date_patterns(name, cap, ddmm))
            add(date_patterns(name, cap, mmdd))
            add(date_patterns(name, cap, dddd))
            add(date_patterns(name, cap, mmmm))
            if self.include_brute:
                add(brute_patterns(name, cap))

        return result

    def validate_names(self) -> list[str]:
        errors = []
        for name in self.names:
            if not name.isalpha():
                errors.append(f"'{name}' must be letters only (a-z)")
        return errors

    def run(self):
        print_section("Wordlist Generator")
        
        if not self.names:
            error("At least one name is required.")
            return

        errs = self.validate_names()
        if errs:
            for e in errs:
                error(e)
            return

        if self.year_from > self.year_to:
            error(f"Year FROM ({self.year_from}) must be <= Year TO ({self.year_to})")
            return

        info(f"Target Names : {', '.join(self.names)}")
        info(f"Year Range   : {self.year_from} -> {self.year_to}")
        info(f"Include Brute: {'Yes' if self.include_brute else 'No'}")
        info("Generating wordlist...")

        words = self.generate_words()
        
        size_kb = len(words) * 15 / 1024 # Approx size assumption
        
        info(f"Writing {len(words):,} entries to '{self.output_path}'...")
        try:
            with open(self.output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(words) + '\n')
            
            actual_size_kb = os.path.getsize(self.output_path) / 1024
            success(f"Wordlist saved successfully to {self.output_path} ({actual_size_kb:.1f} KB)")
        except Exception as e:
            error(f"Failed to write file: {e}")
