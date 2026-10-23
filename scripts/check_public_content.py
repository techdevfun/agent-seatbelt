#!/usr/bin/env python3
"""Public-content sweep (factory STANDING RULE 7).

Fails (exit 1) if any shipped file contains:
  (i)  Vietnamese diacritics — checked by codepoint ranges so this script
       itself stays pure ASCII and never trips its own gate; combining
       marks U+0300..U+036F are also flagged, because Vietnamese text is
       often stored in decomposed (NFD) form; or
  (ii) internal names that must never appear in public content. The names
       are assembled from fragments for the same reason: the checker must
       not contain the strings it checks for.

Excluded from the sweep: .git/, verification/work/ (raw run artefacts,
never shipped), __pycache__/ and *.pyc.

Usage: python3 scripts/check_public_content.py [root]
"""
import os
import re
import sys

# Vietnamese precomposed letters by codepoint range (Latin-1 Supplement
# tonal letters, Latin Extended-A/-B base letters, and the Latin Extended
# Additional block U+1E00..U+1EF9 where most Vietnamese forms live).
VN_RANGES = [
    (192, 195), (200, 202), (204, 205), (210, 213), (217, 218), (221, 221),
    (224, 227), (232, 234), (236, 237), (242, 245), (249, 250), (253, 253),
    (258, 259), (272, 273), (416, 417), (431, 432), (7840, 7929),
]


def is_vietnamese_char(ch):
    cp = ord(ch)
    if 0x300 <= cp <= 0x36F:  # combining diacritical marks
        return True
    return any(lo <= cp <= hi for lo, hi in VN_RANGES)


def _frag(*parts):
    return "".join(parts)


NAME_PATTERNS = {
    "internal-name-1": re.compile(r"\b" + _frag("N", "AB") + r"\b"),
    "internal-name-2": re.compile(r"\b" + _frag("S", "GH") + r"\b"),
    "internal-name-3": re.compile(r"\b" + _frag("Casc", "ade")),
    "internal-name-4": re.compile(_frag("e-tow", "er"), re.I),
    "internal-name-5": re.compile(_frag("etow", "er"), re.I),
    "internal-name-6": re.compile(_frag("ivi", r"\.asia"), re.I),
    "internal-name-7": re.compile(_frag("tran", "myphuc"), re.I),
    "internal-name-8": re.compile(_frag("S", "GH", " Asia")),
}

SKIP_DIRS = {".git", "__pycache__"}
SKIP_PATH_PARTS = {os.path.join("verification", "work")}


def iter_files(root):
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir in SKIP_PATH_PARTS:
            dirs[:] = []
            continue
        for fn in files:
            if fn.endswith(".pyc"):
                continue
            yield os.path.join(dirpath, fn)


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    hits = []
    for path in iter_files(root):
        rel = os.path.relpath(path, root)
        try:
            text = open(path, "rb").read().decode("utf-8")
        except (UnicodeDecodeError, ValueError, OSError):
            continue  # binary files carry no public text
        for lineno, line in enumerate(text.splitlines(), 1):
            if any(is_vietnamese_char(c) for c in line):
                hits.append((rel, lineno, "vietnamese-diacritic",
                             line.strip()[:120]))
            for label, pat in NAME_PATTERNS.items():
                if pat.search(line):
                    hits.append((rel, lineno, label, line.strip()[:120]))
    if hits:
        print(f"PUBLIC-CONTENT SWEEP FAILED: {len(hits)} hit(s)")
        for rel, lineno, label, excerpt in hits:
            print(f"  {rel}:{lineno} [{label}] {excerpt}")
        return 1
    print("public-content sweep: clean (0 Vietnamese-diacritic lines, "
          "0 internal names)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
