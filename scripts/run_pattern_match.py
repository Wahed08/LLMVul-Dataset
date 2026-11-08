#!/usr/bin/env python3
"""Step 06 - SARD-style pattern matching (analyser 3 of 3).

Regex patterns derived from the NIST SARD dangerous-function list, the CWE Top-25
C/C++ patterns and the Flawfinder/ITS4 function-risk taxonomy. Works on
isolated function fragments and has no timeouts. For each function the
highest-risk matching pattern determines the CWE.

Adds columns:

  tool_pattern_match, cwe_pattern_match_raw 

Usage: python scripts/pattern_match.py
"""
import re
from collections import Counter

from common import load_labeled, save_labeled

# (regex, CWE, risk 1-5)
PATTERNS = [
    # CWE-120: Buffer copy without size check
    (r'\bstrcpy\s*\(', 'CWE-120', 3),
    (r'\bstrcat\s*\(', 'CWE-120', 3),
    (r'\bgets\s*\(', 'CWE-120', 5),
    (r'\bscanf\s*\(\s*"[^"]*%s', 'CWE-120', 3),
    (r'\bsprintf\s*\(', 'CWE-134', 3),
    (r'\bvsprintf\s*\(', 'CWE-134', 3),
    (r'\bvsnprintf\s*\(', 'CWE-134', 2),
    (r'\bmemcpy\s*\(', 'CWE-120', 2),
    (r'\bstrncpy\s*\(', 'CWE-120', 2),
    (r'\bstrncat\s*\(', 'CWE-120', 2),
    (r'\bmemmove\s*\(', 'CWE-120', 2),
    (r'\bbcopy\s*\(', 'CWE-120', 2),
    # CWE-78: OS command injection
    (r'\bsystem\s*\(', 'CWE-78', 4),
    (r'\bpopen\s*\(', 'CWE-78', 4),
    (r'\bexecl\s*\(', 'CWE-78', 4),
    (r'\bexeclp\s*\(', 'CWE-78', 4),
    (r'\bexecle\s*\(', 'CWE-78', 4),
    (r'\bexecv\s*\(', 'CWE-78', 4),
    (r'\bexecvp\s*\(', 'CWE-78', 4),
    (r'\bexecve\s*\(', 'CWE-78', 4),
    (r'\bshellcode\b', 'CWE-78', 5),
    # CWE-134: Format string
    (r'\bprintf\s*\(\s*(?!")[^\)]{1,30}\)', 'CWE-134', 3),
    (r'\bfprintf\s*\(\s*\w+\s*,\s*(?!")', 'CWE-134', 3),
    (r'\bsyslog\s*\(', 'CWE-134', 3),
    (r'\berr\s*\(', 'CWE-134', 2),
    (r'\berrx\s*\(', 'CWE-134', 2),
    # CWE-476: NULL pointer dereference
    (r'=\s*malloc\s*\([^)]+\)[^;]*;\s*(?!\s*(if|NULL))', 'CWE-476', 3),
    (r'=\s*calloc\s*\([^)]+\)[^;]*;\s*(?!\s*(if|NULL))', 'CWE-476', 3),
    (r'=\s*realloc\s*\([^)]+\)[^;]*;\s*(?!\s*(if|NULL))', 'CWE-476', 3),
    # CWE-415: Double free
    (r'free\s*\(\s*(\w+)\s*\)[^}]*free\s*\(\s*\1\s*\)', 'CWE-415', 5),
    # CWE-416: Use after free
    (r'free\s*\(\s*(\w+)\s*\)[^}]*\b\1\b', 'CWE-416', 4),
    # CWE-190: Integer overflow
    (r'malloc\s*\(\s*\w+\s*\*\s*\w+', 'CWE-190', 3),
    (r'malloc\s*\(\s*sizeof[^)]+\*', 'CWE-190', 3),
    (r'\batoi\s*\(', 'CWE-190', 2),
    (r'\batol\s*\(', 'CWE-190', 2),
    (r'\batoll\s*\(', 'CWE-190', 2),
    # CWE-338: Weak random
    (r'\brand\s*\(\)', 'CWE-338', 2),
    (r'\bsrand\s*\(', 'CWE-338', 2),
    (r'\bdrand48\s*\(', 'CWE-338', 2),
    (r'\brand48\s*\(', 'CWE-338', 2),
    # CWE-22: Path traversal
    (r'\bfopen\s*\(\s*\w', 'CWE-22', 2),
    (r'\bopen\s*\(\s*\w', 'CWE-22', 2),
    (r'\bcreat\s*\(\s*\w', 'CWE-22', 2),
    (r'\btruncate\s*\(\s*\w', 'CWE-22', 2),
    # CWE-401: Memory leak
    (r'\brealloc\s*\(\s*\w+\s*,', 'CWE-401', 2),
    # CWE-377: Insecure temp file
    (r'\btmpnam\s*\(', 'CWE-377', 4),
    (r'\btempnam\s*\(', 'CWE-377', 4),
    (r'\bmktemp\s*\(', 'CWE-377', 4),
    # CWE-807: Reliance on untrusted input
    (r'\bgetenv\s*\(', 'CWE-807', 2),
    # CWE-369: Divide by zero
    (r'/\s*\w+\s*;', 'CWE-369', 1),
    # CWE-362: Race condition
    (r'\baccess\s*\(\s*\w', 'CWE-362', 2),
    (r'\bstat\s*\(\s*\w', 'CWE-362', 1),
    # CWE-789: Excessive allocation
    (r'alloca\s*\(', 'CWE-789', 3),
    (r'malloc\s*\(\s*\d{5,}', 'CWE-789', 3),
]

# Highest risk first (stable sort: ties keep the order above)
PATTERNS.sort(key=lambda x: x[2], reverse=True)


def main() -> None:
    df = load_labeled()
    print(f"Functions to scan: {len(df):,}   Patterns: {len(PATTERNS)}")

    results: dict = {}
    for _, row in df.iterrows():
        code = str(row.get("function_body", ""))
        uid = str(row.get("unique_id", ""))
        if len(code.strip()) < 10:
            continue
        max_risk, best_cwe = 0, None
        for pattern, cwe, risk in PATTERNS:
            try:
                if re.search(pattern, code, re.MULTILINE | re.DOTALL) and risk > max_risk:
                    max_risk, best_cwe = risk, cwe
            except re.error:
                continue
        if best_cwe and uid not in results:
            results[uid] = {"vulnerable": True, "cwe": best_cwe,
                            "risk_score": max_risk, "rule": "nist_sard_pattern"}

    print(f"Pattern matching vulnerable: {len(results):,}")
    print(f"Pattern matching safe:       {len(df) - len(results):,}")
    for cwe, n in Counter(v["cwe"] for v in results.values()).most_common(10):
        print(f"  {n:5,}  {cwe}")

    uid = df["unique_id"].astype(str)
    flag = uid.map(lambda u: 1 if u in results else 0)
    cwe = uid.map(lambda u: results.get(u, {}).get("cwe"))
    df["tool_pattern_match"], df["cwe_pattern_match_raw"] = flag, cwe   # clearer aliases
    save_labeled(df)


if __name__ == "__main__":
    main()
