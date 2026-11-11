#!/usr/bin/env python3
"""Step 07 - Majority-vote ensemble of Semgrep, Flawfinder and pattern matching.

Voting (3 analysers):
  >= 2 votes -> vulnerable (vuln_label = 1)
  0 votes    -> safe       (vuln_label = 0)
  1 vote     -> uncertain  (vuln_label = NaN)

CWE for vulnerable functions: first available of Semgrep > Flawfinder >
pattern matching, else "CWE-Unknown".

Usage: python scripts/ensemble_labels.py
"""
import pandas as pd

from common import load_labeled, save_labeled

VOTE_COLS = ["tool_semgrep", "tool_flawfinder", "pattern_match"]
CWE_PRIORITY = ["cwe_semgrep_raw", "cwe_flawfinder_raw", "cwe_pattern-match_raw"]


def ensemble(row):
    votes = valid = 0
    for col in VOTE_COLS:
        v = row.get(col)
        if pd.notna(v):
            try:
                value = int(float(v))
            except (ValueError, TypeError):
                continue
            if value in (0, 1):
                valid += 1
                votes += value
    if valid == 0:
        return None, "uncertain"
    if votes >= valid // 2 + 1:
        return 1, "vulnerable"
    if votes == 0:
        return 0, "safe"
    return None, "uncertain"


def pick_cwe(row):
    if row.get("vuln_label") != 1:
        return None
    for col in CWE_PRIORITY:
        v = row.get(col)
        if pd.notna(v) and str(v).strip():
            return str(v).strip()
    return "CWE-Unknown"


def main() -> None:
    df = load_labeled()
    res = df.apply(ensemble, axis=1)
    df["vuln_label"] = [r[0] for r in res]
    df["ensemble_label"] = [r[1] for r in res]
    df["cwe_id"] = df.apply(pick_cwe, axis=1)

    print(f"Rows: {len(df):,}   unique IDs: {df['unique_id'].nunique():,}")
    print("\nEnsemble label distribution:")
    print(df["ensemble_label"].value_counts(dropna=False))
    print("\nTool breakdown:")
    for col in VOTE_COLS:
        print(f"  {col:<18} {df[col].sum():,}")
    print("\nTop CWEs (ensemble-vulnerable):")
    print(df.loc[df["vuln_label"] == 1, "cwe_id"].value_counts().head(10))
    save_labeled(df)


if __name__ == "__main__":
    main()
