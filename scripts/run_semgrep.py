#!/usr/bin/env python3
"""Step 04 - Prepare the labeling table and run the real Semgrep (analyser 1 of 3).

1. Loads data/interim/VD_dataset.csv, drops duplicate unique_id rows and adds
   the empty label columns -> data/labeled/vd_labeled.csv
2. Writes every function to its own .c/.cpp file (data/work/{c,cpp}).
3. Runs the official `semgrep` CLI with Semgrep-registry rulesets
   (downloaded online from semgrep.dev at scan time). No custom rules.
   Default rulesets: p/c, p/security-audit, p/cwe-top-25.

Adds columns: tool_semgrep (0/1), cwe_semgrep_raw, semgrep_rule,
              semgrep_severity, semgrep_cwes_all.
Raw Semgrep JSON is kept in data/work/semgrep_raw_{c,cpp}.json and the tool /
ruleset versions in data/labeled/tool_versions.json (for the paper).

Requires: pip install semgrep   + internet access (registry rulesets)
          (optional) `semgrep login` / SEMGREP_APP_TOKEN for Pro rules; not needed.

Usage:
    python scripts/run_semgrep.py
    python scripts/run_semgrep.py --config p/c --config p/owasp-top-ten
"""
import argparse
import json
import re
import shutil
import subprocess
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from common import (FUNCTIONS_CSV, LABEL_COLUMNS, LABELED_DIR, WORK_DIR,
                    save_labeled, write_function_files)

DEFAULT_CONFIGS = ["p/c", "p/security-audit", "p/cwe-top-25"]
SEVERITY_RANK = {"ERROR": 3, "WARNING": 2, "INFO": 1}
VERSIONS_FILE = LABELED_DIR / "tool_versions.json"


def record_version(name: str, info: dict) -> None:
    data = json.loads(VERSIONS_FILE.read_text()) if VERSIONS_FILE.exists() else {}
    data[name] = info
    VERSIONS_FILE.write_text(json.dumps(data, indent=2))


def parse_cwes(meta_cwe) -> list:
    """Semgrep metadata 'cwe' is a string or a list like 'CWE-120: Buffer Copy ...'."""
    if not meta_cwe:
        return []
    items = meta_cwe if isinstance(meta_cwe, list) else [meta_cwe]
    out = []
    for it in items:
        out += re.findall(r"CWE-\d+", str(it).upper())
    return out


def check_registry_access(configs: list) -> None:
    """Fail fast (instead of hanging) if registry rulesets are needed but offline."""
    if not any(c.startswith(("p/", "r/", "auto")) or c.startswith("https://") for c in configs):
        return
    try:
        urllib.request.urlopen("https://semgrep.dev", timeout=15)
    except Exception as e:
        raise SystemExit(f"Cannot reach https://semgrep.dev ({e}).\n"
                         "Registry rulesets (p/c, ...) are downloaded online at scan time. "
                         "Check your internet/proxy, or pass a local rule file with --config.")


def run_semgrep(folder: Path, tag: str, configs: list, jobs: int,
                timeout: int, results: dict) -> None:
    n_files = len(list(folder.glob("*")))
    if n_files == 0:
        return
    out_json = WORK_DIR / f"semgrep_raw_{tag}.json"
    cmd = ["semgrep", "scan"]
    for c in configs:
        cmd += ["--config", c]
    cmd += ["--json", "--quiet", "--no-git-ignore",   # data/ may be git-ignored
            "--timeout", str(timeout), "--jobs", str(jobs),
            "--output", str(out_json), str(folder)]
    print(f"\nScanning {n_files} {tag} files:\n  {' '.join(cmd)}")
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=6 * 3600)

    if not out_json.exists() or out_json.stat().st_size == 0:
        raise SystemExit(f"Semgrep produced no output (exit {proc.returncode}).\n"
                         f"{proc.stderr[-1500:]}\n"
                         "Check internet access to semgrep.dev and the --config names.")
    data = json.loads(out_json.read_text())
    findings = data.get("results", [])
    errors = data.get("errors", [])
    print(f"  Raw findings: {len(findings)}   scan errors: {len(errors)}")
    for e in errors[:3]:
        print(f"  error: {str(e.get('message', e))[:120]}")

    for fd in findings:
        uid = Path(fd.get("path", "")).stem
        extra = fd.get("extra", {})
        sev = extra.get("severity", "INFO")
        cwes = parse_cwes(extra.get("metadata", {}).get("cwe"))
        cur = results.get(uid)
        if cur is None:
            results[uid] = {"cwes_all": list(cwes), "cwe": cwes[0] if cwes else None,
                            "rule": fd.get("check_id", ""), "severity": sev}
            continue
        for c in cwes:                                   # accumulate all CWEs seen
            if c not in cur["cwes_all"]:
                cur["cwes_all"].append(c)
        # keep the highest-severity finding as the representative one
        if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(cur["severity"], 0):
            cur.update(rule=fd.get("check_id", ""), severity=sev,
                       cwe=cwes[0] if cwes else cur["cwe"])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", action="append",
                    help="Semgrep ruleset (registry pack like p/c, or a local rule file); "
                         f"repeatable. Default: {DEFAULT_CONFIGS}")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=10, help="per-rule, per-file seconds")
    args = ap.parse_args()
    configs = args.config or DEFAULT_CONFIGS

    if shutil.which("semgrep") is None:
        raise SystemExit("semgrep not found. Install with: pip install semgrep")
    version = subprocess.run(["semgrep", "--version"], capture_output=True,
                             text=True).stdout.strip().splitlines()[-1]
    print(f"Semgrep {version}; rulesets: {configs}")
    check_registry_access(configs)

    # --- 1. build labeling table -------------------------------------------
    df = pd.read_csv(FUNCTIONS_CSV)
    print(f"Loaded {len(df):,} rows from {FUNCTIONS_CSV}")
    df = df.drop_duplicates(subset="unique_id", keep="first").copy()
    print(f"Rows after removing duplicates: {len(df):,}")
    for col in LABEL_COLUMNS:
        if col not in df.columns:
            df[col] = None

    # --- 2. write function files -------------------------------------------
    c_dir, cpp_dir = write_function_files(df)

    # --- 3. run semgrep ----------------------------------------------------
    results: dict = {}
    run_semgrep(c_dir, "c", configs, args.jobs, args.timeout, results)
    run_semgrep(cpp_dir, "cpp", configs, args.jobs, args.timeout, results)

    uid = df["unique_id"].astype(str)
    df["tool_semgrep"] = uid.map(lambda u: 1 if u in results else 0)
    df["cwe_semgrep_raw"] = uid.map(lambda u: results.get(u, {}).get("cwe"))
    df["semgrep_rule"] = uid.map(lambda u: results.get(u, {}).get("rule"))
    df["semgrep_severity"] = uid.map(lambda u: results.get(u, {}).get("severity"))
    df["semgrep_cwes_all"] = uid.map(
        lambda u: ";".join(results[u]["cwes_all"]) if u in results and results[u]["cwes_all"] else None)

    print(f"\nSemgrep vulnerable: {df['tool_semgrep'].sum():,}")
    print(f"Semgrep safe:       {(df['tool_semgrep'] == 0).sum():,}")
    print(f"  flagged without a CWE tag: "
          f"{int(((df['tool_semgrep'] == 1) & df['cwe_semgrep_raw'].isna()).sum()):,}")
    print(df["cwe_semgrep_raw"].value_counts().head(10))

    record_version("semgrep", {"version": version, "configs": configs,
                               "run_at": datetime.now(timezone.utc).isoformat()})
    save_labeled(df)


if __name__ == "__main__":
    main()
