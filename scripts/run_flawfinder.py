#!/usr/bin/env python3
"""Step 05 - Run the real Flawfinder (analyser 2 of 3).

Calls the official `flawfinder` CLI with its native CSV report (`--csv`) on
the per-function files from step 04 and reads the results with a proper CSV
parser. CWE IDs come straight from Flawfinder's own `CWEs` column - no
hand-written function->CWE table is used.

For each function the highest-risk hit is kept (ties: first hit).

Adds columns: tool_flawfinder (0/1), cwe_flawfinder_raw, flawfinder_risk,
              flawfinder_hit, flawfinder_cwes_all.
Raw report: data/work/flawfinder_raw.csv; version in data/labeled/tool_versions.json.

Requires: pip install flawfinder
Usage:    python scripts/run_flawfinder.py [--minlevel 1]
"""
import argparse
import csv
import json
import re
import shutil
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from common import LABELED_DIR, WORK_DIR, load_labeled, save_labeled, write_function_files

VERSIONS_FILE = LABELED_DIR / "tool_versions.json"
RAW_CSV = WORK_DIR / "flawfinder_raw.csv"


def record_version(name: str, info: dict) -> None:
    data = json.loads(VERSIONS_FILE.read_text()) if VERSIONS_FILE.exists() else {}
    data[name] = info
    VERSIONS_FILE.write_text(json.dumps(data, indent=2))


def run_flawfinder(folders: list, minlevel: int) -> None:
    cmd = ["flawfinder", "--csv", "--quiet", "--minlevel", str(minlevel),
           *[str(f) for f in folders]]
    print("Running:", " ".join(cmd))
    with open(RAW_CSV, "w", encoding="utf-8", newline="") as fh:
        proc = subprocess.run(cmd, stdout=fh, stderr=subprocess.PIPE,
                              text=True, timeout=6 * 3600)
    if proc.returncode > 1:        # 1 can mean "hits found" with --error-level
        raise SystemExit(f"flawfinder failed (exit {proc.returncode}):\n{proc.stderr[-1500:]}")


def parse_report(results: dict) -> int:
    n_rows = 0
    with open(RAW_CSV, encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames or "File" not in reader.fieldnames:
            raise SystemExit(f"Unexpected Flawfinder output in {RAW_CSV}; "
                             f"header = {reader.fieldnames}")
        for row in reader:
            n_rows += 1
            try:
                risk = int(row.get("Level") or 0)
            except ValueError:
                continue
            if risk < 1:
                continue
            uid = Path(row["File"]).stem                    # file stem == unique_id
            cwes = re.findall(r"CWE-\d+", (row.get("CWEs") or "").upper())
            cur = results.get(uid)
            if cur is None:
                results[uid] = {"risk": risk, "cwes_all": list(cwes),
                                "cwe": cwes[0] if cwes else None,
                                "hit": row.get("Name") or row.get("Category")}
                continue
            for c in cwes:
                if c not in cur["cwes_all"]:
                    cur["cwes_all"].append(c)
            if risk > cur["risk"]:
                cur.update(risk=risk, cwe=cwes[0] if cwes else cur["cwe"],
                           hit=row.get("Name") or row.get("Category"))
    return n_rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--minlevel", type=int, default=1, help="minimum risk level (0-5)")
    args = ap.parse_args()

    if shutil.which("flawfinder") is None:
        raise SystemExit("flawfinder not found. Install with: pip install flawfinder")
    version = subprocess.run(["flawfinder", "--version"], capture_output=True,
                             text=True).stdout.strip()
    print(f"Flawfinder {version}")

    df = load_labeled()
    c_dir, cpp_dir = write_function_files(df)               # idempotent
    folders = [d for d in (c_dir, cpp_dir) if any(d.iterdir())]

    run_flawfinder(folders, args.minlevel)
    results: dict = {}
    n_rows = parse_report(results)
    print(f"Report rows: {n_rows:,}   functions with >=1 hit: {len(results):,}")

    uid = df["unique_id"].astype(str)
    df["tool_flawfinder"] = uid.map(lambda u: 1 if u in results else 0)
    df["cwe_flawfinder_raw"] = uid.map(lambda u: results.get(u, {}).get("cwe"))
    df["flawfinder_risk"] = uid.map(lambda u: results.get(u, {}).get("risk", 0))
    df["flawfinder_hit"] = uid.map(lambda u: results.get(u, {}).get("hit"))
    df["flawfinder_cwes_all"] = uid.map(
        lambda u: ";".join(results[u]["cwes_all"]) if u in results and results[u]["cwes_all"] else None)

    print(f"Flawfinder vulnerable: {df['tool_flawfinder'].sum():,}")
    print(f"Flawfinder safe:       {(df['tool_flawfinder'] == 0).sum():,}")
    print("Risk levels:", dict(Counter(v["risk"] for v in results.values())))
    print("Top CWEs:   ", Counter(v["cwe"] for v in results.values()).most_common(10))
    print("Top hits:   ", Counter(v["hit"] for v in results.values()).most_common(10))

    record_version("flawfinder", {"version": version, "minlevel": args.minlevel,
                                  "run_at": datetime.now(timezone.utc).isoformat()})
    save_labeled(df)


if __name__ == "__main__":
    main()
