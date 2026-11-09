"""Shared paths, schema and helpers for the LLMVul reproducibility pipeline."""
import hashlib
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
RAW_DIR = DATA / "raw"
INTERIM_DIR = DATA / "interim"
LABELED_DIR = DATA / "labeled"
FINAL_DIR = DATA / "final"
WORK_DIR = DATA / "work"          # one .c / .cpp file per function (scanner input)
RULES_DIR = ROOT / "rules"

RAW_COMMITS = RAW_DIR / "commits.jsonl"            # step 01
AI_COMMITS = INTERIM_DIR / "ai_commits.jsonl"      # step 02
FUNCTIONS_CSV = INTERIM_DIR / "VD_dataset.csv"     # step 03
LABELED_CSV = LABELED_DIR / "vd_labeled.csv"       # steps 04-07
FINAL_CSV = FINAL_DIR / "LLMVul_v1.csv"            # step 08

for _d in (RAW_DIR, INTERIM_DIR, LABELED_DIR, FINAL_DIR, WORK_DIR):
    _d.mkdir(parents=True, exist_ok=True)

COLUMNS = [
    # Identity
    "unique_id", "project_name", "project_url", "commit_id", "commit_url",
    "commit_message", "commit_date", "file_name", "file_hash", "language",
    # Function
    "function_body", "function_start_line", "function_end_line", "function_lines",
    # Attribution
    "ai_tool", "signal_strength", "signal_type",
    # Repo metadata
    "repo_stars", "repo_forks", "repo_primary_language", "mined_at",
    # Vulnerability labels
    "vuln_label", "ensemble_label", "pattern_match", "tool_semgrep",
    "tool_flawfinder", "cwe_id", "cwe_description", "cwe_url"
]

LABEL_COLUMNS = [
    "vuln_label", "ensemble_label", "pattern_match", "tool_semgrep",
    "tool_flawfinder", "cwe_id", "cwe_description", "cwe_url"
]


def make_unique_id(repo: str, commit_sha: str, filename: str, start_line: int) -> str:
    raw = f"{repo}_{commit_sha}_{filename}_{start_line}"
    return "ID_" + hashlib.sha256(raw.encode()).hexdigest()[:16].upper()


def compute_file_hash(content: str) -> str:
    """SHA-256 of file content at commit time."""
    return "sha256:" + hashlib.sha256(content.encode()).hexdigest()


def load_labeled() -> pd.DataFrame:
    if not LABELED_CSV.exists():
        raise SystemExit(f"{LABELED_CSV} not found - run the previous step first.")
    return pd.read_csv(LABELED_CSV)


def save_labeled(df: pd.DataFrame) -> None:
    df.to_csv(LABELED_CSV, index=False)
    print(f"Checkpoint saved: {LABELED_CSV}")


def write_function_files(df: pd.DataFrame):
    """Write each function body to WORK_DIR/{c,cpp}/<unique_id>.{c,cpp}.

    Static analysers need files, not DataFrame rows. The file stem is the
    unique_id, which is how findings are mapped back to rows.
    Returns (c_dir, cpp_dir).
    """
    c_dir, cpp_dir = WORK_DIR / "c", WORK_DIR / "cpp"
    c_dir.mkdir(exist_ok=True)
    cpp_dir.mkdir(exist_ok=True)
    written = skipped = 0
    for idx, row in df.iterrows():
        code = str(row.get("function_body", ""))
        lang = str(row.get("language", "c"))
        uid = str(row.get("unique_id", f"func_{idx}"))
        if len(code.strip()) < 20:
            skipped += 1
            continue
        path = c_dir / f"{uid}.c" if lang == "c" else cpp_dir / f"{uid}.cpp"
        try:
            path.write_text(code, encoding="utf-8")
            written += 1
        except OSError:
            skipped += 1
    print(f"Function files written: {written} (skipped {skipped})")
    return c_dir, cpp_dir
