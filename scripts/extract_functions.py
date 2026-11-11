#!/usr/bin/env python3
"""Step 03 - Extract C/C++ functions from AI-attributed commits.

For every AI-attributed commit: fetch the changed files, keep C/C++ files,
take the ADDED lines of each patch, parse them with tree-sitter and keep
functions with 5-150 lines. One row per function is appended to
data/interim/VD_dataset.csv.

Usage:
    export GITHUB_TOKEN=ghp_xxx
    python scripts/extract_functions.py

Resumable: processed commit SHAs are tracked in data/interim/processed_commits.txt.
"""
import csv
import json
import os
import time
from datetime import datetime, timezone

import tree_sitter_c
import tree_sitter_cpp
from github import Auth, Github, RateLimitExceededException, UnknownObjectException
from tree_sitter import Language, Parser

from common import (AI_COMMITS, COLUMNS, FUNCTIONS_CSV, INTERIM_DIR, LABEL_COLUMNS,
                    compute_file_hash, make_unique_id)

MIN_FUNC_LINES = 5     # skip tiny functions
MAX_FUNC_LINES = 150   # skip huge functions
CPP_EXT = (".cpp", ".cc", ".cxx", ".c++", ".hpp")
PROCESSED = INTERIM_DIR / "processed_commits.txt"

c_parser = Parser(Language(tree_sitter_c.language()))
cpp_parser = Parser(Language(tree_sitter_cpp.language()))


def get_added_code(patch: str) -> str:
    """Extract only added lines from a git diff patch."""
    return "\n".join(l[1:] for l in patch.split("\n")
                     if l.startswith("+") and not l.startswith("+++"))


def extract_functions(code: str, language: str) -> list:
    """Parse C/C++ code with a tree-sitter AST and return function dicts.

    Note: line numbers are relative to the concatenated added-code fragment.
    """
    parser = c_parser if language == "c" else cpp_parser
    try:
        tree = parser.parse(bytes(code, "utf-8"))
    except Exception:
        return []

    functions = []

    def walk(node):
        if node.type == "function_definition":
            body = code[node.start_byte:node.end_byte]
            n_lines = len(body.strip().split("\n"))
            if MIN_FUNC_LINES <= n_lines <= MAX_FUNC_LINES:
                functions.append({
                    "function_body": body.strip(),
                    "function_start_line": node.start_point[0] + 1,
                    "function_end_line": node.end_point[0] + 1,
                    "function_lines": n_lines,
                })
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return functions


def append_record(record: dict) -> None:
    for col in LABEL_COLUMNS:
        record.setdefault(col, None)
    with open(FUNCTIONS_CSV, "a", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=COLUMNS).writerow(record)


def main() -> None:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise SystemExit("Set the GITHUB_TOKEN environment variable.")
    g = Github(auth=Auth.Token(token), per_page=100)

    if not FUNCTIONS_CSV.exists():
        with open(FUNCTIONS_CSV, "w", newline="", encoding="utf-8") as f:
            csv.DictWriter(f, fieldnames=COLUMNS).writeheader()

    done = set(PROCESSED.read_text().split()) if PROCESSED.exists() else set()
    repo_cache, n_funcs, n_errors = {}, 0, 0

    with open(AI_COMMITS, encoding="utf-8") as f:
        ai_commits = [json.loads(l) for l in f]
    print(f"{len(ai_commits):,} AI commits; {len(done):,} already processed")

    for i, rec in enumerate(ai_commits, 1):
        sha = rec["commit_id"]
        if sha in done:
            continue
        name = rec["project_name"]
        while True:
            try:
                if name not in repo_cache:
                    repo_cache[name] = g.get_repo(name)
                repo = repo_cache[name]
                commit = repo.get_commit(sha)

                for file in commit.files:
                    fname = file.filename.lower()
                    if fname.endswith(".c"):
                        lang = "c"
                    elif fname.endswith(CPP_EXT):
                        lang = "cpp"
                    else:
                        continue
                    if not file.patch:
                        continue
                    added = get_added_code(file.patch)
                    if len(added.strip()) < 50:
                        continue
                    functions = extract_functions(added, lang)
                    if not functions:
                        continue

                    try:
                        content = repo.get_contents(file.filename, ref=sha) \
                            .decoded_content.decode("utf-8", errors="replace")
                        fhash = compute_file_hash(content)
                    except Exception:
                        fhash = compute_file_hash(added)

                    for func in functions:
                        append_record({
                            "unique_id": make_unique_id(name, sha, file.filename,
                                                        func["function_start_line"]),
                            "project_name": name,
                            "project_url": rec["project_url"],
                            "commit_id": sha,
                            "commit_url": f"{rec['project_url']}/commit/{sha}",
                            "commit_message": rec["commit_message"][:1000],
                            "commit_date": rec["commit_date"],
                            "file_name": file.filename,
                            "file_hash": fhash,
                            "language": lang,
                            **func,
                            "ai_tool": rec["ai_tool"],
                            "signal_strength": rec["signal_strength"],
                            "signal_type": rec["signal_type"],
                            "repo_stars": rec["repo_stars"],
                            "repo_forks": rec["repo_forks"],
                            "repo_primary_language": rec["repo_primary_language"],
                            "mined_at": datetime.now(timezone.utc).isoformat(),
                        })
                        n_funcs += 1
                break
            except RateLimitExceededException:
                reset = g.get_rate_limit().resources.core.reset
                wait = int((reset.replace(tzinfo=None) - datetime.utcnow()).total_seconds()) + 10
                print(f"  Rate limit - sleeping {max(wait, 10)} s")
                time.sleep(max(wait, 10))
            except UnknownObjectException:
                break
            except Exception:
                n_errors += 1
                break

        with open(PROCESSED, "a") as pf:
            pf.write(sha + "\n")
        time.sleep(0.05)
        if i % 50 == 0:
            print(f"  [{i}/{len(ai_commits)}] functions so far: {n_funcs:,} (errors {n_errors})")

    print(f"\nDone. Functions extracted this run: {n_funcs:,}; errors skipped: {n_errors}")
    print(f"Output: {FUNCTIONS_CSV}")


if __name__ == "__main__":
    main()
