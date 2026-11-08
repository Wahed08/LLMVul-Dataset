#!/usr/bin/env python3
"""Step 01 - Mine GitHub repositories and collect raw commit metadata.

Usage:
    export GITHUB_TOKEN=ghp_xxx
    python scripts/mine_repositories.py [--max-repos 1200] [--max-commits 300]

The script is resumable: finished repos are recorded in data/raw/repos_done.txt.
"""
import argparse
import json
import os
import time
from datetime import datetime, timezone

from github import Auth, Github, RateLimitExceededException

from common import RAW_COMMITS, RAW_DIR

SEARCH_QUERIES = [
    "language:C stars:>200 pushed:>2022-06-01",
    "language:C++ stars:>200 pushed:>2022-06-01",
]
DONE_FILE = RAW_DIR / "repos_done.txt"


def wait_for_rate_limit(g: Github) -> None:
    reset = g.get_rate_limit().resources.core.reset
    wait = int((reset.replace(tzinfo=None) - datetime.utcnow()).total_seconds()) + 10
    print(f"  Rate limit hit - sleeping {max(wait, 10)} s ...")
    time.sleep(max(wait, 10))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-repos", type=int, default=1200)
    ap.add_argument("--max-commits", type=int, default=300, help="commits per repo")
    args = ap.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise SystemExit("Set the GITHUB_TOKEN environment variable.")
    g = Github(auth=Auth.Token(token), per_page=100)
    rate = g.get_rate_limit().resources.core
    print(f"Token valid. API remaining: {rate.remaining}/{rate.limit} (resets {rate.reset})")

    done = set(DONE_FILE.read_text().split()) if DONE_FILE.exists() else set()
    scanned = len(done)
    commits_total = 0

    for query in SEARCH_QUERIES:
        if scanned >= args.max_repos:
            break
        print(f"\nSearching: {query}")
        for repo in g.search_repositories(query=query, sort="stars", order="desc"):
            if scanned >= args.max_repos:
                break
            if repo.full_name in done:
                continue

            print(f"[{scanned + 1}/{args.max_repos}] {repo.full_name} stars={repo.stargazers_count}")
            while True:  # retry the repo after a rate-limit sleep
                rows = []
                try:
                    for i, commit in enumerate(repo.get_commits()):
                        if i >= args.max_commits:
                            break
                        rows.append({
                            "project_name": repo.full_name,
                            "project_url": repo.html_url,
                            "repo_stars": repo.stargazers_count,
                            "repo_forks": repo.forks_count,
                            "repo_primary_language": repo.language,
                            "commit_id": commit.sha,
                            "commit_message": commit.commit.message,
                            "commit_date": commit.commit.author.date.isoformat(),
                        })
                        time.sleep(0.02)
                    break
                except RateLimitExceededException:
                    wait_for_rate_limit(g)
                except Exception as e:  # repo empty / blocked / etc.
                    print(f"  repo error: {e}")
                    rows = []
                    break

            with open(RAW_COMMITS, "a", encoding="utf-8") as f:
                for r in rows:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
            with open(DONE_FILE, "a") as f:
                f.write(repo.full_name + "\n")
            done.add(repo.full_name)
            scanned += 1
            commits_total += len(rows)
            print(f"  -> {len(rows)} commits stored")

    print(f"\nDone. Repos scanned: {scanned}; commits stored this run: {commits_total}")
    print(f"Output: {RAW_COMMITS}  (finished {datetime.now(timezone.utc).isoformat()})")


if __name__ == "__main__":
    main()
