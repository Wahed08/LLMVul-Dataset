# LLMVul

**LLMVul: A Vulnerability-Labeled Dataset of LLM-Generated C/C++ Functions from Production Repositories**

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22668216.svg)](https://doi.org/10.5281/zenodo.22668216)
[![License: CC BY 4.0](https://img.shields.io/badge/License-CC_BY_4.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)
[![Functions](https://img.shields.io/badge/Functions-21%2C430-green.svg)]()
[![Vulnerable](https://img.shields.io/badge/Vulnerable-1%2C540-red.svg)]()

---

## Overview

LLMVul is the **first vulnerability-labeled 
dataset of C/C++ functions mined from real 
production GitHub repositories** where developers 
used AI coding assistants including GitHub Copilot, 
ChatGPT, Claude Code, Cursor, and Gemini.

Unlike all prior LLM security benchmarks 
(SecurityEval, CyberSecEval, SafeGenBench, CWEval), 
which generate code through controlled researcher 
prompts, LLMVul captures vulnerabilities that 
arise **incidentally** in authentic developer 
workflows — the threat model that CI/CD security 
pipelines must actually defend against.


✨ **Real production code** — mined from 1200 GitHub
repositories, not researcher-directed prompts

✨ **AI tool attribution** — records which assistant
generated the code (9 tools covered)

✨ **Validated labels** — three-tool ensemble with
human validation (Cohen's κ = 0.79)

✨ **Full provenance** — commit ID, URL, message,
date, file hash per function

### Key Statistics

| Metric | Value |
|--------|-------|
| Total functions | 21,430 |
| Vulnerable functions | 1,540 (7.2%) |
| Safe functions | 17,211 (80.3%) |
| Uncertain functions | 2,679 (12.5%) |
| Source repositories | 226 |
| LLM-attributed commits | 1,684 |
| Repositories scanned | 1,200 |
| Commits scanned | 321,080 |
| Date range | Nov 2022 – Sep 2026 |
| Languages | C, C++ |
| AI tools covered | 9 |
| Inter-rater agreement | κ = 0.79 |
| Columns per function | 34 |

---

## Repository Structure

```
LLMVul/
├── README.md
├── CITATION.cff
├── LICENSE                        (CC BY 4.0)
├── data/
│   ├── LLMVul_v3-Updated.csv           (full dataset — also on Zenodo)
│   │                              
│   ├── LLMVul_sample_100.csv   (100-row preview)
│   └── manual_validation/
│       └── manual_review_100.csv (100 manually
│                                  validated functions
│                                  with rater labels
│                                  and consensus)
├── scripts/
│   ├── mining/
│   │   └── pivd_mine_cpp.py      (GitHub mining)
│   └── labeling/
│       └── label_ensemble.py     (3-tool labeling)
└── paper/
    └── llmvul.pdf     (arxiv)
```

---

## Dataset Columns (34 Total)

| Category | Column | Description |
|----------|--------|-------------|
| **Function Identity** | `unique_id` | Stable SHA-256-based identifier. Format: `PIVD_XXXXXXXXXXXXXXXX` |
| **Project** | `project_name` | GitHub repository in `owner/repo` format |
| **Project** | `project_url` | Full URL of the GitHub repository |
| **Commit** | `commit_id` | Full 40-character Git commit SHA |
| **Commit** | `commit_url` | Direct URL to the commit on GitHub |
| **Commit** | `commit_message` | Full commit message (max 1,000 chars) |
| **Commit** | `commit_date` | ISO 8601 commit timestamp, e.g. `2024-03-15T10:22:31` |
| **Source** | `file_name` | Relative path of the source file within the repository |
| **Source** | `file_hash` | SHA-256 hash of the file at commit time, prefixed `sha256:` |
| **Source** | `language` | Programming language: `c` or `cpp` |
| **Function** | `function_body` | Extracted source code of the function |
| **Function** | `function_start_line` | Starting line number in the source file |
| **Function** | `function_end_line` | Ending line number in the source file |
| **Function** | `function_lines` | Total number of lines in the function body |
| **AI Provenance** | `ai_tool` | AI assistant: `copilot`, `chatgpt`, `claude`, `claude_code`, `cursor`, `gemini`, `openai_codex`, `devin`, `generic_llm` |
| **AI Provenance** | `signal_strength` | Attribution confidence: `strong` (co-author tag) or `medium` (commit message) |
| **AI Provenance** | `signal_type` | Attribution source: `coauthor` or `commit_message` |
| **Repository** | `repo_stars` | Number of GitHub stars at mining time |
| **Repository** | `repo_forks` | Number of GitHub forks at mining time |
| **Repository** | `repo_primary_language` | Primary language of the repository as reported by GitHub |
| **Dataset** | `mined_at` | ISO 8601 timestamp when this function was collected |
| **Label** | `vuln_label` | Final binary label: `1` = vulnerable, `0` = safe, `null` = uncertain |
| **Label** | `ensemble_label` | Ensemble verdict: `vulnerable`, `safe`, or `uncertain` |
| **Tool Result** | `tool_semgrep` | Semgrep result: `1` = flagged, `0` = clean |
| **Tool Result** | `tool_flawfinder` | Flawfinder result: `1` = flagged, `0` = clean |
| **Tool Result** | `pattern_match` | Pattern matching result: `1` = flagged, `0` = clean |
| **CWE** | `cwe_id` | Final CWE assigned, e.g. `CWE-120`. Null if safe or uncertain |
| **CWE** | `cwe_description` | Human-readable CWE description from MITRE CWE catalogue |
| **CWE** | `cwe_url` | MITRE CWE reference URL, e.g. `https://cwe.mitre.org/data/definitions/120.html` |
| **Tool CWE** | `cwe_semgrep_raw` | CWE reported by Semgrep. Null if not flagged |
| **Tool CWE** | `cwe_flawfinder_raw` | CWE reported by Flawfinder. Null if not flagged |
| **Tool CWE** | `cwe_pattern_match_raw` | CWE reported by pattern matching. Null if not flagged |
| **Tool Meta** | `semgrep_rule` | Semgrep rule ID that triggered the finding, e.g. `dangerous-strcpy` |
| **Tool Meta** | `flawfinder_risk` | Flawfinder risk level: `1` (lowest) to `5` (highest). `0` if not flagged |

---

## Labeling Methodology

Functions are labeled using a **three-tool majority 
vote ensemble**:

```
Tool 1: Semgrep      — CWE-mapped rules
Tool 2: Flawfinder   — dangerous function database
Tool 3: Pattern Match — 54 NIST SARD-derived patterns

Majority vote:
  ≥ 2 tools flag → VULNERABLE (vuln_label = 1)
  0 tools flag   → SAFE       (vuln_label = 0)
  1 tool flags   → UNCERTAIN  (excluded from labels)
```

**Human validation:** Two independent raters 
manually labeled 100 randomly sampled 
ensemble-vulnerable functions.
Inter-rater agreement: **Cohen's κ = 0.79** 
(substantial agreement, Landis & Koch 1977).
The manual validation CSV is available at 
`data/manual_validation/manual_review_100.csv`.

---

## AI Attribution Signals

Commits are classified as LLM-attributed using 
two signal categories:

**Strong signals** (co-authorship tags):
```
Co-authored-by: GitHub Copilot
Co-authored-by: cursor-noreply
Co-authored-by: claude-code
Co-authored-by: anthropic
```

**Medium signals** (commit message keywords):
```
"generated with ChatGPT"
"copilot suggested"
"via cursor ai"
"generated by claude"
"ai-assisted"
```

---

## Quick Start

```python
import pandas as pd

# Load full dataset
df = pd.read_csv('data/LLMVul_v3-Updated.csv')

# Vulnerable functions only
vuln = df[df['vuln_label'] == 1]

# By AI tool
copilot = df[df['ai_tool'] == 'copilot']

# By CWE
cwe120 = df[df['cwe_id'] == 'CWE-120']

# Strong signal only (high confidence)
strong = df[df['signal_strength'] == 'strong']

# For ML training — binary labeled only
labeled = df[df['vuln_label'].isin([0, 1])]

print(f"Total:      {len(df):,}")
print(f"Vulnerable: {(df['vuln_label']==1).sum():,}")
print(f"Safe:       {(df['vuln_label']==0).sum():,}")
```

---

## Research Questions Enabled

| RQ | Question |
|----|----------|
| RQ1 | Do existing vulnerability predictors (LineVul, VulBERTa) degrade on LLM-generated code vs human-written code? |
| RQ2 | Do LLM-generated C/C++ functions exhibit a distinct CWE distribution compared to BigVul/PrimeVul? |
| RQ3 | Can a predictor fine-tuned on LLMVul outperform general-purpose detectors on LLM-generated code? |
| RQ4 | Can AI tool attribution metadata train a provenance classifier distinguishing LLM from human code? |
| RQ5 | Which static analysis tools are most effective on LLM-generated C/C++ code? |
| RQ6 | Has the vulnerability rate of LLM-generated code changed across AI tool generations (2022–2026)? |

---

## Reproduce the Dataset

```bash
# Clone the repository
git clone https://github.com/Wahed08/LLMVul
cd LLMVul

# Install dependencies
pip install PyGithub pandas tqdm semgrep
pip install tree-sitter-languages
apt-get install flawfinder  # Linux/Colab

# Set GitHub token
export GITHUB_TOKEN="your_token_here"

# Step 1: Mine LLM-attributed commits
python scripts/mining/llmvul_mine_cpp.py

# Step 2: Label with ensemble
python scripts/labeling/label_ensemble.py
```

---

## Download

The full dataset is hosted on Zenodo:

**DOI:** [10.5281/zenodo.22668216](https://doi.org/10.5281/zenodo.22668216)

Files available on Zenodo:
- `LLMVul_v3-Updated.csv` — full dataset (21,430 functions)

---

## Manual Validation File

`data/manual_validation/manual_review_100.csv` 
contains 100 randomly sampled 
ensemble-vulnerable functions with:

| Column | Description |
|--------|-------------|
| `row_num` | Row number (1–100) |
| `unique_id` | Links back to main dataset |
| `language` | C or C++ |
| `cwe_id` | Assigned CWE |
| `ai_tool` | AI tool that generated the code |
| `project_name` | Source repository |
| `function_body` | Function source code |
| `rater1_label` | First rater label (0/1) |
| `rater2_label` | Second rater label (0/1) |
| `consensus` | Agreed final label |

---

## License

Dataset: [Creative Commons Attribution 4.0](https://creativecommons.org/licenses/by/4.0/)

Scripts: [MIT License](LICENSE)

---


## Citation

If you use LLMVul in your research, please cite:

```bibtex
@inproceedings{llmvul2026Farhad,
  author    = {Mohammad Farhad and Shuvalaxmi Dass},
  title     = {LLMVul: A Vulnerability-Labeled Dataset of LLM-Generated C/C++ Functions from Production Repositories},
  booktitle = {arxiv},
  year      = {2026},
  doi       = {https://doi.org/10.5281/zenodo.22668216}
}
```
---