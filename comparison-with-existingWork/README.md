## Comparison with Existing Vulnerability and AI-Generated Code Datasets

Existing datasets for vulnerability detection and AI-generated code can be broadly grouped into three categories: human-written vulnerability datasets, LLM-prompted code datasets, and datasets mined from real-world AI-assisted software development. These categories differ in code provenance, labeling methodology, scale, and availability of AI-generation metadata.

Unlike LLM-prompted datasets, which primarily contain code generated through controlled research prompts, AI-assisted code datasets capture code produced with AI coding assistants during real-world software development. LLMVul focuses on this latter setting and provides vulnerability labels, CWE labels, and AI-tool attribution metadata for functions mined from public production repositories.

### Dataset Comparison

| Dataset (Year) | Purpose | Code Origin | Language | Repositories | Unit | Scale | Vulnerability Labels | CWE Labels | Ground-Truth Method | Production Code | AI Tool Metadata |
|---|---|---|---|---:|---|---:|:---:|:---:|---|:---:|:---:|
| **Human-Written Vulnerability Datasets** |||||||||||
| Devign (2019) | Vulnerability detection | Human (CVE) | C/C++ | 2 | Functions | 27K+ | ✓ | ✗ | CVE-linked | ✓ | ✗ |
| BigVul (2020) | Vulnerability detection | Human (CVE) | C/C++ | 348 | Functions | 265K+ | ✓ | ✓ | CVE-linked | ✓ | ✗ |
| ICVul (2025) | Vulnerability detection | Human | C/C++ | 807 | Functions | 15K+ | ✓ | ✓ | Automated | ✓ | ✗ |
| PrimeVul (2025) | Vulnerability detection | Human | C/C++ | 755 | Functions | 235K+ | ✓ | ✓ | Deduplication and verification | ✓ | ✗ |
| **LLM-Prompted Code Datasets** |||||||||||
| SecurityEval (2022) | Security evaluation | LLM-prompted | Python | — | Prompts | 130 | ✓ | ✓ | Manual | ✗ | ✗ |
| FormAI (2023) | Security evaluation | LLM-generated | C | — | Programs | 112K | ✓ | ✗ | Formal verification | ✗ | ✗ |
| CyberSecEval 2 (2024) | Security evaluation | LLM-generated | Multi | — | Prompts | 500 | N/A | N/A | N/A | ✗ | ✗ |
| CWEval (2025) | CWE evaluation | LLM-generated | Multi | — | Functions | 119 | ✓ | ✓ | Dynamic analysis | ✗ | ✗ |
| SafeGenBench (2025) | Security evaluation | LLM-generated | Multi | — | Functions | 558 | ✓ | ✓ | Automated | ✗ | ✗ |
| **AI-Assisted Public Code Datasets** |||||||||||
| DevGPT (2024) | AI-assisted development analysis | Real-world AI-assisted | Multi | — | Snippets | 19K+ | ✗ | ✗ | N/A | ✓ | Partial |
| Debt AI Boom (2026) | Technical debt analysis | Real-world AI-assisted | Python/JS/TS | 6,299 | Commits | 302.6K | ✗ | ✗ | N/A | ✓ | ✓ |
| **LLMVul (Ours)** | Vulnerability detection | Real-world AI-assisted | C/C++ | 1,200 scanned | Functions | 21.4K | ✓ | ✓ | Three-tool ensemble and human validation (κ = 0.79) | ✓ | ✓ |

**Notes:**
- ✓ indicates available; ✗ indicates unavailable.
- **Production Code** indicates whether the dataset contains code mined from real-world software repositories.
- **AI Tool Metadata** indicates whether the dataset records information about the AI coding assistant associated with code generation.
- **Multi** indicates multiple programming languages; **JS/TS** indicates JavaScript/TypeScript.
- **N/A** indicates that the information is not applicable or is not available.
- Repository counts for LLMVul distinguish the **1,200 repositories scanned** during data collection from the **226 repositories represented** in the released dataset.
- LLM-prompted datasets contain code generated through controlled research prompts, whereas AI-assisted public code datasets contain code produced during real-world software development.

### LLMVul's Distinguishing Characteristics

LLMVul complements existing vulnerability datasets by focusing on AI-assisted code from real-world software repositories rather than code generated exclusively through controlled prompting. Its main distinguishing characteristics are:

- **Real-world provenance:** Functions are collected from public GitHub repositories containing evidence of AI-assisted development.
- **AI-tool attribution:** The dataset includes metadata identifying the AI coding assistant associated with the code, where attribution signals are available.
- **Vulnerability and CWE labels:** Functions are labeled using a three-tool ensemble, with vulnerability categories and CWE information.
- **Human validation:** A sample of 100 ensemble-labeled vulnerable functions was independently reviewed by two raters, achieving Cohen's κ = 0.79.
- **Reproducible research resource:** The dataset supports research on vulnerability detection, vulnerability patterns, and the generalization of existing detectors to AI-assisted code.

