
## Table 1
### Top 10 Projects with the Highest Number of Ensemble-Vulnerable Functions

| Project | Vulnerable Functions | Percentage |
|---|---:|---:|
| `nature-lang/nature` | 227 | 14.74% |
| `Serial-Studio/Serial-Studio` | 210 | 13.64% |
| `sqliteai/warp` | 108 | 7.01% |
| `google/security-research` | 77 | 5.00% |
| `xroche/httrack` | 72 | 4.68% |
| `ggml-org/whisper.cpp` | 50 | 3.25% |
| `memovai/mimiclaw` | 50 | 3.25% |
| `DarkFlippers/unleashed-firmware` | 37 | 2.40% |
| `DavidXanatos/TaskExplorer` | 29 | 1.88% |
| `coturn/coturn` | 28 | 1.82% |

**Note:** Percentages represent each project's share of the total ensemble-vulnerable functions in the dataset.


## Table 2
### Flawfinder Finding Distribution by Category

To further categorize the CWE-676 findings, we applied a function-name-based classification procedure that mapped Flawfinder-flagged functions to predefined vulnerability categories using their associated security-risk descriptions. 

The following table summarizes the distribution of Flawfinder findings across vulnerability categories. **Buffer-related** issues accounted for 84.6\% of these classified findings.

| Category | Classified Findings |
|---|---:|
| `Buffer-related` | 1,307 |
| `Miscellaneous (e.g., divide by zero)` | 101 |
| `Formatted-I/O operations` | 41 |
| `Dangerous shell commands` | 30 |
| `Race-condition / TOCTOU-related` | 26 |
| `Integer-related` | 15 |
| `Unsafe temporary-file handling` | 13 |
| `Unsuitable random-number generation` | 6 |
| `Use of obsolete/deprecated functions` | 6 |
| **Total classified findings** | **1,545** |
| **Unclassified (but dangerous functions)** | **546** |

**Note:** The 546 unclassified findings correspond to potentially dangerous function usages that were not assigned to the above vulnerability categories.

## Table 3
### Distribution of Vulnerable Functions Across CWE Categories

| CWE / Vulnerability Type | Vulnerable Functions |
|---|---:|
| `CWE-120`: Buffer Copy | 494 |
| `CWE-787`: Out-of-Bounds Write | 478 |
| `CWE-676`: Dangerous Function Use* | 411 |
| `CWE-22`: Path Traversal | 75 |
| `CWE-190`: Integer Overflow | 45 |
| `CWE-78`: OS Command Injection | 25 |
| `CWE-134`: Format String | 6 |
| `CWE-338`: Weak PRNG | 6 |
| **Total** | **1,540** |

**Note:** *Dangerous functions include CWE-369 (Divide by Zero), CWE-476 (Null Pointer Dereference), CWE-362 (Race Condition), CWE-416 (Use After Free), CWE-807 (Untrusted Inputs) and more.