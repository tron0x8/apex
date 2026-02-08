<p align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=JetBrains+Mono&weight=700&size=24&duration=3000&pause=1000&color=00FF00&center=true&vCenter=true&width=200&lines=Tron" alt="Tron" />
</p>

# APEX v3.0 - Advanced PHP Exploitation Scanner

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License MIT">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/CWE-130%2B%20rules-orange.svg" alt="CWE Coverage">
  <img src="https://img.shields.io/badge/OWASP%20Top%2010-100%25-brightgreen.svg" alt="OWASP Coverage">
  <img src="https://img.shields.io/badge/F1%20Score-94.4%25-brightgreen.svg" alt="F1 Score">
  <img src="https://img.shields.io/badge/frameworks-Laravel%20%7C%20Symfony%20%7C%20WordPress-green.svg" alt="Framework Support">
</p>

## Overview

APEX is a static security analysis framework for PHP applications. It combines tree-sitter AST parsing, CFG-based taint analysis, inter-procedural flow tracking, ML false-positive filtering, and optional LLM-powered deep analysis to detect vulnerabilities with high accuracy.

```
    +===========================================================================+
    |      _    ____  _______  __                                               |
    |     / \  |  _ \| ____\ \/ /                                               |
    |    / _ \ | |_) |  _|  \  /                                                |
    |   / ___ \|  __/| |___ /  \                                                |
    |  /_/   \_\_|   |_____/_/\_\                                               |
    |                                                                           |
    |  Advanced PHP Exploitation Scanner v3.0                                   |
    +===========================================================================+
```

## Features

### Multi-Layer Analysis Engine

- **Tree-sitter AST Parsing** - Full PHP syntax tree via tree-sitter (replaces hand-written parser)
- **CFG-Based Taint Analysis** - Control flow graph construction with worklist-based taint propagation
- **Inter-procedural Analysis** - Cross-function taint flow tracking with call graph and function summaries
- **Pattern Matching** - 130+ vulnerability patterns across 30 categories with 15-line multiline window
- **File-Wide Taint Tracking** - Tracks tainted variables from source to sink across entire files
- **ML FP Classifier** - GradientBoosting model (F1=0.954) for false positive filtering
- **LLM Deep Analysis** - Optional Ollama (free/local) or Anthropic Claude (API) powered verification
- **Framework Detection** - Laravel, Symfony, CodeIgniter, WordPress, DLE, Drupal auto-detection

### OWASP Top 10 Coverage: 100%

| Category | Vulnerability Types | CWE | Severity |
|----------|-------------------|-----|----------|
| A01: Broken Access Control | Path Traversal, IDOR, Open Redirect | CWE-22, CWE-601 | HIGH-CRITICAL |
| A02: Cryptographic Failures | Weak Crypto, Hardcoded Credentials, Insecure Random | CWE-327, CWE-798, CWE-330 | MEDIUM-HIGH |
| A03: Injection | SQLi, CMDi, Code Injection, LDAP, XPath, SSTI, Header Injection, Log Injection | CWE-89, CWE-78, CWE-94, CWE-90, CWE-643, CWE-1336, CWE-113, CWE-117 | MEDIUM-CRITICAL |
| A04: Insecure Design | Mass Assignment, Type Juggling, Race Condition | CWE-915, CWE-843, CWE-362 | MEDIUM-HIGH |
| A05: Security Misconfiguration | Debug Enabled, Information Disclosure | CWE-489, CWE-200 | LOW-MEDIUM |
| A06: Vulnerable Components | Deserialization, PHAR Deserialization | CWE-502 | CRITICAL |
| A07: Auth Failures | Authentication Bypass, Insecure Cookie, Session Fixation | CWE-287, CWE-614, CWE-384 | MEDIUM-HIGH |
| A08: Data Integrity | Unsafe File Upload, File Write/Read | CWE-434, CWE-73 | HIGH |
| A09: Logging Failures | Log Injection | CWE-117 | LOW |
| A10: SSRF | Server-Side Request Forgery | CWE-918 | HIGH |

**Additional:** XSS (CWE-79), XXE (CWE-611), File Inclusion LFI/RFI (CWE-98)

### Framework Support

| Framework | Detection | Sanitizers | Sources | Sinks |
|-----------|-----------|------------|---------|-------|
| Laravel | Auto | Eloquent, Blade, Validator | Request facade | DB::raw, whereRaw |
| Symfony | Auto | Doctrine, Twig, ParamConverter | Request object | createQuery |
| CodeIgniter | Auto | Query Builder, xss_clean | Input class | simple_query |
| WordPress | Auto | $wpdb->prepare, esc_* | Superglobals | $wpdb->query |
| Drupal | Auto | db_select, Html::escape | Request object | db_query |
| DLE (DataLife Engine) | Auto | DLE sanitizers | DLE globals | DLE DB functions |

### Output Formats

- **Text** - Human-readable terminal report with color coding
- **JSON** - Machine-readable format for integration
- **SARIF** - Static Analysis Results Interchange Format (IDE/GitHub integration)
- **HTML** - Professional report with charts, filters, severity breakdown, and remediation guidance

## Installation

```bash
git clone https://github.com/tron0x8/apex.git
cd apex
pip install -r requirements.txt
```

### Requirements

- Python 3.8+
- tree-sitter + tree-sitter-php (for AST parsing)
- scikit-learn (for ML FP filtering)
- Optional: Ollama or Anthropic API key (for LLM analysis)

## Usage

### Basic Scan

```bash
python apex.py /path/to/php/project
```

### With ML False Positive Filtering (Recommended)

```bash
python apex.py /path/to/project --ml
```

### Full Options

```bash
python apex.py <target> [options]

Options:
  target                PHP file or directory to scan
  -o, --output FILE     Output file path
  -f, --format FORMAT   Output format: text, json, sarif, html
  -v, --verbose         Verbose output
  --include-vendor      Include vendor/library files (skipped by default)
  --no-taint            Disable taint tracking (faster, more FPs)

ML Options:
  --ml                  Enable ML-based false positive filtering (instant)
  --ml-train            Train ML model from test fixtures before scanning

LLM Options:
  --llm                 Enable LLM-powered deep analysis
  --llm-backend TYPE    ollama (free/local), anthropic (paid/API), auto
  --llm-model MODEL     Model name (default: qwen2.5-coder:32b / claude-sonnet)
  --ollama-url URL      Ollama server URL (default: http://localhost:11434)
  --llm-fast            CPU-optimized mode: shorter prompts, smaller model
  --llm-verify-only     Only verify existing findings with LLM
  --llm-hunt-only       Only hunt for new vulnerabilities with LLM
```

### Examples

```bash
# Scan with ML filtering and HTML report
python apex.py /var/www/myapp --ml -f html -o report.html

# Scan single file
python apex.py vulnerable.php --ml

# Scan with LLM deep analysis (requires Ollama or Anthropic key)
python apex.py /var/www/myapp --ml --llm

# JSON output for CI/CD integration
python apex.py /var/www/myapp --ml -f json -o results.json

# SARIF output for GitHub Code Scanning
python apex.py /var/www/myapp -f sarif -o results.sarif

# Train ML model from custom fixtures then scan
python apex.py /var/www/myapp --ml --ml-train
```

### CI/CD Integration

```yaml
# .github/workflows/apex-scan.yml
name: APEX Security Scan
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run APEX
        run: |
          git clone https://github.com/tron0x8/apex.git /tmp/apex
          pip install -r /tmp/apex/requirements.txt
          python /tmp/apex/apex.py . --ml -f sarif -o results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Architecture

```
apex/
├── apex.py                    # CLI entry point
├── core/
│   ├── ts_adapter.py          # Tree-sitter PHP parser adapter
│   ├── taint_engine.py        # AST walk + CFG worklist taint analysis
│   ├── cfg.py                 # Control flow graph builder
│   ├── unified_scanner.py     # 130+ pattern scanner with multiline + file-wide taint
│   ├── interprocedural.py     # Cross-function flow tracking
│   ├── apex_core.py           # Main orchestrator
│   ├── ml_fp_classifier.py    # ML false positive classifier (GradientBoosting)
│   ├── html_report.py         # HTML report generator with charts
│   ├── llm_analyzer.py        # Ollama + Anthropic dual-backend LLM analyzer
│   ├── context_analyzer.py    # Context-aware analysis
│   ├── fp_prefilter.py        # False positive pre-filtering
│   ├── fp_filter.py           # False positive filtering
│   ├── frameworks.py          # Framework detection
│   ├── ast_parser.py          # AST utilities
│   └── symbolic_executor.py   # Symbolic execution engine
├── models/
│   └── fp_classifier_model.pkl  # Trained ML model (GradientBoosting)
├── train_ml.py                # ML training pipeline
├── tests/
│   ├── test_ts_adapter.py     # Tree-sitter adapter tests
│   ├── test_cfg.py            # CFG builder tests
│   ├── test_interprocedural.py # Inter-procedural analysis tests
│   ├── test_multiline.py      # Multi-line detection tests
│   ├── test_new_features.py   # New vulnerability type tests
│   ├── test_precision_recall.py # Precision/recall measurement
│   └── fixtures/              # Test PHP files (vulnerable + safe)
├── test_vuln_sample.py        # Core regression tests (14 tests)
└── requirements.txt
```

### Analysis Pipeline

```
┌─────────────────┐    ┌──────────────────┐    ┌────────────────────┐
│   PHP Source     │───>│  Tree-sitter     │───>│   AST + CFG        │
│     Files        │    │  PHP Parser      │    │   Construction     │
└─────────────────┘    └──────────────────┘    └────────────────────┘
         │                                               │
         v                                               v
┌─────────────────┐                          ┌────────────────────┐
│   Framework     │                          │  Pattern Scanner   │
│   Detection     │                          │ (130+ patterns,    │
│                 │                          │  15-line window,   │
│                 │                          │  file-wide taint)  │
└─────────────────┘                          └────────────────────┘
         │                                               │
         v                                               v
┌─────────────────────────────────────────────────────────────────────┐
│                        Analysis Engines                             │
├─────────────────┬──────────────────────┬───────────────────────────┤
│ CFG Taint       │ Symbolic Execution   │ Inter-procedural          │
│ Analysis        │                      │ Analysis                  │
│                 │                      │                           │
│ - Worklist algo │ - Path constraints   │ - Call graph              │
│ - Branch-aware  │ - Branch forking     │ - Function summaries      │
│ - Fixed-point   │ - Loop unrolling     │ - Arg-to-param binding    │
│ - FW sanitizers │                      │ - Return taint propagation│
└─────────────────┴──────────────────────┴───────────────────────────┘
         │                    │                          │
         v                    v                          v
┌─────────────────────────────────────────────────────────────────────┐
│                  False Positive Filtering Chain                      │
│                                                                     │
│  fp_prefilter -> context_analyzer -> fp_filter -> ML FP classifier  │
│                                                                     │
│  ML Model: GradientBoosting (F1=0.954, 0.10ms/prediction)          │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                v
                  ┌───────────────────────────┐
                  │   Optional: LLM Analysis  │
                  │   (Ollama / Anthropic)     │
                  │   - Verify findings        │
                  │   - Hunt new vulns         │
                  └───────────────────────────┘
                                │
                                v
                    ┌───────────────────────┐
                    │   Reports             │
                    │  (Text/JSON/SARIF/    │
                    │   HTML)               │
                    └───────────────────────┘
```

## Benchmark Results

Tested against 5 real-world and intentionally vulnerable PHP applications:

| Application | PHP Files | Findings | Top Vulnerability Types |
|-------------|-----------|----------|----------------------|
| bWAPP | 198 | 212 | SQLi (64), XSS (46), Header Injection (26) |
| Mutillidae | 170 | 55 | SQLi, XSS, XXE, Code Injection |
| MaxSiteCMS | 698 | 19 | File Write, File Read, Code Injection |
| WackoPicko | 49 | 14 | SQLi, XSS, Command Injection |
| VulnPHP | 9 | 12 | SQLi, XSS, File Inclusion |

**Total: 312 findings across 1,124 PHP files**

### Test Suite

- **78 tests** across 7 test files
- **Precision: 94.4%** | **Recall: 94.4%** | **F1: 94.4%**
- Covers: tree-sitter parsing, CFG construction, inter-procedural flow, multiline detection, new vuln types, precision/recall

## Example Output

### Terminal Output

```
======================================================================
APEX v3.0 - Security Analysis Report
======================================================================

Framework Detected: Laravel
Files Scanned: 156
Time Elapsed: 4.2s

SUMMARY
----------------------------------------------------------------------
CRITICAL: 3    HIGH: 5    MEDIUM: 4    LOW: 1

FINDINGS
----------------------------------------------------------------------

[1] SQL_INJECTION (CRITICAL) [Confidence: 95%]
    File: app/Http/Controllers/UserController.php:45
    Sink: DB::raw($request->input('id'))
    CWE: CWE-89
    Remediation: Use parameterized queries or Eloquent ORM

[2] DESERIALIZATION (CRITICAL) [Confidence: 90%]
    File: app/Services/CacheService.php:78
    Sink: unserialize($cookie)
    CWE: CWE-502
    Remediation: Use json_decode() instead of unserialize()
```

### JSON Report

```json
{
  "summary": {
    "total_findings": 13,
    "critical": 3,
    "high": 5,
    "medium": 4,
    "low": 1
  },
  "framework": "Laravel",
  "findings": [
    {
      "type": "SQL_INJECTION",
      "severity": "CRITICAL",
      "file": "app/Http/Controllers/UserController.php",
      "line": 45,
      "confidence": 0.95,
      "cwe": "CWE-89",
      "remediation": "Use parameterized queries or Eloquent ORM"
    }
  ]
}
```

## Taint Sources

### PHP Superglobals
- `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, `$_SERVER`

### Framework-Specific
- **Laravel:** `$request->input()`, `Request::get()`
- **Symfony:** `$request->query->get()`, `$request->request->get()`
- **CodeIgniter:** `$this->input->get()`, `$this->request->getVar()`
- **WordPress:** `get_query_var()`

### Weak Sources (lower confidence)
- `$post`, `$data`, `$input`, `$request`, `$params`

## Sanitizers

| Function | Protects Against |
|----------|-----------------|
| `intval()` / `(int)` | SQLi, XSS, Path Traversal |
| `htmlspecialchars()` / `htmlentities()` | XSS |
| `mysqli_real_escape_string()` / `PDO::quote()` | SQLi |
| `escapeshellarg()` / `escapeshellcmd()` | Command Injection |
| `basename()` / `realpath()` | Path Traversal, File Inclusion |
| `filter_var()` | XSS, SQLi, SSRF |
| `prepared statements` / `->prepare()` | SQLi |
| `libxml_disable_entity_loader()` | XXE |

## Contributing

Contributions are welcome. Please submit pull requests with:

1. Clear description of changes
2. Test cases for new vulnerability patterns
3. Documentation updates

## License

MIT License - see LICENSE file for details.

## Author

**Tron** - Security Researcher

- GitHub: [@tron0x8](https://github.com/tron0x8)

## Disclaimer

This tool is intended for authorized security testing and research purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems or applications.

---

<p align="center">
  <b>If you find this tool useful, please star the repository!</b>
</p>
