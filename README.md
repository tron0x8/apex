<p align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=JetBrains+Mono&weight=700&size=24&duration=3000&pause=1000&color=00FF00&center=true&vCenter=true&width=200&lines=Tron" alt="Tron" />
</p>

# APEX v4.0 - Advanced PHP Exploitation Scanner

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License MIT">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/patterns-135%20rules-orange.svg" alt="135 Rules">
  <img src="https://img.shields.io/badge/OWASP%20Top%2010-9%2F10-brightgreen.svg" alt="OWASP Coverage">
  <img src="https://img.shields.io/badge/ML%20F1-92.8%25-brightgreen.svg" alt="ML F1 Score">
  <img src="https://img.shields.io/badge/tests-179%20passed-brightgreen.svg" alt="179 Tests">
  <img src="https://img.shields.io/badge/frameworks-10%20supported-green.svg" alt="10 Frameworks">
</p>

## Overview

APEX is a static security analysis framework for PHP applications. It combines tree-sitter AST parsing, SSA-based taint analysis, abstract interpretation, inter-procedural flow tracking (k-CFA), alias/points-to analysis, type inference, ML false-positive classification, and optional LLM-powered deep analysis.

```
    +===========================================================================+
    |      _    ____  _______  __                                               |
    |     / \  |  _ \| ____\ \/ /                                               |
    |    / _ \ | |_) |  _|  \  /                                                |
    |   / ___ \|  __/| |___ /  \                                                |
    |  /_/   \_\_|   |_____/_/\_\                                               |
    |                                                                           |
    |  Advanced PHP Exploitation Scanner v4.0                                   |
    +===========================================================================+
```

## What's New in v4.0

- **YAML Rule Engine** - All sources, sinks, sanitizers, patterns externalized to `rules/` YAML files. Zero hardcoding.
- **SSA (Static Single Assignment)** - Variable versioning with phi nodes and dominator tree for precise branch-aware taint tracking.
- **Abstract Interpretation** - Lattice-based taint analysis (BOTTOM < UNTAINTED < WEAK < TAINTED < TOP) with widening for loop termination.
- **String Domain Analysis** - Tracks string construction via concatenation/interpolation, determines if tainted fragment is in a safe SQL/XSS position.
- **Context-Sensitive Inter-procedural Analysis (k-CFA)** - k=2 call-site sensitivity, Tarjan SCC for recursive groups, function summaries with argument-to-parameter binding.
- **Points-to / Alias Analysis** - Andersen's inclusion-based analysis for PHP references (`$a = &$b`) and object properties.
- **Type Inference** - PHP type narrowing (`is_int()`, `(int)`, `settype()`) to eliminate false positives when variable is proven safe.
- **Framework Deep Models** - YAML-driven validation constraint modeling for Laravel, Symfony, WordPress, etc.
- **Incremental Analysis** - SHA-256 content hash caching with dependency-aware invalidation. Only re-analyzes changed files.
- **ML v4 Classifier** - 30-feature GradientBoosting model trained on 548 samples (339 TP, 209 FP). Uses real v4.0 module outputs, not just regex heuristics.

## Installation

```bash
git clone https://github.com/tron0x8/apex.git
cd apex
pip install -r requirements.txt
```

### Requirements

- Python 3.8+
- tree-sitter + tree-sitter-php
- scikit-learn, numpy (for ML)
- pyyaml (for rule engine)
- Optional: Ollama or Anthropic API key (for LLM analysis)

## Usage

```bash
# Basic scan
python apex.py /path/to/php/project

# With ML false positive filtering (recommended)
python apex.py /path/to/project --ml

# HTML report
python apex.py /path/to/project --ml -f html -o report.html

# JSON for CI/CD
python apex.py /path/to/project --ml -f json -o results.json

# SARIF for GitHub Code Scanning
python apex.py /path/to/project -f sarif -o results.sarif

# LLM deep analysis (requires Ollama or Anthropic key)
python apex.py /path/to/project --ml --llm

# Train ML model then scan
python apex.py /path/to/project --ml --ml-train

# Single file scan
python apex.py vulnerable.php --ml -v
```

### CLI Options

```
python apex.py <target> [options]

Positional:
  target                  PHP file or directory to scan

Output:
  -o, --output FILE       Output file path
  -f, --format FORMAT     text | json | sarif | html
  -v, --verbose           Verbose output

Scan:
  --include-vendor        Include vendor/library directories
  --no-taint              Disable taint tracking (faster, more FPs)

ML:
  --ml                    Enable ML false positive filtering
  --ml-train              Train ML model from fixtures before scan

LLM:
  --llm                   Enable LLM-powered deep analysis
  --llm-backend TYPE      ollama (free/local) | anthropic (paid/API) | auto
  --llm-model MODEL       Model name (default: qwen2.5-coder:32b / claude-sonnet)
  --ollama-url URL        Ollama server URL
  --llm-fast              CPU-optimized: shorter prompts, smaller model
  --llm-verify-only       Only verify existing findings
  --llm-hunt-only         Only hunt for new vulnerabilities
```

### ML Training

```bash
# Train with full pipeline (recommended)
python train_ml.py --verbose

# Train with custom data directory
python train_ml.py --data-dir /path/to/scan/jsons --verbose
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
├── apex.py                        # CLI entry point
├── train_ml.py                    # ML training pipeline
├── training_data_extended.py      # 180 extended TP/FP training examples
├── core/
│   ├── ts_adapter.py              # Tree-sitter PHP parser adapter
│   ├── cfg.py                     # Control flow graph builder
│   ├── ssa.py                     # SSA builder (phi nodes, dominators)
│   ├── abstract_interp.py         # Abstract interpretation engine
│   ├── string_domain.py           # String fragment analysis
│   ├── type_inference.py          # PHP type inference
│   ├── alias_analysis.py          # Points-to / alias analysis
│   ├── taint_engine.py            # AST walk + CFG taint analysis
│   ├── unified_scanner.py         # 135-pattern scanner
│   ├── interprocedural.py         # Basic inter-procedural analysis
│   ├── interprocedural_v2.py      # k-CFA inter-procedural engine
│   ├── rule_engine.py             # YAML rule loader (single source of truth)
│   ├── framework_models.py        # Framework validation modeling
│   ├── frameworks.py              # Framework detection
│   ├── ml_fp_classifier.py        # ML false positive classifier
│   ├── fp_prefilter.py            # FP pre-filter
│   ├── fp_filter.py               # FP filter
│   ├── fp_filter_v2.py            # Consolidated FP filter v2
│   ├── context_analyzer.py        # Context-aware analysis
│   ├── incremental.py             # Incremental analysis cache
│   ├── apex_core.py               # Main orchestrator
│   ├── html_report.py             # HTML report with charts
│   ├── llm_analyzer.py            # Ollama + Anthropic LLM backend
│   ├── symbolic_executor.py       # Symbolic execution engine
│   └── ast_parser.py              # AST utilities
├── rules/
│   ├── sources.yml                # 15 taint sources
│   ├── sinks.yml                  # 78 dangerous sinks
│   ├── sanitizers.yml             # 98 sanitizer functions
│   ├── patterns.yml               # 135 vulnerability patterns
│   ├── fp_rules.yml               # 50 false positive rules
│   └── frameworks/                # 10 framework configs
│       ├── laravel.yml
│       ├── symfony.yml
│       ├── wordpress.yml
│       ├── codeigniter.yml
│       ├── drupal.yml
│       ├── yii.yml
│       ├── cakephp.yml
│       ├── slim.yml
│       ├── laminas.yml
│       └── dle.yml
├── models/
│   └── apex_fp_classifier_v4.pkl  # Trained ML model
├── tests/
│   ├── test_rule_engine.py        # 15 tests
│   ├── test_ssa.py                # 11 tests
│   ├── test_abstract_interp.py    # 14 tests
│   ├── test_string_domain.py      # 17 tests
│   ├── test_interprocedural_v2.py # 10 tests
│   ├── test_alias_type.py         # 15 tests
│   ├── test_framework_models.py   # 11 tests
│   ├── test_incremental.py        # 8 tests
│   ├── test_cfg.py                # 10 tests
│   ├── test_ts_adapter.py         # 14 tests
│   ├── test_interprocedural.py    # 10 tests
│   ├── test_multiline.py          # 9 tests
│   ├── test_context_v2.py         # 7 tests
│   ├── test_new_features.py       # 28 tests
│   └── fixtures/                  # Vulnerable + safe PHP fixtures
└── test_vuln_sample.py            # 14 regression tests
```

### Analysis Pipeline

```
  PHP Source Files
        |
        v
  +-----------------+     +------------------+
  | Tree-sitter     |---->| CFG Builder      |
  | PHP Parser      |     | (cfg.py)         |
  +-----------------+     +------------------+
                                   |
              +--------------------+--------------------+
              |                    |                    |
              v                    v                    v
  +-----------------+  +------------------+  +------------------+
  | SSA Builder     |  | Type Inference   |  | Alias Analysis   |
  | (phi nodes,     |  | (INT/FLOAT/BOOL  |  | (Andersen's      |
  |  dominators)    |  |  narrowing)      |  |  points-to)      |
  +-----------------+  +------------------+  +------------------+
              |                    |                    |
              +--------------------+--------------------+
                                   |
                                   v
                    +-----------------------------+
                    | Abstract Interpreter        |
                    | (lattice taint analysis,    |
                    |  widening, fixed-point)     |
                    +-----------------------------+
                                   |
          +------------------------+------------------------+
          |                        |                        |
          v                        v                        v
  +-----------------+  +--------------------+  +---------------------+
  | String Domain   |  | Pattern Scanner    |  | Inter-procedural    |
  | (concat/interp  |  | (135 patterns,     |  | k-CFA Engine        |
  |  tracking)      |  |  30 vuln types)    |  | (Tarjan SCC,        |
  +-----------------+  +--------------------+  |  func summaries)    |
                                |               +---------------------+
                                v
                    +-----------------------------+
                    | FP Filter Chain             |
                    | prefilter -> context ->      |
                    | fp_filter -> ML classifier   |
                    +-----------------------------+
                                |
                    +-----------+-----------+
                    |                       |
                    v                       v
          +------------------+    +------------------+
          | ML FP Classifier |    | LLM Analysis     |
          | (GradientBoost,  |    | (Ollama /        |
          |  30 features,    |    |  Anthropic)      |
          |  F1=0.928)       |    |                  |
          +------------------+    +------------------+
                    |                       |
                    v                       v
              +-------------------------------+
              | Reports (Text/JSON/SARIF/HTML) |
              +-------------------------------+
```

## ML FP Classifier

### Model: `apex_fp_classifier_v4.pkl`

| Metric | Value |
|--------|-------|
| Algorithm | GradientBoosting |
| Features | 30 |
| Training samples | 548 (339 TP, 209 FP) |
| Cross-val F1 | 0.928 |
| Cross-val Accuracy | 91.1% |
| FP Precision | 95% |
| TP Precision | 100% |
| Prediction speed | 0.14ms / 6,950 predictions per second |
| Model size | 347 KB |

### 30 Features

**Core (22):** severity, rule_confidence, source_risk, has_direct_source, sink_danger, sanitizer_present, sanitizer_count, sanitizer_type_match, sanitizer_distance, prepared_stmt_nearby, type_cast_nearby, validation_nearby, orm_detected, in_comment, in_admin_path, auth_check_nearby, in_try_catch, is_ajax_handler, var_reassigned, uses_string_concat, uses_interpolation, cms_safe_pattern

**v4.0 Analysis (8):** ssa_branch_sanitized, string_context_safe, string_tainted_ratio, type_narrowed_safe, alias_count, interproc_flow_to_sink, interproc_sanitized, framework_validated

### Training Data Sources

| Source | TP | FP | Total |
|--------|----|----|-------|
| bWAPP (198 PHP files) | 170 | - | 170 |
| Mutillidae (170 PHP files) | 50 | - | 50 |
| WackoPicko (49 PHP files) | 12 | - | 12 |
| VulnPHP (9 PHP files) | 12 | - | 12 |
| Test fixtures (vuln/safe PHP) | 38 | 8 | 46 |
| Synthetic patterns | 8 | 8 | 16 |
| Augmented patterns | 15 | 27 | 42 |
| Extended dataset (20 categories) | 20 | 160 | 180 |
| MaxSiteCMS (698 PHP files) | 14 | 6 | 20 |
| **Total** | **339** | **209** | **548** |

### Feature Importance

```
rule_confidence         58.9%  ##############################
severity                 6.7%  ###
source_risk              5.9%  ###
sanitizer_distance       5.9%  ###
in_comment               4.9%  ##
var_reassigned           3.9%  ##
sink_danger              2.5%  #
sanitizer_type_match     2.5%  #
validation_nearby        2.3%  #
string_tainted_ratio     1.6%  #
```

## Vulnerability Coverage

### 30 Vulnerability Types, 135 Patterns

| OWASP | Category | Types | CWEs |
|-------|----------|-------|------|
| A01 | Broken Access Control | Path Traversal, IDOR, Open Redirect, File Read/Write | CWE-22, CWE-639, CWE-601, CWE-73 |
| A02 | Cryptographic Failures | Weak Crypto, Hardcoded Credentials, Insecure Randomness | CWE-327, CWE-798, CWE-330 |
| A03 | Injection | SQLi, CMDi, Code Injection, LDAP, XPath, SSTI, Header Injection, Log Injection | CWE-89, CWE-78, CWE-94, CWE-90, CWE-643, CWE-1336, CWE-113, CWE-117 |
| A04 | Insecure Design | Mass Assignment, Type Juggling, Race Condition | CWE-915, CWE-843, CWE-362 |
| A05 | Security Misconfiguration | XXE, Information Disclosure | CWE-611, CWE-200 |
| A07 | Auth Failures | Authentication Bypass, Type Juggling | CWE-287, CWE-843 |
| A08 | Data Integrity | Deserialization, CSRF, Unsafe File Upload | CWE-502, CWE-352, CWE-434 |
| A09 | Logging Failures | Log Injection | CWE-117 |
| A10 | SSRF | Server-Side Request Forgery | CWE-918 |

Plus: XSS (CWE-79), File Inclusion LFI/RFI (CWE-98), NoSQL Injection (CWE-943), Remote Code Execution (CWE-94), Regex DoS (CWE-1333)

### YAML Rule Engine

| File | Contents | Count |
|------|----------|-------|
| `sources.yml` | Taint sources (superglobals, framework inputs) | 15 |
| `sinks.yml` | Dangerous functions with arg positions | 78 |
| `sanitizers.yml` | Sanitizer functions with protection mappings | 98 |
| `patterns.yml` | Regex patterns with CWE + remediation | 135 |
| `fp_rules.yml` | False positive detection rules | 50 |
| `frameworks/*.yml` | Framework-specific configs | 10 files |

### Supported Frameworks

| Framework | Detection | Validation | ORM/Query Builder | Template Escaping |
|-----------|-----------|------------|-------------------|-------------------|
| Laravel | Auto | `$request->validate()`, FormRequest | Eloquent, Query Builder | Blade `{{ }}` |
| Symfony | Auto | Form validation, `isValid()` | Doctrine, QueryBuilder | Twig `{{ }}` |
| WordPress | Auto | `wp_verify_nonce()`, `sanitize_*()` | `$wpdb->prepare()` | `esc_html()`, `wp_kses()` |
| CodeIgniter | Auto | `form_validation` | Active Record | `xss_clean()` |
| Yii | Auto | Model validation rules | ActiveRecord, Query | `Html::encode()` |
| Drupal | Auto | Form API | `db_select()` | `Html::escape()` |
| CakePHP | Auto | Validator | Table, Query | `h()` |
| Slim | Auto | - | - | - |
| Laminas | Auto | InputFilter | TableGateway | `escapeHtml()` |
| DLE | Auto | DLE sanitizers | DLE DB functions | DLE filters |

## Benchmark Results

| Application | PHP Files | Raw Findings | After ML | FP Eliminated |
|-------------|-----------|-------------|----------|---------------|
| bWAPP | 198 | 212 | ~178 | ~34 (16%) |
| Mutillidae | 170 | 55 | ~48 | ~7 (13%) |
| DLE CMS | 192 | 75 | ~41 | ~34 (45%) |
| MaxSiteCMS | 698 | 19 | ~15 | ~4 (21%) |
| WackoPicko | 49 | 14 | ~12 | ~2 (14%) |
| VulnPHP | 9 | 12 | ~11 | ~1 (8%) |

## Test Suite: 179 Tests

| Test File | Tests | Coverage |
|-----------|-------|----------|
| test_vuln_sample.py | 14 | Core regression (SQLi, XSS, CMDi, eval, LFI, SSRF, deser, RCE, type juggling) |
| test_new_features.py | 28 | ML classifier, HTML report, dedup, OWASP, new vuln types |
| test_string_domain.py | 17 | String concat, interpolation, taint ratio, sink context |
| test_rule_engine.py | 15 | YAML loading, source/sink/sanitizer/pattern queries |
| test_alias_type.py | 15 | Points-to sets, aliasing, type narrowing, references |
| test_abstract_interp.py | 14 | Lattice ops, transfer functions, fixed-point, widening |
| test_ts_adapter.py | 14 | Tree-sitter PHP parsing |
| test_ssa.py | 11 | Phi nodes, dominator tree, SSA variable renaming |
| test_framework_models.py | 11 | Validation constraints, middleware, ORM, Blade |
| test_cfg.py | 10 | CFG block building, edges, conditions |
| test_interprocedural.py | 10 | Cross-function taint flow |
| test_interprocedural_v2.py | 10 | k-CFA, SCC, arg binding, return propagation |
| test_multiline.py | 9 | Multi-line pattern detection (15-line window) |
| test_incremental.py | 8 | Cache hit/miss, dependency tracking, invalidation |
| test_context_v2.py | 7 | Context analyzer patterns |

## Codebase Stats

| Metric | Value |
|--------|-------|
| Total code | 31,875 lines |
| Python | 29,101 lines (64 files) |
| YAML rules | 2,774 lines (15 files) |
| Core modules | 22,666 lines (34 files) |
| v4.0 new modules | 10 modules |
| Test files | 16 files, 179 tests |
| ML model | 347 KB, 30 features, 548 training samples |

## Example Output

```
APEX v4.0 - Security Analysis Report
======================================================================

Framework Detected: Laravel
Files Scanned: 156
Time Elapsed: 4.2s

SUMMARY
----------------------------------------------------------------------
CRITICAL: 3    HIGH: 5    MEDIUM: 4    LOW: 1

FINDINGS
----------------------------------------------------------------------

[1] SQL_INJECTION (CRITICAL) [Confidence: 95%] [ML: 0.996 TP]
    File: app/Http/Controllers/UserController.php:45
    Sink: DB::raw($request->input('id'))
    CWE: CWE-89
    Remediation: Use parameterized queries or Eloquent ORM

[2] DESERIALIZATION (CRITICAL) [Confidence: 90%] [ML: 0.983 TP]
    File: app/Services/CacheService.php:78
    Sink: unserialize($cookie)
    CWE: CWE-502
    Remediation: Use json_decode() instead of unserialize()
```

## Contributing

Contributions welcome. Submit PRs with:

1. Clear description of changes
2. Test cases for new patterns
3. Documentation updates

## License

MIT License

## Author

**Tron** - Security Researcher - [@tron0x8](https://github.com/tron0x8)

## Disclaimer

This tool is intended for authorized security testing and research purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems or applications.

---

<p align="center">
  <b>If you find this tool useful, please star the repository!</b>
</p>
