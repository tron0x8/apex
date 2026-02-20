<p align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=JetBrains+Mono&weight=700&size=24&duration=3000&pause=1000&color=00FF00&center=true&vCenter=true&width=200&lines=Tron" alt="Tron" />
</p>

# APEX v12 - Advanced PHP Exploitation Scanner

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License MIT">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/patterns-135%20rules%20%2B%20120%20sigs-orange.svg" alt="135 Rules + 120 Sigs">
  <img src="https://img.shields.io/badge/OWASP%20Top%2010-9%2F10-brightgreen.svg" alt="OWASP Coverage">
  <img src="https://img.shields.io/badge/ML%20F2-0.945-brightgreen.svg" alt="ML F2 Score">
  <img src="https://img.shields.io/badge/tests-172%20passed-brightgreen.svg" alt="172 Tests">
  <img src="https://img.shields.io/badge/frameworks-10%20supported-green.svg" alt="10 Frameworks">
  <img src="https://img.shields.io/badge/datasets%20tested-11%20projects-blue.svg" alt="11 Datasets">
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
    |  Advanced PHP Exploitation Scanner v12                                    |
    +===========================================================================+
```

## What's New in v12

- **Built-in Function Signature Database** - 120+ PHP function taint propagation rules in `builtin_sigs.yml`. Each function defines which arguments propagate taint and which sanitize. `str_replace($p,$r,$subject)` propagates only arg[2]; `intval($x)` sanitizes SQL/XSS/CMD; `count($arr)` returns clean int.
- **Object Property Taint Tracking** - `$obj->prop = $_GET['x']; echo $obj->prop;` now tracked. Properties stored as `$obj->prop` keys in taint environment. Setter methods (`set*`, `add*`, `assign*`) propagate taint to object.
- **Type-Hint Sanitization** - `function foo(int $id)` automatically sanitizes SQL/XSS/CMD taint types. PHP enforces type coercion at runtime, so typed parameters are safe for those injection categories. Covers `int`, `float`, `bool` hints.
- **Class-Aware Method Resolution** - `ClassInfo` extraction with parent class, interfaces, methods, properties, constructor params. Methods registered as `ClassName::methodName` with backward-compatible simple name fallback.
- **Cross-File Class Resolution** - `use App\Models\User;` + `$user = new User();` + `$user->getName()` resolved across files via PSR-4 namespace mapping and per-file use-alias tracking.
- **Interprocedural Call Graph Enhancement** - `$var = new Foo(); $var->bar()` resolved to `Foo::bar()` via local variable-to-class mapping. Namespace aliases used for disambiguation.

### v11 Changes
- **Alias Analysis Integration** - Andersen's points-to analysis connected to taint engine.
- **Array Element-Level Taint** - Per-key taint tracking on arrays.
- **Word-Boundary Variable Matching** - Regex word boundaries in inter-procedural checks.
- **PHP Magic Method Tracking** - Deserialization gadget chain tracking.
- **extract() Taint Propagation** - `extract($tainted)` marks unknown variables as tainted.
- **SSA Use-Def Chains** - Variable uses mapped to SSA definitions.
- **TOCTOU Detection Fixed** - Race condition detection across line boundaries.
- **Code Cleanup** - 4,420 comment/docstring lines stripped.

## What's in v4.0

- **YAML Rule Engine** - All sources, sinks, sanitizers, patterns externalized to `rules/` YAML files.
- **SSA (Static Single Assignment)** - Variable versioning with phi nodes and dominator tree for precise branch-aware taint tracking.
- **Abstract Interpretation** - Lattice-based taint analysis (BOTTOM < UNTAINTED < WEAK < TAINTED < TOP) with widening for loop termination.
- **String Domain Analysis** - Tracks string construction via concatenation/interpolation, determines if tainted fragment is in a safe SQL/XSS position.
- **Context-Sensitive Inter-procedural Analysis (k-CFA)** - k=2 call-site sensitivity, Tarjan SCC for recursive groups, function summaries with argument-to-parameter binding.
- **Points-to / Alias Analysis** - Andersen's inclusion-based analysis for PHP references and object properties.
- **Type Inference** - PHP type narrowing (`is_int()`, `(int)`, `settype()`) to eliminate false positives when variable is proven safe.
- **Framework Deep Models** - YAML-driven validation constraint modeling for Laravel, Symfony, WordPress, etc.
- **Incremental Analysis** - SHA-256 content hash caching with dependency-aware invalidation.
- **ML v6 Classifier** - GradientBoosting with asymmetric weights (TP=3.5x, FP=1.0x), F2-optimized scoring, 3-class output.

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
├── train_ml_v3.py                 # ML training pipeline
├── core/
│   ├── ts_adapter.py              # Tree-sitter PHP parser adapter
│   ├── cfg.py                     # Control flow graph builder
│   ├── ssa.py                     # SSA builder (phi nodes, dominators)
│   ├── abstract_interp.py         # Abstract interpretation engine
│   ├── string_domain.py           # String fragment analysis
│   ├── type_inference.py          # PHP type inference
│   ├── alias_analysis.py          # Points-to / alias analysis (Andersen's)
│   ├── taint_engine.py            # AST walk + CFG taint analysis
│   ├── unified_scanner.py         # 135-pattern scanner + multiline detection
│   ├── interprocedural_v2.py      # k-CFA inter-procedural engine (active)
│   ├── interprocedural.py         # Basic inter-procedural analysis (legacy)
│   ├── rule_engine.py             # YAML rule loader
│   ├── framework_models.py        # Framework validation modeling
│   ├── frameworks.py              # Framework detection + CWE mapping
│   ├── ml_fp_classifier.py        # ML false positive classifier
│   ├── fp_prefilter.py            # FP pre-filter
│   ├── fp_filter.py               # FP filter
│   ├── fp_filter_v2.py            # Consolidated FP filter v2
│   ├── context_analyzer.py        # Context-aware analysis
│   ├── incremental.py             # Incremental analysis cache
│   ├── symbolic_executor.py       # Symbolic execution engine
│   ├── apex_core.py               # Main orchestrator
│   ├── html_report.py             # HTML report with charts
│   └── llm_analyzer.py            # Ollama + Anthropic LLM backend
├── rules/
│   ├── sources.yml                # 15 taint sources
│   ├── sinks.yml                  # 78 dangerous sinks
│   ├── sanitizers.yml             # 98 sanitizer functions
│   ├── patterns.yml               # 135 vulnerability patterns
│   ├── builtin_sigs.yml           # 120+ PHP function taint propagation signatures
│   ├── fp_rules.yml               # 50 false positive rules
│   └── frameworks/                # 10 framework configs
├── models/
│   └── apex_fp_classifier_v4.pkl  # Trained ML model
└── tests/                         # 172 tests, 14 test files
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
  |  dominators,    |  |  narrowing)      |  |  points-to,      |
  |  use-def)       |  |                  |  |  taint-connected) |
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
  |  tracking)      |  |  30 vuln types,    |  | (Tarjan SCC,        |
  +-----------------+  |  multiline TOCTOU)  |  |  word-boundary,     |
                       +--------------------+  |  magic methods)     |
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
          |  3-class output) |    |                  |
          +------------------+    +------------------+
                    |                       |
                    v                       v
              +-------------------------------+
              | Reports (Text/JSON/SARIF/HTML) |
              +-------------------------------+
```

## ML FP Classifier

### Model: `apex_fp_classifier_v4.pkl` (v6)

| Metric | Value |
|--------|-------|
| Algorithm | GradientBoosting (asymmetric weights) |
| Features | 30 |
| Training samples | 4,701 (2,456 TP, 2,245 FP) |
| Weight ratio | TP=3.5x, FP=1.0x (recall-biased) |
| Optimization | F2 score (recall 2x more important) |
| F2 Score | 0.945 |
| TP Recall | 99% |
| Model size | 392 KB |

### 3-Class Output

| Class | Score Range | Meaning |
|-------|------------|---------|
| SAFE | < 0.30 | High confidence false positive |
| SUSPICIOUS | 0.30 - 0.55 | Needs manual review |
| VULNERABLE | > 0.55 | High confidence true positive |

## Vulnerability Coverage

### 30 Vulnerability Types, 135 Patterns

| OWASP | Category | Types | CWEs |
|-------|----------|-------|------|
| A01 | Broken Access Control | Path Traversal, IDOR, Open Redirect, File Read/Write | CWE-22, CWE-639, CWE-601, CWE-73 |
| A02 | Cryptographic Failures | Weak Crypto, Hardcoded Credentials, Insecure Randomness | CWE-327, CWE-798, CWE-330 |
| A03 | Injection | SQLi, CMDi, Code Injection, LDAP, XPath, SSTI, Header Injection, Log Injection | CWE-89, CWE-78, CWE-94, CWE-90, CWE-643, CWE-1336, CWE-113, CWE-117 |
| A04 | Insecure Design | Mass Assignment, Type Juggling, Race Condition (TOCTOU) | CWE-915, CWE-843, CWE-362 |
| A05 | Security Misconfiguration | XXE, Information Disclosure | CWE-611, CWE-200 |
| A07 | Auth Failures | Authentication Bypass, Type Juggling | CWE-287, CWE-843 |
| A08 | Data Integrity | Deserialization, CSRF, Unsafe File Upload | CWE-502, CWE-352, CWE-434 |
| A09 | Logging Failures | Log Injection | CWE-117 |
| A10 | SSRF | Server-Side Request Forgery | CWE-918 |

Plus: XSS (CWE-79), File Inclusion LFI/RFI (CWE-98), NoSQL Injection (CWE-943), Remote Code Execution (CWE-94), Regex DoS (CWE-1333)

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
| Custom CMS | Auto | Custom sanitizers | Custom DB functions | Custom filters |

## Benchmark Results

### Real-World CMS Scans

| Application | PHP Files | Findings | Critical | High | Top Vulnerability Types |
|-------------|-----------|----------|----------|------|------------------------|
| DVWA | 169 | 61 | 0 | 61 | XXE (13), IDOR (11), SQLi (10), CMDi (6) |
| XVWA | 304 | 24 | 1 | 23 | XSS (6), SQLi (5), Path Traversal (3) |
| WebGoatPHP | 908 | 14 | 0 | 14 | XSS (10), XPath (1), SSRF (1), XXE (1) |
| OWASP VWA | 28 | 17 | 1 | 16 | SQLi (6), File Inclusion (4), XSS (3), CMDi (3) |

### NIST/Stivalet Benchmark (42,212 PHP files)

| Version | Recall | Precision | F1 | Findings |
|---------|--------|-----------|-----|----------|
| v1 (baseline scanner) | 16.2% | 27.6% | 20.4% | 12,671 |
| v2 (+ML retraining) | 19.6% | 29.4% | 23.5% | 14,644 |
| v3 (+array taint, cast, 3-class ML) | 24.6% | 29.1% | 26.7% | 19,345 |

## Test Suite: 172 Tests

| Test File | Tests | Coverage |
|-----------|-------|----------|
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
| test_precision_recall.py | 10 | End-to-end precision/recall on fixtures |
| test_incremental.py | 8 | Cache hit/miss, dependency tracking, invalidation |

## Codebase Stats

| Metric | Value |
|--------|-------|
| Total code | ~26,000 lines |
| Core modules | 36 Python files |
| YAML rules | 16 files (sources, sinks, sanitizers, patterns, builtin_sigs, frameworks) |
| Test files | 14 files, 172 tests |
| ML model | 392 KB, 30 features, 4,701 training samples |
| Datasets tested | 11 projects, 49,000+ PHP files |

## Example Output

```
APEX v12 - Security Analysis Report
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
