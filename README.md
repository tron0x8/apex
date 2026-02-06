<p align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=JetBrains+Mono&weight=700&size=24&duration=3000&pause=1000&color=00FF00&center=true&vCenter=true&width=200&lines=Tron" alt="Tron" />
</p>

# APEX - Advanced PHP Exploitation Scanner

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License MIT">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/CWE-40%2B%20rules-orange.svg" alt="CWE Coverage">
  <img src="https://img.shields.io/badge/frameworks-Laravel%20%7C%20Symfony%20%7C%20WordPress-green.svg" alt="Framework Support">
</p>

## Overview

APEX is a static security analysis framework for PHP applications. It combines multiple analysis techniques to detect security vulnerabilities with high accuracy and low false-positive rates.

```
    +===========================================================================+
    |      _    ____  _______  __                                               |
    |     / \  |  _ \| ____\ \/ /                                               |
    |    / _ \ | |_) |  _|  \  /                                                |
    |   / ___ \|  __/| |___ /  \                                                |
    |  /_/   \_\_|   |_____/_/\_\                                               |
    |                                                                           |
    |  Advanced PHP Exploitation Scanner                                        |
    +===========================================================================+
```

## Features

### Multi-Layer Analysis Engine

- **Pattern Matching** - 40+ vulnerability patterns with regex-based detection
- **Taint Tracking** - Source to sink data flow analysis
- **ML Scoring** - LightGBM classifier with 93% accuracy
- **Inter-procedural Analysis** - Cross-function taint flow with call graph
- **Framework Support** - Laravel, Symfony, CodeIgniter, WordPress, DLE

### Vulnerability Detection (40+ CWE)

| Type | CWE | Severity |
|------|-----|----------|
| SQL Injection | CWE-89 | CRITICAL |
| Command Injection | CWE-78 | CRITICAL |
| Code Injection (eval/assert) | CWE-94 | CRITICAL |
| Deserialization | CWE-502 | CRITICAL |
| PHAR Deserialization | CWE-502 | CRITICAL |
| File Inclusion (LFI/RFI) | CWE-98 | CRITICAL |
| Server-Side Template Injection | CWE-1336 | CRITICAL |
| XSS (Reflected/Stored/DOM) | CWE-79 | HIGH |
| Path Traversal | CWE-22 | HIGH |
| SSRF | CWE-918 | HIGH |
| XXE | CWE-611 | HIGH |
| LDAP Injection | CWE-90 | HIGH |
| XPath Injection | CWE-643 | HIGH |
| Insecure File Upload | CWE-434 | HIGH |
| Mass Assignment | CWE-915 | HIGH |
| Open Redirect | CWE-601 | MEDIUM |
| Header Injection | CWE-113 | MEDIUM |
| Hardcoded Credentials | CWE-798 | MEDIUM |
| Weak Cryptography | CWE-327 | MEDIUM |
| Weak Random | CWE-330 | MEDIUM |
| Type Juggling | CWE-843 | MEDIUM |
| Log Injection | CWE-117 | LOW |
| Debug Enabled | CWE-489 | LOW |
| Insecure Cookie | CWE-614 | LOW |

### Framework Support

| Framework | Detection | Sanitizers | Sources | Sinks |
|-----------|-----------|------------|---------|-------|
| Laravel | Auto | Eloquent, Blade, Validator | Request facade | DB::raw, whereRaw |
| Symfony | Auto | Doctrine, Twig, ParamConverter | Request object | createQuery |
| CodeIgniter | Auto | Query Builder, xss_clean | Input class | simple_query |
| WordPress | Auto | $wpdb->prepare, esc_* | Superglobals | $wpdb->query |
| Drupal | Auto | db_select, Html::escape | Request object | db_query |

### Output Formats

- **JSON** - Machine-readable format for integration
- **SARIF** - Static Analysis Results Interchange Format (IDE/GitHub integration)
- **Text** - Human-readable report

### CI/CD Integration

APEX includes GitHub Actions workflow for automated security scanning:

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
          python /tmp/apex/apex.py . -f sarif -o results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Installation

```bash
git clone https://github.com/tron0x8/apex.git
cd apex
pip install -r requirements.txt
```

## Usage

### Basic Scan

```bash
python apex.py /path/to/php/project
```

### Analysis Modes

```bash
# Quick scan (pattern matching + taint analysis)
python apex.py -m quick /path/to/project

# Standard scan (+ symbolic execution)
python apex.py -m standard /path/to/project

# Full scan (+ inter-procedural analysis)
python apex.py -m full /path/to/project
```

### Output Options

```bash
# JSON output
python apex.py -f json -o report.json /path/to/project

# SARIF output (for VS Code, GitHub Code Scanning)
python apex.py -f sarif -o report.sarif /path/to/project

# Text report
python apex.py -f text /path/to/project
```

### Advanced Options

```bash
python apex.py --help

Options:
  target              Target file or directory
  -m, --mode          Analysis mode: quick, standard, full
  -o, --output        Output file path
  -f, --format        Output format: json, sarif, text
  -w, --workers       Parallel workers (default: 4)
  -v, --verbose       Verbose output
```

## Architecture

```
apex/
├── apex.py
├── core/
│   ├── php_parser.py
│   ├── taint_engine.py
│   ├── taint_tracker.py
│   ├── unified_scanner.py
│   ├── symbolic_executor.py
│   ├── interprocedural.py
│   ├── patterns.py
│   ├── fp_prefilter.py
│   ├── frameworks.py
│   └── apex_core.py
├── ml/
│   ├── train_v8.py
│   ├── vuln_model_v8.pkl
│   └── training_data/
├── .github/
│   └── workflows/
│       └── apex-scan.yml
└── README.md
```

### Analysis Pipeline

```
┌─────────────────┐    ┌──────────────────┐    ┌────────────────────┐
│   PHP Source    │───>│   PHP Lexer      │───>│    AST Parser      │
│     Files       │    │   (Tokenizer)    │    │ (Recursive Descent)│
└─────────────────┘    └──────────────────┘    └────────────────────┘
         │                                               │
         v                                               v
┌─────────────────┐                          ┌────────────────────┐
│    Framework    │                          │  Pattern Scanner   │
│    Detection    │                          │   (40+ patterns)   │
└─────────────────┘                          └────────────────────┘
         │                                               │
         v                                               v
┌─────────────────────────────────────────────────────────────────────┐
│                        Analysis Engines                              │
├─────────────────┬──────────────────────┬────────────────────────────┤
│ Taint Analysis  │ Symbolic Execution   │ Inter-procedural Analysis  │
│                 │                      │                            │
│ - Source track  │ - Path constraints   │ - Call graph               │
│ - Sink detect   │ - Branch forking     │ - Function summaries       │
│ - FW sanitizers │ - Loop unrolling     │ - Fixed-point iteration    │
└─────────────────┴──────────────────────┴────────────────────────────┘
         │                    │                          │
         v                    v                          v
┌─────────────────────────────────────────────────────────────────────┐
│                     False Positive Filtering                         │
│                                                                      │
│  - Context-aware sanitizer detection                                 │
│  - Framework-specific safe patterns                                  │
│  - Confidence scoring                                                │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                v
                    ┌───────────────────────┐
                    │   Vulnerability       │
                    │   Reports             │
                    │  (JSON/SARIF/Text)    │
                    └───────────────────────┘
```

## Example Output

### JSON Report

```json
{
  "summary": {
    "total_findings": 5,
    "critical": 2,
    "high": 2,
    "medium": 1,
    "low": 0
  },
  "framework": "Laravel",
  "findings": [
    {
      "type": "SQL_INJECTION",
      "severity": "CRITICAL",
      "file": "app/Http/Controllers/UserController.php",
      "line": 45,
      "sink": "DB::raw",
      "source": "Request:id",
      "cwe": "CWE-89",
      "confidence": 0.95,
      "remediation": "Use parameterized queries or Eloquent ORM"
    }
  ]
}
```

### Terminal Output

```
======================================================================
APEX Security Analysis Report
======================================================================

Framework Detected: Laravel
Files Scanned: 156
Functions Analyzed: 423
Patterns Matched: 12
Time Elapsed: 8.34s

SUMMARY
----------------------------------------------------------------------
CRITICAL: 2
HIGH: 2
MEDIUM: 1
LOW: 0

FINDINGS
----------------------------------------------------------------------

[1] SQL_INJECTION (CRITICAL) [Confidence: 95%]
    File: app/Http/Controllers/UserController.php:45
    Sink: DB::raw
    Source: Request:id
    CWE: CWE-89

[2] DESERIALIZATION (CRITICAL) [Confidence: 90%]
    File: app/Services/CacheService.php:78
    Sink: unserialize
    Source: Cookie:data
    CWE: CWE-502
```

## Taint Sources

### PHP Superglobals
- `$_GET` - URL query parameters
- `$_POST` - POST form data
- `$_REQUEST` - Combined GET/POST/COOKIE
- `$_COOKIE` - HTTP cookies
- `$_FILES` - Uploaded files
- `$_SERVER` - Server variables

### Framework-Specific
- Laravel: `$request->input()`, `Request::get()`
- Symfony: `$request->query->get()`, `$request->request->get()`
- CodeIgniter: `$this->input->get()`, `$this->request->getVar()`
- WordPress: `get_query_var()`

## Sanitizers

### Native PHP
| Function | Protects Against |
|----------|-----------------|
| `intval()` | SQL Injection, XSS, Path Traversal |
| `htmlspecialchars()` | XSS |
| `htmlentities()` | XSS |
| `addslashes()` | SQL Injection |
| `mysqli_real_escape_string()` | SQL Injection |
| `PDO::quote()` | SQL Injection |
| `escapeshellarg()` | Command Injection |
| `escapeshellcmd()` | Command Injection |
| `basename()` | Path Traversal, File Inclusion |
| `realpath()` | Path Traversal |
| `filter_var()` | XSS, SQL Injection, SSRF |

### Framework-Specific
| Framework | Sanitizers |
|-----------|------------|
| Laravel | `$request->validate()`, Eloquent ORM, Blade `{{ }}` |
| Symfony | `->setParameter()`, Twig `{{ }}`, `@Assert` |
| WordPress | `$wpdb->prepare()`, `esc_html()`, `wp_kses()` |
| CodeIgniter | `$this->db->escape()`, `xss_clean()` |

## Contributing

Contributions are welcome. Please submit pull requests with:

1. Clear description of changes
2. Test cases for new vulnerability patterns
3. Documentation updates

### Adding New Patterns

Edit `core/patterns.py`:

```python
VulnPattern(
    name="MY_NEW_VULN",
    pattern=r'dangerous_function\s*\(\s*\$_GET',
    severity="HIGH",
    cwe="CWE-XXX",
    description="Description of the vulnerability",
    confidence=0.85,
    false_positive_patterns=[r'sanitizer\s*\(']
)
```

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
