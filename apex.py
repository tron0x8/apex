#!/usr/bin/env python3
"""
APEX - Advanced PHP Exploitation Scanner v4.0

A comprehensive PHP security scanner with:
- Pattern-based vulnerability detection (55+ vuln types, 164 patterns)
- Taint tracking and data flow analysis
- Cross-file taint analysis (include resolution, global state, PSR-4)
- ML-based false positive filtering (ensemble classifier)
- Framework-aware analysis (Laravel, Symfony, WordPress, etc.)
- LLM-powered deep analysis (optional)

Usage:
    apex /path/to/project                    # Standard scan (recommended)
    apex /path/to/project -m quick           # Fast pattern-only scan
    apex /path/to/project -m deep            # Full analysis with LLM
    apex /path/to/project -f html -o report  # HTML report
"""

import sys
import os
import argparse
import json
import glob
import time
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

# Add core to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'core'))

VERSION = "4.0"

# ── Color helpers (auto-disable on non-TTY or Windows without colorama) ──────

_COLOR_ENABLED = hasattr(sys.stderr, 'isatty') and sys.stderr.isatty()

try:
    if os.name == 'nt':
        os.system('')  # Enable ANSI on Windows 10+
except Exception:
    pass

def _c(code: str, text: str) -> str:
    if not _COLOR_ENABLED:
        return text
    return f"\033[{code}m{text}\033[0m"

def _red(t):    return _c("31", t)
def _green(t):  return _c("32", t)
def _yellow(t): return _c("33", t)
def _cyan(t):   return _c("36", t)
def _bold(t):   return _c("1", t)
def _dim(t):    return _c("2", t)

def _severity_color(sev: str) -> str:
    colors = {'CRITICAL': "31;1", 'HIGH': "31", 'MEDIUM': "33", 'LOW': "36"}
    return _c(colors.get(sev, "0"), sev)


# ── Progress output (stderr) ─────────────────────────────────────────────────

_quiet = False

def _progress(msg: str, prefix: str = "[*]"):
    """Print progress/status to stderr (not mixed with results)."""
    if _quiet:
        return
    print(f"{_cyan(prefix)} {msg}", file=sys.stderr)

def _success(msg: str):
    _progress(msg, _green("[+]"))

def _warn(msg: str):
    _progress(msg, _yellow("[!]"))

def _error(msg: str):
    print(f"{_red('[ERROR]')} {msg}", file=sys.stderr)


# ── Scan mode presets ─────────────────────────────────────────────────────────

MODES = {
    'quick': {
        'ml': False, 'llm': False, 'cross_file': False,
        'description': 'Fast pattern + taint scan (~10-30s)',
    },
    'standard': {
        'ml': True, 'llm': False, 'cross_file': True,
        'description': 'Pattern + taint + ML filtering + cross-file (~1-5m)',
    },
    'deep': {
        'ml': True, 'llm': True, 'cross_file': True,
        'description': 'Full analysis with LLM verification (~10-30m, requires Ollama)',
    },
}


# ── Banner ────────────────────────────────────────────────────────────────────

def print_banner():
    banner = f"""
    +===============================================================+
    |      _    ____  _______  __                                   |
    |     / \\  |  _ \\| ____\\ \\/ /                                   |
    |    / _ \\ | |_) |  _|  \\  /                                    |
    |   / ___ \\|  __/| |___ /  \\                                    |
    |  /_/   \\_\\_|   |_____/_/\\_\\   v{VERSION}                            |
    |                                                               |
    |  Advanced PHP Exploitation Scanner                            |
    |  Pattern + Taint + ML + Cross-File Analysis                   |
    +===============================================================+
    """
    print(banner, file=sys.stderr)


# ── Pre-scan validation ──────────────────────────────────────────────────────

def validate_environment(args) -> List[str]:
    """Check all prerequisites before scanning. Returns list of errors."""
    errors = []

    if not os.path.exists(args.target):
        errors.append(f"Target not found: {args.target}")
        if os.path.exists(args.target + '.php'):
            errors.append(f"  Did you mean: {args.target}.php?")

    if not os.access(args.target, os.R_OK) and os.path.exists(args.target):
        errors.append(f"Cannot read target: {args.target} (permission denied)")

    # Check scanner dependencies
    try:
        from core.unified_scanner import UnifiedScanner
    except ImportError as e:
        errors.append(f"Scanner module not available: {e}")
        errors.append("  Fix: pip install tree-sitter tree-sitter-php")

    # Check ML if needed
    mode = MODES.get(getattr(args, 'mode', 'standard'), {})
    use_ml = getattr(args, 'ml', False) or mode.get('ml', False)
    if use_ml:
        try:
            import sklearn
        except ImportError:
            errors.append("ML requires scikit-learn: pip install scikit-learn")

    # Check LLM if needed
    use_llm = getattr(args, 'llm', False) or mode.get('llm', False)
    if use_llm:
        try:
            from core.llm_analyzer import LLMAnalyzer
        except ImportError:
            errors.append("LLM module not available: pip install anthropic")

    return errors


# ── File scanning ─────────────────────────────────────────────────────────────

def scan_file(filepath: str, scanner, verbose: bool = False) -> List[Dict]:
    """Scan a single PHP file."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
        findings = scanner.scan_code(code, filepath)
        return findings
    except Exception as e:
        if verbose:
            _warn(f"Error scanning {filepath}: {e}")
        return []


# Vendor/library paths to skip
VENDOR_SKIP_DIRS = {
    'vendor', 'node_modules', 'composer', 'bower_components',
    'htmlpurifier', 'phpseclib', 'phpmailer', 'guzzle', 'guzzlehttp',
    'aws', 'aws-sdk', 'symfony', 'laravel', 'illuminate',
    'monolog', 'psr', 'doctrine', 'twig', 'swiftmailer',
    'phpunit', 'mockery', 'fzaninotto', 'fakerphp',
    'league', 'nesbot', 'carbon', 'ramsey', 'nikic',
    'paragonie', 'defuse', 'firebase', 'google',
    '.git', '.svn', '__pycache__', 'cache', 'tmp',
}


def _is_vendor_path(filepath: str) -> bool:
    parts = Path(filepath).parts
    for part in parts:
        if part.lower() in VENDOR_SKIP_DIRS:
            return True
    return False


def scan_directory(dirpath: str, scanner, verbose: bool = False,
                   skip_vendor: bool = True) -> Dict:
    """Scan all PHP files in directory with progress reporting."""
    results = {
        'scan_date': datetime.now().isoformat(),
        'target': dirpath,
        'total_files': 0,
        'total_findings': 0,
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'findings': [],
        'skipped_vendor_files': 0,
    }

    php_files = glob.glob(os.path.join(dirpath, '**', '*.php'), recursive=True)

    if skip_vendor:
        original_count = len(php_files)
        php_files = [f for f in php_files if not _is_vendor_path(f)]
        results['skipped_vendor_files'] = original_count - len(php_files)
        if results['skipped_vendor_files'] > 0:
            _progress(f"Skipped {results['skipped_vendor_files']} vendor/library files")

    results['total_files'] = len(php_files)
    total = len(php_files)
    _progress(f"Scanning {total} PHP files...")

    for i, filepath in enumerate(php_files):
        # Progress bar to stderr
        if not _quiet and total > 20:
            pct = (i + 1) / total
            bar_len = 30
            filled = int(bar_len * pct)
            bar = '=' * filled + '-' * (bar_len - filled)
            speed = (i + 1) / max(time.time() - _scan_start_time, 0.001)
            eta = (total - i - 1) / max(speed, 0.001)
            print(f"\r  [{bar}] {i+1}/{total} ({pct:.0%}) ETA: {eta:.0f}s   ",
                  end='', file=sys.stderr)

        findings = scan_file(filepath, scanner, verbose)

        for f in findings:
            results['total_findings'] += 1
            sev = f.severity.name if hasattr(f.severity, 'name') else str(f.severity)
            if sev == 'CRITICAL':
                results['critical'] += 1
            elif sev == 'HIGH':
                results['high'] += 1
            elif sev == 'MEDIUM':
                results['medium'] += 1
            else:
                results['low'] += 1

            finding_dict = f.to_dict() if hasattr(f, 'to_dict') else {
                'file': filepath,
                'line': getattr(f, 'line', 0),
                'severity': sev,
                'type': getattr(f, 'vuln_type', ''),
                'code': getattr(f, 'code', ''),
                'confidence': getattr(f, 'confidence', 0),
            }
            results['findings'].append(finding_dict)

    # Clear progress bar
    if not _quiet and total > 20:
        print('\r' + ' ' * 70 + '\r', end='', file=sys.stderr)

    return results


# ── Cross-file analysis ──────────────────────────────────────────────────────

def run_cross_file_analysis(dirpath: str, results: Dict, verbose: bool = False) -> Dict:
    """Run cross-file taint analysis and add findings."""
    try:
        from core.cross_file_analyzer import CrossFileAnalyzer
        analyzer = CrossFileAnalyzer(dirpath)

        # Collect PHP files
        php_files = glob.glob(os.path.join(dirpath, '**', '*.php'), recursive=True)
        php_files = [f for f in php_files if not _is_vendor_path(f)]

        _progress("Cross-file analysis: resolving includes...")
        context = analyzer.analyze_project(project_root=dirpath, php_files=php_files)

        n_includes = sum(len(v) for v in context.include_graph.values())
        n_globals = sum(len(v) for v in context.global_vars.values())
        n_namespaces = len(context.namespace_map)

        _progress(f"  Include edges: {n_includes}, Global vars: {n_globals}, "
                  f"Namespaces: {n_namespaces}")

        if context.cross_file_flows:
            _success(f"  Found {len(context.cross_file_flows)} cross-file taint flows!")
            for flow in context.cross_file_flows:
                finding = {
                    'type': flow.vuln_type,
                    'severity': flow.severity,
                    'line': flow.sink_line,
                    'code': flow.sink_code[:100],
                    'file': flow.sink_file,
                    'confidence': f"{flow.confidence:.0%}",
                    'source': flow.source_type,
                    'sink': flow.vuln_type,
                    'sanitizers': [],
                    'cross_file': True,
                    'source_file': flow.source_file,
                    'source_line': flow.source_line,
                    'flow_path': flow.flow_path,
                }
                results['findings'].append(finding)
                results['total_findings'] += 1

                sev = flow.severity
                if sev == 'CRITICAL':
                    results['critical'] += 1
                elif sev == 'HIGH':
                    results['high'] += 1
                elif sev == 'MEDIUM':
                    results['medium'] += 1
                else:
                    results['low'] += 1

        results['cross_file_stats'] = {
            'include_edges': n_includes,
            'global_vars': n_globals,
            'namespace_mappings': n_namespaces,
            'cross_file_findings': len(context.cross_file_flows),
        }

    except ImportError:
        if verbose:
            _warn("Cross-file analyzer not available")
    except Exception as e:
        _warn(f"Cross-file analysis error: {e}")

    return results


# ── Results display (stdout only) ─────────────────────────────────────────────

def print_results(results: Dict, verbose: bool = False):
    """Print scan results to stdout."""
    print("\n" + "=" * 70)
    print(_bold("SCAN RESULTS"))
    print("=" * 70)

    print(f"\nTarget: {results['target']}")
    print(f"Files scanned: {results['total_files']}")
    if results.get('skipped_vendor_files'):
        print(f"Vendor files skipped: {results['skipped_vendor_files']}")
    print(f"Total findings: {_bold(str(results['total_findings']))}")
    if results.get('scan_time_seconds'):
        print(f"Scan time: {results['scan_time_seconds']}s")

    print(f"\n  {_severity_color('CRITICAL')}: {results['critical']}")
    print(f"  {_severity_color('HIGH')}:     {results['high']}")
    print(f"  {_severity_color('MEDIUM')}:   {results['medium']}")
    print(f"  {_severity_color('LOW')}:      {results['low']}")

    # Risk score
    risk = min(100, results.get('critical', 0) * 25 + results.get('high', 0) * 10 +
               results.get('medium', 0) * 3 + results.get('low', 0))
    risk_label = ('CRITICAL' if risk >= 75 else 'HIGH' if risk >= 50 else
                  'MEDIUM' if risk >= 25 else 'LOW')
    print(f"\n  Risk Score: {_bold(str(risk))}/100 ({_severity_color(risk_label)})")

    # Filter stats
    if results.get('ml_fps_eliminated'):
        print(f"  ML FPs eliminated: {results['ml_fps_eliminated']}")
    if results.get('llm_fps_eliminated'):
        print(f"  LLM FPs eliminated: {results['llm_fps_eliminated']}")
    if results.get('cross_file_stats'):
        cfs = results['cross_file_stats']
        print(f"  Cross-file: {cfs['include_edges']} includes, "
              f"{cfs['cross_file_findings']} cross-file findings")

    # Vulnerability type breakdown
    if results['total_findings'] > 0:
        from collections import Counter
        type_counts = Counter(f.get('type', 'Unknown') for f in results['findings'])
        if len(type_counts) > 1:
            print("\n  Vulnerability Types:")
            for vtype, count in type_counts.most_common(10):
                print(f"    {vtype}: {count}")

        file_counts = Counter(os.path.basename(f.get('file', '')) for f in results['findings'])
        if len(file_counts) > 1:
            print("\n  Most Vulnerable Files:")
            for fname, count in file_counts.most_common(5):
                print(f"    {fname}: {count} findings")

    if results['total_findings'] > 0:
        print("\n" + "-" * 70)
        print(_bold("FINDINGS"))
        print("-" * 70)

        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            severity_findings = [f for f in results['findings']
                                if f.get('severity') == severity]
            if severity_findings:
                print(f"\n[{_severity_color(severity)}] - {len(severity_findings)} findings")

                for f in severity_findings[:10]:
                    file_path = f.get('file', 'unknown')
                    line = f.get('line', 0)
                    vuln_type = f.get('type', f.get('pattern', 'unknown'))
                    confidence = f.get('confidence', '0%')

                    cross_marker = _dim(" [cross-file]") if f.get('cross_file') else ""
                    print(f"\n  {vuln_type}{cross_marker}")
                    print(f"    File: {file_path}:{line}")
                    print(f"    Confidence: {confidence}")

                    if f.get('cross_file') and f.get('source_file'):
                        print(f"    Source: {f['source_file']}:{f.get('source_line', '?')}")

                    if verbose and f.get('code'):
                        code_preview = f['code'][:60].replace('\n', ' ')
                        print(f"    Code: {code_preview}...")

                if len(severity_findings) > 10:
                    print(f"\n  ... and {len(severity_findings) - 10} more {severity} findings")

    # LLM findings
    llm_findings = results.get('llm_findings', [])
    if llm_findings:
        print("\n" + "=" * 70)
        print(f"{_bold('LLM DEEP ANALYSIS FINDINGS')} ({len(llm_findings)} new)")
        print("=" * 70)

        for f in llm_findings:
            sev = f.get('severity', 'MEDIUM')
            print(f"\n  [{_severity_color(sev)}] {f.get('vuln_type', 'Unknown')}")
            print(f"    File: {f.get('file', 'unknown')}:{f.get('line', 0)}")
            if f.get('cwe'):
                print(f"    CWE: {f['cwe']}")
            print(f"    Description: {f.get('description', '')[:120]}")
            if f.get('attack_scenario'):
                print(f"    Attack: {f['attack_scenario'][:120]}")
            if verbose and f.get('fix'):
                print(f"    Fix: {f['fix'][:120]}")
            print(f"    Layer: {f.get('layer', 'deep_hunt')}")


# ── SARIF generation ──────────────────────────────────────────────────────────

def generate_sarif(results: Dict, target: str) -> Dict:
    """Generate SARIF format output for GitHub Code Scanning."""

    severity_map = {
        'CRITICAL': 'error', 'HIGH': 'error',
        'MEDIUM': 'warning', 'LOW': 'note'
    }

    cwe_map = {
        'SQL Injection': 'CWE-89',
        'Cross-Site Scripting': 'CWE-79',
        'Command Injection': 'CWE-78',
        'Code Injection': 'CWE-94',
        'File Inclusion': 'CWE-98',
        'Path Traversal': 'CWE-22',
        'Arbitrary File Write': 'CWE-434',
        'Arbitrary File Read': 'CWE-22',
        'Server-Side Request Forgery': 'CWE-918',
        'Insecure Deserialization': 'CWE-502',
        'Open Redirect': 'CWE-601',
        'Remote Code Execution': 'CWE-94',
        'Type Juggling': 'CWE-697',
        'Weak Cryptography': 'CWE-327',
        'Hardcoded Credentials': 'CWE-798',
        'Information Disclosure': 'CWE-200',
        'Insecure Direct Object Reference': 'CWE-639',
        'Authentication Bypass': 'CWE-287',
        'Cross-Site Request Forgery': 'CWE-352',
        'Unsafe File Upload': 'CWE-434',
        'XML External Entity': 'CWE-611',
        'HTTP Header Injection': 'CWE-113',
        'Mass Assignment': 'CWE-915',
        'Insecure Randomness': 'CWE-330',
        'Race Condition': 'CWE-362',
        'Log Injection': 'CWE-117',
        'Regular Expression DoS': 'CWE-1333',
        'LDAP Injection': 'CWE-90',
        'Template Injection': 'CWE-1336',
    }

    rules = []
    rule_ids = set()
    sarif_results = []

    for finding in results.get('findings', []):
        vuln_type = finding.get('type', 'Unknown')
        rule_id = vuln_type.replace(' ', '_').upper()

        if rule_id not in rule_ids:
            rule_ids.add(rule_id)
            rules.append({
                'id': rule_id,
                'name': vuln_type,
                'shortDescription': {'text': vuln_type},
                'fullDescription': {'text': f'Potential {vuln_type} vulnerability detected'},
                'helpUri': f'https://cwe.mitre.org/data/definitions/{cwe_map.get(vuln_type, "CWE-1035").split("-")[1]}.html',
                'properties': {
                    'tags': ['security', cwe_map.get(vuln_type, 'CWE-1035')],
                    'precision': 'medium',
                    'security-severity': '7.5' if finding.get('severity') in ['CRITICAL', 'HIGH'] else '5.0'
                }
            })

        file_path = finding.get('file', '')
        if not os.path.isabs(file_path):
            file_path = os.path.join(target, file_path) if os.path.isdir(target) else file_path

        sarif_results.append({
            'ruleId': rule_id,
            'level': severity_map.get(finding.get('severity', 'MEDIUM'), 'warning'),
            'message': {
                'text': f"{vuln_type} vulnerability detected. Confidence: {finding.get('confidence', 'N/A')}"
            },
            'locations': [{
                'physicalLocation': {
                    'artifactLocation': {
                        'uri': file_path.replace('\\', '/'),
                        'uriBaseId': '%SRCROOT%'
                    },
                    'region': {
                        'startLine': finding.get('line', 1),
                        'startColumn': 1
                    }
                }
            }],
            'properties': {
                'confidence': finding.get('confidence', 'N/A'),
                'source': finding.get('source'),
                'sanitizers': finding.get('sanitizers', [])
            }
        })

    sarif = {
        '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {
                'driver': {
                    'name': 'APEX',
                    'version': VERSION,
                    'informationUri': 'https://github.com/tron0x8/apex',
                    'rules': rules
                }
            },
            'results': sarif_results,
            'invocations': [{
                'executionSuccessful': True,
                'endTimeUtc': datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
            }]
        }]
    }

    return sarif


# ── Main entry point ──────────────────────────────────────────────────────────

_scan_start_time = 0.0

def main():
    """Main entry point."""
    global _quiet, _scan_start_time

    parser = argparse.ArgumentParser(
        description='APEX - Advanced PHP Exploitation Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Scan Modes:
  quick      Fast pattern + taint scan (~10-30s)
  standard   Pattern + taint + ML + cross-file (~1-5m) [DEFAULT]
  deep       Full analysis with LLM (~10-30m, requires Ollama)

Examples:
  %(prog)s /var/www/html                        Standard scan
  %(prog)s /var/www/html -m quick               Fast scan
  %(prog)s /var/www/html -m deep                Deep LLM analysis
  %(prog)s /path/to/project -f html -o report   HTML report
  %(prog)s /path/to/project -f sarif -o out     GitHub Code Scanning
  %(prog)s /path/to/file.php -v                 Verbose single file

Output Formats:
  text   Console output with severity breakdown [DEFAULT]
  html   Interactive web report for stakeholders
  json   Machine-readable for CI/CD pipelines
  sarif  GitHub Code Scanning integration
        '''
    )

    parser.add_argument('target', help='PHP file or directory to scan')
    parser.add_argument('-m', '--mode', choices=['quick', 'standard', 'deep'],
                       default='standard',
                       help='Scan mode: quick, standard (default), deep')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-f', '--format', choices=['json', 'text', 'sarif', 'html'],
                       default='text', help='Output format (default: text)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output with code snippets')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Suppress progress output (results only)')
    parser.add_argument('--no-taint', action='store_true',
                       help='Disable taint tracking (faster but more FPs)')
    parser.add_argument('--include-vendor', action='store_true',
                       help='Include vendor/library files (skipped by default)')
    parser.add_argument('--no-cross-file', action='store_true',
                       help='Disable cross-file taint analysis')

    # ML options
    ml_group = parser.add_argument_group('ML Options')
    ml_group.add_argument('--ml', action='store_true',
                         help='Enable ML filtering (auto-enabled in standard/deep mode)')
    ml_group.add_argument('--no-ml', action='store_true',
                         help='Disable ML filtering even in standard/deep mode')
    ml_group.add_argument('--ml-train', action='store_true',
                         help='Train ML model from fixtures before scanning')

    # LLM options
    llm_group = parser.add_argument_group('LLM Options (deep mode)')
    llm_group.add_argument('--llm', action='store_true',
                          help='Enable LLM analysis (auto-enabled in deep mode)')
    llm_group.add_argument('--llm-backend', choices=['ollama', 'anthropic', 'auto'],
                          default='auto',
                          help='LLM backend: ollama (local), anthropic (API), auto')
    llm_group.add_argument('--llm-model', default=None,
                          help='LLM model name')
    llm_group.add_argument('--ollama-url', default='http://localhost:11434',
                          help='Ollama server URL')
    llm_group.add_argument('--llm-fast', action='store_true',
                          help='CPU-optimized LLM mode')
    llm_group.add_argument('--llm-verify-only', action='store_true',
                          help='Only verify findings, skip deep hunt')
    llm_group.add_argument('--llm-hunt-only', action='store_true',
                          help='Only deep hunt, skip verification')

    parser.add_argument('--version', action='version', version=f'APEX v{VERSION}')

    args = parser.parse_args()

    # Apply mode presets
    mode_cfg = MODES.get(args.mode, MODES['standard'])
    use_ml = (args.ml or mode_cfg.get('ml', False)) and not args.no_ml
    use_llm = args.llm or mode_cfg.get('llm', False)
    use_cross_file = mode_cfg.get('cross_file', False) and not args.no_cross_file

    # Quiet mode
    _quiet = args.quiet

    # Print banner (stderr)
    if not _quiet:
        print_banner()

    # ── Pre-scan validation ──────────────────────────────────────────────
    errors = validate_environment(args)
    if errors:
        for err in errors:
            _error(err)
        return 1

    _progress(f"Mode: {_bold(args.mode)} - {mode_cfg['description']}")

    # ── Initialize scanner ───────────────────────────────────────────────
    try:
        from core.unified_scanner import UnifiedScanner
        scanner = UnifiedScanner()
        _success("Scanner initialized (Pattern + Taint)")
    except ImportError as e:
        _error(f"Could not initialize scanner: {e}")
        _error("  Fix: pip install tree-sitter tree-sitter-php pyyaml")
        return 1

    # ── Scan ─────────────────────────────────────────────────────────────
    _scan_start_time = time.time()
    scan_start = _scan_start_time

    if os.path.isfile(args.target):
        _progress(f"Scanning file: {args.target}")
        findings = scan_file(args.target, scanner, args.verbose)
        finding_dicts = [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings]
        results = {
            'scan_date': datetime.now().isoformat(),
            'target': args.target,
            'total_files': 1,
            'total_findings': len(findings),
            'critical': sum(1 for f in finding_dicts if f.get('severity') == 'CRITICAL'),
            'high': sum(1 for f in finding_dicts if f.get('severity') == 'HIGH'),
            'medium': sum(1 for f in finding_dicts if f.get('severity') == 'MEDIUM'),
            'low': sum(1 for f in finding_dicts if f.get('severity') == 'LOW'),
            'findings': finding_dicts,
        }
    else:
        _progress(f"Scanning directory: {args.target}")
        results = scan_directory(args.target, scanner, args.verbose,
                                skip_vendor=not args.include_vendor)

    scan_elapsed = time.time() - scan_start
    results['scan_time_seconds'] = round(scan_elapsed, 2)
    files_per_sec = results['total_files'] / scan_elapsed if scan_elapsed > 0 else 0
    _success(f"Scan completed in {scan_elapsed:.1f}s ({files_per_sec:.0f} files/sec)")

    # ── Cross-file analysis ──────────────────────────────────────────────
    if use_cross_file and os.path.isdir(args.target):
        _progress("Running cross-file taint analysis...")
        cf_start = time.time()
        results = run_cross_file_analysis(args.target, results, args.verbose)
        cf_elapsed = time.time() - cf_start
        _success(f"Cross-file analysis completed in {cf_elapsed:.1f}s")

    # ── ML filtering ─────────────────────────────────────────────────────
    if use_ml or args.ml_train:
        try:
            from core.ml_fp_classifier import FPClassifier
            classifier = FPClassifier()
            _success(f"ML classifier initialized ({classifier.stats['method']})")

            if args.ml_train:
                _progress("Training ML model...")
                metrics = classifier.train_from_fixtures(verbose=args.verbose)
                if 'error' not in metrics:
                    _progress(f"  Training complete: {metrics.get('n_samples', 0)} samples, "
                              f"CV: {metrics.get('cv_accuracy', 0):.1%}")

            if results.get('findings'):
                ml_file_codes = {}
                if os.path.isdir(args.target):
                    for fp in glob.glob(os.path.join(args.target, '**', '*.php'), recursive=True):
                        if not args.include_vendor and _is_vendor_path(fp):
                            continue
                        try:
                            with open(fp, 'r', encoding='utf-8', errors='ignore') as fh:
                                ml_file_codes[fp] = fh.read()
                        except Exception:
                            pass
                else:
                    try:
                        with open(args.target, 'r', encoding='utf-8', errors='ignore') as fh:
                            ml_file_codes[args.target] = fh.read()
                    except Exception:
                        pass

                pre_count = len(results['findings'])
                _progress(f"ML filter: analyzing {pre_count} findings...")
                results['findings'] = classifier.classify_batch(
                    results['findings'], ml_file_codes
                )
                post_count = len(results['findings'])
                eliminated = pre_count - post_count

                if pre_count > 0:
                    _progress(f"  Eliminated {eliminated} false positives "
                              f"({eliminated/pre_count*100:.0f}% FP rate)")
                _success(f"  Confirmed {post_count} true positives")

                results['total_findings'] = post_count
                results['critical'] = sum(1 for f in results['findings'] if f.get('severity') == 'CRITICAL')
                results['high'] = sum(1 for f in results['findings'] if f.get('severity') == 'HIGH')
                results['medium'] = sum(1 for f in results['findings'] if f.get('severity') == 'MEDIUM')
                results['low'] = sum(1 for f in results['findings'] if f.get('severity') == 'LOW')
                results['ml_fps_eliminated'] = eliminated

        except ImportError as e:
            _warn(f"ML classifier not available: {e}")
        except Exception as e:
            _warn(f"ML classification failed: {e}")

    # ── LLM analysis ─────────────────────────────────────────────────────
    if use_llm:
        try:
            from core.llm_analyzer import LLMAnalyzer
            backend = None if args.llm_backend == 'auto' else args.llm_backend
            llm = LLMAnalyzer(
                backend=backend,
                model=args.llm_model,
                ollama_url=args.ollama_url,
                fast_mode=args.llm_fast,
            )
            mode_str = " [CPU-optimized]" if args.llm_fast else ""
            _success(f"LLM initialized: {llm.backend}/{llm.model}{mode_str}")

            if llm.backend == "ollama":
                llm.warmup(verbose=not _quiet)

            file_codes = {}
            if os.path.isdir(args.target):
                for fp in glob.glob(os.path.join(args.target, '**', '*.php'), recursive=True):
                    if not args.include_vendor and _is_vendor_path(fp):
                        continue
                    try:
                        with open(fp, 'r', encoding='utf-8', errors='ignore') as fh:
                            file_codes[fp] = fh.read()
                    except Exception:
                        pass
            else:
                with open(args.target, 'r', encoding='utf-8', errors='ignore') as fh:
                    file_codes[args.target] = fh.read()

            # Verify findings
            if not args.llm_hunt_only and results.get('findings'):
                _progress(f"LLM verifying {len(results['findings'])} findings...")
                verified = llm.verify_findings_batch(results['findings'], file_codes)
                eliminated = len(results['findings']) - len(verified)
                _progress(f"  LLM eliminated {eliminated} false positives")
                results['findings_pre_llm'] = results['findings']
                results['findings'] = verified
                results['llm_fps_eliminated'] = eliminated
                results['total_findings'] = len(verified)
                results['critical'] = sum(1 for f in verified if f.get('severity') == 'CRITICAL')
                results['high'] = sum(1 for f in verified if f.get('severity') == 'HIGH')
                results['medium'] = sum(1 for f in verified if f.get('severity') == 'MEDIUM')
                results['low'] = sum(1 for f in verified if f.get('severity') == 'LOW')

            # Deep hunt
            if not args.llm_verify_only:
                _progress(f"LLM deep hunting {len(file_codes)} files...")
                llm_results = llm.scan_project(
                    args.target, rule_findings=None,
                    file_codes=file_codes, verbose=not _quiet,
                )
                new_findings = llm_results.get('new_findings', [])
                if new_findings:
                    _success(f"  LLM found {len(new_findings)} NEW vulnerabilities!")
                    results['llm_findings'] = new_findings
                    results['total_findings'] += len(new_findings)
                    for f in new_findings:
                        sev = f.get('severity', 'MEDIUM')
                        if sev == 'CRITICAL': results['critical'] += 1
                        elif sev == 'HIGH': results['high'] += 1
                        elif sev == 'MEDIUM': results['medium'] += 1
                        else: results['low'] += 1
                else:
                    _progress("  No additional vulnerabilities found by LLM")

            cost = llm.get_cost_estimate()
            results['llm_cost'] = cost
            _progress(f"LLM: {cost['api_calls']} calls, "
                      f"~${cost['estimated_cost_usd']:.4f}")

        except ImportError as e:
            _error(f"LLM module not available: {e}")
            _error("  Fix: pip install anthropic")
        except Exception as e:
            _error(f"LLM analysis failed: {e}")

    # ── Output ───────────────────────────────────────────────────────────
    results['scan_mode'] = args.mode

    if args.output:
        if args.format == 'sarif':
            sarif_output = generate_sarif(results, args.target)
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(sarif_output, f, indent=2)
            _success(f"SARIF results saved to: {args.output}")
        elif args.format == 'html':
            from core.html_report import generate_html_report
            generate_html_report(results, args.target, args.output)
            _success(f"HTML report saved to: {args.output}")
        else:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)
            _success(f"Results saved to: {args.output}")

    if args.format == 'text' or (not args.output and args.format not in ('sarif', 'html')):
        print_results(results, args.verbose)
    elif args.format == 'sarif' and not args.output:
        sarif_output = generate_sarif(results, args.target)
        print(json.dumps(sarif_output, indent=2))
    elif args.format == 'html' and not args.output:
        from core.html_report import generate_html_report
        html_file = os.path.splitext(os.path.basename(args.target))[0] + '_report.html'
        html_path = os.path.join(os.path.dirname(args.target) or '.', html_file)
        generate_html_report(results, args.target, html_path)
        _success(f"HTML report saved to: {html_path}")

    # ── Summary line ─────────────────────────────────────────────────────
    total_time = time.time() - scan_start
    _progress(f"\nTotal time: {total_time:.1f}s | "
              f"Findings: {results['total_findings']} | "
              f"Mode: {args.mode}")

    # Return code based on findings
    if results['critical'] > 0:
        return 2
    elif results['high'] > 0:
        return 1
    else:
        return 0


if __name__ == "__main__":
    sys.exit(main())
