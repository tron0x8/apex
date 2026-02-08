#!/usr/bin/env python3
"""
APEX - Advanced PHP Exploitation Scanner v2.0

A comprehensive PHP security scanner with:
- Pattern-based vulnerability detection (40+ patterns)
- Taint tracking and data flow analysis
- Advanced false positive filtering
- Framework-aware analysis (Laravel, Symfony, WordPress, etc.)

Usage:
    python apex.py /path/to/php/project
    python apex.py /path/to/file.php
    python apex.py --help
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


def print_banner():
    """Print APEX banner"""
    banner = """
    +===============================================================+
    |      _    ____  _______  __                                   |
    |     / \\  |  _ \\| ____\\ \\/ /                                   |
    |    / _ \\ | |_) |  _|  \\  /                                    |
    |   / ___ \\|  __/| |___ /  \\                                    |
    |  /_/   \\_\\_|   |_____/_/\\_\\   v3.0                            |
    |                                                               |
    |  Advanced PHP Exploitation Scanner                            |
    |  Pattern + Taint + CFG + LLM Deep Analysis                    |
    +===============================================================+
    """
    print(banner)


def scan_file(filepath: str, scanner, verbose: bool = False) -> List[Dict]:
    """Scan a single PHP file"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()

        findings = scanner.scan_code(code, filepath)
        return findings

    except Exception as e:
        if verbose:
            print(f"[ERROR] {filepath}: {e}")
        return []


# Vendor/library paths to skip (well-maintained third-party code)
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
    """Check if file is in a vendor/library directory"""
    parts = Path(filepath).parts
    for part in parts:
        if part.lower() in VENDOR_SKIP_DIRS:
            return True
    return False


def scan_directory(dirpath: str, scanner, verbose: bool = False,
                   skip_vendor: bool = True) -> Dict:
    """Scan all PHP files in directory"""
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
        if verbose and results['skipped_vendor_files'] > 0:
            print(f"  Skipped {results['skipped_vendor_files']} vendor/library files")

    results['total_files'] = len(php_files)

    if verbose:
        print(f"\nScanning {len(php_files)} PHP files...")

    for i, filepath in enumerate(php_files):
        if verbose and (i + 1) % 50 == 0:
            print(f"  Progress: {i + 1}/{len(php_files)}")

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

    return results


def print_results(results: Dict, verbose: bool = False):
    """Print scan results to console"""
    print("\n" + "=" * 70)
    print("SCAN RESULTS")
    print("=" * 70)

    print(f"\nTarget: {results['target']}")
    print(f"Files scanned: {results['total_files']}")
    if results.get('skipped_vendor_files'):
        print(f"Vendor files skipped: {results['skipped_vendor_files']}")
    print(f"Total findings: {results['total_findings']}")
    if results.get('scan_time_seconds'):
        print(f"Scan time: {results['scan_time_seconds']}s")

    print(f"\n  CRITICAL: {results['critical']}")
    print(f"  HIGH:     {results['high']}")
    print(f"  MEDIUM:   {results['medium']}")
    print(f"  LOW:      {results['low']}")

    # Risk score
    risk = min(100, results.get('critical', 0) * 25 + results.get('high', 0) * 10 +
               results.get('medium', 0) * 3 + results.get('low', 0))
    risk_label = ('CRITICAL' if risk >= 75 else 'HIGH' if risk >= 50 else
                  'MEDIUM' if risk >= 25 else 'LOW')
    print(f"\n  Risk Score: {risk}/100 ({risk_label})")

    # ML/LLM filter stats
    if results.get('ml_fps_eliminated'):
        print(f"  ML FPs eliminated: {results['ml_fps_eliminated']}")
    if results.get('llm_fps_eliminated'):
        print(f"  LLM FPs eliminated: {results['llm_fps_eliminated']}")

    # Vulnerability type breakdown
    if results['total_findings'] > 0:
        from collections import Counter
        type_counts = Counter(f.get('type', 'Unknown') for f in results['findings'])
        if len(type_counts) > 1:
            print("\n  Vulnerability Types:")
            for vtype, count in type_counts.most_common(10):
                print(f"    {vtype}: {count}")

        # Top vulnerable files
        file_counts = Counter(os.path.basename(f.get('file', '')) for f in results['findings'])
        if len(file_counts) > 1:
            print("\n  Most Vulnerable Files:")
            for fname, count in file_counts.most_common(5):
                print(f"    {fname}: {count} findings")

    if results['total_findings'] > 0:
        print("\n" + "-" * 70)
        print("FINDINGS")
        print("-" * 70)

        # Group by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            severity_findings = [f for f in results['findings']
                                if f.get('severity') == severity]

            if severity_findings:
                print(f"\n[{severity}] - {len(severity_findings)} findings")

                for f in severity_findings[:10]:  # Limit output
                    file_path = f.get('file', 'unknown')
                    line = f.get('line', 0)
                    vuln_type = f.get('type', f.get('pattern', 'unknown'))
                    confidence = f.get('confidence', '0%')

                    print(f"\n  {vuln_type}")
                    print(f"    File: {file_path}:{line}")
                    print(f"    Confidence: {confidence}")

                    if verbose and f.get('code'):
                        code_preview = f['code'][:60].replace('\n', ' ')
                        print(f"    Code: {code_preview}...")

                if len(severity_findings) > 10:
                    print(f"\n  ... and {len(severity_findings) - 10} more {severity} findings")

    # Print LLM findings if present
    llm_findings = results.get('llm_findings', [])
    if llm_findings:
        print("\n" + "=" * 70)
        print(f"LLM DEEP ANALYSIS FINDINGS ({len(llm_findings)} new)")
        print("=" * 70)

        for f in llm_findings:
            sev = f.get('severity', 'MEDIUM')
            print(f"\n  [{sev}] {f.get('vuln_type', 'Unknown')}")
            print(f"    File: {f.get('file', 'unknown')}:{f.get('line', 0)}")
            if f.get('cwe'):
                print(f"    CWE: {f['cwe']}")
            print(f"    Description: {f.get('description', '')[:120]}")
            if f.get('attack_scenario'):
                print(f"    Attack: {f['attack_scenario'][:120]}")
            if verbose and f.get('fix'):
                print(f"    Fix: {f['fix'][:120]}")
            print(f"    Layer: {f.get('layer', 'deep_hunt')}")


def generate_sarif(results: Dict, target: str) -> Dict:
    """Generate SARIF format output for GitHub Code Scanning"""

    severity_map = {
        'CRITICAL': 'error',
        'HIGH': 'error',
        'MEDIUM': 'warning',
        'LOW': 'note'
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
                    'version': '2.0',
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


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='APEX - Advanced PHP Exploitation Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python apex.py /var/www/html
  python apex.py /path/to/file.php
  python apex.py /path/to/project -o report.json
  python apex.py /path/to/project --verbose
        '''
    )

    parser.add_argument('target', help='PHP file or directory to scan')
    parser.add_argument('-o', '--output', help='Output file (JSON format)')
    parser.add_argument('-f', '--format', choices=['json', 'text', 'sarif', 'html'],
                       default='text', help='Output format (default: text)')
    parser.add_argument('--no-taint', action='store_true',
                       help='Disable taint tracking (faster but more FPs)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--include-vendor', action='store_true',
                       help='Include vendor/library files in scan (skipped by default)')
    parser.add_argument('--ml', action='store_true',
                       help='Enable ML-based false positive filtering (instant, no LLM needed)')
    parser.add_argument('--ml-train', action='store_true',
                       help='Train ML model from test fixtures before scanning')
    parser.add_argument('--llm', action='store_true',
                       help='Enable LLM-powered analysis (auto-detects Ollama or Anthropic)')
    parser.add_argument('--llm-backend', choices=['ollama', 'anthropic', 'auto'],
                       default='auto',
                       help='LLM backend: ollama (free/local), anthropic (paid/API), auto (default)')
    parser.add_argument('--llm-model', default=None,
                       help='LLM model (default: qwen2.5-coder:32b for Ollama, claude-sonnet for Anthropic)')
    parser.add_argument('--ollama-url', default='http://localhost:11434',
                       help='Ollama server URL (default: http://localhost:11434)')
    parser.add_argument('--llm-fast', action='store_true',
                       help='CPU-optimized LLM mode: shorter prompts, smaller model, faster')
    parser.add_argument('--llm-verify-only', action='store_true',
                       help='Only use LLM for verification, skip deep hunt')
    parser.add_argument('--llm-hunt-only', action='store_true',
                       help='Only use LLM for deep hunt, skip verification')
    parser.add_argument('--version', action='version', version='APEX v3.0')

    args = parser.parse_args()

    # Print banner
    print_banner()

    # Check target exists
    if not os.path.exists(args.target):
        print(f"[ERROR] Target not found: {args.target}")
        return 1

    # Initialize scanner
    try:
        from core.unified_scanner import UnifiedScanner
        scanner = UnifiedScanner()
        print("[+] Unified Scanner initialized (Pattern + Taint)")
    except ImportError as e:
        print(f"[ERROR] Could not initialize scanner: {e}")
        return 1

    # Scan
    scan_start = time.time()
    if os.path.isfile(args.target):
        print(f"\n[*] Scanning file: {args.target}")
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
        print(f"\n[*] Scanning directory: {args.target}")
        results = scan_directory(args.target, scanner, args.verbose,
                                skip_vendor=not args.include_vendor)
    scan_elapsed = time.time() - scan_start
    results['scan_time_seconds'] = round(scan_elapsed, 2)
    files_per_sec = results['total_files'] / scan_elapsed if scan_elapsed > 0 else 0
    print(f"\n[+] Scan completed in {scan_elapsed:.1f}s "
          f"({files_per_sec:.0f} files/sec)")

    # ML False Positive Filtering (if enabled)
    if args.ml or args.ml_train:
        try:
            from core.ml_fp_classifier import FPClassifier
            classifier = FPClassifier()
            print(f"\n[+] ML FP Classifier initialized ({classifier.stats['method']} mode)")

            # Train if requested
            if args.ml_train:
                print("[*] Training ML model...")
                metrics = classifier.train_from_fixtures(verbose=args.verbose)
                if 'error' not in metrics:
                    print(f"    Training complete: {metrics.get('n_samples', 0)} samples")
                    if 'cv_accuracy' in metrics:
                        print(f"    CV Accuracy: {metrics['cv_accuracy']:.1%}")
                else:
                    print(f"    Training skipped: {metrics.get('error', 'unknown')}")

            # Apply ML filter to findings
            if results.get('findings'):
                # Load file codes for context
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
                print(f"\n[*] ML FP Filter: Analyzing {pre_count} findings...")
                results['findings'] = classifier.classify_batch(
                    results['findings'], ml_file_codes
                )
                post_count = len(results['findings'])
                eliminated = pre_count - post_count

                print(f"    Eliminated {eliminated} false positives "
                      f"({eliminated/pre_count*100:.0f}% FP rate)" if pre_count > 0 else "")
                print(f"    Confirmed {post_count} true positives")

                # Recount severities
                results['total_findings'] = post_count
                results['critical'] = sum(1 for f in results['findings'] if f.get('severity') == 'CRITICAL')
                results['high'] = sum(1 for f in results['findings'] if f.get('severity') == 'HIGH')
                results['medium'] = sum(1 for f in results['findings'] if f.get('severity') == 'MEDIUM')
                results['low'] = sum(1 for f in results['findings'] if f.get('severity') == 'LOW')
                results['ml_fps_eliminated'] = eliminated

        except ImportError as e:
            print(f"\n[WARNING] ML classifier not available: {e}")
        except Exception as e:
            print(f"\n[WARNING] ML classification failed: {e}")

    # LLM Analysis (if enabled)
    if args.llm:
        try:
            from core.llm_analyzer import LLMAnalyzer
            backend = None if args.llm_backend == 'auto' else args.llm_backend
            llm = LLMAnalyzer(
                backend=backend,
                model=args.llm_model,
                ollama_url=args.ollama_url,
                fast_mode=args.llm_fast,
            )
            mode_str = " [FAST/CPU]" if args.llm_fast else ""
            print(f"\n[+] LLM Analyzer initialized{mode_str}")
            print(f"    Backend: {llm.backend}")
            print(f"    Model:   {llm.model}")
            if args.llm_fast:
                print(f"    Mode:    CPU-optimized (short prompts, priority files only)")

            # Warmup model (load into RAM)
            if llm.backend == "ollama":
                llm.warmup(verbose=True)

            # Load file codes for context
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

            # Layer 2: Verify existing findings
            if not args.llm_hunt_only and results.get('findings'):
                print(f"\n[*] LLM Layer 2: Verifying {len(results['findings'])} findings...")
                verified = llm.verify_findings_batch(results['findings'], file_codes)
                eliminated = len(results['findings']) - len(verified)
                print(f"    Eliminated {eliminated} false positives")
                print(f"    Confirmed {len(verified)} true positives")
                results['findings_pre_llm'] = results['findings']
                results['findings'] = verified
                results['llm_fps_eliminated'] = eliminated
                # Recount severities after LLM filtering
                results['total_findings'] = len(verified)
                results['critical'] = sum(1 for f in verified if f.get('severity') == 'CRITICAL')
                results['high'] = sum(1 for f in verified if f.get('severity') == 'HIGH')
                results['medium'] = sum(1 for f in verified if f.get('severity') == 'MEDIUM')
                results['low'] = sum(1 for f in verified if f.get('severity') == 'LOW')

            # Layer 3: Deep hunt
            if not args.llm_verify_only:
                print(f"\n[*] LLM Layer 3: Deep hunting {len(file_codes)} files...")
                llm_results = llm.scan_project(
                    args.target,
                    rule_findings=None,
                    file_codes=file_codes,
                    verbose=True,  # Always show progress for LLM
                )

                new_findings = llm_results.get('new_findings', [])
                if new_findings:
                    print(f"\n    LLM found {len(new_findings)} NEW vulnerabilities!")
                    results['llm_findings'] = new_findings
                    results['total_findings'] += len(new_findings)

                    # Count new findings by severity
                    for f in new_findings:
                        sev = f.get('severity', 'MEDIUM')
                        if sev == 'CRITICAL':
                            results['critical'] += 1
                        elif sev == 'HIGH':
                            results['high'] += 1
                        elif sev == 'MEDIUM':
                            results['medium'] += 1
                        else:
                            results['low'] += 1
                else:
                    print(f"    No additional vulnerabilities found by LLM")

            # Cost report
            cost = llm.get_cost_estimate()
            results['llm_cost'] = cost
            print(f"\n[*] LLM Stats: {cost['api_calls']} API calls, "
                  f"{cost['input_tokens']} in / {cost['output_tokens']} out tokens, "
                  f"~${cost['estimated_cost_usd']:.4f}")

        except ImportError as e:
            print(f"\n[ERROR] LLM module not available: {e}")
            print("  Install with: pip install anthropic")
        except Exception as e:
            print(f"\n[ERROR] LLM analysis failed: {e}")

    # Output results
    if args.output:
        if args.format == 'sarif':
            sarif_output = generate_sarif(results, args.target)
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(sarif_output, f, indent=2)
            print(f"\n[+] SARIF results saved to: {args.output}")
        elif args.format == 'html':
            from core.html_report import generate_html_report
            generate_html_report(results, args.target, args.output)
            print(f"\n[+] HTML report saved to: {args.output}")
        else:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\n[+] Results saved to: {args.output}")

    if args.format == 'text' or (not args.output and args.format != 'sarif' and args.format != 'html'):
        print_results(results, args.verbose)
    elif args.format == 'sarif' and not args.output:
        sarif_output = generate_sarif(results, args.target)
        print(json.dumps(sarif_output, indent=2))
    elif args.format == 'html' and not args.output:
        # Auto-generate output filename for HTML
        from core.html_report import generate_html_report
        html_file = os.path.splitext(os.path.basename(args.target))[0] + '_report.html'
        html_path = os.path.join(os.path.dirname(args.target) or '.', html_file)
        generate_html_report(results, args.target, html_path)
        print(f"\n[+] HTML report saved to: {html_path}")

    # Return code based on findings
    if results['critical'] > 0:
        return 2  # Critical findings
    elif results['high'] > 0:
        return 1  # High findings
    else:
        return 0  # No critical/high findings


if __name__ == "__main__":
    sys.exit(main())
