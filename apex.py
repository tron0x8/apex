#!/usr/bin/env python3
"""
APEX - Advanced PHP Exploitation Scanner v2.0

A comprehensive PHP security scanner with:
- Pattern-based vulnerability detection (40+ patterns)
- Taint tracking and data flow analysis
- ML-based false positive filtering
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
    |  /_/   \\_\\_|   |_____/_/\\_\\   v2.0                            |
    |                                                               |
    |  Advanced PHP Exploitation Scanner                            |
    |  Pattern Matching + Taint Tracking + ML Filtering             |
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


def scan_directory(dirpath: str, scanner, verbose: bool = False) -> Dict:
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
    }

    php_files = glob.glob(os.path.join(dirpath, '**', '*.php'), recursive=True)
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
    print(f"Total findings: {results['total_findings']}")

    print(f"\n  CRITICAL: {results['critical']}")
    print(f"  HIGH:     {results['high']}")
    print(f"  MEDIUM:   {results['medium']}")
    print(f"  LOW:      {results['low']}")

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
  python apex.py /path/to/project --no-ml --verbose
        '''
    )

    parser.add_argument('target', help='PHP file or directory to scan')
    parser.add_argument('-o', '--output', help='Output file (JSON format)')
    parser.add_argument('-f', '--format', choices=['json', 'text', 'sarif'],
                       default='text', help='Output format (default: text)')
    parser.add_argument('--no-taint', action='store_true',
                       help='Disable taint tracking (faster but more FPs)')
    parser.add_argument('--no-ml', action='store_true',
                       help='Disable ML filtering')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--version', action='version', version='APEX v2.0')

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
        scanner = UnifiedScanner(enable_ml=not args.no_ml)
        print("[+] Unified Scanner initialized (Pattern + Taint + ML)")
    except ImportError as e:
        print(f"[ERROR] Could not initialize scanner: {e}")
        return 1

    # Scan
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
        results = scan_directory(args.target, scanner, args.verbose)

    # Output results
    if args.output:
        if args.format == 'sarif':
            sarif_output = generate_sarif(results, args.target)
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(sarif_output, f, indent=2)
            print(f"\n[+] SARIF results saved to: {args.output}")
        else:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\n[+] Results saved to: {args.output}")

    if args.format == 'text' or (not args.output and args.format != 'sarif'):
        print_results(results, args.verbose)
    elif args.format == 'sarif' and not args.output:
        sarif_output = generate_sarif(results, args.target)
        print(json.dumps(sarif_output, indent=2))

    # Return code based on findings
    if results['critical'] > 0:
        return 2  # Critical findings
    elif results['high'] > 0:
        return 1  # High findings
    else:
        return 0  # No critical/high findings


if __name__ == "__main__":
    sys.exit(main())
