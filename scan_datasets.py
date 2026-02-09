#!/usr/bin/env python3
"""
Scan all ML training datasets and save results.
Runs on the REMOTE SERVER to scan webshells, progpilot, vuln apps, etc.

Usage (on server):
    /root/apex_env/bin/python /root/apex/scan_datasets.py

Output: /root/scan_results/ml_training_scans.json
"""

import json
import os
import sys
import time
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent / "core"))

from core.unified_scanner import UnifiedScanner


def scan_directory(scanner, path, label, max_files=5000):
    """Scan a directory and return findings with metadata."""
    if not os.path.exists(path):
        print(f"  [SKIP] {path} not found")
        return []

    # Count PHP files
    php_files = []
    for root, dirs, files in os.walk(path):
        # Skip .git directories
        dirs[:] = [d for d in dirs if d != '.git']
        for f in files:
            if f.endswith('.php'):
                php_files.append(os.path.join(root, f))
                if len(php_files) >= max_files:
                    break
        if len(php_files) >= max_files:
            break

    print(f"  Scanning {len(php_files)} PHP files in {path}...")
    findings = []
    errors = 0

    for i, fp in enumerate(php_files):
        if (i + 1) % 500 == 0:
            print(f"    Progress: {i+1}/{len(php_files)} ({len(findings)} findings)")
        try:
            with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            if not code.strip():
                continue
            result = scanner.scan_code(code, fp)
            for finding in result:
                finding['_label'] = label
                finding['_dataset_path'] = path
                findings.append(finding)
        except Exception as e:
            errors += 1

    print(f"  Found {len(findings)} findings ({errors} errors)")
    return findings


def main():
    print("=" * 60)
    print("APEX - Scan All ML Training Datasets")
    print("=" * 60)

    scanner = UnifiedScanner()
    all_results = {}
    total_findings = 0

    # ================================================================
    # 1. Webshell collections (ALL findings = TP, these are malware)
    # ================================================================
    print("\n[1] Webshell / Malware Collections (all = TP)")

    webshell_dirs = [
        ('/root/ml_datasets/PHP-backdoors', 'tp_webshell'),
        ('/root/ml_datasets/webshell', 'tp_webshell'),
    ]
    for path, label in webshell_dirs:
        name = os.path.basename(path)
        findings = scan_directory(scanner, path, label, max_files=3000)
        if findings:
            all_results[f'webshell_{name}'] = findings
            total_findings += len(findings)

    # ================================================================
    # 2. Known vulnerable apps (ALL findings = TP)
    # ================================================================
    print("\n[2] Known Vulnerable Apps (all = TP)")

    vuln_apps = [
        ('/root/vuln_apps/DVWA', 'tp_vuln_app'),
        ('/root/vuln_apps/xvwa', 'tp_vuln_app'),
        ('/root/vuln_apps/OWASPWebGoatPHP', 'tp_vuln_app'),
        ('/root/vuln_apps/Vulnerable-Web-Application', 'tp_vuln_app'),
    ]
    for path, label in vuln_apps:
        name = os.path.basename(path)
        findings = scan_directory(scanner, path, label, max_files=500)
        if findings:
            all_results[f'vuln_{name}'] = findings
            total_findings += len(findings)

    # ================================================================
    # 3. Progpilot test cases (safe/ = FP, unsafe/ = TP)
    # ================================================================
    print("\n[3] Progpilot Test Cases (labeled)")

    progpilot_base = '/root/ml_datasets/progpilot'
    # Progpilot has tests in _tests/ dirs with structure like:
    # tests/real/tests/
    progpilot_tests = os.path.join(progpilot_base, 'projects', 'tests')
    if os.path.exists(progpilot_tests):
        # Scan all test files
        findings = scan_directory(scanner, progpilot_tests, 'tp_progpilot', max_files=2000)
        if findings:
            all_results['progpilot_tests'] = findings
            total_findings += len(findings)

    # Also check for real-world tests
    for sub in ['tests/real', 'projects/tests/tests']:
        subpath = os.path.join(progpilot_base, sub)
        if os.path.exists(subpath) and subpath != progpilot_tests:
            findings = scan_directory(scanner, subpath, 'tp_progpilot', max_files=1000)
            if findings:
                all_results[f'progpilot_{sub.replace("/","_")}'] = findings
                total_findings += len(findings)

    # ================================================================
    # 4. Stivalet FULL benchmark (labeled by directory structure)
    # ================================================================
    print("\n[4] Stivalet FULL Benchmark")

    stivalet_base = '/root/vuln_apps/PHP-Vulnerability-test-suite'
    if os.path.exists(stivalet_base):
        # Pre-load labels from directory structure
        stiv_safe_findings = []
        stiv_unsafe_findings = []

        for cat in sorted(os.listdir(stivalet_base)):
            cat_path = os.path.join(stivalet_base, cat)
            if not os.path.isdir(cat_path) or cat.startswith('.'):
                continue
            for cwe in sorted(os.listdir(cat_path)):
                cwe_path = os.path.join(cat_path, cwe)
                if not os.path.isdir(cwe_path):
                    continue
                for label_dir in ['safe', 'unsafe']:
                    label_path = os.path.join(cwe_path, label_dir)
                    if not os.path.isdir(label_path):
                        continue
                    label = 'fp_stivalet' if label_dir == 'safe' else 'tp_stivalet'
                    findings = scan_directory(scanner, label_path, label, max_files=10000)
                    if label_dir == 'safe':
                        stiv_safe_findings.extend(findings)
                    else:
                        stiv_unsafe_findings.extend(findings)

        if stiv_safe_findings:
            all_results['stivalet_safe'] = stiv_safe_findings
            total_findings += len(stiv_safe_findings)
        if stiv_unsafe_findings:
            all_results['stivalet_unsafe'] = stiv_unsafe_findings
            total_findings += len(stiv_unsafe_findings)

        print(f"  Stivalet totals: {len(stiv_unsafe_findings)} TP, {len(stiv_safe_findings)} FP")

    # ================================================================
    # 5. CMS projects (mixed - use high-confidence heuristic labels)
    # ================================================================
    print("\n[5] CMS Projects (heuristic labels)")

    cms_dirs = [
        '/root/maxsitecms',
        '/root/dle_test',
        '/root/cms_test/geeklog',
        '/root/cms_test/ImpressPages',
        '/root/cms_test/pagekit',
    ]
    for path in cms_dirs:
        name = os.path.basename(path)
        findings = scan_directory(scanner, path, 'mixed_cms', max_files=2000)
        if findings:
            all_results[f'cms_{name}'] = findings
            total_findings += len(findings)

    # ================================================================
    # 6. RealVul dataset (if PHP data available)
    # ================================================================
    print("\n[6] RealVul Dataset")

    realvul_base = '/root/ml_datasets/RealVul-emnlp24'
    realvul_data = os.path.join(realvul_base, 'data')
    if os.path.exists(realvul_data):
        # RealVul has JSON/JSONL files with labeled PHP snippets
        for fn in os.listdir(realvul_data):
            if fn.endswith(('.json', '.jsonl')):
                fpath = os.path.join(realvul_data, fn)
                print(f"  Found RealVul data: {fn}")
                try:
                    with open(fpath, 'r') as f:
                        if fn.endswith('.jsonl'):
                            entries = [json.loads(line) for line in f if line.strip()]
                        else:
                            entries = json.load(f)
                            if isinstance(entries, dict):
                                entries = entries.get('data', entries.get('samples', [entries]))

                    php_entries = [e for e in entries if e.get('language', '').lower() == 'php'
                                   or e.get('lang', '').lower() == 'php'
                                   or 'php' in str(e.get('file', '')).lower()]
                    print(f"  PHP entries: {len(php_entries)}")
                except Exception as e:
                    print(f"  Error loading {fn}: {e}")
    else:
        # Check if data files are in repo root
        for fn in os.listdir(realvul_base):
            if fn.endswith(('.json', '.jsonl', '.csv', '.parquet')):
                print(f"  Found: {fn}")

    # ================================================================
    # 7. CrossVul dataset
    # ================================================================
    print("\n[7] CrossVul Dataset")

    crossvul_base = '/root/ml_datasets/CrossVul'
    if os.path.exists(crossvul_base):
        # CrossVul has PHP files with CVE labels
        for sub in ['data', 'vulnerable', 'safe', 'dataset']:
            subpath = os.path.join(crossvul_base, sub)
            if os.path.exists(subpath):
                php_count = sum(1 for r, d, f in os.walk(subpath)
                               for fn in f if fn.endswith('.php'))
                print(f"  {sub}/: {php_count} PHP files")

    # ================================================================
    # Save all results
    # ================================================================
    print(f"\n{'='*60}")
    print(f"TOTALS")
    print(f"{'='*60}")

    summary = {}
    for key, findings in all_results.items():
        tp_count = sum(1 for f in findings if f.get('_label', '').startswith('tp'))
        fp_count = sum(1 for f in findings if f.get('_label', '').startswith('fp'))
        mixed_count = sum(1 for f in findings if f.get('_label', '').startswith('mixed'))
        summary[key] = {'total': len(findings), 'tp': tp_count, 'fp': fp_count, 'mixed': mixed_count}
        print(f"  {key:30s}: {len(findings):6d} findings (TP:{tp_count}, FP:{fp_count}, Mixed:{mixed_count})")

    output = {
        'summary': summary,
        'total_findings': total_findings,
        'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'datasets': all_results,
    }

    out_path = '/root/scan_results/ml_training_scans.json'
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=1, default=str)

    size_mb = os.path.getsize(out_path) / 1024 / 1024
    print(f"\nSaved to: {out_path} ({size_mb:.1f} MB)")
    print(f"Total: {total_findings} findings across {len(all_results)} datasets")


if __name__ == '__main__':
    main()
