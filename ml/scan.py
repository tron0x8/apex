#!/usr/bin/env python3

import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from train import PHPVulnDetector


def print_banner():
    print("""
    +-------------------------------------------+
    |  PHP Vulnerability Scanner (ML)           |
    +-------------------------------------------+
    """)


def scan_file(detector, file_path: str) -> dict:
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()

        label, confidence, details = detector.predict(code)

        return {
            'file': file_path,
            'result': label,
            'confidence': confidence,
            'is_vulnerable': label != 'SAFE',
            'method': details.get('method', 'ml'),
            'flows': details.get('features', {})
        }
    except Exception as e:
        return {
            'file': file_path,
            'error': str(e)
        }


def scan_code(detector, code: str) -> dict:
    label, confidence, details = detector.predict(code)

    return {
        'result': label,
        'confidence': confidence,
        'is_vulnerable': label != 'SAFE',
        'method': details.get('method', 'ml'),
        'flows': details.get('features', {})
    }


def scan_directory(detector, dir_path: str, max_files: int = 100) -> list:
    results = []
    php_files = list(Path(dir_path).rglob('*.php'))[:max_files]

    print(f"Scanning {len(php_files)} PHP files...\n")

    for i, php_file in enumerate(php_files, 1):
        result = scan_file(detector, str(php_file))
        results.append(result)

        if result.get('is_vulnerable'):
            print(f"[!] {result['result']:5} | {result['confidence']:.0%} | {php_file.name}")

    return results


def print_result(result: dict):
    if 'error' in result:
        print(f"[ERROR] {result.get('file', 'unknown')}: {result['error']}")
        return

    if result['is_vulnerable']:
        icon = "[!]"
    else:
        icon = "[OK]"

    print(f"""
{icon} Result: {result['result']}
    Confidence: {result['confidence']:.1%}
    Method: {result['method']}
    """)

    flows = result.get('flows', {})
    if flows:
        print("    Flow Analysis:")
        if flows.get('direct_sqli_flow'): print("      - Direct SQL injection flow detected")
        if flows.get('direct_xss_flow'): print("      - Direct XSS flow detected")
        if flows.get('direct_cmdi_flow'): print("      - Direct command injection flow detected")
        if flows.get('direct_lfi_flow'): print("      - Direct file inclusion flow detected")
        if flows.get('sanitized_sqli_flow'): print("      - SQL sanitization detected")
        if flows.get('sanitized_xss_flow'): print("      - XSS sanitization detected")
        if flows.get('has_source'): print(f"      - User input sources: {flows.get('source_count', 0)}")
        if flows.get('has_sink'): print(f"      - Dangerous sinks: {flows.get('sink_count', 0)}")


def main():
    print_banner()

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python scan.py <file.php>          # Scan single file")
        print("  python scan.py <directory>         # Scan directory")
        print('  python scan.py --code "<?php ..."  # Scan code snippet')
        print("\nExamples:")
        print("  python scan.py test.php")
        print("  python scan.py ./my_project/")
        print('  python scan.py --code "<?php echo $_GET[\'x\']; ?>"')
        sys.exit(1)

    model_path = Path(__file__).parent / 'vuln_model.pkl'
    if not model_path.exists():
        print("[ERROR] Model not found! Run train.py first.")
        sys.exit(1)

    print("Loading model...")
    detector = PHPVulnDetector()
    detector.load(str(model_path))
    print("Model loaded!\n")

    if sys.argv[1] == '--code':
        code = sys.argv[2] if len(sys.argv) > 2 else input("Enter PHP code: ")
        result = scan_code(detector, code)
        print_result(result)

    elif os.path.isfile(sys.argv[1]):
        result = scan_file(detector, sys.argv[1])
        print(f"File: {sys.argv[1]}")
        print_result(result)

    elif os.path.isdir(sys.argv[1]):
        results = scan_directory(detector, sys.argv[1])

        vulns = [r for r in results if r.get('is_vulnerable')]
        safe = [r for r in results if not r.get('is_vulnerable') and 'error' not in r]
        errors = [r for r in results if 'error' in r]

        print(f"\n{'='*50}")
        print(f"SUMMARY")
        print(f"{'='*50}")
        print(f"Total files:  {len(results)}")
        print(f"Vulnerable:   {len(vulns)}")
        print(f"Safe:         {len(safe)}")
        print(f"Errors:       {len(errors)}")

        if vulns:
            print(f"\nVulnerable files:")
            for v in vulns:
                print(f"  [{v['result']}] {v['file']}")

    else:
        print(f"[ERROR] File or directory not found: {sys.argv[1]}")
        sys.exit(1)


if __name__ == '__main__':
    main()
