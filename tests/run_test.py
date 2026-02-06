#!/usr/bin/env python3

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'core'))

from patterns import PatternScanner, VULN_PATTERNS
from fp_filter import FalsePositiveFilter

def main():
    test_file = os.path.join(os.path.dirname(__file__), 'test_vulns.php')

    with open(test_file, 'r', encoding='utf-8') as f:
        code = f.read()

    print("=" * 70)
    print("APEX Pattern Scanner Test")
    print("=" * 70)

    scanner = PatternScanner()
    findings = scanner.scan(code, test_file)

    print(f"\n[*] Raw findings (before FP filter): {len(findings)}")

    fp_filter = FalsePositiveFilter()
    filtered = fp_filter.filter_findings(findings, {test_file: code})

    print(f"[*] After FP filter: {len(filtered)}")
    print(f"[*] Filtered out: {len(findings) - len(filtered)}")

    true_positive_lines = [9, 15, 22, 28, 33, 39, 45, 52, 58, 64, 186, 192, 204]
    false_positive_lines = [73, 79, 85, 92, 98, 104, 111, 120, 132, 143, 150, 155, 161, 167, 171, 176]

    print("\n" + "=" * 70)
    print("TRUE POSITIVES (should detect)")
    print("=" * 70)

    detected_tp = []
    missed_tp = []

    for finding in filtered:
        if finding['line'] in true_positive_lines:
            detected_tp.append(finding)

    for line in true_positive_lines:
        found = any(f['line'] == line for f in filtered)
        if found:
            print(f"  [OK] Line {line} - detected")
        else:
            missed_tp.append(line)
            print(f"  [MISS] Line {line} - NOT detected")

    print("\n" + "=" * 70)
    print("FALSE POSITIVES (should NOT detect)")
    print("=" * 70)

    false_positives = []
    for finding in filtered:
        if finding['line'] in false_positive_lines:
            false_positives.append(finding)
            print(f"  [FP] Line {finding['line']} - {finding['pattern_name']} (confidence: {finding['confidence']:.2f})")

    for line in false_positive_lines:
        found = any(f['line'] == line for f in filtered)
        if not found:
            print(f"  [OK] Line {line} - correctly filtered")

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    tp_rate = len(detected_tp) / len(true_positive_lines) * 100 if true_positive_lines else 0
    fp_count = len(false_positives)

    print(f"  True Positive Rate: {tp_rate:.1f}% ({len(detected_tp)}/{len(true_positive_lines)})")
    print(f"  False Positives: {fp_count}")
    print(f"  Missed: {len(missed_tp)}")

    if missed_tp:
        print(f"  Missed lines: {missed_tp}")

    precision = len(detected_tp) / (len(detected_tp) + fp_count) * 100 if (len(detected_tp) + fp_count) > 0 else 0
    print(f"\n  Precision: {precision:.1f}%")

    print("\n" + "=" * 70)
    print("ALL FINDINGS")
    print("=" * 70)

    for i, f in enumerate(filtered, 1):
        conf_str = f"[{f['confidence']*100:.0f}%]"
        print(f"  {i:2}. {f['pattern_name']:30} Line {f['line']:3} {conf_str:6} {f['severity']}")

if __name__ == "__main__":
    main()
