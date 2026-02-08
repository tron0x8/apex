#!/usr/bin/env python3
"""
End-to-end precision/recall measurement for APEX scanner.
Tests against known-vulnerable and known-safe PHP fixture files.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.unified_scanner import UnifiedScanner, VulnType

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')


def load_fixture(name):
    path = os.path.join(FIXTURES_DIR, name)
    with open(path, 'r', encoding='utf-8') as f:
        return f.read(), path


scanner = UnifiedScanner()


# Ground truth: (file, expected_vuln_types, min_expected_count)
VULNERABLE_FILES = {
    'vuln_sqli.php': {
        'vuln_types': {VulnType.SQL_INJECTION},
        'min_count': 3,  # At least 3 SQLi findings expected
        'description': 'SQL injection variants',
    },
    'vuln_xss.php': {
        'vuln_types': {VulnType.XSS},
        'min_count': 3,
        'description': 'XSS variants',
    },
    'vuln_cmdi.php': {
        'vuln_types': {VulnType.COMMAND_INJECTION},
        'min_count': 3,
        'description': 'Command injection variants',
    },
    'vuln_deserialization.php': {
        'vuln_types': {VulnType.DESERIALIZATION},
        'min_count': 2,
        'description': 'Insecure deserialization',
    },
    'vuln_interprocedural.php': {
        'vuln_types': {VulnType.SQL_INJECTION, VulnType.COMMAND_INJECTION, VulnType.XSS},
        'min_count': 1,  # At least 1 cross-function finding
        'description': 'Inter-procedural flows',
    },
    'vuln_multiline.php': {
        'vuln_types': {VulnType.SQL_INJECTION, VulnType.COMMAND_INJECTION, VulnType.XSS,
                       VulnType.FILE_INCLUSION, VulnType.CODE_INJECTION},
        'min_count': 3,
        'description': 'Multi-line patterns',
    },
    'vuln_new_types.php': {
        'vuln_types': {VulnType.HEADER_INJECTION, VulnType.MASS_ASSIGNMENT,
                       VulnType.INSECURE_RANDOM, VulnType.RACE_CONDITION,
                       VulnType.LOG_INJECTION, VulnType.REGEX_DOS},
        'min_count': 6,
        'description': 'New v3.0 vulnerability types (header inj, mass assign, insecure random, race cond, log inj, regex dos)',
    },
}

SAFE_FILES = {
    'safe_sanitized.php': {
        'forbidden_types': {VulnType.SQL_INJECTION, VulnType.XSS,
                           VulnType.COMMAND_INJECTION, VulnType.FILE_INCLUSION},
        'description': 'Properly sanitized inputs',
    },
    'safe_parameterized.php': {
        'forbidden_types': {VulnType.SQL_INJECTION},
        'description': 'Parameterized/prepared statements',
    },
    'safe_strict.php': {
        'forbidden_types': {VulnType.TYPE_JUGGLING},
        'description': 'Strict comparisons and whitelist validation',
    },
    'safe_new_types.php': {
        'forbidden_types': {VulnType.HEADER_INJECTION, VulnType.MASS_ASSIGNMENT,
                           VulnType.INSECURE_RANDOM, VulnType.LOG_INJECTION,
                           VulnType.RACE_CONDITION},
        'description': 'Sanitized new vulnerability types',
    },
}


def run_precision_recall():
    print("=" * 70)
    print("APEX Precision/Recall Measurement")
    print("=" * 70)

    tp = 0  # True positives: vuln file, correct vuln type detected
    fp = 0  # False positives: safe file, vuln detected
    fn = 0  # False negatives: vuln file, expected vuln NOT detected
    tn = 0  # True negatives: safe file, no vuln detected

    # Test vulnerable files
    print("\n--- VULNERABLE FILES (should detect) ---\n")
    for filename, ground_truth in VULNERABLE_FILES.items():
        try:
            code, filepath = load_fixture(filename)
        except FileNotFoundError:
            print(f"  [SKIP] {filename} not found")
            continue

        findings = scanner.scan_code(code, filepath)
        found_types = {f.vuln_type for f in findings}
        expected_types = ground_truth['vuln_types']

        # Check if at least one expected type was found
        detected = found_types & expected_types
        missed = expected_types - found_types

        if detected:
            tp += len(detected)
            status = "DETECTED"
        else:
            fn += len(expected_types)
            status = "MISSED"

        if missed:
            fn += len(missed)

        count_ok = len(findings) >= ground_truth['min_count']

        print(f"  [{status}] {filename}: {ground_truth['description']}")
        print(f"    Expected types: {', '.join(v.value for v in expected_types)}")
        print(f"    Found types:    {', '.join(v.value for v in found_types) if found_types else 'NONE'}")
        print(f"    Finding count:  {len(findings)} (min expected: {ground_truth['min_count']}) {'OK' if count_ok else 'LOW'}")
        if missed:
            print(f"    MISSED types:   {', '.join(v.value for v in missed)}")
        print()

    # Test safe files
    print("--- SAFE FILES (should NOT detect) ---\n")
    for filename, ground_truth in SAFE_FILES.items():
        try:
            code, filepath = load_fixture(filename)
        except FileNotFoundError:
            print(f"  [SKIP] {filename} not found")
            continue

        findings = scanner.scan_code(code, filepath)
        found_types = {f.vuln_type for f in findings}
        forbidden = ground_truth['forbidden_types']

        false_positives = found_types & forbidden
        if false_positives:
            fp += len(false_positives)
            status = "FP"
        else:
            tn += 1
            status = "CLEAN"

        print(f"  [{status}] {filename}: {ground_truth['description']}")
        if false_positives:
            print(f"    FALSE POSITIVES: {', '.join(v.value for v in false_positives)}")
            for f in findings:
                if f.vuln_type in forbidden:
                    print(f"      Line {f.line}: {f.vuln_type.value} - {f.code[:60]}")
        else:
            # Report non-forbidden findings (informational)
            other = found_types - forbidden
            if other:
                print(f"    Other findings (not forbidden): {', '.join(v.value for v in other)}")
            else:
                print(f"    No findings (correct)")
        print()

    # Calculate metrics
    print("=" * 70)
    print("METRICS")
    print("=" * 70)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print(f"  True Positives:  {tp}")
    print(f"  False Positives: {fp}")
    print(f"  False Negatives: {fn}")
    print(f"  True Negatives:  {tn}")
    print(f"")
    print(f"  Precision: {precision:.1%}")
    print(f"  Recall:    {recall:.1%}")
    print(f"  F1 Score:  {f1:.1%}")
    print()

    return tp, fp, fn, tn, precision, recall, f1


if __name__ == '__main__':
    tp, fp, fn, tn, precision, recall, f1 = run_precision_recall()
    # Exit with error if precision or recall is below threshold
    if precision < 0.50 or recall < 0.50:
        print(f"WARNING: Metrics below threshold (precision={precision:.1%}, recall={recall:.1%})")
        sys.exit(1)
    print("All metrics above minimum threshold.")
    sys.exit(0)
