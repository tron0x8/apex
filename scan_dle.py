#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, 'C:/Users/User/Desktop/apex')
from core.patterns import PatternScanner
from core.fp_filter import FalsePositiveFilter

base_path = 'C:/Users/User/Downloads/Telegram Desktop/dle_trial_extracted/upload/engine'

scanner = PatternScanner()
fp_filter = FalsePositiveFilter()
all_findings = []
code_map = {}

# Scan all PHP files in engine folder (not deep in vendor)
for root, dirs, files in os.walk(base_path):
    # Skip vendor/composer directories
    if 'vendor' in root or 'composer' in root or 'htmlpurifier' in root:
        continue
    for f in files:
        if f.endswith('.php'):
            full_path = os.path.join(root, f)
            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as file:
                    code = file.read()
                code_map[full_path] = code
                findings = scanner.scan(code, full_path)
                all_findings.extend(findings)
            except:
                pass

# Filter
filtered = fp_filter.filter_findings(all_findings, code_map)

print(f'Raw findings: {len(all_findings)}')
print(f'After FP filter: {len(filtered)}')
print()

# Group by severity
critical = [f for f in filtered if f['severity'] == 'CRITICAL']
high = [f for f in filtered if f['severity'] == 'HIGH']
medium = [f for f in filtered if f['severity'] == 'MEDIUM']

print(f'CRITICAL: {len(critical)}')
print(f'HIGH: {len(high)}')
print(f'MEDIUM: {len(medium)}')
print()

# Show top findings
print("=" * 80)
print("TOP FINDINGS")
print("=" * 80)
for f in sorted(filtered, key=lambda x: -x['confidence'])[:20]:
    rel_path = f['file'].replace(base_path, '').lstrip('/').lstrip('\\')
    print(f"{f['severity']:8} [{f['confidence']*100:.0f}%] {f['pattern_name']:30}")
    print(f"         {rel_path}:{f['line']}")
    print(f"         {f['code'][:70]}")
    print()
