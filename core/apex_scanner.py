#!/usr/bin/env python3
# apex/core - tron (@tron0x8)

import os
import re
import glob
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

from patterns import PatternScanner
from taint_tracker import TaintTracker, DataFlowAnalyzer, TaintType


@dataclass
class Finding:
    filepath: str
    line: int
    severity: str
    category: str
    pattern_name: str
    code: str
    confidence: float
    source: Optional[str] = None
    sink: Optional[str] = None
    sanitizers: Optional[List[str]] = None
    is_verified: bool = False
    verification_method: str = "pattern"


class APEXScanner:

    def __init__(self, enable_taint_tracking: bool = True):
        self.pattern_scanner = PatternScanner()
        self.taint_tracker = TaintTracker()
        self.data_flow_analyzer = DataFlowAnalyzer()
        self.enable_taint_tracking = enable_taint_tracking

        self.pattern_to_taint = {
            'SQL_INJECTION': TaintType.SQL,
            'SQL_INJECTION_STRING': TaintType.SQL,
            'SQL_INJECTION_VARIABLE': TaintType.SQL,
            'XSS': TaintType.XSS,
            'XSS_ECHO': TaintType.XSS,
            'XSS_ECHO_DIRECT': TaintType.XSS,
            'XSS_ECHO_CONCAT': TaintType.XSS,
            'COMMAND_INJECTION': TaintType.COMMAND,
            'CODE_INJECTION': TaintType.COMMAND,
            'FILE_INCLUSION': TaintType.FILE_PATH,
            'FILE_INCLUSION_VAR': TaintType.FILE_PATH,
            'PATH_TRAVERSAL': TaintType.FILE_PATH,
            'ARBITRARY_FILE_READ': TaintType.FILE_PATH,
            'ARBITRARY_FILE_WRITE': TaintType.FILE_PATH,
            'SSRF': TaintType.SSRF,
            'SSRF_VAR': TaintType.SSRF,
            'SSRF_CURL': TaintType.SSRF,
        }

    def _extract_variable_from_code(self, code: str) -> Optional[str]:
        vars_found = re.findall(r'\$\w+', code)
        if vars_found:
            return vars_found[0]
        return None

    def _is_pattern_verified_by_taint(self, finding: Dict, code: str) -> Tuple[bool, float, List[str]]:
        pattern_name = finding.get('pattern_name', '')
        line = finding.get('line', 0)
        code_snippet = finding.get('code', '')

        taint_type = None
        for pattern_prefix, t_type in self.pattern_to_taint.items():
            if pattern_prefix in pattern_name:
                taint_type = t_type
                break

        if not taint_type:
            return True, finding.get('confidence', 0.5), []

        var_name = self._extract_variable_from_code(code_snippet)
        if not var_name:
            return True, finding.get('confidence', 0.5), []

        sanitizations = self.taint_tracker.find_sanitizations(code)
        assignments = self.taint_tracker.find_variable_assignments(code)

        is_tainted, active_taints, sanitizers, source = \
            self.taint_tracker.trace_variable(var_name, line, assignments, sanitizations, code)

        if not is_tainted:
            return False, 0.1, sanitizers

        if taint_type not in active_taints:
            return False, 0.2, sanitizers

        confidence = 0.95 if source else 0.85
        return True, confidence, sanitizers

    def scan_code(self, code: str, filepath: str = "") -> List[Finding]:
        findings = []

        pattern_findings = self.pattern_scanner.scan(code, filepath)

        if self.enable_taint_tracking:
            for pf in pattern_findings:
                is_vuln, confidence, sanitizers = self._is_pattern_verified_by_taint(pf, code)

                if is_vuln:
                    finding = Finding(
                        filepath=filepath,
                        line=pf['line'],
                        severity=pf['severity'],
                        category=pf.get('category', 'UNKNOWN'),
                        pattern_name=pf['pattern_name'],
                        code=pf['code'],
                        confidence=confidence,
                        sanitizers=sanitizers if sanitizers else None,
                        is_verified=True,
                        verification_method="pattern+taint"
                    )
                    findings.append(finding)

            taint_findings = self.data_flow_analyzer.analyze_file(code, filepath)

            for tv in taint_findings.get('vulnerabilities', []):
                already_found = False
                for f in findings:
                    if abs(f.line - tv.sink_line) <= 2:
                        already_found = True
                        break

                if not already_found:
                    finding = Finding(
                        filepath=filepath,
                        line=tv.sink_line,
                        severity='CRITICAL' if tv.confidence > 0.8 else 'HIGH',
                        category=tv.taint_type.value.upper(),
                        pattern_name=f"TAINT_{tv.taint_type.value.upper()}",
                        code=f"Sink: {tv.sink_type}",
                        confidence=tv.confidence,
                        source=tv.source_type,
                        sink=tv.sink_type,
                        sanitizers=tv.sanitizers_applied if tv.sanitizers_applied else None,
                        is_verified=True,
                        verification_method="taint"
                    )
                    findings.append(finding)
        else:
            for pf in pattern_findings:
                finding = Finding(
                    filepath=filepath,
                    line=pf['line'],
                    severity=pf['severity'],
                    category=pf.get('category', 'UNKNOWN'),
                    pattern_name=pf['pattern_name'],
                    code=pf['code'],
                    confidence=pf['confidence'],
                    is_verified=False,
                    verification_method="pattern"
                )
                findings.append(finding)

        return findings

    def scan_file(self, filepath: str) -> List[Finding]:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            return self.scan_code(code, filepath)
        except Exception as e:
            print(f"Error scanning {filepath}: {e}")
            return []

    def scan_directory(self, directory: str, pattern: str = "**/*.php") -> Dict:
        results = {
            'total_files': 0,
            'total_findings': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'findings': [],
            'by_pattern': {},
            'by_file': {},
        }

        php_files = glob.glob(os.path.join(directory, pattern), recursive=True)
        results['total_files'] = len(php_files)

        for filepath in php_files:
            findings = self.scan_file(filepath)
            rel_path = os.path.relpath(filepath, directory)

            for f in findings:
                results['total_findings'] += 1

                if f.severity == 'CRITICAL':
                    results['critical'] += 1
                elif f.severity == 'HIGH':
                    results['high'] += 1
                elif f.severity == 'MEDIUM':
                    results['medium'] += 1
                else:
                    results['low'] += 1

                if f.pattern_name not in results['by_pattern']:
                    results['by_pattern'][f.pattern_name] = []
                results['by_pattern'][f.pattern_name].append(f)

                if rel_path not in results['by_file']:
                    results['by_file'][rel_path] = []
                results['by_file'][rel_path].append(f)

                results['findings'].append(f)

        return results


def main():
    import sys

    print("=" * 80)
    print("APEX Security Scanner v2.0")
    print("Pattern Matching + Taint Tracking + Data Flow Analysis")
    print("=" * 80)

    dle_path = sys.argv[1] if len(sys.argv) > 1 else '.'

    if not os.path.exists(dle_path):
        print(f"DLE path not found: {dle_path}")
        sys.exit(1)

    print("\n[1] Scanning WITH taint tracking (reduced false positives)...")
    scanner_with_taint = APEXScanner(enable_taint_tracking=True)
    results_with = scanner_with_taint.scan_directory(dle_path)

    print(f"\nResults WITH taint tracking:")
    print(f"  Files scanned: {results_with['total_files']}")
    print(f"  Total findings: {results_with['total_findings']}")
    print(f"  Critical: {results_with['critical']}")
    print(f"  High: {results_with['high']}")
    print(f"  Medium: {results_with['medium']}")
    print(f"  Low: {results_with['low']}")

    print("\n[2] Scanning WITHOUT taint tracking (original patterns only)...")
    scanner_no_taint = APEXScanner(enable_taint_tracking=False)
    results_without = scanner_no_taint.scan_directory(dle_path)

    print(f"\nResults WITHOUT taint tracking:")
    print(f"  Files scanned: {results_without['total_files']}")
    print(f"  Total findings: {results_without['total_findings']}")
    print(f"  Critical: {results_without['critical']}")
    print(f"  High: {results_without['high']}")

    if results_without['total_findings'] > 0:
        reduction = (1 - results_with['total_findings'] / results_without['total_findings']) * 100
        print(f"\n{'=' * 80}")
        print(f"FALSE POSITIVE REDUCTION: {reduction:.1f}%")
        print(f"  Before: {results_without['total_findings']} findings")
        print(f"  After:  {results_with['total_findings']} findings")
        print(f"  Eliminated: {results_without['total_findings'] - results_with['total_findings']} false positives")
        print(f"{'=' * 80}")

    print("\n" + "=" * 80)
    print("VERIFIED CRITICAL FINDINGS (After Taint Tracking)")
    print("=" * 80)

    critical_findings = [f for f in results_with['findings'] if f.severity == 'CRITICAL']
    for f in critical_findings[:20]:
        print(f"\n[CRITICAL] {f.pattern_name}")
        print(f"  File: {os.path.basename(f.filepath)}:{f.line}")
        print(f"  Code: {f.code[:70]}")
        print(f"  Confidence: {f.confidence:.0%}")
        print(f"  Verified by: {f.verification_method}")
        if f.source:
            print(f"  Source: {f.source}")
        if f.sanitizers:
            print(f"  Sanitizers (bypassed): {f.sanitizers}")

    print("\n" + "=" * 80)
    print("FINDINGS BY PATTERN (Top 15)")
    print("=" * 80)

    for pattern, findings in sorted(results_with['by_pattern'].items(),
                                    key=lambda x: -len(x[1]))[:15]:
        severity = findings[0].severity
        verified = sum(1 for f in findings if f.is_verified)
        print(f"  [{severity}] {pattern}: {len(findings)} ({verified} verified)")


if __name__ == "__main__":
    main()
