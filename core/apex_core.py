#!/usr/bin/env python3

import os
import sys
import json
import time
import hashlib
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from .taint_engine import TaintAnalyzer, TaintFinding, analyze_php_file
from .symbolic_executor import SymbolicExecutor, symbolic_execute_file
from .interprocedural import InterproceduralAnalyzer
from .rule_engine import get_rule_engine, RuleEngine

# v4.0 modules - imported with fallback for graceful degradation
try:
    from .interprocedural_v2 import InterproceduralEngine
    _HAS_INTERPROC_V2 = True
except ImportError:
    _HAS_INTERPROC_V2 = False

try:
    from .incremental import IncrementalAnalyzer
    _HAS_INCREMENTAL = True
except ImportError:
    _HAS_INCREMENTAL = False

try:
    from .fp_filter_v2 import FPFilterV2, AnalysisContext
    _HAS_FP_V2 = True
except ImportError:
    _HAS_FP_V2 = False

try:
    from .framework_models import FrameworkModelEngine
    _HAS_FRAMEWORK_MODELS = True
except ImportError:
    _HAS_FRAMEWORK_MODELS = False

try:
    from .ml_fp_classifier import FPClassifier, FileAnalysisResults, build_file_analysis
    _HAS_ML = True
except ImportError:
    _HAS_ML = False


@dataclass
class VulnerabilityReport:
    vuln_type: str
    severity: str
    file: str
    line: int
    sink: str
    source: str
    description: str
    confidence: float
    path: List[str] = field(default_factory=list)
    remediation: str = ""
    cwe: str = ""

    def to_dict(self) -> Dict:
        return {
            'type': self.vuln_type,
            'severity': self.severity,
            'file': self.file,
            'line': self.line,
            'sink': self.sink,
            'source': self.source,
            'description': self.description,
            'confidence': self.confidence,
            'path': self.path,
            'remediation': self.remediation,
            'cwe': self.cwe,
        }


class APEXCore:

    def __init__(self, workers: int = 4, verbose: bool = False, rule_engine=None, **kwargs):
        self.workers = workers
        self.verbose = verbose
        self.rules = rule_engine or get_rule_engine()
        self.findings: List[VulnerabilityReport] = []
        self.stats = {
            'files_scanned': 0,
            'functions_analyzed': 0,
            'paths_explored': 0,
            'time_elapsed': 0,
        }
        self._file_cache: Dict[str, str] = {}
        self._init_cwe_remediation()

        # v4.0: incremental analysis cache
        self._incremental = None
        if _HAS_INCREMENTAL:
            cache_dir = kwargs.get('cache_dir', '.')
            try:
                self._incremental = IncrementalAnalyzer(cache_dir=cache_dir)
            except Exception:
                pass

        # v4.0: consolidated FP filter
        self._fp_filter = None
        if _HAS_FP_V2:
            try:
                self._fp_filter = FPFilterV2(self.rules)
            except Exception:
                pass

        # v4.0: framework model engine
        self._framework_engine = None
        if _HAS_FRAMEWORK_MODELS:
            try:
                self._framework_engine = FrameworkModelEngine(self.rules)
            except Exception:
                pass

        # v4.0: ML FP classifier with real analysis integration
        self._ml_classifier = None
        if _HAS_ML:
            try:
                self._ml_classifier = FPClassifier(use_ml=True)
            except Exception:
                pass

    def _init_cwe_remediation(self):
        """Initialize CWE mapping and remediation from rules."""
        # Start with hardcoded defaults
        self.cwe_map = {
            'SQL_INJECTION': ('CWE-89', 'SQL Injection'),
            'COMMAND_INJECTION': ('CWE-78', 'OS Command Injection'),
            'CODE_INJECTION': ('CWE-94', 'Code Injection'),
            'XSS': ('CWE-79', 'Cross-site Scripting'),
            'FILE_INCLUSION': ('CWE-98', 'PHP File Inclusion'),
            'PATH_TRAVERSAL': ('CWE-22', 'Path Traversal'),
            'SSRF': ('CWE-918', 'Server-Side Request Forgery'),
            'DESERIALIZATION': ('CWE-502', 'Deserialization of Untrusted Data'),
            'XXE': ('CWE-611', 'XML External Entity'),
            'RCE': ('CWE-94', 'Remote Code Execution'),
            'OPEN_REDIRECT': ('CWE-601', 'Open Redirect'),
            'IDOR': ('CWE-639', 'Insecure Direct Object Reference'),
            'WEAK_CRYPTO': ('CWE-327', 'Weak Cryptography'),
            'HARDCODED_CREDS': ('CWE-798', 'Hardcoded Credentials'),
            'INFO_DISCLOSURE': ('CWE-200', 'Information Disclosure'),
            'UNSAFE_UPLOAD': ('CWE-434', 'Unsafe File Upload'),
            'TYPE_JUGGLING': ('CWE-843', 'Type Juggling'),
            'HEADER_INJECTION': ('CWE-113', 'HTTP Header Injection'),
            'MASS_ASSIGNMENT': ('CWE-915', 'Mass Assignment'),
            'INSECURE_RANDOM': ('CWE-330', 'Insecure Randomness'),
            'RACE_CONDITION': ('CWE-362', 'Race Condition'),
            'LOG_INJECTION': ('CWE-117', 'Log Injection'),
            'REGEX_DOS': ('CWE-1333', 'Regular Expression DoS'),
            'AUTH_BYPASS': ('CWE-287', 'Authentication Bypass'),
            'CSRF': ('CWE-352', 'Cross-Site Request Forgery'),
            'LDAP_INJECTION': ('CWE-90', 'LDAP Injection'),
            'XPATH_INJECTION': ('CWE-643', 'XPath Injection'),
            'TEMPLATE_INJECTION': ('CWE-1336', 'Template Injection'),
            'FILE_WRITE': ('CWE-73', 'Arbitrary File Write'),
            'FILE_READ': ('CWE-22', 'Arbitrary File Read'),
            'NOSQL': ('CWE-943', 'NoSQL Injection'),
        }
        self.remediation_map = {
            'SQL_INJECTION': 'Use parameterized queries or prepared statements.',
            'COMMAND_INJECTION': 'Use escapeshellarg() and escapeshellcmd().',
            'CODE_INJECTION': 'Never use eval() with user input.',
            'XSS': 'Use htmlspecialchars() with ENT_QUOTES flag.',
            'FILE_INCLUSION': 'Use basename() and validate against whitelist.',
            'PATH_TRAVERSAL': 'Use realpath() and validate path is within expected directory.',
            'SSRF': 'Validate and whitelist allowed URLs/hosts.',
            'DESERIALIZATION': 'Avoid unserialize() with user input. Use JSON.',
            'XXE': 'Disable external entity loading.',
        }
        # Extend from YAML rules (patterns have remediation)
        for vuln_name, pats in self.rules.get_patterns().items():
            if pats and pats[0].remediation and vuln_name not in self.remediation_map:
                self.remediation_map[vuln_name] = pats[0].remediation
            if pats and pats[0].cwe and vuln_name not in self.cwe_map:
                self.cwe_map[vuln_name] = (pats[0].cwe, vuln_name.replace('_', ' ').title())

    def analyze(self, target: str, mode: str = 'full') -> List[VulnerabilityReport]:
        start_time = time.time()
        target_path = Path(target)

        if target_path.is_file():
            self._analyze_file(str(target_path), mode)
        else:
            self._analyze_directory(str(target_path), mode)

        self.stats['time_elapsed'] = time.time() - start_time
        self._deduplicate_findings()
        self._rank_findings()

        return self.findings

    def _analyze_directory(self, directory: str, mode: str):
        php_files = list(Path(directory).rglob("*.php"))
        self.stats['files_scanned'] = len(php_files)

        if self.verbose:
            print(f"[*] Found {len(php_files)} PHP files")

        if self.verbose:
            print("[*] Phase 1: Taint Analysis")

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {
                executor.submit(self._run_taint_analysis, str(f)): f
                for f in php_files
            }

            for future in as_completed(futures):
                try:
                    findings = future.result()
                    self._add_taint_findings(findings)
                except Exception as e:
                    if self.verbose:
                        print(f"[!] Error in taint analysis: {e}")

        if mode in ('standard', 'full'):
            if self.verbose:
                print("[*] Phase 2: Symbolic Execution")

            critical_files = self._identify_critical_files(php_files)

            for php_file in critical_files[:50]:
                try:
                    findings = symbolic_execute_file(str(php_file))
                    self._add_symbolic_findings(findings)
                except Exception as e:
                    if self.verbose:
                        print(f"[!] Error in symbolic execution: {e}")

        if mode == 'full':
            if self.verbose:
                print("[*] Phase 3: Inter-procedural Analysis")

            try:
                if _HAS_INTERPROC_V2:
                    engine = InterproceduralEngine(k=2)
                    findings = engine.analyze_directory(directory)
                    self._add_interprocedural_findings(findings)
                    self.stats['functions_analyzed'] = engine.get_summary().get('total_functions', 0)
                else:
                    interprocedural = InterproceduralAnalyzer()
                    findings = interprocedural.analyze_directory(directory)
                    self._add_interprocedural_findings(findings)
                    self.stats['functions_analyzed'] = interprocedural.get_call_graph_stats()['total_functions']
            except Exception as e:
                if self.verbose:
                    print(f"[!] Error in inter-procedural analysis: {e}")

        # Apply ML scoring to all findings
        if self.findings and self._ml_classifier:
            file_codes = {}
            for f in self.findings:
                fp = f.file if hasattr(f, 'file') else f.get('file', '')
                if fp and fp not in file_codes:
                    try:
                        with open(fp, 'r', encoding='utf-8', errors='ignore') as fh:
                            file_codes[fp] = fh.read()
                    except Exception:
                        file_codes[fp] = ''
            # Convert VulnerabilityReport objects to dicts for ML scoring
            finding_dicts = [fi.to_dict() for fi in self.findings]
            finding_dicts = self._apply_ml_scoring(finding_dicts, file_codes)
            # Update findings with ML metadata
            for fi, fd in zip(self.findings, finding_dicts):
                if 'ml_score' in fd:
                    fi.confidence = fd.get('confidence', fi.confidence)

        # v4.0: Save incremental cache
        if self._incremental:
            try:
                self._incremental.save_cache()
            except Exception:
                pass

    def _analyze_file(self, file_path: str, mode: str):
        self.stats['files_scanned'] = 1

        try:
            findings = analyze_php_file(file_path)
            self._add_taint_findings(findings)
        except Exception as e:
            if self.verbose:
                print(f"[!] Taint analysis error: {e}")

        if mode in ('standard', 'full'):
            try:
                findings = symbolic_execute_file(file_path)
                self._add_symbolic_findings(findings)
            except Exception as e:
                if self.verbose:
                    print(f"[!] Symbolic execution error: {e}")

        # Apply ML scoring to findings from single file
        if self.findings and self._ml_classifier:
            file_codes = {}
            for f in self.findings:
                fp = f.file if hasattr(f, 'file') else f.get('file', '')
                if fp and fp not in file_codes:
                    try:
                        with open(fp, 'r', encoding='utf-8', errors='ignore') as fh:
                            file_codes[fp] = fh.read()
                    except Exception:
                        file_codes[fp] = ''
            finding_dicts = [fi.to_dict() for fi in self.findings]
            finding_dicts = self._apply_ml_scoring(finding_dicts, file_codes)
            for fi, fd in zip(self.findings, finding_dicts):
                if 'ml_score' in fd:
                    fi.confidence = fd.get('confidence', fi.confidence)

    def _run_taint_analysis(self, file_path: str) -> List[TaintFinding]:
        try:
            return analyze_php_file(file_path)
        except:
            return []

    def _identify_critical_files(self, files: List[Path]) -> List[Path]:
        critical = []
        critical_patterns = [
            'login', 'auth', 'admin', 'upload', 'download',
            'include', 'exec', 'eval', 'query', 'sql',
            'api', 'ajax', 'rpc', 'service'
        ]

        for f in files:
            name = f.stem.lower()
            if any(p in name for p in critical_patterns):
                critical.append(f)

        remaining = [f for f in files if f not in critical]
        for f in remaining[:100]:
            try:
                size = f.stat().st_size
                if size > 10000:
                    critical.append(f)
            except:
                pass

        return critical

    def _add_taint_findings(self, findings: List[TaintFinding]):
        for f in findings:
            vuln_type = f.taint_type.name if hasattr(f.taint_type, 'name') else str(f.taint_type)
            cwe, _ = self.cwe_map.get(vuln_type, ('', ''))

            report = VulnerabilityReport(
                vuln_type=vuln_type,
                severity=f.severity,
                file=f.sink_file,
                line=f.sink_line,
                sink=f.sink_name,
                source=f.source.name if hasattr(f.source, 'name') else str(f.source),
                description=f"Tainted data from {f.source} flows to {f.sink_name}",
                confidence=f.confidence,
                path=[str(p) for p in f.path],
                remediation=self.remediation_map.get(vuln_type, ''),
                cwe=cwe
            )
            self.findings.append(report)

    def _add_symbolic_findings(self, findings: List[Dict]):
        for f in findings:
            vuln_type = f.get('type', 'UNKNOWN')
            cwe, _ = self.cwe_map.get(vuln_type.replace('_INJECTION', ''), ('', ''))

            report = VulnerabilityReport(
                vuln_type=vuln_type,
                severity=f.get('severity', 'MEDIUM'),
                file=f.get('file', ''),
                line=f.get('line', 0),
                sink=f.get('sink', ''),
                source=f.get('source', ''),
                description=f"Symbolic execution found path from {f.get('source')} to {f.get('sink')}",
                confidence=0.7,
                path=f.get('operations', []),
                remediation=self.remediation_map.get(vuln_type.replace('_INJECTION', ''), ''),
                cwe=cwe
            )
            self.findings.append(report)

    def _add_interprocedural_findings(self, findings: List[Dict]):
        for f in findings:
            vuln_type = f.get('type', 'UNKNOWN')
            cwe, _ = self.cwe_map.get(vuln_type.replace('_INJECTION', ''), ('', ''))

            desc = f"Inter-procedural taint flow through {f.get('function', f.get('vulnerable_function', ''))} "
            desc += f"from parameter {f.get('param_name', f.get('param_index', '?'))}"

            report = VulnerabilityReport(
                vuln_type=vuln_type,
                severity=f.get('severity', 'HIGH'),
                file=f.get('file', f.get('call_site_file', '')),
                line=f.get('sink_line', f.get('call_site_line', 0)),
                sink=f.get('sink', ''),
                source=f"param:{f.get('param_name', f.get('param_index', '?'))}",
                description=desc,
                confidence=0.8,
                remediation=self.remediation_map.get(vuln_type.replace('_INJECTION', ''), ''),
                cwe=cwe
            )
            self.findings.append(report)

    def _build_analysis_results(self, filepath: str, code: str) -> Optional['FileAnalysisResults']:
        """Run v4.0 analysis modules on a file for ML feature extraction."""
        if not _HAS_ML:
            return None
        try:
            return build_file_analysis(filepath, code, self.rules)
        except Exception:
            return None

    def _apply_ml_scoring(self, findings: list, file_codes: dict) -> list:
        """Apply ML FP classifier to findings, adjusting confidence scores.
        
        This integrates ML scoring INTO the pipeline (not just post-filter).
        ML score adjusts finding confidence rather than removing findings outright.
        """
        if not self._ml_classifier:
            return findings
        
        try:
            # Build analysis results for each file
            file_analyses = {}
            for filepath, code in file_codes.items():
                ar = self._build_analysis_results(filepath, code)
                if ar:
                    file_analyses[filepath] = ar
            
            # Classify each finding
            for f in findings:
                filepath = f.get('file', '')
                code = file_codes.get(filepath, '')
                file_lines = code.splitlines() if code else []
                analysis = file_analyses.get(filepath)
                
                result = self._ml_classifier.classify(f, code, file_lines, analysis)
                
                # Add ML metadata to finding
                f['ml_is_tp'] = result.is_tp
                f['ml_score'] = round(result.score, 3)
                f['ml_confidence'] = round(result.confidence, 2)
                f['ml_reasoning'] = result.reasoning
                f['ml_method'] = result.method
                
                # Adjust finding confidence based on ML score
                original_conf = f.get('confidence', 50)
                if isinstance(original_conf, str) and '%' in original_conf:
                    original_conf = float(original_conf.replace('%', ''))
                original_conf = float(original_conf)
                
                # Blend original confidence with ML score
                # ML score influences final confidence (30% weight)
                ml_adjustment = (result.score - 0.5) * 60  # -30 to +30
                adjusted = max(5, min(100, original_conf + ml_adjustment))
                f['confidence'] = f'{int(adjusted)}%'
                f['original_confidence'] = f'{int(original_conf)}%'
            
            return findings
        except Exception:
            return findings

    def _deduplicate_findings(self):
        seen = set()
        unique = []

        for f in self.findings:
            key = f"{f.vuln_type}:{f.file}:{f.line}:{f.sink}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        self.findings = unique

    def _rank_findings(self):
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        self.findings.sort(
            key=lambda f: (
                severity_order.get(f.severity, 4),
                -f.confidence
            )
        )

    def generate_report(self, output_format: str = 'json') -> str:
        if output_format == 'json':
            report = {
                'summary': {
                    'total_findings': len(self.findings),
                    'critical': len([f for f in self.findings if f.severity == 'CRITICAL']),
                    'high': len([f for f in self.findings if f.severity == 'HIGH']),
                    'medium': len([f for f in self.findings if f.severity == 'MEDIUM']),
                    'low': len([f for f in self.findings if f.severity == 'LOW']),
                },
                'stats': self.stats,
                'findings': [f.to_dict() for f in self.findings]
            }

            return json.dumps(report, indent=2)

        elif output_format == 'sarif':
            return self._generate_sarif()

        else:
            return self._generate_text_report()

    def _generate_sarif(self) -> str:
        sarif = {
            '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            'version': '2.1.0',
            'runs': [{
                'tool': {
                    'driver': {
                        'name': 'APEX',
                        'version': '1.0.0',
                        'informationUri': 'https://github.com/tron0x8/apex',
                        'rules': []
                    }
                },
                'results': []
            }]
        }

        rules_added = set()
        for f in self.findings:
            if f.vuln_type not in rules_added:
                cwe, desc = self.cwe_map.get(f.vuln_type, ('', f.vuln_type))
                sarif['runs'][0]['tool']['driver']['rules'].append({
                    'id': f.vuln_type,
                    'name': desc,
                    'shortDescription': {'text': desc},
                    'help': {'text': self.remediation_map.get(f.vuln_type, '')}
                })
                rules_added.add(f.vuln_type)

            sarif['runs'][0]['results'].append({
                'ruleId': f.vuln_type,
                'level': 'error' if f.severity in ('CRITICAL', 'HIGH') else 'warning',
                'message': {'text': f.description},
                'locations': [{
                    'physicalLocation': {
                        'artifactLocation': {'uri': f.file},
                        'region': {'startLine': f.line}
                    }
                }]
            })

        return json.dumps(sarif, indent=2)

    def _generate_text_report(self) -> str:
        lines = [
            "=" * 70,
            "APEX Security Analysis Report",
            "=" * 70,
            "",
            f"Files Scanned: {self.stats['files_scanned']}",
            f"Functions Analyzed: {self.stats['functions_analyzed']}",
            f"Time Elapsed: {self.stats['time_elapsed']:.2f}s",
            "",
            "SUMMARY",
            "-" * 70,
            f"CRITICAL: {len([f for f in self.findings if f.severity == 'CRITICAL'])}",
            f"HIGH: {len([f for f in self.findings if f.severity == 'HIGH'])}",
            f"MEDIUM: {len([f for f in self.findings if f.severity == 'MEDIUM'])}",
            f"LOW: {len([f for f in self.findings if f.severity == 'LOW'])}",
        ]

        lines.extend([
            "",
            "FINDINGS",
            "-" * 70,
        ])

        for i, f in enumerate(self.findings, 1):
            lines.extend([
                f"",
                f"[{i}] {f.vuln_type} ({f.severity})",
                f"    File: {f.file}:{f.line}",
                f"    Sink: {f.sink}",
                f"    Source: {f.source}",
                f"    {f.description}",
                f"    CWE: {f.cwe}",
                f"    Remediation: {f.remediation[:100]}..."
            ])

        return '\n'.join(lines)


def main():
    import argparse

    parser = argparse.ArgumentParser(description='APEX - Advanced PHP Exploitation Scanner')
    parser.add_argument('target', help='Target file or directory')
    parser.add_argument('-m', '--mode', choices=['quick', 'standard', 'full'],
                       default='standard', help='Analysis mode')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('-f', '--format', choices=['json', 'sarif', 'text'],
                       default='json', help='Output format')
    parser.add_argument('-w', '--workers', type=int, default=4,
                       help='Number of parallel workers')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    print(r"""
    +===========================================================================+
    |      _    ____  _______  __                                               |
    |     / \  |  _ \| ____\ \/ /                                               |
    |    / _ \ | |_) |  _|  \  /                                                |
    |   / ___ \|  __/| |___ /  \                                                |
    |  /_/   \_\_|   |_____/_/\_\                                               |
    |                                                                           |
    |  Advanced PHP Exploitation Scanner                                        |
    |  github.com/tron0x8/apex                                                  |
    +===========================================================================+
    """)

    analyzer = APEXCore(
        workers=args.workers,
        verbose=args.verbose,
    )
    findings = analyzer.analyze(args.target, args.mode)

    report = analyzer.generate_report(args.format)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"\n[+] Report written to {args.output}")
    else:
        print(report)

    print(f"\n[*] Analysis complete!")
    print(f"    Files: {analyzer.stats['files_scanned']}")
    print(f"    Time: {analyzer.stats['time_elapsed']:.2f}s")
    print(f"    Findings: {len(findings)}")

    critical = len([f for f in findings if f.severity == 'CRITICAL'])
    if critical > 0:
        print(f"\n[!] {critical} CRITICAL vulnerabilities found!")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
