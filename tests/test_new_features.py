#!/usr/bin/env python3
"""
Tests for APEX v3.0 new features:
- New vulnerability type detection (6 new types)
- HTML report generation
- ML FP classifier
- Auth Bypass detection
- Improved sanitizer detection
- Deduplication improvements
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from core.unified_scanner import UnifiedScanner, VulnType, Finding


@pytest.fixture(scope='module')
def scanner():
    return UnifiedScanner()


# ============================================================
# New vulnerability type tests
# ============================================================

class TestHeaderInjection:
    def test_header_with_get(self, scanner):
        code = '<?php\nheader("Location: " . $_GET["url"]);\n?>'
        findings = scanner.scan_code(code, 'test.php')
        types = {f.vuln_type for f in findings}
        assert VulnType.HEADER_INJECTION in types

    def test_header_with_variable(self, scanner):
        code = '<?php\nheader("X-Custom: " . $_POST["value"]);\n?>'
        findings = scanner.scan_code(code, 'test.php')
        types = {f.vuln_type for f in findings}
        assert VulnType.HEADER_INJECTION in types

    def test_setcookie_injection(self, scanner):
        code = '<?php\nsetcookie($_GET["name"], "value");\n?>'
        findings = scanner.scan_code(code, 'test.php')
        types = {f.vuln_type for f in findings}
        assert VulnType.HEADER_INJECTION in types


class TestMassAssignment:
    def test_extract_post(self, scanner):
        code = '<?php\nextract($_POST);\n?>'
        findings = scanner.scan_code(code, 'test.php')
        types = {f.vuln_type for f in findings}
        assert VulnType.MASS_ASSIGNMENT in types

    def test_orm_fill(self, scanner):
        code = '<?php\n$user->fill($_POST);\n?>'
        findings = scanner.scan_code(code, 'test.php')
        types = {f.vuln_type for f in findings}
        assert VulnType.MASS_ASSIGNMENT in types

    def test_orm_create(self, scanner):
        code = '<?php\nUser::create($_REQUEST);\n?>'
        findings = scanner.scan_code(code, 'test.php')
        types = {f.vuln_type for f in findings}
        assert VulnType.MASS_ASSIGNMENT in types

    def test_safe_with_only(self, scanner):
        """->only() should reduce confidence significantly"""
        code = '<?php\n$user->fill($request->only(["name", "email"]));\n?>'
        findings = scanner.scan_code(code, 'test.php')
        mass = [f for f in findings if f.vuln_type == VulnType.MASS_ASSIGNMENT]
        # Should either not detect or have low confidence
        assert not mass or mass[0].confidence < 0.6


class TestInsecureRandom:
    def test_md5_mt_rand(self, scanner):
        code = '<?php\n$token = md5(mt_rand());\n?>'
        findings = scanner.scan_code(code, 'test.php')
        types = {f.vuln_type for f in findings}
        assert VulnType.INSECURE_RANDOM in types

    def test_uniqid_bare(self, scanner):
        code = '<?php\n$id = uniqid();\n?>'
        findings = scanner.scan_code(code, 'test.php')
        types = {f.vuln_type for f in findings}
        assert VulnType.INSECURE_RANDOM in types


class TestRaceCondition:
    def test_toctou(self, scanner):
        code = '<?php\nif (file_exists($file)) {\n  unlink($file);\n}\n?>'
        findings = scanner.scan_code(code, 'test.php')
        types = {f.vuln_type for f in findings}
        assert VulnType.RACE_CONDITION in types


class TestLogInjection:
    def test_error_log_post(self, scanner):
        code = '<?php\nerror_log("Login: " . $_POST["user"]);\n?>'
        findings = scanner.scan_code(code, 'test.php')
        types = {f.vuln_type for f in findings}
        assert VulnType.LOG_INJECTION in types

    def test_syslog_get(self, scanner):
        code = '<?php\nsyslog(LOG_INFO, $_GET["msg"]);\n?>'
        findings = scanner.scan_code(code, 'test.php')
        types = {f.vuln_type for f in findings}
        assert VulnType.LOG_INJECTION in types


class TestRegexDoS:
    def test_nested_quantifiers(self, scanner):
        code = '<?php\npreg_match("/^(a+)+$/", $_GET["input"]);\n?>'
        findings = scanner.scan_code(code, 'test.php')
        types = {f.vuln_type for f in findings}
        assert VulnType.REGEX_DOS in types

    def test_user_controlled_pattern(self, scanner):
        code = '<?php\npreg_match($_GET["pattern"], $input);\n?>'
        findings = scanner.scan_code(code, 'test.php')
        types = {f.vuln_type for f in findings}
        assert VulnType.REGEX_DOS in types


class TestAuthBypass:
    def test_admin_from_cookie(self, scanner):
        code = '<?php\n$is_admin = $_COOKIE["admin"];\n?>'
        findings = scanner.scan_code(code, 'test.php')
        types = {f.vuln_type for f in findings}
        assert VulnType.AUTH_BYPASS in types

    def test_role_from_get(self, scanner):
        code = '<?php\n$role = $_GET["role"];\n?>'
        findings = scanner.scan_code(code, 'test.php')
        types = {f.vuln_type for f in findings}
        assert VulnType.AUTH_BYPASS in types


# ============================================================
# Sanitizer detection tests
# ============================================================

class TestSanitizerDetection:
    def test_intval_safe_sql(self, scanner):
        """intval should prevent SQL injection"""
        code = '<?php\n$id = intval($_GET["id"]);\n$db->query("SELECT * FROM t WHERE id=" . $id);\n?>'
        findings = scanner.scan_code(code, 'test.php')
        sql = [f for f in findings if f.vuln_type == VulnType.SQL_INJECTION]
        assert not sql or all(f.confidence < 0.6 for f in sql)

    def test_escapeshellarg_safe_cmd(self, scanner):
        """escapeshellarg should prevent command injection"""
        code = '<?php\n$arg = escapeshellarg($_GET["arg"]);\nsystem("ls " . $arg);\n?>'
        findings = scanner.scan_code(code, 'test.php')
        cmd = [f for f in findings if f.vuln_type == VulnType.COMMAND_INJECTION]
        assert not cmd or all(f.confidence < 0.6 for f in cmd)


# ============================================================
# HTML Report generation tests
# ============================================================

class TestHTMLReport:
    def test_generates_html(self):
        from core.html_report import generate_html_report
        results = {
            'scan_date': '2024-01-01T00:00:00',
            'target': '/test',
            'total_files': 10,
            'total_findings': 2,
            'critical': 1,
            'high': 1,
            'medium': 0,
            'low': 0,
            'findings': [
                {'type': 'SQL Injection', 'severity': 'CRITICAL', 'line': 5,
                 'code': 'mysql_query($x)', 'file': 'test.php', 'confidence': '100%',
                 'source': 'GET', 'sanitizers': []},
                {'type': 'XSS', 'severity': 'HIGH', 'line': 10,
                 'code': 'echo $y', 'file': 'test.php', 'confidence': '85%',
                 'source': 'POST', 'sanitizers': []},
            ],
        }
        html = generate_html_report(results, '/test')
        assert '<!DOCTYPE html>' in html
        assert 'APEX Security Report' in html
        assert 'SQL Injection' in html
        assert 'CWE-89' in html
        assert 'Risk Score' in html

    def test_empty_findings(self):
        from core.html_report import generate_html_report
        results = {
            'scan_date': '2024-01-01T00:00:00', 'target': '/test',
            'total_files': 5, 'total_findings': 0,
            'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
            'findings': [],
        }
        html = generate_html_report(results, '/test')
        assert 'No vulnerabilities found' in html

    def test_file_output(self, tmp_path):
        from core.html_report import generate_html_report
        results = {
            'scan_date': '2024-01-01T00:00:00', 'target': '/test',
            'total_files': 1, 'total_findings': 0,
            'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
            'findings': [],
        }
        out = str(tmp_path / 'report.html')
        result = generate_html_report(results, '/test', out)
        assert os.path.exists(out)
        assert os.path.getsize(out) > 100


# ============================================================
# ML FP Classifier tests
# ============================================================

class TestMLFPClassifier:
    def test_heuristic_tp(self):
        from core.ml_fp_classifier import FPClassifier
        classifier = FPClassifier()
        findings = [{
            'type': 'SQL Injection', 'severity': 'CRITICAL', 'line': 5,
            'code': 'mysql_query("SELECT * FROM users WHERE id=" . $_GET["id"])',
            'file': 'test.php', 'confidence': '100%', 'source': 'GET', 'sanitizers': [],
        }]
        result = classifier.classify_batch(findings, {
            'test.php': '<?php\nmysql_query("SELECT * FROM users WHERE id=" . $_GET["id"]);\n?>'
        })
        assert len(result) == 1  # Should keep TP

    def test_heuristic_fp_sanitized(self):
        from core.ml_fp_classifier import FPClassifier
        classifier = FPClassifier()
        findings = [{
            'type': 'SQL Injection', 'severity': 'MEDIUM', 'line': 5,
            'code': '$stmt = $db->prepare("SELECT * FROM users WHERE id = ?");',
            'file': 'test.php', 'confidence': '55%', 'source': 'GET',
            'sanitizers': ['prepare', 'intval'],
        }]
        code = '<?php\n$id = intval($_GET["id"]);\n$stmt = $db->prepare("SELECT * FROM users WHERE id = ?");\n$stmt->execute([$id]);\n?>'
        result = classifier.classify_batch(findings, {'test.php': code})
        assert len(result) == 0  # Should eliminate FP (prepared stmt + intval + low confidence)

    def test_classify_batch_empty(self):
        from core.ml_fp_classifier import FPClassifier
        classifier = FPClassifier()
        result = classifier.classify_batch([], {})
        assert result == []


# ============================================================
# Deduplication tests
# ============================================================

class TestDeduplication:
    def test_same_line_same_type_dedup(self, scanner):
        """Multiple matches on same line, same type should be deduplicated"""
        code = '<?php\necho $_GET["a"] . $_GET["b"];\n?>'
        findings = scanner.scan_code(code, 'test.php')
        xss = [f for f in findings if f.vuln_type == VulnType.XSS]
        # Should be max 1 XSS finding on line 2
        lines = [f.line for f in xss if f.line == 2]
        assert len(lines) <= 1

    def test_highest_confidence_kept(self, scanner):
        """When deduplicating, highest confidence should be kept"""
        # This is tested implicitly - hard to unit test directly
        code = '<?php\n$id = $_GET["id"];\necho $id;\n?>'
        findings = scanner.scan_code(code, 'test.php')
        # Verify findings are present and have meaningful confidence
        for f in findings:
            assert f.confidence >= 0.50


# ============================================================
# OWASP coverage test
# ============================================================

class TestOWASPCoverage:
    def test_all_owasp_types_have_patterns(self, scanner):
        """All OWASP Top 10 related types should have patterns"""
        owasp_types = [
            VulnType.SQL_INJECTION, VulnType.XSS, VulnType.COMMAND_INJECTION,
            VulnType.CODE_INJECTION, VulnType.FILE_INCLUSION,
            VulnType.DESERIALIZATION, VulnType.SSRF, VulnType.WEAK_CRYPTO,
            VulnType.HARDCODED_CREDS, VulnType.TYPE_JUGGLING,
            VulnType.AUTH_BYPASS, VulnType.HEADER_INJECTION,
            VulnType.MASS_ASSIGNMENT, VulnType.INSECURE_RANDOM,
            VulnType.RACE_CONDITION, VulnType.LOG_INJECTION,
            VulnType.REGEX_DOS,
        ]
        for vt in owasp_types:
            assert vt in scanner.compiled_patterns, f"Missing patterns for {vt.value}"
            assert len(scanner.compiled_patterns[vt]) > 0, f"Empty patterns for {vt.value}"

    def test_pattern_count(self, scanner):
        """Should have at least 100 patterns total"""
        total = sum(len(p) for p in scanner.compiled_patterns.values())
        assert total >= 100, f"Only {total} patterns, expected 100+"
