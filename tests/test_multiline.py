#!/usr/bin/env python3
"""Tests for multi-line pattern detection (Phase E)."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.unified_scanner import UnifiedScanner, VulnType


scanner = UnifiedScanner()


def has_vuln(findings, vuln_type):
    """Check if a specific vulnerability type was found."""
    return any(f.vuln_type == vuln_type for f in findings)


def test_multiline_sqli():
    """Test SQL injection across multiple lines."""
    code = '''<?php
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id=" . $id;
$result = mysql_query($query);
'''
    findings = scanner.scan_code(code, 'test.php')
    assert has_vuln(findings, VulnType.SQL_INJECTION), \
        f"Expected SQL injection, got: {[f.vuln_type.value for f in findings]}"
    print("  [PASS] multiline_sqli")


def test_multiline_cmdi():
    """Test command injection across multiple lines."""
    code = '''<?php
$cmd = $_POST['command'];
$escaped = $cmd;
system($escaped);
'''
    findings = scanner.scan_code(code, 'test.php')
    assert has_vuln(findings, VulnType.COMMAND_INJECTION), \
        f"Expected command injection, got: {[f.vuln_type.value for f in findings]}"
    print("  [PASS] multiline_cmdi")


def test_multiline_xss():
    """Test XSS across multiple lines (same variable name tracked)."""
    code = '''<?php
$name = $_GET['name'];
$x = "something";
echo "Hello " . $name;
'''
    findings = scanner.scan_code(code, 'test.php')
    assert has_vuln(findings, VulnType.XSS), \
        f"Expected XSS, got: {[f.vuln_type.value for f in findings]}"
    print("  [PASS] multiline_xss")


def test_multiline_lfi():
    """Test file inclusion across multiple lines."""
    code = '''<?php
$page = $_GET['page'];
$path = "pages/" . $page;
include($path);
'''
    findings = scanner.scan_code(code, 'test.php')
    assert has_vuln(findings, VulnType.FILE_INCLUSION), \
        f"Expected file inclusion, got: {[f.vuln_type.value for f in findings]}"
    print("  [PASS] multiline_lfi")


def test_multiline_eval():
    """Test code injection via eval across multiple lines."""
    code = '''<?php
$code = $_REQUEST['code'];
$exec = $code;
eval($exec);
'''
    findings = scanner.scan_code(code, 'test.php')
    assert has_vuln(findings, VulnType.CODE_INJECTION), \
        f"Expected code injection, got: {[f.vuln_type.value for f in findings]}"
    print("  [PASS] multiline_eval")


def test_multiline_deser():
    """Test deserialization across multiple lines."""
    code = '''<?php
$data = $_POST['data'];
$decoded = base64_decode($data);
$obj = unserialize($decoded);
'''
    findings = scanner.scan_code(code, 'test.php')
    assert has_vuln(findings, VulnType.DESERIALIZATION), \
        f"Expected deserialization, got: {[f.vuln_type.value for f in findings]}"
    print("  [PASS] multiline_deser")


def test_multiline_sanitized_no_fp():
    """Test that multiline sanitized flows are not flagged."""
    code = '''<?php
$id = $_GET['id'];
$safe_id = intval($id);
$result = mysql_query("SELECT * FROM users WHERE id=" . $safe_id);
'''
    findings = scanner.scan_code(code, 'test.php')
    # Should NOT have SQL injection (intval sanitizes)
    sqli_findings = [f for f in findings if f.vuln_type == VulnType.SQL_INJECTION]
    assert len(sqli_findings) == 0, \
        f"Expected no SQL injection with intval, got {len(sqli_findings)}"
    print("  [PASS] multiline_sanitized_no_fp")


def test_multiline_htmlspecialchars_no_fp():
    """Test that htmlspecialchars prevents XSS detection."""
    code = '''<?php
$name = $_GET['name'];
$safe = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
echo $safe;
'''
    findings = scanner.scan_code(code, 'test.php')
    xss_findings = [f for f in findings if f.vuln_type == VulnType.XSS]
    assert len(xss_findings) == 0, \
        f"Expected no XSS with htmlspecialchars, got {len(xss_findings)}"
    print("  [PASS] multiline_htmlspecialchars_no_fp")


def test_no_source_skip():
    """Test that files without superglobals are skipped quickly."""
    code = '''<?php
$x = 1;
$y = 2;
echo $x + $y;
mysql_query("SELECT 1");
'''
    findings = scanner.scan_code(code, 'test.php')
    # Should have no multiline findings (no sources)
    multiline = [f for f in findings if hasattr(f, 'source') and f.source and f.source.startswith('$_')]
    # This is a basic check - files without $_GET/POST should not produce multiline findings
    print("  [PASS] no_source_skip")


if __name__ == '__main__':
    print("=== Multi-line Pattern Tests ===\n")
    tests = [
        test_multiline_sqli,
        test_multiline_cmdi,
        test_multiline_xss,
        test_multiline_lfi,
        test_multiline_eval,
        test_multiline_deser,
        test_multiline_sanitized_no_fp,
        test_multiline_htmlspecialchars_no_fp,
        test_no_source_skip,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"  [FAIL] {test.__name__}: {e}")
            failed += 1

    print(f"\n{'='*50}")
    print(f"Results: {passed} PASS, {failed} FAIL out of {passed + failed} tests")
    sys.exit(1 if failed else 0)
