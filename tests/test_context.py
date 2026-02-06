#!/usr/bin/env python3
"""Test advanced context analyzer"""

import sys
sys.path.insert(0, 'C:\\Users\\User\\Desktop\\apex')

from core.context_analyzer import (
    WhitelistDetector, CustomFunctionAnalyzer,
    AuthContextAnalyzer, AdvancedContextAnalyzer
)

def test_whitelist():
    print("=== TEST 1: Whitelist Detection ===")

    code = '''<?php
$page = $_GET['page'];
$allowed = ['home', 'about', 'contact'];
if (in_array($page, $allowed)) {
    include $page . '.php';
}
?>'''

    wl = WhitelistDetector(code)
    is_wl, reason = wl.is_whitelisted("$page", 5)
    print(f"  Whitelist detected: {is_wl}")
    print(f"  Reason: {reason}")
    assert is_wl, "Should detect whitelist!"
    print("  [PASS]\n")


def test_custom_function():
    print("=== TEST 2: Custom Function Analysis ===")

    code = '''<?php
function sanitize($input) {
    return htmlspecialchars($input, ENT_QUOTES);
}

function validate($id) {
    return intval($id);
}

$name = sanitize($_GET['name']);
echo $name;
?>'''

    cf = CustomFunctionAnalyzer(code)
    is_san, types = cf.is_sanitizer_function('sanitize')
    print(f"  sanitize() is sanitizer: {is_san}, types: {types}")
    assert is_san and 'xss' in types, "Should detect XSS sanitizer!"

    is_san, types = cf.is_sanitizer_function('validate')
    print(f"  validate() is sanitizer: {is_san}, types: {types}")
    assert is_san and 'sql' in types, "Should detect SQL sanitizer!"
    print("  [PASS]\n")


def test_auth_context():
    print("=== TEST 3: Auth Context Detection ===")

    code = '''<?php
if (!$is_logged) {
    die('Access denied');
}

if ($member_id['user_group'] == 1) {
    // Admin only
    eval($_POST['code']);
}
?>'''

    auth = AuthContextAnalyzer(code)
    ctx = auth.analyze(8)  # eval line
    print(f"  Has auth check: {ctx.has_auth_check}")
    print(f"  Auth type: {ctx.auth_type}")
    print(f"  Confidence: {ctx.confidence}")
    assert ctx.has_auth_check, "Should detect auth check!"
    assert ctx.auth_type == 'admin', "Should detect admin context!"
    print("  [PASS]\n")


def test_combined():
    print("=== TEST 4: Combined Analysis ===")

    code = '''<?php
$action = $_GET['action'];

switch($action) {
    case 'view':
        showPage();
        break;
    case 'edit':
        editPage();
        break;
}

function clean($s) {
    return mysqli_real_escape_string($conn, $s);
}

$id = clean($_GET['id']);
mysql_query("SELECT * FROM users WHERE id = $id");
?>'''

    adv = AdvancedContextAnalyzer(code)

    # Switch whitelist
    is_fp, reason = adv.is_false_positive(5, "$_GET['action']", "CODE_INJECTION")
    print(f"  Switch whitelist FP: {is_fp}, reason: {reason}")

    # Custom sanitizer
    is_fp, reason = adv.is_false_positive(18, "$_GET['id']", "SQL_INJECTION")
    print(f"  Custom function FP: {is_fp}, reason: {reason}")

    print("  [PASS]\n")


if __name__ == '__main__':
    test_whitelist()
    test_custom_function()
    test_auth_context()
    test_combined()
    print("=== ALL TESTS PASSED ===")
