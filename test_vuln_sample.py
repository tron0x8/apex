#!/usr/bin/env python3
"""Test scanner with known vulnerable code samples"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.unified_scanner import UnifiedScanner

scanner = UnifiedScanner(enable_ml=False, enable_ast=False)

# Test vulnerable code samples
test_cases = {
    "SQL Injection (direct)": '''<?php
$id = $_GET['id'];
$result = mysql_query("SELECT * FROM users WHERE id=" . $_GET['id']);
?>''',

    "SQL Injection (variable)": '''<?php
$name = $_POST['name'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE name='$name'");
?>''',

    "Command Injection (exec)": '''<?php
$cmd = $_GET['cmd'];
system($cmd);
exec($_POST['command']);
?>''',

    "Command Injection (backtick - real shell)": '''<?php
$output = `ls $_GET['dir']`;
?>''',

    "XSS (echo)": '''<?php
echo $_GET['name'];
echo "Hello " . $_POST['user'];
?>''',

    "Code Injection (eval)": '''<?php
eval($_GET['code']);
eval($row['template']);
?>''',

    "File Inclusion": '''<?php
include($_GET['page']);
require_once($module);
?>''',

    "SSRF": '''<?php
$url = $_GET['url'];
$content = file_get_contents($_GET['url']);
?>''',

    "Deserialization": '''<?php
$data = unserialize($_POST['data']);
$obj = unserialize(base64_decode($input));
?>''',

    "RCE (call_user_func)": '''<?php
call_user_func($_GET['func']);
$_GET['method']();
?>''',

    "Type Juggling (VULNERABLE - loose ==)": '''<?php
if ($password == $_POST['password']) {
    login();
}
?>''',

    "Type Juggling (SAFE - strict ===)": '''<?php
if ($password === $_POST['password']) {
    login();
}
?>''',

    "Backtick SQL (should NOT flag)": '''<?php
$db->query("SELECT `id`, `name` FROM `users` WHERE `status` = 1");
$tables .= ", `" . $db->safesql($row[0]) . "`";
$result = $mysqli->query("SELECT VERSION() AS `version`");
?>''',

    "Safe code (should NOT flag)": '''<?php
$id = intval($_GET['id']);
$name = htmlspecialchars($_POST['name']);
$cmd = escapeshellarg($_GET['cmd']);
exec("ls " . escapeshellarg($dir));
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
?>''',
}

total_pass = 0
total_fail = 0

for test_name, code in test_cases.items():
    findings = scanner.scan_code(code, "test.php")
    should_find = "should NOT" not in test_name and "SAFE" not in test_name

    if should_find:
        if findings:
            status = "PASS"
            total_pass += 1
        else:
            status = "FAIL (expected findings but got none)"
            total_fail += 1
    else:
        if findings:
            status = f"FAIL (expected 0 findings but got {len(findings)})"
            total_fail += 1
        else:
            status = "PASS"
            total_pass += 1

    print(f"\n[{status}] {test_name}")
    if findings:
        for f in findings:
            print(f"  [{f.severity.name}] {f.vuln_type.value} @ line {f.line} (conf: {f.confidence:.0%})")
            print(f"    Code: {f.code[:70]}")

print(f"\n\n{'='*60}")
print(f"Results: {total_pass} PASS, {total_fail} FAIL out of {total_pass + total_fail} tests")
