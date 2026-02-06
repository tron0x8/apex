#!/usr/bin/env python3
"""Test Advanced Context Analyzer v2.0 - All Features"""

import sys
sys.path.insert(0, 'C:\\Users\\User\\Desktop\\apex')

from core.context_analyzer import (
    AdvancedContextAnalyzer, TypeCastDetector, ORMDetector,
    DeadCodeAnalyzer, ExtendedWhitelistDetector, DataFlowTracker
)


def test_type_casting():
    print("=== TEST 1: Type Casting Detection ===")

    code = '''<?php
$id = (int)$_GET['id'];
$price = floatval($_POST['price']);
$safe = intval($user_input);

// This should be safe
$query = "SELECT * FROM users WHERE id = $id";
echo $price;
?>'''

    tc = TypeCastDetector(code)

    # Test (int) cast
    is_safe, reason = tc.is_type_safe("$id", "SQL_INJECTION", 6)
    print(f"  (int) cast safe for SQL: {is_safe}")
    assert is_safe, "Should detect (int) cast!"

    # Test floatval
    is_safe, reason = tc.is_type_safe("$price", "XSS", 7)
    print(f"  floatval safe for XSS: {is_safe}")
    assert is_safe, "Should detect floatval!"

    # Test intval
    is_safe, reason = tc.is_type_safe("$safe", "SQL_INJECTION", 10)
    print(f"  intval safe for SQL: {is_safe}")
    assert is_safe, "Should detect intval!"

    print("  [PASS]\n")


def test_orm_detection():
    print("=== TEST 2: ORM/Prepared Statement Detection ===")

    code = '''<?php
// Laravel Eloquent
$user = User::where('id', $id)->first();
$users = User::find($id);

// PDO Prepared
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);

// Raw query (NOT safe)
mysql_query("SELECT * FROM users WHERE id = $id");
?>'''

    orm = ORMDetector(code)

    # Test Eloquent
    is_safe, reason = orm.is_orm_protected(3)
    print(f"  Eloquent where() safe: {is_safe}")
    assert is_safe, "Should detect Eloquent!"

    # Test PDO
    is_safe, reason = orm.is_orm_protected(7)
    print(f"  PDO prepare() safe: {is_safe}")
    assert is_safe, "Should detect PDO prepared!"

    # Test raw query should NOT be safe
    has_prep = orm.has_prepared_statement(10, 11)
    print(f"  Raw mysql_query has prepared: {has_prep}")
    assert not has_prep, "Raw query should not be prepared!"

    print("  [PASS]\n")


def test_dead_code():
    print("=== TEST 3: Dead Code Detection ===")

    code = '''<?php
if (false) {
    eval($_GET['code']);  // Line 3 - dead
}

if (0) {
    system($_POST['cmd']);  // Line 7 - dead
}

if (1 == 0) {
    include $_GET['file'];  // Line 11 - dead
}

function test() {
    return;
    echo $_GET['x'];  // Line 16 - dead (after return)
}
?>'''

    dc = DeadCodeAnalyzer(code)

    # Test if(false)
    is_dead, reason = dc.is_dead_code(3)
    print(f"  if(false) block dead: {is_dead}")
    assert is_dead, "Should detect if(false)!"

    # Test if(0)
    is_dead, reason = dc.is_dead_code(7)
    print(f"  if(0) block dead: {is_dead}")
    assert is_dead, "Should detect if(0)!"

    # Test if(1==0)
    is_dead, reason = dc.is_dead_code(11)
    print(f"  if(1==0) block dead: {is_dead}")
    assert is_dead, "Should detect impossible condition!"

    print("  [PASS]\n")


def test_extended_whitelist():
    print("=== TEST 4: Extended Whitelist Detection ===")

    code = '''<?php
$key = $_GET['key'];

// Pattern 1: isset array key
if (isset($allowed[$key])) {
    include $key . '.php';
}

// Pattern 2: ctype_alnum
if (ctype_alnum($key)) {
    echo $key;
}

// Pattern 3: preg_match
if (preg_match('/^[a-z0-9]+$/', $key)) {
    system($key);
}

// Pattern 4: filter_var
$email = $_GET['email'];
if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo $email;
}

// Pattern 5: is_numeric
$id = $_GET['id'];
if (is_numeric($id)) {
    $query = "SELECT * FROM t WHERE id = $id";
}
?>'''

    wl = ExtendedWhitelistDetector(code)

    # Test isset
    is_wl, reason = wl.is_whitelisted("$key", 6)
    print(f"  isset array key: {is_wl}")
    assert is_wl, "Should detect isset key check!"

    # Test ctype_alnum
    is_wl, reason = wl.is_whitelisted("$key", 11)
    print(f"  ctype_alnum: {is_wl}")
    assert is_wl, "Should detect ctype_alnum!"

    # Test preg_match
    is_wl, reason = wl.is_whitelisted("$key", 16)
    print(f"  preg_match: {is_wl}")
    assert is_wl, "Should detect preg_match validation!"

    # Test filter_var
    is_wl, reason = wl.is_whitelisted("$email", 22)
    print(f"  filter_var: {is_wl}")
    assert is_wl, "Should detect filter_var!"

    # Test is_numeric
    is_wl, reason = wl.is_whitelisted("$id", 27)
    print(f"  is_numeric: {is_wl}")
    assert is_wl, "Should detect is_numeric!"

    print("  [PASS]\n")


def test_data_flow():
    print("=== TEST 5: Data Flow Tracking ===")

    code = '''<?php
$input = $_GET['name'];
$safe = htmlspecialchars($input);
echo $safe;

$id = $_POST['id'];
$clean_id = intval($id);
$query = "SELECT * FROM t WHERE id = $clean_id";
?>'''

    df = DataFlowTracker(code)

    # Test sanitized XSS
    is_tainted, sanitized = df.is_var_tainted("$safe", 4)
    print(f"  $safe tainted: {is_tainted}, sanitized_for: {sanitized}")
    assert 'xss' in sanitized, "Should track XSS sanitization!"

    # Test sanitized SQL
    is_tainted, sanitized = df.is_var_tainted("$clean_id", 8)
    print(f"  $clean_id tainted: {is_tainted}, sanitized_for: {sanitized}")
    assert 'sql' in sanitized, "Should track SQL sanitization!"

    # Test unsanitized
    is_tainted, sanitized = df.is_var_tainted("$input", 3)
    print(f"  $input tainted: {is_tainted}")
    assert is_tainted or len(sanitized) == 0, "Original input should be tainted!"

    print("  [PASS]\n")


def test_combined_analysis():
    print("=== TEST 6: Combined Analysis ===")

    code = '''<?php
// Case 1: Type cast protects SQL
$id = (int)$_GET['id'];
$query = "SELECT * FROM users WHERE id = $id";

// Case 2: ORM protects SQL
$user = User::where('email', $_POST['email'])->first();

// Case 3: Dead code
if (false) {
    eval($_GET['evil']);
}

// Case 4: Whitelist protects
$action = $_GET['action'];
if (in_array($action, ['view', 'edit', 'delete'])) {
    call_user_func($action);
}

// Case 5: Data flow sanitization
$name = htmlspecialchars($_POST['name']);
echo $name;
?>'''

    adv = AdvancedContextAnalyzer(code)

    # Case 1: Type cast
    is_fp, reason = adv.is_false_positive(4, "$id", "SQL_INJECTION")
    print(f"  Type cast FP: {is_fp} - {reason}")
    assert is_fp and "TYPE_CAST" in reason, "Should detect type cast!"

    # Case 2: ORM
    is_fp, reason = adv.is_false_positive(7, "$_POST['email']", "SQL_INJECTION")
    print(f"  ORM FP: {is_fp} - {reason}")
    assert is_fp and "ORM" in reason, "Should detect ORM!"

    # Case 3: Dead code
    is_fp, reason = adv.is_false_positive(11, "$_GET['evil']", "CODE_INJECTION")
    print(f"  Dead code FP: {is_fp} - {reason}")
    assert is_fp and "DEAD_CODE" in reason, "Should detect dead code!"

    # Case 4: Whitelist
    is_fp, reason = adv.is_false_positive(17, "$action", "CODE_INJECTION")
    print(f"  Whitelist FP: {is_fp} - {reason}")
    assert is_fp and "WHITELIST" in reason, "Should detect whitelist!"

    # Case 5: Data flow
    is_fp, reason = adv.is_false_positive(21, "$name", "XSS")
    print(f"  Data flow FP: {is_fp} - {reason}")
    assert is_fp and "DATA_FLOW" in reason, "Should detect data flow sanitization!"

    print("  [PASS]\n")


def test_real_world_patterns():
    print("=== TEST 7: Real World Patterns ===")

    code = '''<?php
// WordPress style
$post_id = absint($_GET['post_id']);
$wpdb->query($wpdb->prepare("SELECT * FROM posts WHERE id = %d", $post_id));

// Laravel style
$users = DB::table('users')->where('status', request('status'))->get();

// Symfony/Doctrine style
$user = $em->getRepository(User::class)->find($request->get('id'));

// Manual sanitization chain
$input = $_POST['data'];
$clean = strip_tags($input);
$safe = htmlspecialchars($clean, ENT_QUOTES);
echo $safe;

// Numeric validation
$page = $_GET['page'];
if (!is_numeric($page)) die('Invalid');
$offset = $page * 10;
$db->query("SELECT * FROM items LIMIT 10 OFFSET $offset");
?>'''

    adv = AdvancedContextAnalyzer(code)

    # WordPress absint
    is_fp, reason = adv.is_false_positive(4, "$post_id", "SQL_INJECTION")
    print(f"  WordPress absint: {is_fp}")

    # Laravel query builder
    is_fp, reason = adv.is_false_positive(7, "request('status')", "SQL_INJECTION")
    print(f"  Laravel query builder: {is_fp}")
    assert is_fp, "Should detect Laravel query builder!"

    # Doctrine
    is_fp, reason = adv.is_false_positive(10, "$request->get('id')", "SQL_INJECTION")
    print(f"  Doctrine repository: {is_fp}")
    assert is_fp, "Should detect Doctrine!"

    # is_numeric validation
    is_fp, reason = adv.is_false_positive(20, "$page", "SQL_INJECTION")
    print(f"  is_numeric validation: {is_fp}")
    assert is_fp, "Should detect is_numeric validation!"

    print("  [PASS]\n")


if __name__ == '__main__':
    test_type_casting()
    test_orm_detection()
    test_dead_code()
    test_extended_whitelist()
    test_data_flow()
    test_combined_analysis()
    test_real_world_patterns()
    print("=" * 50)
    print("ALL v2.0 TESTS PASSED!")
    print("=" * 50)
