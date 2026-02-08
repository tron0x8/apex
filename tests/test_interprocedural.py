#!/usr/bin/env python3
"""Tests for inter-procedural analysis (Phase D)."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.interprocedural import InterproceduralAnalyzer, FunctionInfo


def test_extract_functions():
    """Test function extraction from PHP code."""
    code = '''<?php
function foo($a, $b) {
    return $a + $b;
}

function bar($x) {
    echo $x;
}
'''
    analyzer = InterproceduralAnalyzer()
    functions = analyzer.analyze_file('test.php', code)
    names = [f.name for f in functions]
    assert 'foo' in names, f"Expected 'foo' in {names}"
    assert 'bar' in names, f"Expected 'bar' in {names}"

    foo = analyzer.functions['foo']
    assert len(foo.params) == 2, f"Expected 2 params, got {len(foo.params)}"
    assert '$a' in foo.params or 'a' in foo.params, f"Expected $a param, got {foo.params}"
    print("  [PASS] extract_functions")


def test_param_flows_to_sink():
    """Test detection of parameter flowing to a sink."""
    code = '''<?php
function vulnerable($input) {
    mysql_query("SELECT * FROM users WHERE id=" . $input);
}
'''
    analyzer = InterproceduralAnalyzer()
    analyzer.analyze_file('test.php', code)

    func = analyzer.functions.get('vulnerable')
    assert func is not None, "Function 'vulnerable' not found"
    assert len(func.param_flows_to_sink) > 0, "Expected param_flows_to_sink to be non-empty"
    assert 0 in func.param_flows_to_sink, "Expected param 0 to flow to sink"
    assert 'SQL' in func.param_flows_to_sink[0], \
        f"Expected SQL in sink types, got {func.param_flows_to_sink[0]}"
    print("  [PASS] param_flows_to_sink")


def test_sanitizer_detection():
    """Test detection of functions that wrap sanitizers."""
    code = '''<?php
function cleanInput($input) {
    return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
}
'''
    analyzer = InterproceduralAnalyzer()
    analyzer.analyze_file('test.php', code)

    func = analyzer.functions.get('cleanInput')
    assert func is not None, "Function 'cleanInput' not found"
    assert func.is_sanitizer, "Expected cleanInput to be detected as sanitizer"
    assert 'XSS' in func.sanitizes_for, f"Expected XSS in sanitizes_for, got {func.sanitizes_for}"
    print("  [PASS] sanitizer_detection")


def test_call_graph():
    """Test call graph construction."""
    code = '''<?php
function inner($x) {
    echo $x;
}

function outer($data) {
    inner($data);
}
'''
    analyzer = InterproceduralAnalyzer()
    analyzer.analyze_file('test.php', code)
    analyzer.build_call_graph()

    assert 'outer' in analyzer.call_graph, "Expected 'outer' in call graph"
    assert 'inner' in analyzer.call_graph['outer'], \
        f"Expected 'inner' in outer's callees, got {analyzer.call_graph['outer']}"

    assert 'inner' in analyzer.reverse_graph, "Expected 'inner' in reverse graph"
    assert 'outer' in analyzer.reverse_graph['inner'], \
        f"Expected 'outer' as caller of inner"
    print("  [PASS] call_graph")


def test_cross_function_taint():
    """Test taint flow detection across function boundaries."""
    code = '''<?php
function runQuery($sql) {
    mysql_query($sql);
}

function handleRequest() {
    $id = $_GET['id'];
    $query = "SELECT * FROM users WHERE id=" . $id;
    runQuery($query);
}
'''
    analyzer = InterproceduralAnalyzer()
    analyzer.analyze_file('test.php', code)
    analyzer.build_call_graph()
    flows = analyzer.find_taint_flows()

    assert len(flows) > 0, "Expected at least one cross-function taint flow"
    sql_flows = [f for f in flows if f.vuln_type == 'SQL']
    assert len(sql_flows) > 0, "Expected SQL injection flow"
    print("  [PASS] cross_function_taint")


def test_returns_tainted():
    """Test detection of functions that return tainted data."""
    code = '''<?php
function getUserInput() {
    return $_GET['input'];
}
'''
    analyzer = InterproceduralAnalyzer()
    analyzer.analyze_file('test.php', code)

    func = analyzer.functions.get('getUserInput')
    assert func is not None, "Function 'getUserInput' not found"
    assert func.returns_tainted, "Expected getUserInput to return tainted data"
    print("  [PASS] returns_tainted")


def test_param_flows_to_return():
    """Test detection of params flowing to return value."""
    # Direct return of param (no intermediate variable)
    code = '''<?php
function processData($input) {
    return trim($input);
}
'''
    analyzer = InterproceduralAnalyzer()
    analyzer.analyze_file('test.php', code)

    func = analyzer.functions.get('processData')
    assert func is not None, "Function 'processData' not found"
    assert 0 in func.param_flows_to_return, \
        f"Expected param 0 in param_flows_to_return, got {func.param_flows_to_return}"
    print("  [PASS] param_flows_to_return")


def test_no_false_positive_sanitized():
    """Test that sanitized flows are not reported."""
    code = '''<?php
function safeQuery($input) {
    $clean = intval($input);
    mysql_query("SELECT * FROM users WHERE id=" . $clean);
}
'''
    analyzer = InterproceduralAnalyzer()
    analyzer.analyze_file('test.php', code)

    func = analyzer.functions.get('safeQuery')
    assert func is not None
    # With intval sanitizer, SQL sink should not be flagged
    sql_sinks = func.param_flows_to_sink.get(0, set())
    assert 'SQL' not in sql_sinks, f"Expected no SQL flow with intval sanitizer, got {sql_sinks}"
    print("  [PASS] no_false_positive_sanitized")


def test_summary():
    """Test analysis summary generation."""
    code = '''<?php
function a($x) { mysql_query($x); }
function b($y) { return htmlspecialchars($y); }
function c() { return $_GET['z']; }
'''
    analyzer = InterproceduralAnalyzer()
    analyzer.analyze_file('test.php', code)
    analyzer.build_call_graph()
    summary = analyzer.get_summary()

    assert summary['total_functions'] == 3, f"Expected 3 functions, got {summary['total_functions']}"
    assert summary['tainted_params'] >= 1, "Expected at least 1 tainted param function"
    assert summary['tainted_returns'] >= 1, "Expected at least 1 tainted return function"
    print("  [PASS] summary")


def test_backward_compat_aliases():
    """Test backward compatibility method aliases."""
    analyzer = InterproceduralAnalyzer()
    # These should exist and not raise
    assert hasattr(analyzer, 'analyze_directory')
    assert hasattr(analyzer, 'get_call_graph_stats')
    print("  [PASS] backward_compat_aliases")


if __name__ == '__main__':
    print("=== Inter-procedural Analysis Tests ===\n")
    tests = [
        test_extract_functions,
        test_param_flows_to_sink,
        test_sanitizer_detection,
        test_call_graph,
        test_cross_function_taint,
        test_returns_tainted,
        test_param_flows_to_return,
        test_no_false_positive_sanitized,
        test_summary,
        test_backward_compat_aliases,
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
