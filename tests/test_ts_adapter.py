#!/usr/bin/env python3
"""Tests for tree-sitter adapter (Phase B)."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.ts_adapter import TSNode, parse_php_ts


def test_parse_basic():
    """Test basic PHP parsing."""
    root = parse_php_ts('<?php echo "hello"; ?>')
    assert root.type == 'program', f"Expected 'program', got '{root.type}'"
    print("  [PASS] parse_basic")


def test_auto_php_tag():
    """Test automatic <?php insertion."""
    root = parse_php_ts('echo "hello";')
    assert root.type == 'program'
    # Should have parsed as valid PHP
    descendants = list(root.walk_descendants())
    types = [n.type for n in descendants]
    assert 'echo_statement' in types, f"Expected echo_statement, got: {types}"
    print("  [PASS] auto_php_tag")


def test_node_text():
    """Test node text extraction."""
    root = parse_php_ts('<?php $x = 42;')
    for node in root.walk_descendants():
        if node.type == 'variable_name':
            assert node.text == '$x', f"Expected '$x', got '{node.text}'"
            print("  [PASS] node_text")
            return
    assert False, "variable_name node not found"


def test_node_line():
    """Test 1-based line numbering."""
    root = parse_php_ts('<?php\n$x = 1;\n$y = 2;')
    lines_found = {}
    for node in root.walk_descendants():
        if node.type == 'variable_name':
            lines_found[node.text] = node.line
    assert lines_found.get('$x') == 2, f"Expected $x at line 2, got {lines_found.get('$x')}"
    assert lines_found.get('$y') == 3, f"Expected $y at line 3, got {lines_found.get('$y')}"
    print("  [PASS] node_line")


def test_child_by_field():
    """Test field-based child access."""
    root = parse_php_ts('<?php function foo($a) { return $a; }')
    for node in root.walk_descendants():
        if node.type == 'function_definition':
            name = node.child_by_field('name')
            assert name is not None, "Expected name field"
            assert name.text == 'foo', f"Expected 'foo', got '{name.text}'"
            params = node.child_by_field('parameters')
            assert params is not None, "Expected parameters field"
            body = node.child_by_field('body')
            assert body is not None, "Expected body field"
            print("  [PASS] child_by_field")
            return
    assert False, "function_definition not found"


def test_named_children():
    """Test named children filtering."""
    root = parse_php_ts('<?php $x = 1 + 2;')
    for node in root.walk_descendants():
        if node.type == 'binary_expression':
            named = node.named_children
            # Should have left, right (named), skipping operator
            assert len(named) >= 2, f"Expected >= 2 named children, got {len(named)}"
            print("  [PASS] named_children")
            return
    assert False, "binary_expression not found"


def test_get_function_name():
    """Test function name extraction from call expressions."""
    root = parse_php_ts('<?php mysql_query($sql);')
    for node in root.walk_descendants():
        if node.type == 'function_call_expression':
            name = node.get_function_name()
            assert name == 'mysql_query', f"Expected 'mysql_query', got '{name}'"
            print("  [PASS] get_function_name")
            return
    assert False, "function_call_expression not found"


def test_get_arguments():
    """Test argument extraction from call expressions."""
    root = parse_php_ts('<?php foo($a, $b, $c);')
    for node in root.walk_descendants():
        if node.type == 'function_call_expression':
            args = node.get_arguments()
            assert len(args) == 3, f"Expected 3 arguments, got {len(args)}"
            print("  [PASS] get_arguments")
            return
    assert False, "function_call_expression not found"


def test_walk_descendants():
    """Test depth-first descendant walk."""
    root = parse_php_ts('<?php $x = $_GET["id"]; echo $x;')
    types = [n.type for n in root.walk_descendants()]
    assert 'variable_name' in types
    assert 'echo_statement' in types
    assert 'subscript_expression' in types
    print("  [PASS] walk_descendants")


def test_variable_name():
    """Test variable name extraction."""
    root = parse_php_ts('<?php $_GET["id"];')
    for node in root.walk_descendants():
        if node.type == 'variable_name' and '_GET' in node.text:
            name = node.get_variable_name()
            assert name == '$_GET', f"Expected '$_GET', got '{name}'"
            print("  [PASS] variable_name")
            return
    assert False, "$_GET variable not found"


def test_method_call():
    """Test method call parsing."""
    root = parse_php_ts('<?php $pdo->query($sql);')
    for node in root.walk_descendants():
        if node.type == 'member_call_expression':
            name = node.get_function_name()
            assert name == 'query', f"Expected 'query', got '{name}'"
            print("  [PASS] method_call")
            return
    assert False, "member_call_expression not found"


def test_if_statement_fields():
    """Test if statement field access."""
    root = parse_php_ts('<?php if ($x) { echo 1; } else { echo 2; }')
    for node in root.walk_descendants():
        if node.type == 'if_statement':
            cond = node.child_by_field('condition')
            body = node.child_by_field('body')
            alt = node.child_by_field('alternative')
            assert cond is not None, "Expected condition"
            assert body is not None, "Expected body"
            assert alt is not None, "Expected alternative"
            print("  [PASS] if_statement_fields")
            return
    assert False, "if_statement not found"


def test_assignment_fields():
    """Test assignment expression field access."""
    root = parse_php_ts('<?php $x = 42;')
    for node in root.walk_descendants():
        if node.type == 'assignment_expression':
            left = node.child_by_field('left')
            right = node.child_by_field('right')
            assert left is not None, "Expected left"
            assert right is not None, "Expected right"
            assert left.text == '$x', f"Expected '$x', got '{left.text}'"
            print("  [PASS] assignment_fields")
            return
    assert False, "assignment_expression not found"


def test_repr():
    """Test node repr."""
    root = parse_php_ts('<?php echo 1;')
    r = repr(root)
    assert 'TSNode' in r
    assert 'program' in r
    print("  [PASS] repr")


if __name__ == '__main__':
    print("=== Tree-sitter Adapter Tests ===\n")
    tests = [
        test_parse_basic,
        test_auto_php_tag,
        test_node_text,
        test_node_line,
        test_child_by_field,
        test_named_children,
        test_get_function_name,
        test_get_arguments,
        test_walk_descendants,
        test_variable_name,
        test_method_call,
        test_if_statement_fields,
        test_assignment_fields,
        test_repr,
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
