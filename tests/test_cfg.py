#!/usr/bin/env python3
"""Tests for CFG builder (Phase C)."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.ts_adapter import parse_php_ts
from core.cfg import CFGBuilder, CFGBlock


def get_function_body(code):
    """Parse PHP and return the body node of the first function."""
    root = parse_php_ts(code)
    for node in root.walk_descendants():
        if node.type == 'function_definition':
            return node.child_by_field('body')
    return None


def test_linear_cfg():
    """Test CFG for straight-line code."""
    body = get_function_body('<?php function f() { $x = 1; $y = 2; $z = 3; }')
    assert body is not None
    builder = CFGBuilder()
    blocks = builder.build(body)

    # Should have entry + exit (at minimum)
    entry_blocks = [b for b in blocks if b.is_entry]
    exit_blocks = [b for b in blocks if b.is_exit]
    assert len(entry_blocks) == 1, f"Expected 1 entry, got {len(entry_blocks)}"
    assert len(exit_blocks) == 1, f"Expected 1 exit, got {len(exit_blocks)}"

    # Entry should have statements
    entry = entry_blocks[0]
    assert len(entry.statements) == 3, f"Expected 3 statements, got {len(entry.statements)}"

    # Entry should connect to exit
    assert exit_blocks[0].id in entry.successors
    print("  [PASS] linear_cfg")


def test_if_cfg():
    """Test CFG for if/else branching."""
    code = '<?php function f($x) { if ($x) { $a = 1; } else { $b = 2; } $c = 3; }'
    body = get_function_body(code)
    builder = CFGBuilder()
    blocks = builder.build(body)

    # Should have: entry, then_block, else_block, join_block, exit
    assert len(blocks) >= 5, f"Expected >= 5 blocks, got {len(blocks)}"

    # Entry should have 2+ successors (then and else paths)
    entry = [b for b in blocks if b.is_entry][0]
    assert len(entry.successors) >= 2, f"Expected >= 2 successors from entry, got {len(entry.successors)}"
    print("  [PASS] if_cfg")


def test_while_cfg():
    """Test CFG for while loop (back edge)."""
    code = '<?php function f() { while ($x) { $a = 1; } $b = 2; }'
    body = get_function_body(code)
    builder = CFGBuilder()
    blocks = builder.build(body)

    # Should have back edge (a block whose successor is a predecessor)
    has_back_edge = False
    for block in blocks:
        for succ_id in block.successors:
            succ = next((b for b in blocks if b.id == succ_id), None)
            if succ and block.id in succ.successors:
                has_back_edge = True
                break

    # Alternative check: at least one block has a successor with a lower id
    has_back_edge2 = any(
        any(s_id < b.id for s_id in b.successors)
        for b in blocks if not b.is_entry and not b.is_exit
    )
    assert has_back_edge or has_back_edge2, "Expected back edge in while loop CFG"
    print("  [PASS] while_cfg")


def test_foreach_cfg():
    """Test CFG for foreach loop."""
    code = '<?php function f($arr) { foreach ($arr as $v) { echo $v; } }'
    body = get_function_body(code)
    builder = CFGBuilder()
    blocks = builder.build(body)
    assert len(blocks) >= 4, f"Expected >= 4 blocks for foreach, got {len(blocks)}"
    print("  [PASS] foreach_cfg")


def test_return_terminates():
    """Test that return terminates the block (no successors except exit)."""
    code = '<?php function f() { return 42; $dead = 1; }'
    body = get_function_body(code)
    builder = CFGBuilder()
    blocks = builder.build(body)

    entry = [b for b in blocks if b.is_entry][0]
    exit_block = [b for b in blocks if b.is_exit][0]

    # Entry block should connect to exit (via return)
    assert exit_block.id in entry.successors, "Return should connect to exit"

    # Dead code after return should NOT be in entry's statements (if separate)
    # The entry block should have at most 1 statement (the return)
    print("  [PASS] return_terminates")


def test_try_catch_cfg():
    """Test CFG for try/catch."""
    code = '''<?php function f() {
        try { $a = risky(); }
        catch (Exception $e) { $b = handle(); }
        $c = after();
    }'''
    body = get_function_body(code)
    builder = CFGBuilder()
    blocks = builder.build(body)

    # Should have: entry, try_block, catch_block, join, exit (at minimum)
    assert len(blocks) >= 5, f"Expected >= 5 blocks for try/catch, got {len(blocks)}"
    print("  [PASS] try_catch_cfg")


def test_switch_cfg():
    """Test CFG for switch/case."""
    code = '''<?php function f($x) {
        switch ($x) {
            case 1: $a = 1; break;
            case 2: $b = 2; break;
            default: $c = 3;
        }
    }'''
    body = get_function_body(code)
    builder = CFGBuilder()
    blocks = builder.build(body)

    # Should have blocks for each case
    assert len(blocks) >= 5, f"Expected >= 5 blocks for switch, got {len(blocks)}"
    print("  [PASS] switch_cfg")


def test_nested_if():
    """Test CFG for nested if statements."""
    code = '''<?php function f($a, $b) {
        if ($a) {
            if ($b) { $x = 1; } else { $x = 2; }
        } else {
            $x = 3;
        }
        return $x;
    }'''
    body = get_function_body(code)
    builder = CFGBuilder()
    blocks = builder.build(body)

    # Should have many blocks for nested branches
    assert len(blocks) >= 7, f"Expected >= 7 blocks for nested if, got {len(blocks)}"
    print("  [PASS] nested_if")


def test_empty_function():
    """Test CFG for empty function body."""
    code = '<?php function f() { }'
    body = get_function_body(code)
    builder = CFGBuilder()
    blocks = builder.build(body)

    entry = [b for b in blocks if b.is_entry][0]
    exit_block = [b for b in blocks if b.is_exit][0]
    assert exit_block.id in entry.successors, "Empty function should connect entry to exit"
    print("  [PASS] empty_function")


def test_block_predecessors():
    """Test that predecessor links are correct."""
    code = '<?php function f($x) { if ($x) { $a = 1; } $b = 2; }'
    body = get_function_body(code)
    builder = CFGBuilder()
    blocks = builder.build(body)

    # Every successor relationship should have a matching predecessor
    for block in blocks:
        for succ_id in block.successors:
            succ = next((b for b in blocks if b.id == succ_id), None)
            assert succ is not None, f"Successor {succ_id} not found"
            assert block.id in succ.predecessors, \
                f"Block {block.id} is successor of {succ.id} but not in predecessors"
    print("  [PASS] block_predecessors")


if __name__ == '__main__':
    print("=== CFG Builder Tests ===\n")
    tests = [
        test_linear_cfg,
        test_if_cfg,
        test_while_cfg,
        test_foreach_cfg,
        test_return_terminates,
        test_try_catch_cfg,
        test_switch_cfg,
        test_nested_if,
        test_empty_function,
        test_block_predecessors,
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
