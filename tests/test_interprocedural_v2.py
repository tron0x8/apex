#!/usr/bin/env python3
"""Tests for the k-CFA inter-procedural analysis engine (interprocedural_v2)."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.interprocedural_v2 import (
    CallContext,
    FunctionSummary,
    InterproceduralEngine,
    _tarjan_sccs,
)
from core.ts_adapter import parse_php_ts


# ---------------------------------------------------------------------------
# CallContext tests
# ---------------------------------------------------------------------------

def test_call_context_empty():
    """Default CallContext has empty sites tuple."""
    ctx = CallContext()
    assert ctx.sites == (), f"Expected empty sites, got {ctx.sites}"
    assert ctx.k == 2, f"Expected k=2, got {ctx.k}"
    print("  [PASS] test_call_context_empty")


def test_call_context_extend():
    """Extending a context appends the call site and trims to k."""
    ctx = CallContext(k=2)
    ctx1 = ctx.extend("file1.php", 10)
    assert ctx1.sites == (("file1.php", 10),), f"Got {ctx1.sites}"

    ctx2 = ctx1.extend("file2.php", 20)
    assert ctx2.sites == (("file1.php", 10), ("file2.php", 20)), f"Got {ctx2.sites}"

    # Adding a third site should trim the oldest (k=2)
    ctx3 = ctx2.extend("file3.php", 30)
    assert ctx3.sites == (("file2.php", 20), ("file3.php", 30)), f"Got {ctx3.sites}"
    assert len(ctx3.sites) == 2
    print("  [PASS] test_call_context_extend")


def test_call_context_frozen():
    """CallContext is frozen (immutable) and therefore hashable."""
    ctx = CallContext(sites=(("a.php", 1),), k=2)
    # Should be usable as dict key / set member
    d = {ctx: "value"}
    assert d[ctx] == "value"
    s = {ctx, ctx}
    assert len(s) == 1
    print("  [PASS] test_call_context_frozen")


def test_call_context_key():
    """The key property returns the sites tuple for dict lookups."""
    ctx = CallContext(sites=(("x.php", 5), ("y.php", 10)), k=2)
    assert ctx.key == (("x.php", 5), ("y.php", 10))
    assert ctx.key == ctx.sites

    empty_ctx = CallContext()
    assert empty_ctx.key == ()
    print("  [PASS] test_call_context_key")


# ---------------------------------------------------------------------------
# Tarjan SCC tests
# ---------------------------------------------------------------------------

def test_tarjan_simple():
    """Tarjan detects SCCs in a graph with one cycle and a singleton."""
    graph = {"a": {"b"}, "b": {"a"}, "c": {"a"}}
    sccs = _tarjan_sccs(graph)

    # Flatten each SCC into a set for easier comparison
    scc_sets = [set(scc) for scc in sccs]
    assert {"a", "b"} in scc_sets, f"Expected cycle {{a,b}} in {scc_sets}"
    assert {"c"} in scc_sets, f"Expected singleton {{c}} in {scc_sets}"
    print("  [PASS] test_tarjan_simple")


def test_tarjan_cycle():
    """Tarjan detects a two-node cycle: A -> B -> A."""
    graph = {"A": {"B"}, "B": {"A"}}
    sccs = _tarjan_sccs(graph)

    scc_sets = [set(scc) for scc in sccs]
    assert {"A", "B"} in scc_sets, f"Expected cycle in {scc_sets}"
    assert len(sccs) == 1, f"Expected 1 SCC for a pure cycle, got {len(sccs)}"
    print("  [PASS] test_tarjan_cycle")


def test_tarjan_dag():
    """A DAG has no non-trivial SCCs -- every SCC is a singleton."""
    graph = {"a": {"b"}, "b": {"c"}, "c": set()}
    sccs = _tarjan_sccs(graph)

    for scc in sccs:
        assert len(scc) == 1, f"Expected singleton SCC, got {scc}"
    assert len(sccs) == 3, f"Expected 3 singleton SCCs, got {len(sccs)}"
    print("  [PASS] test_tarjan_dag")


# ---------------------------------------------------------------------------
# FunctionSummary tests
# ---------------------------------------------------------------------------

def test_function_summary_defaults():
    """FunctionSummary fields default to empty collections."""
    summary = FunctionSummary(name="test_func", file="test.php")
    assert summary.params == [], f"Expected empty params, got {summary.params}"
    assert summary.param_to_sink == {}, f"Expected empty param_to_sink"
    assert summary.param_to_return == {}, f"Expected empty param_to_return"
    assert summary.sanitizer_for == set(), f"Expected empty sanitizer_for"
    assert summary.raw_callees == [], f"Expected empty raw_callees"
    assert summary.body_node is None
    assert summary.line == 0
    print("  [PASS] test_function_summary_defaults")


# ---------------------------------------------------------------------------
# InterproceduralEngine tests
# ---------------------------------------------------------------------------

def test_engine_empty_project():
    """Analyzing an empty project produces no findings and valid stats."""
    engine = InterproceduralEngine(k=2)
    findings = engine.analyze_project({})

    assert findings == [], f"Expected no findings, got {findings}"
    stats = engine.get_call_graph_stats()
    assert stats["total_functions"] == 0
    assert stats["total_files"] == 0
    assert stats["call_graph_edges"] == 0

    summary = engine.get_summary()
    assert summary["total_functions"] == 0
    assert summary["context_sensitivity_k"] == 2
    print("  [PASS] test_engine_empty_project")


def test_engine_simple_php():
    """Analyzing a simple PHP file extracts function summaries."""
    code = '<?php function foo($x) { return $x; } function bar($y) { echo $y; } ?>'
    tree = parse_php_ts(code)

    engine = InterproceduralEngine(k=2)
    engine.analyze_project({"test.php": tree})

    assert "foo" in engine.summaries, f"Expected 'foo' in summaries, got {list(engine.summaries.keys())}"
    assert "bar" in engine.summaries, f"Expected 'bar' in summaries"

    foo_summary = engine.summaries["foo"]
    assert foo_summary.file == "test.php"
    assert len(foo_summary.params) >= 1, f"Expected at least 1 param for foo, got {foo_summary.params}"

    stats = engine.get_call_graph_stats()
    assert stats["total_functions"] == 2
    assert stats["total_files"] == 1
    print("  [PASS] test_engine_simple_php")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== Inter-procedural v2 (k-CFA) Tests ===\n")
    tests = [
        test_call_context_empty,
        test_call_context_extend,
        test_call_context_frozen,
        test_call_context_key,
        test_tarjan_simple,
        test_tarjan_cycle,
        test_tarjan_dag,
        test_function_summary_defaults,
        test_engine_empty_project,
        test_engine_simple_php,
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

    print(f"\n{'=' * 50}")
    print(f"Results: {passed} PASS, {failed} FAIL out of {passed + failed} tests")
    sys.exit(1 if failed else 0)
