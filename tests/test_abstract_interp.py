#!/usr/bin/env python3
"""Tests for core/abstract_interp.py -- lattice-based taint analysis."""

import pytest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.abstract_interp import (
    TaintLattice,
    TaintInfo,
    AbstractState,
    Finding,
    AbstractInterpreter,
)


# ---------------------------------------------------------------------------
# TaintLattice
# ---------------------------------------------------------------------------

class TestTaintLattice:
    def test_lattice_join(self):
        """join() returns the least upper bound (max)."""
        assert TaintLattice.join(TaintLattice.UNTAINTED, TaintLattice.TAINTED) == TaintLattice.TAINTED
        assert TaintLattice.join(TaintLattice.BOTTOM, TaintLattice.WEAK) == TaintLattice.WEAK
        assert TaintLattice.join(TaintLattice.TOP, TaintLattice.TAINTED) == TaintLattice.TOP
        assert TaintLattice.join(TaintLattice.WEAK, TaintLattice.WEAK) == TaintLattice.WEAK

    def test_lattice_meet(self):
        """meet() returns the greatest lower bound (min)."""
        assert TaintLattice.meet(TaintLattice.TAINTED, TaintLattice.WEAK) == TaintLattice.WEAK
        assert TaintLattice.meet(TaintLattice.TOP, TaintLattice.UNTAINTED) == TaintLattice.UNTAINTED
        assert TaintLattice.meet(TaintLattice.BOTTOM, TaintLattice.TAINTED) == TaintLattice.BOTTOM
        assert TaintLattice.meet(TaintLattice.WEAK, TaintLattice.WEAK) == TaintLattice.WEAK

    def test_lattice_widen(self):
        """widen() jumps to TOP when new > old, otherwise keeps old."""
        assert TaintLattice.widen(TaintLattice.UNTAINTED, TaintLattice.TAINTED) == TaintLattice.TOP
        assert TaintLattice.widen(TaintLattice.TAINTED, TaintLattice.WEAK) == TaintLattice.TAINTED
        assert TaintLattice.widen(TaintLattice.WEAK, TaintLattice.WEAK) == TaintLattice.WEAK
        assert TaintLattice.widen(TaintLattice.BOTTOM, TaintLattice.UNTAINTED) == TaintLattice.TOP


# ---------------------------------------------------------------------------
# TaintInfo
# ---------------------------------------------------------------------------

class TestTaintInfo:
    def test_taint_info_is_tainted(self):
        """is_tainted() is True for WEAK and TAINTED, False for UNTAINTED."""
        assert TaintInfo(level=TaintLattice.WEAK).is_tainted() is True
        assert TaintInfo(level=TaintLattice.TAINTED).is_tainted() is True
        assert TaintInfo(level=TaintLattice.UNTAINTED).is_tainted() is False
        assert TaintInfo(level=TaintLattice.BOTTOM).is_tainted() is False

    def test_taint_info_effective_types(self):
        """effective_types() subtracts sanitized_types from taint_types."""
        info = TaintInfo(
            level=TaintLattice.TAINTED,
            taint_types={"SQL", "XSS", "COMMAND"},
            sanitized_types={"XSS"},
        )
        assert info.effective_types() == {"SQL", "COMMAND"}

        fully_sanitized = TaintInfo(
            level=TaintLattice.TAINTED,
            taint_types={"SQL"},
            sanitized_types={"SQL"},
        )
        assert fully_sanitized.effective_types() == set()

    def test_taint_info_copy(self):
        """copy() produces an independent deep copy."""
        original = TaintInfo(
            level=TaintLattice.TAINTED,
            taint_types={"SQL", "XSS"},
            sources={"$_GET"},
            sanitizers_applied={"htmlspecialchars"},
            sanitized_types={"XSS"},
        )
        copied = original.copy()

        assert copied.level == original.level
        assert copied.taint_types == original.taint_types
        assert copied.sources == original.sources

        # Mutating the copy must not affect the original.
        copied.taint_types.add("COMMAND")
        assert "COMMAND" not in original.taint_types

        copied.sources.add("$_POST")
        assert "$_POST" not in original.sources


# ---------------------------------------------------------------------------
# AbstractState
# ---------------------------------------------------------------------------

class TestAbstractState:
    def test_state_bottom(self):
        """bottom() creates a state flagged as unreachable."""
        s = AbstractState.bottom()
        assert getattr(s, "_is_bottom", False) is True

    def test_state_get_set(self):
        """get/set round-trips taint info correctly."""
        s = AbstractState()
        info = TaintInfo(level=TaintLattice.TAINTED, taint_types={"SQL"}, sources={"$_GET"})
        s.set("$user_id", info)

        retrieved = s.get("$user_id")
        assert retrieved.level == TaintLattice.TAINTED
        assert "SQL" in retrieved.taint_types

        # Getting an unknown variable yields a default (BOTTOM) TaintInfo.
        unknown = s.get("$nonexistent")
        assert unknown.level == TaintLattice.BOTTOM

    def test_state_join(self):
        """join() merges levels via max, unions types, intersects sanitizers."""
        s1 = AbstractState()
        s1.set("$x", TaintInfo(
            level=TaintLattice.WEAK,
            taint_types={"SQL"},
            sanitizers_applied={"intval", "htmlspecialchars"},
            sanitized_types={"SQL", "XSS"},
        ))

        s2 = AbstractState()
        s2.set("$x", TaintInfo(
            level=TaintLattice.TAINTED,
            taint_types={"XSS"},
            sanitizers_applied={"htmlspecialchars"},
            sanitized_types={"XSS"},
        ))

        merged = s1.join(s2)
        x = merged.get("$x")
        assert x.level == TaintLattice.TAINTED          # max(WEAK, TAINTED)
        assert x.taint_types == {"SQL", "XSS"}           # union
        assert x.sanitizers_applied == {"htmlspecialchars"}  # intersection
        assert x.sanitized_types == {"XSS"}               # intersection

    def test_state_equality(self):
        """Two states with the same variable mappings are equal."""
        s1 = AbstractState()
        s1.set("$a", TaintInfo(level=TaintLattice.TAINTED, taint_types={"SQL"}))

        s2 = AbstractState()
        s2.set("$a", TaintInfo(level=TaintLattice.TAINTED, taint_types={"SQL"}))

        assert s1 == s2

        # Different levels are not equal.
        s3 = AbstractState()
        s3.set("$a", TaintInfo(level=TaintLattice.WEAK, taint_types={"SQL"}))
        assert s1 != s3

    def test_state_widen(self):
        """Widening jumps variable levels to TOP when new > old."""
        s_old = AbstractState()
        s_old.set("$v", TaintInfo(level=TaintLattice.UNTAINTED))

        s_new = AbstractState()
        s_new.set("$v", TaintInfo(level=TaintLattice.TAINTED))

        widened = s_old.widen(s_new)
        assert widened.get("$v").level == TaintLattice.TOP

    def test_state_join_with_bottom(self):
        """Joining with a bottom state returns the other state."""
        bottom = AbstractState.bottom()
        s = AbstractState()
        s.set("$x", TaintInfo(level=TaintLattice.TAINTED, taint_types={"SQL"}))

        merged = bottom.join(s)
        assert merged.get("$x").level == TaintLattice.TAINTED


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

class TestFinding:
    def test_finding_to_dict(self):
        """to_dict() serializes all fields to a plain dictionary."""
        f = Finding(
            sink_name="mysqli_query",
            sink_line=42,
            sink_file="test.php",
            source_name="$_GET['id']",
            taint_types={"SQL"},
            vuln_type="SQL_INJECTION",
            severity="CRITICAL",
            confidence=0.9,
            sanitizers={"intval"},
        )
        d = f.to_dict()
        assert d["sink"] == "mysqli_query"
        assert d["sink_line"] == 42
        assert d["sink_file"] == "test.php"
        assert d["source"] == "$_GET['id']"
        assert "SQL" in d["taint_types"]
        assert d["vuln_type"] == "SQL_INJECTION"
        assert d["severity"] == "CRITICAL"
        assert d["confidence"] == 0.9
        assert "intval" in d["sanitizers"]


# ---------------------------------------------------------------------------
# AbstractInterpreter
# ---------------------------------------------------------------------------

class TestAbstractInterpreter:
    def test_interpreter_basic(self):
        """Interpreter can be instantiated and handles empty block list."""
        interp = AbstractInterpreter(rule_engine=None)
        assert interp.rules is None
        assert interp.findings == []

        states, findings = interp.analyze([], entry_state=None, filename="empty.php")
        assert states == {}
        assert findings == []
