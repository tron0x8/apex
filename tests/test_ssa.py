#!/usr/bin/env python3
"""
Tests for core/ssa.py - SSA builder that converts CFG blocks to
Static Single Assignment form with phi nodes and variable versioning.
"""

import pytest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.ssa import SSAVariable, PhiNode, SSACFGBlock, SSABuilder, build_ssa
from core.cfg import CFGBuilder, CFGBlock
from core.ts_adapter import parse_php_ts


# --------------- helpers ---------------

def _build_cfg(php_code: str):
    """Parse PHP code and build CFG blocks from the program node."""
    root = parse_php_ts(php_code)
    builder = CFGBuilder()
    return builder.build(root)


# --------------- SSAVariable tests ---------------

class TestSSAVariable:
    def test_ssa_variable_str(self):
        """SSAVariable.__str__ renders as '$name_version'."""
        v = SSAVariable("$x", 0)
        assert str(v) == "$x_0"

        v2 = SSAVariable("$data", 3)
        assert str(v2) == "$data_3"

    def test_ssa_variable_frozen(self):
        """SSAVariable is a frozen dataclass: immutable and hashable."""
        v = SSAVariable("$x", 0)

        # Immutable - assignment raises
        with pytest.raises(AttributeError):
            v.name = "$y"
        with pytest.raises(AttributeError):
            v.version = 1

        # Hashable - can be used as dict key / set member
        d = {v: "tainted"}
        assert d[SSAVariable("$x", 0)] == "tainted"

        s = {v, SSAVariable("$x", 1)}
        assert len(s) == 2

    def test_ssa_variable_equality(self):
        """Two SSAVariables with the same name and version are equal."""
        a = SSAVariable("$x", 0)
        b = SSAVariable("$x", 0)
        assert a == b
        assert hash(a) == hash(b)

        c = SSAVariable("$x", 1)
        assert a != c


# --------------- PhiNode tests ---------------

class TestPhiNode:
    def test_phi_node_str(self):
        """PhiNode.__str__ shows target = phi(sources)."""
        phi = PhiNode(
            target=SSAVariable("$x", 2),
            sources={0: SSAVariable("$x", 0), 1: SSAVariable("$x", 1)},
            block_id=3,
            original_name="$x",
        )
        s = str(phi)
        assert "$x_2 = phi(" in s
        assert "$x_0" in s
        assert "$x_1" in s

    def test_phi_node_empty_sources(self):
        """PhiNode with no sources renders correctly."""
        phi = PhiNode(target=SSAVariable("$y", 0), original_name="$y")
        s = str(phi)
        assert "$y_0 = phi()" == s


# --------------- SSABuilder tests ---------------

class TestBuildSSALinear:
    def test_build_ssa_linear(self):
        """Linear code (no branches) produces no phi nodes."""
        code = "<?php $x = 1; $y = 2; $z = $x + $y; ?>"
        cfg_blocks = _build_cfg(code)
        ssa_blocks = build_ssa(cfg_blocks)

        assert len(ssa_blocks) > 0
        # No phi nodes in purely linear code
        for sb in ssa_blocks:
            assert isinstance(sb, SSACFGBlock)
            assert len(sb.phi_nodes) == 0


class TestBuildSSABranch:
    def test_build_ssa_branch(self):
        """if/else reassigning the same variable should create phi nodes."""
        code = (
            "<?php\n"
            "$x = 1;\n"
            "if ($cond) {\n"
            "    $x = 2;\n"
            "} else {\n"
            "    $x = 3;\n"
            "}\n"
            "echo $x;\n"
            "?>"
        )
        cfg_blocks = _build_cfg(code)
        ssa_blocks = build_ssa(cfg_blocks)

        assert len(ssa_blocks) >= 3, "Branch should produce multiple blocks"

        # Collect all phi nodes across every block
        all_phi = [phi for sb in ssa_blocks for phi in sb.phi_nodes]
        phi_vars = [phi.original_name for phi in all_phi]
        assert "$x" in phi_vars, "Expected a phi node for $x at the join point"


class TestBuildSSAEmpty:
    def test_build_ssa_empty(self):
        """Empty block list returns empty list."""
        result = build_ssa([])
        assert result == []


class TestSSAVersionsIncrement:
    def test_ssa_versions_increment(self):
        """Each assignment to the same variable creates a new SSA version."""
        code = "<?php $a = 1; $a = 2; $a = 3; ?>"
        cfg_blocks = _build_cfg(code)
        ssa_blocks = build_ssa(cfg_blocks)

        # Find blocks that record $a in var_versions_out
        versions_seen = set()
        for sb in ssa_blocks:
            if "$a" in sb.var_versions_out:
                versions_seen.add(sb.var_versions_out["$a"].version)

        # Three assignments should produce versions 0, 1, 2
        # The exit block records the final version (at least version 2)
        assert max(versions_seen) >= 2, (
            f"Expected version >= 2 after 3 assignments, got {versions_seen}"
        )


class TestBuildSSAConvenience:
    def test_build_ssa_convenience(self):
        """build_ssa() convenience wrapper works the same as SSABuilder().build()."""
        code = "<?php $v = 10; $v = 20; ?>"
        cfg_blocks = _build_cfg(code)

        result_a = SSABuilder().build(cfg_blocks)
        # rebuild CFG for a fresh set of blocks (SSABuilder mutates blocks)
        cfg_blocks2 = _build_cfg(code)
        result_b = build_ssa(cfg_blocks2)

        assert len(result_a) == len(result_b)
        # Both should track $v in their output versions
        a_has_v = any("$v" in sb.var_versions_out for sb in result_a)
        b_has_v = any("$v" in sb.var_versions_out for sb in result_b)
        assert a_has_v and b_has_v


class TestSSACFGBlockProperties:
    def test_ssa_block_delegates_to_cfg(self):
        """SSACFGBlock delegates id, statements, successors, predecessors to CFGBlock."""
        code = "<?php $z = 42; ?>"
        cfg_blocks = _build_cfg(code)
        ssa_blocks = build_ssa(cfg_blocks)

        entry = [sb for sb in ssa_blocks if sb.is_entry]
        assert len(entry) == 1
        sb = entry[0]
        assert sb.id == sb.block.id
        assert sb.statements is sb.block.statements
        assert sb.successors is sb.block.successors
        assert sb.predecessors is sb.block.predecessors
        assert sb.is_entry is True
