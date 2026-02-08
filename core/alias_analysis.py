#!/usr/bin/env python3
"""
Points-to / alias analysis for PHP in the APEX security scanner.

Implements Andersen's inclusion-based points-to analysis to track references
and object properties through PHP code. This enables the taint engine to
correctly propagate taint across aliased variables and object fields.

Constraint rules:
    $a = &$b        -> points_to($a) >= points_to($b)   (reference)
    $a = new Foo()  -> points_to($a) = {alloc_site_N}   (allocation)
    $a->prop = $b   -> points_to(alloc.prop) >= points_to($b)  (field store)
    $a = $b         -> points_to($a) >= points_to($b)   (simple copy)

Fixed-point iteration continues until no points-to set changes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple

from .cfg import CFGBlock
from .ts_adapter import TSNode


# ---------------------------------------------------------------------------
# Points-to set representation
# ---------------------------------------------------------------------------

@dataclass
class PointsToSet:
    """Represents the set of abstract locations a variable may point to.

    Each location is a string identifier:
      - 'alloc_N'       : heap allocation site N
      - 'alloc_N.prop'  : the 'prop' field of allocation site N
      - '$varname'      : stack location for variable $varname
    """

    locations: Set[str] = field(default_factory=set)

    def union(self, other: PointsToSet) -> PointsToSet:
        """Return a new PointsToSet that is the union of self and other."""
        return PointsToSet(locations=self.locations | other.locations)

    def intersects(self, other: PointsToSet) -> bool:
        """Return True if self and other share at least one location."""
        return bool(self.locations & other.locations)

    def add(self, location: str) -> None:
        """Add a single location to this set."""
        self.locations.add(location)

    def __len__(self) -> int:
        return len(self.locations)

    def __contains__(self, item: str) -> bool:
        return item in self.locations

    def __repr__(self) -> str:
        if not self.locations:
            return "PointsToSet({})"
        items = ", ".join(sorted(self.locations))
        return f"PointsToSet({{{items}}})"

    def copy(self) -> PointsToSet:
        """Return a shallow copy of this points-to set."""
        return PointsToSet(locations=set(self.locations))


# ---------------------------------------------------------------------------
# Constraint types used during analysis
# ---------------------------------------------------------------------------

@dataclass
class _Constraint:
    """Base class for points-to constraints."""
    pass


@dataclass
class _AssignConstraint(_Constraint):
    """points_to(lhs) >= points_to(rhs)  -- simple assignment or reference."""
    lhs: str
    rhs: str


@dataclass
class _AllocConstraint(_Constraint):
    """points_to(lhs) >= {alloc_site}  -- new object allocation."""
    lhs: str
    alloc_site: str


@dataclass
class _FieldStoreConstraint(_Constraint):
    """For each loc in points_to(base): points_to(loc.field) >= points_to(rhs)."""
    base: str
    field_name: str
    rhs: str


@dataclass
class _FieldLoadConstraint(_Constraint):
    """For each loc in points_to(base): points_to(lhs) >= points_to(loc.field)."""
    lhs: str
    base: str
    field_name: str


# ---------------------------------------------------------------------------
# Main alias analyzer
# ---------------------------------------------------------------------------

class AliasAnalyzer:
    """Computes points-to information for PHP variables using
    Andersen's inclusion-based analysis over CFG blocks.

    Usage::

        analyzer = AliasAnalyzer()
        analyzer.analyze(cfg_blocks)
        if analyzer.may_alias('$a', '$b'):
            ...
        aliases = analyzer.get_aliases('$x')
    """

    # Maximum number of fixed-point iterations to prevent infinite loops
    MAX_ITERATIONS = 100

    def __init__(self) -> None:
        self._points_to: Dict[str, PointsToSet] = {}
        self._constraints: List[_Constraint] = []
        self._alloc_counter: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, cfg_blocks: List[CFGBlock]) -> None:
        """Compute points-to sets for all variables in the given CFG.

        This is the main entry point. It walks every statement in every
        block, extracts constraints, and iterates to a fixed point.

        Args:
            cfg_blocks: list of CFGBlock objects from the CFG builder.
        """
        self._points_to.clear()
        self._constraints.clear()
        self._alloc_counter = 0

        # Phase 1: collect constraints from all statements
        for block in cfg_blocks:
            for stmt in block.statements:
                self._extract_constraints(stmt)

        # Phase 2: fixed-point iteration
        self._solve()

    def may_alias(self, var1: str, var2: str) -> bool:
        """Return True if var1 and var2 may refer to the same memory.

        Two variables may alias if their points-to sets share at least
        one abstract location.

        Args:
            var1: first variable name (e.g. '$a').
            var2: second variable name (e.g. '$b').
        """
        pts1 = self._get_pts(var1)
        pts2 = self._get_pts(var2)
        return pts1.intersects(pts2)

    def get_aliases(self, var: str) -> Set[str]:
        """Return the set of variable names that may alias with *var*.

        Args:
            var: variable name (e.g. '$x').

        Returns:
            Set of variable names (including *var* itself) whose points-to
            sets overlap with *var*'s points-to set.
        """
        pts = self._get_pts(var)
        if not pts.locations:
            return {var}

        aliases: Set[str] = set()
        for other_var, other_pts in self._points_to.items():
            if pts.intersects(other_pts):
                aliases.add(other_var)
        # Always include the variable itself
        aliases.add(var)
        return aliases

    def get_points_to(self, var: str) -> PointsToSet:
        """Return the points-to set for a variable (read-only copy).

        Args:
            var: variable name.

        Returns:
            A copy of the points-to set for *var*, or an empty set if
            the variable was never encountered.
        """
        return self._get_pts(var).copy()

    # ------------------------------------------------------------------
    # Constraint extraction from AST nodes
    # ------------------------------------------------------------------

    def _extract_constraints(self, node: TSNode) -> None:
        """Walk an AST statement and generate points-to constraints."""
        if node.type == "expression_statement":
            # Unwrap the expression inside
            for child in node.named_children:
                self._extract_constraints(child)
            return

        if node.type == "assignment_expression":
            self._handle_assignment(node)
            return

        if node.type == "augmented_assignment_expression":
            # e.g. $a .= $b  -- treat as $a = $a . $b, i.e. copy constraint
            lhs = node.child_by_field("left")
            rhs = node.child_by_field("right")
            if lhs and rhs:
                lhs_name = self._var_name(lhs)
                rhs_name = self._var_name(rhs)
                if lhs_name and rhs_name:
                    self._add_constraint(_AssignConstraint(lhs=lhs_name, rhs=rhs_name))
            return

        # Recurse into child statements for compound constructs
        for child in node.named_children:
            self._extract_constraints(child)

    def _handle_assignment(self, node: TSNode) -> None:
        """Process an assignment_expression node and emit constraints."""
        lhs_node = node.child_by_field("left")
        rhs_node = node.child_by_field("right")
        if lhs_node is None or rhs_node is None:
            return

        lhs_name = self._var_name(lhs_node)
        if not lhs_name:
            # Could be a field store: $a->prop = $b
            self._handle_possible_field_store(lhs_node, rhs_node)
            return

        # Check for reference assignment: $a = &$b
        if rhs_node.type == "reference_assignment_expression":
            ref_var = rhs_node.child_by_field("right")
            if ref_var is None:
                # Fallback: try named children
                children = rhs_node.named_children
                ref_var = children[-1] if children else None
            if ref_var:
                ref_name = self._var_name(ref_var)
                if ref_name:
                    # Both share same location: add the ref variable's
                    # stack location to lhs's points-to set and vice versa
                    self._add_constraint(_AssignConstraint(lhs=lhs_name, rhs=ref_name))
                    # Also ensure they point to same abstract location
                    shared_loc = f"ref_{ref_name}"
                    self._get_pts(lhs_name).add(shared_loc)
                    self._get_pts(ref_name).add(shared_loc)
            return

        # Check for object instantiation: $a = new Foo()
        if rhs_node.type == "object_creation_expression":
            alloc_site = self._fresh_alloc()
            self._add_constraint(_AllocConstraint(lhs=lhs_name, alloc_site=alloc_site))
            return

        # Check for field load: $a = $b->prop
        if rhs_node.type == "member_access_expression":
            base_node = rhs_node.child_by_field("object")
            prop_node = rhs_node.child_by_field("name")
            if base_node and prop_node:
                base_name = self._var_name(base_node)
                prop_text = prop_node.text if prop_node else ""
                if base_name and prop_text:
                    self._add_constraint(
                        _FieldLoadConstraint(lhs=lhs_name, base=base_name,
                                             field_name=prop_text)
                    )
                    return

        # Default: simple copy  $a = $b  or  $a = expr($b)
        rhs_name = self._var_name(rhs_node)
        if rhs_name:
            self._add_constraint(_AssignConstraint(lhs=lhs_name, rhs=rhs_name))
        else:
            # RHS is a complex expression -- try to find variables within it
            for desc in rhs_node.walk_descendants():
                desc_name = self._var_name(desc)
                if desc_name:
                    self._add_constraint(_AssignConstraint(lhs=lhs_name, rhs=desc_name))

    def _handle_possible_field_store(self, lhs_node: TSNode, rhs_node: TSNode) -> None:
        """Handle  $obj->field = $rhs  patterns."""
        if lhs_node.type != "member_access_expression":
            return

        base_node = lhs_node.child_by_field("object")
        prop_node = lhs_node.child_by_field("name")
        if not base_node or not prop_node:
            return

        base_name = self._var_name(base_node)
        prop_text = prop_node.text if prop_node else ""
        rhs_name = self._var_name(rhs_node)

        if base_name and prop_text and rhs_name:
            self._add_constraint(
                _FieldStoreConstraint(base=base_name, field_name=prop_text,
                                      rhs=rhs_name)
            )

    # ------------------------------------------------------------------
    # Fixed-point solver
    # ------------------------------------------------------------------

    def _solve(self) -> None:
        """Iterate constraints until the points-to sets stabilize."""
        for _ in range(self.MAX_ITERATIONS):
            changed = False

            for constraint in self._constraints:
                if isinstance(constraint, _AllocConstraint):
                    pts = self._get_pts(constraint.lhs)
                    if constraint.alloc_site not in pts:
                        pts.add(constraint.alloc_site)
                        changed = True

                elif isinstance(constraint, _AssignConstraint):
                    # points_to(lhs) >= points_to(rhs)
                    src_pts = self._get_pts(constraint.rhs)
                    dst_pts = self._get_pts(constraint.lhs)
                    before = len(dst_pts)
                    dst_pts.locations |= src_pts.locations
                    if len(dst_pts) != before:
                        changed = True

                elif isinstance(constraint, _FieldStoreConstraint):
                    # For each loc in points_to(base):
                    #   points_to(loc.field) >= points_to(rhs)
                    base_pts = self._get_pts(constraint.base)
                    rhs_pts = self._get_pts(constraint.rhs)
                    for loc in list(base_pts.locations):
                        field_loc = f"{loc}.{constraint.field_name}"
                        field_pts = self._get_pts(field_loc)
                        before = len(field_pts)
                        field_pts.locations |= rhs_pts.locations
                        if len(field_pts) != before:
                            changed = True

                elif isinstance(constraint, _FieldLoadConstraint):
                    # For each loc in points_to(base):
                    #   points_to(lhs) >= points_to(loc.field)
                    base_pts = self._get_pts(constraint.base)
                    lhs_pts = self._get_pts(constraint.lhs)
                    for loc in list(base_pts.locations):
                        field_loc = f"{loc}.{constraint.field_name}"
                        field_pts = self._get_pts(field_loc)
                        before = len(lhs_pts)
                        lhs_pts.locations |= field_pts.locations
                        if len(lhs_pts) != before:
                            changed = True

            if not changed:
                break

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_pts(self, name: str) -> PointsToSet:
        """Get or create the points-to set for *name*."""
        if name not in self._points_to:
            self._points_to[name] = PointsToSet()
        return self._points_to[name]

    def _add_constraint(self, constraint: _Constraint) -> None:
        """Register a new constraint."""
        self._constraints.append(constraint)

    def _fresh_alloc(self) -> str:
        """Return a fresh allocation site identifier."""
        site = f"alloc_{self._alloc_counter}"
        self._alloc_counter += 1
        return site

    @staticmethod
    def _var_name(node: TSNode) -> Optional[str]:
        """Extract the variable name string from a TSNode, or None.

        Handles:
          - variable_name nodes  -> '$foo'
          - dynamic_variable_name -> None (not trackable)
        """
        if node.type == "variable_name":
            return node.text
        # Some tree-sitter grammars wrap the variable
        if node.type in ("cast_expression", "parenthesized_expression"):
            for child in node.named_children:
                name = AliasAnalyzer._var_name(child)
                if name:
                    return name
        return None
