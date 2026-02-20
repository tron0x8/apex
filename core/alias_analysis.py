#!/usr/bin/env python3
# apex/core - tron (@tron0x8)

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple

from .cfg import CFGBlock
from .ts_adapter import TSNode


# andersen's inclusion-based - handles php references ($a = &$b)
@dataclass
class PointsToSet:

    locations: Set[str] = field(default_factory=set)

    def union(self, other: PointsToSet) -> PointsToSet:
        return PointsToSet(locations=self.locations | other.locations)

    def intersects(self, other: PointsToSet) -> bool:
        return bool(self.locations & other.locations)

    def add(self, location: str) -> None:
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
        return PointsToSet(locations=set(self.locations))


@dataclass
class _Constraint:
    pass


@dataclass
class _AssignConstraint(_Constraint):
    lhs: str
    rhs: str


@dataclass
class _AllocConstraint(_Constraint):
    lhs: str
    alloc_site: str


@dataclass
class _FieldStoreConstraint(_Constraint):
    base: str
    field_name: str
    rhs: str


@dataclass
class _FieldLoadConstraint(_Constraint):
    lhs: str
    base: str
    field_name: str


class AliasAnalyzer:

    MAX_ITERATIONS = 100

    def __init__(self) -> None:
        self._points_to: Dict[str, PointsToSet] = {}
        self._constraints: List[_Constraint] = []
        self._alloc_counter: int = 0


    def analyze(self, cfg_blocks: List[CFGBlock]) -> None:
        self._points_to.clear()
        self._constraints.clear()
        self._alloc_counter = 0

        for block in cfg_blocks:
            for stmt in block.statements:
                self._extract_constraints(stmt)

        self._solve()

    def may_alias(self, var1: str, var2: str) -> bool:
        pts1 = self._get_pts(var1)
        pts2 = self._get_pts(var2)
        return pts1.intersects(pts2)

    def get_aliases(self, var: str) -> Set[str]:
        pts = self._get_pts(var)
        if not pts.locations:
            return {var}

        aliases: Set[str] = set()
        for other_var, other_pts in self._points_to.items():
            if pts.intersects(other_pts):
                aliases.add(other_var)
        aliases.add(var)
        return aliases

    def get_points_to(self, var: str) -> PointsToSet:
        return self._get_pts(var).copy()


    def _extract_constraints(self, node: TSNode) -> None:
        if node.type == "expression_statement":
            for child in node.named_children:
                self._extract_constraints(child)
            return

        if node.type == "assignment_expression":
            self._handle_assignment(node)
            return

        if node.type == "augmented_assignment_expression":
            lhs = node.child_by_field("left")
            rhs = node.child_by_field("right")
            if lhs and rhs:
                lhs_name = self._var_name(lhs)
                rhs_name = self._var_name(rhs)
                if lhs_name and rhs_name:
                    self._add_constraint(_AssignConstraint(lhs=lhs_name, rhs=rhs_name))
            return

        for child in node.named_children:
            self._extract_constraints(child)

    def _handle_assignment(self, node: TSNode) -> None:
        lhs_node = node.child_by_field("left")
        rhs_node = node.child_by_field("right")
        if lhs_node is None or rhs_node is None:
            return

        lhs_name = self._var_name(lhs_node)
        if not lhs_name:
            self._handle_possible_field_store(lhs_node, rhs_node)
            return

        if rhs_node.type == "reference_assignment_expression":
            ref_var = rhs_node.child_by_field("right")
            if ref_var is None:
                children = rhs_node.named_children
                ref_var = children[-1] if children else None
            if ref_var:
                ref_name = self._var_name(ref_var)
                if ref_name:
                    self._add_constraint(_AssignConstraint(lhs=lhs_name, rhs=ref_name))
                    shared_loc = f"ref_{ref_name}"
                    self._get_pts(lhs_name).add(shared_loc)
                    self._get_pts(ref_name).add(shared_loc)
            return

        if rhs_node.type == "object_creation_expression":
            alloc_site = self._fresh_alloc()
            self._add_constraint(_AllocConstraint(lhs=lhs_name, alloc_site=alloc_site))
            return

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

        rhs_name = self._var_name(rhs_node)
        if rhs_name:
            self._add_constraint(_AssignConstraint(lhs=lhs_name, rhs=rhs_name))
        else:
            for desc in rhs_node.walk_descendants():
                desc_name = self._var_name(desc)
                if desc_name:
                    self._add_constraint(_AssignConstraint(lhs=lhs_name, rhs=desc_name))

    def _handle_possible_field_store(self, lhs_node: TSNode, rhs_node: TSNode) -> None:
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


    def _solve(self) -> None:
        for _ in range(self.MAX_ITERATIONS):
            changed = False

            for constraint in self._constraints:
                if isinstance(constraint, _AllocConstraint):
                    pts = self._get_pts(constraint.lhs)
                    if constraint.alloc_site not in pts:
                        pts.add(constraint.alloc_site)
                        changed = True

                elif isinstance(constraint, _AssignConstraint):
                    src_pts = self._get_pts(constraint.rhs)
                    dst_pts = self._get_pts(constraint.lhs)
                    before = len(dst_pts)
                    dst_pts.locations |= src_pts.locations
                    if len(dst_pts) != before:
                        changed = True

                elif isinstance(constraint, _FieldStoreConstraint):
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


    def _get_pts(self, name: str) -> PointsToSet:
        if name not in self._points_to:
            self._points_to[name] = PointsToSet()
        return self._points_to[name]

    def _add_constraint(self, constraint: _Constraint) -> None:
        self._constraints.append(constraint)

    def _fresh_alloc(self) -> str:
        site = f"alloc_{self._alloc_counter}"
        self._alloc_counter += 1
        return site

    @staticmethod
    def _var_name(node: TSNode) -> Optional[str]:
        if node.type == "variable_name":
            return node.text
        if node.type in ("cast_expression", "parenthesized_expression"):
            for child in node.named_children:
                name = AliasAnalyzer._var_name(child)
                if name:
                    return name
        return None
