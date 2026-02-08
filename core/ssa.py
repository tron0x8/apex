#!/usr/bin/env python3
"""
APEX SSA (Static Single Assignment) Builder
Converts CFG to SSA form using dominance frontiers for precise taint tracking.

SSA ensures each variable is assigned exactly once, with phi nodes at join points.
This enables precise tracking when the same variable is reassigned in different branches.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict, deque
from .cfg import CFGBlock
from .ts_adapter import TSNode


@dataclass(frozen=True)
class SSAVariable:
    """A variable with SSA version number."""
    name: str       # Original PHP name, e.g. "$x"
    version: int    # SSA version, e.g. 0, 1, 2

    def __str__(self):
        return f"{self.name}_{self.version}"


@dataclass
class PhiNode:
    """Phi function at a join point in the CFG."""
    target: SSAVariable
    sources: Dict[int, SSAVariable] = field(default_factory=dict)  # pred_block_id -> SSAVar
    block_id: int = 0
    original_name: str = ""

    def __str__(self):
        srcs = ", ".join(f"{v} (from B{k})" for k, v in self.sources.items())
        return f"{self.target} = phi({srcs})"


@dataclass
class SSACFGBlock:
    """Extended CFG block with phi nodes and SSA variable mappings."""
    block: CFGBlock
    phi_nodes: List[PhiNode] = field(default_factory=list)
    # Maps original variable name to current SSA version at block exit
    var_versions_out: Dict[str, SSAVariable] = field(default_factory=dict)

    @property
    def id(self):
        return self.block.id

    @property
    def statements(self):
        return self.block.statements

    @property
    def successors(self):
        return self.block.successors

    @property
    def predecessors(self):
        return self.block.predecessors

    @property
    def is_entry(self):
        return self.block.is_entry

    @property
    def is_exit(self):
        return self.block.is_exit


class SSABuilder:
    """
    Convert CFG to SSA form using the classic algorithm:
    1. Compute dominators (Cooper/Harvey/Kennedy iterative algorithm)
    2. Compute dominance frontiers
    3. Insert phi nodes at dominance frontiers
    4. Rename variables via DFS of dominator tree
    """

    def __init__(self):
        self._version_counters: Dict[str, int] = defaultdict(int)
        self._version_stacks: Dict[str, List[int]] = defaultdict(list)

    def build(self, cfg_blocks: List[CFGBlock]) -> List[SSACFGBlock]:
        """Convert a CFG to SSA form."""
        if not cfg_blocks:
            return []

        # Wrap blocks
        ssa_blocks = {b.id: SSACFGBlock(block=b) for b in cfg_blocks}
        block_ids = [b.id for b in cfg_blocks]

        # Find entry
        entry_id = None
        for b in cfg_blocks:
            if b.is_entry:
                entry_id = b.id
                break
        if entry_id is None:
            entry_id = block_ids[0]

        # Collect variables defined in each block
        defs = self._collect_definitions(cfg_blocks)

        # Step 1: Compute dominators
        idom = self._compute_dominators(cfg_blocks, entry_id)

        # Step 2: Compute dominance frontiers
        df = self._compute_dom_frontiers(cfg_blocks, idom)

        # Step 3: Insert phi nodes
        self._insert_phi_nodes(ssa_blocks, defs, df)

        # Step 4: Rename variables
        self._version_counters.clear()
        self._version_stacks.clear()
        dom_children = self._build_dom_tree(idom, block_ids)
        self._rename_variables(entry_id, ssa_blocks, dom_children)

        return list(ssa_blocks.values())

    def _collect_definitions(self, blocks: List[CFGBlock]) -> Dict[str, Set[int]]:
        """Collect which blocks define each variable."""
        defs = defaultdict(set)
        for block in blocks:
            for stmt in block.statements:
                for var_name in self._get_defined_vars(stmt):
                    defs[var_name].add(block.id)
        return defs

    def _get_defined_vars(self, node: TSNode) -> List[str]:
        """Extract variables defined (assigned to) in a statement."""
        defined = []
        if node.type == 'expression_statement':
            for child in node.named_children:
                defined.extend(self._get_defined_vars(child))
        elif node.type == 'assignment_expression':
            left = node.child_by_field('left')
            if left:
                var_name = self._extract_var_name(left)
                if var_name:
                    defined.append(var_name)
        elif node.type == 'augmented_assignment_expression':
            left = node.child_by_field('left')
            if left:
                var_name = self._extract_var_name(left)
                if var_name:
                    defined.append(var_name)
        return defined

    def _extract_var_name(self, node: TSNode) -> Optional[str]:
        """Extract PHP variable name from a node."""
        if node.type == 'variable_name':
            return node.text
        if node.type == 'subscript_expression':
            # $arr[$key] - get the array variable
            if node.named_children:
                return self._extract_var_name(node.named_children[0])
        return None

    def _compute_dominators(self, blocks: List[CFGBlock], entry_id: int) -> Dict[int, int]:
        """
        Iterative dominator computation (Cooper/Harvey/Kennedy algorithm).
        Returns idom: block_id -> immediate dominator block_id.
        """
        block_map = {b.id: b for b in blocks}
        block_ids = [b.id for b in blocks]

        # Post-order numbering
        post_order = []
        visited = set()

        def dfs(bid):
            if bid in visited:
                return
            visited.add(bid)
            block = block_map.get(bid)
            if block:
                for succ_id in block.successors:
                    dfs(succ_id)
            post_order.append(bid)

        dfs(entry_id)
        post_num = {bid: i for i, bid in enumerate(post_order)}

        # Initialize
        idom = {bid: -1 for bid in block_ids}
        idom[entry_id] = entry_id

        def intersect(b1, b2):
            finger1, finger2 = b1, b2
            while finger1 != finger2:
                while post_num.get(finger1, -1) < post_num.get(finger2, -1):
                    finger1 = idom.get(finger1, finger1)
                    if finger1 == -1:
                        return b2
                while post_num.get(finger2, -1) < post_num.get(finger1, -1):
                    finger2 = idom.get(finger2, finger2)
                    if finger2 == -1:
                        return b1
            return finger1

        # Iterate in reverse post-order (skip entry)
        rpo = list(reversed(post_order))
        changed = True
        max_iters = 100
        iters = 0
        while changed and iters < max_iters:
            changed = False
            iters += 1
            for bid in rpo:
                if bid == entry_id:
                    continue
                block = block_map.get(bid)
                if not block:
                    continue

                # Find first processed predecessor
                new_idom = -1
                for pred_id in block.predecessors:
                    if idom.get(pred_id, -1) != -1:
                        new_idom = pred_id
                        break

                if new_idom == -1:
                    continue

                for pred_id in block.predecessors:
                    if pred_id == new_idom:
                        continue
                    if idom.get(pred_id, -1) != -1:
                        new_idom = intersect(pred_id, new_idom)

                if idom.get(bid) != new_idom:
                    idom[bid] = new_idom
                    changed = True

        return idom

    def _compute_dom_frontiers(self, blocks: List[CFGBlock],
                                idom: Dict[int, int]) -> Dict[int, Set[int]]:
        """Compute dominance frontiers from immediate dominators."""
        df = defaultdict(set)
        block_map = {b.id: b for b in blocks}

        for block in blocks:
            if len(block.predecessors) < 2:
                continue
            for pred_id in block.predecessors:
                runner = pred_id
                max_steps = 100
                steps = 0
                while runner != idom.get(block.id, -1) and runner != -1 and steps < max_steps:
                    df[runner].add(block.id)
                    runner = idom.get(runner, -1)
                    steps += 1

        return df

    def _insert_phi_nodes(self, ssa_blocks: Dict[int, SSACFGBlock],
                           defs: Dict[str, Set[int]],
                           df: Dict[int, Set[int]]):
        """Place phi nodes at dominance frontiers for each variable."""
        for var_name, def_blocks in defs.items():
            worklist = deque(def_blocks)
            processed = set()
            phi_placed = set()

            while worklist:
                block_id = worklist.popleft()
                for frontier_id in df.get(block_id, set()):
                    if frontier_id not in phi_placed:
                        phi_placed.add(frontier_id)
                        if frontier_id in ssa_blocks:
                            phi = PhiNode(
                                target=SSAVariable(var_name, 0),  # Version set during rename
                                block_id=frontier_id,
                                original_name=var_name,
                            )
                            ssa_blocks[frontier_id].phi_nodes.append(phi)
                        if frontier_id not in processed:
                            processed.add(frontier_id)
                            worklist.append(frontier_id)

    def _build_dom_tree(self, idom: Dict[int, int],
                         block_ids: List[int]) -> Dict[int, List[int]]:
        """Build dominator tree children map from idom."""
        children = defaultdict(list)
        for bid in block_ids:
            parent = idom.get(bid, -1)
            if parent != -1 and parent != bid:
                children[parent].append(bid)
        return children

    def _new_version(self, var_name: str) -> int:
        """Generate next SSA version for a variable."""
        ver = self._version_counters[var_name]
        self._version_counters[var_name] = ver + 1
        self._version_stacks[var_name].append(ver)
        return ver

    def _current_version(self, var_name: str) -> int:
        """Get current SSA version of a variable."""
        stack = self._version_stacks.get(var_name)
        if stack:
            return stack[-1]
        # First use without prior def - create version 0
        return self._new_version(var_name)

    def _rename_variables(self, block_id: int,
                           ssa_blocks: Dict[int, SSACFGBlock],
                           dom_children: Dict[int, List[int]]):
        """Rename variables with SSA versions via DFS of dominator tree."""
        block = ssa_blocks.get(block_id)
        if not block:
            return

        # Track how many versions we push (to pop on exit)
        push_counts: Dict[str, int] = defaultdict(int)

        # Process phi nodes - each phi defines a new version
        for phi in block.phi_nodes:
            ver = self._new_version(phi.original_name)
            phi.target = SSAVariable(phi.original_name, ver)
            push_counts[phi.original_name] += 1

        # Process statements - rename uses and definitions
        for stmt in block.statements:
            self._rename_stmt_vars(stmt, push_counts)

        # Record output versions
        for var_name in set(list(push_counts.keys()) +
                           list(self._version_stacks.keys())):
            stack = self._version_stacks.get(var_name)
            if stack:
                block.var_versions_out[var_name] = SSAVariable(var_name, stack[-1])

        # Fill phi node sources in successor blocks
        for succ_id in block.successors:
            succ = ssa_blocks.get(succ_id)
            if not succ:
                continue
            for phi in succ.phi_nodes:
                stack = self._version_stacks.get(phi.original_name)
                if stack:
                    phi.sources[block_id] = SSAVariable(phi.original_name, stack[-1])

        # Recurse into dominator tree children
        for child_id in dom_children.get(block_id, []):
            self._rename_variables(child_id, ssa_blocks, dom_children)

        # Pop versions pushed in this block
        for var_name, count in push_counts.items():
            for _ in range(count):
                if self._version_stacks[var_name]:
                    self._version_stacks[var_name].pop()

    def _rename_stmt_vars(self, node: TSNode, push_counts: Dict[str, int]):
        """Rename variable uses and definitions in a statement."""
        if node.type == 'expression_statement':
            for child in node.named_children:
                self._rename_stmt_vars(child, push_counts)
        elif node.type == 'assignment_expression':
            # First rename the RHS (uses), then the LHS (definition)
            right = node.child_by_field('right')
            if right:
                self._rename_uses(right)
            left = node.child_by_field('left')
            if left:
                var_name = self._extract_var_name(left)
                if var_name:
                    ver = self._new_version(var_name)
                    push_counts[var_name] += 1
        elif node.type == 'augmented_assignment_expression':
            # += etc: use then define
            right = node.child_by_field('right')
            if right:
                self._rename_uses(right)
            left = node.child_by_field('left')
            if left:
                var_name = self._extract_var_name(left)
                if var_name:
                    ver = self._new_version(var_name)
                    push_counts[var_name] += 1
        else:
            # Other statements: just rename uses
            self._rename_uses(node)

    def _rename_uses(self, node: TSNode):
        """Rename variable uses in an expression (read current version)."""
        # This is a lightweight pass - actual SSA renaming for the taint
        # engine happens at the AbstractState level using var_versions_out.
        # Here we just ensure version stacks are properly maintained.
        pass


def build_ssa(cfg_blocks: List[CFGBlock]) -> List[SSACFGBlock]:
    """Convenience function to build SSA from CFG blocks."""
    builder = SSABuilder()
    return builder.build(cfg_blocks)
