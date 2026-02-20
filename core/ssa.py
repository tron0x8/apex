#!/usr/bin/env python3
# apex/core - tron (@tron0x8)

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict, deque
from .cfg import CFGBlock
from .ts_adapter import TSNode


# ssa with phi nodes - needed for branch-aware taint tracking
@dataclass(frozen=True)
class SSAVariable:
    name: str
    version: int

    def __str__(self):
        return f"{self.name}_{self.version}"


@dataclass
class PhiNode:
    target: SSAVariable
    sources: Dict[int, SSAVariable] = field(default_factory=dict)
    block_id: int = 0
    original_name: str = ""

    def __str__(self):
        srcs = ", ".join(f"{v} (from B{k})" for k, v in self.sources.items())
        return f"{self.target} = phi({srcs})"


@dataclass
class SSACFGBlock:
    block: CFGBlock
    phi_nodes: List[PhiNode] = field(default_factory=list)
    var_versions_out: Dict[str, SSAVariable] = field(default_factory=dict)
    use_versions: Dict[Tuple[int, str], SSAVariable] = field(default_factory=dict)

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

    def __init__(self):
        self._version_counters: Dict[str, int] = defaultdict(int)
        self._version_stacks: Dict[str, List[int]] = defaultdict(list)

    def build(self, cfg_blocks: List[CFGBlock]) -> List[SSACFGBlock]:
        if not cfg_blocks:
            return []

        ssa_blocks = {b.id: SSACFGBlock(block=b) for b in cfg_blocks}
        block_ids = [b.id for b in cfg_blocks]

        entry_id = None
        for b in cfg_blocks:
            if b.is_entry:
                entry_id = b.id
                break
        if entry_id is None:
            entry_id = block_ids[0]

        defs = self._collect_definitions(cfg_blocks)

        idom = self._compute_dominators(cfg_blocks, entry_id)

        df = self._compute_dom_frontiers(cfg_blocks, idom)

        self._insert_phi_nodes(ssa_blocks, defs, df)

        self._version_counters.clear()
        self._version_stacks.clear()
        dom_children = self._build_dom_tree(idom, block_ids)
        self._rename_variables(entry_id, ssa_blocks, dom_children)

        return list(ssa_blocks.values())

    def _collect_definitions(self, blocks: List[CFGBlock]) -> Dict[str, Set[int]]:
        defs = defaultdict(set)
        for block in blocks:
            for stmt in block.statements:
                for var_name in self._get_defined_vars(stmt):
                    defs[var_name].add(block.id)
        return defs

    def _get_defined_vars(self, node: TSNode) -> List[str]:
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
        if node.type == 'variable_name':
            return node.text
        if node.type == 'subscript_expression':
            if node.named_children:
                return self._extract_var_name(node.named_children[0])
        return None

    def _compute_dominators(self, blocks: List[CFGBlock], entry_id: int) -> Dict[int, int]:
        # cooper, harvey, kennedy - "a simple, fast dominance algorithm"
        block_map = {b.id: b for b in blocks}
        block_ids = [b.id for b in blocks]

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
        # cytron et al. algorithm - place phi at iterated dominance frontiers
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
                                target=SSAVariable(var_name, 0),
                                block_id=frontier_id,
                                original_name=var_name,
                            )
                            ssa_blocks[frontier_id].phi_nodes.append(phi)
                        if frontier_id not in processed:
                            processed.add(frontier_id)
                            worklist.append(frontier_id)

    def _build_dom_tree(self, idom: Dict[int, int],
                         block_ids: List[int]) -> Dict[int, List[int]]:
        children = defaultdict(list)
        for bid in block_ids:
            parent = idom.get(bid, -1)
            if parent != -1 and parent != bid:
                children[parent].append(bid)
        return children

    def _new_version(self, var_name: str) -> int:
        ver = self._version_counters[var_name]
        self._version_counters[var_name] = ver + 1
        self._version_stacks[var_name].append(ver)
        return ver

    def _current_version(self, var_name: str) -> int:
        stack = self._version_stacks.get(var_name)
        if stack:
            return stack[-1]
        return self._new_version(var_name)

    def _rename_variables(self, block_id: int,
                           ssa_blocks: Dict[int, SSACFGBlock],
                           dom_children: Dict[int, List[int]]):
        block = ssa_blocks.get(block_id)
        if not block:
            return

        push_counts: Dict[str, int] = defaultdict(int)

        for phi in block.phi_nodes:
            ver = self._new_version(phi.original_name)
            phi.target = SSAVariable(phi.original_name, ver)
            push_counts[phi.original_name] += 1

        for stmt in block.statements:
            self._rename_stmt_vars(stmt, push_counts)

        for var_name in set(list(push_counts.keys()) +
                           list(self._version_stacks.keys())):
            stack = self._version_stacks.get(var_name)
            if stack:
                block.var_versions_out[var_name] = SSAVariable(var_name, stack[-1])

        for succ_id in block.successors:
            succ = ssa_blocks.get(succ_id)
            if not succ:
                continue
            for phi in succ.phi_nodes:
                stack = self._version_stacks.get(phi.original_name)
                if stack:
                    phi.sources[block_id] = SSAVariable(phi.original_name, stack[-1])

        for child_id in dom_children.get(block_id, []):
            self._rename_variables(child_id, ssa_blocks, dom_children)

        for var_name, count in push_counts.items():
            for _ in range(count):
                if self._version_stacks[var_name]:
                    self._version_stacks[var_name].pop()

    def _rename_stmt_vars(self, node: TSNode, push_counts: Dict[str, int]):
        if node.type == 'expression_statement':
            for child in node.named_children:
                self._rename_stmt_vars(child, push_counts)
        elif node.type == 'assignment_expression':
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
            self._rename_uses(node)

    def _rename_uses(self, node: TSNode):
        if node.type == 'variable_name':
            var_name = node.text
            if var_name and var_name.startswith('$'):
                ver = self._current_version(var_name)
        for child in node.named_children:
            self._rename_uses(child)


def build_ssa(cfg_blocks: List[CFGBlock]) -> List[SSACFGBlock]:
    builder = SSABuilder()
    return builder.build(cfg_blocks)
