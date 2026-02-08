#!/usr/bin/env python3
"""
APEX Abstract Interpretation Engine
Lattice-based taint analysis with widening for guaranteed termination.

Uses SSA variables for precision and YAML-driven rules for sources/sinks/sanitizers.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from collections import deque, defaultdict
from enum import IntEnum

from .cfg import CFGBlock
from .ssa import SSAVariable, SSACFGBlock, PhiNode
from .ts_adapter import TSNode


class TaintLattice(IntEnum):
    """Taint lattice: BOTTOM < UNTAINTED < WEAK < TAINTED < TOP"""
    BOTTOM = 0      # Unreachable code
    UNTAINTED = 1   # Definitely clean
    WEAK = 2        # From weak/indirect source ($data, $input)
    TAINTED = 3     # From direct source ($_GET, $_POST)
    TOP = 4         # Unknown / could be anything

    @staticmethod
    def join(a: 'TaintLattice', b: 'TaintLattice') -> 'TaintLattice':
        """Least upper bound (conservative merge)."""
        return TaintLattice(max(int(a), int(b)))

    @staticmethod
    def meet(a: 'TaintLattice', b: 'TaintLattice') -> 'TaintLattice':
        """Greatest lower bound."""
        return TaintLattice(min(int(a), int(b)))

    @staticmethod
    def widen(old: 'TaintLattice', new: 'TaintLattice') -> 'TaintLattice':
        """Widening operator for loop convergence."""
        if int(new) > int(old):
            return TaintLattice.TOP
        return old


@dataclass
class TaintInfo:
    """Taint information for a single variable."""
    level: TaintLattice = TaintLattice.BOTTOM
    taint_types: Set[str] = field(default_factory=set)
    sources: Set[str] = field(default_factory=set)
    sanitizers_applied: Set[str] = field(default_factory=set)
    sanitized_types: Set[str] = field(default_factory=set)

    def is_tainted(self) -> bool:
        return self.level >= TaintLattice.WEAK

    def effective_types(self) -> Set[str]:
        """Taint types minus sanitized types."""
        return self.taint_types - self.sanitized_types

    def copy(self) -> 'TaintInfo':
        return TaintInfo(
            level=self.level,
            taint_types=set(self.taint_types),
            sources=set(self.sources),
            sanitizers_applied=set(self.sanitizers_applied),
            sanitized_types=set(self.sanitized_types),
        )


class AbstractState:
    """Maps variables to their taint information."""

    def __init__(self):
        self.vars: Dict[str, TaintInfo] = {}
        self._hash = None

    @staticmethod
    def bottom() -> 'AbstractState':
        """Create bottom state (unreachable)."""
        state = AbstractState()
        state._is_bottom = True
        return state

    @staticmethod
    def top() -> 'AbstractState':
        """Create top state (unknown)."""
        state = AbstractState()
        return state

    def get(self, var_name: str) -> TaintInfo:
        """Get taint info for a variable."""
        return self.vars.get(var_name, TaintInfo())

    def set(self, var_name: str, info: TaintInfo):
        """Set taint info for a variable."""
        self.vars[var_name] = info
        self._hash = None

    def join(self, other: 'AbstractState') -> 'AbstractState':
        """Merge two states at a join point (conservative)."""
        if getattr(self, '_is_bottom', False):
            return other.copy()
        if getattr(other, '_is_bottom', False):
            return self.copy()

        result = AbstractState()
        all_vars = set(self.vars.keys()) | set(other.vars.keys())

        for var in all_vars:
            a = self.get(var)
            b = other.get(var)
            result.vars[var] = TaintInfo(
                level=TaintLattice.join(a.level, b.level),
                taint_types=a.taint_types | b.taint_types,
                sources=a.sources | b.sources,
                sanitizers_applied=a.sanitizers_applied & b.sanitizers_applied,
                sanitized_types=a.sanitized_types & b.sanitized_types,
            )

        return result

    def widen(self, other: 'AbstractState') -> 'AbstractState':
        """Widening to ensure termination in loops."""
        result = AbstractState()
        all_vars = set(self.vars.keys()) | set(other.vars.keys())

        for var in all_vars:
            a = self.get(var)
            b = other.get(var)
            result.vars[var] = TaintInfo(
                level=TaintLattice.widen(a.level, b.level),
                taint_types=a.taint_types | b.taint_types,
                sources=a.sources | b.sources,
                sanitizers_applied=a.sanitizers_applied & b.sanitizers_applied,
                sanitized_types=a.sanitized_types & b.sanitized_types,
            )

        return result

    def copy(self) -> 'AbstractState':
        result = AbstractState()
        for var, info in self.vars.items():
            result.vars[var] = info.copy()
        if getattr(self, '_is_bottom', False):
            result._is_bottom = True
        return result

    def __eq__(self, other):
        if not isinstance(other, AbstractState):
            return False
        if getattr(self, '_is_bottom', False) != getattr(other, '_is_bottom', False):
            return False
        if set(self.vars.keys()) != set(other.vars.keys()):
            return False
        for var in self.vars:
            a = self.vars[var]
            b = other.vars.get(var, TaintInfo())
            if a.level != b.level or a.taint_types != b.taint_types:
                return False
        return True


@dataclass
class Finding:
    """A potential vulnerability found during analysis."""
    sink_name: str
    sink_line: int
    sink_file: str
    source_name: str
    taint_types: Set[str]
    vuln_type: str
    severity: str
    confidence: float
    sanitizers: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict:
        return {
            'sink': self.sink_name,
            'sink_line': self.sink_line,
            'sink_file': self.sink_file,
            'source': self.source_name,
            'taint_types': list(self.taint_types),
            'vuln_type': self.vuln_type,
            'severity': self.severity,
            'confidence': self.confidence,
            'sanitizers': list(self.sanitizers),
        }


class AbstractInterpreter:
    """
    Worklist-based abstract interpretation over CFG.

    Performs fixed-point iteration with widening for guaranteed termination.
    Uses YAML-driven rules for sources, sinks, and sanitizers.
    """

    MAX_ITERATIONS = 100
    WIDENING_THRESHOLD = 50  # Apply widening after this many iterations

    def __init__(self, rule_engine=None):
        self.rules = rule_engine
        self.findings: List[Finding] = []
        self._source_patterns = {}
        self._sink_patterns = {}
        self._sanitizer_patterns = {}
        if rule_engine:
            self._build_lookup_tables()

    def _build_lookup_tables(self):
        """Pre-build lookup tables from rule engine for fast matching."""
        if not self.rules:
            return

        for name, src in self.rules.sources.items():
            self._source_patterns[name] = src

        for name, sink in self.rules.sinks.items():
            self._sink_patterns[name] = sink

        for name, san in self.rules.sanitizers.items():
            self._sanitizer_patterns[name] = san

    def analyze(self, blocks: List[Any], entry_state: Optional[AbstractState] = None,
                filename: str = "") -> Tuple[Dict[int, AbstractState], List[Finding]]:
        """
        Run abstract interpretation over CFG blocks.

        Args:
            blocks: CFG blocks (CFGBlock or SSACFGBlock)
            entry_state: Initial state at function entry
            filename: Source file path

        Returns:
            (block_id -> final AbstractState, list of findings)
        """
        if not blocks:
            return {}, []

        self.findings = []

        # Build block map
        block_map = {}
        entry_id = None
        for b in blocks:
            bid = b.id if hasattr(b, 'id') else b.block.id
            block_map[bid] = b
            if (hasattr(b, 'is_entry') and b.is_entry) or \
               (hasattr(b, 'block') and b.block.is_entry):
                entry_id = bid

        if entry_id is None and blocks:
            entry_id = blocks[0].id if hasattr(blocks[0], 'id') else blocks[0].block.id

        # Initialize states
        in_states: Dict[int, AbstractState] = {}
        out_states: Dict[int, AbstractState] = {}
        for bid in block_map:
            in_states[bid] = AbstractState.bottom()
            out_states[bid] = AbstractState.bottom()

        if entry_state is None:
            entry_state = AbstractState()
        in_states[entry_id] = entry_state

        # Worklist iteration
        worklist = deque([entry_id])
        visit_count: Dict[int, int] = defaultdict(int)
        iterations = 0

        while worklist and iterations < self.MAX_ITERATIONS:
            bid = worklist.popleft()
            iterations += 1
            visit_count[bid] += 1

            block = block_map[bid]

            # Merge predecessor outputs
            preds = block.predecessors if hasattr(block, 'predecessors') else block.block.predecessors
            if preds and bid != entry_id:
                merged = AbstractState.bottom()
                for pred_id in preds:
                    pred_out = out_states.get(pred_id, AbstractState.bottom())
                    merged = merged.join(pred_out)

                # Apply widening if we've visited this block many times
                if visit_count[bid] > self.WIDENING_THRESHOLD:
                    merged = in_states[bid].widen(merged)

                in_states[bid] = merged
            elif bid == entry_id:
                in_states[bid] = entry_state

            # Process phi nodes (for SSA blocks)
            current_state = in_states[bid].copy()
            if hasattr(block, 'phi_nodes'):
                for phi in block.phi_nodes:
                    self._process_phi(phi, current_state, out_states)

            # Transfer each statement
            stmts = block.statements if hasattr(block, 'statements') else block.block.statements
            for stmt in stmts:
                current_state = self._transfer(stmt, current_state, filename)

            # Check if state changed
            old_out = out_states.get(bid, AbstractState.bottom())
            if current_state != old_out:
                out_states[bid] = current_state
                # Add successors to worklist
                succs = block.successors if hasattr(block, 'successors') else block.block.successors
                for succ_id in succs:
                    if succ_id not in worklist:
                        worklist.append(succ_id)

        return out_states, self.findings

    def _process_phi(self, phi: PhiNode, state: AbstractState,
                      out_states: Dict[int, AbstractState]):
        """Process a phi node by joining taint from all predecessors."""
        merged = TaintInfo()
        for pred_id, src_var in phi.sources.items():
            pred_out = out_states.get(pred_id, AbstractState.bottom())
            pred_info = pred_out.get(str(src_var))
            merged = TaintInfo(
                level=TaintLattice.join(merged.level, pred_info.level),
                taint_types=merged.taint_types | pred_info.taint_types,
                sources=merged.sources | pred_info.sources,
                sanitizers_applied=merged.sanitizers_applied & pred_info.sanitizers_applied
                    if merged.sanitizers_applied else pred_info.sanitizers_applied,
                sanitized_types=merged.sanitized_types & pred_info.sanitized_types
                    if merged.sanitized_types else pred_info.sanitized_types,
            )
        state.set(str(phi.target), merged)
        # Also set under original name for lookups
        state.set(phi.original_name, merged)

    def _transfer(self, stmt: TSNode, state: AbstractState,
                   filename: str) -> AbstractState:
        """Transfer function for a single statement."""
        state = state.copy()

        if stmt.type == 'expression_statement':
            for child in stmt.named_children:
                state = self._transfer(child, state, filename)

        elif stmt.type == 'assignment_expression':
            state = self._handle_assignment(stmt, state, filename)

        elif stmt.type == 'function_call_expression':
            state = self._handle_call(stmt, state, filename)

        elif stmt.type == 'member_call_expression':
            state = self._handle_call(stmt, state, filename)

        elif stmt.type == 'echo_statement':
            self._check_sink('echo', stmt, state, filename)

        elif stmt.type in ('include_expression', 'require_expression',
                           'include_once_expression', 'require_once_expression'):
            self._check_sink(stmt.type.split('_')[0], stmt, state, filename)

        return state

    def _handle_assignment(self, node: TSNode, state: AbstractState,
                            filename: str) -> AbstractState:
        """Handle $var = expr."""
        left = node.child_by_field('left')
        right = node.child_by_field('right')

        if not left or not right:
            return state

        var_name = self._extract_var_name(left)
        if not var_name:
            return state

        # Evaluate RHS taint
        rhs_taint = self._eval_expr_taint(right, state, filename)
        state.set(var_name, rhs_taint)

        return state

    def _handle_call(self, node: TSNode, state: AbstractState,
                      filename: str) -> AbstractState:
        """Handle function/method calls - check for source, sink, sanitizer."""
        func_name = self._get_call_name(node)
        if not func_name:
            return state

        # Check if it's a sink
        self._check_sink(func_name, node, state, filename)

        return state

    def _eval_expr_taint(self, node: TSNode, state: AbstractState,
                          filename: str) -> TaintInfo:
        """Evaluate the taint of an expression."""
        if node is None:
            return TaintInfo(level=TaintLattice.UNTAINTED)

        node_type = node.type

        # Variable reference
        if node_type == 'variable_name':
            var_name = node.text
            existing = state.get(var_name)
            if existing.level > TaintLattice.BOTTOM:
                return existing.copy()
            # Check if it's a source superglobal
            return self._check_source_var(var_name, node)

        # Subscript: $arr[$key]
        if node_type == 'subscript_expression':
            if node.named_children:
                base = node.named_children[0]
                base_taint = self._eval_expr_taint(base, state, filename)
                if base_taint.is_tainted():
                    return base_taint
            # Check full text for source patterns
            text = node.text
            return self._check_source_text(text, node)

        # Function call
        if node_type in ('function_call_expression', 'member_call_expression'):
            func_name = self._get_call_name(node)
            if func_name:
                # Check if sanitizer
                san_result = self._check_sanitizer(func_name, node, state, filename)
                if san_result is not None:
                    return san_result

                # Check if source function
                src_result = self._check_source_func(func_name, node)
                if src_result.is_tainted():
                    return src_result

            # Default: propagate taint from arguments
            args = self._get_call_args(node)
            merged = TaintInfo(level=TaintLattice.UNTAINTED)
            for arg in args:
                arg_taint = self._eval_expr_taint(arg, state, filename)
                if arg_taint.is_tainted():
                    merged = TaintInfo(
                        level=TaintLattice.join(merged.level, arg_taint.level),
                        taint_types=merged.taint_types | arg_taint.taint_types,
                        sources=merged.sources | arg_taint.sources,
                    )
            return merged

        # String concatenation
        if node_type == 'binary_expression':
            left = node.child_by_field('left')
            right = node.child_by_field('right')
            if left and right:
                l_taint = self._eval_expr_taint(left, state, filename)
                r_taint = self._eval_expr_taint(right, state, filename)
                if l_taint.is_tainted() or r_taint.is_tainted():
                    return TaintInfo(
                        level=TaintLattice.join(l_taint.level, r_taint.level),
                        taint_types=l_taint.taint_types | r_taint.taint_types,
                        sources=l_taint.sources | r_taint.sources,
                    )

        # String with interpolation
        if node_type in ('encapsed_string', 'string', 'heredoc'):
            for child in node.named_children:
                child_taint = self._eval_expr_taint(child, state, filename)
                if child_taint.is_tainted():
                    return child_taint

        # Parenthesized expression
        if node_type == 'parenthesized_expression':
            if node.named_children:
                return self._eval_expr_taint(node.named_children[0], state, filename)

        # Cast expression
        if node_type == 'cast_expression':
            cast_type = node.child_by_field('type')
            if cast_type and cast_type.text in ('int', 'integer', 'float', 'double', 'bool', 'boolean'):
                return TaintInfo(level=TaintLattice.UNTAINTED)
            if node.named_children:
                return self._eval_expr_taint(node.named_children[-1], state, filename)

        # Literal values
        if node_type in ('integer', 'float', 'null', 'boolean'):
            return TaintInfo(level=TaintLattice.UNTAINTED)

        # String literal (no interpolation)
        if node_type == 'string' and not node.named_children:
            return TaintInfo(level=TaintLattice.UNTAINTED)

        return TaintInfo(level=TaintLattice.UNTAINTED)

    def _check_source_var(self, var_name: str, node: TSNode) -> TaintInfo:
        """Check if a variable is a taint source."""
        if not self.rules:
            # Fallback: hardcoded superglobals
            if var_name in ('$_GET', '$_POST', '$_REQUEST'):
                return TaintInfo(
                    level=TaintLattice.TAINTED,
                    taint_types={'SQL', 'XSS', 'COMMAND', 'CODE'},
                    sources={var_name},
                )
            return TaintInfo()

        src = self.rules.sources.get(var_name)
        if src:
            level = TaintLattice.TAINTED if src.taint_level == 'HIGH' else \
                    TaintLattice.WEAK if src.taint_level == 'MEDIUM' else \
                    TaintLattice.WEAK
            return TaintInfo(
                level=level,
                taint_types=set(src.taint_types),
                sources={var_name},
            )
        return TaintInfo()

    def _check_source_text(self, text: str, node: TSNode) -> TaintInfo:
        """Check if text contains a source pattern."""
        if not text:
            return TaintInfo()

        if not self.rules:
            for src_name in ('$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES', '$_SERVER'):
                if src_name in text:
                    return TaintInfo(
                        level=TaintLattice.TAINTED,
                        taint_types={'SQL', 'XSS', 'COMMAND', 'CODE'},
                        sources={src_name},
                    )
            return TaintInfo()

        for name, src in self.rules.sources.items():
            if name in text:
                level = TaintLattice.TAINTED if src.taint_level == 'HIGH' else TaintLattice.WEAK
                return TaintInfo(
                    level=level,
                    taint_types=set(src.taint_types),
                    sources={name},
                )
        return TaintInfo()

    def _check_source_func(self, func_name: str, node: TSNode) -> TaintInfo:
        """Check if a function call is a source (e.g., file_get_contents('php://input'))."""
        text = node.text if node else ''
        if 'php://input' in text:
            return TaintInfo(
                level=TaintLattice.TAINTED,
                taint_types={'SQL', 'XSS', 'COMMAND', 'CODE', 'XXE'},
                sources={'php://input'},
            )
        return TaintInfo()

    def _check_sanitizer(self, func_name: str, node: TSNode,
                          state: AbstractState, filename: str) -> Optional[TaintInfo]:
        """Check if a function call is a sanitizer and apply it."""
        if not self.rules:
            return None

        # Look up sanitizer
        san = self.rules.sanitizers.get(func_name)
        if not san:
            # Try matching by pattern
            for name, s in self.rules.sanitizers.items():
                if func_name in name or name in func_name:
                    san = s
                    break

        if not san:
            return None

        # Get argument taint
        args = self._get_call_args(node)
        if not args:
            return None

        arg_taint = self._eval_expr_taint(args[0], state, filename)
        if not arg_taint.is_tainted():
            return TaintInfo(level=TaintLattice.UNTAINTED)

        # Apply sanitizer: remove protected taint types
        protected = set(san.protects_against)
        remaining_types = arg_taint.taint_types - protected

        if not remaining_types:
            return TaintInfo(
                level=TaintLattice.UNTAINTED,
                sanitizers_applied=arg_taint.sanitizers_applied | {func_name},
                sanitized_types=arg_taint.sanitized_types | protected,
            )

        return TaintInfo(
            level=arg_taint.level,
            taint_types=remaining_types,
            sources=arg_taint.sources,
            sanitizers_applied=arg_taint.sanitizers_applied | {func_name},
            sanitized_types=arg_taint.sanitized_types | protected,
        )

    def _check_sink(self, func_name: str, node: TSNode,
                     state: AbstractState, filename: str):
        """Check if a function call is a sink with tainted arguments."""
        if not self.rules:
            return

        sink = self.rules.sinks.get(func_name)
        if not sink:
            return

        # Get arguments
        args = self._get_call_args(node)
        if not args:
            # For echo/print, check named children
            for child in node.named_children:
                child_taint = self._eval_expr_taint(child, state, filename)
                if child_taint.is_tainted():
                    effective = child_taint.effective_types()
                    if effective:
                        self.findings.append(Finding(
                            sink_name=func_name,
                            sink_line=node.line,
                            sink_file=filename,
                            source_name=', '.join(child_taint.sources) or 'unknown',
                            taint_types=effective,
                            vuln_type=sink.vuln_type,
                            severity=sink.severity,
                            confidence=0.85 if child_taint.level == TaintLattice.TAINTED else 0.5,
                            sanitizers=child_taint.sanitizers_applied,
                        ))
            return

        # Check relevant argument positions
        for pos in sink.arg_positions:
            if pos < len(args):
                arg_taint = self._eval_expr_taint(args[pos], state, filename)
                if arg_taint.is_tainted():
                    effective = arg_taint.effective_types()
                    if effective:
                        self.findings.append(Finding(
                            sink_name=func_name,
                            sink_line=node.line,
                            sink_file=filename,
                            source_name=', '.join(arg_taint.sources) or 'unknown',
                            taint_types=effective,
                            vuln_type=sink.vuln_type,
                            severity=sink.severity,
                            confidence=0.9 if arg_taint.level == TaintLattice.TAINTED else 0.5,
                            sanitizers=arg_taint.sanitizers_applied,
                        ))

    # ==================== Helper Methods ====================

    def _extract_var_name(self, node: TSNode) -> Optional[str]:
        """Extract PHP variable name from a node."""
        if node.type == 'variable_name':
            return node.text
        if node.type == 'subscript_expression':
            if node.named_children:
                return self._extract_var_name(node.named_children[0])
        return None

    def _get_call_name(self, node: TSNode) -> Optional[str]:
        """Extract function/method name from a call node."""
        if node.type == 'function_call_expression':
            func = node.child_by_field('function')
            if func:
                return func.text
        elif node.type == 'member_call_expression':
            name = node.child_by_field('name')
            if name:
                return name.text
        return None

    def _get_call_args(self, node: TSNode) -> List[TSNode]:
        """Get argument nodes from a function call."""
        args_node = node.child_by_field('arguments')
        if args_node:
            return [c for c in args_node.named_children if c.type == 'argument']
        return []
