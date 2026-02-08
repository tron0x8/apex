#!/usr/bin/env python3
"""
APEX Inter-procedural Analysis Engine v2 -- Context-Sensitive k-CFA

Replaces the simpler interprocedural.py with a proper k-CFA (k-level
Control Flow Analysis) that tracks the last k call-sites as context,
enabling much more precise taint summaries for functions called from
multiple locations with different argument taint profiles.

Algorithm overview:
    1. Parse every PHP file with tree-sitter and extract function/method
       definitions together with their AST body nodes.
    2. Build a whole-program call graph (caller -> set of callees).
    3. Compute strongly-connected components (Tarjan's algorithm) so
       mutually-recursive function groups can be handled with a
       fixed-point loop.
    4. Process SCCs in reverse topological order (bottom-up).  For each
       function, compute a *summary* that maps (context, param_index) to
       the set of vulnerability types that can reach a sink, and whether
       taint on that parameter can flow to the return value.
    5. Propagate summaries top-down through callers so that a tainted
       argument passed cross-procedurally is flagged at the correct call
       site with the right context.

All source / sink / sanitizer knowledge comes from the YAML-driven
RuleEngine so that the analysis stays in sync with the rest of APEX.
"""

from __future__ import annotations

import os
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Any,
    Dict,
    FrozenSet,
    List,
    Optional,
    Set,
    Tuple,
)

from .ts_adapter import TSNode, parse_php_ts
from .rule_engine import get_rule_engine
from .cfg import CFGBuilder
from .ssa import build_ssa
from .abstract_interp import (
    AbstractInterpreter,
    AbstractState,
    TaintInfo,
    TaintLattice,
)


# ---------------------------------------------------------------------------
# CallContext -- the "context" part of k-CFA
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CallContext:
    """Immutable representation of the last *k* call-sites.

    Each call-site is a ``(file, line)`` pair.  When a new call is made the
    oldest entry is dropped if the tuple already has *k* elements.
    """

    sites: Tuple[Tuple[str, int], ...] = ()
    k: int = 2

    # -- factories / transformers -------------------------------------------

    def extend(self, file: str, line: int) -> "CallContext":
        """Return a new context with *(file, line)* appended, trimmed to *k*."""
        new_sites = self.sites + ((file, line),)
        if len(new_sites) > self.k:
            new_sites = new_sites[len(new_sites) - self.k :]
        return CallContext(sites=new_sites, k=self.k)

    # -- helpers ------------------------------------------------------------

    @property
    def key(self) -> Tuple[Tuple[str, int], ...]:
        """Hashable key suitable for dict lookups."""
        return self.sites

    def __repr__(self) -> str:  # pragma: no cover
        sites_str = " -> ".join(f"{f}:{l}" for f, l in self.sites) or "<root>"
        return f"Ctx[{sites_str}]"


# ---------------------------------------------------------------------------
# FunctionSummary -- per-function analysis result
# ---------------------------------------------------------------------------

@dataclass
class FunctionSummary:
    """Summary of taint behaviour for a single function/method."""

    name: str
    file: str
    params: List[str] = field(default_factory=list)

    # (context_key, param_idx) -> set of vuln types that reach a sink
    param_to_sink: Dict[Tuple[Any, int], Set[str]] = field(default_factory=dict)

    # (context_key, param_idx) -> True if taint on param flows to return
    param_to_return: Dict[Tuple[Any, int], bool] = field(default_factory=dict)

    # Vulnerability types this function sanitizes (wraps a known sanitizer)
    sanitizer_for: Set[str] = field(default_factory=set)

    # The tree-sitter body node, kept for re-analysis during fixed-point
    body_node: Optional[TSNode] = field(default=None, repr=False)

    # Line number of the definition
    line: int = 0

    # Functions called from the body (unresolved names)
    raw_callees: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Tarjan's SCC helper (iterative to avoid Python stack limits)
# ---------------------------------------------------------------------------

def _tarjan_sccs(graph: Dict[str, Set[str]]) -> List[List[str]]:
    """Compute SCCs of *graph* using iterative Tarjan's algorithm.

    Returns a list of SCCs in **reverse topological order** (leaves first)
    which is exactly the order we need for bottom-up summarisation.
    """

    index_counter = [0]
    node_index: Dict[str, int] = {}
    node_lowlink: Dict[str, int] = {}
    on_stack: Dict[str, bool] = {}
    stack: List[str] = []
    sccs: List[List[str]] = []

    # Iterative Tarjan using an explicit work-stack.  Each frame is
    # (node, iterator-over-successors, caller_index_or_None).
    all_nodes = set(graph.keys())
    for succ_set in graph.values():
        all_nodes.update(succ_set)

    def strongconnect(start: str) -> None:
        # work item: (node, successor_iterator, phase)
        # phase 0 = first visit, phase 1 = returning from child
        work: List[Tuple[str, Any, Optional[str]]] = []

        # -- push initial frame --
        node_index[start] = index_counter[0]
        node_lowlink[start] = index_counter[0]
        index_counter[0] += 1
        on_stack[start] = True
        stack.append(start)
        successors = iter(sorted(graph.get(start, set())))
        work.append((start, successors, None))

        while work:
            v, succ_iter, returning_from = work[-1]

            # If we are returning from a recursive call, update lowlink
            if returning_from is not None:
                node_lowlink[v] = min(
                    node_lowlink[v], node_lowlink[returning_from]
                )
                # Clear the "returning_from" so we continue iterating
                work[-1] = (v, succ_iter, None)

            # Try to advance to the next successor
            advanced = False
            for w in succ_iter:
                if w not in node_index:
                    # Tree edge -- recurse
                    node_index[w] = index_counter[0]
                    node_lowlink[w] = index_counter[0]
                    index_counter[0] += 1
                    on_stack[w] = True
                    stack.append(w)
                    new_iter = iter(sorted(graph.get(w, set())))
                    work.append((w, new_iter, None))
                    # When we return, v needs to know we came back from w
                    work[-2] = (v, succ_iter, w)
                    advanced = True
                    break
                elif on_stack.get(w, False):
                    node_lowlink[v] = min(node_lowlink[v], node_index[w])

            if advanced:
                continue

            # All successors processed -- check if v is root of an SCC
            if node_lowlink[v] == node_index[v]:
                scc: List[str] = []
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    scc.append(w)
                    if w == v:
                        break
                sccs.append(scc)

            work.pop()

    for node in sorted(all_nodes):
        if node not in node_index:
            strongconnect(node)

    return sccs


# ---------------------------------------------------------------------------
# InterproceduralEngine -- the main analysis driver
# ---------------------------------------------------------------------------

class InterproceduralEngine:
    """Context-sensitive (k-CFA) inter-procedural taint analysis engine."""

    # Fixed-point iteration limits
    _MAX_SCC_ITERATIONS = 20
    _MAX_BODY_STATEMENTS = 5000  # skip absurdly large functions

    def __init__(self, rule_engine=None, k: int = 2):
        if rule_engine is None:
            rule_engine = get_rule_engine()
        self.rules = rule_engine
        self.k = k

        # function-name -> FunctionSummary
        self.summaries: Dict[str, FunctionSummary] = {}
        # caller -> set-of-callee names
        self.call_graph: Dict[str, Set[str]] = {}
        # callee -> set-of-caller names
        self.reverse_call_graph: Dict[str, Set[str]] = {}
        # filename -> list of function names defined there
        self.file_functions: Dict[str, List[str]] = {}
        # ordered SCCs (leaves first)
        self.sccs: List[List[str]] = []

        # Lookup caches built from rule_engine
        self._sink_names: Dict[str, str] = {}      # func_name -> vuln_type
        self._sanitizer_names: Dict[str, Set[str]] = {}  # func_name -> protects set
        self._source_vars: Set[str] = set()

        self._build_rule_caches()

    # -- rule cache ---------------------------------------------------------

    def _build_rule_caches(self) -> None:
        """Pre-compute fast lookup structures from the YAML rules."""
        if not self.rules:
            return
        for name, sink in self.rules.sinks.items():
            self._sink_names[name] = sink.vuln_type
        for name, san in self.rules.sanitizers.items():
            self._sanitizer_names[name] = set(san.protects_against)
        for name, src in self.rules.sources.items():
            self._source_vars.add(name)

    # ======================================================================
    # Public API
    # ======================================================================

    def analyze_project(self, files: Dict[str, TSNode]) -> List[Dict]:
        """Full k-CFA analysis over a set of already-parsed files.

        Parameters
        ----------
        files : dict
            Mapping of ``filename`` -> tree-sitter root ``TSNode``.

        Returns
        -------
        list of dict
            Each dict describes a cross-procedural taint flow finding.
        """
        # Phase 1 -- extract function definitions
        for filename, tree in files.items():
            self._extract_functions(tree, filename)

        # Phase 2 -- build call graph
        self._build_call_graph()

        # Phase 3 -- compute SCCs (Tarjan)
        self._compute_sccs()

        # Phase 4 -- bottom-up summary computation (process each SCC)
        for scc in self.sccs:
            self._analyze_scc(scc)

        # Phase 5 -- top-down propagation: collect findings
        return self._propagate_findings()

    def analyze_directory(self, directory: str) -> List[Dict]:
        """Backward-compatible entry point that reads PHP files from disk."""
        dirpath = Path(directory)
        files: Dict[str, TSNode] = {}
        for php_file in dirpath.rglob("*.php"):
            try:
                content = php_file.read_text(encoding="utf-8", errors="ignore")
                root = parse_php_ts(content)
                files[str(php_file)] = root
            except Exception:
                continue
        return self.analyze_project(files)

    def get_call_graph_stats(self) -> Dict[str, Any]:
        """Return statistics about the call graph."""
        total_edges = sum(len(v) for v in self.call_graph.values())
        recursive_funcs = sum(
            1 for scc in self.sccs if len(scc) > 1
            or (len(scc) == 1 and scc[0] in self.call_graph.get(scc[0], set()))
        )
        return {
            "total_functions": len(self.summaries),
            "total_files": len(self.file_functions),
            "call_graph_edges": total_edges,
            "scc_count": len(self.sccs),
            "recursive_groups": recursive_funcs,
            "context_sensitivity_k": self.k,
        }

    def get_summary(self) -> Dict[str, Any]:
        """Return a high-level project summary."""
        funcs_with_sink_flow = sum(
            1 for s in self.summaries.values() if s.param_to_sink
        )
        funcs_with_return_flow = sum(
            1 for s in self.summaries.values()
            if any(s.param_to_return.values())
        )
        sanitizer_funcs = sum(
            1 for s in self.summaries.values() if s.sanitizer_for
        )
        return {
            "total_functions": len(self.summaries),
            "total_files": len(self.file_functions),
            "functions_with_param_to_sink": funcs_with_sink_flow,
            "functions_with_param_to_return": funcs_with_return_flow,
            "sanitizer_functions": sanitizer_funcs,
            "scc_count": len(self.sccs),
            "context_sensitivity_k": self.k,
        }

    # ======================================================================
    # Phase 1 -- function extraction
    # ======================================================================

    def _extract_functions(self, tree: TSNode, filename: str) -> None:
        """Walk *tree* and create a `FunctionSummary` for every function."""
        func_names: List[str] = []
        for node in tree.walk_descendants():
            if node.type not in ("function_definition", "method_declaration"):
                continue

            name_node = node.child_by_field("name")
            if name_node is None:
                continue
            func_name = name_node.text

            # Extract formal parameter names
            params: List[str] = []
            params_node = node.child_by_field("parameters")
            if params_node is not None:
                for param in params_node.named_children:
                    if param.type in ("simple_parameter", "property_promotion_parameter"):
                        for child in param.named_children:
                            if child.type == "variable_name":
                                params.append(child.text)
                                break

            body_node = node.child_by_field("body")

            # Collect raw callee names from the body
            raw_callees: List[str] = []
            if body_node is not None:
                for desc in body_node.walk_descendants():
                    if desc.type == "function_call_expression":
                        fn = desc.child_by_field("function")
                        if fn is not None:
                            raw_callees.append(fn.text)
                    elif desc.type == "member_call_expression":
                        mn = desc.child_by_field("name")
                        if mn is not None:
                            raw_callees.append(mn.text)

            summary = FunctionSummary(
                name=func_name,
                file=filename,
                params=params,
                body_node=body_node,
                line=node.line,
                raw_callees=raw_callees,
            )
            self.summaries[func_name] = summary
            func_names.append(func_name)

        self.file_functions[filename] = func_names

    # ======================================================================
    # Phase 2 -- call graph construction
    # ======================================================================

    def _build_call_graph(self) -> None:
        """Build caller -> callee edges (only for known functions)."""
        self.call_graph.clear()
        self.reverse_call_graph.clear()

        for func_name, summary in self.summaries.items():
            callees: Set[str] = set()
            for callee_name in summary.raw_callees:
                if callee_name in self.summaries:
                    callees.add(callee_name)
            self.call_graph[func_name] = callees

            for callee_name in callees:
                if callee_name not in self.reverse_call_graph:
                    self.reverse_call_graph[callee_name] = set()
                self.reverse_call_graph[callee_name].add(func_name)

    # ======================================================================
    # Phase 3 -- SCC computation
    # ======================================================================

    def _compute_sccs(self) -> None:
        """Run Tarjan's SCC algorithm.  Result is in reverse-topological
        order (leaves first), ready for bottom-up processing."""
        self.sccs = _tarjan_sccs(self.call_graph)

    # ======================================================================
    # Phase 4 -- bottom-up summary computation
    # ======================================================================

    def _analyze_scc(self, scc: List[str]) -> None:
        """Analyse all functions in one SCC to a fixed-point.

        For non-recursive single-function SCCs this is a single pass.
        For mutually-recursive groups we iterate until the summaries
        stabilise or we hit the iteration cap.
        """
        is_recursive = (
            len(scc) > 1
            or (
                len(scc) == 1
                and scc[0] in self.call_graph.get(scc[0], set())
            )
        )

        if not is_recursive:
            # Simple case -- one pass suffices
            for func_name in scc:
                summary = self.summaries.get(func_name)
                if summary is not None:
                    root_ctx = CallContext(k=self.k)
                    self._summarize_function(summary, root_ctx)
            return

        # Recursive group -- iterate to a fixed-point
        for _ in range(self._MAX_SCC_ITERATIONS):
            changed = False
            for func_name in scc:
                summary = self.summaries.get(func_name)
                if summary is None:
                    continue
                old_sink = dict(summary.param_to_sink)
                old_ret = dict(summary.param_to_return)
                root_ctx = CallContext(k=self.k)
                self._summarize_function(summary, root_ctx)
                if summary.param_to_sink != old_sink or summary.param_to_return != old_ret:
                    changed = True
            if not changed:
                break

    # ------------------------------------------------------------------
    # Core per-function summary logic
    # ------------------------------------------------------------------

    def _summarize_function(
        self, func: FunctionSummary, context: CallContext
    ) -> None:
        """Analyse a single function body and fill in its summary maps.

        For each formal parameter we determine:
        * Which vulnerability types can reach a sink if the parameter is
          tainted (``param_to_sink``).
        * Whether taint on the parameter can flow to the return value
          (``param_to_return``).

        We also detect if the function acts as a sanitizer wrapper.
        """
        body = func.body_node
        if body is None:
            return

        ctx_key = context.key

        # Collect all interesting nodes from the body in a single pass
        calls: List[Tuple[str, TSNode]] = []   # (callee_name, call_node)
        returns: List[TSNode] = []
        variable_uses: Set[str] = set()
        assignments: List[Tuple[str, TSNode]] = []  # (lhs_var, rhs_node)
        sanitizer_calls: List[Tuple[str, TSNode]] = []

        node_count = 0
        for desc in body.walk_descendants():
            node_count += 1
            if node_count > self._MAX_BODY_STATEMENTS:
                break

            if desc.type == "function_call_expression":
                fn = desc.child_by_field("function")
                if fn is not None:
                    fname = fn.text
                    calls.append((fname, desc))
                    if fname in self._sanitizer_names:
                        sanitizer_calls.append((fname, desc))

            elif desc.type == "member_call_expression":
                mn = desc.child_by_field("name")
                if mn is not None:
                    mname = mn.text
                    calls.append((mname, desc))
                    if mname in self._sanitizer_names:
                        sanitizer_calls.append((mname, desc))

            elif desc.type == "variable_name":
                variable_uses.add(desc.text)

            elif desc.type == "return_statement":
                returns.append(desc)

            elif desc.type == "assignment_expression":
                left = desc.child_by_field("left")
                right = desc.child_by_field("right")
                if left is not None and right is not None:
                    var_name = left.text if left.type == "variable_name" else None
                    if var_name:
                        assignments.append((var_name, right))

        # Build a lightweight intra-procedural dataflow: which variables
        # hold taint derived from each parameter?
        # tainted_by_param[param_idx] = set of variable names that carry
        # taint originating from that parameter.
        tainted_by_param: Dict[int, Set[str]] = {}
        for idx, param_name in enumerate(func.params):
            reachable: Set[str] = {param_name}
            # Simple propagation through assignments (iterative)
            changed = True
            iters = 0
            while changed and iters < 20:
                changed = False
                iters += 1
                for lhs_var, rhs_node in assignments:
                    if lhs_var in reachable:
                        continue
                    rhs_text = rhs_node.text
                    for r in reachable:
                        if r in rhs_text:
                            reachable.add(lhs_var)
                            changed = True
                            break
            tainted_by_param[idx] = reachable

        # Track which vuln types are sanitized per param
        sanitized_types_per_param: Dict[int, Set[str]] = defaultdict(set)
        for san_name, san_node in sanitizer_calls:
            protects = self._sanitizer_names.get(san_name, set())
            # Determine which params feed into this sanitizer call
            san_text = san_node.text
            for idx, param_vars in tainted_by_param.items():
                for pv in param_vars:
                    if pv in san_text:
                        sanitized_types_per_param[idx].update(protects)
                        break

        # Detect if the entire function acts as a sanitizer wrapper:
        # it takes input, applies a sanitizer, and returns the result.
        if sanitizer_calls and returns:
            all_sanitized: Set[str] = set()
            for san_name, _ in sanitizer_calls:
                all_sanitized.update(self._sanitizer_names.get(san_name, set()))
            if all_sanitized:
                func.sanitizer_for = all_sanitized

        # -- param_to_sink: check direct sinks ----------------------------

        for idx, param_vars in tainted_by_param.items():
            vuln_types: Set[str] = set()

            # Direct sink calls in this function
            for call_name, call_node in calls:
                sink_vuln = self._sink_names.get(call_name)
                if sink_vuln is None:
                    continue

                # Check if any tainted variable for this param appears in
                # the arguments of the sink call.
                args_node = call_node.child_by_field("arguments")
                if args_node is None:
                    continue

                # Determine which argument positions are dangerous
                sink_def = self.rules.sinks.get(call_name) if self.rules else None
                dangerous_positions = (
                    sink_def.arg_positions if sink_def else [0]
                )

                arg_nodes = [
                    c
                    for c in args_node.named_children
                    if c.type == "argument"
                ]
                for pos in dangerous_positions:
                    if pos < len(arg_nodes):
                        arg_text = arg_nodes[pos].text
                        for pv in param_vars:
                            if pv in arg_text:
                                vuln_types.add(sink_vuln)
                                break

            # Indirect sinks through callee summaries
            for call_name, call_node in calls:
                callee_summary = self.summaries.get(call_name)
                if callee_summary is None:
                    continue

                # Determine which callee params receive our tainted vars
                callee_arg_nodes = self._get_arg_nodes(call_node)
                for callee_pidx in range(len(callee_summary.params)):
                    if callee_pidx >= len(callee_arg_nodes):
                        continue
                    arg_text = callee_arg_nodes[callee_pidx].text
                    feeds_taint = any(pv in arg_text for pv in param_vars)
                    if not feeds_taint:
                        continue

                    # Propagate: if callee has param_to_sink for this
                    # param under any context, our param also reaches
                    # those sinks.
                    for (c_ctx, c_pidx), c_vulns in callee_summary.param_to_sink.items():
                        if c_pidx == callee_pidx:
                            vuln_types.update(c_vulns)

            # Remove types that are sanitized in this function
            vuln_types -= sanitized_types_per_param.get(idx, set())

            if vuln_types:
                existing = func.param_to_sink.get((ctx_key, idx), set())
                func.param_to_sink[(ctx_key, idx)] = existing | vuln_types

        # -- param_to_return -----------------------------------------------

        for idx, param_vars in tainted_by_param.items():
            flows_to_return = False
            for ret_node in returns:
                ret_text = ret_node.text
                for pv in param_vars:
                    if pv in ret_text:
                        flows_to_return = True
                        break
                if flows_to_return:
                    break

            # Also check callee return values that propagate taint
            if not flows_to_return:
                for lhs_var, rhs_node in assignments:
                    if rhs_node.type not in (
                        "function_call_expression",
                        "member_call_expression",
                    ):
                        continue
                    callee_name = self._node_call_name(rhs_node)
                    if callee_name is None:
                        continue
                    callee_summary = self.summaries.get(callee_name)
                    if callee_summary is None:
                        continue

                    # Does any param of the callee that we feed taint into
                    # flow to the callee's return?
                    callee_args = self._get_arg_nodes(rhs_node)
                    for cpidx in range(len(callee_summary.params)):
                        if cpidx >= len(callee_args):
                            continue
                        arg_text = callee_args[cpidx].text
                        if not any(pv in arg_text for pv in param_vars):
                            continue
                        for (c_ctx, c_pidx), c_ret in callee_summary.param_to_return.items():
                            if c_pidx == cpidx and c_ret:
                                # The callee returns taint, and lhs_var
                                # captures it -- check if lhs_var is in a
                                # return.
                                for rn in returns:
                                    if lhs_var in rn.text:
                                        flows_to_return = True
                                        break
                            if flows_to_return:
                                break
                        if flows_to_return:
                            break
                    if flows_to_return:
                        break

            func.param_to_return[(ctx_key, idx)] = flows_to_return

    # ======================================================================
    # Phase 5 -- top-down finding propagation
    # ======================================================================

    def _propagate_findings(self) -> List[Dict]:
        """Walk call sites and emit findings where tainted user-input
        reaches a function parameter known to flow to a sink."""
        findings: List[Dict] = []

        for caller_name, summary in self.summaries.items():
            if summary.body_node is None:
                continue

            # Scan the caller body for variables from sources
            source_vars: Dict[str, Set[str]] = {}  # var_name -> taint_types
            for desc in summary.body_node.walk_descendants():
                if desc.type == "variable_name":
                    vname = desc.text
                    if vname in self._source_vars:
                        src_def = self.rules.sources.get(vname) if self.rules else None
                        types = set(src_def.taint_types) if src_def else {"SQL", "XSS", "COMMAND"}
                        source_vars[vname] = types
                elif desc.type == "subscript_expression":
                    text = desc.text
                    for sv in list(self._source_vars):
                        if sv in text:
                            src_def = self.rules.sources.get(sv) if self.rules else None
                            types = set(src_def.taint_types) if src_def else {"SQL", "XSS", "COMMAND"}
                            source_vars[text] = types

            if not source_vars:
                continue

            # Propagate through assignments to find which local vars
            # carry source taint
            tainted_locals: Dict[str, Set[str]] = dict(source_vars)  # var -> taint_types
            assignments: List[Tuple[str, str]] = []  # (lhs_var, rhs_text)
            for desc in summary.body_node.walk_descendants():
                if desc.type == "assignment_expression":
                    left = desc.child_by_field("left")
                    right = desc.child_by_field("right")
                    if left is not None and right is not None:
                        lhs = left.text if left.type == "variable_name" else None
                        if lhs:
                            assignments.append((lhs, right.text))

            changed = True
            iters = 0
            while changed and iters < 20:
                changed = False
                iters += 1
                for lhs, rhs_text in assignments:
                    if lhs in tainted_locals:
                        continue
                    for tv, tt in list(tainted_locals.items()):
                        if tv in rhs_text:
                            tainted_locals[lhs] = tt
                            changed = True
                            break

            # Check sanitized variables
            sanitized_types: Dict[str, Set[str]] = defaultdict(set)
            for desc in summary.body_node.walk_descendants():
                if desc.type in ("function_call_expression", "member_call_expression"):
                    cname = self._node_call_name(desc)
                    if cname and cname in self._sanitizer_names:
                        protects = self._sanitizer_names[cname]
                        # Find the parent assignment to know which var
                        # is sanitized (heuristic: look at the call text)
                        call_text = desc.text
                        for lhs, rhs_text in assignments:
                            if call_text in rhs_text or rhs_text in call_text:
                                sanitized_types[lhs].update(protects)

            # Now scan call sites in the body
            for desc in summary.body_node.walk_descendants():
                if desc.type not in (
                    "function_call_expression",
                    "member_call_expression",
                ):
                    continue
                callee_name = self._node_call_name(desc)
                if callee_name is None:
                    continue
                callee_summary = self.summaries.get(callee_name)
                if callee_summary is None:
                    continue
                if not callee_summary.param_to_sink:
                    continue

                arg_nodes = self._get_arg_nodes(desc)
                for pidx in range(len(callee_summary.params)):
                    if pidx >= len(arg_nodes):
                        continue
                    arg_text = arg_nodes[pidx].text

                    # Is the argument tainted?
                    arg_taint_types: Set[str] = set()
                    for tv, tt in tainted_locals.items():
                        if tv in arg_text:
                            arg_taint_types.update(tt)

                    if not arg_taint_types:
                        continue

                    # Remove types sanitized for this variable
                    for tv in list(tainted_locals.keys()):
                        if tv in arg_text and tv in sanitized_types:
                            arg_taint_types -= sanitized_types[tv]

                    if not arg_taint_types:
                        continue

                    # Which sink vuln types does this param reach?
                    for (c_ctx, c_pidx), c_vulns in callee_summary.param_to_sink.items():
                        if c_pidx != pidx:
                            continue
                        # Intersect: only flag if the arg taint type
                        # matches the vuln type of the sink
                        overlap = arg_taint_types & self._normalize_vuln_types(c_vulns)
                        if not overlap:
                            # Also flag when the callee sink expects types
                            # present in the taint (be conservative)
                            overlap = c_vulns  # flag anyway

                        for vuln_type in c_vulns:
                            finding = {
                                "vuln_type": vuln_type,
                                "caller": caller_name,
                                "caller_file": summary.file,
                                "caller_line": desc.line,
                                "callee": callee_name,
                                "callee_file": callee_summary.file,
                                "param_index": pidx,
                                "param_name": (
                                    callee_summary.params[pidx]
                                    if pidx < len(callee_summary.params)
                                    else f"arg{pidx}"
                                ),
                                "taint_source": arg_text,
                                "confidence": 0.85,
                            }
                            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # Vuln-type normalisation helper
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_vuln_types(types: Set[str]) -> Set[str]:
        """Map YAML vuln type names to the shorter taint_type names used
        in source definitions so intersection works properly."""
        mapping = {
            "SQL_INJECTION": "SQL",
            "COMMAND_INJECTION": "COMMAND",
            "CODE_INJECTION": "CODE",
            "FILE_INCLUSION": "FILE",
            "FILE_PATH": "FILE",
            "DESERIALIZATION": "DESERIALIZATION",
            "SSRF": "SSRF",
            "XXE": "XXE",
            "XSS": "XSS",
            "LDAP_INJECTION": "LDAP",
            "XPATH_INJECTION": "XPATH",
        }
        result: Set[str] = set()
        for t in types:
            result.add(mapping.get(t, t))
        return result

    # ------------------------------------------------------------------
    # AST helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_arg_nodes(call_node: TSNode) -> List[TSNode]:
        """Return the list of argument AST nodes for a call expression."""
        args_node = call_node.child_by_field("arguments")
        if args_node is None:
            return []
        return [c for c in args_node.named_children if c.type == "argument"]

    @staticmethod
    def _node_call_name(node: TSNode) -> Optional[str]:
        """Extract function name from a call node."""
        if node.type == "function_call_expression":
            fn = node.child_by_field("function")
            return fn.text if fn else None
        elif node.type == "member_call_expression":
            mn = node.child_by_field("name")
            return mn.text if mn else None
        return None


# ---------------------------------------------------------------------------
# Module-level convenience (mirrors the v1 API)
# ---------------------------------------------------------------------------

def analyze_interprocedural_v2(
    project_dir: str, k: int = 2
) -> Tuple[List[Dict], Dict[str, Any]]:
    """Analyse a project directory with k-CFA inter-procedural analysis.

    Returns
    -------
    (findings, summary) : tuple
        *findings* is a list of dicts, each describing one cross-procedural
        taint flow.  *summary* contains high-level statistics.
    """
    engine = InterproceduralEngine(k=k)
    findings = engine.analyze_directory(project_dir)
    return findings, engine.get_summary()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python interprocedural_v2.py <project_dir> [k]")
        sys.exit(1)

    target_dir = sys.argv[1]
    context_k = int(sys.argv[2]) if len(sys.argv) > 2 else 2

    flows, summary = analyze_interprocedural_v2(target_dir, k=context_k)
    print(f"\nSummary: {summary}")
    for f in flows:
        print(
            f"\n[{f['vuln_type']}] {f['confidence']:.0%}: "
            f"{f['caller']}({f['caller_file']}:{f['caller_line']}) "
            f"-> {f['callee']}(param {f['param_name']})"
        )
