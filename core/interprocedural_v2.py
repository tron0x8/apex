#!/usr/bin/env python3
# apex/core - tron (@tron0x8)

from __future__ import annotations

import os
import re
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

try:
    from .cross_file_analyzer import NamespaceResolver
except ImportError:
    NamespaceResolver = None

_USE_RE = re.compile(r'^\s*use\s+([\w\\]+)(?:\s+as\s+(\w+))?\s*;', re.MULTILINE)


@dataclass(frozen=True)
class CallContext:

    sites: Tuple[Tuple[str, int], ...] = ()
    k: int = 2


    def extend(self, file: str, line: int) -> "CallContext":
        new_sites = self.sites + ((file, line),)
        if len(new_sites) > self.k:
            new_sites = new_sites[len(new_sites) - self.k :]
        return CallContext(sites=new_sites, k=self.k)


    @property
    def key(self) -> Tuple[Tuple[str, int], ...]:
        return self.sites

    def __repr__(self) -> str:  # pragma: no cover
        sites_str = " -> ".join(f"{f}:{l}" for f, l in self.sites) or "<root>"
        return f"Ctx[{sites_str}]"


@dataclass
class ClassInfo:
    name: str
    file: str
    line: int = 0
    parent_class: Optional[str] = None
    interfaces: List[str] = field(default_factory=list)
    methods: Dict[str, str] = field(default_factory=dict)
    properties: List[str] = field(default_factory=list)
    constructor_params: List[str] = field(default_factory=list)


@dataclass
class FunctionSummary:

    name: str
    file: str
    params: List[str] = field(default_factory=list)

    param_to_sink: Dict[Tuple[Any, int], Set[str]] = field(default_factory=dict)

    param_to_return: Dict[Tuple[Any, int], bool] = field(default_factory=dict)

    sanitizer_for: Set[str] = field(default_factory=set)

    body_node: Optional[TSNode] = field(default=None, repr=False)

    line: int = 0

    raw_callees: List[str] = field(default_factory=list)

    owning_class: Optional[str] = None
    param_types: Dict[str, str] = field(default_factory=dict)

    raw_method_calls: List[Tuple[str, str]] = field(default_factory=list)
    local_var_classes: Dict[str, str] = field(default_factory=dict)


def _tarjan_sccs(graph: Dict[str, Set[str]]) -> List[List[str]]:
    # iterative tarjan - recursive version blows the stack on deep call graphs
    index_counter = [0]
    node_index: Dict[str, int] = {}
    node_lowlink: Dict[str, int] = {}
    on_stack: Dict[str, bool] = {}
    stack: List[str] = []
    sccs: List[List[str]] = []

    all_nodes = set(graph.keys())
    for succ_set in graph.values():
        all_nodes.update(succ_set)

    def strongconnect(start: str) -> None:
        work: List[Tuple[str, Any, Optional[str]]] = []

        node_index[start] = index_counter[0]
        node_lowlink[start] = index_counter[0]
        index_counter[0] += 1
        on_stack[start] = True
        stack.append(start)
        successors = iter(sorted(graph.get(start, set())))
        work.append((start, successors, None))

        while work:
            v, succ_iter, returning_from = work[-1]

            if returning_from is not None:
                node_lowlink[v] = min(
                    node_lowlink[v], node_lowlink[returning_from]
                )
                work[-1] = (v, succ_iter, None)

            advanced = False
            for w in succ_iter:
                if w not in node_index:
                    node_index[w] = index_counter[0]
                    node_lowlink[w] = index_counter[0]
                    index_counter[0] += 1
                    on_stack[w] = True
                    stack.append(w)
                    new_iter = iter(sorted(graph.get(w, set())))
                    work.append((w, new_iter, None))
                    work[-2] = (v, succ_iter, w)
                    advanced = True
                    break
                elif on_stack.get(w, False):
                    node_lowlink[v] = min(node_lowlink[v], node_index[w])

            if advanced:
                continue

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


class InterproceduralEngine:
    # k-CFA: k=2 call-site sensitivity, enough for most php codebases
    _MAX_SCC_ITERATIONS = 20
    _MAX_BODY_STATEMENTS = 5000

    def __init__(self, rule_engine=None, k: int = 2):
        if rule_engine is None:
            rule_engine = get_rule_engine()
        self.rules = rule_engine
        self.k = k

        self.summaries: Dict[str, FunctionSummary] = {}
        self.call_graph: Dict[str, Set[str]] = {}
        self.reverse_call_graph: Dict[str, Set[str]] = {}
        self.file_functions: Dict[str, List[str]] = {}
        self.sccs: List[List[str]] = []
        self.class_index: Dict[str, ClassInfo] = {}
        self.var_class_map: Dict[str, str] = {}
        self.namespace_resolver = None
        self.file_use_aliases: Dict[str, Dict[str, str]] = {}
        self.namespace_class_map: Dict[str, str] = {}

        self._sink_names: Dict[str, str] = {}
        self._sanitizer_names: Dict[str, Set[str]] = {}
        self._source_vars: Set[str] = set()

        self._build_rule_caches()


    def _build_rule_caches(self) -> None:
        if not self.rules:
            return
        for name, sink in self.rules.sinks.items():
            self._sink_names[name] = sink.vuln_type
        for name, san in self.rules.sanitizers.items():
            self._sanitizer_names[name] = set(san.protects_against)
        for name, src in self.rules.sources.items():
            self._source_vars.add(name)


    def analyze_project(self, files: Dict[str, TSNode]) -> List[Dict]:
        for filename, tree in files.items():
            self._extract_functions(tree, filename)

        self._build_call_graph()

        self._compute_sccs()

        for scc in self.sccs:
            self._analyze_scc(scc)

        return self._propagate_findings()

    def analyze_directory(self, directory: str) -> List[Dict]:
        dirpath = Path(directory)
        if NamespaceResolver is not None:
            self.namespace_resolver = NamespaceResolver(str(dirpath))
        files: Dict[str, TSNode] = {}
        php_files: List[str] = []
        for php_file in dirpath.rglob("*.php"):
            try:
                content = php_file.read_text(encoding="utf-8", errors="ignore")
                root = parse_php_ts(content)
                files[str(php_file)] = root
                php_files.append(str(php_file))
            except Exception:
                continue
        if self.namespace_resolver and php_files:
            self.namespace_class_map = self.namespace_resolver.build_namespace_map(php_files)
        return self.analyze_project(files)

    def get_call_graph_stats(self) -> Dict[str, Any]:
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


    def _extract_class(self, node: TSNode, filename: str) -> Optional[str]:
        name_node = node.child_by_field("name")
        if name_node is None:
            return None
        class_name = name_node.text

        parent_class = None
        interfaces = []
        for child in node.named_children:
            if child.type == "base_clause":
                for nc in child.named_children:
                    if nc.type in ("name", "qualified_name"):
                        parent_class = nc.text
                        break
            elif child.type == "class_interface_clause":
                for nc in child.named_children:
                    if nc.type in ("name", "qualified_name"):
                        interfaces.append(nc.text)

        methods = {}
        properties = []
        constructor_params = []
        body = node.child_by_field("body")
        if body:
            for member in body.walk_descendants():
                if member.type == "method_declaration":
                    mname_node = member.child_by_field("name")
                    if mname_node:
                        mname = mname_node.text
                        qualified = f"{class_name}::{mname}"
                        methods[mname] = qualified
                        if mname == "__construct":
                            pnode = member.child_by_field("parameters")
                            if pnode:
                                for p in pnode.named_children:
                                    for c in p.named_children:
                                        if c.type == "variable_name":
                                            constructor_params.append(c.text)
                elif member.type == "property_declaration":
                    for pd in member.walk_descendants():
                        if pd.type == "variable_name" and pd.text.startswith("$"):
                            properties.append(pd.text)
                            break

        info = ClassInfo(
            name=class_name, file=filename, line=node.line,
            parent_class=parent_class, interfaces=interfaces,
            methods=methods, properties=properties,
            constructor_params=constructor_params,
        )
        self.class_index[class_name] = info
        return class_name

    def _find_owning_class(self, method_node: TSNode, filename: str) -> Optional[str]:
        for cls_name, cls_info in self.class_index.items():
            if cls_info.file == filename and method_node.line >= cls_info.line:
                name_node = method_node.child_by_field("name")
                if name_node and name_node.text in cls_info.methods:
                    return cls_name
        return None

    def _extract_functions(self, tree: TSNode, filename: str) -> None:
        func_names: List[str] = []

        file_text = tree.text if hasattr(tree, 'text') else ''
        if file_text:
            use_aliases: Dict[str, str] = {}
            for m in _USE_RE.finditer(file_text):
                fqcn = m.group(1)
                alias = m.group(2) or fqcn.rsplit("\\", 1)[-1]
                use_aliases[alias] = fqcn
            if use_aliases:
                self.file_use_aliases[filename] = use_aliases

        for node in tree.walk_descendants():
            if node.type == "class_declaration":
                self._extract_class(node, filename)
                continue
            if node.type not in ("function_definition", "method_declaration"):
                continue

            name_node = node.child_by_field("name")
            if name_node is None:
                continue
            func_name = name_node.text

            owning_class = None
            if node.type == "method_declaration":
                owning_class = self._find_owning_class(node, filename)

            params: List[str] = []
            param_types: Dict[str, str] = {}
            params_node = node.child_by_field("parameters")
            if params_node is not None:
                for param in params_node.named_children:
                    if param.type in ("simple_parameter", "property_promotion_parameter"):
                        var_name = None
                        type_hint = None
                        for child in param.named_children:
                            if child.type == "variable_name":
                                var_name = child.text
                            elif child.type in ("primitive_type", "named_type",
                                                "optional_type", "nullable_type"):
                                type_hint = child.text.lower().lstrip("?")
                        if var_name:
                            params.append(var_name)
                            if type_hint:
                                param_types[var_name] = type_hint

            body_node = node.child_by_field("body")

            raw_callees: List[str] = []
            raw_method_calls: List[Tuple[str, str]] = []
            local_var_classes: Dict[str, str] = {}
            if body_node is not None:
                for desc in body_node.walk_descendants():
                    if desc.type == "function_call_expression":
                        fn = desc.child_by_field("function")
                        if fn is not None:
                            raw_callees.append(fn.text)
                    elif desc.type == "member_call_expression":
                        mn = desc.child_by_field("name")
                        obj = desc.child_by_field("object")
                        if mn is not None:
                            raw_callees.append(mn.text)
                            if obj is not None and obj.type == "variable_name":
                                raw_method_calls.append((obj.text, mn.text))
                    elif desc.type == "assignment_expression":
                        left = desc.child_by_field("left")
                        right = desc.child_by_field("right")
                        if left and right and left.type == "variable_name":
                            if right.type == "object_creation_expression":
                                for child in right.named_children:
                                    if child.type in ("name", "qualified_name"):
                                        cls_text = child.text
                                        aliases = self.file_use_aliases.get(filename, {})
                                        resolved = aliases.get(cls_text, cls_text)
                                        local_var_classes[left.text] = resolved.rsplit("\\", 1)[-1]
                                        break

            qualified_name = f"{owning_class}::{func_name}" if owning_class else func_name
            summary = FunctionSummary(
                name=qualified_name,
                file=filename,
                params=params,
                body_node=body_node,
                line=node.line,
                raw_callees=raw_callees,
                owning_class=owning_class,
                param_types=param_types,
                raw_method_calls=raw_method_calls,
                local_var_classes=local_var_classes,
            )
            self.summaries[qualified_name] = summary
            if qualified_name != func_name:
                self.summaries.setdefault(func_name, summary)
            func_names.append(qualified_name)

        self.file_functions[filename] = func_names


    def _build_call_graph(self) -> None:
        self.call_graph.clear()
        self.reverse_call_graph.clear()

        for func_name, summary in self.summaries.items():
            callees: Set[str] = set()
            for callee_name in summary.raw_callees:
                if callee_name in self.summaries:
                    callees.add(callee_name)
                if summary.owning_class:
                    qualified = f"{summary.owning_class}::{callee_name}"
                    if qualified in self.summaries:
                        callees.add(qualified)
                for cls_info in self.class_index.values():
                    if callee_name in cls_info.methods:
                        qname = cls_info.methods[callee_name]
                        if qname in self.summaries:
                            callees.add(qname)
                            break

            for obj_var, method_name in summary.raw_method_calls:
                cls_name = summary.local_var_classes.get(obj_var)
                if not cls_name:
                    continue
                qualified = f"{cls_name}::{method_name}"
                if qualified in self.summaries:
                    callees.add(qualified)
                elif cls_name in self.class_index:
                    cls_info = self.class_index[cls_name]
                    if method_name in cls_info.methods:
                        qname = cls_info.methods[method_name]
                        if qname in self.summaries:
                            callees.add(qname)
                elif self.namespace_class_map:
                    aliases = self.file_use_aliases.get(summary.file, {})
                    for alias, fqcn in aliases.items():
                        simple = fqcn.rsplit("\\", 1)[-1]
                        if simple == cls_name and simple in self.class_index:
                            ci = self.class_index[simple]
                            if method_name in ci.methods:
                                qname = ci.methods[method_name]
                                if qname in self.summaries:
                                    callees.add(qname)
                                    break

            self.call_graph[func_name] = callees

            for callee_name in callees:
                if callee_name not in self.reverse_call_graph:
                    self.reverse_call_graph[callee_name] = set()
                self.reverse_call_graph[callee_name].add(func_name)


    def _compute_sccs(self) -> None:
        self.sccs = _tarjan_sccs(self.call_graph)


    def _analyze_scc(self, scc: List[str]) -> None:
        is_recursive = (
            len(scc) > 1
            or (
                len(scc) == 1
                and scc[0] in self.call_graph.get(scc[0], set())
            )
        )

        if not is_recursive:
            for func_name in scc:
                summary = self.summaries.get(func_name)
                if summary is not None:
                    root_ctx = CallContext(k=self.k)
                    self._summarize_function(summary, root_ctx)
            return

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


    def _summarize_function(
        self, func: FunctionSummary, context: CallContext
    ) -> None:
        body = func.body_node
        if body is None:
            return

        ctx_key = context.key

        calls: List[Tuple[str, TSNode]] = []
        returns: List[TSNode] = []
        variable_uses: Set[str] = set()
        assignments: List[Tuple[str, TSNode]] = []
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

        tainted_by_param: Dict[int, Set[str]] = {}
        for idx, param_name in enumerate(func.params):
            reachable: Set[str] = {param_name}
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
                        if self._var_in_text(r, rhs_text):
                            reachable.add(lhs_var)
                            changed = True
                            break
            tainted_by_param[idx] = reachable

        sanitized_types_per_param: Dict[int, Set[str]] = defaultdict(set)
        for san_name, san_node in sanitizer_calls:
            protects = self._sanitizer_names.get(san_name, set())
            san_text = san_node.text
            for idx, param_vars in tainted_by_param.items():
                for pv in param_vars:
                    if self._var_in_text(pv, san_text):
                        sanitized_types_per_param[idx].update(protects)
                        break

        if sanitizer_calls and returns:
            all_sanitized: Set[str] = set()
            for san_name, _ in sanitizer_calls:
                all_sanitized.update(self._sanitizer_names.get(san_name, set()))
            if all_sanitized:
                func.sanitizer_for = all_sanitized


        for idx, param_vars in tainted_by_param.items():
            vuln_types: Set[str] = set()

            for call_name, call_node in calls:
                sink_vuln = self._sink_names.get(call_name)
                if sink_vuln is None:
                    continue

                args_node = call_node.child_by_field("arguments")
                if args_node is None:
                    continue

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
                            if self._var_in_text(pv, arg_text):
                                vuln_types.add(sink_vuln)
                                break

            for call_name, call_node in calls:
                callee_summary = self.summaries.get(call_name)
                if callee_summary is None:
                    continue

                callee_arg_nodes = self._get_arg_nodes(call_node)
                for callee_pidx in range(len(callee_summary.params)):
                    if callee_pidx >= len(callee_arg_nodes):
                        continue
                    arg_text = callee_arg_nodes[callee_pidx].text
                    feeds_taint = any(self._var_in_text(pv, arg_text) for pv in param_vars)
                    if not feeds_taint:
                        continue

                    for (c_ctx, c_pidx), c_vulns in callee_summary.param_to_sink.items():
                        if c_pidx == callee_pidx:
                            vuln_types.update(c_vulns)

            vuln_types -= sanitized_types_per_param.get(idx, set())

            if vuln_types:
                existing = func.param_to_sink.get((ctx_key, idx), set())
                func.param_to_sink[(ctx_key, idx)] = existing | vuln_types


        for idx, param_vars in tainted_by_param.items():
            flows_to_return = False
            for ret_node in returns:
                ret_text = ret_node.text
                for pv in param_vars:
                    if self._var_in_text(pv, ret_text):
                        flows_to_return = True
                        break
                if flows_to_return:
                    break

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

                    callee_args = self._get_arg_nodes(rhs_node)
                    for cpidx in range(len(callee_summary.params)):
                        if cpidx >= len(callee_args):
                            continue
                        arg_text = callee_args[cpidx].text
                        if not any(self._var_in_text(pv, arg_text) for pv in param_vars):
                            continue
                        for (c_ctx, c_pidx), c_ret in callee_summary.param_to_return.items():
                            if c_pidx == cpidx and c_ret:
                                for rn in returns:
                                    if self._var_in_text(lhs_var, rn.text):
                                        flows_to_return = True
                                        break
                            if flows_to_return:
                                break
                        if flows_to_return:
                            break
                    if flows_to_return:
                        break

            func.param_to_return[(ctx_key, idx)] = flows_to_return


    def _propagate_findings(self) -> List[Dict]:
        findings: List[Dict] = []

        for caller_name, summary in self.summaries.items():
            if summary.body_node is None:
                continue

            source_vars: Dict[str, Set[str]] = {}
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

            tainted_locals: Dict[str, Set[str]] = dict(source_vars)
            assignments: List[Tuple[str, str]] = []
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
                        if self._var_in_text(tv, rhs_text):
                            tainted_locals[lhs] = tt
                            changed = True
                            break

            sanitized_types: Dict[str, Set[str]] = defaultdict(set)
            for desc in summary.body_node.walk_descendants():
                if desc.type in ("function_call_expression", "member_call_expression"):
                    cname = self._node_call_name(desc)
                    if cname and cname in self._sanitizer_names:
                        protects = self._sanitizer_names[cname]
                        call_text = desc.text
                        for lhs, rhs_text in assignments:
                            if call_text in rhs_text or rhs_text in call_text:
                                sanitized_types[lhs].update(protects)

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

                    arg_taint_types: Set[str] = set()
                    for tv, tt in tainted_locals.items():
                        if self._var_in_text(tv, arg_text):
                            arg_taint_types.update(tt)

                    if not arg_taint_types:
                        continue

                    for tv in list(tainted_locals.keys()):
                        if self._var_in_text(tv, arg_text) and tv in sanitized_types:
                            arg_taint_types -= sanitized_types[tv]

                    if not arg_taint_types:
                        continue

                    for (c_ctx, c_pidx), c_vulns in callee_summary.param_to_sink.items():
                        if c_pidx != pidx:
                            continue
                        overlap = arg_taint_types & self._normalize_vuln_types(c_vulns)
                        if not overlap:
                            continue

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


    @staticmethod
    def _normalize_vuln_types(types: Set[str]) -> Set[str]:
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

    @staticmethod
    def _var_in_text(var: str, text: str) -> bool:
        return bool(re.search(re.escape(var) + r'(?![a-zA-Z0-9_])', text))


    @staticmethod
    def _get_arg_nodes(call_node: TSNode) -> List[TSNode]:
        args_node = call_node.child_by_field("arguments")
        if args_node is None:
            return []
        return [c for c in args_node.named_children if c.type == "argument"]

    @staticmethod
    def _node_call_name(node: TSNode) -> Optional[str]:
        if node.type == "function_call_expression":
            fn = node.child_by_field("function")
            return fn.text if fn else None
        elif node.type == "member_call_expression":
            mn = node.child_by_field("name")
            return mn.text if mn else None
        return None


def analyze_interprocedural_v2(
    project_dir: str, k: int = 2
) -> Tuple[List[Dict], Dict[str, Any]]:
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
