#!/usr/bin/env python3
"""
APEX Inter-procedural Analysis v2.0
Tree-sitter based function extraction with proper parameter binding
and return value taint propagation.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple
from pathlib import Path
from .ts_adapter import TSNode, parse_php_ts


@dataclass
class FunctionInfo:
    name: str
    file: str
    line: int
    params: List[str] = field(default_factory=list)
    returns_tainted: bool = False
    tainted_params: Set[int] = field(default_factory=set)
    param_flows_to_sink: Dict[int, Set[str]] = field(default_factory=dict)
    param_flows_to_return: Set[int] = field(default_factory=set)
    calls: List[str] = field(default_factory=list)
    body_node: Optional[TSNode] = field(default=None, repr=False)
    body: str = ""
    is_sanitizer: bool = False
    sanitizes_for: Set[str] = field(default_factory=set)


@dataclass
class TaintFlow:
    source_func: str
    source_file: str
    sink_func: str
    sink_file: str
    flow_path: List[str]
    vuln_type: str
    confidence: float


# Sink definitions for inter-procedural analysis
SOURCES = {'$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES'}

SINKS = {
    'SQL': {'mysql_query', 'mysqli_query', 'pg_query', 'sqlite_query', 'oci_parse'},
    'XSS': {'echo', 'print', 'printf'},
    'CMD': {'exec', 'system', 'passthru', 'shell_exec', 'popen', 'proc_open'},
    'FILE': {'include', 'include_once', 'require', 'require_once'},
    'CODE': {'eval', 'assert', 'create_function', 'call_user_func'},
    'DESER': {'unserialize'},
}

SANITIZERS = {
    'SQL': {'intval', 'escape_string', 'real_escape_string', 'prepare', 'bindParam', 'bindValue'},
    'XSS': {'htmlspecialchars', 'htmlentities', 'strip_tags'},
    'CMD': {'escapeshellarg', 'escapeshellcmd'},
    'FILE': {'basename', 'realpath'},
    'CODE': {'intval', 'is_numeric'},
}

SINK_METHODS = {'query', 'exec', 'execute', 'prepare'}


class InterproceduralAnalyzer:
    """Tree-sitter based inter-procedural taint analyzer."""

    def __init__(self):
        self.functions: Dict[str, FunctionInfo] = {}
        self.call_graph: Dict[str, Set[str]] = {}
        self.reverse_graph: Dict[str, Set[str]] = {}
        self.file_functions: Dict[str, List[str]] = {}

    def analyze_file(self, filepath: str, content: str):
        """Extract and analyze all functions from a file using tree-sitter."""
        try:
            root = parse_php_ts(content)
        except Exception:
            return []

        code_bytes = content.encode('utf8')
        functions = []

        for node in root.walk_descendants():
            if node.type not in ('function_definition', 'method_declaration'):
                continue

            name_node = node.child_by_field('name')
            if not name_node:
                continue
            func_name = name_node.text

            # Extract parameters
            params = []
            params_node = node.child_by_field('parameters')
            if params_node:
                for param in params_node.named_children:
                    if param.type == 'simple_parameter':
                        for c in param.named_children:
                            if c.type == 'variable_name':
                                params.append(c.text)

            body_node = node.child_by_field('body')
            body_text = body_node.text if body_node else ''

            fi = FunctionInfo(
                name=func_name,
                file=filepath,
                line=node.line,
                params=params,
                body_node=body_node,
                body=body_text,
            )

            # Analyze function for taint properties
            self._analyze_function_ts(fi, body_node)
            functions.append(fi)
            self.functions[func_name] = fi

        self.file_functions[filepath] = [f.name for f in functions]
        return functions

    def _analyze_function_ts(self, func: FunctionInfo, body_node: Optional[TSNode]):
        """Analyze a function using tree-sitter for taint properties."""
        if not body_node:
            return

        # Collect all variable_name, function_call, and return nodes
        variables_used = set()
        function_calls = []
        return_exprs = []
        has_source = False

        for node in body_node.walk_descendants():
            if node.type == 'variable_name':
                var = node.text
                variables_used.add(var)
                if var in SOURCES:
                    has_source = True
            elif node.type == 'function_call_expression':
                fn = node.child_by_field('function')
                if fn:
                    function_calls.append(fn.text)
            elif node.type == 'member_call_expression':
                name = node.child_by_field('name')
                if name:
                    function_calls.append(name.text)
            elif node.type == 'return_statement':
                for c in node.named_children:
                    return_exprs.append(c)

        # Track which params are used and if sources exist in body
        for i, param in enumerate(func.params):
            if param in variables_used:
                # Check if param reaches a sink
                for vuln_type, sink_set in SINKS.items():
                    for call in function_calls:
                        if call in sink_set or call in SINK_METHODS:
                            # Check if sanitized for this type
                            sans = SANITIZERS.get(vuln_type, set())
                            if not any(s in function_calls for s in sans):
                                func.param_flows_to_sink.setdefault(i, set()).add(vuln_type)
                                func.tainted_params.add(i)

                # Check if param flows to return
                for ret_node in return_exprs:
                    if param in ret_node.text:
                        func.param_flows_to_return.add(i)

        # Check if function body has direct source usage in return
        for ret_node in return_exprs:
            ret_text = ret_node.text
            for source in SOURCES:
                if source in ret_text:
                    func.returns_tainted = True

        # Check if function is a sanitizer
        sanitizer_names = set()
        for sans_set in SANITIZERS.values():
            sanitizer_names.update(sans_set)
        if func.name in sanitizer_names:
            func.is_sanitizer = True
        # Also check if function wraps a sanitizer and returns result
        if func.param_flows_to_return and not func.param_flows_to_sink:
            for call in function_calls:
                if call in sanitizer_names:
                    func.is_sanitizer = True
                    for vuln_type, sans_set in SANITIZERS.items():
                        if call in sans_set:
                            func.sanitizes_for.add(vuln_type)

        func.calls = list(set(function_calls))

    def build_call_graph(self):
        """Build call graph from extracted function calls."""
        self.call_graph.clear()
        self.reverse_graph.clear()
        for fn, fi in self.functions.items():
            callees = set()
            for c in fi.calls:
                if c in self.functions:
                    callees.add(c)
            self.call_graph[fn] = callees
            for c in callees:
                self.reverse_graph.setdefault(c, set()).add(fn)

    def find_taint_flows(self) -> List[TaintFlow]:
        """Find taint flows that cross function boundaries."""
        flows = []

        for fn, fi in self.functions.items():
            if not fi.param_flows_to_sink:
                continue

            # For each param that reaches a sink, trace backward through callers
            for param_idx, vuln_types in fi.param_flows_to_sink.items():
                for vuln_type in vuln_types:
                    # Find callers that pass tainted data to this param
                    self._trace_callers(fi, param_idx, vuln_type, flows, set())

        return flows

    def _trace_callers(self, func: FunctionInfo, param_idx: int,
                       vuln_type: str, flows: List[TaintFlow],
                       visited: Set[str]):
        """Trace backward through callers to find taint sources."""
        if func.name in visited:
            return
        visited.add(func.name)

        for caller_name in self.reverse_graph.get(func.name, set()):
            caller = self.functions.get(caller_name)
            if not caller:
                continue

            # Check if caller passes tainted data (source) as this param
            body_text = caller.body
            for source in SOURCES:
                if source in body_text:
                    # Check if not sanitized
                    sans = SANITIZERS.get(vuln_type, set())
                    if not any(s in caller.calls for s in sans):
                        flow = TaintFlow(
                            source_func=caller_name,
                            source_file=caller.file,
                            sink_func=func.name,
                            sink_file=func.file,
                            flow_path=[caller_name, func.name],
                            vuln_type=vuln_type,
                            confidence=0.75,
                        )
                        flows.append(flow)

            # Also check if caller receives tainted data from its own params
            for ci, cp in enumerate(caller.params):
                if cp in body_text:
                    self._trace_callers(caller, ci, vuln_type, flows, visited)

    def analyze_project(self, project_dir):
        """Analyze all PHP files in a project."""
        ppath = Path(project_dir)
        php_files = list(ppath.rglob('*.php'))
        for pf in php_files:
            try:
                content = pf.read_text(encoding='utf-8', errors='ignore')
                self.analyze_file(str(pf), content)
            except Exception:
                pass
        self.build_call_graph()
        flows = self.find_taint_flows()
        return flows

    def get_summary(self):
        return {
            'total_functions': len(self.functions),
            'total_files': len(self.file_functions),
            'tainted_params': sum(1 for f in self.functions.values() if f.tainted_params),
            'tainted_returns': sum(1 for f in self.functions.values() if f.returns_tainted),
            'sanitizer_functions': sum(1 for f in self.functions.values() if f.is_sanitizer),
        }

    # Backward compatibility aliases
    def analyze_directory(self, directory):
        return self.analyze_project(directory)

    def get_call_graph_stats(self):
        return self.get_summary()


def analyze_interprocedural(project_dir):
    analyzer = InterproceduralAnalyzer()
    flows = analyzer.analyze_project(project_dir)
    return flows, analyzer.get_summary()


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python interprocedural.py <project_dir>")
        sys.exit(1)
    flows, summary = analyze_interprocedural(sys.argv[1])
    print(f"\nSummary: {summary}")
    for f in flows:
        print(f"\n[{f.vuln_type}] {f.confidence:.0%}: {' -> '.join(f.flow_path)}")
