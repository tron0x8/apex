#!/usr/bin/env python3

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any, Tuple, Union
from enum import Enum, auto
from collections import defaultdict
import re
import hashlib

try:
    from .php_parser import ASTNode, NodeType, parse_php
except ImportError:
    # php_parser removed - symbolic executor is deprecated
    ASTNode = None
    NodeType = None
    parse_php = None


class SymbolicType(Enum):
    CONCRETE = auto()
    SYMBOLIC = auto()
    TAINTED = auto()
    CONSTRAINED = auto()


@dataclass
class SymbolicValue:
    type: SymbolicType
    name: str
    value: Any = None
    constraints: List[str] = field(default_factory=list)
    source: Optional[str] = None
    operations: List[str] = field(default_factory=list)

    def is_tainted(self) -> bool:
        return self.type == SymbolicType.TAINTED

    def apply_operation(self, op: str) -> 'SymbolicValue':
        new_val = SymbolicValue(
            type=self.type,
            name=f"({op} {self.name})",
            value=None,
            constraints=self.constraints.copy(),
            source=self.source,
            operations=self.operations + [op]
        )
        return new_val

    def with_constraint(self, constraint: str) -> 'SymbolicValue':
        new_val = SymbolicValue(
            type=SymbolicType.CONSTRAINED,
            name=self.name,
            value=self.value,
            constraints=self.constraints + [constraint],
            source=self.source,
            operations=self.operations.copy()
        )
        return new_val


@dataclass
class PathConstraint:
    condition: str
    negated: bool = False
    line: int = 0

    def __str__(self):
        prefix = "NOT " if self.negated else ""
        return f"{prefix}({self.condition})"


@dataclass
class ExecutionPath:
    constraints: List[PathConstraint] = field(default_factory=list)
    state: Dict[str, SymbolicValue] = field(default_factory=dict)
    findings: List[Dict] = field(default_factory=list)
    depth: int = 0

    def add_constraint(self, constraint: PathConstraint):
        self.constraints.append(constraint)

    def fork(self) -> 'ExecutionPath':
        return ExecutionPath(
            constraints=self.constraints.copy(),
            state={k: SymbolicValue(
                v.type, v.name, v.value,
                v.constraints.copy(), v.source, v.operations.copy()
            ) for k, v in self.state.items()},
            findings=self.findings.copy(),
            depth=self.depth + 1
        )

    def is_feasible(self) -> bool:
        for i, c1 in enumerate(self.constraints):
            for c2 in self.constraints[i+1:]:
                if c1.condition == c2.condition and c1.negated != c2.negated:
                    return False
        return True

    def get_path_id(self) -> str:
        return hashlib.md5(
            ''.join(str(c) for c in self.constraints).encode()
        ).hexdigest()[:8]


class SymbolicExecutor:
    MAX_DEPTH = 20
    MAX_PATHS = 1000
    MAX_LOOP_ITERATIONS = 3

    def __init__(self, file_path: str = ""):
        self.file_path = file_path
        self.paths: List[ExecutionPath] = []
        self.completed_paths: List[ExecutionPath] = []
        self.findings: List[Dict] = []
        self.function_summaries: Dict[str, Dict] = {}
        self.loop_counts: Dict[int, int] = defaultdict(int)

    def execute(self, code: str) -> List[Dict]:
        try:
            ast = parse_php(code)
            initial_path = ExecutionPath()
            self._execute_node(ast, initial_path)
        except Exception as e:
            pass
        return self.findings

    def _execute_node(self, node: ASTNode, path: ExecutionPath) -> Optional[SymbolicValue]:
        if path.depth > self.MAX_DEPTH:
            return None
        if len(self.completed_paths) > self.MAX_PATHS:
            return None

        handlers = {
            NodeType.PROGRAM: self._exec_program,
            NodeType.FUNCTION_DECL: self._exec_function,
            NodeType.STMT_BLOCK: self._exec_block,
            NodeType.STMT_IF: self._exec_if,
            NodeType.STMT_WHILE: self._exec_while,
            NodeType.STMT_FOR: self._exec_for,
            NodeType.STMT_FOREACH: self._exec_foreach,
            NodeType.STMT_RETURN: self._exec_return,
            NodeType.STMT_ECHO: self._exec_echo,
            NodeType.STMT_EXPR: self._exec_expr_stmt,
            NodeType.EXPR_ASSIGN: self._exec_assign,
            NodeType.EXPR_BINARY: self._exec_binary,
            NodeType.EXPR_CALL: self._exec_call,
            NodeType.EXPR_METHOD_CALL: self._exec_method_call,
            NodeType.EXPR_ARRAY_ACCESS: self._exec_array_access,
            NodeType.EXPR_VARIABLE: self._exec_variable,
            NodeType.EXPR_LITERAL: self._exec_literal,
            NodeType.EXPR_EVAL: self._exec_eval,
            NodeType.EXPR_INCLUDE: self._exec_include,
        }

        handler = handlers.get(node.type)
        if handler:
            return handler(node, path)

        for child in node.children:
            self._execute_node(child, path)
        return None

    def _exec_program(self, node: ASTNode, path: ExecutionPath) -> None:
        for child in node.children:
            self._execute_node(child, path)
        self.completed_paths.append(path)

    def _exec_function(self, node: ASTNode, path: ExecutionPath) -> None:
        func_name = node.value
        func_path = path.fork()

        for child in node.children:
            if child.type == NodeType.PARAMETER:
                param_name = child.value
                func_path.state[param_name] = SymbolicValue(
                    SymbolicType.SYMBOLIC,
                    f"param_{param_name}",
                    source=f"parameter:{param_name}"
                )

        for child in node.children:
            if child.type == NodeType.STMT_BLOCK:
                self._execute_node(child, func_path)

        self.function_summaries[func_name] = {
            'path': func_path,
            'returns': func_path.state.get('$__return__')
        }

    def _exec_block(self, node: ASTNode, path: ExecutionPath) -> None:
        for child in node.children:
            self._execute_node(child, path)

    def _exec_if(self, node: ASTNode, path: ExecutionPath) -> None:
        if not node.children:
            return

        condition = node.children[0]
        cond_value = self._execute_node(condition, path)
        cond_str = self._node_to_string(condition)

        then_path = path.fork()
        then_path.add_constraint(PathConstraint(cond_str, False, node.line))

        else_path = path.fork()
        else_path.add_constraint(PathConstraint(cond_str, True, node.line))

        if then_path.is_feasible() and len(node.children) > 1:
            self._execute_node(node.children[1], then_path)
            self.completed_paths.append(then_path)

        if else_path.is_feasible() and len(node.children) > 2:
            self._execute_node(node.children[2], else_path)
            self.completed_paths.append(else_path)

        path.findings.extend(then_path.findings)
        path.findings.extend(else_path.findings)

    def _exec_while(self, node: ASTNode, path: ExecutionPath) -> None:
        loop_id = id(node)
        for _ in range(self.MAX_LOOP_ITERATIONS):
            self.loop_counts[loop_id] += 1
            if not node.children:
                break
            cond_value = self._execute_node(node.children[0], path)
            if len(node.children) > 1:
                self._execute_node(node.children[1], path)

    def _exec_for(self, node: ASTNode, path: ExecutionPath) -> None:
        if node.children:
            self._execute_node(node.children[0], path)

        loop_id = id(node)
        for _ in range(self.MAX_LOOP_ITERATIONS):
            self.loop_counts[loop_id] += 1
            if len(node.children) > 1:
                self._execute_node(node.children[1], path)
            if len(node.children) > 3:
                self._execute_node(node.children[3], path)
            if len(node.children) > 2:
                self._execute_node(node.children[2], path)

    def _exec_foreach(self, node: ASTNode, path: ExecutionPath) -> None:
        if not node.children:
            return

        array_value = self._execute_node(node.children[0], path)

        if len(node.children) > 1:
            value_node = node.children[1]
            if value_node.type == NodeType.EXPR_VARIABLE:
                var_name = value_node.value
                if array_value and array_value.is_tainted():
                    path.state[var_name] = SymbolicValue(
                        SymbolicType.TAINTED,
                        f"foreach_value",
                        source=array_value.source
                    )

        for _ in range(self.MAX_LOOP_ITERATIONS):
            if len(node.children) > 2:
                self._execute_node(node.children[2], path)

    def _exec_return(self, node: ASTNode, path: ExecutionPath) -> Optional[SymbolicValue]:
        if node.children:
            value = self._execute_node(node.children[0], path)
            path.state['$__return__'] = value
            return value
        return None

    def _exec_echo(self, node: ASTNode, path: ExecutionPath) -> None:
        for child in node.children:
            value = self._execute_node(child, path)
            if value and value.is_tainted():
                if not any(op in ('htmlspecialchars', 'htmlentities', 'strip_tags')
                          for op in value.operations):
                    self._report_finding(path, 'XSS', 'echo', node.line, value)

    def _exec_expr_stmt(self, node: ASTNode, path: ExecutionPath) -> Optional[SymbolicValue]:
        if node.children:
            return self._execute_node(node.children[0], path)
        return None

    def _exec_assign(self, node: ASTNode, path: ExecutionPath) -> Optional[SymbolicValue]:
        if len(node.children) < 2:
            return None

        left = node.children[0]
        right = node.children[1]
        value = self._execute_node(right, path)
        var_name = self._get_var_name(left)
        if var_name and value:
            path.state[var_name] = value
        return value

    def _exec_binary(self, node: ASTNode, path: ExecutionPath) -> SymbolicValue:
        left_val = self._execute_node(node.children[0], path) if node.children else None
        right_val = self._execute_node(node.children[1], path) if len(node.children) > 1 else None

        if (left_val and left_val.is_tainted()) or (right_val and right_val.is_tainted()):
            source = left_val.source if left_val and left_val.is_tainted() else right_val.source
            return SymbolicValue(
                SymbolicType.TAINTED,
                f"binary_{node.value}",
                source=source,
                operations=(left_val.operations if left_val else []) +
                          (right_val.operations if right_val else [])
            )
        return SymbolicValue(SymbolicType.SYMBOLIC, f"binary_{node.value}")

    def _exec_call(self, node: ASTNode, path: ExecutionPath) -> Optional[SymbolicValue]:
        func_name = node.value

        if func_name is None and node.children:
            first_child = node.children[0]
            if first_child.type == NodeType.EXPR_LITERAL:
                func_name = first_child.value

        if not func_name:
            return None

        args = []
        for child in node.children[1:] if len(node.children) > 1 else node.children:
            arg_val = self._execute_node(child, path)
            args.append(arg_val)

        dangerous_sinks = {
            'eval': 'CODE_INJECTION',
            'exec': 'COMMAND_INJECTION',
            'shell_exec': 'COMMAND_INJECTION',
            'system': 'COMMAND_INJECTION',
            'passthru': 'COMMAND_INJECTION',
            'mysql_query': 'SQL_INJECTION',
            'mysqli_query': 'SQL_INJECTION',
            'pg_query': 'SQL_INJECTION',
            'unserialize': 'DESERIALIZATION',
            'file_get_contents': 'SSRF/PATH_TRAVERSAL',
            'file_put_contents': 'ARBITRARY_FILE_WRITE',
            'include': 'FILE_INCLUSION',
            'include_once': 'FILE_INCLUSION',
            'require': 'FILE_INCLUSION',
            'require_once': 'FILE_INCLUSION',
        }

        if func_name in dangerous_sinks:
            for arg in args:
                if arg and arg.is_tainted():
                    self._report_finding(
                        path, dangerous_sinks[func_name],
                        func_name, node.line, arg
                    )

        sanitizers = {
            'intval': lambda v: SymbolicValue(SymbolicType.CONCRETE, 'int', operations=v.operations + ['intval'] if v else ['intval']),
            'htmlspecialchars': lambda v: v.apply_operation('htmlspecialchars') if v else None,
            'htmlentities': lambda v: v.apply_operation('htmlentities') if v else None,
            'addslashes': lambda v: v.apply_operation('addslashes') if v else None,
            'mysql_real_escape_string': lambda v: v.apply_operation('mysql_escape') if v else None,
            'mysqli_real_escape_string': lambda v: v.apply_operation('mysqli_escape') if v else None,
            'escapeshellarg': lambda v: v.apply_operation('escapeshellarg') if v else None,
            'escapeshellcmd': lambda v: v.apply_operation('escapeshellcmd') if v else None,
            'basename': lambda v: v.apply_operation('basename') if v else None,
            'strip_tags': lambda v: v.apply_operation('strip_tags') if v else None,
        }

        if func_name in sanitizers and args:
            return sanitizers[func_name](args[0])

        if func_name in self.function_summaries:
            summary = self.function_summaries[func_name]
            return summary.get('returns')

        for arg in args:
            if arg and arg.is_tainted():
                return SymbolicValue(
                    SymbolicType.TAINTED,
                    f"call_{func_name}",
                    source=arg.source,
                    operations=arg.operations
                )
        return SymbolicValue(SymbolicType.SYMBOLIC, f"call_{func_name}")

    def _exec_method_call(self, node: ASTNode, path: ExecutionPath) -> Optional[SymbolicValue]:
        method_name = node.value
        obj_val = self._execute_node(node.children[0], path) if node.children else None

        args = []
        for child in node.children[1:]:
            arg_val = self._execute_node(child, path)
            args.append(arg_val)

        if method_name in ('query', 'exec', 'prepare'):
            for arg in args:
                if arg and arg.is_tainted():
                    if not any(op in ('mysqli_escape', 'mysql_escape', 'safesql', 'intval')
                              for op in arg.operations):
                        self._report_finding(
                            path, 'SQL_INJECTION',
                            f'->{method_name}', node.line, arg
                        )

        if method_name == 'safesql' and args:
            return args[0].apply_operation('safesql') if args[0] else None

        return SymbolicValue(SymbolicType.SYMBOLIC, f"method_{method_name}")

    def _exec_array_access(self, node: ASTNode, path: ExecutionPath) -> SymbolicValue:
        if not node.children:
            return SymbolicValue(SymbolicType.SYMBOLIC, "array_access")

        array_node = node.children[0]
        var_name = self._get_var_name(array_node)

        tainted_sources = {
            '$_GET': 'GET',
            '$_POST': 'POST',
            '$_REQUEST': 'REQUEST',
            '$_COOKIE': 'COOKIE',
            '$_FILES': 'FILES',
            '$_SERVER': 'SERVER',
        }

        if var_name in tainted_sources:
            key = ""
            if len(node.children) > 1:
                key_node = node.children[1]
                if key_node.type == NodeType.EXPR_LITERAL:
                    key = key_node.value

            return SymbolicValue(
                SymbolicType.TAINTED,
                f"{var_name}[{key}]",
                source=f"{tainted_sources[var_name]}:{key}"
            )

        if var_name in path.state:
            return path.state[var_name]
        return SymbolicValue(SymbolicType.SYMBOLIC, f"array_{var_name}")

    def _exec_variable(self, node: ASTNode, path: ExecutionPath) -> SymbolicValue:
        var_name = node.value

        if var_name in ('$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES'):
            return SymbolicValue(
                SymbolicType.TAINTED,
                var_name,
                source=var_name[2:]
            )

        if var_name in path.state:
            return path.state[var_name]
        return SymbolicValue(SymbolicType.SYMBOLIC, var_name)

    def _exec_literal(self, node: ASTNode, path: ExecutionPath) -> SymbolicValue:
        return SymbolicValue(
            SymbolicType.CONCRETE,
            "literal",
            value=node.value
        )

    def _exec_eval(self, node: ASTNode, path: ExecutionPath) -> None:
        if node.children:
            value = self._execute_node(node.children[0], path)
            if value and value.is_tainted():
                self._report_finding(path, 'CODE_INJECTION', 'eval', node.line, value)

    def _exec_include(self, node: ASTNode, path: ExecutionPath) -> None:
        include_type = node.value
        if node.children:
            value = self._execute_node(node.children[0], path)
            if value and value.is_tainted():
                if not any(op in ('basename', 'realpath') for op in value.operations):
                    self._report_finding(
                        path, 'FILE_INCLUSION',
                        include_type, node.line, value
                    )

    def _get_var_name(self, node: ASTNode) -> Optional[str]:
        if node.type == NodeType.EXPR_VARIABLE:
            return node.value
        if node.type == NodeType.EXPR_ARRAY_ACCESS and node.children:
            return self._get_var_name(node.children[0])
        return None

    def _node_to_string(self, node: ASTNode) -> str:
        if node.type == NodeType.EXPR_VARIABLE:
            return node.value
        if node.type == NodeType.EXPR_LITERAL:
            return str(node.value)
        if node.type == NodeType.EXPR_BINARY:
            left = self._node_to_string(node.children[0]) if node.children else "?"
            right = self._node_to_string(node.children[1]) if len(node.children) > 1 else "?"
            return f"({left} {node.value} {right})"
        return "?"

    def _report_finding(self, path: ExecutionPath, vuln_type: str,
                       sink: str, line: int, value: SymbolicValue):
        finding = {
            'type': vuln_type,
            'sink': sink,
            'line': line,
            'file': self.file_path,
            'source': value.source,
            'operations': value.operations,
            'constraints': [str(c) for c in path.constraints],
            'path_id': path.get_path_id(),
            'severity': self._get_severity(vuln_type)
        }

        finding_hash = f"{vuln_type}:{sink}:{line}:{value.source}"
        if not any(f['type'] == vuln_type and f['sink'] == sink and
                  f['line'] == line and f['source'] == value.source
                  for f in self.findings):
            self.findings.append(finding)
            path.findings.append(finding)

    def _get_severity(self, vuln_type: str) -> str:
        critical = ['CODE_INJECTION', 'COMMAND_INJECTION', 'SQL_INJECTION',
                   'FILE_INCLUSION', 'DESERIALIZATION', 'ARBITRARY_FILE_WRITE']
        high = ['XSS', 'SSRF/PATH_TRAVERSAL', 'PATH_TRAVERSAL']

        if vuln_type in critical:
            return 'CRITICAL'
        if vuln_type in high:
            return 'HIGH'
        return 'MEDIUM'


def symbolic_execute_file(file_path: str) -> List[Dict]:
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        code = f.read()
    executor = SymbolicExecutor(file_path)
    return executor.execute(code)


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python symbolic_executor.py <php_file>")
        sys.exit(1)

    findings = symbolic_execute_file(sys.argv[1])
    print(f"Found {len(findings)} potential vulnerabilities:")
    for finding in findings:
        print(json.dumps(finding, indent=2))
