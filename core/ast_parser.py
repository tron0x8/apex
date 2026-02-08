#!/usr/bin/env python3
"""
APEX AST Parser v4.0
Tree-sitter based PHP AST parsing for accurate vulnerability detection

Improvements over regex:
- Understands code structure
- Proper scope handling
- Function/class awareness
- Accurate variable tracking
- Sanitization tracking through assignments
"""

import tree_sitter_php as tsphp
from tree_sitter import Language, Parser
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass, field
from enum import Enum


class NodeType(Enum):
    """Important PHP AST node types"""
    FUNCTION_DEF = "function_definition"
    METHOD_DEF = "method_declaration"
    CLASS_DEF = "class_declaration"
    VARIABLE = "variable_name"
    FUNCTION_CALL = "function_call_expression"
    METHOD_CALL = "member_call_expression"
    ASSIGNMENT = "assignment_expression"
    SUBSCRIPT = "subscript_expression"
    STRING = "string"
    BINARY_OP = "binary_expression"
    IF_STMT = "if_statement"
    RETURN_STMT = "return_statement"
    ECHO_STMT = "echo_statement"
    INCLUDE = "include_expression"
    REQUIRE = "require_expression"


@dataclass
class Variable:
    """Represents a PHP variable with taint state"""
    name: str
    line: int
    scope: str  # function name or "global"
    is_tainted: bool = False
    taint_source: Optional[str] = None
    is_sanitized: bool = False
    sanitizer: Optional[str] = None
    sanitized_for: List[str] = field(default_factory=list)  # Vuln types it's sanitized for


@dataclass
class FunctionInfo:
    """Represents a PHP function/method"""
    name: str
    file: str
    start_line: int
    end_line: int
    params: List[str] = field(default_factory=list)
    returns_tainted: bool = False
    has_sink: bool = False
    sink_type: Optional[str] = None
    calls: List[str] = field(default_factory=list)
    is_sanitizer: bool = False
    sanitizes_for: List[str] = field(default_factory=list)


@dataclass
class TaintFlow:
    """Represents a taint flow from source to sink"""
    source: str
    source_line: int
    sink: str
    sink_line: int
    sink_type: str  # Vulnerability type
    path: List[Tuple[str, int]]  # (variable, line) pairs
    is_sanitized: bool = False
    sanitizer: Optional[str] = None


@dataclass
class CFGNode:
    """Control Flow Graph node"""
    id: int
    line: int
    node_type: str
    code: str
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    variables_defined: Set[str] = field(default_factory=set)
    variables_used: Set[str] = field(default_factory=set)


class PHPASTParser:
    """
    PHP AST Parser using tree-sitter

    Provides:
    - AST parsing
    - Variable tracking with scope
    - Function analysis
    - Taint propagation with sanitization tracking
    - Control Flow Graph generation
    """

    # Taint sources (superglobals and functions)
    SOURCES = {
        '$_GET': 'GET',
        '$_POST': 'POST',
        '$_REQUEST': 'REQUEST',
        '$_COOKIE': 'COOKIE',
        '$_FILES': 'FILES',
        '$_SERVER': 'SERVER',
    }

    SOURCE_FUNCTIONS = {
        'file_get_contents': 'FILE',
        'fread': 'FILE',
        'fgets': 'FILE',
        'readline': 'INPUT',
        'getenv': 'ENV',
        'apache_getenv': 'ENV',
    }

    # Sinks by vulnerability type
    SINKS = {
        'SQL_INJECTION': [
            'mysql_query', 'mysqli_query', 'pg_query',
            'query', 'exec', 'execute', 'prepare',
            'sqlite_query', 'oci_parse',
        ],
        'COMMAND_INJECTION': [
            'exec', 'system', 'passthru', 'shell_exec',
            'popen', 'proc_open', 'pcntl_exec',
        ],
        'CODE_INJECTION': [
            'eval', 'assert', 'create_function', 'preg_replace',
            'call_user_func', 'call_user_func_array',
        ],
        'FILE_INCLUSION': [
            'include', 'include_once', 'require', 'require_once'
        ],
        'XSS': [
            'echo', 'print', 'printf', 'vprintf', 'die', 'exit'
        ],
        'FILE_WRITE': [
            'file_put_contents', 'fwrite', 'fputs', 'fputcsv'
        ],
        'FILE_READ': [
            'file_get_contents', 'readfile', 'file', 'fread',
            'fgets', 'fgetc', 'fpassthru',
        ],
        'SSRF': [
            'curl_init', 'curl_exec', 'file_get_contents',
            'fsockopen', 'fopen', 'get_headers',
        ],
        'DESERIALIZATION': [
            'unserialize', 'yaml_parse', 'json_decode'
        ],
        'XXE': [
            'simplexml_load_string', 'simplexml_load_file',
            'DOMDocument', 'XMLReader', 'xml_parse',
        ],
        'LDAP_INJECTION': [
            'ldap_search', 'ldap_list', 'ldap_read', 'ldap_bind'
        ],
        'XPATH_INJECTION': [
            'xpath', 'query', 'evaluate'
        ],
    }

    # Sanitizers by vulnerability type
    SANITIZERS = {
        'SQL_INJECTION': {
            'intval': True, 'floatval': True,
            'mysqli_real_escape_string': True, 'mysql_real_escape_string': True,
            'addslashes': True, 'pg_escape_string': True,
            'prepare': True, 'bindParam': True, 'bindValue': True,
            'quote': True, 'safesql': True,
            '(int)': True, '(float)': True,
            'is_numeric': True, 'ctype_digit': True,
            'abs': True, 'floor': True, 'ceil': True, 'round': True,
        },
        'COMMAND_INJECTION': {
            'escapeshellarg': True, 'escapeshellcmd': True,
        },
        'XSS': {
            'htmlspecialchars': True, 'htmlentities': True, 'strip_tags': True,
            'esc_html': True, 'esc_attr': True, 'e': True,
            'purify': True, 'clean': True, 'sanitize': True,
            'json_encode': True,
        },
        'FILE_INCLUSION': {
            'basename': True, 'realpath': True, 'in_array': True,
        },
        'SSRF': {
            'filter_var': True, 'parse_url': True,
        },
        'PATH_TRAVERSAL': {
            'basename': True, 'realpath': True,
        },
    }

    def __init__(self):
        """Initialize the parser"""
        self.language = Language(tsphp.language_php())
        self.parser = Parser(self.language)
        self.functions: Dict[str, FunctionInfo] = {}
        self.variables: Dict[str, Variable] = {}
        self.taint_flows: List[TaintFlow] = []
        self.current_file = ""
        self.current_scope = "global"
        self.cfg_nodes: List[CFGNode] = []
        self._node_counter = 0

    def parse(self, code: str, filename: str = "") -> Any:
        """Parse PHP code and return AST"""
        self.current_file = filename
        # Ensure code starts with <?php
        if not code.strip().startswith('<?'):
            code = '<?php\n' + code
        return self.parser.parse(bytes(code, 'utf8'))

    def get_node_text(self, node, code: bytes) -> str:
        """Get text content of a node"""
        return code[node.start_byte:node.end_byte].decode('utf8')

    def find_variables(self, tree, code: str) -> List[Variable]:
        """Find all variables in code with their context"""
        code_bytes = bytes(code, 'utf8')
        variables = []

        def visit(node, scope="global"):
            # Track function scope
            if node.type in ['function_definition', 'method_declaration']:
                name_node = node.child_by_field_name('name')
                if name_node:
                    scope = self.get_node_text(name_node, code_bytes)

            # Find variable nodes
            if node.type == 'variable_name':
                var_name = self.get_node_text(node, code_bytes)
                var = Variable(
                    name=var_name,
                    line=node.start_point[0] + 1,
                    scope=scope,
                    is_tainted=self._is_tainted_source(var_name),
                    taint_source=self.SOURCES.get(var_name)
                )
                variables.append(var)

            # Recurse
            for child in node.children:
                visit(child, scope)

        visit(tree.root_node)
        return variables

    def find_function_calls(self, tree, code: str) -> List[Tuple[str, int, List[str]]]:
        """Find all function calls with their arguments"""
        code_bytes = bytes(code, 'utf8')
        calls = []

        def visit(node):
            if node.type == 'function_call_expression':
                func_node = node.child_by_field_name('function')
                args_node = node.child_by_field_name('arguments')

                if func_node:
                    func_name = self.get_node_text(func_node, code_bytes)
                    args = []
                    if args_node:
                        for arg in args_node.children:
                            if arg.type not in ['(', ')', ',']:
                                args.append(self.get_node_text(arg, code_bytes))

                    calls.append((func_name, node.start_point[0] + 1, args))

            # Also handle method calls
            if node.type == 'member_call_expression':
                name_node = node.child_by_field_name('name')
                args_node = node.child_by_field_name('arguments')

                if name_node:
                    method_name = self.get_node_text(name_node, code_bytes)
                    args = []
                    if args_node:
                        for arg in args_node.children:
                            if arg.type not in ['(', ')', ',']:
                                args.append(self.get_node_text(arg, code_bytes))
                    calls.append((method_name, node.start_point[0] + 1, args))

            for child in node.children:
                visit(child)

        visit(tree.root_node)
        return calls

    def find_assignments(self, tree, code: str) -> List[Tuple[str, str, int]]:
        """Find all variable assignments: (var, value, line)"""
        code_bytes = bytes(code, 'utf8')
        assignments = []

        def visit(node):
            if node.type == 'assignment_expression':
                left = node.child_by_field_name('left')
                right = node.child_by_field_name('right')

                if left and right:
                    var_name = self.get_node_text(left, code_bytes)
                    value = self.get_node_text(right, code_bytes)
                    assignments.append((var_name, value, node.start_point[0] + 1))

            for child in node.children:
                visit(child)

        visit(tree.root_node)
        return assignments

    def find_sinks(self, tree, code: str) -> List[Tuple[str, str, int, List[str]]]:
        """Find all potential sinks: (sink_type, func_name, line, args)"""
        code_bytes = bytes(code, 'utf8')
        sinks = []

        def visit(node):
            # Function calls
            if node.type == 'function_call_expression':
                func_node = node.child_by_field_name('function')
                args_node = node.child_by_field_name('arguments')

                if func_node:
                    func_name = self.get_node_text(func_node, code_bytes)

                    # Check if it's a sink
                    for sink_type, sink_funcs in self.SINKS.items():
                        if func_name in sink_funcs:
                            args = []
                            if args_node:
                                for arg in args_node.children:
                                    if arg.type not in ['(', ')', ',']:
                                        args.append(self.get_node_text(arg, code_bytes))
                            sinks.append((sink_type, func_name, node.start_point[0] + 1, args))

            # Echo/print statements
            if node.type == 'echo_statement':
                args = []
                for child in node.children:
                    if child.type not in ['echo', ';']:
                        args.append(self.get_node_text(child, code_bytes))
                sinks.append(('XSS', 'echo', node.start_point[0] + 1, args))

            # Include/require
            if node.type in ['include_expression', 'require_expression']:
                arg = self.get_node_text(node, code_bytes)
                sinks.append(('FILE_INCLUSION', node.type.replace('_expression', ''),
                             node.start_point[0] + 1, [arg]))

            for child in node.children:
                visit(child)

        visit(tree.root_node)
        return sinks

    def _is_tainted_source(self, var_name: str) -> bool:
        """Check if variable is a taint source"""
        return var_name in self.SOURCES

    def _contains_tainted_var(self, expr: str, tainted_vars: Set[str]) -> bool:
        """Check if expression contains any tainted variable"""
        for var in tainted_vars:
            if var in expr:
                return True
        # Check for superglobals
        for source in self.SOURCES:
            if source in expr:
                return True
        return False

    def _extract_sanitizers(self, expr: str) -> Dict[str, List[str]]:
        """
        Extract sanitizers from expression and return what they protect against
        Returns: {sanitizer_name: [vuln_types_protected]}
        """
        found_sanitizers = {}

        for vuln_type, sanitizers in self.SANITIZERS.items():
            for san_name in sanitizers:
                # Check for function call
                if san_name + '(' in expr:
                    if san_name not in found_sanitizers:
                        found_sanitizers[san_name] = []
                    if vuln_type not in found_sanitizers[san_name]:
                        found_sanitizers[san_name].append(vuln_type)
                # Check for type casting
                elif san_name.startswith('(') and san_name in expr:
                    if san_name not in found_sanitizers:
                        found_sanitizers[san_name] = []
                    if vuln_type not in found_sanitizers[san_name]:
                        found_sanitizers[san_name].append(vuln_type)

        return found_sanitizers

    def _is_sanitized_for(self, expr: str, sink_type: str) -> Tuple[bool, Optional[str]]:
        """Check if expression is sanitized for given sink type"""
        sanitizers = self.SANITIZERS.get(sink_type, {})

        for san in sanitizers:
            if san + '(' in expr:
                return True, san
            if san.startswith('(') and san in expr:
                return True, san

        # Also check for type casting
        if sink_type == 'SQL_INJECTION':
            if '(int)' in expr or 'intval(' in expr:
                return True, 'intval'
            if '(float)' in expr or 'floatval(' in expr:
                return True, 'floatval'

        return False, None

    def trace_taint(self, tree, code: str) -> List[TaintFlow]:
        """
        Trace taint from sources to sinks with proper sanitization tracking

        Algorithm:
        1. Find all taint sources
        2. Propagate taint through assignments, tracking sanitization
        3. Check if taint reaches sinks
        4. Check for sanitization matching sink type
        """
        flows = []

        # Get all assignments and sinks
        assignments = self.find_assignments(tree, code)
        sinks = self.find_sinks(tree, code)

        # Track tainted variables with their sanitization status
        # var -> (source, source_line, {vuln_type: is_sanitized}, sanitizer)
        tainted: Dict[str, Dict] = {}

        # Initialize with superglobals
        for source in self.SOURCES:
            tainted[source] = {
                'source': source,
                'source_line': 0,
                'sanitized_for': {},  # vuln_type -> sanitizer
                'all_sanitizers': [],
            }

        # Propagate taint through assignments (forward analysis)
        for var, value, line in sorted(assignments, key=lambda x: x[2]):
            if self._contains_tainted_var(value, set(tainted.keys())):
                # Extract sanitizers from this assignment
                sanitizers_used = self._extract_sanitizers(value)

                # Find which tainted var is in the value
                source_var = None
                for tv in tainted:
                    if tv in value:
                        source_var = tv
                        break

                if source_var:
                    # Copy taint info from source
                    source_info = tainted[source_var]

                    # Create new taint info for this variable
                    new_sanitized_for = dict(source_info.get('sanitized_for', {}))
                    new_all_sanitizers = list(source_info.get('all_sanitizers', []))

                    # Add any new sanitizers
                    for san_name, vuln_types in sanitizers_used.items():
                        new_all_sanitizers.append(san_name)
                        for vuln_type in vuln_types:
                            if vuln_type not in new_sanitized_for:
                                new_sanitized_for[vuln_type] = san_name

                    tainted[var] = {
                        'source': source_info['source'],
                        'source_line': source_info['source_line'],
                        'sanitized_for': new_sanitized_for,
                        'all_sanitizers': new_all_sanitizers,
                    }

        # Check sinks for tainted data
        for sink_type, func_name, line, args in sinks:
            for arg in args:
                if self._contains_tainted_var(arg, set(tainted.keys())):
                    # Find the source variable
                    source_var = None
                    for tv in tainted:
                        if tv in arg:
                            source_var = tv
                            break

                    if source_var:
                        taint_info = tainted[source_var]

                        # Check if sanitized for this specific sink type
                        is_sanitized = sink_type in taint_info.get('sanitized_for', {})
                        sanitizer = taint_info.get('sanitized_for', {}).get(sink_type)

                        # Also check if the arg itself has inline sanitization
                        inline_san, inline_sanitizer = self._is_sanitized_for(arg, sink_type)
                        if inline_san:
                            is_sanitized = True
                            sanitizer = inline_sanitizer

                        flow = TaintFlow(
                            source=taint_info['source'],
                            source_line=taint_info['source_line'],
                            sink=f"{func_name}({arg[:50]}...)" if len(arg) > 50 else f"{func_name}({arg})",
                            sink_line=line,
                            sink_type=sink_type,
                            path=[(taint_info['source'], taint_info['source_line']), (arg, line)],
                            is_sanitized=is_sanitized,
                            sanitizer=sanitizer
                        )
                        flows.append(flow)

        return flows

    def find_functions(self, tree, code: str) -> List[FunctionInfo]:
        """Find all function definitions with analysis"""
        code_bytes = bytes(code, 'utf8')
        functions = []

        def visit(node):
            if node.type in ['function_definition', 'method_declaration']:
                name_node = node.child_by_field_name('name')
                params_node = node.child_by_field_name('parameters')
                body_node = node.child_by_field_name('body')

                if name_node:
                    func_name = self.get_node_text(name_node, code_bytes)

                    # Get parameters
                    params = []
                    if params_node:
                        for param in params_node.children:
                            if param.type == 'simple_parameter':
                                var_node = param.child_by_field_name('name')
                                if var_node:
                                    params.append(self.get_node_text(var_node, code_bytes))

                    # Analyze if this is a sanitizer function
                    is_sanitizer = False
                    sanitizes_for = []

                    # Check function name for sanitizer hints
                    sanitizer_hints = ['sanitize', 'clean', 'escape', 'filter', 'safe', 'validate']
                    if any(hint in func_name.lower() for hint in sanitizer_hints):
                        is_sanitizer = True
                        # Guess what it sanitizes based on name
                        if any(x in func_name.lower() for x in ['sql', 'query', 'db']):
                            sanitizes_for.append('SQL_INJECTION')
                        if any(x in func_name.lower() for x in ['html', 'xss', 'output']):
                            sanitizes_for.append('XSS')
                        if any(x in func_name.lower() for x in ['shell', 'cmd', 'command']):
                            sanitizes_for.append('COMMAND_INJECTION')
                        if not sanitizes_for:  # Generic sanitizer
                            sanitizes_for = ['SQL_INJECTION', 'XSS']

                    func_info = FunctionInfo(
                        name=func_name,
                        file=self.current_file,
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                        params=params,
                        is_sanitizer=is_sanitizer,
                        sanitizes_for=sanitizes_for,
                    )
                    functions.append(func_info)

            for child in node.children:
                visit(child)

        visit(tree.root_node)
        return functions

    def build_cfg(self, tree, code: str) -> List[CFGNode]:
        """Build Control Flow Graph from AST"""
        code_bytes = bytes(code, 'utf8')
        self.cfg_nodes = []
        self._node_counter = 0

        def create_node(node, node_type: str) -> CFGNode:
            self._node_counter += 1
            cfg_node = CFGNode(
                id=self._node_counter,
                line=node.start_point[0] + 1,
                node_type=node_type,
                code=self.get_node_text(node, code_bytes)[:100],
            )
            self.cfg_nodes.append(cfg_node)
            return cfg_node

        def visit(node, prev_node: Optional[CFGNode] = None) -> Optional[CFGNode]:
            current = None

            # Create CFG nodes for important statements
            if node.type in ['if_statement', 'while_statement', 'for_statement',
                           'foreach_statement', 'switch_statement']:
                current = create_node(node, node.type)
                if prev_node:
                    prev_node.successors.append(current.id)
                    current.predecessors.append(prev_node.id)

            elif node.type == 'expression_statement':
                current = create_node(node, 'statement')
                if prev_node:
                    prev_node.successors.append(current.id)
                    current.predecessors.append(prev_node.id)

            elif node.type == 'return_statement':
                current = create_node(node, 'return')
                if prev_node:
                    prev_node.successors.append(current.id)
                    current.predecessors.append(prev_node.id)

            # Recurse into children
            last_node = current if current else prev_node
            for child in node.children:
                result = visit(child, last_node)
                if result:
                    last_node = result

            return current if current else last_node

        visit(tree.root_node)
        return self.cfg_nodes

    def analyze(self, code: str, filename: str = "") -> Dict:
        """
        Full AST-based analysis

        Returns:
        - variables: All variables with taint info
        - functions: Function/method definitions
        - calls: Function calls
        - sinks: Potential sinks
        - flows: Taint flows from source to sink
        - cfg: Control Flow Graph nodes
        """
        tree = self.parse(code, filename)

        return {
            'variables': self.find_variables(tree, code),
            'assignments': self.find_assignments(tree, code),
            'calls': self.find_function_calls(tree, code),
            'sinks': self.find_sinks(tree, code),
            'functions': self.find_functions(tree, code),
            'flows': self.trace_taint(tree, code),
            'cfg': self.build_cfg(tree, code),
        }

    def get_vulnerable_flows(self, code: str, filename: str = "") -> List[TaintFlow]:
        """Get only vulnerable (unsanitized) flows"""
        tree = self.parse(code, filename)
        flows = self.trace_taint(tree, code)
        return [f for f in flows if not f.is_sanitized]


def test():
    """Test AST parser"""
    parser = PHPASTParser()

    test_code = '''<?php
$id = $_GET["id"];
$name = htmlspecialchars($_POST["name"]);
$result = mysql_query("SELECT * FROM users WHERE id = " . $id);
echo $name;
echo $_GET["xss"];
include($_GET["page"] . ".php");
$safe_id = intval($_GET["uid"]);
$result2 = mysql_query("SELECT * FROM users WHERE id = " . $safe_id);
'''

    print("=" * 60)
    print("AST PARSER TEST v4.0")
    print("=" * 60)

    result = parser.analyze(test_code, "test.php")

    print(f"\nVariables found: {len(result['variables'])}")
    for v in result['variables'][:5]:
        print(f"  {v.name} (line {v.line}, tainted={v.is_tainted})")

    print(f"\nAssignments: {len(result['assignments'])}")
    for var, val, line in result['assignments']:
        print(f"  {var} = {val[:40]}... (line {line})")

    print(f"\nFunctions: {len(result['functions'])}")
    for f in result['functions']:
        san_info = f" [SANITIZER for {f.sanitizes_for}]" if f.is_sanitizer else ""
        print(f"  {f.name}() lines {f.start_line}-{f.end_line}{san_info}")

    print(f"\nSinks: {len(result['sinks'])}")
    for sink_type, func, line, args in result['sinks']:
        print(f"  [{sink_type}] {func}() at line {line}")

    print(f"\nTaint Flows: {len(result['flows'])}")
    for flow in result['flows']:
        status = "SANITIZED" if flow.is_sanitized else "VULNERABLE"
        print(f"  [{status}] {flow.source} -> {flow.sink} (line {flow.sink_line})")
        if flow.sanitizer:
            print(f"    Sanitizer: {flow.sanitizer}")
        print(f"    Sink Type: {flow.sink_type}")

    print(f"\nCFG Nodes: {len(result['cfg'])}")
    for node in result['cfg'][:5]:
        print(f"  Node {node.id}: {node.node_type} at line {node.line}")

    # Show only vulnerable flows
    print("\n" + "=" * 60)
    print("VULNERABLE FLOWS ONLY:")
    print("=" * 60)
    vuln_flows = parser.get_vulnerable_flows(test_code, "test.php")
    for flow in vuln_flows:
        print(f"  {flow.source} -> {flow.sink}")
        print(f"    Sink Type: {flow.sink_type}, Line: {flow.sink_line}")


if __name__ == "__main__":
    test()
