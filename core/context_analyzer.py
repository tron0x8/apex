#!/usr/bin/env python3
"""
Advanced Context Analyzer for APEX v2.0
Comprehensive false positive detection with:
1. Whitelist detection (in_array, switch/case, isset, ctype_*, preg_match)
2. Custom function analysis
3. Inter-file session/global tracking
4. Business logic / Auth context
5. Type casting detection
6. ORM/Query Builder detection
7. Dead code path analysis
8. AST-based data flow tracking
"""

import re
import os
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

try:
    from .rule_engine import get_rule_engine
except ImportError:
    get_rule_engine = None


@dataclass
class WhitelistCheck:
    variable: str
    allowed_values: List[str]
    line: int
    check_type: str


@dataclass
class CustomFunction:
    name: str
    file: str
    has_sanitizer: bool
    sanitizer_type: Set[str]
    params_sanitized: Set[int]


@dataclass
class SessionTaint:
    key: str
    source_file: str
    source_line: int
    tainted: bool
    sanitized: bool


@dataclass
class AuthContext:
    has_auth_check: bool
    auth_type: str
    check_line: int
    confidence: float


@dataclass
class TypeCast:
    variable: str
    cast_type: str
    line: int
    safe_for: Set[str]


@dataclass
class ORMUsage:
    variable: str
    orm_type: str
    line: int
    is_safe: bool


@dataclass
class DeadCodeBlock:
    start_line: int
    end_line: int
    reason: str


@dataclass
class DataFlowNode:
    variable: str
    line: int
    node_type: str  # 'source', 'sanitizer', 'sink', 'assignment'
    tainted: bool
    sanitized_for: Set[str]


class TypeCastDetector:
    """Detects type casting that neutralizes vulnerabilities"""

    SAFE_CASTS = {
        'int': {'sql', 'xss', 'cmd', 'file'},
        'integer': {'sql', 'xss', 'cmd', 'file'},
        'float': {'sql', 'xss'},
        'double': {'sql', 'xss'},
        'bool': {'sql', 'xss', 'cmd', 'file'},
        'boolean': {'sql', 'xss', 'cmd', 'file'},
    }

    SAFE_FUNCTIONS = {
        'intval': {'sql', 'xss', 'cmd', 'file'},
        'floatval': {'sql', 'xss'},
        'boolval': {'sql', 'xss', 'cmd', 'file'},
        'abs': {'sql', 'xss'},
        'round': {'sql', 'xss'},
        'floor': {'sql', 'xss'},
        'ceil': {'sql', 'xss'},
        'ord': {'sql', 'xss'},
        'chr': set(),
        'strlen': {'sql', 'xss', 'cmd', 'file'},
        'count': {'sql', 'xss', 'cmd', 'file'},
    }

    def __init__(self, code: str):
        self.code = code
        self.lines = code.split('\n')
        self.casts: Dict[str, TypeCast] = {}
        self._analyze()

    def _analyze(self):
        for i, line in enumerate(self.lines, 1):
            # Pattern 1: $target = (type)$source - target variable becomes safe
            m = re.search(r'(\$\w+)\s*=\s*\((\w+)\)\s*(.+?)\s*;', line)
            if m:
                target_var = m.group(1)
                cast_type = m.group(2).lower()
                if cast_type in self.SAFE_CASTS:
                    self.casts[target_var] = TypeCast(target_var, cast_type, i, self.SAFE_CASTS[cast_type])

            # Pattern 2: $var = intval($input) / floatval($input) etc
            for func, safe_for in self.SAFE_FUNCTIONS.items():
                pattern = rf'(\$\w+)\s*=\s*{func}\s*\('
                m = re.search(pattern, line, re.I)
                if m:
                    result_var = m.group(1)
                    self.casts[result_var] = TypeCast(result_var, func, i, safe_for)

            # Pattern 3: Direct cast in expression without assignment
            # e.g., query("... WHERE id = " . (int)$_GET['id'])
            for m in re.finditer(r'\((\w+)\)\s*(\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\])', line):
                cast_type = m.group(1).lower()
                source_var = m.group(2)
                if cast_type in self.SAFE_CASTS:
                    self.casts[source_var] = TypeCast(source_var, cast_type, i, self.SAFE_CASTS[cast_type])

    def is_type_safe(self, var: str, vuln_type: str, line: int) -> Tuple[bool, str]:
        vuln_lower = vuln_type.lower()
        var_normalized = var.replace(' ', '').replace('"', "'")

        for cast_var, cast in self.casts.items():
            cast_var_normalized = cast_var.replace(' ', '').replace('"', "'")
            if cast_var_normalized in var_normalized or var_normalized in cast_var_normalized:
                if cast.line <= line:
                    for vuln_key in ['sql', 'xss', 'cmd', 'file', 'lfi', 'rfi', 'rce', 'injection']:
                        if vuln_key in vuln_lower:
                            check_type = 'sql' if 'sql' in vuln_key else \
                                        'xss' if 'xss' in vuln_key else \
                                        'cmd' if vuln_key in ['cmd', 'rce'] else \
                                        'file' if vuln_key in ['file', 'lfi', 'rfi'] else vuln_key
                            if check_type in cast.safe_for:
                                return True, f"Type cast ({cast.cast_type}) on line {cast.line}"
        return False, ""


class ORMDetector:
    """Detects ORM and Query Builder usage that prevents SQL injection"""

    ORM_PATTERNS = [
        # Laravel Eloquent
        (r'(\w+)::where\s*\(\s*[\'"][^\'"]+[\'"]\s*,\s*\$', 'eloquent', True),
        (r'(\w+)::find\s*\(\s*\$', 'eloquent', True),
        (r'(\w+)::findOrFail\s*\(\s*\$', 'eloquent', True),
        (r'->where\s*\(\s*[\'"][^\'"]+[\'"]\s*,\s*\$', 'eloquent', True),
        (r'->whereIn\s*\(\s*[\'"][^\'"]+[\'"]\s*,', 'eloquent', True),
        (r'->first\s*\(\s*\)', 'eloquent', True),
        (r'->get\s*\(\s*\)', 'eloquent', True),
        (r'->pluck\s*\(', 'eloquent', True),

        # PDO Prepared Statements
        (r'->prepare\s*\(\s*[\'"]', 'pdo_prepared', True),
        (r'->execute\s*\(\s*\[', 'pdo_prepared', True),
        (r'->bindParam\s*\(', 'pdo_prepared', True),
        (r'->bindValue\s*\(', 'pdo_prepared', True),
        (r'\?\s*,?\s*\)', 'pdo_placeholder', True),  # ? placeholder
        (r':\w+', 'pdo_named', True),  # :name placeholder

        # MySQLi Prepared
        (r'mysqli_prepare\s*\(', 'mysqli_prepared', True),
        (r'->prepare\s*\(\s*[\'"].*\?\s*', 'mysqli_prepared', True),
        (r'mysqli_stmt_bind_param\s*\(', 'mysqli_prepared', True),
        (r'->bind_param\s*\(', 'mysqli_prepared', True),

        # Doctrine
        (r'->createQueryBuilder\s*\(', 'doctrine', True),
        (r'->setParameter\s*\(', 'doctrine', True),
        (r'->getRepository\s*\(', 'doctrine', True),
        (r'->find\s*\(\s*\$', 'doctrine', True),

        # WordPress
        (r'\$wpdb->prepare\s*\(', 'wpdb_prepared', True),
        (r'\$wpdb->get_var\s*\(\s*\$wpdb->prepare', 'wpdb_prepared', True),
        (r'\$wpdb->get_row\s*\(\s*\$wpdb->prepare', 'wpdb_prepared', True),
        (r'\$wpdb->get_results\s*\(\s*\$wpdb->prepare', 'wpdb_prepared', True),

        # CodeIgniter
        (r'->where\s*\(\s*[\'"][^\'"]+[\'"]\s*,\s*\$', 'codeigniter', True),
        (r'->get\s*\(\s*[\'"]', 'codeigniter', True),
        (r'->insert\s*\(\s*[\'"][^\'"]+[\'"]\s*,\s*\$', 'codeigniter', True),

        # Raw queries (NOT safe)
        (r'mysql_query\s*\(\s*[\'"].*\$', 'raw_mysql', False),
        (r'mysqli_query\s*\(\s*\$\w+\s*,\s*[\'"].*\$', 'raw_mysqli', False),
        (r'->query\s*\(\s*[\'"].*\$', 'raw_query', False),
    ]

    def __init__(self, code: str, rule_engine=None):
        self.code = code
        self.lines = code.split('\n')
        self.orm_usages: List[ORMUsage] = []
        self._effective_orm_patterns = list(self.ORM_PATTERNS)
        self._load_orm_patterns_from_engine(rule_engine)
        self._analyze()

    def _load_orm_patterns_from_engine(self, rule_engine=None):
        """Extend ORM_PATTERNS from RuleEngine fp_rules orm_patterns category."""
        try:
            if rule_engine is None and get_rule_engine is not None:
                rule_engine = get_rule_engine()
            if rule_engine is None:
                return

            fp_rules = rule_engine.get_fp_rules()
            if not fp_rules:
                return

            orm_rules = fp_rules.get('orm_patterns', []) + fp_rules.get('orm', []) + fp_rules.get('prepared_stmt', [])
            existing_patterns = {p[0] for p in self._effective_orm_patterns}

            for rule in orm_rules:
                if rule.pattern and rule.pattern not in existing_patterns:
                    # Determine orm_type from rule name or default
                    orm_type = rule.name if rule.name else 'rule_engine'
                    self._effective_orm_patterns.append(
                        (rule.pattern, orm_type, True)
                    )
        except Exception:
            # If RuleEngine fails, fall back to hardcoded patterns silently
            pass

    def _analyze(self):
        for i, line in enumerate(self.lines, 1):
            for pattern, orm_type, is_safe in self._effective_orm_patterns:
                if re.search(pattern, line, re.I):
                    var_match = re.search(r'(\$\w+)', line)
                    var = var_match.group(1) if var_match else ''
                    self.orm_usages.append(ORMUsage(var, orm_type, i, is_safe))

    def is_orm_protected(self, line: int, context_lines: int = 5) -> Tuple[bool, str]:
        for usage in self.orm_usages:
            if abs(usage.line - line) <= context_lines and usage.is_safe:
                return True, f"ORM/Prepared statement ({usage.orm_type}) on line {usage.line}"
        return False, ""

    def has_prepared_statement(self, start_line: int, end_line: int) -> bool:
        for usage in self.orm_usages:
            if start_line <= usage.line <= end_line and usage.is_safe:
                if 'prepared' in usage.orm_type or usage.orm_type in ['eloquent', 'doctrine', 'codeigniter']:
                    return True
        return False


class DeadCodeAnalyzer:
    """Detects dead code paths that will never execute"""

    def __init__(self, code: str):
        self.code = code
        self.lines = code.split('\n')
        self.dead_blocks: List[DeadCodeBlock] = []
        self._analyze()

    def _analyze(self):
        for i, line in enumerate(self.lines, 1):
            # Pattern 1: if (false) { ... }
            if re.search(r'if\s*\(\s*false\s*\)', line, re.I):
                end = self._find_block_end(i)
                self.dead_blocks.append(DeadCodeBlock(i, end, 'if(false)'))

            # Pattern 2: if (0) { ... }
            if re.search(r'if\s*\(\s*0\s*\)', line):
                end = self._find_block_end(i)
                self.dead_blocks.append(DeadCodeBlock(i, end, 'if(0)'))

            # Pattern 3: if (1 == 0) or similar
            if re.search(r'if\s*\(\s*\d+\s*[=!]=+\s*\d+\s*\)', line):
                m = re.search(r'if\s*\(\s*(\d+)\s*([=!]=+)\s*(\d+)\s*\)', line)
                if m:
                    a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
                    is_dead = False
                    if op in ['==', '==='] and a != b:
                        is_dead = True
                    elif op in ['!=', '!=='] and a == b:
                        is_dead = True
                    if is_dead:
                        end = self._find_block_end(i)
                        self.dead_blocks.append(DeadCodeBlock(i, end, f'if({a}{op}{b})'))

            # Pattern 4: return/die/exit before code
            if re.search(r'^\s*(return|die|exit)\s*[;(]', line):
                block_end = self._find_block_end_from_here(i)
                if block_end > i:
                    self.dead_blocks.append(DeadCodeBlock(i + 1, block_end, 'after return/die/exit'))

            # Pattern 5: Commented out code block
            if re.search(r'/\*.*\$_(GET|POST|REQUEST)', line):
                end = i
                for j in range(i, min(len(self.lines), i + 50)):
                    if '*/' in self.lines[j]:
                        end = j + 1
                        break
                self.dead_blocks.append(DeadCodeBlock(i, end, 'commented code'))

    def _find_block_end(self, start_line: int) -> int:
        brace_count = 0
        started = False
        for i in range(start_line - 1, min(len(self.lines), start_line + 100)):
            line = self.lines[i]
            if '{' in line:
                started = True
                brace_count += line.count('{')
            brace_count -= line.count('}')
            if started and brace_count <= 0:
                return i + 1
        return start_line

    def _find_block_end_from_here(self, line: int) -> int:
        brace_count = 0
        for i in range(line - 1, -1, -1):
            brace_count += self.lines[i].count('{')
            brace_count -= self.lines[i].count('}')

        for i in range(line, len(self.lines)):
            brace_count -= self.lines[i].count('{')
            brace_count += self.lines[i].count('}')
            if brace_count >= 0:
                return i + 1
        return line

    def is_dead_code(self, line: int) -> Tuple[bool, str]:
        for block in self.dead_blocks:
            if block.start_line <= line <= block.end_line:
                return True, f"Dead code ({block.reason}) lines {block.start_line}-{block.end_line}"
        return False, ""


class ExtendedWhitelistDetector:
    """Extended whitelist detection with more patterns"""

    def __init__(self, code: str):
        self.code = code
        self.lines = code.split('\n')
        self.whitelists: Dict[str, WhitelistCheck] = {}
        self._analyze()

    def _analyze(self):
        for i, line in enumerate(self.lines, 1):
            # Pattern 1: in_array check
            m = re.search(r'in_array\s*\(\s*(\$[^,]+),\s*(\[[^\]]+\]|\$\w+)', line)
            if m:
                var = m.group(1).strip()
                values = m.group(2)
                allowed = self._extract_array_values(values)
                self.whitelists[var] = WhitelistCheck(var, allowed, i, 'in_array')

            # Pattern 2: switch/case
            m = re.search(r'switch\s*\(\s*(\$[\w\[\]\'"]+)', line)
            if m:
                var = m.group(1)
                cases = self._extract_switch_cases(i)
                if cases:
                    self.whitelists[var] = WhitelistCheck(var, cases, i, 'switch')

            # Pattern 3: strict comparison
            m = re.search(r'if\s*\(\s*(\$\w+)\s*===?\s*[\'"](\w+)[\'"]', line)
            if m:
                var = m.group(1)
                values = re.findall(r'===?\s*[\'"](\w+)[\'"]', line)
                if values:
                    self.whitelists[var] = WhitelistCheck(var, values, i, 'strict_compare')

            # Pattern 4: isset with array key check
            # if (isset($allowed[$key]))
            m = re.search(r'isset\s*\(\s*\$\w+\s*\[\s*(\$[\w\[\]\'"]+)\s*\]', line)
            if m:
                var = m.group(1)
                if var not in self.whitelists:
                    self.whitelists[var] = WhitelistCheck(var, ['<array_key>'], i, 'isset_key')

            # Pattern 5: array_key_exists
            m = re.search(r'array_key_exists\s*\(\s*(\$[\w\[\]\'"]+)\s*,', line)
            if m:
                var = m.group(1)
                if var not in self.whitelists:
                    self.whitelists[var] = WhitelistCheck(var, ['<array_key>'], i, 'array_key_exists')

            # Pattern 6: ctype_* functions
            for ctype in ['ctype_alnum', 'ctype_alpha', 'ctype_digit', 'ctype_xdigit']:
                m = re.search(rf'{ctype}\s*\(\s*(\$[\w\[\]\'"]+)', line)
                if m:
                    var = m.group(1)
                    if var not in self.whitelists:
                        self.whitelists[var] = WhitelistCheck(var, [f'<{ctype}>'], i, ctype)

            # Pattern 7: preg_match validation
            # if (preg_match('/^[a-z0-9]+$/', $var))
            m = re.search(r'preg_match\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*(\$[\w\[\]\'"]+)', line)
            if m:
                pattern = m.group(1)
                var = m.group(2)
                # Check if it's a restrictive pattern
                if re.search(r'\^.*\$', pattern):  # Anchored pattern
                    if re.search(r'\[[\w-]+\][\+\*]', pattern):  # Character class
                        if var not in self.whitelists:
                            self.whitelists[var] = WhitelistCheck(var, [pattern], i, 'preg_match')

            # Pattern 8: filter_var with validation
            m = re.search(r'filter_var\s*\(\s*(\$[\w\[\]\'"]+)\s*,\s*FILTER_VALIDATE', line)
            if m:
                var = m.group(1)
                if var not in self.whitelists:
                    filter_type = re.search(r'FILTER_VALIDATE_(\w+)', line)
                    ftype = filter_type.group(1) if filter_type else 'UNKNOWN'
                    self.whitelists[var] = WhitelistCheck(var, [f'<filter_{ftype}>'], i, 'filter_var')

            # Pattern 9: is_numeric
            m = re.search(r'is_numeric\s*\(\s*(\$[\w\[\]\'"]+)', line)
            if m:
                var = m.group(1)
                if var not in self.whitelists:
                    self.whitelists[var] = WhitelistCheck(var, ['<numeric>'], i, 'is_numeric')

            # Pattern 10: Enum/constant comparison
            m = re.search(r'(\$\w+)\s*===?\s*([A-Z][A-Z0-9_]+)', line)
            if m:
                var = m.group(1)
                const = m.group(2)
                if var not in self.whitelists:
                    self.whitelists[var] = WhitelistCheck(var, [const], i, 'constant_compare')

    def _extract_array_values(self, arr_str: str) -> List[str]:
        if arr_str.startswith('$'):
            return []
        matches = re.findall(r'[\'"]([^\'"]+)[\'"]', arr_str)
        return matches

    def _extract_switch_cases(self, switch_line: int) -> List[str]:
        cases = []
        brace_count = 0
        started = False
        for i in range(switch_line - 1, min(len(self.lines), switch_line + 50)):
            line = self.lines[i]
            if '{' in line:
                started = True
                brace_count += line.count('{')
            brace_count -= line.count('}')
            if started and brace_count <= 0:
                break
            m = re.search(r'case\s+[\'"]([^\'"]+)[\'"]', line)
            if m:
                cases.append(m.group(1))
        return cases

    def is_whitelisted(self, var: str, line: int) -> Tuple[bool, str]:
        var_normalized = var.replace(' ', '').replace('"', "'")

        for wl_var, wl in self.whitelists.items():
            wl_var_normalized = wl_var.replace(' ', '').replace('"', "'")
            if wl_var_normalized in var_normalized or var_normalized in wl_var_normalized:
                if wl.line <= line:
                    vals = wl.allowed_values[:3] if len(wl.allowed_values) <= 3 else wl.allowed_values[:2] + ['...']
                    return True, f"Whitelist ({wl.check_type}) on line {wl.line}: {vals}"
        return False, ""


class DataFlowTracker:
    """AST-like data flow tracking for taint analysis"""

    SOURCES = [
        r'\$_GET\s*\[',
        r'\$_POST\s*\[',
        r'\$_REQUEST\s*\[',
        r'\$_COOKIE\s*\[',
        r'\$_FILES\s*\[',
        r'\$_SERVER\s*\[\s*[\'"](?:HTTP_|REQUEST_|QUERY_)',
        r'file_get_contents\s*\(\s*[\'"]php://input',
        r'getenv\s*\(',
        r'apache_request_headers\s*\(',
    ]

    SANITIZERS = {
        'sql': [
            r'mysqli_real_escape_string', r'mysql_real_escape_string',
            r'addslashes', r'->quote\(', r'->prepare\(',
            r'intval', r'floatval', r'\(int\)', r'\(float\)',
            r'pg_escape_string', r'sqlite_escape_string',
        ],
        'xss': [
            r'htmlspecialchars', r'htmlentities', r'strip_tags',
            r'esc_html', r'esc_attr', r'wp_kses',
            r'Purifier', r'clean\(',
        ],
        'cmd': [
            r'escapeshellarg', r'escapeshellcmd',
        ],
        'file': [
            r'basename', r'realpath',
            r'pathinfo\s*\([^)]+,\s*PATHINFO_BASENAME',
        ],
    }

    def __init__(self, code: str):
        self.code = code
        self.lines = code.split('\n')
        self.nodes: List[DataFlowNode] = []
        self.var_states: Dict[str, DataFlowNode] = {}
        self._analyze()

    def _analyze(self):
        for i, line in enumerate(self.lines, 1):
            # Track sources
            for src_pattern in self.SOURCES:
                for m in re.finditer(src_pattern, line):
                    var_match = re.search(r'(\$_\w+\s*\[[^\]]+\])', line[m.start():])
                    if var_match:
                        var = var_match.group(1)
                        node = DataFlowNode(var, i, 'source', True, set())
                        self.nodes.append(node)
                        self.var_states[self._normalize_var(var)] = node

            # Track assignments: $var = $source
            m = re.search(r'(\$\w+)\s*=\s*(.+?)[;\n]', line)
            if m:
                target = m.group(1)
                expr = m.group(2)

                # Check if expression contains tainted var
                is_tainted = False
                sanitized_for = set()

                for var, state in self.var_states.items():
                    if var in expr.replace(' ', ''):
                        if state.tainted:
                            is_tainted = True
                            sanitized_for = state.sanitized_for.copy()

                # Check if expression contains source
                for src_pattern in self.SOURCES:
                    if re.search(src_pattern, expr):
                        is_tainted = True
                        break

                # Check for sanitizers in expression
                for san_type, patterns in self.SANITIZERS.items():
                    for p in patterns:
                        if re.search(p, expr, re.I):
                            sanitized_for.add(san_type)

                if is_tainted or sanitized_for:
                    node = DataFlowNode(target, i, 'assignment', is_tainted and not sanitized_for, sanitized_for)
                    self.nodes.append(node)
                    self.var_states[self._normalize_var(target)] = node

    def _normalize_var(self, var: str) -> str:
        return var.replace(' ', '').replace('"', "'")

    def is_var_tainted(self, var: str, line: int) -> Tuple[bool, Set[str]]:
        var_norm = self._normalize_var(var)

        # Check direct match
        if var_norm in self.var_states:
            state = self.var_states[var_norm]
            if state.line <= line:
                return state.tainted, state.sanitized_for

        # Check partial match (e.g., $var matches $_GET['var'])
        for state_var, state in self.var_states.items():
            if state_var in var_norm or var_norm in state_var:
                if state.line <= line:
                    return state.tainted, state.sanitized_for

        return False, set()

    def get_taint_chain(self, var: str, line: int) -> List[DataFlowNode]:
        chain = []
        var_norm = self._normalize_var(var)

        for node in sorted(self.nodes, key=lambda n: n.line):
            if node.line <= line:
                node_var_norm = self._normalize_var(node.variable)
                if node_var_norm in var_norm or var_norm in node_var_norm:
                    chain.append(node)

        return chain


class CustomFunctionAnalyzer:
    """Analyzes custom functions to detect sanitization"""

    SANITIZER_PATTERNS = {
        'sql': [r'mysql_real_escape', r'mysqli_real_escape', r'addslashes', r'intval', r'->prepare', r'->quote'],
        'xss': [r'htmlspecialchars', r'htmlentities', r'strip_tags', r'esc_html'],
        'cmd': [r'escapeshellarg', r'escapeshellcmd'],
        'file': [r'basename', r'realpath'],
    }

    def __init__(self, code: str, file_path: str = ''):
        self.code = code
        self.file_path = file_path
        self.functions: Dict[str, CustomFunction] = {}
        self._analyze()

    def _analyze(self):
        pattern = r'function\s+(\w+)\s*\(([^)]*)\)\s*\{'
        for m in re.finditer(pattern, self.code):
            func_name = m.group(1)
            func_start = m.end()
            func_body = self._extract_function_body(func_start)

            sanitizer_types = set()
            for san_type, patterns in self.SANITIZER_PATTERNS.items():
                for p in patterns:
                    if re.search(p, func_body, re.I):
                        sanitizer_types.add(san_type)

            params_sanitized = set()
            if sanitizer_types and 'return' in func_body:
                params_sanitized.add(0)

            self.functions[func_name] = CustomFunction(
                name=func_name,
                file=self.file_path,
                has_sanitizer=bool(sanitizer_types),
                sanitizer_type=sanitizer_types,
                params_sanitized=params_sanitized
            )

    def _extract_function_body(self, start: int) -> str:
        brace_count = 1
        i = start
        while i < len(self.code) and brace_count > 0:
            if self.code[i] == '{':
                brace_count += 1
            elif self.code[i] == '}':
                brace_count -= 1
            i += 1
        return self.code[start:i]

    def is_sanitizer_function(self, func_name: str) -> Tuple[bool, Set[str]]:
        if func_name in self.functions:
            f = self.functions[func_name]
            return f.has_sanitizer, f.sanitizer_type
        return False, set()


class InterFileTracker:
    """Tracks taint across files via session/globals"""

    def __init__(self, project_path: str = ''):
        self.project_path = project_path
        self.session_taints: Dict[str, SessionTaint] = {}
        self.global_taints: Dict[str, SessionTaint] = {}
        self.analyzed_files: Set[str] = set()

    def analyze_file(self, file_path: str, code: str):
        if file_path in self.analyzed_files:
            return
        self.analyzed_files.add(file_path)

        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            m = re.search(r"\$_SESSION\s*\[\s*['\"](\w+)['\"]\s*\]\s*=\s*(.+)", line)
            if m:
                key = m.group(1)
                value = m.group(2)
                tainted = bool(re.search(r'\$_(GET|POST|REQUEST|COOKIE)', value))
                sanitized = bool(re.search(r'htmlspecialchars|intval|escape', value, re.I))
                self.session_taints[key] = SessionTaint(key, file_path, i, tainted, sanitized)

            m = re.search(r"\$GLOBALS\s*\[\s*['\"](\w+)['\"]\s*\]\s*=\s*(.+)", line)
            if m:
                key = m.group(1)
                value = m.group(2)
                tainted = bool(re.search(r'\$_(GET|POST|REQUEST|COOKIE)', value))
                self.global_taints[key] = SessionTaint(key, file_path, i, tainted, False)

    def analyze_project(self):
        if not self.project_path:
            return
        for php_file in Path(self.project_path).rglob('*.php'):
            try:
                code = php_file.read_text(errors='ignore')
                self.analyze_file(str(php_file), code)
            except:
                pass

    def is_session_tainted(self, key: str) -> Tuple[bool, Optional[SessionTaint]]:
        if key in self.session_taints:
            t = self.session_taints[key]
            return t.tainted and not t.sanitized, t
        return False, None

    def get_session_source(self, key: str) -> Optional[str]:
        if key in self.session_taints:
            return f"{self.session_taints[key].source_file}:{self.session_taints[key].source_line}"
        return None


class AuthContextAnalyzer:
    """Analyzes authentication/authorization context"""

    AUTH_PATTERNS = [
        (r'if\s*\(\s*!\s*\$is_logged', 'user', 0.9),
        (r'if\s*\(\s*\$is_admin\s*\)', 'admin', 0.95),
        (r'if\s*\(\s*is_admin\s*\(\s*\)', 'admin', 0.95),
        (r'current_user_can\s*\(\s*[\'"]manage', 'admin', 0.9),
        (r'check_admin\s*\(', 'admin', 0.85),
        (r'\$member_id\s*\[\s*[\'"]user_group[\'"]\s*\]\s*==\s*1', 'admin', 0.9),
        (r'wp_verify_nonce', 'csrf', 0.7),
        (r'check_permission\s*\(', 'role', 0.8),
        (r'has_capability\s*\(', 'role', 0.8),
        (r'if\s*\(\s*\$_SESSION\s*\[\s*[\'"]admin[\'"]\s*\]', 'admin', 0.85),
    ]

    ADMIN_FILE_PATTERNS = [
        r'/admin/', r'/administrator/', r'admin\.php', r'admin_',
        r'_admin\.php', r'/backend/', r'/cp/', r'/dashboard/',
    ]

    def __init__(self, code: str, file_path: str = ''):
        self.code = code
        self.file_path = file_path
        self.lines = code.split('\n')

    def analyze(self, sink_line: int) -> AuthContext:
        is_admin_file = any(re.search(p, self.file_path, re.I) for p in self.ADMIN_FILE_PATTERNS)
        start = max(0, sink_line - 100)
        context = '\n'.join(self.lines[start:sink_line])

        best_match = AuthContext(False, 'none', 0, 0.0)

        for pattern, auth_type, confidence in self.AUTH_PATTERNS:
            m = re.search(pattern, context, re.I)
            if m:
                for i, line in enumerate(self.lines[start:sink_line], start + 1):
                    if re.search(pattern, line, re.I):
                        if auth_type == 'admin' or (confidence > best_match.confidence and best_match.auth_type != 'admin'):
                            best_match = AuthContext(True, auth_type, i, confidence)
                        break

        if is_admin_file and best_match.auth_type in ('admin', 'role'):
            best_match = AuthContext(
                best_match.has_auth_check or True,
                best_match.auth_type if best_match.has_auth_check else 'admin_file',
                best_match.check_line,
                min(1.0, best_match.confidence + 0.2) if best_match.has_auth_check else 0.6
            )

        return best_match

    def is_admin_protected(self, sink_line: int) -> Tuple[bool, str]:
        ctx = self.analyze(sink_line)
        if ctx.has_auth_check and ctx.auth_type in ('admin', 'role', 'admin_file'):
            return True, f"Admin check ({ctx.auth_type}) on line {ctx.check_line}"
        return False, ""


class AdvancedContextAnalyzer:
    """
    Main class combining ALL advanced context analysis.
    v2.0 with Type Casting, ORM, Dead Code, Extended Whitelist, Data Flow
    """

    def __init__(self, code: str, file_path: str = '', project_path: str = ''):
        self.code = code
        self.file_path = file_path
        self.project_path = project_path

        # Original analyzers
        self.whitelist = ExtendedWhitelistDetector(code)
        self.custom_funcs = CustomFunctionAnalyzer(code, file_path)
        self.auth = AuthContextAnalyzer(code, file_path)
        self.inter_file = InterFileTracker(project_path)

        # New analyzers (v2.0)
        self.type_cast = TypeCastDetector(code)
        self.orm = ORMDetector(code)
        self.dead_code = DeadCodeAnalyzer(code)
        self.data_flow = DataFlowTracker(code)

        if project_path:
            self.inter_file.analyze_project()

    def is_false_positive(self, sink_line: int, source_var: str, vuln_type: str) -> Tuple[bool, str]:
        """Comprehensive FP check with all analyzers"""

        # 1. Dead code check (highest priority)
        is_dead, reason = self.dead_code.is_dead_code(sink_line)
        if is_dead:
            return True, f"DEAD_CODE: {reason}"

        # 2. Type casting check
        is_cast_safe, reason = self.type_cast.is_type_safe(source_var, vuln_type, sink_line)
        if is_cast_safe:
            return True, f"TYPE_CAST: {reason}"

        # 3. ORM/Prepared statement check (for SQL only)
        if 'sql' in vuln_type.lower():
            is_orm_safe, reason = self.orm.is_orm_protected(sink_line)
            if is_orm_safe:
                return True, f"ORM_SAFE: {reason}"

        # 4. Whitelist check (extended)
        is_wl, reason = self.whitelist.is_whitelisted(source_var, sink_line)
        if is_wl:
            return True, f"WHITELIST: {reason}"

        # 5. Data flow tracking
        is_tainted, sanitized_for = self.data_flow.is_var_tainted(source_var, sink_line)
        if sanitized_for:
            vuln_lower = vuln_type.lower()
            for san_type in sanitized_for:
                if san_type in vuln_lower or \
                   (san_type == 'sql' and 'injection' in vuln_lower) or \
                   (san_type == 'xss' and 'cross' in vuln_lower):
                    return True, f"DATA_FLOW: Sanitized for {san_type}"

        # 6. Custom function sanitizer
        lines = self.code.split('\n')
        for i in range(max(0, sink_line - 20), sink_line):
            if i >= len(lines):
                continue
            line = lines[i]
            for func_name in self.custom_funcs.functions:
                if func_name + '(' in line and (source_var in line or self._var_key(source_var) in line):
                    is_san, san_types = self.custom_funcs.is_sanitizer_function(func_name)
                    if is_san:
                        vuln_lower = vuln_type.lower()
                        for san_type in san_types:
                            if san_type in vuln_lower:
                                return True, f"CUSTOM_FUNC: {func_name}() sanitizes {san_type}"

        # 7. Session tracking
        if '$_SESSION' in source_var:
            key_match = re.search(r"\$_SESSION\s*\[\s*['\"](\w+)['\"]", source_var)
            if key_match:
                key = key_match.group(1)
                is_tainted, taint_info = self.inter_file.is_session_tainted(key)
                if taint_info and not is_tainted:
                    return True, f"SESSION: Key '{key}' sanitized at source"

        # 8. Admin context (informational, doesn't filter)
        # Could be used to adjust severity

        return False, ""

    def get_analysis_summary(self, sink_line: int, source_var: str, vuln_type: str) -> Dict[str, Any]:
        """Get detailed analysis summary for debugging"""
        return {
            'dead_code': self.dead_code.is_dead_code(sink_line),
            'type_cast': self.type_cast.is_type_safe(source_var, vuln_type, sink_line),
            'orm': self.orm.is_orm_protected(sink_line),
            'whitelist': self.whitelist.is_whitelisted(source_var, sink_line),
            'data_flow': self.data_flow.is_var_tainted(source_var, sink_line),
            'auth': self.auth.analyze(sink_line),
        }

    def _var_key(self, var: str) -> str:
        m = re.search(r"\[\s*['\"](\w+)['\"]", var)
        return m.group(1) if m else var


def analyze_context(code: str, file_path: str = '', project_path: str = '') -> AdvancedContextAnalyzer:
    return AdvancedContextAnalyzer(code, file_path, project_path)
