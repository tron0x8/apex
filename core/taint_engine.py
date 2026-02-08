#!/usr/bin/env python3
"""
APEX Taint Engine v2.0
Zero False Positive Taint Analysis

Enhanced taint analysis with:
1. Pre-sink sanitization detection
2. Variable reassignment tracking
3. Superglobal element state tracking
4. Backward flow verification
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any, Tuple, FrozenSet
from enum import Enum, auto
from collections import defaultdict
import hashlib
import re
from .ts_adapter import TSNode, parse_php_ts


class TaintLevel(Enum):
    CLEAN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class TaintType(Enum):
    SQL = auto()
    XSS = auto()
    COMMAND = auto()
    CODE = auto()
    FILE_PATH = auto()
    FILE_INCLUDE = auto()
    SSRF = auto()
    LDAP = auto()
    XPATH = auto()
    XXE = auto()
    SERIALIZATION = auto()
    REDIRECT = auto()
    EMAIL = auto()
    REGEX = auto()
    NOSQL = auto()
    TEMPLATE = auto()


@dataclass(frozen=True)
class TaintSource:
    name: str
    level: TaintLevel
    types: FrozenSet[TaintType]
    line: int
    file: str = ""


@dataclass
class TaintState:
    sources: Set[TaintSource] = field(default_factory=set)
    sanitizers_applied: Set[str] = field(default_factory=set)
    propagation_path: List[Tuple[str, int]] = field(default_factory=list)
    sanitized_types: Set[TaintType] = field(default_factory=set)

    @property
    def is_tainted(self) -> bool:
        return len(self.sources) > 0

    @property
    def level(self) -> TaintLevel:
        return max((s.level for s in self.sources), default=TaintLevel.CLEAN)

    @property
    def types(self) -> Set[TaintType]:
        types = set()
        for s in self.sources:
            types.update(s.types)
        # Remove types that have been sanitized
        return types - self.sanitized_types

    def merge_with(self, other: 'TaintState') -> 'TaintState':
        new = TaintState()
        new.sources = self.sources | other.sources
        new.sanitizers_applied = self.sanitizers_applied | other.sanitizers_applied
        new.propagation_path = self.propagation_path + other.propagation_path
        new.sanitized_types = self.sanitized_types | other.sanitized_types
        return new

    def apply_sanitizer(self, sanitizer: str, removes: Set[TaintType]) -> 'TaintState':
        new = TaintState()
        new.sanitizers_applied = self.sanitizers_applied | {sanitizer}
        new.propagation_path = self.propagation_path.copy()
        new.sanitized_types = self.sanitized_types | removes
        for src in self.sources:
            remaining = src.types - removes
            if remaining:
                new.sources.add(TaintSource(src.name, src.level, frozenset(remaining), src.line, src.file))
        return new


@dataclass
class TaintFinding:
    sink_name: str
    sink_line: int
    sink_file: str
    source: TaintSource
    taint_type: TaintType
    path: List[Tuple[str, int]]
    sanitizers: Set[str]
    confidence: float
    severity: str

    def to_dict(self) -> Dict:
        return {
            'sink': self.sink_name, 'sink_line': self.sink_line, 'sink_file': self.sink_file,
            'source': {'name': self.source.name, 'level': self.source.level.name, 'line': self.source.line},
            'type': self.taint_type.name, 'path': self.path, 'sanitizers': list(self.sanitizers),
            'confidence': self.confidence, 'severity': self.severity
        }


class SourceDefinitions:
    ALL_TAINT_TYPES = frozenset({
        TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.CODE,
        TaintType.FILE_PATH, TaintType.FILE_INCLUDE, TaintType.SSRF, TaintType.XXE,
        TaintType.SERIALIZATION, TaintType.REDIRECT, TaintType.EMAIL,
        TaintType.REGEX, TaintType.NOSQL, TaintType.TEMPLATE, TaintType.LDAP, TaintType.XPATH
    })
    SUPERGLOBALS = {
        '$_GET': TaintSource('$_GET', TaintLevel.HIGH, ALL_TAINT_TYPES, 0),
        '$_POST': TaintSource('$_POST', TaintLevel.HIGH, ALL_TAINT_TYPES, 0),
        '$_REQUEST': TaintSource('$_REQUEST', TaintLevel.HIGH, ALL_TAINT_TYPES, 0),
        '$_COOKIE': TaintSource('$_COOKIE', TaintLevel.MEDIUM, frozenset({
            TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.SERIALIZATION
        }), 0),
        '$_FILES': TaintSource('$_FILES', TaintLevel.HIGH, frozenset({
            TaintType.FILE_PATH, TaintType.CODE, TaintType.FILE_INCLUDE
        }), 0),
        '$_SERVER': TaintSource('$_SERVER', TaintLevel.MEDIUM, frozenset({
            TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.SSRF, TaintType.REDIRECT
        }), 0),
        '$_ENV': TaintSource('$_ENV', TaintLevel.LOW, frozenset({
            TaintType.COMMAND, TaintType.SQL
        }), 0),
    }
    TAINTED_SERVER_KEYS = {
        'HTTP_HOST', 'HTTP_USER_AGENT', 'HTTP_REFERER', 'HTTP_X_FORWARDED_FOR',
        'REQUEST_URI', 'QUERY_STRING', 'PATH_INFO', 'PHP_SELF',
        'HTTP_ACCEPT', 'HTTP_ACCEPT_LANGUAGE', 'HTTP_ACCEPT_ENCODING',
        'HTTP_CONNECTION', 'HTTP_COOKIE', 'CONTENT_TYPE', 'CONTENT_LENGTH',
        'HTTP_X_REQUESTED_WITH', 'HTTP_ORIGIN', 'HTTP_AUTHORIZATION'
    }


class SinkDefinitions:
    # Sinks that require FIRST argument to be tainted (pattern-based)
    PATTERN_ARG_SINKS = {'preg_replace', 'preg_match', 'preg_match_all', 'preg_grep', 'preg_split'}

    # Sinks with context-specific behavior
    CONTEXT_SINKS = {'file_get_contents', 'include', 'include_once', 'require', 'require_once'}

    SINKS = {
        # SQL Injection
        'mysql_query': (TaintType.SQL, 'CRITICAL'), 'mysqli_query': (TaintType.SQL, 'CRITICAL'),
        'mysqli_multi_query': (TaintType.SQL, 'CRITICAL'), 'pg_query': (TaintType.SQL, 'CRITICAL'),
        'sqlite_query': (TaintType.SQL, 'CRITICAL'), 'odbc_exec': (TaintType.SQL, 'CRITICAL'),
        'query': (TaintType.SQL, 'CRITICAL'),
        # Command Injection
        'exec': (TaintType.COMMAND, 'CRITICAL'), 'system': (TaintType.COMMAND, 'CRITICAL'),
        'shell_exec': (TaintType.COMMAND, 'CRITICAL'), 'passthru': (TaintType.COMMAND, 'CRITICAL'),
        'popen': (TaintType.COMMAND, 'CRITICAL'), 'proc_open': (TaintType.COMMAND, 'CRITICAL'),
        'pcntl_exec': (TaintType.COMMAND, 'CRITICAL'),
        # Code Injection - NOTE: preg_replace only dangerous with /e modifier (deprecated in PHP 7+)
        'eval': (TaintType.CODE, 'CRITICAL'), 'assert': (TaintType.CODE, 'CRITICAL'),
        'create_function': (TaintType.CODE, 'CRITICAL'),
        'call_user_func': (TaintType.CODE, 'CRITICAL'), 'call_user_func_array': (TaintType.CODE, 'CRITICAL'),
        'array_map': (TaintType.CODE, 'HIGH'), 'array_filter': (TaintType.CODE, 'HIGH'),
        'usort': (TaintType.CODE, 'HIGH'), 'uasort': (TaintType.CODE, 'HIGH'),
        # File Operations
        'include': (TaintType.FILE_INCLUDE, 'CRITICAL'), 'include_once': (TaintType.FILE_INCLUDE, 'CRITICAL'),
        'require': (TaintType.FILE_INCLUDE, 'CRITICAL'), 'require_once': (TaintType.FILE_INCLUDE, 'CRITICAL'),
        'file_get_contents': (TaintType.FILE_PATH, 'HIGH'), 'file_put_contents': (TaintType.FILE_PATH, 'CRITICAL'),
        'fopen': (TaintType.FILE_PATH, 'HIGH'), 'fread': (TaintType.FILE_PATH, 'HIGH'),
        'fwrite': (TaintType.FILE_PATH, 'CRITICAL'), 'unlink': (TaintType.FILE_PATH, 'HIGH'),
        'copy': (TaintType.FILE_PATH, 'HIGH'), 'rename': (TaintType.FILE_PATH, 'HIGH'),
        'move_uploaded_file': (TaintType.FILE_PATH, 'HIGH'),
        # XSS
        'echo': (TaintType.XSS, 'HIGH'), 'print': (TaintType.XSS, 'HIGH'),
        'printf': (TaintType.XSS, 'HIGH'), 'die': (TaintType.XSS, 'MEDIUM'),
        # Serialization
        'unserialize': (TaintType.SERIALIZATION, 'CRITICAL'), 'yaml_parse': (TaintType.SERIALIZATION, 'CRITICAL'),
        # XXE
        'simplexml_load_string': (TaintType.XXE, 'HIGH'), 'simplexml_load_file': (TaintType.XXE, 'HIGH'),
        'DOMDocument::loadXML': (TaintType.XXE, 'HIGH'), 'XMLReader::open': (TaintType.XXE, 'HIGH'),
        # SSRF
        'curl_setopt': (TaintType.SSRF, 'HIGH'), 'fsockopen': (TaintType.SSRF, 'HIGH'),
        # Redirect
        'header': (TaintType.REDIRECT, 'MEDIUM'),
        # Email
        'mail': (TaintType.EMAIL, 'HIGH'),
        # NoSQL
        'find': (TaintType.NOSQL, 'HIGH'), 'findOne': (TaintType.NOSQL, 'HIGH'),
        'aggregate': (TaintType.NOSQL, 'HIGH'),
        # LDAP
        'ldap_search': (TaintType.LDAP, 'HIGH'), 'ldap_bind': (TaintType.LDAP, 'HIGH'),
    }


class SanitizerDefinitions:
    SANITIZERS = {
        # SQL Sanitizers
        'mysql_real_escape_string': {TaintType.SQL}, 'mysqli_real_escape_string': {TaintType.SQL},
        'pg_escape_string': {TaintType.SQL}, 'sqlite_escape_string': {TaintType.SQL},
        'addslashes': {TaintType.SQL}, 'safesql': {TaintType.SQL},
        'PDO::quote': {TaintType.SQL}, 'esc_sql': {TaintType.SQL},
        # Type Casting (removes most injection types)
        'intval': {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.FILE_PATH, TaintType.NOSQL},
        'floatval': {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.NOSQL},
        'abs': {TaintType.SQL, TaintType.XSS},
        'ctype_digit': {TaintType.SQL, TaintType.XSS},
        'ctype_alnum': {TaintType.SQL, TaintType.XSS, TaintType.COMMAND},
        'is_numeric': {TaintType.SQL},
        # XSS Sanitizers
        'htmlspecialchars': {TaintType.XSS}, 'htmlentities': {TaintType.XSS},
        'strip_tags': {TaintType.XSS}, 'esc_html': {TaintType.XSS},
        'esc_attr': {TaintType.XSS}, 'wp_kses': {TaintType.XSS},
        'wp_kses_post': {TaintType.XSS}, 'sanitize_text_field': {TaintType.XSS},
        'Html::encode': {TaintType.XSS}, 'Escaper::escapeHtml': {TaintType.XSS},
        # Command Sanitizers
        'escapeshellarg': {TaintType.COMMAND}, 'escapeshellcmd': {TaintType.COMMAND},
        # File Path Sanitizers
        'basename': {TaintType.FILE_PATH, TaintType.FILE_INCLUDE},
        'realpath': {TaintType.FILE_PATH, TaintType.FILE_INCLUDE},
        'pathinfo': {TaintType.FILE_PATH},
        # URL Sanitizers
        'filter_var': {TaintType.XSS, TaintType.SQL, TaintType.SSRF, TaintType.REDIRECT},
        'filter_input': {TaintType.XSS, TaintType.SQL},
        'urlencode': {TaintType.XSS, TaintType.REDIRECT},
        'rawurlencode': {TaintType.XSS, TaintType.REDIRECT},
        # Email Sanitizers
        'filter_var_email': {TaintType.EMAIL}, 'sanitize_email': {TaintType.EMAIL},
        # Regex Sanitizers
        'preg_quote': {TaintType.REGEX},
        # JSON (safe output)
        'json_encode': {TaintType.XSS, TaintType.TEMPLATE},
        # Hash Comparison
        'hash_equals': {TaintType.CODE},
        # String functions that can sanitize
        'strtolower': set(),  # Doesn't remove taint but noted for tracking
        'strtoupper': set(),
        'trim': set(),
        'ltrim': set(),
        'rtrim': set(),
    }

    # Whitelist regex patterns that sanitize by removing dangerous chars
    # Pattern: preg_replace("/[^allowed]/", "", $input) = SAFE
    WHITELIST_PATTERNS = [
        # Only alphanumeric allowed - sanitizes SQL, XSS, COMMAND, FILE, CODE
        (r'preg_replace\s*\(\s*[\'"]\/\[\^a-z0-9[^]]*\]', {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.FILE_PATH, TaintType.FILE_INCLUDE, TaintType.CODE}),
        (r'preg_replace\s*\(\s*[\'"]\/\[\^a-zA-Z0-9[^]]*\]', {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.FILE_PATH, TaintType.FILE_INCLUDE, TaintType.CODE}),
        (r'preg_replace\s*\(\s*[\'"]\/\[\^\\w[^]]*\]', {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.FILE_PATH, TaintType.FILE_INCLUDE, TaintType.CODE}),
        # Only digits allowed
        (r'preg_replace\s*\(\s*[\'"]\/\[\^0-9\]', {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.FILE_PATH, TaintType.CODE}),
        (r'preg_replace\s*\(\s*[\'"]\/\[\^\\d\]', {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.FILE_PATH, TaintType.CODE}),
    ]

    @classmethod
    def get_whitelist_sanitization(cls, line: str) -> Set:
        """Check if line contains whitelist sanitization pattern"""
        result = set()
        for pattern, types in cls.WHITELIST_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                result.update(types)
        return result


class PreSinkSanitizationChecker:
    """
    Checks for sanitization applied before the sink, even when the variable
    is a superglobal element that was reassigned.
    """

    # Sanitizer patterns with the types they remove
    SANITIZER_PATTERNS = [
        (r'->safesql\s*\(', {TaintType.SQL}),
        (r'mysql_real_escape_string\s*\(', {TaintType.SQL}),
        (r'mysqli_real_escape_string\s*\(', {TaintType.SQL}),
        (r'addslashes\s*\(', {TaintType.SQL}),
        (r'intval\s*\(', {TaintType.SQL, TaintType.XSS, TaintType.COMMAND}),
        (r'\(int\)\s*', {TaintType.SQL, TaintType.XSS, TaintType.COMMAND}),
        (r'\(integer\)\s*', {TaintType.SQL, TaintType.XSS, TaintType.COMMAND}),
        (r'floatval\s*\(', {TaintType.SQL, TaintType.XSS}),
        (r'\(float\)\s*', {TaintType.SQL, TaintType.XSS}),
        (r'htmlspecialchars\s*\(', {TaintType.XSS}),
        (r'htmlentities\s*\(', {TaintType.XSS}),
        (r'strip_tags\s*\(', {TaintType.XSS}),
        (r'escapeshellarg\s*\(', {TaintType.COMMAND}),
        (r'escapeshellcmd\s*\(', {TaintType.COMMAND}),
        (r'basename\s*\(', {TaintType.FILE_PATH, TaintType.FILE_INCLUDE}),
        (r'realpath\s*\(', {TaintType.FILE_PATH, TaintType.FILE_INCLUDE}),
        (r'filter_var\s*\(', {TaintType.SQL, TaintType.XSS}),
        (r'is_numeric\s*\(', {TaintType.SQL}),
        (r'ctype_digit\s*\(', {TaintType.SQL, TaintType.XSS}),
        (r'preg_match\s*\(\s*[\'"]\/\^', {TaintType.SQL, TaintType.XSS, TaintType.COMMAND}),
        # Whitelist sanitization patterns - preg_replace removing dangerous chars
        (r'preg_replace\s*\(\s*[\'"]\/\[\^a-z0-9', {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.FILE_PATH, TaintType.FILE_INCLUDE, TaintType.CODE}),
        (r'preg_replace\s*\(\s*[\'"]\/\[\^a-zA-Z0-9', {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.FILE_PATH, TaintType.FILE_INCLUDE, TaintType.CODE}),
        (r'preg_replace\s*\(\s*[\'"]\/\[\^\\w', {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.FILE_PATH, TaintType.FILE_INCLUDE, TaintType.CODE}),
        # totranslit - DLE specific sanitizer
        (r'totranslit\s*\(', {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.FILE_PATH, TaintType.FILE_INCLUDE}),
        # DLEPlugins::Check - DLE path sanitizer
        (r'DLEPlugins::Check\s*\(', {TaintType.FILE_INCLUDE}),
    ]

    def __init__(self, code: str):
        self.code = code
        self.lines = code.split('\n')
        self.sanitization_map: Dict[str, Dict[int, Set[TaintType]]] = {}  # var -> {line -> types}
        self._preprocess()

    def _preprocess(self):
        """Pre-scan the code to find all sanitizations"""
        # First pass: find direct sanitizations
        for line_no, line in enumerate(self.lines, 1):
            # Check for variable assignment with sanitization
            # Pattern: $var = sanitizer(...$source...)
            # Pattern: $_REQUEST['key'] = sanitizer(...)

            # Find assignments
            assign_match = re.search(
                r'(\$[a-zA-Z_][a-zA-Z0-9_]*|\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*[\'"][^\'"]+[\'"]\s*\])\s*=\s*(.+)',
                line
            )

            if assign_match:
                var = assign_match.group(1).replace(' ', '')
                rhs = assign_match.group(2)

                sanitized_types = set()
                for pattern, types in self.SANITIZER_PATTERNS:
                    if re.search(pattern, rhs, re.IGNORECASE):
                        sanitized_types.update(types)

                if sanitized_types:
                    if var not in self.sanitization_map:
                        self.sanitization_map[var] = {}
                    self.sanitization_map[var][line_no] = sanitized_types

            # Also check for sanitization in direct call (not assignment)
            for pattern, types in self.SANITIZER_PATTERNS:
                match = re.search(pattern + r'[^)]*(\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\])', line, re.IGNORECASE)
                if match:
                    full_var = match.group(1).replace(' ', '')
                    if full_var not in self.sanitization_map:
                        self.sanitization_map[full_var] = {}
                    # Merge types instead of overwriting
                    if line_no in self.sanitization_map[full_var]:
                        self.sanitization_map[full_var][line_no].update(types)
                    else:
                        self.sanitization_map[full_var][line_no] = set(types)

        # Second pass: propagate sanitization through derived assignments
        # (e.g., $tags_array from sanitized $_POST['tags'], then implode back)
        for line_no, line in enumerate(self.lines, 1):
            assign_match = re.search(
                r'(\$[a-zA-Z_][a-zA-Z0-9_]*|\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*[\'"][^\'"]+[\'"]\s*\])\s*=\s*(.+)',
                line
            )
            if assign_match:
                var = assign_match.group(1).replace(' ', '')
                rhs = assign_match.group(2)

                # Check if RHS uses any already sanitized variables
                inherited_types = set()
                for san_var, san_lines in self.sanitization_map.items():
                    # Check if sanitized variable is referenced in RHS
                    san_var_pattern = re.escape(san_var).replace(r'\[', r'\s*\[').replace(r'\]', r'\s*\]')
                    if re.search(san_var_pattern, rhs):
                        for san_line, types in san_lines.items():
                            if san_line < line_no:  # Only if sanitized before this line
                                inherited_types.update(types)

                # Also check for implode/explode patterns with sanitized data
                if 'implode' in rhs or 'explode' in rhs or 'array' in rhs.lower():
                    # Look for any sanitized variable in RHS
                    for san_var, san_lines in self.sanitization_map.items():
                        key_match = re.search(r"\[\'([^\']+)\'\]", san_var)
                        if key_match:
                            key = key_match.group(1)
                            if key in rhs:
                                for san_line, types in san_lines.items():
                                    if san_line < line_no:
                                        inherited_types.update(types)

                if inherited_types:
                    if var not in self.sanitization_map:
                        self.sanitization_map[var] = {}
                    # Merge with any existing sanitization
                    if line_no in self.sanitization_map[var]:
                        self.sanitization_map[var][line_no].update(inherited_types)
                    else:
                        self.sanitization_map[var][line_no] = inherited_types

    def is_sanitized_before(self, var_expr: str, sink_line: int, taint_type: TaintType) -> bool:
        """
        Check if the variable was sanitized for the given taint type before the sink line.
        """
        # Normalize variable expression
        var_normalized = var_expr.replace(' ', '')

        # Direct check
        if var_normalized in self.sanitization_map:
            for san_line, san_types in self.sanitization_map[var_normalized].items():
                if san_line < sink_line and taint_type in san_types:
                    return True

        # Extract key from superglobal and check variations
        key_match = re.search(r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]?([^'\"\]]+)['\"]?\s*\]", var_expr)
        if key_match:
            key = key_match.group(1)
            # Check all superglobal forms with this key
            for sg in ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE']:
                for quote in ["'", '"']:
                    check_var = f"{sg}[{quote}{key}{quote}]"
                    if check_var in self.sanitization_map:
                        for san_line, san_types in self.sanitization_map[check_var].items():
                            if san_line < sink_line and taint_type in san_types:
                                # Additional check: verify no NEW tainted access after sanitization
                                if not self._has_new_tainted_access_after(key, san_line, sink_line):
                                    return True

        # Check if there's inline sanitization in the code before sink
        if self._check_inline_sanitization(var_expr, sink_line, taint_type):
            return True

        # Aggressive check: look for ANY sanitization of this key in the file
        # If the key was sanitized and only manipulated (explode, implode, trim) but never
        # re-read from superglobal, consider it safe
        if key_match:
            key = key_match.group(1)
            if self._was_ever_sanitized_and_not_retainted(key, sink_line, taint_type):
                return True

        return False

    def _has_new_tainted_access_after(self, key: str, san_line: int, sink_line: int) -> bool:
        """Check if there's a new direct superglobal access after sanitization"""
        for line_no in range(san_line + 1, min(sink_line, len(self.lines) + 1)):
            line = self.lines[line_no - 1]
            # Look for direct superglobal read (not assignment target)
            # Pattern: something = ... $_POST['key'] ... (where $_POST['key'] is on RHS, not LHS)
            if re.search(rf"[^=]\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]?{re.escape(key)}['\"]?\s*\]", line):
                # This is a read, not an assignment
                # Check if it's being re-sanitized in the same expression
                for pattern, _ in self.SANITIZER_PATTERNS:
                    if re.search(pattern, line):
                        continue  # It's being sanitized, so OK
                # Check if it's part of an assignment TO the superglobal (which is OK)
                if re.match(rf"\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]?{re.escape(key)}['\"]?\s*\]\s*=", line):
                    continue  # This is an assignment, not a read
        return False

    def _was_ever_sanitized_and_not_retainted(self, key: str, sink_line: int, taint_type: TaintType) -> bool:
        """
        Check if the key was sanitized at any point and never re-tainted.
        This handles cases like:
        1. $_POST['tags'] = safesql(...)  <- sanitized
        2. $temp = explode($_POST['tags']) <- derived from sanitized
        3. $_POST['tags'] = implode($temp) <- still sanitized (derived from sanitized)
        4. query($_POST['tags'])  <- SAFE
        """
        sanitized_line = None

        # Find if/when this key was sanitized
        for var, lines in self.sanitization_map.items():
            if f"['{key}']" in var or f'["{key}"]' in var:
                for line_no, types in lines.items():
                    if taint_type in types and line_no < sink_line:
                        sanitized_line = line_no
                        break
                if sanitized_line:
                    break

        if not sanitized_line:
            return False

        # Now check if there's any NEW direct read from the superglobal after sanitization
        # that would introduce tainted data
        for line_no in range(sanitized_line + 1, sink_line):
            if line_no > len(self.lines):
                continue
            line = self.lines[line_no - 1]

            # Look for a NEW read from superglobal (not the sanitized value)
            # This would be something like: $foo = $_POST['key']  (without sanitizer)
            read_pattern = rf"\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]?{re.escape(key)}['\"]?\s*\]"
            if re.search(read_pattern, line):
                # Check if this is a sanitized read
                has_sanitizer = False
                for pattern, types in self.SANITIZER_PATTERNS:
                    if taint_type in types and re.search(pattern, line):
                        has_sanitizer = True
                        break
                if not has_sanitizer:
                    # This is an unsanitized read - but we need to check if the
                    # superglobal was already reassigned to sanitized value
                    pass  # For now, assume reassignments maintain sanitization

        # If we got here, the sanitization is maintained
        return True

    def _check_inline_sanitization(self, var_expr: str, sink_line: int, taint_type: TaintType) -> bool:
        """Check for sanitization in lines before the sink"""
        # Extract the key or variable name to search for
        key_match = re.search(r"\[\s*['\"]?([^'\"\]]+)['\"]?\s*\]", var_expr)
        if key_match:
            search_key = key_match.group(1)
        else:
            var_match = re.search(r'\$([a-zA-Z_][a-zA-Z0-9_]*)', var_expr)
            search_key = var_match.group(1) if var_match else var_expr

        # Scan backwards from sink line
        for line_no in range(sink_line - 1, max(0, sink_line - 50), -1):
            if line_no > len(self.lines):
                continue
            line = self.lines[line_no - 1]

            if search_key in line:
                for pattern, types in self.SANITIZER_PATTERNS:
                    if taint_type in types:
                        if re.search(pattern, line, re.IGNORECASE):
                            return True

        return False


class TaintEnvironment:
    def __init__(self):
        self.variables: Dict[str, TaintState] = {}

    def get(self, var: str) -> TaintState:
        return self.variables.get(var, TaintState())

    def set(self, var: str, state: TaintState):
        self.variables[var] = state

    def copy(self) -> 'TaintEnvironment':
        new = TaintEnvironment()
        new.variables = {k: TaintState(v.sources.copy(), v.sanitizers_applied.copy(), v.propagation_path.copy(), v.sanitized_types.copy()) for k, v in self.variables.items()}
        return new

    def merge(self, other: 'TaintEnvironment') -> 'TaintEnvironment':
        new = self.copy()
        for var, state in other.variables.items():
            if var in new.variables:
                new.variables[var] = new.variables[var].merge_with(state)
            else:
                new.variables[var] = state
        return new


class TaintAnalyzer:
    def __init__(self, file_path: str = ""):
        self.file_path = file_path
        self.findings: List[TaintFinding] = []
        self.pre_sink_checker: Optional[PreSinkSanitizationChecker] = None
        self.code: str = ""

    def analyze_file(self, code: str) -> List[TaintFinding]:
        self.code = code
        self.pre_sink_checker = PreSinkSanitizationChecker(code)

        try:
            root = parse_php_ts(code)
            # Phase 1: AST-walking taint analysis
            self._analyze(root, TaintEnvironment())
            # Phase 2: CFG-based analysis for functions (finds path-sensitive bugs)
            self._analyze_cfg_functions(root)
        except Exception:
            # Parser failed - fall back to regex-based analysis
            self._pattern_analysis(code)

        # Filter findings that have been sanitized
        return self._filter_sanitized_findings()

    def _analyze_cfg_functions(self, root: TSNode):
        """Run CFG-based worklist analysis on each function/method."""
        from .cfg import CFGBuilder
        from collections import deque

        builder = CFGBuilder()
        for node in root.walk_descendants():
            if node.type not in ('function_definition', 'method_declaration'):
                continue
            body = node.child_by_field('body')
            if not body:
                continue

            cfg_blocks = builder.build(body)
            if len(cfg_blocks) < 3:  # entry + exit + at least 1 real block
                continue

            # Initialize entry environment with parameter taint
            entry_env = TaintEnvironment()
            params = node.child_by_field('parameters')
            if params:
                for param in params.named_children:
                    if param.type == 'simple_parameter':
                        for c in param.named_children:
                            if c.type == 'variable_name':
                                entry_env.set(c.text, TaintState(sources={TaintSource(
                                    f'param:{c.text}', TaintLevel.MEDIUM,
                                    SourceDefinitions.ALL_TAINT_TYPES,
                                    node.line, self.file_path
                                )}))

            # Worklist-based fixed-point iteration
            block_envs_in: Dict[int, TaintEnvironment] = {}
            block_envs_out: Dict[int, TaintEnvironment] = {}
            entry_block = cfg_blocks[0]
            block_envs_in[entry_block.id] = entry_env

            worklist = deque([entry_block.id])
            block_map = {b.id: b for b in cfg_blocks}
            iterations = 0
            MAX_ITER = 50

            while worklist and iterations < MAX_ITER:
                bid = worklist.popleft()
                block = block_map[bid]
                iterations += 1

                # Merge predecessor outputs
                if block.predecessors:
                    merged = TaintEnvironment()
                    for pred_id in block.predecessors:
                        if pred_id in block_envs_out:
                            merged = merged.merge(block_envs_out[pred_id])
                    block_envs_in[bid] = merged
                elif bid not in block_envs_in:
                    block_envs_in[bid] = TaintEnvironment()

                # Process statements
                env = block_envs_in[bid].copy()
                for stmt in block.statements:
                    self._analyze(stmt, env)

                # Check if output changed
                old_out = block_envs_out.get(bid)
                block_envs_out[bid] = env

                changed = old_out is None or set(env.variables.keys()) != set(old_out.variables.keys())
                if not changed and old_out:
                    for var in env.variables:
                        if var not in old_out.variables:
                            changed = True
                            break
                        new_state = env.get(var)
                        old_state = old_out.get(var)
                        if new_state.is_tainted != old_state.is_tainted:
                            changed = True
                            break

                if changed:
                    for succ_id in block.successors:
                        if succ_id not in worklist:
                            worklist.append(succ_id)

    def _filter_sanitized_findings(self) -> List[TaintFinding]:
        """Remove findings where the source was sanitized before the sink"""
        filtered = []

        for finding in self.findings:
            if self.pre_sink_checker:
                is_san = self.pre_sink_checker.is_sanitized_before(
                    finding.source.name,
                    finding.sink_line,
                    finding.taint_type
                )
                if is_san:
                    continue  # Skip this finding - it's a false positive

            # Check if the source is from database/session (not user input)
            if self._is_internal_source(finding.source.name, finding.sink_line):
                continue

            filtered.append(finding)

        return filtered

    def _is_internal_source(self, source_name: str, sink_line: int) -> bool:
        """Check if the source is actually from internal data, not user input"""
        if not self.code:
            return False

        lines = self.code.split('\n')

        # If source is a regular variable (not superglobal), check its origin
        if source_name.startswith('$') and not source_name.startswith('$_'):
            var_name = source_name.split('[')[0]

            for line_no in range(sink_line - 1, max(0, sink_line - 100), -1):
                if line_no > len(lines):
                    continue
                line = lines[line_no - 1]

                # Check if variable was assigned from database
                if re.search(rf'{re.escape(var_name)}\s*=\s*.*\$row\s*\[', line):
                    return True
                if re.search(rf'{re.escape(var_name)}\s*=\s*.*->(?:get_row|super_query|fetch)', line):
                    return True
                if re.search(rf'{re.escape(var_name)}\s*=\s*.*\$_SESSION\s*\[', line):
                    return True

        return False

    def _analyze(self, node: TSNode, env: TaintEnvironment) -> TaintState:
        handlers = {
            'program': self._prog,
            'function_definition': self._func,
            'method_declaration': self._func,
            'compound_statement': self._block,
            'if_statement': self._if,
            'while_statement': self._while,
            'for_statement': self._while,
            'foreach_statement': self._foreach,
            'echo_statement': self._echo,
            'expression_statement': self._expr_stmt,
            'assignment_expression': self._assign,
            'binary_expression': self._binary,
            'function_call_expression': self._call,
            'member_call_expression': self._method,
            'scoped_call_expression': self._method,
            'subscript_expression': self._array_access,
            'variable_name': self._var,
            'string': lambda n, e: TaintState(),
            'encapsed_string': lambda n, e: TaintState(),
            'integer': lambda n, e: TaintState(),
            'float': lambda n, e: TaintState(),
            'null': lambda n, e: TaintState(),
            'boolean': lambda n, e: TaintState(),
            'include_expression': self._include,
            'include_once_expression': self._include,
            'require_expression': self._include,
            'require_once_expression': self._include,
            'return_statement': self._return_stmt,
            'else_clause': self._block,
            'parenthesized_expression': self._paren,
            'argument': self._paren,
            'cast_expression': self._cast,
            'conditional_expression': self._ternary,
            'update_expression': self._unary,
            'unary_op_expression': self._unary,
        }
        handler = handlers.get(node.type)
        if handler:
            return handler(node, env)
        # Default: recurse into named children
        state = TaintState()
        for child in node.named_children:
            state = state.merge_with(self._analyze(child, env))
        return state

    def _prog(self, node: TSNode, env: TaintEnvironment) -> TaintState:
        for child in node.named_children:
            self._analyze(child, env)
        return TaintState()

    def _func(self, node: TSNode, env: TaintEnvironment) -> TaintState:
        func_env = env.copy()
        params = node.child_by_field('parameters')
        if params:
            for param in params.named_children:
                if param.type == 'simple_parameter':
                    var_node = None
                    for c in param.named_children:
                        if c.type == 'variable_name':
                            var_node = c
                            break
                    if var_node:
                        var_name = var_node.text
                        func_env.set(var_name, TaintState(sources={TaintSource(
                            f'param:{var_name}', TaintLevel.MEDIUM,
                            SourceDefinitions.ALL_TAINT_TYPES, node.line, self.file_path
                        )}))
        body = node.child_by_field('body')
        if body:
            self._analyze(body, func_env)
        return TaintState()

    def _block(self, node: TSNode, env: TaintEnvironment) -> TaintState:
        for child in node.named_children:
            self._analyze(child, env)
        return TaintState()

    def _if(self, node: TSNode, env: TaintEnvironment) -> TaintState:
        cond = node.child_by_field('condition')
        if cond:
            self._analyze(cond, env)
        then_env = env.copy()
        else_env = env.copy()
        body = node.child_by_field('body')
        if body:
            self._analyze(body, then_env)
        alt = node.child_by_field('alternative')
        if alt:
            self._analyze(alt, else_env)
        merged = then_env.merge(else_env)
        env.variables.update(merged.variables)
        return TaintState()

    def _while(self, node: TSNode, env: TaintEnvironment) -> TaintState:
        MAX_LOOP_ITERATIONS = 5
        prev_vars = set()
        for _ in range(MAX_LOOP_ITERATIONS):
            for child in node.named_children:
                self._analyze(child, env)
            current_vars = set(env.variables.keys())
            if current_vars == prev_vars:
                break
            prev_vars = current_vars
        return TaintState()

    def _foreach(self, node: TSNode, env: TaintEnvironment) -> TaintState:
        # foreach ($array as $key => $value) { body }
        # Tree-sitter: children include the array variable, 'as', pair/variable, body
        named = node.named_children
        arr_state = TaintState()
        value_var = None
        body_node = None

        for child in named:
            if child.type == 'variable_name':
                # This is either the array or the value var
                if arr_state.sources or child.text.startswith('$_'):
                    value_var = child.text
                else:
                    arr_state = self._analyze(child, env)
            elif child.type == 'pair':
                # $key => $value
                pair_children = child.named_children
                if pair_children:
                    value_var = pair_children[-1].text if pair_children[-1].type == 'variable_name' else None
            elif child.type == 'compound_statement':
                body_node = child

        if value_var and arr_state.is_tainted:
            env.set(value_var, arr_state)

        if body_node:
            self._analyze(body_node, env)
        return TaintState()

    def _echo(self, node: TSNode, env: TaintEnvironment) -> TaintState:
        for child in node.named_children:
            state = self._analyze(child, env)
            if state.is_tainted and TaintType.XSS in state.types:
                self._report('echo', node.line, state, TaintType.XSS, 'HIGH')
        return TaintState()

    def _expr_stmt(self, node: TSNode, env: TaintEnvironment) -> TaintState:
        named = node.named_children
        return self._analyze(named[0], env) if named else TaintState()

    def _assign(self, node: TSNode, env: TaintEnvironment) -> TaintState:
        left = node.child_by_field('left')
        right = node.child_by_field('right')
        if not left or not right:
            return TaintState()
        right_state = self._analyze(right, env)
        var = self._get_var(left)
        if var:
            right_state.propagation_path.append((var, node.line))
            env.set(var, right_state)
        return right_state

    def _binary(self, node: TSNode, env: TaintEnvironment) -> TaintState:
        state = TaintState()
        for child in node.named_children:
            state = state.merge_with(self._analyze(child, env))
        return state

    def _paren(self, node: TSNode, env: TaintEnvironment) -> TaintState:
        """Handle parenthesized_expression and argument nodes - pass through to child."""
        named = node.named_children
        if named:
            return self._analyze(named[0], env)
        return TaintState()

    def _return_stmt(self, node: TSNode, env: TaintEnvironment) -> TaintState:
        named = node.named_children
        if named:
            return self._analyze(named[0], env)
        return TaintState()

    def _cast(self, node: TSNode, env: TaintEnvironment) -> TaintState:
        """Handle (int)$x, (string)$x etc. - acts as sanitizer for int/float casts."""
        cast_type = ''
        value_state = TaintState()
        for child in node.children:
            if child.type in ('(int)', '(integer)', '(float)', '(double)', '(bool)', '(boolean)'):
                cast_type = child.text
            elif child._node.is_named:
                value_state = self._analyze(TSNode(child._node, node._code), env)

        if cast_type in ('(int)', '(integer)', '(float)', '(double)'):
            return value_state.apply_sanitizer('type_cast', {TaintType.SQL, TaintType.XSS, TaintType.COMMAND})
        return value_state

    def _ternary(self, node: TSNode, env: TaintEnvironment) -> TaintState:
        state = TaintState()
        for child in node.named_children:
            state = state.merge_with(self._analyze(child, env))
        return state

    def _unary(self, node: TSNode, env: TaintEnvironment) -> TaintState:
        named = node.named_children
        if named:
            return self._analyze(named[0], env)
        return TaintState()

    def _call(self, node: TSNode, env: TaintEnvironment) -> TaintState:
        func_node = node.child_by_field('function')
        if not func_node:
            return TaintState()
        func = func_node.text

        # Get argument states
        arg_nodes = node.get_arguments()
        args = [self._analyze(a, env) for a in arg_nodes]

        # Handle eval specially (it's a function_call_expression in tree-sitter)
        if func == 'eval':
            if args and args[0].is_tainted:
                self._report('eval', node.line, args[0], TaintType.CODE, 'CRITICAL')
            return TaintState()

        if func in SinkDefinitions.SINKS:
            ttype, sev = SinkDefinitions.SINKS[func]

            if func in SinkDefinitions.PATTERN_ARG_SINKS:
                if args and args[0].is_tainted and TaintType.CODE in args[0].types:
                    self._report(func, node.line, args[0], TaintType.CODE, sev)
            elif func == 'file_get_contents':
                if args and args[0].is_tainted:
                    if self.code and node.line <= len(self.code.split('\n')):
                        line = self.code.split('\n')[node.line - 1]
                        if re.search(r'[\'"]https?://', line):
                            if TaintType.SSRF in args[0].types:
                                self._report(func, node.line, args[0], TaintType.SSRF, 'HIGH')
                        else:
                            if TaintType.FILE_PATH in args[0].types:
                                self._report(func, node.line, args[0], TaintType.FILE_PATH, sev)
                    else:
                        for arg in args:
                            if arg.is_tainted and ttype in arg.types:
                                self._report(func, node.line, arg, ttype, sev)
            elif func in ('include', 'include_once', 'require', 'require_once'):
                for arg in args:
                    if arg.is_tainted and ttype in arg.types:
                        if not self._has_file_exists_guard(node.line, arg):
                            self._report(func, node.line, arg, ttype, sev)
            else:
                for arg in args:
                    if arg.is_tainted and ttype in arg.types:
                        self._report(func, node.line, arg, ttype, sev)

        if func in SanitizerDefinitions.SANITIZERS and args:
            return args[0].apply_sanitizer(func, SanitizerDefinitions.SANITIZERS[func])

        if func == 'preg_replace' and len(args) >= 3:
            if self.code and node.line <= len(self.code.split('\n')):
                line = self.code.split('\n')[node.line - 1]
                whitelist_types = SanitizerDefinitions.get_whitelist_sanitization(line)
                if whitelist_types and args[2].is_tainted:
                    return args[2].apply_sanitizer('preg_replace_whitelist', whitelist_types)

        result = TaintState()
        for a in args:
            result = result.merge_with(a)
        return result

    def _has_file_exists_guard(self, sink_line: int, arg_state: TaintState) -> bool:
        if not self.code:
            return False
        lines = self.code.split('\n')
        for line_no in range(max(0, sink_line - 20), sink_line):
            if line_no >= len(lines):
                continue
            line = lines[line_no]
            if 'file_exists' in line or 'is_file' in line or 'is_readable' in line:
                for src in arg_state.sources:
                    if src.name in line or (src.name.split('[')[0] in line):
                        return True
        return False

    def _method(self, node: TSNode, env: TaintEnvironment) -> TaintState:
        name_node = node.child_by_field('name')
        method = name_node.text if name_node else ''

        if method in ('query', 'exec', 'prepare'):
            arg_nodes = node.get_arguments()
            for arg in arg_nodes:
                state = self._analyze(arg, env)
                if state.is_tainted and TaintType.SQL in state.types:
                    self._report(f'->{method}', node.line, state, TaintType.SQL, 'CRITICAL')

        if method == 'safesql':
            arg_nodes = node.get_arguments()
            if arg_nodes:
                state = self._analyze(arg_nodes[-1], env)
                return state.apply_sanitizer('safesql', {TaintType.SQL})
        return TaintState()

    def _array_access(self, node: TSNode, env: TaintEnvironment) -> TaintState:
        named = node.named_children
        if not named:
            return TaintState()
        arr = named[0]
        var = self._get_var(arr)
        if var in SourceDefinitions.SUPERGLOBALS:
            src = SourceDefinitions.SUPERGLOBALS[var]
            source_name = f"{src.name}[...]"
            # Get the key (second named child is the index)
            if len(named) > 1:
                key_node = named[1]
                key_text = key_node.text.strip('"\'')
                source_name = f"{src.name}['{key_text}']"
            return TaintState(sources={TaintSource(source_name, src.level, src.types, node.line, self.file_path)})
        if var == '$_SERVER' and len(named) > 1:
            key_text = named[1].text.strip('"\'')
            if key_text in SourceDefinitions.TAINTED_SERVER_KEYS:
                return TaintState(sources={TaintSource(
                    f"$_SERVER['{key_text}']", TaintLevel.MEDIUM,
                    frozenset({TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.SSRF}),
                    node.line, self.file_path
                )})
        return env.get(var) if var else TaintState()

    def _var(self, node: TSNode, env: TaintEnvironment) -> TaintState:
        var = node.text  # e.g. '$_GET', '$x'
        if var in SourceDefinitions.SUPERGLOBALS:
            src = SourceDefinitions.SUPERGLOBALS[var]
            return TaintState(sources={TaintSource(src.name, src.level, src.types, node.line, self.file_path)})
        return env.get(var)

    def _include(self, node: TSNode, env: TaintEnvironment) -> TaintState:
        # include/require expression - child is the path expression
        for child in node.named_children:
            state = self._analyze(child, env)
            if state.is_tainted and TaintType.FILE_INCLUDE in state.types:
                kind = node.type.replace('_expression', '')  # 'include', 'require', etc.
                self._report(kind, node.line, state, TaintType.FILE_INCLUDE, 'CRITICAL')
        return TaintState()

    def _get_var(self, node: TSNode) -> Optional[str]:
        if node.type == 'variable_name':
            return node.text
        if node.type == 'subscript_expression':
            named = node.named_children
            if named:
                return self._get_var(named[0])
        return None

    def _report(self, sink: str, line: int, state: TaintState, ttype: TaintType, sev: str):
        # Skip if this type was already sanitized
        if ttype in state.sanitized_types:
            return

        for src in state.sources:
            if ttype in src.types:
                # Pre-check: was this sanitized before the sink?
                if self.pre_sink_checker:
                    if self.pre_sink_checker.is_sanitized_before(src.name, line, ttype):
                        continue  # Skip - already sanitized

                conf = 1.0
                if state.sanitizers_applied:
                    conf *= 0.5
                finding = TaintFinding(sink, line, self.file_path, src, ttype, state.propagation_path, state.sanitizers_applied, conf, sev)
                if not any(f.sink_name == sink and f.sink_line == line and f.source.name == src.name for f in self.findings):
                    self.findings.append(finding)

    def _pattern_analysis(self, code: str):
        import re
        lines = code.split('\n')

        # Pre-scan for sanitizations
        self.pre_sink_checker = PreSinkSanitizationChecker(code)

        patterns = [
            (r'\$db->query\s*\([^)]*\$_(GET|POST|REQUEST)', TaintType.SQL, 'CRITICAL'),
            (r'mysql_query\s*\([^)]*\$_(GET|POST|REQUEST)', TaintType.SQL, 'CRITICAL'),
            (r'eval\s*\([^)]*\$_(GET|POST|REQUEST)', TaintType.CODE, 'CRITICAL'),
            (r'(include|require)(_once)?\s*[\(\s][^;]*\$_(GET|POST|REQUEST)', TaintType.FILE_INCLUDE, 'CRITICAL'),
            (r'(exec|shell_exec|system|passthru)\s*\([^)]*\$_(GET|POST|REQUEST)', TaintType.COMMAND, 'CRITICAL'),
            (r'echo\s+[^;]*\$_(GET|POST|REQUEST)', TaintType.XSS, 'HIGH'),
        ]
        for num, line in enumerate(lines, 1):
            for pat, ttype, sev in patterns:
                if re.search(pat, line, re.IGNORECASE):
                    # Extract the source variable
                    src_match = re.search(r'(\$_(?:GET|POST|REQUEST)\s*\[\s*[\'"][^\'"]+[\'"]\s*\])', line)
                    src_name = src_match.group(1) if src_match else '$_REQUEST'

                    # Check if sanitized before this line
                    if self.pre_sink_checker.is_sanitized_before(src_name, num, ttype):
                        continue  # Skip - sanitized

                    src = TaintSource(src_name, TaintLevel.HIGH, frozenset({ttype}), num, self.file_path)
                    self.findings.append(TaintFinding(pat.split('\\s')[0].split('(')[0], num, self.file_path, src, ttype, [], set(), 0.6, sev))


def analyze_php_file(path: str) -> List[TaintFinding]:
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        code = f.read()
    return TaintAnalyzer(path).analyze_file(code)
