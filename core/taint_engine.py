#!/usr/bin/env python3
# apex/core - tron (@tron0x8)

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any, Tuple, FrozenSet
from enum import Enum, auto
from collections import defaultdict
import hashlib
import logging
import re

logger = logging.getLogger(__name__)
from .ts_adapter import TSNode, parse_php_ts
from .rule_engine import get_rule_engine

try:
    from .alias_analysis import AliasAnalyzer
    _HAS_ALIAS = True
except ImportError:
    _HAS_ALIAS = False


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
    # not all $_SERVER keys are user-controlled, only these
    TAINTED_SERVER_KEYS = {
        'HTTP_HOST', 'HTTP_USER_AGENT', 'HTTP_REFERER', 'HTTP_X_FORWARDED_FOR',
        'REQUEST_URI', 'QUERY_STRING', 'PATH_INFO', 'PHP_SELF',
        'HTTP_ACCEPT', 'HTTP_ACCEPT_LANGUAGE', 'HTTP_ACCEPT_ENCODING',
        'HTTP_CONNECTION', 'HTTP_COOKIE', 'CONTENT_TYPE', 'CONTENT_LENGTH',
        'HTTP_X_REQUESTED_WITH', 'HTTP_ORIGIN', 'HTTP_AUTHORIZATION'
    }

    @classmethod
    def from_rule_engine(cls, rule_engine=None):
        rules = rule_engine or get_rule_engine()
        for name, src in rules.get_sources().items():
            if src.category == 'superglobals' and name.startswith('$_'):
                if name not in cls.SUPERGLOBALS:
                    level = TaintLevel[src.taint_level] if src.taint_level in TaintLevel.__members__ else TaintLevel.HIGH
                    taint_types = cls.ALL_TAINT_TYPES
                    cls.SUPERGLOBALS[name] = TaintSource(name, level, taint_types, 0)
        for name, src in rules.get_sources().items():
            if src.category == 'tainted_server_keys':
                cls.TAINTED_SERVER_KEYS.add(src.name)


class SinkDefinitions:
    # first arg is the regex pattern, not user data - don't flag these
    PATTERN_ARG_SINKS = {'preg_replace', 'preg_match', 'preg_match_all', 'preg_grep', 'preg_split'}

    CONTEXT_SINKS = {'file_get_contents', 'include', 'include_once', 'require', 'require_once'}

    SINKS = {
        'mysql_query': (TaintType.SQL, 'CRITICAL'), 'mysqli_query': (TaintType.SQL, 'CRITICAL'),
        'mysqli_multi_query': (TaintType.SQL, 'CRITICAL'), 'pg_query': (TaintType.SQL, 'CRITICAL'),
        'sqlite_query': (TaintType.SQL, 'CRITICAL'), 'odbc_exec': (TaintType.SQL, 'CRITICAL'),
        'query': (TaintType.SQL, 'CRITICAL'),
        'exec': (TaintType.COMMAND, 'CRITICAL'), 'system': (TaintType.COMMAND, 'CRITICAL'),
        'shell_exec': (TaintType.COMMAND, 'CRITICAL'), 'passthru': (TaintType.COMMAND, 'CRITICAL'),
        'popen': (TaintType.COMMAND, 'CRITICAL'), 'proc_open': (TaintType.COMMAND, 'CRITICAL'),
        'pcntl_exec': (TaintType.COMMAND, 'CRITICAL'),
        'eval': (TaintType.CODE, 'CRITICAL'), 'assert': (TaintType.CODE, 'CRITICAL'),
        'create_function': (TaintType.CODE, 'CRITICAL'),
        'call_user_func': (TaintType.CODE, 'CRITICAL'), 'call_user_func_array': (TaintType.CODE, 'CRITICAL'),
        'array_map': (TaintType.CODE, 'HIGH'), 'array_filter': (TaintType.CODE, 'HIGH'),
        'usort': (TaintType.CODE, 'HIGH'), 'uasort': (TaintType.CODE, 'HIGH'),
        'include': (TaintType.FILE_INCLUDE, 'CRITICAL'), 'include_once': (TaintType.FILE_INCLUDE, 'CRITICAL'),
        'require': (TaintType.FILE_INCLUDE, 'CRITICAL'), 'require_once': (TaintType.FILE_INCLUDE, 'CRITICAL'),
        'file_get_contents': (TaintType.FILE_PATH, 'HIGH'), 'file_put_contents': (TaintType.FILE_PATH, 'CRITICAL'),
        'fopen': (TaintType.FILE_PATH, 'HIGH'), 'fread': (TaintType.FILE_PATH, 'HIGH'),
        'fwrite': (TaintType.FILE_PATH, 'CRITICAL'), 'unlink': (TaintType.FILE_PATH, 'HIGH'),
        'copy': (TaintType.FILE_PATH, 'HIGH'), 'rename': (TaintType.FILE_PATH, 'HIGH'),
        'move_uploaded_file': (TaintType.FILE_PATH, 'HIGH'),
        'echo': (TaintType.XSS, 'HIGH'), 'print': (TaintType.XSS, 'HIGH'),
        'printf': (TaintType.XSS, 'HIGH'), 'die': (TaintType.XSS, 'MEDIUM'),
        'unserialize': (TaintType.SERIALIZATION, 'CRITICAL'), 'yaml_parse': (TaintType.SERIALIZATION, 'CRITICAL'),
        'simplexml_load_string': (TaintType.XXE, 'HIGH'), 'simplexml_load_file': (TaintType.XXE, 'HIGH'),
        'DOMDocument::loadXML': (TaintType.XXE, 'HIGH'), 'XMLReader::open': (TaintType.XXE, 'HIGH'),
        'curl_setopt': (TaintType.SSRF, 'HIGH'), 'fsockopen': (TaintType.SSRF, 'HIGH'),
        'header': (TaintType.REDIRECT, 'MEDIUM'),
        'mail': (TaintType.EMAIL, 'HIGH'),
        'find': (TaintType.NOSQL, 'HIGH'), 'findOne': (TaintType.NOSQL, 'HIGH'),
        'aggregate': (TaintType.NOSQL, 'HIGH'),
        'ldap_search': (TaintType.LDAP, 'HIGH'), 'ldap_bind': (TaintType.LDAP, 'HIGH'),
    }

    @classmethod
    def from_rule_engine(cls, rule_engine=None):
        rules = rule_engine or get_rule_engine()
        taint_type_map = {t.name: t for t in TaintType}
        vuln_to_taint = {
            'SQL_INJECTION': TaintType.SQL, 'COMMAND_INJECTION': TaintType.COMMAND,
            'CODE_INJECTION': TaintType.CODE, 'XSS': TaintType.XSS,
            'FILE_INCLUDE': TaintType.FILE_INCLUDE, 'FILE_PATH': TaintType.FILE_PATH,
            'SSRF': TaintType.SSRF, 'XXE': TaintType.XXE,
            'SERIALIZATION': TaintType.SERIALIZATION, 'DESERIALIZATION': TaintType.SERIALIZATION,
            'REDIRECT': TaintType.REDIRECT, 'EMAIL': TaintType.EMAIL,
            'NOSQL': TaintType.NOSQL, 'LDAP': TaintType.LDAP,
            'XPATH': TaintType.XPATH, 'TEMPLATE_INJECTION': TaintType.TEMPLATE,
            'REGEX_DOS': TaintType.REGEX,
        }
        for name, sink in rules.get_sinks().items():
            if name not in cls.SINKS:
                taint_type = vuln_to_taint.get(sink.vuln_type)
                if taint_type:
                    cls.SINKS[name] = (taint_type, sink.severity)


class SanitizerDefinitions:
    SANITIZERS = {
        'mysql_real_escape_string': {TaintType.SQL}, 'mysqli_real_escape_string': {TaintType.SQL},
        'pg_escape_string': {TaintType.SQL}, 'sqlite_escape_string': {TaintType.SQL},
        'addslashes': {TaintType.SQL}, 'safesql': {TaintType.SQL},
        'PDO::quote': {TaintType.SQL}, 'esc_sql': {TaintType.SQL},
        'intval': {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.FILE_PATH, TaintType.NOSQL},
        'floatval': {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.NOSQL},
        'abs': {TaintType.SQL, TaintType.XSS},
        'ctype_digit': {TaintType.SQL, TaintType.XSS},
        'ctype_alnum': {TaintType.SQL, TaintType.XSS, TaintType.COMMAND},
        'is_numeric': {TaintType.SQL},
        'htmlspecialchars': {TaintType.XSS}, 'htmlentities': {TaintType.XSS},
        'strip_tags': {TaintType.XSS}, 'esc_html': {TaintType.XSS},
        'esc_attr': {TaintType.XSS}, 'wp_kses': {TaintType.XSS},
        'wp_kses_post': {TaintType.XSS}, 'sanitize_text_field': {TaintType.XSS},
        'Html::encode': {TaintType.XSS}, 'Escaper::escapeHtml': {TaintType.XSS},
        'escapeshellarg': {TaintType.COMMAND}, 'escapeshellcmd': {TaintType.COMMAND},
        'basename': {TaintType.FILE_PATH, TaintType.FILE_INCLUDE},
        'realpath': {TaintType.FILE_PATH, TaintType.FILE_INCLUDE},
        'pathinfo': {TaintType.FILE_PATH},
        'filter_var': {TaintType.XSS, TaintType.SQL, TaintType.SSRF, TaintType.REDIRECT},
        'filter_input': {TaintType.XSS, TaintType.SQL},
        'urlencode': {TaintType.XSS, TaintType.REDIRECT},
        'rawurlencode': {TaintType.XSS, TaintType.REDIRECT},
        'filter_var_email': {TaintType.EMAIL}, 'sanitize_email': {TaintType.EMAIL},
        'preg_quote': {TaintType.REGEX},
        'json_encode': {TaintType.XSS, TaintType.TEMPLATE},
        'hash_equals': {TaintType.CODE},
        'strtolower': set(),
        'strtoupper': set(),
        'trim': set(),
        'ltrim': set(),
        'rtrim': set(),
    }

    WHITELIST_PATTERNS = [
        (r'preg_replace\s*\(\s*[\'"]\/\[\^a-z0-9[^]]*\]', {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.FILE_PATH, TaintType.FILE_INCLUDE, TaintType.CODE}),
        (r'preg_replace\s*\(\s*[\'"]\/\[\^a-zA-Z0-9[^]]*\]', {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.FILE_PATH, TaintType.FILE_INCLUDE, TaintType.CODE}),
        (r'preg_replace\s*\(\s*[\'"]\/\[\^\\w[^]]*\]', {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.FILE_PATH, TaintType.FILE_INCLUDE, TaintType.CODE}),
        (r'preg_replace\s*\(\s*[\'"]\/\[\^0-9\]', {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.FILE_PATH, TaintType.CODE}),
        (r'preg_replace\s*\(\s*[\'"]\/\[\^\\d\]', {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.FILE_PATH, TaintType.CODE}),
    ]

    @classmethod
    def from_rule_engine(cls, rule_engine=None):
        rules = rule_engine or get_rule_engine()
        taint_type_map = {
            'SQL_INJECTION': TaintType.SQL, 'XSS': TaintType.XSS,
            'COMMAND_INJECTION': TaintType.COMMAND, 'CODE_INJECTION': TaintType.CODE,
            'RCE': TaintType.COMMAND, 'FILE_INCLUSION': TaintType.FILE_INCLUDE,
            'FILE_READ': TaintType.FILE_PATH, 'FILE_WRITE': TaintType.FILE_PATH,
            'FILE_PATH': TaintType.FILE_PATH, 'PATH_TRAVERSAL': TaintType.FILE_PATH,
            'SSRF': TaintType.SSRF, 'XXE': TaintType.XXE,
            'DESERIALIZATION': TaintType.SERIALIZATION, 'OPEN_REDIRECT': TaintType.REDIRECT,
            'EMAIL_INJECTION': TaintType.EMAIL, 'NOSQL': TaintType.NOSQL,
            'LDAP': TaintType.LDAP, 'XPATH': TaintType.XPATH,
            'TEMPLATE_INJECTION': TaintType.TEMPLATE, 'REGEX_DOS': TaintType.REGEX,
            'IDOR': TaintType.SQL,
        }
        for name, san in rules.get_sanitizers().items():
            if name not in cls.SANITIZERS:
                types = set()
                for vt_name in san.protects_against:
                    tt = taint_type_map.get(vt_name)
                    if tt:
                        types.add(tt)
                if types:
                    cls.SANITIZERS[name] = types

    @classmethod
    def get_whitelist_sanitization(cls, line: str) -> Set:
        result = set()
        for pattern, types in cls.WHITELIST_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                result.update(types)
        return result


class PreSinkSanitizationChecker:

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
        (r'preg_replace\s*\(\s*[\'"]\/\[\^a-z0-9', {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.FILE_PATH, TaintType.FILE_INCLUDE, TaintType.CODE}),
        (r'preg_replace\s*\(\s*[\'"]\/\[\^a-zA-Z0-9', {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.FILE_PATH, TaintType.FILE_INCLUDE, TaintType.CODE}),
        (r'preg_replace\s*\(\s*[\'"]\/\[\^\\w', {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.FILE_PATH, TaintType.FILE_INCLUDE, TaintType.CODE}),
        (r'totranslit\s*\(', {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.FILE_PATH, TaintType.FILE_INCLUDE}),
        (r'DLEPlugins::Check\s*\(', {TaintType.FILE_INCLUDE}),
    ]

    @classmethod
    def from_rule_engine(cls, rule_engine=None):
        rules = rule_engine or get_rule_engine()
        taint_type_map = {
            'SQL_INJECTION': TaintType.SQL, 'XSS': TaintType.XSS,
            'COMMAND_INJECTION': TaintType.COMMAND, 'CODE_INJECTION': TaintType.CODE,
            'FILE_INCLUSION': TaintType.FILE_INCLUDE, 'FILE_PATH': TaintType.FILE_PATH,
        }
        existing_patterns = {p for p, _ in cls.SANITIZER_PATTERNS}
        for name, san in rules.get_sanitizers().items():
            if san.pattern not in existing_patterns and san.strength == 'strong':
                types = set()
                for vt_name in san.protects_against:
                    tt = taint_type_map.get(vt_name)
                    if tt:
                        types.add(tt)
                if types:
                    cls.SANITIZER_PATTERNS.append((san.pattern, types))

    def __init__(self, code: str):
        self.code = code
        self.lines = code.split('\n')
        self.sanitization_map: Dict[str, Dict[int, Set[TaintType]]] = {}
        self._preprocess()

    def _preprocess(self):
        for line_no, line in enumerate(self.lines, 1):

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

            for pattern, types in self.SANITIZER_PATTERNS:
                match = re.search(pattern + r'[^)]*(\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\])', line, re.IGNORECASE)
                if match:
                    full_var = match.group(1).replace(' ', '')
                    if full_var not in self.sanitization_map:
                        self.sanitization_map[full_var] = {}
                    if line_no in self.sanitization_map[full_var]:
                        self.sanitization_map[full_var][line_no].update(types)
                    else:
                        self.sanitization_map[full_var][line_no] = set(types)

        for line_no, line in enumerate(self.lines, 1):
            assign_match = re.search(
                r'(\$[a-zA-Z_][a-zA-Z0-9_]*|\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*[\'"][^\'"]+[\'"]\s*\])\s*=\s*(.+)',
                line
            )
            if assign_match:
                var = assign_match.group(1).replace(' ', '')
                rhs = assign_match.group(2)

                inherited_types = set()
                for san_var, san_lines in self.sanitization_map.items():
                    san_var_pattern = re.escape(san_var).replace(r'\[', r'\s*\[').replace(r'\]', r'\s*\]')
                    if re.search(san_var_pattern, rhs):
                        for san_line, types in san_lines.items():
                            if san_line < line_no:
                                inherited_types.update(types)

                if 'implode' in rhs or 'explode' in rhs or 'array' in rhs.lower():
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
                    if line_no in self.sanitization_map[var]:
                        self.sanitization_map[var][line_no].update(inherited_types)
                    else:
                        self.sanitization_map[var][line_no] = inherited_types

    def is_sanitized_before(self, var_expr: str, sink_line: int, taint_type: TaintType) -> bool:
        var_normalized = var_expr.replace(' ', '')

        if var_normalized in self.sanitization_map:
            for san_line, san_types in self.sanitization_map[var_normalized].items():
                if san_line < sink_line and taint_type in san_types:
                    return True

        key_match = re.search(r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]?([^'\"\]]+)['\"]?\s*\]", var_expr)
        if key_match:
            key = key_match.group(1)
            for sg in ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE']:
                for quote in ["'", '"']:
                    check_var = f"{sg}[{quote}{key}{quote}]"
                    if check_var in self.sanitization_map:
                        for san_line, san_types in self.sanitization_map[check_var].items():
                            if san_line < sink_line and taint_type in san_types:
                                if not self._has_new_tainted_access_after(key, san_line, sink_line):
                                    return True

        if self._check_inline_sanitization(var_expr, sink_line, taint_type):
            return True

        if key_match:
            key = key_match.group(1)
            if self._was_ever_sanitized_and_not_retainted(key, sink_line, taint_type):
                return True

        return False

    def _has_new_tainted_access_after(self, key: str, san_line: int, sink_line: int) -> bool:
        for line_no in range(san_line + 1, min(sink_line, len(self.lines) + 1)):
            line = self.lines[line_no - 1]
            if re.search(rf"[^=]\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]?{re.escape(key)}['\"]?\s*\]", line):
                if re.match(rf"\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]?{re.escape(key)}['\"]?\s*\]\s*=", line):
                    continue
                is_sanitized = False
                for pattern, _ in self.SANITIZER_PATTERNS:
                    if re.search(pattern, line):
                        is_sanitized = True
                        break
                if is_sanitized:
                    continue
                return True
        return False

    def _was_ever_sanitized_and_not_retainted(self, key: str, sink_line: int, taint_type: TaintType) -> bool:
        sanitized_line = None

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

        for line_no in range(sanitized_line + 1, sink_line):
            if line_no > len(self.lines):
                continue
            line = self.lines[line_no - 1]

            read_pattern = rf"\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]?{re.escape(key)}['\"]?\s*\]"
            if re.search(read_pattern, line):
                has_sanitizer = False
                for pattern, types in self.SANITIZER_PATTERNS:
                    if taint_type in types and re.search(pattern, line):
                        has_sanitizer = True
                        break
                if not has_sanitizer:
                    return False

        return True

    def _check_inline_sanitization(self, var_expr: str, sink_line: int, taint_type: TaintType) -> bool:
        key_match = re.search(r"\[\s*['\"]?([^'\"\]]+)['\"]?\s*\]", var_expr)
        if key_match:
            search_key = key_match.group(1)
        else:
            var_match = re.search(r'\$([a-zA-Z_][a-zA-Z0-9_]*)', var_expr)
            search_key = var_match.group(1) if var_match else var_expr

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
        self._propagation_rules: Dict[str, Any] = {}
        try:
            rule_engine = get_rule_engine()
            SourceDefinitions.from_rule_engine(rule_engine)
            SinkDefinitions.from_rule_engine(rule_engine)
            SanitizerDefinitions.from_rule_engine(rule_engine)
            self._propagation_rules = rule_engine.propagators
        except Exception as e:
            logger.debug("Rule engine init failed, using hardcoded rules: %s", e)

    def analyze_file(self, code: str) -> List[TaintFinding]:
        self.code = code
        self.pre_sink_checker = PreSinkSanitizationChecker(code)

        try:
            root = parse_php_ts(code)
            self._analyze(root, TaintEnvironment())
            self._analyze_cfg_functions(root)
        except Exception as e:
            logger.debug("AST parse failed for %s, falling back to regex: %s", self.file_path, e)
            self._pattern_analysis(code)

        return self._filter_sanitized_findings()

    def _analyze_cfg_functions(self, root: TSNode):
        from .cfg import CFGBuilder
        from collections import deque

        try:
            from .ssa import build_ssa
            from .abstract_interp import AbstractInterpreter, AbstractState, TaintInfo, TaintLattice
            has_ssa_ai = True
        except ImportError:
            has_ssa_ai = False

        builder = CFGBuilder()
        rule_engine = None
        try:
            rule_engine = get_rule_engine()
        except Exception:
            pass

        for node in root.walk_descendants():
            if node.type not in ('function_definition', 'method_declaration'):
                continue
            body = node.child_by_field('body')
            if not body:
                continue

            cfg_blocks = builder.build(body)
            if len(cfg_blocks) < 3:
                continue

            if has_ssa_ai:
                self._analyze_cfg_ssa(node, cfg_blocks, rule_engine,
                                       build_ssa, AbstractInterpreter,
                                       AbstractState, TaintInfo, TaintLattice)
            else:
                self._analyze_cfg_legacy(node, cfg_blocks)

    def _analyze_cfg_ssa(self, func_node, cfg_blocks, rule_engine,
                          build_ssa, AbstractInterpreter,
                          AbstractState, TaintInfo, TaintLattice):
        try:
            ssa_blocks = build_ssa(cfg_blocks)
        except Exception as e:
            logger.debug("SSA build failed, using legacy CFG: %s", e)
            self._analyze_cfg_legacy(func_node, cfg_blocks)
            return

        entry_state = AbstractState()
        params = func_node.child_by_field('parameters')
        if params:
            for param in params.named_children:
                if param.type == 'simple_parameter':
                    for c in param.named_children:
                        if c.type == 'variable_name':
                            entry_state.set(c.text, TaintInfo(
                                level=TaintLattice.WEAK,
                                taint_types={'SQL', 'XSS', 'COMMAND', 'CODE'},
                                sources={f'param:{c.text}'},
                            ))

        interp = AbstractInterpreter(rule_engine=rule_engine)
        try:
            _, ai_findings = interp.analyze(ssa_blocks, entry_state, self.file_path)
        except Exception as e:
            logger.debug("Abstract interpretation failed, using legacy: %s", e)
            self._analyze_cfg_legacy(func_node, cfg_blocks)
            return

        vuln_to_taint = {
            'SQL_INJECTION': TaintType.SQL, 'COMMAND_INJECTION': TaintType.COMMAND,
            'CODE_INJECTION': TaintType.CODE, 'XSS': TaintType.XSS,
            'FILE_INCLUSION': TaintType.FILE_INCLUDE, 'FILE_READ': TaintType.FILE_PATH,
            'FILE_WRITE': TaintType.FILE_PATH, 'PATH_TRAVERSAL': TaintType.FILE_PATH,
            'SSRF': TaintType.SSRF, 'DESERIALIZATION': TaintType.SERIALIZATION,
            'XXE': TaintType.XXE, 'OPEN_REDIRECT': TaintType.REDIRECT,
            'LDAP_INJECTION': TaintType.LDAP, 'XPATH_INJECTION': TaintType.XPATH,
            'EMAIL_INJECTION': TaintType.EMAIL, 'NOSQL_INJECTION': TaintType.NOSQL,
            'TEMPLATE_INJECTION': TaintType.TEMPLATE,
        }
        for f in ai_findings:
            taint_type = vuln_to_taint.get(f.vuln_type, TaintType.SQL)
            source = TaintSource(
                name=f.source_name,
                level=TaintLevel.HIGH if f.confidence > 0.7 else TaintLevel.MEDIUM,
                types=frozenset({taint_type}),
                line=f.sink_line,
                file=f.sink_file or self.file_path,
            )
            self.findings.append(TaintFinding(
                sink_name=f.sink_name,
                sink_line=f.sink_line,
                sink_file=f.sink_file or self.file_path,
                source=source,
                taint_type=taint_type,
                path=[],
                sanitizers=f.sanitizers if f.sanitizers else set(),
                confidence=f.confidence,
                severity=f.severity,
            ))

    def _analyze_cfg_legacy(self, func_node, cfg_blocks):
        from collections import deque

        alias_analyzer = None
        if _HAS_ALIAS:
            try:
                alias_analyzer = AliasAnalyzer()
                alias_analyzer.analyze(cfg_blocks)
            except Exception:
                alias_analyzer = None

        entry_env = TaintEnvironment()
        params = func_node.child_by_field('parameters')
        if params:
            for param in params.named_children:
                if param.type == 'simple_parameter':
                    for c in param.named_children:
                        if c.type == 'variable_name':
                            entry_env.set(c.text, TaintState(sources={TaintSource(
                                f'param:{c.text}', TaintLevel.MEDIUM,
                                SourceDefinitions.ALL_TAINT_TYPES,
                                func_node.line, self.file_path
                            )}))

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

            if block.predecessors:
                merged = TaintEnvironment()
                for pred_id in block.predecessors:
                    if pred_id in block_envs_out:
                        merged = merged.merge(block_envs_out[pred_id])
                block_envs_in[bid] = merged
            elif bid not in block_envs_in:
                block_envs_in[bid] = TaintEnvironment()

            env = block_envs_in[bid].copy()
            for stmt in block.statements:
                self._analyze(stmt, env)

            if alias_analyzer:
                for var_name, state in list(env.variables.items()):
                    if state.is_tainted:
                        for alias_var in alias_analyzer.get_aliases(var_name):
                            if alias_var != var_name:
                                alias_state = env.get(alias_var)
                                if not alias_state.is_tainted:
                                    env.set(alias_var, state.merge_with(alias_state))

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
        filtered = []

        for finding in self.findings:
            if self.pre_sink_checker:
                is_san = self.pre_sink_checker.is_sanitized_before(
                    finding.source.name,
                    finding.sink_line,
                    finding.taint_type
                )
                if is_san:
                    continue

            if self._is_internal_source(finding.source.name, finding.sink_line):
                continue

            filtered.append(finding)

        return filtered

    def _is_internal_source(self, source_name: str, sink_line: int) -> bool:
        if not self.code:
            return False

        lines = self.code.split('\n')

        if source_name.startswith('$') and not source_name.startswith('$_'):
            var_name = source_name.split('[')[0]

            for line_no in range(sink_line - 1, max(0, sink_line - 100), -1):
                if line_no > len(lines):
                    continue
                line = lines[line_no - 1]

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
            'member_access_expression': self._member_access,
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
        name_node = node.child_by_field('name')
        func_name = name_node.text if name_node else ''
        if func_name in self._MAGIC_SINK_METHODS:
            func_env.set('$this', TaintState(sources={TaintSource(
                f'unserialize:$this', TaintLevel.HIGH,
                frozenset({TaintType.CODE, TaintType.XSS, TaintType.COMMAND,
                          TaintType.FILE_PATH, TaintType.SQL}),
                node.line, self.file_path
            )}))
        params = node.child_by_field('parameters')
        if params:
            for param in params.named_children:
                if param.type in ('simple_parameter', 'property_promotion_parameter'):
                    var_node = None
                    type_node = None
                    for c in param.named_children:
                        if c.type == 'variable_name':
                            var_node = c
                        elif c.type in ('primitive_type', 'named_type', 'optional_type',
                                        'nullable_type', 'union_type', 'intersection_type'):
                            type_node = c
                    if var_node:
                        var_name = var_node.text
                        param_state = TaintState(sources={TaintSource(
                            f'param:{var_name}', TaintLevel.MEDIUM,
                            SourceDefinitions.ALL_TAINT_TYPES, node.line, self.file_path
                        )})
                        if type_node:
                            type_text = type_node.text.lower().lstrip('?')
                            san_types = self._TYPE_HINT_SANITIZATION.get(type_text, set())
                            if san_types:
                                param_state = param_state.apply_sanitizer(f'type:{type_text}', san_types)
                        func_env.set(var_name, param_state)
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
        named = node.named_children
        arr_state = TaintState()
        value_var = None
        body_node = None

        for child in named:
            if child.type == 'variable_name':
                if arr_state.sources or child.text.startswith('$_'):
                    value_var = child.text
                else:
                    arr_state = self._analyze(child, env)
            elif child.type == 'pair':
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
        full_key = self._get_full_var(left)
        if full_key and full_key != var:
            env.set(full_key, right_state)
        return right_state

    def _binary(self, node: TSNode, env: TaintEnvironment) -> TaintState:
        state = TaintState()
        for child in node.named_children:
            state = state.merge_with(self._analyze(child, env))
        return state

    def _paren(self, node: TSNode, env: TaintEnvironment) -> TaintState:
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

        arg_nodes = node.get_arguments()
        args = [self._analyze(a, env) for a in arg_nodes]

        if func == 'eval':
            if args and args[0].is_tainted:
                self._report('eval', node.line, args[0], TaintType.CODE, 'CRITICAL')
            return TaintState()

        if func == 'extract' and args and args[0].is_tainted:
            env.set('__extract_tainted__', args[0])
            self._report('extract', node.line, args[0], TaintType.CODE, 'HIGH')
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

        # check builtin sigs before falling back to merge-all
        # e.g. str_replace only propagates from arg[2], not arg[0]/arg[1]
        prop_rule = self._propagation_rules.get(func)
        if prop_rule is not None:
            result = TaintState()
            for idx in prop_rule.propagates_from:
                if idx < len(args):
                    result = result.merge_with(args[idx])
            if prop_rule.sanitizes and result.is_tainted:
                san_types = set()
                for st in prop_rule.sanitizes:
                    tt = getattr(TaintType, st, None)
                    if tt:
                        san_types.add(tt)
                if san_types:
                    result = result.apply_sanitizer(func, san_types)
            return result

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

    # php enforces type coercion at runtime - function(int $x) means $x is always int
    _TYPE_HINT_SANITIZATION = {
        'int': {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.CODE,
                TaintType.FILE_PATH, TaintType.FILE_INCLUDE, TaintType.NOSQL},
        'integer': {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.CODE,
                    TaintType.FILE_PATH, TaintType.FILE_INCLUDE, TaintType.NOSQL},
        'float': {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.CODE,
                  TaintType.FILE_PATH, TaintType.NOSQL},
        'double': {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.CODE,
                   TaintType.FILE_PATH, TaintType.NOSQL},
        'bool': {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.CODE,
                 TaintType.FILE_PATH, TaintType.NOSQL, TaintType.FILE_INCLUDE},
        'boolean': {TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.CODE,
                    TaintType.FILE_PATH, TaintType.NOSQL, TaintType.FILE_INCLUDE},
    }

    # deserialization gadget chains - these get called implicitly by unserialize()
    _MAGIC_SINK_METHODS = {
        '__toString': (TaintType.XSS, 'HIGH'),
        '__destruct': (TaintType.CODE, 'HIGH'),
        '__wakeup': (TaintType.CODE, 'HIGH'),
        '__call': (TaintType.CODE, 'MEDIUM'),
        '__callStatic': (TaintType.CODE, 'MEDIUM'),
    }

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

        obj_node = node.child_by_field('object')
        arg_nodes = node.get_arguments()
        args = [self._analyze(a, env) for a in arg_nodes]

        if obj_node:
            obj_state = self._analyze(obj_node, env)
            if re.match(r'^(set|add|assign|append|push|write|put)', method, re.I):
                for arg in args:
                    if arg.is_tainted:
                        obj_var = self._get_var(obj_node)
                        if obj_var:
                            env.set(obj_var, obj_state.merge_with(arg))
                        break
            if obj_state.is_tainted:
                return obj_state

        result = TaintState()
        for a in args:
            result = result.merge_with(a)
        return result

    def _array_access(self, node: TSNode, env: TaintEnvironment) -> TaintState:
        named = node.named_children
        if not named:
            return TaintState()
        arr = named[0]
        var = self._get_var(arr)
        if var in SourceDefinitions.SUPERGLOBALS:
            src = SourceDefinitions.SUPERGLOBALS[var]
            source_name = f"{src.name}[...]"
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
        full_key = self._get_full_var(node)
        if full_key:
            elem_state = env.get(full_key)
            if elem_state.is_tainted:
                return elem_state
        return env.get(var) if var else TaintState()

    def _var(self, node: TSNode, env: TaintEnvironment) -> TaintState:
        var = node.text
        if var in SourceDefinitions.SUPERGLOBALS:
            src = SourceDefinitions.SUPERGLOBALS[var]
            return TaintState(sources={TaintSource(src.name, src.level, src.types, node.line, self.file_path)})
        existing = env.get(var)
        if existing.is_tainted:
            return existing
        extract_state = env.get('__extract_tainted__')
        if extract_state.is_tainted and var.startswith('$') and not var.startswith('$_'):
            return TaintState(sources={TaintSource(
                f'extract:{var}', TaintLevel.MEDIUM,
                SourceDefinitions.ALL_TAINT_TYPES, node.line, self.file_path
            )})
        return existing

    def _member_access(self, node: TSNode, env: TaintEnvironment) -> TaintState:
        prop_key = self._get_property_key(node)
        if prop_key:
            prop_state = env.get(prop_key)
            if prop_state.is_tainted:
                return prop_state
        obj_node = node.child_by_field('object')
        if obj_node:
            obj_state = self._analyze(obj_node, env)
            if obj_state.is_tainted:
                return obj_state
        return TaintState()

    def _include(self, node: TSNode, env: TaintEnvironment) -> TaintState:
        for child in node.named_children:
            state = self._analyze(child, env)
            if state.is_tainted and TaintType.FILE_INCLUDE in state.types:
                kind = node.type.replace('_expression', '')
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

    def _get_full_var(self, node: TSNode) -> Optional[str]:
        if node.type == 'subscript_expression':
            named = node.named_children
            if len(named) >= 2:
                base = self._get_var(named[0])
                key_node = named[1]
                key_text = key_node.text.strip('"\'')
                if base and key_text:
                    return f"{base}['{key_text}']"
        if node.type == 'member_access_expression':
            return self._get_property_key(node)
        return None

    def _get_property_key(self, node: TSNode) -> Optional[str]:
        if node.type != 'member_access_expression':
            return None
        obj_node = node.child_by_field('object')
        name_node = node.child_by_field('name')
        if not obj_node or not name_node:
            return None
        base = self._get_var(obj_node)
        prop = name_node.text
        if base and prop:
            return f"{base}->{prop}"
        return None

    def _report(self, sink: str, line: int, state: TaintState, ttype: TaintType, sev: str):
        if ttype in state.sanitized_types:
            return

        for src in state.sources:
            if ttype in src.types:
                if self.pre_sink_checker:
                    if self.pre_sink_checker.is_sanitized_before(src.name, line, ttype):
                        continue

                conf = 1.0
                if state.sanitizers_applied:
                    conf *= 0.5
                finding = TaintFinding(sink, line, self.file_path, src, ttype, state.propagation_path, state.sanitizers_applied, conf, sev)
                if not any(f.sink_name == sink and f.sink_line == line and f.source.name == src.name for f in self.findings):
                    self.findings.append(finding)

    def _pattern_analysis(self, code: str):
        import re
        lines = code.split('\n')

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
                    src_match = re.search(r'(\$_(?:GET|POST|REQUEST)\s*\[\s*[\'"][^\'"]+[\'"]\s*\])', line)
                    src_name = src_match.group(1) if src_match else '$_REQUEST'

                    if self.pre_sink_checker.is_sanitized_before(src_name, num, ttype):
                        continue

                    src = TaintSource(src_name, TaintLevel.HIGH, frozenset({ttype}), num, self.file_path)
                    self.findings.append(TaintFinding(pat.split('\\s')[0].split('(')[0], num, self.file_path, src, ttype, [], set(), 0.6, sev))


def analyze_php_file(path: str) -> List[TaintFinding]:
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        code = f.read()
    return TaintAnalyzer(path).analyze_file(code)
