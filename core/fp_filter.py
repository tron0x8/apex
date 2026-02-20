#!/usr/bin/env python3
# apex/core - tron (@tron0x8)

import re
from typing import List, Dict, Set, Optional, Tuple, NamedTuple
from dataclasses import dataclass, field
from enum import Enum, auto

try:
    from .context_analyzer import AdvancedContextAnalyzer, analyze_context
except ImportError:
    AdvancedContextAnalyzer = None
    analyze_context = None

try:
    from .rule_engine import get_rule_engine
except ImportError:
    get_rule_engine = None


class SanitizationType(Enum):
    SQL = auto()
    XSS = auto()
    COMMAND = auto()
    FILE = auto()
    CODE = auto()
    SSRF = auto()
    NOSQL = auto()
    ALL = auto()


@dataclass
class SanitizerInfo:
    name: str
    pattern: str
    removes: Set[SanitizationType]
    is_method: bool = False


SANITIZERS: List[SanitizerInfo] = [
    SanitizerInfo("safesql", r"->safesql\s*\(", {SanitizationType.SQL}, True),
    SanitizerInfo("mysql_real_escape_string", r"mysql_real_escape_string\s*\(", {SanitizationType.SQL}),
    SanitizerInfo("mysqli_real_escape_string", r"mysqli_real_escape_string\s*\(", {SanitizationType.SQL}),
    SanitizerInfo("pg_escape_string", r"pg_escape_string\s*\(", {SanitizationType.SQL}),
    SanitizerInfo("sqlite_escape_string", r"sqlite_escape_string\s*\(", {SanitizationType.SQL}),
    SanitizerInfo("addslashes", r"addslashes\s*\(", {SanitizationType.SQL}),
    SanitizerInfo("PDO::quote", r"->quote\s*\(", {SanitizationType.SQL}, True),
    SanitizerInfo("esc_sql", r"esc_sql\s*\(", {SanitizationType.SQL}),
    SanitizerInfo("$wpdb->prepare", r"\$wpdb->prepare\s*\(", {SanitizationType.SQL}),

    SanitizerInfo("intval", r"intval\s*\(", {SanitizationType.SQL, SanitizationType.XSS, SanitizationType.COMMAND, SanitizationType.NOSQL}),
    SanitizerInfo("(int)", r"\(int\)\s*", {SanitizationType.SQL, SanitizationType.XSS, SanitizationType.COMMAND, SanitizationType.NOSQL}),
    SanitizerInfo("(integer)", r"\(integer\)\s*", {SanitizationType.SQL, SanitizationType.XSS, SanitizationType.COMMAND, SanitizationType.NOSQL}),
    SanitizerInfo("floatval", r"floatval\s*\(", {SanitizationType.SQL, SanitizationType.XSS, SanitizationType.NOSQL}),
    SanitizerInfo("(float)", r"\(float\)\s*", {SanitizationType.SQL, SanitizationType.XSS, SanitizationType.NOSQL}),
    SanitizerInfo("abs", r"abs\s*\(", {SanitizationType.SQL, SanitizationType.XSS}),

    SanitizerInfo("htmlspecialchars", r"htmlspecialchars\s*\(", {SanitizationType.XSS}),
    SanitizerInfo("htmlentities", r"htmlentities\s*\(", {SanitizationType.XSS}),
    SanitizerInfo("strip_tags", r"strip_tags\s*\(", {SanitizationType.XSS}),
    SanitizerInfo("esc_html", r"esc_html\s*\(", {SanitizationType.XSS}),
    SanitizerInfo("esc_attr", r"esc_attr\s*\(", {SanitizationType.XSS}),
    SanitizerInfo("wp_kses", r"wp_kses\s*\(", {SanitizationType.XSS}),
    SanitizerInfo("wp_kses_post", r"wp_kses_post\s*\(", {SanitizationType.XSS}),
    SanitizerInfo("sanitize_text_field", r"sanitize_text_field\s*\(", {SanitizationType.XSS}),

    SanitizerInfo("escapeshellarg", r"escapeshellarg\s*\(", {SanitizationType.COMMAND}),
    SanitizerInfo("escapeshellcmd", r"escapeshellcmd\s*\(", {SanitizationType.COMMAND}),

    SanitizerInfo("basename", r"basename\s*\(", {SanitizationType.FILE}),
    SanitizerInfo("realpath", r"realpath\s*\(", {SanitizationType.FILE}),
    SanitizerInfo("DLEPlugins::Check", r"DLEPlugins::Check\s*\(", {SanitizationType.FILE}),

    SanitizerInfo("is_numeric", r"is_numeric\s*\(", {SanitizationType.SQL, SanitizationType.XSS}),
    SanitizerInfo("ctype_digit", r"ctype_digit\s*\(", {SanitizationType.SQL, SanitizationType.XSS}),
    SanitizerInfo("ctype_alnum", r"ctype_alnum\s*\(", {SanitizationType.SQL, SanitizationType.XSS, SanitizationType.COMMAND}),
    SanitizerInfo("filter_var", r"filter_var\s*\(", {SanitizationType.SQL, SanitizationType.XSS, SanitizationType.SSRF}),
    SanitizerInfo("preg_match_validate", r"preg_match\s*\(\s*['\"]\/\^", {SanitizationType.SQL, SanitizationType.XSS, SanitizationType.COMMAND}),

    SanitizerInfo("preg_replace_whitelist_alnum", r"preg_replace\s*\(\s*['\"]\/\[\^a-z0-9", {SanitizationType.SQL, SanitizationType.XSS, SanitizationType.COMMAND, SanitizationType.FILE, SanitizationType.CODE}),
    SanitizerInfo("preg_replace_whitelist_word", r"preg_replace\s*\(\s*['\"]\/\[\^\\w", {SanitizationType.SQL, SanitizationType.XSS, SanitizationType.COMMAND, SanitizationType.FILE, SanitizationType.CODE}),

    SanitizerInfo("totranslit", r"totranslit\s*\(", {SanitizationType.SQL, SanitizationType.XSS, SanitizationType.COMMAND, SanitizationType.FILE}),
    SanitizerInfo("dle_strtolower", r"dle_strtolower\s*\(", {SanitizationType.XSS}),
]


def _extend_sanitizers_from_rule_engine():
    try:
        if get_rule_engine is None:
            return
        engine = get_rule_engine()
        if engine is None:
            return

        all_sanitizers = engine.get_sanitizers()
        if not all_sanitizers:
            return

        existing_names = {s.name for s in SANITIZERS}

        _type_map = {
            'SQL_INJECTION': SanitizationType.SQL,
            'SQL': SanitizationType.SQL,
            'XSS': SanitizationType.XSS,
            'CROSS_SITE_SCRIPTING': SanitizationType.XSS,
            'COMMAND_INJECTION': SanitizationType.COMMAND,
            'COMMAND': SanitizationType.COMMAND,
            'FILE_INCLUSION': SanitizationType.FILE,
            'FILE': SanitizationType.FILE,
            'PATH_TRAVERSAL': SanitizationType.FILE,
            'CODE_INJECTION': SanitizationType.CODE,
            'CODE': SanitizationType.CODE,
            'SSRF': SanitizationType.SSRF,
            'NOSQL_INJECTION': SanitizationType.NOSQL,
            'NOSQL': SanitizationType.NOSQL,
        }

        for san_name, san_def in all_sanitizers.items():
            if san_name in existing_names:
                continue
            if not san_def.pattern:
                continue

            removes = set()
            for prot in san_def.protects_against:
                mapped = _type_map.get(prot.upper())
                if mapped:
                    removes.add(mapped)

            if not removes:
                continue

            is_method = san_def.pattern.startswith(r'->')
            SANITIZERS.append(SanitizerInfo(
                name=san_name,
                pattern=san_def.pattern,
                removes=removes,
                is_method=is_method,
            ))
    except Exception:
        pass


_extend_sanitizers_from_rule_engine()


@dataclass
class VariableState:
    name: str
    line: int
    sanitized_for: Set[SanitizationType] = field(default_factory=set)
    sanitizers_applied: List[str] = field(default_factory=list)
    source_line: int = 0
    is_from_db: bool = False
    is_from_session: bool = False
    is_constant: bool = False


class VariableTracker:

    def __init__(self, code: str):
        self.code = code
        self.lines = code.split('\n')
        self.variable_states: Dict[str, VariableState] = {}
        self.superglobal_states: Dict[str, VariableState] = {}
        self._analyze_code()

    def _analyze_code(self):
        for line_no, line in enumerate(self.lines, 1):
            self._analyze_line(line, line_no)

    def _analyze_line(self, line: str, line_no: int):

        superglobal_reassign = re.search(
            r"(\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]([^'\"]+)['\"]\s*\])\s*=\s*(.+)",
            line
        )
        if superglobal_reassign:
            full_var = superglobal_reassign.group(1).replace(" ", "")
            key = superglobal_reassign.group(2)
            rhs = superglobal_reassign.group(3)

            state = VariableState(full_var, line_no)
            sanitized = self._detect_sanitizers_in_expression(rhs)

            if full_var in self.superglobal_states and self.superglobal_states[full_var].sanitized_for:
                if key in rhs or 'implode' in rhs or 'array' in rhs.lower():
                    sanitized.update(self.superglobal_states[full_var].sanitized_for)

            state.sanitized_for = sanitized
            self.superglobal_states[full_var] = state

            for sg in ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE']:
                normalized = f"{sg}['{key}']"
                self.superglobal_states[normalized] = state

        var_assign = re.search(r"(\$[a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+)", line)
        if var_assign:
            var_name = var_assign.group(1)
            rhs = var_assign.group(2)

            state = VariableState(var_name, line_no)

            sanitized = self._detect_sanitizers_in_expression(rhs)

            for known_var, known_state in self.variable_states.items():
                if known_var in rhs and known_state.sanitized_for:
                    sanitized.update(known_state.sanitized_for)

            for sg_var, sg_state in self.superglobal_states.items():
                if sg_var in rhs.replace(' ', '') and sg_state.sanitized_for:
                    sanitized.update(sg_state.sanitized_for)

            state.sanitized_for = sanitized

            if re.search(r"\$(?:row|result|data|record|db|res)\s*\[", rhs) or \
               re.search(r"->(?:get_row|super_query|fetch|query)\s*\(", rhs):
                state.is_from_db = True

            if re.search(r"\$_SESSION\s*\[", rhs):
                state.is_from_session = True

            self.variable_states[var_name] = state

    def _detect_sanitizers_in_expression(self, expr: str) -> Set[SanitizationType]:
        sanitized = set()

        for san in SANITIZERS:
            if re.search(san.pattern, expr, re.IGNORECASE):
                sanitized.update(san.removes)

        return sanitized

    def is_sanitized_before(self, var_pattern: str, sink_line: int,
                            vuln_type: SanitizationType) -> Tuple[bool, str]:

        superglobal_match = re.search(
            r"\$_(GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]?([^'\"\]]+)['\"]?\s*\]",
            var_pattern
        )

        if superglobal_match:
            sg_type = superglobal_match.group(1)
            key = superglobal_match.group(2)

            for pattern_to_check in [
                f"$_{sg_type}['{key}']",
                f'$_{sg_type}["{key}"]',
                f"$_{sg_type}[{key}]",
            ]:
                if pattern_to_check in self.superglobal_states:
                    state = self.superglobal_states[pattern_to_check]
                    if state.line < sink_line and vuln_type in state.sanitized_for:
                        return True, f"Sanitized on line {state.line}"

        var_match = re.search(r"(\$[a-zA-Z_][a-zA-Z0-9_]*)", var_pattern)
        if var_match:
            var_name = var_match.group(1)
            if var_name in self.variable_states:
                state = self.variable_states[var_name]
                if state.line < sink_line:
                    if vuln_type in state.sanitized_for:
                        return True, f"Sanitized on line {state.line}"
                    if state.is_from_db:
                        return True, f"Value from database (line {state.line})"
                    if state.is_from_session:
                        return True, f"Value from session (line {state.line})"

        return False, ""

    def scan_for_sanitization_before_line(self, target_line: int,
                                          var_expr: str,
                                          vuln_type: SanitizationType) -> Tuple[bool, int, str]:

        key_match = re.search(r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]?([^'\"\]]+)['\"]?\s*\]", var_expr)
        if key_match:
            key = key_match.group(1)
        else:
            key = var_expr

        for line_no in range(target_line - 1, max(0, target_line - 50), -1):
            if line_no > len(self.lines):
                continue
            line = self.lines[line_no - 1]

            if key in line:
                for san in SANITIZERS:
                    if vuln_type in san.removes or SanitizationType.ALL in san.removes:
                        if re.search(san.pattern, line, re.IGNORECASE):
                            sanitizer_call = re.search(
                                san.pattern + r"[^)]*" + re.escape(key),
                                line, re.IGNORECASE
                            )
                            if sanitizer_call:
                                return True, line_no, san.name

                            if re.search(
                                rf"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]?{re.escape(key)}['\"]?\s*\]\s*=.*" + san.pattern,
                                line, re.IGNORECASE
                            ):
                                return True, line_no, san.name

        return False, 0, ""


class BackwardTaintAnalyzer:

    def __init__(self, code: str):
        self.code = code
        self.lines = code.split('\n')
        self.tracker = VariableTracker(code)

    def verify_vulnerability(self, sink_line: int, var_expr: str,
                            vuln_type: str) -> Tuple[bool, str]:

        type_map = {
            'SQL': SanitizationType.SQL,
            'SQL_INJECTION': SanitizationType.SQL,
            'XSS': SanitizationType.XSS,
            'COMMAND': SanitizationType.COMMAND,
            'COMMAND_INJECTION': SanitizationType.COMMAND,
            'FILE': SanitizationType.FILE,
            'FILE_INCLUSION': SanitizationType.FILE,
            'FILE_PATH': SanitizationType.FILE,
            'PATH_TRAVERSAL': SanitizationType.FILE,
            'CODE': SanitizationType.CODE,
            'CODE_INJECTION': SanitizationType.CODE,
            'SSRF': SanitizationType.SSRF,
            'NOSQL': SanitizationType.NOSQL,
            'NOSQL_INJECTION': SanitizationType.NOSQL,
        }

        san_type = type_map.get(vuln_type.upper(), SanitizationType.SQL)

        is_san, reason = self.tracker.is_sanitized_before(var_expr, sink_line, san_type)
        if is_san:
            return False, reason

        found, san_line, san_name = self.tracker.scan_for_sanitization_before_line(
            sink_line, var_expr, san_type
        )
        if found:
            return False, f"{san_name}() applied on line {san_line}"

        if self._is_internal_value(var_expr, sink_line):
            return False, "Value from internal/trusted source"

        if self._has_auth_protection(sink_line):
            pass

        return True, ""

    def _is_internal_value(self, var_expr: str, sink_line: int) -> bool:

        var_match = re.search(r"(\$[a-zA-Z_][a-zA-Z0-9_]*)", var_expr)
        if not var_match:
            return False

        var_name = var_match.group(1)

        for line_no in range(sink_line - 1, max(0, sink_line - 100), -1):
            if line_no > len(self.lines):
                continue
            line = self.lines[line_no - 1]

            assign_pattern = rf"{re.escape(var_name)}\s*=\s*(.+)"
            match = re.search(assign_pattern, line)
            if match:
                rhs = match.group(1)

                db_patterns = [
                    r"\$row\s*\[",
                    r"\$result\s*\[",
                    r"\$data\s*\[",
                    r"->get_row\s*\(",
                    r"->get_array\s*\(",
                    r"->super_query\s*\(",
                    r"->fetch_",
                    r"->query\s*\(",
                    r"mysql_fetch",
                    r"mysqli_fetch",
                ]
                for pattern in db_patterns:
                    if re.search(pattern, rhs, re.IGNORECASE):
                        return True

                if re.search(r"\$_SESSION\s*\[", rhs):
                    return True

                if re.match(r"^['\"].*['\"]$", rhs.strip().rstrip(';')):
                    return True
                if re.match(r"^\d+$", rhs.strip().rstrip(';')):
                    return True

        return False

    def _has_auth_protection(self, sink_line: int) -> bool:

        start = max(0, sink_line - 100)
        context = '\n'.join(self.lines[start:sink_line])

        auth_patterns = [
            r"if\s*\(\s*\$member_id\s*\[\s*['\"]user_group['\"]\s*\]\s*[!=]=\s*1\s*\)",
            r"if\s*\(\s*!\s*\$is_logged\s*\)",
            r"check_(?:auth|permission|access)",
            r"is_admin\s*\(",
            r"current_user_can\s*\(",
            r"\$_REQUEST\s*\[\s*['\"]user_hash['\"]\s*\]\s*!=\s*\$dle_login_hash",
        ]

        for pattern in auth_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True

        return False


class ContextAnalyzer:

    def __init__(self, code: str):
        self.code = code
        self.lines = code.split('\n')

    def is_in_safe_context(self, line_no: int, finding_type: str) -> Tuple[bool, str]:

        if line_no <= 0 or line_no > len(self.lines):
            return False, ""

        line = self.lines[line_no - 1]

        if finding_type in ('SQL', 'SQL_INJECTION'):
            if '`' in line and re.search(r'`\s*\.\s*\$', line):
                return True, "SQL identifier escaping with backticks"

        if re.search(r'\$config\s*\[', line) or re.search(r'CONFIG_', line):
            return True, "Configuration constant"

        if re.search(r'->prepare\s*\(', line) or re.search(r'\?\s*[,)]', line):
            return True, "Prepared statement"

        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('#') or stripped.startswith('*'):
            return True, "In comment"

        if re.search(r'(?:test|example|sample|demo|mock)_?', line, re.IGNORECASE):
            return True, "Test/example code"

        if finding_type in ('CODE', 'CODE_INJECTION', 'REGEX'):
            if re.search(r'preg_(?:replace|match|match_all|split|grep)\s*\(', line):
                match = re.search(r'preg_(?:replace|match)\s*\(\s*([\'"][^\'"]+[\'"])', line)
                if match:
                    return True, "User input is subject, not pattern (safe)"

        if finding_type in ('FILE_PATH', 'FILE'):
            if 'file_get_contents' in line:
                if re.search(r'file_get_contents\s*\(\s*[\'"]https?://', line):
                    return True, "URL context, not file path"

        if finding_type in ('FILE_INCLUDE', 'FILE_INCLUSION', 'FILE'):
            for check_line in range(max(0, line_no - 10), line_no):
                if check_line >= len(self.lines):
                    continue
                check = self.lines[check_line]
                if re.search(r'file_exists\s*\(|is_file\s*\(|is_readable\s*\(', check):
                    return True, "Protected by file_exists check"

            if 'DLEPlugins::Check' in line:
                return True, "Path validated by DLEPlugins::Check"

        if self._is_admin_only_context(line_no):
            pass

        return False, ""

    def _is_admin_only_context(self, line_no: int) -> bool:
        start = max(0, line_no - 50)
        context = '\n'.join(self.lines[start:line_no])

        admin_patterns = [
            r"if\s*\(\s*!\s*\$is_logged",
            r"if\s*\(\s*\$member_id\s*\[\s*['\"]user_group['\"]\s*\]\s*[!=]=",
            r"allow_admin\s*\]",
            r"user_hash.*!=.*dle_login_hash",
            r"check_permission\s*\(",
            r"is_admin\s*\(\s*\)",
            r"current_user_can\s*\(",
        ]

        for pattern in admin_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        return False


class ZeroFPFilter:

    def __init__(self, project_path: str = ''):
        self.project_path = project_path
        self.stats = {
            'total_checked': 0,
            'filtered_out': 0,
            'reasons': {}
        }
        self._context_cache: Dict[str, AdvancedContextAnalyzer] = {}

    def filter_findings(self, findings: List[Dict], code_map: Dict[str, str]) -> List[Dict]:
        filtered = []

        for finding in findings:
            self.stats['total_checked'] += 1

            file_path = finding.get('file', finding.get('sink_file', ''))
            line_no = finding.get('line', finding.get('sink_line', 0))
            vuln_type = finding.get('type', finding.get('vuln_type', ''))
            source = finding.get('source', '')
            if isinstance(source, dict):
                source = source.get('name', str(source))

            code = code_map.get(file_path, '')
            if not code:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        code = f.read()
                        code_map[file_path] = code
                except:
                    code = ''

            if not code:
                filtered.append(finding)
                continue

            is_fp, reason = self._check_false_positive(
                code, line_no, vuln_type, source, file_path
            )

            if is_fp:
                self.stats['filtered_out'] += 1
                self.stats['reasons'][reason] = self.stats['reasons'].get(reason, 0) + 1
                finding['filtered'] = True
                finding['filter_reason'] = reason
            else:
                filtered.append(finding)

        return filtered

    def _check_false_positive(self, code: str, line_no: int,
                              vuln_type: str, source: str,
                              file_path: str = '') -> Tuple[bool, str]:

        backward = BackwardTaintAnalyzer(code)
        context = ContextAnalyzer(code)

        is_safe, reason = context.is_in_safe_context(line_no, vuln_type)
        if is_safe:
            return True, reason

        is_vuln, reason = backward.verify_vulnerability(line_no, source, vuln_type)
        if not is_vuln:
            return True, reason

        if AdvancedContextAnalyzer is not None:
            if file_path not in self._context_cache:
                self._context_cache[file_path] = AdvancedContextAnalyzer(
                    code, file_path, self.project_path
                )
            adv_ctx = self._context_cache[file_path]
            is_fp, reason = adv_ctx.is_false_positive(line_no, source, vuln_type)
            if is_fp:
                return True, reason

        lines = code.split('\n')
        if line_no > 0 and line_no <= len(lines):
            start = max(0, line_no - 10)
            context_code = '\n'.join(lines[start:line_no])

            key_match = re.search(r"\[\s*['\"]?([^'\"\]]+)['\"]?\s*\]", source)
            if key_match:
                key = key_match.group(1)
                san_type = self._get_sanitization_type(vuln_type)
                for san in SANITIZERS:
                    if san_type in san.removes:
                        if re.search(san.pattern + r"[^)]*" + re.escape(key), context_code, re.IGNORECASE):
                            return True, f"{san.name}() applied in context"

        return False, ""

    def _get_sanitization_type(self, vuln_type: str) -> SanitizationType:
        type_map = {
            'SQL': SanitizationType.SQL,
            'SQL_INJECTION': SanitizationType.SQL,
            'XSS': SanitizationType.XSS,
            'COMMAND': SanitizationType.COMMAND,
            'COMMAND_INJECTION': SanitizationType.COMMAND,
            'FILE': SanitizationType.FILE,
            'FILE_INCLUSION': SanitizationType.FILE,
            'CODE': SanitizationType.CODE,
            'CODE_INJECTION': SanitizationType.CODE,
        }
        return type_map.get(vuln_type.upper(), SanitizationType.SQL)

    def get_stats(self) -> Dict:
        return self.stats


def filter_false_positives(findings: List[Dict], code_map: Dict[str, str]) -> List[Dict]:
    filter_instance = ZeroFPFilter()
    return filter_instance.filter_findings(findings, code_map)


def validate_data_flow(code: str, source_line: int, sink_line: int, var_name: str) -> bool:
    backward = BackwardTaintAnalyzer(code)
    is_vuln, _ = backward.verify_vulnerability(sink_line, var_name, 'SQL')
    return is_vuln
