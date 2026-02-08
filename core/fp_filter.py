#!/usr/bin/env python3
"""
APEX False Positive Filter v2.0
Zero False Positive Architecture

This module implements a comprehensive false positive elimination system using:
1. Backward taint analysis from sink to source
2. Variable reassignment tracking (including superglobal elements)
3. Sanitization chain detection
4. Context-aware flow analysis
"""

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


# Comprehensive sanitizer database
SANITIZERS: List[SanitizerInfo] = [
    # SQL Sanitizers
    SanitizerInfo("safesql", r"->safesql\s*\(", {SanitizationType.SQL}, True),
    SanitizerInfo("mysql_real_escape_string", r"mysql_real_escape_string\s*\(", {SanitizationType.SQL}),
    SanitizerInfo("mysqli_real_escape_string", r"mysqli_real_escape_string\s*\(", {SanitizationType.SQL}),
    SanitizerInfo("pg_escape_string", r"pg_escape_string\s*\(", {SanitizationType.SQL}),
    SanitizerInfo("sqlite_escape_string", r"sqlite_escape_string\s*\(", {SanitizationType.SQL}),
    SanitizerInfo("addslashes", r"addslashes\s*\(", {SanitizationType.SQL}),
    SanitizerInfo("PDO::quote", r"->quote\s*\(", {SanitizationType.SQL}, True),
    SanitizerInfo("esc_sql", r"esc_sql\s*\(", {SanitizationType.SQL}),
    SanitizerInfo("$wpdb->prepare", r"\$wpdb->prepare\s*\(", {SanitizationType.SQL}),

    # Type casting (removes multiple types)
    SanitizerInfo("intval", r"intval\s*\(", {SanitizationType.SQL, SanitizationType.XSS, SanitizationType.COMMAND, SanitizationType.NOSQL}),
    SanitizerInfo("(int)", r"\(int\)\s*", {SanitizationType.SQL, SanitizationType.XSS, SanitizationType.COMMAND, SanitizationType.NOSQL}),
    SanitizerInfo("(integer)", r"\(integer\)\s*", {SanitizationType.SQL, SanitizationType.XSS, SanitizationType.COMMAND, SanitizationType.NOSQL}),
    SanitizerInfo("floatval", r"floatval\s*\(", {SanitizationType.SQL, SanitizationType.XSS, SanitizationType.NOSQL}),
    SanitizerInfo("(float)", r"\(float\)\s*", {SanitizationType.SQL, SanitizationType.XSS, SanitizationType.NOSQL}),
    SanitizerInfo("abs", r"abs\s*\(", {SanitizationType.SQL, SanitizationType.XSS}),

    # XSS Sanitizers
    SanitizerInfo("htmlspecialchars", r"htmlspecialchars\s*\(", {SanitizationType.XSS}),
    SanitizerInfo("htmlentities", r"htmlentities\s*\(", {SanitizationType.XSS}),
    SanitizerInfo("strip_tags", r"strip_tags\s*\(", {SanitizationType.XSS}),
    SanitizerInfo("esc_html", r"esc_html\s*\(", {SanitizationType.XSS}),
    SanitizerInfo("esc_attr", r"esc_attr\s*\(", {SanitizationType.XSS}),
    SanitizerInfo("wp_kses", r"wp_kses\s*\(", {SanitizationType.XSS}),
    SanitizerInfo("wp_kses_post", r"wp_kses_post\s*\(", {SanitizationType.XSS}),
    SanitizerInfo("sanitize_text_field", r"sanitize_text_field\s*\(", {SanitizationType.XSS}),

    # Command Sanitizers
    SanitizerInfo("escapeshellarg", r"escapeshellarg\s*\(", {SanitizationType.COMMAND}),
    SanitizerInfo("escapeshellcmd", r"escapeshellcmd\s*\(", {SanitizationType.COMMAND}),

    # File/Path Sanitizers
    SanitizerInfo("basename", r"basename\s*\(", {SanitizationType.FILE}),
    SanitizerInfo("realpath", r"realpath\s*\(", {SanitizationType.FILE}),
    SanitizerInfo("DLEPlugins::Check", r"DLEPlugins::Check\s*\(", {SanitizationType.FILE}),

    # Validation functions (treat as sanitizers when used in conditions)
    SanitizerInfo("is_numeric", r"is_numeric\s*\(", {SanitizationType.SQL, SanitizationType.XSS}),
    SanitizerInfo("ctype_digit", r"ctype_digit\s*\(", {SanitizationType.SQL, SanitizationType.XSS}),
    SanitizerInfo("ctype_alnum", r"ctype_alnum\s*\(", {SanitizationType.SQL, SanitizationType.XSS, SanitizationType.COMMAND}),
    SanitizerInfo("filter_var", r"filter_var\s*\(", {SanitizationType.SQL, SanitizationType.XSS, SanitizationType.SSRF}),
    SanitizerInfo("preg_match_validate", r"preg_match\s*\(\s*['\"]\/\^", {SanitizationType.SQL, SanitizationType.XSS, SanitizationType.COMMAND}),

    # Whitelist sanitization patterns - preg_replace removing dangerous chars
    SanitizerInfo("preg_replace_whitelist_alnum", r"preg_replace\s*\(\s*['\"]\/\[\^a-z0-9", {SanitizationType.SQL, SanitizationType.XSS, SanitizationType.COMMAND, SanitizationType.FILE, SanitizationType.CODE}),
    SanitizerInfo("preg_replace_whitelist_word", r"preg_replace\s*\(\s*['\"]\/\[\^\\w", {SanitizationType.SQL, SanitizationType.XSS, SanitizationType.COMMAND, SanitizationType.FILE, SanitizationType.CODE}),

    # DLE specific sanitizers
    SanitizerInfo("totranslit", r"totranslit\s*\(", {SanitizationType.SQL, SanitizationType.XSS, SanitizationType.COMMAND, SanitizationType.FILE}),
    SanitizerInfo("dle_strtolower", r"dle_strtolower\s*\(", {SanitizationType.XSS}),
]


def _extend_sanitizers_from_rule_engine():
    """Extend the SANITIZERS list with entries from RuleEngine. Hardcoded entries are kept as fallback."""
    try:
        if get_rule_engine is None:
            return
        engine = get_rule_engine()
        if engine is None:
            return

        all_sanitizers = engine.get_sanitizers()
        if not all_sanitizers:
            return

        # Build set of existing sanitizer names to avoid duplicates
        existing_names = {s.name for s in SANITIZERS}

        # Map RuleEngine protects_against strings to SanitizationType
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
        # If RuleEngine fails, fall back to hardcoded sanitizers silently
        pass


# Extend sanitizers from RuleEngine at module load time
_extend_sanitizers_from_rule_engine()


@dataclass
class VariableState:
    """Tracks the sanitization state of a variable"""
    name: str
    line: int
    sanitized_for: Set[SanitizationType] = field(default_factory=set)
    sanitizers_applied: List[str] = field(default_factory=list)
    source_line: int = 0
    is_from_db: bool = False
    is_from_session: bool = False
    is_constant: bool = False


class VariableTracker:
    """
    Tracks variable states throughout the code, including:
    - Superglobal element reassignments
    - Sanitization applications
    - Data flow through assignments
    """

    def __init__(self, code: str):
        self.code = code
        self.lines = code.split('\n')
        self.variable_states: Dict[str, VariableState] = {}
        self.superglobal_states: Dict[str, VariableState] = {}  # Key: "$_REQUEST['key']"
        self._analyze_code()

    def _analyze_code(self):
        """Pre-analyze the entire code for variable assignments and sanitizations"""
        for line_no, line in enumerate(self.lines, 1):
            self._analyze_line(line, line_no)

    def _analyze_line(self, line: str, line_no: int):
        """Analyze a single line for assignments and sanitizations"""

        # Pattern 1: Direct superglobal element reassignment with sanitization
        # $_REQUEST['date'] = $db->safesql($_REQUEST['date'])
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

            # If this is a reassignment from already sanitized data (e.g., implode of sanitized array)
            # Keep the sanitization state
            if full_var in self.superglobal_states and self.superglobal_states[full_var].sanitized_for:
                # Check if RHS uses data derived from the same variable
                if key in rhs or 'implode' in rhs or 'array' in rhs.lower():
                    # Propagate previous sanitization
                    sanitized.update(self.superglobal_states[full_var].sanitized_for)

            state.sanitized_for = sanitized
            self.superglobal_states[full_var] = state

            # Also track normalized versions
            for sg in ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE']:
                normalized = f"{sg}['{key}']"
                self.superglobal_states[normalized] = state

        # Pattern 2: Variable assignment from sanitized superglobal
        # $date = $db->safesql($_REQUEST['date'])
        var_assign = re.search(r"(\$[a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+)", line)
        if var_assign:
            var_name = var_assign.group(1)
            rhs = var_assign.group(2)

            state = VariableState(var_name, line_no)

            # Check for sanitizers
            sanitized = self._detect_sanitizers_in_expression(rhs)

            # Check if RHS references an already sanitized variable
            for known_var, known_state in self.variable_states.items():
                if known_var in rhs and known_state.sanitized_for:
                    sanitized.update(known_state.sanitized_for)

            # Check if RHS references a sanitized superglobal
            for sg_var, sg_state in self.superglobal_states.items():
                if sg_var in rhs.replace(' ', '') and sg_state.sanitized_for:
                    sanitized.update(sg_state.sanitized_for)

            state.sanitized_for = sanitized

            # Check if value comes from database
            if re.search(r"\$(?:row|result|data|record|db|res)\s*\[", rhs) or \
               re.search(r"->(?:get_row|super_query|fetch|query)\s*\(", rhs):
                state.is_from_db = True

            # Check if value comes from session
            if re.search(r"\$_SESSION\s*\[", rhs):
                state.is_from_session = True

            self.variable_states[var_name] = state

    def _detect_sanitizers_in_expression(self, expr: str) -> Set[SanitizationType]:
        """Detect all sanitizers applied in an expression"""
        sanitized = set()

        for san in SANITIZERS:
            if re.search(san.pattern, expr, re.IGNORECASE):
                sanitized.update(san.removes)

        return sanitized

    def is_sanitized_before(self, var_pattern: str, sink_line: int,
                            vuln_type: SanitizationType) -> Tuple[bool, str]:
        """
        Check if a variable/superglobal element was sanitized before the sink line.
        Returns (is_sanitized, reason)
        """

        # Extract variable/superglobal info from pattern
        # Handle patterns like "$_REQUEST['date']" or "$_REQUEST[...]"
        superglobal_match = re.search(
            r"\$_(GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]?([^'\"\]]+)['\"]?\s*\]",
            var_pattern
        )

        if superglobal_match:
            sg_type = superglobal_match.group(1)
            key = superglobal_match.group(2)

            # Check all possible forms
            for pattern_to_check in [
                f"$_{sg_type}['{key}']",
                f'$_{sg_type}["{key}"]',
                f"$_{sg_type}[{key}]",
            ]:
                if pattern_to_check in self.superglobal_states:
                    state = self.superglobal_states[pattern_to_check]
                    if state.line < sink_line and vuln_type in state.sanitized_for:
                        return True, f"Sanitized on line {state.line}"

        # Check if it's a regular variable
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
        """
        Scan lines before target_line for sanitization of var_expr.
        Returns (found, sanitizer_line, sanitizer_name)
        """

        # Extract the key part of the variable expression
        # e.g., "$_REQUEST['date']" -> "date", "$_GET['id']" -> "id"
        key_match = re.search(r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]?([^'\"\]]+)['\"]?\s*\]", var_expr)
        if key_match:
            key = key_match.group(1)
        else:
            key = var_expr

        # Scan backwards from target line
        for line_no in range(target_line - 1, max(0, target_line - 50), -1):
            if line_no > len(self.lines):
                continue
            line = self.lines[line_no - 1]

            # Check if this line contains sanitization of our variable
            if key in line:
                for san in SANITIZERS:
                    if vuln_type in san.removes or SanitizationType.ALL in san.removes:
                        if re.search(san.pattern, line, re.IGNORECASE):
                            # Verify the sanitization is for our variable
                            # Pattern: key appears after sanitizer opening paren
                            sanitizer_call = re.search(
                                san.pattern + r"[^)]*" + re.escape(key),
                                line, re.IGNORECASE
                            )
                            if sanitizer_call:
                                return True, line_no, san.name

                            # Pattern: assignment to the variable with sanitizer
                            # $_REQUEST['key'] = sanitizer(...
                            if re.search(
                                rf"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]?{re.escape(key)}['\"]?\s*\]\s*=.*" + san.pattern,
                                line, re.IGNORECASE
                            ):
                                return True, line_no, san.name

        return False, 0, ""


class BackwardTaintAnalyzer:
    """
    Performs backward analysis from sink to source to verify taint flow.
    """

    def __init__(self, code: str):
        self.code = code
        self.lines = code.split('\n')
        self.tracker = VariableTracker(code)

    def verify_vulnerability(self, sink_line: int, var_expr: str,
                            vuln_type: str) -> Tuple[bool, str]:
        """
        Verify if a potential vulnerability is real by checking backward taint flow.
        Returns (is_vulnerable, reason_if_not)
        """

        # Map vuln_type string to SanitizationType
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

        # Check 1: Was the variable sanitized before this line?
        is_san, reason = self.tracker.is_sanitized_before(var_expr, sink_line, san_type)
        if is_san:
            return False, reason

        # Check 2: Scan for sanitization in code before sink
        found, san_line, san_name = self.tracker.scan_for_sanitization_before_line(
            sink_line, var_expr, san_type
        )
        if found:
            return False, f"{san_name}() applied on line {san_line}"

        # Check 3: Is the variable coming from internal sources?
        if self._is_internal_value(var_expr, sink_line):
            return False, "Value from internal/trusted source"

        # Check 4: Is there admin/auth context protection?
        if self._has_auth_protection(sink_line):
            # Still vulnerable but lower priority - but we want zero FP so mark as secure
            # Actually for this we should still report but with lower confidence
            pass

        # All checks passed - this appears to be a real vulnerability
        return True, ""

    def _is_internal_value(self, var_expr: str, sink_line: int) -> bool:
        """Check if the variable contains internal/database data, not user input"""

        # Check backwards for variable assignment
        var_match = re.search(r"(\$[a-zA-Z_][a-zA-Z0-9_]*)", var_expr)
        if not var_match:
            return False

        var_name = var_match.group(1)

        # Look for where this variable was assigned
        for line_no in range(sink_line - 1, max(0, sink_line - 100), -1):
            if line_no > len(self.lines):
                continue
            line = self.lines[line_no - 1]

            # Check if this line assigns to our variable
            assign_pattern = rf"{re.escape(var_name)}\s*=\s*(.+)"
            match = re.search(assign_pattern, line)
            if match:
                rhs = match.group(1)

                # Check if RHS is from database
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

                # Check if from session
                if re.search(r"\$_SESSION\s*\[", rhs):
                    return True

                # Check if constant
                if re.match(r"^['\"].*['\"]$", rhs.strip().rstrip(';')):
                    return True
                if re.match(r"^\d+$", rhs.strip().rstrip(';')):
                    return True

        return False

    def _has_auth_protection(self, sink_line: int) -> bool:
        """Check if the code block has authentication/authorization checks"""

        # Look at surrounding context (100 lines before)
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
    """
    Analyzes the context around a finding to detect false positives.
    """

    def __init__(self, code: str):
        self.code = code
        self.lines = code.split('\n')

    def is_in_safe_context(self, line_no: int, finding_type: str) -> Tuple[bool, str]:
        """
        Check if the finding is in a safe context that makes it a false positive.
        Returns (is_safe, reason)
        """

        if line_no <= 0 or line_no > len(self.lines):
            return False, ""

        line = self.lines[line_no - 1]

        # Check: Is this a SQL table/column escaping (backticks)?
        if finding_type in ('SQL', 'SQL_INJECTION'):
            if '`' in line and re.search(r'`\s*\.\s*\$', line):
                # Likely table name concatenation with backticks, not injection
                return True, "SQL identifier escaping with backticks"

        # Check: Is the variable a constant/config value?
        if re.search(r'\$config\s*\[', line) or re.search(r'CONFIG_', line):
            return True, "Configuration constant"

        # Check: Is this a prepared statement?
        if re.search(r'->prepare\s*\(', line) or re.search(r'\?\s*[,)]', line):
            return True, "Prepared statement"

        # Check: Is this in a comment?
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('#') or stripped.startswith('*'):
            return True, "In comment"

        # Check: Test/example code
        if re.search(r'(?:test|example|sample|demo|mock)_?', line, re.IGNORECASE):
            return True, "Test/example code"

        # Check: preg_replace/preg_match with user input as SUBJECT not PATTERN
        if finding_type in ('CODE', 'CODE_INJECTION', 'REGEX'):
            if re.search(r'preg_(?:replace|match|match_all|split|grep)\s*\(', line):
                # Check if user input is in pattern position (first argument)
                # Pattern: preg_X( STATIC_STRING , ... , $user_input )
                # If pattern is a static string, it's safe
                match = re.search(r'preg_(?:replace|match)\s*\(\s*([\'"][^\'"]+[\'"])', line)
                if match:
                    # First arg is a string literal, not tainted - safe
                    return True, "User input is subject, not pattern (safe)"

        # Check: file_get_contents with fixed URL prefix (SSRF context, not file path)
        if finding_type in ('FILE_PATH', 'FILE'):
            if 'file_get_contents' in line:
                if re.search(r'file_get_contents\s*\(\s*[\'"]https?://', line):
                    return True, "URL context, not file path"

        # Check: include/require with file_exists guard
        if finding_type in ('FILE_INCLUDE', 'FILE_INCLUSION', 'FILE'):
            # Look backwards for file_exists check
            for check_line in range(max(0, line_no - 10), line_no):
                if check_line >= len(self.lines):
                    continue
                check = self.lines[check_line]
                if re.search(r'file_exists\s*\(|is_file\s*\(|is_readable\s*\(', check):
                    return True, "Protected by file_exists check"

            # Check for DLEPlugins::Check wrapper
            if 'DLEPlugins::Check' in line:
                return True, "Path validated by DLEPlugins::Check"

        # Check: admin-only context (lower priority but often acceptable)
        if self._is_admin_only_context(line_no):
            # For now, still report but could be used to lower severity
            pass

        return False, ""

    def _is_admin_only_context(self, line_no: int) -> bool:
        """Check if code is in admin-only protected block"""
        # Look backwards for admin checks
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
    """
    Main filter class that combines all analysis techniques to achieve
    zero false positives.
    """

    def __init__(self, project_path: str = ''):
        self.project_path = project_path
        self.stats = {
            'total_checked': 0,
            'filtered_out': 0,
            'reasons': {}
        }
        self._context_cache: Dict[str, AdvancedContextAnalyzer] = {}

    def filter_findings(self, findings: List[Dict], code_map: Dict[str, str]) -> List[Dict]:
        """
        Filter findings to remove false positives.

        Args:
            findings: List of vulnerability findings
            code_map: Dictionary mapping file paths to their code content

        Returns:
            Filtered list of findings (only true positives)
        """
        filtered = []

        for finding in findings:
            self.stats['total_checked'] += 1

            file_path = finding.get('file', finding.get('sink_file', ''))
            line_no = finding.get('line', finding.get('sink_line', 0))
            vuln_type = finding.get('type', finding.get('vuln_type', ''))
            source = finding.get('source', '')
            # Handle dict source format
            if isinstance(source, dict):
                source = source.get('name', str(source))

            # Get the code for this file
            code = code_map.get(file_path, '')
            if not code:
                # Try to read the file
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        code = f.read()
                        code_map[file_path] = code
                except:
                    code = ''

            if not code:
                # Can't verify, include finding
                filtered.append(finding)
                continue

            # Run all analysis
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
        """
        Run comprehensive false positive checks.
        Returns (is_fp, reason)
        """

        # Initialize analyzers
        backward = BackwardTaintAnalyzer(code)
        context = ContextAnalyzer(code)

        # Check 1: Context analysis
        is_safe, reason = context.is_in_safe_context(line_no, vuln_type)
        if is_safe:
            return True, reason

        # Check 2: Backward taint verification
        is_vuln, reason = backward.verify_vulnerability(line_no, source, vuln_type)
        if not is_vuln:
            return True, reason

        # Check 3: Advanced context analysis (whitelist, custom functions, inter-file, auth)
        if AdvancedContextAnalyzer is not None:
            if file_path not in self._context_cache:
                self._context_cache[file_path] = AdvancedContextAnalyzer(
                    code, file_path, self.project_path
                )
            adv_ctx = self._context_cache[file_path]
            is_fp, reason = adv_ctx.is_false_positive(line_no, source, vuln_type)
            if is_fp:
                return True, reason

        # Check 4: Check for sanitization in the same line or nearby
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
        """Convert vulnerability type string to SanitizationType"""
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
        """Get filtering statistics"""
        return self.stats


# Compatibility functions for existing code
def filter_false_positives(findings: List[Dict], code_map: Dict[str, str]) -> List[Dict]:
    """Legacy compatibility function"""
    filter_instance = ZeroFPFilter()
    return filter_instance.filter_findings(findings, code_map)


def validate_data_flow(code: str, source_line: int, sink_line: int, var_name: str) -> bool:
    """Legacy compatibility function"""
    backward = BackwardTaintAnalyzer(code)
    is_vuln, _ = backward.verify_vulnerability(sink_line, var_name, 'SQL')
    return is_vuln
