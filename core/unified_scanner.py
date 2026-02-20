#!/usr/bin/env python3
# apex/core - tron (@tron0x8)

import os
import re
import glob
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from .rule_engine import get_rule_engine

try:
    from .interprocedural_v2 import InterproceduralEngine, analyze_interprocedural_v2
    HAS_INTERPROCEDURAL = True
except ImportError:
    HAS_INTERPROCEDURAL = False

try:
    from .ast_parser import PHPASTParser, TaintFlow
    HAS_AST_PARSER = True
except ImportError:
    HAS_AST_PARSER = False


class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0


class VulnType(Enum):
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting"
    COMMAND_INJECTION = "Command Injection"
    CODE_INJECTION = "Code Injection"
    RCE = "Remote Code Execution"
    FILE_INCLUSION = "File Inclusion"
    FILE_WRITE = "Arbitrary File Write"
    FILE_READ = "Arbitrary File Read"
    PATH_TRAVERSAL = "Path Traversal"
    SSRF = "Server-Side Request Forgery"
    DESERIALIZATION = "Insecure Deserialization"
    AUTH_BYPASS = "Authentication Bypass"
    OPEN_REDIRECT = "Open Redirect"
    IDOR = "Insecure Direct Object Reference"
    CSRF = "Cross-Site Request Forgery"
    WEAK_CRYPTO = "Weak Cryptography"
    HARDCODED_CREDS = "Hardcoded Credentials"
    INFO_DISCLOSURE = "Information Disclosure"
    UNSAFE_UPLOAD = "Unsafe File Upload"
    TYPE_JUGGLING = "Type Juggling"
    XXE = "XML External Entity"
    LDAP_INJECTION = "LDAP Injection"
    XPATH_INJECTION = "XPath Injection"
    TEMPLATE_INJECTION = "Template Injection"
    HEADER_INJECTION = "HTTP Header Injection"
    MASS_ASSIGNMENT = "Mass Assignment"
    INSECURE_RANDOM = "Insecure Randomness"
    RACE_CONDITION = "Race Condition"
    LOG_INJECTION = "Log Injection"
    REGEX_DOS = "Regular Expression DoS"
    SSTI = "Server-Side Template Injection"
    PHAR_DESERIALIZATION = "PHAR Deserialization"
    ASSERT_INJECTION = "Assert Injection"
    UNSAFE_OBJECT_INSTANTIATION = "Unsafe Object Instantiation"
    CREATE_FUNCTION = "Insecure create_function()"
    FORMAT_STRING = "Format String Vulnerability"
    UNSAFE_EXTRACT = "Unsafe extract()"
    UNSAFE_PARSE_STR = "Unsafe parse_str()"
    PHPINFO_EXPOSURE = "PHPInfo Exposure"
    INSECURE_PASSWORD_STORAGE = "Insecure Password Storage"
    INSECURE_CRYPTO_DEFAULTS = "Insecure Cryptographic Defaults"
    IMPROPER_CERT_VALIDATION = "Improper Certificate Validation"
    UNSAFE_PUTENV = "Unsafe putenv()"
    YAML_INJECTION = "YAML Injection"
    UNSAFE_CALLBACK = "Unsafe Callback Injection"
    INSECURE_PHP_CONFIG = "Insecure PHP Configuration"
    SENSITIVE_DATA_IN_LOGS = "Sensitive Data in Logs"
    IMPROPER_ERROR_HANDLING = "Improper Error Handling"
    AUTH_BYPASS_USER_KEY = "Authorization Bypass via User-Controlled Key"
    WEAK_SESSION_MANAGEMENT = "Weak Session Management"


@dataclass
class Finding:
    vuln_type: VulnType
    severity: Severity
    line: int
    code: str
    file: str

    pattern_match: bool = False
    taint_verified: bool = False

    source: Optional[str] = None
    sink: Optional[str] = None
    sanitizers: List[str] = field(default_factory=list)

    confidence: float = 0.0

    framework: Optional[str] = None
    in_auth_context: bool = False

    def to_dict(self) -> Dict:
        return {
            'type': self.vuln_type.value,
            'severity': self.severity.name,
            'line': self.line,
            'code': self.code[:100],
            'file': self.file,
            'confidence': f"{self.confidence:.0%}",
            'source': self.source,
            'sink': self.sink,
            'sanitizers': self.sanitizers,
            'stages': {
                'pattern': self.pattern_match,
                'taint': self.taint_verified,
            }
        }


class UnifiedScanner:

    def __init__(self, enable_ast: bool = True, rule_engine=None, **kwargs):
        self.enable_ast = enable_ast and HAS_AST_PARSER
        self.rules = rule_engine or get_rule_engine()
        self._init_patterns()
        self._compile_patterns()
        self._init_sources_sinks()
        self._init_sanitizers()
        self._init_frameworks()
        self._init_ast_parser()

    def _init_patterns(self):
        vuln_type_map = {name: member for name, member in VulnType.__members__.items()}
        self.patterns = {}
        for vuln_name, pats in self.rules.get_patterns().items():
            vt = vuln_type_map.get(vuln_name)
            if vt:
                self.patterns[vt] = [(p.regex, Severity[p.severity]) for p in pats]

    def _compile_patterns(self):
        self.compiled_patterns = {}
        for vuln_type, patterns in self.patterns.items():
            compiled = []
            for pattern, severity in patterns:
                compiled.append((re.compile(pattern, re.IGNORECASE), severity))
            self.compiled_patterns[vuln_type] = compiled

    def _init_sources_sinks(self):
        self.sources = {}
        for name, src in self.rules.get_sources().items():
            if src.category == 'superglobals':
                self.sources[name.replace('$_', '')] = src.pattern
            elif src.category == 'input_functions':
                self.sources[name] = src.pattern

        if not self.sources:
            self.sources = {
                'GET': r'\$_GET\s*\[',
                'POST': r'\$_POST\s*\[',
                'REQUEST': r'\$_REQUEST\s*\[',
                'COOKIE': r'\$_COOKIE\s*\[',
                'FILES': r'\$_FILES\s*\[',
                'SERVER': r'\$_SERVER\s*\[\s*[\'"](?:REQUEST_URI|QUERY_STRING|HTTP_)',
                'INPUT': r'file_get_contents\s*\(\s*[\'"]php://input',
            }

        vuln_type_map = {name: member for name, member in VulnType.__members__.items()}
        self.sinks = {}
        for name, sink in self.rules.get_sinks().items():
            vt = vuln_type_map.get(sink.vuln_type)
            if vt and vt not in self.sinks:
                self.sinks[vt] = []
            if vt:
                self.sinks[vt].append(sink.pattern)

        if not self.sinks:
            self.sinks = {
                VulnType.SQL_INJECTION: [
                    r'mysql_query', r'mysqli_query', r'pg_query', r'->query\s*\(',
                    r'->exec\s*\(', r'->execute\s*\(',
                ],
                VulnType.COMMAND_INJECTION: [
                    r'\bexec\s*\(', r'\bsystem\s*\(', r'\bpassthru\s*\(',
                    r'\bshell_exec\s*\(', r'\bpopen\s*\(', r'`',
                ],
                VulnType.XSS: [
                    r'\becho\b', r'\bprint\b', r'\bprintf\b',
                ],
                VulnType.FILE_INCLUSION: [
                    r'\binclude\b', r'\brequire\b',
                ],
            }

    def _init_sanitizers(self):
        vuln_type_map = {name: member for name, member in VulnType.__members__.items()}
        self.sanitizers = {}
        for name, san in self.rules.get_sanitizers().items():
            protects = []
            for vt_name in san.protects_against:
                vt = vuln_type_map.get(vt_name)
                if vt:
                    protects.append(vt)
            if protects:
                self.sanitizers[name] = {'pattern': san.pattern, 'protects': protects}

    def _detect_custom_sanitizer_usage(self, code: str, line_num: int) -> List[str]:
        lines = code.split('\n')
        start = max(0, line_num - 30)
        context = '\n'.join(lines[start:line_num])

        sanitizers_found = []

        sanitizer_patterns = [
            r'(\w*(?:safe|escape|clean|sanitize|filter|validate|secure|protect|purify)\w*)\s*\(',
            r'->(\w*(?:safe|escape|clean|sanitize|filter|validate|quote|protect)\w*)\s*\(',
        ]

        for pattern in sanitizer_patterns:
            matches = re.findall(pattern, context, re.I)
            for match in matches:
                if match.lower() not in ['if', 'for', 'while', 'switch']:
                    if match not in sanitizers_found:
                        sanitizers_found.append(match)

        return sanitizers_found

    def _init_frameworks(self):
        self.frameworks = {}
        for name, fw in self.rules.frameworks.items():
            patterns = [re.escape(p) for p in fw.detect_patterns]
            self.frameworks[name] = patterns

        if 'orm_protected' not in self.frameworks:
            self.frameworks['orm_protected'] = [r'->prepare\s*\(', r'->bind(?:Param|Value)\s*\(', r'\?\s*,\s*\[']

    def _init_ast_parser(self):
        self.ast_parser = None
        self.dataflow_analyzer = None

        if self.enable_ast and HAS_AST_PARSER:
            try:
                self.ast_parser = PHPASTParser()
            except Exception:
                pass


    def _analyze_with_ast(self, code: str, filepath: str = "") -> List[Finding]:
        if not self.ast_parser:
            return []

        findings = []
        lines = code.split('\n')

        framework = self._detect_framework(code)
        is_admin_path = self._check_admin_path(filepath)
        has_admin_check = self._check_admin_code_context(code, 0)
        is_admin_only = is_admin_path and has_admin_check

        try:
            vuln_flows = self.ast_parser.get_vulnerable_flows(code, filepath)

            for flow in vuln_flows:
                vuln_type_map = {
                    'SQL_INJECTION': VulnType.SQL_INJECTION,
                    'XSS': VulnType.XSS,
                    'COMMAND_INJECTION': VulnType.COMMAND_INJECTION,
                    'CODE_INJECTION': VulnType.CODE_INJECTION,
                    'FILE_INCLUSION': VulnType.FILE_INCLUSION,
                    'FILE_WRITE': VulnType.FILE_WRITE,
                    'FILE_READ': VulnType.FILE_READ,
                    'SSRF': VulnType.SSRF,
                    'DESERIALIZATION': VulnType.DESERIALIZATION,
                    'XXE': VulnType.XXE,
                    'LDAP_INJECTION': VulnType.LDAP_INJECTION,
                    'XPATH_INJECTION': VulnType.XPATH_INJECTION,
                }

                vuln_type = vuln_type_map.get(flow.sink_type)
                if not vuln_type:
                    continue

                line_code = lines[flow.sink_line - 1].strip() if flow.sink_line <= len(lines) else ""

                if self._check_safe_context(code, flow.sink_line, vuln_type):
                    continue

                if self._is_false_positive_pattern(line_code, vuln_type):
                    continue

                confidence = 0.85

                if flow.source in ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE']:
                    confidence = 0.90

                if framework in ['laravel', 'symfony', 'wordpress', 'dle']:
                    confidence -= 0.20

                if is_admin_only:
                    confidence -= 0.25

                if confidence < 0.60:
                    continue

                critical_types = {VulnType.SQL_INJECTION, VulnType.COMMAND_INJECTION,
                                VulnType.CODE_INJECTION, VulnType.FILE_INCLUSION,
                                VulnType.DESERIALIZATION}
                severity = Severity.CRITICAL if vuln_type in critical_types and confidence >= 0.80 else Severity.HIGH

                finding = Finding(
                    vuln_type=vuln_type,
                    severity=severity,
                    line=flow.sink_line,
                    code=line_code[:100],
                    file=filepath,
                    pattern_match=False,
                    taint_verified=True,
                    source=flow.source,
                    sink=flow.sink,
                    sanitizers=[flow.sanitizer] if flow.sanitizer else [],
                    confidence=confidence,
                    framework=framework,
                    in_auth_context=is_admin_only,
                )
                findings.append(finding)

        except Exception:
            pass

        return findings

    def _verify_with_dataflow(self, code: str, line_num: int,
                              vuln_type: VulnType) -> Tuple[bool, float]:
        if not self.dataflow_analyzer:
            return True, 0.0

        try:
            var_taints = self.dataflow_analyzer.analyze_code(code)

            lines = code.split('\n')
            if line_num > len(lines):
                return True, 0.0

            line = lines[line_num - 1]

            sink_type_map = {
                VulnType.SQL_INJECTION: 'SQL_INJECTION',
                VulnType.XSS: 'XSS',
                VulnType.COMMAND_INJECTION: 'COMMAND_INJECTION',
                VulnType.CODE_INJECTION: 'CODE_INJECTION',
                VulnType.FILE_INCLUSION: 'FILE_INCLUSION',
            }

            sink_type = sink_type_map.get(vuln_type, vuln_type.name)

            is_vuln, source = self.dataflow_analyzer.is_tainted_at_sink(
                var_taints, line, sink_type
            )

            if is_vuln:
                return True, 0.1
            else:
                return False, -0.3

        except Exception:
            return True, 0.0

    def _detect_framework(self, code: str) -> Optional[str]:
        for fw, patterns in self.frameworks.items():
            for pattern in patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    return fw
        return None

    def _find_sources(self, code: str, line_num: int) -> List[str]:
        lines = code.split('\n')
        start = max(0, line_num - 15)
        context = '\n'.join(lines[start:line_num])

        found = []
        for name, pattern in self.sources.items():
            if re.search(pattern, context, re.IGNORECASE):
                found.append(name)
        return found

    def _find_sanitizers(self, code: str, line_num: int, vuln_type: VulnType) -> List[str]:
        lines = code.split('\n')
        start = max(0, line_num - 20)
        context = '\n'.join(lines[start:line_num])

        found = []
        for name, info in self.sanitizers.items():
            if vuln_type in info['protects']:
                if re.search(info['pattern'], context, re.IGNORECASE):
                    found.append(name)
        return found

    def _check_auth_context(self, code: str, line_num: int) -> bool:
        lines = code.split('\n')
        start = max(0, line_num - 50)
        context = '\n'.join(lines[start:line_num])

        auth_patterns = [
            r'if\s*\([^)]*(?:logged|auth|admin|session)',
            r'if\s*\([^)]*\$_SESSION',
            r'user_group\s*!=\s*1',
            r'->isAdmin\(',
            r'->isAuthenticated\(',
            r'->isLoggedIn\(',
            r'\$member_id\s*\[\s*[\'"]user_group[\'"]',
            r'check_permission\s*\(',
            r'current_user_can\s*\(',
            r'Auth::\w+\s*\(',
            r'\$this->user',
            r'middleware.*auth',
        ]

        for pattern in auth_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        return False

    def _detect_custom_sanitizers(self, code: str) -> List[str]:
        custom_sanitizers = []

        sanitizer_patterns = [
            r'function\s+(sanitize\w*|clean\w*|escape\w*|filter\w*|validate\w*|safe\w*)\s*\(',
            r'function\s+(\w*_clean|\w*_escape|\w*_filter|\w*_sanitize)\s*\(',
        ]

        for pattern in sanitizer_patterns:
            matches = re.findall(pattern, code, re.I)
            custom_sanitizers.extend(matches)

        return custom_sanitizers

    def _check_wrapped_in_function(self, code: str, line_num: int, funcs: List[str]) -> bool:
        lines = code.split('\n')
        if line_num > len(lines):
            return False

        line = lines[line_num - 1]

        for func in funcs:
            if re.search(rf'{func}\s*\([^)]*$', line, re.I):
                return True

        return False

    def _check_admin_path(self, filepath: str) -> bool:
        admin_indicators = [
            r'[/\\]admin[/\\]',
            r'[/\\]backend[/\\]',
            r'[/\\]dashboard[/\\]',
            r'[/\\]panel[/\\]',
            r'[/\\]manage[/\\]',
            r'[/\\]adm[/\\]',
            r'[/\\]cpanel[/\\]',
            r'[/\\]control[/\\]',
            r'[/\\]administrator[/\\]',
            r'[/\\]moderator[/\\]',
            r'[/\\]staff[/\\]',
            r'[/\\]internal[/\\]',
            r'[/\\]private[/\\]',
        ]
        for pattern in admin_indicators:
            if re.search(pattern, filepath, re.IGNORECASE):
                return True
        return False

    def _check_admin_code_context(self, code: str, line_num: int) -> bool:
        lines = code.split('\n')
        header = '\n'.join(lines[:min(50, len(lines))])

        admin_check_patterns = [
            r'\b(?:is_?admin|isAdmin|check_?admin|require_?admin)\s*\(',
            r'\b(?:has_?permission|hasPermission|check_?permission)\s*\(',
            r'\b(?:is_?superuser|isSuperuser|is_?root)\s*\(',
            r'\b(?:is_?moderator|isModerator|is_?staff)\s*\(',
            r'(?:admin|superuser|root)\s*[!=]==?\s*(?:true|1)',
            r'(?:role|user_?type|user_?level|access_?level)\s*[!=]==?\s*[\'"]?(?:admin|super)',
            r'->(?:isAdmin|isSuperAdmin|hasRole)\s*\(',
            r'Auth::(?:admin|check)\s*\(',
            r'if\s*\([^)]*(?:admin|permission|role|access)',
            r'(?:require|check|verify)_?(?:admin|auth|permission)\s*\(',
        ]

        for pattern in admin_check_patterns:
            if re.search(pattern, header, re.I):
                return True
        return False

    def _track_variable_taint(self, code: str, line_num: int, max_depth: int = 7) -> dict:
        lines = code.split('\n')
        result = {'tainted': False, 'sanitized': False, 'hops': 0}

        if line_num > len(lines):
            return result

        current_line = lines[line_num - 1]

        var_matches = re.findall(r'\$([a-zA-Z_]\w*)', current_line)
        if not var_matches:
            return result

        tracked_vars = set(var_matches)
        visited_lines = set()

        for depth in range(max_depth):
            start = max(0, line_num - 1 - (depth * 10))
            end = line_num - 1

            for i in range(end - 1, start - 1, -1):
                if i in visited_lines or i >= len(lines):
                    continue
                visited_lines.add(i)

                line = lines[i]

                for var in list(tracked_vars):
                    assign_pattern = rf'\${var}\s*=\s*(.+?)(?:;|$)'
                    match = re.search(assign_pattern, line)
                    if match:
                        rhs = match.group(1)

                        if re.search(r'\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)', rhs):
                            result['tainted'] = True
                            result['hops'] = depth + 1

                        if re.search(r'(?:intval|htmlspecialchars|escape|sanitize|filter_var|addslashes)\s*\(', rhs, re.I):
                            result['sanitized'] = True

                        new_vars = re.findall(r'\$([a-zA-Z_]\w*)', rhs)
                        tracked_vars.update(new_vars)

        return result

    def _is_in_comment(self, code: str, line_num: int) -> bool:
        lines = code.split('\n')
        if line_num > len(lines):
            return False

        line = lines[line_num - 1].strip()

        if line.startswith('//') or line.startswith('#') or line.startswith('*'):
            return True

        in_comment = False
        for i in range(line_num):
            l = lines[i]
            if '/*' in l:
                in_comment = True
            if '*/' in l:
                in_comment = False

        return in_comment

    def _is_false_positive_pattern(self, line: str, vuln_type: VulnType) -> bool:

        if len(line.strip()) < 10:
            return True

        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('#') or stripped.startswith('/*') or stripped.startswith('*'):
            return True

        if re.search(r'(?:example|sample|demo|test|TODO|FIXME|NOTE):', line, re.I):
            return True

        if re.search(r'(?:echo|print)\s+["\'].*(?:error|warning|notice|failed)', line, re.I):
            return True

        if vuln_type not in (VulnType.LOG_INJECTION, VulnType.SENSITIVE_DATA_IN_LOGS):
            if re.search(r'(?:log|debug|trace|error_log)\s*\(', line, re.I):
                return True

        if re.search(r'(?:define|const)\s*\(?\s*[\'"][A-Z_]+[\'"]', line, re.I):
            return True


        if vuln_type == VulnType.SQL_INJECTION:
            if re.search(r'\?\s*,|\:\w+|bindParam|bindValue', line, re.I):
                return True
            if re.search(r'->(?:where|find|first|get)\s*\([^,]+,\s*\[', line, re.I):
                return True
            if re.search(r'->prepare\s*\(', line, re.I):
                return True
            if re.search(r'->query\s*\(', line) and not re.search(r'\$', line):
                return True
            if re.search(r'(?:intval|\(int\))\s*\([^)]*\$', line, re.I):
                return True
            if re.search(r'sprintf\s*\(\s*\$(?:LANG|lang|_LANG|language|locale|L10N|i18n)\w*\s*\[', line, re.I):
                return True
            if re.search(r'\$(?:LANG|lang|_LANG)\w*\s*\[.*\]\s*\.', line, re.I):
                if not re.search(r'(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b', line, re.I):
                    return True

        if vuln_type == VulnType.XSS:
            if re.search(r'(?:htmlspecialchars|esc_html|e\()\s*\(', line, re.I):
                return True
            if re.search(r'json_encode|application/json', line, re.I):
                return True
            if re.search(r'<<<\s*[\'"]?\w+[\'"]?\s*$', line):
                return True
            if re.search(r'^\s*\w+\s*;\s*$', line):
                return True
            if re.search(r'^<[a-zA-Z][^${}]*>$', line.strip()):
                return True
            if re.search(r'\$_(GET|POST|REQUEST)\s*\[[^\]]+\]\s*(?:==|!=|===|!==|>|<|AND|OR|\|\||&&)', line, re.I):
                return True
            if re.search(r'\$\w+\s*=\s*\$_(GET|POST|REQUEST)', line, re.I):
                if not re.search(r'(?:echo|print)\s', line, re.I):
                    return True
            if re.search(r'(?:isset|empty)\s*\(\s*\$_(GET|POST|REQUEST)', line, re.I):
                return True
            if re.search(r'user_hash|csrf|token.*=', line, re.I):
                return True
            if re.search(r'\w+\s*\(\s*\$_(GET|POST|REQUEST)', line, re.I):
                if not re.search(r'(?:echo|print)\s', line, re.I):
                    return True
            if re.search(r'\[\s*\$_(GET|POST|REQUEST)', line, re.I):
                return True

        if vuln_type == VulnType.COMMAND_INJECTION:
            if re.search(r'escapeshell(?:arg|cmd)\s*\(', line, re.I):
                return True
            if re.search(r'(?:mysqli?_|pg_|oci_|sqlite_|->)\s*(?:exec|execute|query)', line, re.I):
                return True
            if re.search(r'\$\w+->execute\s*\(', line, re.I):
                return True
            if '`' in line:
                line_upper = line.upper()
                sql_words = {
                    'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'ALTER',
                    'DROP', 'PRIMARY', 'FOREIGN', 'UNIQUE', 'KEY', 'INDEX',
                    'FROM', 'WHERE', 'JOIN', 'TABLE', 'DATABASE', 'FULLTEXT',
                    'ENGINE', 'AUTO_INCREMENT', 'DEFAULT', 'VARCHAR', 'TEXT',
                    'ENUM', 'VALUES', 'INTO', 'ORDER', 'GROUP', 'HAVING',
                    'LIMIT', 'UNION', 'EXISTS', 'DISTINCT', 'CONSTRAINT',
                    'REFERENCES', 'CASCADE', 'REPLACE', 'CHARSET', 'COLLATE',
                    'UNSIGNED', 'BIGINT', 'SMALLINT', 'TINYINT', 'MEDIUMINT',
                    'BLOB', 'MEDIUMTEXT', 'LONGTEXT', 'DATETIME', 'TIMESTAMP',
                    'BOOLEAN', 'BINARY', 'VARBINARY', 'NVARCHAR',
                }
                if any(w in line_upper for w in sql_words):
                    return True
                if re.search(r'->query\s*\([^)]*`', line, re.I):
                    return True
                if re.search(r'"[^"]*`[^"]*"', line):
                    return True
                if re.search(r"'[^']*`[^']*'", line):
                    return True
                if re.search(r'\.\s*["\']\s*`', line):
                    return True
                if re.search(r'`\s*["\'].*\.', line):
                    return True
                if re.search(r'(?:PREFIX|TABLE_PREFIX|DB_PREFIX)', line, re.I):
                    return True
                if re.search(r'\$\w*(?:db|sql|mysql|mysqli|pdo|conn|connection|query|stmt)\w*\s*->', line, re.I):
                    return True
            if re.search(r'safesql\s*\(', line, re.I):
                return True

        if vuln_type == VulnType.CODE_INJECTION:
            # DLE CMS standard encoding pattern (commercial license protection)
            if re.search(r'\$_F\s*=\s*__FILE__', line):
                return True
            if re.search(r'\$_X\s*=\s*["\']', line):
                return True
            if re.search(r'(?:ioncube|zend|sourceguardian|phpshield)\s*(?:loader|guard|encoded)', line, re.I):
                return True
            if re.search(r'\beval\s*\(\s*["\'][^$]+["\']', line):
                return True
            if re.search(r'(?:template|view|render|blade|twig)', line, re.I):
                return True
            if re.search(r'eval\s*\([^)]*(?:class|function|namespace)', line, re.I):
                return True

        if vuln_type == VulnType.FILE_INCLUSION:
            if re.search(r'(?:include|require)[^$]+["\'][^"\'$]+\.php["\']', line, re.I):
                return True
            if re.search(r'\$_SERVER\s*\[\s*[\'"]DOCUMENT_ROOT[\'"]\s*\]\s*\.\s*[\'"]/', line, re.I):
                return True
            if re.search(r'(?:include|require).*\b[A-Z_]{3,}\b\s*\.\s*[\'"]', line, re.I):
                return True
            if re.search(r'(?:include|require).*__(?:DIR|FILE)__', line, re.I):
                return True
            if re.search(r'(?:include|require).*\$_?(?:CONF|CONFIG|CFG|config)\s*\[', line, re.I):
                if re.search(r'\.\s*[\'"][^"\'$]+\.php["\']', line):
                    return True
            if re.search(r'(?:include|require).*\$(?:plugin|module|component|class)_(?:path|dir|inst|file)', line, re.I):
                return True
            if re.search(r'(?:include|require)\w*\s*\(?\s*\$\w*(?:Config|Env|Setting|Option)(?:File|Path)', line, re.I):
                return True
            if re.search(r'(?:include|require)\w*\s*\(?\s*\$\w+\s*\)', line, re.I):
                if not re.search(r'\$_(GET|POST|REQUEST|COOKIE)', line, re.I):
                    pass
            if re.search(r'(?:include|require)\w*\s*\(?\s*\$(?:composer|autoload|vendor)', line, re.I):
                return True

        if vuln_type == VulnType.PATH_TRAVERSAL:
            if re.search(r'__(?:DIR|FILE)__\s*\.\s*[\'"]', line, re.I):
                return True
            if re.search(r'(?:include|require)(?:_once)?\s*\(\s*["\'][^"\'$]+["\']', line, re.I):
                return True
            if re.search(r'str_replace\s*\(\s*["\']', line, re.I):
                if not re.search(r'\.\.|%2e|%00', line, re.I):
                    return True
            if re.search(r'\$_POST\s*\[[^\]]+\]\s*\)', line, re.I):
                if re.search(r'(?:str_replace|addslashes|addcslashes|preg_replace)\s*\(', line, re.I):
                    return True

        if vuln_type == VulnType.FILE_WRITE:
            if re.search(r'file_put_contents\s*\(\s*["\'][^"\'$]+["\']', line, re.I):
                return True
            if re.search(r'file_put_contents\s*\([^,]*(?:cache|temp|tmp|log|\.lock)', line, re.I):
                return True
            if re.search(r'file_put_contents\s*\(\s*\$\w*(?:etag|cache|hash|compiled|manifest)', line, re.I):
                return True
            if re.search(r'@file_put_contents\s*\(', line, re.I):
                if not re.search(r'\$_(GET|POST|REQUEST|COOKIE)', line, re.I):
                    return True

        if vuln_type == VulnType.FILE_READ:
            if re.search(r'file_get_contents\s*\(\s*["\'][^"\'$]+["\']', line, re.I):
                return True
            if re.search(r'file_get_contents\s*\([^)]*(?:BASEPATH|ROOT_DIR|__DIR__|dirname)', line, re.I):
                return True
            if re.search(r'file_get_contents\s*\(\s*\$\w*(?:etag|cache|config|template|theme|layout|css|style)\w*\s*\)', line, re.I):
                return True

        if vuln_type == VulnType.UNSAFE_UPLOAD:
            if re.search(r'(?:echo|print|die|exit)\s*[^;]*\$_FILES', line, re.I):
                return True
            if re.search(r'move_uploaded_file\s*\([^,]+,\s*[^)]*(?:md5|sha1|uniqid|time)\s*\(', line, re.I):
                return True

        if vuln_type == VulnType.TYPE_JUGGLING:
            if '===' in line or '!==' in line:
                cleaned = line.replace('!==', '').replace('===', '')
                if '==' not in cleaned:
                    return True
            if re.search(r'==\s*["\'](?:lostpassword|login|logout|register|auth|session)', line, re.I):
                return True
            if re.search(r'\$(?:action|do|mode|act|cmd|op|type|step|page|view|tab|section|category)\s*==', line, re.I):
                return True
            if not re.search(r'\$\w*(?:pass|pwd|token|hash|secret|credential|key)\w*\s*==', line, re.I):
                if not re.search(r'==\s*\$\w*(?:pass|pwd|token|hash|secret|credential|key)', line, re.I):
                    return True

        if vuln_type == VulnType.HARDCODED_CREDS:
            if re.search(r'(?:UPDATE|INSERT)\s+.*password\s*=\s*[\'"]?\{?\$', line, re.I):
                return True
            if re.search(r'["\']password["\']?\s*(?:=>|,|\.)', line, re.I):
                return True
            if re.search(r'password\s*=\s*(?:md5|sha1|sha256|password_hash|crypt)\s*\(', line, re.I):
                return True
            if re.search(r'password\s*=\s*["\']["\']', line, re.I):
                return True
            if re.search(r'password\s*=\s*[\'"]?\{?\$', line, re.I):
                return True
            if re.search(r'password\s*=\s*[\'"][\'"]?\s*\.\s*\$', line, re.I):
                return True
            if re.search(r'\[\s*[\'"]password[\'"]\s*\]\s*=', line, re.I):
                return True
            if re.search(r'(?:url|api|endpoint|auth_url)\s*=', line, re.I):
                return True
            if re.search(r'token=.*\$_(?:GET|POST|REQUEST)', line, re.I):
                return True

        if vuln_type == VulnType.WEAK_CRYPTO:
            if re.search(r'(?:cache|etag|checksum|file_?hash|content_?hash)\s*=', line, re.I):
                return True
            if re.search(r'(?:md5|sha1)_file\s*\(', line, re.I):
                return True
            if re.search(r'(?:md5|sha1)\s*\([^)]*(?:SECURE|SECRET|KEY|SALT|_KEY)', line, re.I):
                if not re.search(r'password|passwd|pwd|token|auth', line, re.I):
                    return True
            if re.search(r'(?:login_?hash|session_?hash|cookie_?hash|user_?agent)', line, re.I):
                return True
            if re.search(r'(?:uniqid|microtime|rand|time)\s*\(', line, re.I):
                return True
            if re.search(r'(?:md5|sha1)\s*\(\s*(?:json_encode|serialize|implode)\s*\(', line, re.I):
                return True
            if re.search(r'\$\w*(?:hash|md5|digest)\s*=\s*(?:md5|sha1)\s*\(', line, re.I):
                if not re.search(r'password|passwd|pwd', line, re.I):
                    return True
            if re.search(r'(?:less|sass|scss|css|compile|asset)\w*', line, re.I):
                if re.search(r'(?:md5|sha1|crc32)\s*\(', line, re.I):
                    return True

        if vuln_type == VulnType.XXE:
            if re.search(r'libxml_disable_entity_loader\s*\(\s*true', line, re.I):
                return True
            if re.search(r'simplexml_load_string\s*\(', line) and 'LIBXML_NOENT' not in line:
                pass
            if re.search(r'simplexml_load_string\s*\(\s*["\']<', line):
                return True
            if re.search(r'simplexml_load_file\s*\(\s*["\']', line):
                return True
            if re.search(r'file_get_contents\s*\(\s*["\']php://input["\']', line, re.I):
                return True

        if vuln_type == VulnType.SSRF:
            if re.search(r'(?:stripos|strpos)\s*\([^)]*[\'"]https?://', line, re.I):
                return True
            if re.search(r'filter_var\s*\([^)]*FILTER_VALIDATE_URL', line, re.I):
                return True
            if re.search(r'(?:in_array|preg_match)\s*\([^)]*(?:allowed|whitelist|valid)', line, re.I):
                return True
            if re.search(r'file_get_contents\s*\(\s*\$\w*(?:etag|cache|config|template|theme|layout|css|style|path|file_?name)\w*\s*\)', line, re.I):
                if not re.search(r'\$_(GET|POST|REQUEST|COOKIE)', line, re.I):
                    return True
            if re.search(r'(?:locator|resolver|finder|loader)\s*(?:->|::)\s*(?:get|find|locate|resolve)\s*\(', line, re.I):
                return True

        if vuln_type == VulnType.IDOR:
            if re.search(r'\$_SESSION\s*\[\s*[\'"](?:user_?id|member_?id|id)[\'"]\s*\]', line, re.I):
                return True
            if re.search(r'intval\s*\(\s*\$_(?:GET|POST)', line, re.I):
                pass

        if vuln_type == VulnType.HEADER_INJECTION:
            if re.search(r'header\s*\(\s*["\']Location:\s*/', line) and not re.search(r'\$_(GET|POST|REQUEST)', line):
                return True
            if re.search(r'str_replace\s*\([^)]*\\[rn]', line, re.I):
                return True
            if re.search(r'header\s*\(\s*["\'](?:ETag|Cache-control|Expires|Content-Type|Status|X-)\s*:', line, re.I):
                if not re.search(r'\$_(GET|POST|REQUEST|COOKIE)', line, re.I):
                    return True
            if re.search(r'header\s*\(\s*["\']Content-Disposition:\s*attachment', line, re.I):
                if not re.search(r'\$_(GET|POST|REQUEST|COOKIE)', line, re.I):
                    return True
            if re.search(r'header\s*\(\s*["\']Location:\s*["\']?\s*\.\s*\$(?:url|redirect|location|return_url|site_url)', line, re.I):
                if not re.search(r'\$_(GET|POST|REQUEST|COOKIE)', line, re.I):
                    return True
            if re.search(r'header\s*\(\s*["\'](?:WWW-Authenticate|P3P|Pragma|Vary|Access-Control)', line, re.I):
                return True
            if re.search(r'header\s*\(\s*["\']Location:\s*[^"\']+["\']\s*\)', line, re.I):
                if not re.search(r'\.\s*\$', line):
                    return True

        if vuln_type == VulnType.MASS_ASSIGNMENT:
            if re.search(r'->only\s*\(', line, re.I):
                return True
            if re.search(r'\$fillable\s*=', line, re.I):
                return True

        if vuln_type == VulnType.INSECURE_RANDOM:
            if re.search(r'(?:random_bytes|random_int|openssl_random_pseudo_bytes)\s*\(', line, re.I):
                return True
            if re.search(r'(?:md5|sha1)\s*\(\s*(?:microtime|time)\s*\(', line, re.I):
                if re.search(r'(?:etag|cache|css|style|header\s*\(\s*["\']ETag)', line, re.I):
                    return True
            if re.search(r'(?:uuid|feed|atom|rss|slug)\s*', line, re.I):
                if re.search(r'(?:md5|sha1)\s*\(\s*(?:\$\w+\s*\?\s*:\s*)?(?:uniqid|microtime)', line, re.I):
                    return True
            if re.search(r'\$(?:etag|cache_?key|css_?hash|style_?hash)\s*=\s*(?:md5|sha1)\s*\(', line, re.I):
                return True
            if re.search(r'array_rand\s*\(', line, re.I):
                return True
            if re.search(r'uniqid\s*\(\s*["\']', line, re.I):
                if not re.search(r'(?:token|session|csrf|nonce|auth|rand|random)', line, re.I):
                    return True
            if re.search(r'(?:mt_rand|rand)\s*\(', line, re.I):
                if re.search(r'(?:color|position|delay|margin|padding|width|height|font|captcha|placeholder)', line, re.I):
                    return True
            if re.search(r'\$_SESSION\s*\[', line, re.I):
                if not re.search(r'(?:mt_rand|rand|uniqid)\s*\(', line, re.I):
                    return True

        if vuln_type == VulnType.RACE_CONDITION:
            if re.search(r'flock\s*\(', line, re.I):
                return True
            if re.search(r'@?chmod\s*\(', line, re.I):
                return True
            if re.search(r'@?mkdir\s*\(', line, re.I):
                return True
            if re.search(r'@?(?:unlink|rmdir)\s*\(', line, re.I):
                if not re.search(r'\$_(GET|POST|REQUEST|COOKIE)', line, re.I):
                    return True
            if re.search(r'file_exists\s*\([^)]+\)\s*&&\s*@?(?:unlink|rmdir)', line, re.I):
                return True
            if re.search(r'clearstatcache\s*\(', line, re.I):
                return True
            if re.search(r'@?touch\s*\(', line, re.I):
                return True
            if re.search(r'@?(?:rename|copy)\s*\(', line, re.I):
                if not re.search(r'\$_(GET|POST|REQUEST|COOKIE)', line, re.I):
                    return True
            if re.search(r'^[^=]*(?:is_dir|is_file|is_writable|is_readable)\s*\(', line, re.I):
                return True
            if re.search(r'(?:rss|feed|atom|syndication|sitemap)', line, re.I):
                return True
            if re.search(r'file_exists\s*\(\s*\$', line, re.I):
                if not re.search(r'(?:unlink|rmdir|rename|move|copy|fopen|include|require)', line, re.I):
                    return True
            if re.search(r'@?fopen\s*\(', line, re.I):
                if re.search(r'(?:log|cache|temp|tmp|rss|rdf|feed|sitemap)\w*', line, re.I):
                    return True
                if re.search(r'fopen\s*\(\s*\$(?:this|self)\s*->', line, re.I):
                    return True
                if re.search(r'fopen\s*\(\s*\$_?(?:CONF|CONFIG|CFG)\s*\[', line, re.I):
                    return True
                if re.search(r'fopen\s*\([^)]+,\s*["\'][wa][+"]?\s*["\']', line, re.I):
                    if not re.search(r'\$_(GET|POST|REQUEST|COOKIE)', line, re.I):
                        return True

        if vuln_type == VulnType.INFO_DISCLOSURE:
            if re.search(r'print_r\s*\([^,]+,\s*(?:true|TRUE|1)\s*\)', line, re.I):
                return True
            if re.search(r'\$(?:lang|_LANG|language|locale|i18n|l10n)\s*\[', line, re.I):
                return True
            if re.search(r'(?:display_errors|error_reporting|ini_set)', line, re.I):
                return True
            if re.search(r'\$\w*(?:debug|trace|log)\w*\s*[.=]', line, re.I):
                if not re.search(r'(?:echo|print)\s', line, re.I):
                    return True
            if re.search(r'=>\s*["\'].*(?:phpinfo|phpversion|server_info)', line, re.I):
                return True
            if re.search(r'["\'][\w_]+["\']\s*=>\s*["\']', line, re.I):
                if not re.search(r'(?:echo|print|die|exit)\s', line, re.I):
                    return True

        if vuln_type == VulnType.SSTI:
            if re.search(r'(?:render|display|fetch)\s*\(\s*["\'][^"\'$]+["\']', line, re.I):
                return True
            if re.search(r'->assign\s*\(\s*["\']', line, re.I):
                return True

        if vuln_type == VulnType.PHAR_DESERIALIZATION:
            if re.search(r'(?:file_exists|is_dir|is_file)\s*\(\s*["\'][^"\'$]+["\']\s*\)', line, re.I):
                return True
            if re.search(r'__(?:DIR|FILE)__', line, re.I):
                if not re.search(r'\$_(GET|POST|REQUEST|COOKIE)', line, re.I):
                    return True
            if re.search(r'(?:file_exists|is_dir|is_file)\s*\(\s*\$_?(?:CONF|CONFIG|CFG|config)\s*\[', line, re.I):
                return True
            if re.search(r'\$_FILES\s*\[', line, re.I):
                return True
            if not re.search(r'\$_(GET|POST|REQUEST|COOKIE|SERVER)', line, re.I):
                if not re.search(r'phar://', line, re.I):
                    return True

        if vuln_type == VulnType.ASSERT_INJECTION:
            if re.search(r'assert\s*\(\s*["\'][^$]+["\']', line):
                return True
            if re.search(r'assert\s*\(\s*\$\w+\s*(?:===|!==|instanceof|>|<)', line):
                return True

        if vuln_type == VulnType.UNSAFE_OBJECT_INSTANTIATION:
            if re.search(r'(?:in_array|class_exists)\s*\(', line, re.I):
                return True
            if re.search(r'new\s+[A-Z]\w+\s*\(', line):
                return True

        if vuln_type == VulnType.CREATE_FUNCTION:
            if re.search(r'//.*create_function|/\*.*create_function', line, re.I):
                return True

        if vuln_type == VulnType.FORMAT_STRING:
            if re.search(r'(?:sprintf|printf)\s*\(\s*["\']', line, re.I):
                return True
            if re.search(r'sprintf\s*\(\s*\$(?:LANG|lang|_LANG|language|locale)\w*\s*\[', line, re.I):
                return True

        if vuln_type == VulnType.UNSAFE_EXTRACT:
            if re.search(r'extract\s*\([^)]*(?:EXTR_SKIP|EXTR_PREFIX_ALL|EXTR_PREFIX_SAME|EXTR_IF_EXISTS)', line, re.I):
                return True
            if re.search(r'extract\s*\(\s*\$(?:row|record|result|data)\s*\)', line, re.I):
                if not re.search(r'\$_(GET|POST|REQUEST|COOKIE)', line, re.I):
                    return True

        if vuln_type == VulnType.UNSAFE_PARSE_STR:
            if re.search(r'parse_str\s*\([^,]+,\s*\$\w+', line, re.I):
                return True

        if vuln_type == VulnType.PHPINFO_EXPOSURE:
            if re.search(r'//.*phpinfo|/\*.*phpinfo', line, re.I):
                return True
            if re.search(r'["\'].*phpinfo.*["\']', line, re.I):
                if not re.search(r'phpinfo\s*\(', line, re.I):
                    return True
            if re.search(r'=>\s*["\'].*phpinfo', line, re.I):
                return True

        if vuln_type == VulnType.INSECURE_PASSWORD_STORAGE:
            if re.search(r'(?:cache|etag|checksum|file_?hash|content_?hash)\s*=', line, re.I):
                return True
            if re.search(r'(?:md5|sha1)_file\s*\(', line, re.I):
                return True
            if not re.search(r'(?:password|passwd|pwd)', line, re.I):
                return True

        if vuln_type == VulnType.INSECURE_CRYPTO_DEFAULTS:
            if re.search(r'//.*(?:ecb|mcrypt|des)|/\*.*(?:ecb|mcrypt|des)', line, re.I):
                return True

        if vuln_type == VulnType.IMPROPER_CERT_VALIDATION:
            if re.search(r'//.*(?:VERIFYPEER|verify_peer)|/\*.*(?:VERIFYPEER|verify_peer)', line, re.I):
                return True
            if re.search(r'(?:dev|test|debug|localhost|127\.0\.0\.1)', line, re.I):
                return True

        if vuln_type == VulnType.UNSAFE_PUTENV:
            if re.search(r'putenv\s*\(\s*["\'][A-Z_]+=(?:[^"\'$]+)["\']', line):
                if not re.search(r'(?:LD_PRELOAD|PATH=|LD_LIBRARY)', line, re.I):
                    return True

        if vuln_type == VulnType.YAML_INJECTION:
            if re.search(r'(?:yaml_parse_file|Yaml::parseFile)\s*\(\s*["\'][^"\'$]+["\']', line, re.I):
                return True

        if vuln_type == VulnType.UNSAFE_CALLBACK:
            if re.search(r'(?:array_map|array_filter|usort)\s*\(\s*["\']', line, re.I):
                return True
            if re.search(r'(?:array_map|array_filter|usort)\s*\(\s*function\s*\(', line, re.I):
                return True
            if re.search(r'(?:array_map|array_filter)\s*\(\s*\[\s*\$this\s*,', line, re.I):
                return True

        if vuln_type == VulnType.INSECURE_PHP_CONFIG:
            if re.search(r'//.*ini_set|/\*.*ini_set', line, re.I):
                return True

        if vuln_type == VulnType.SENSITIVE_DATA_IN_LOGS:
            if re.search(r'(?:str_repeat|mask|redact|censor)\s*\(', line, re.I):
                return True
            if re.search(r'password_verify|password_hash|password_needs_rehash', line, re.I):
                return True

        if vuln_type == VulnType.IMPROPER_ERROR_HANDLING:
            if re.search(r'catch.*\{.*(?:log|error_log|->error|->warning)', line, re.I):
                return True
            if re.search(r'display_errors.*(?:0|false|off|Off)', line, re.I):
                return True
            if re.search(r'catch\s*\(\s*(?:\\?\w+)?(?:Exception|Error|Throwable)\s+\$\w+\s*\)\s*\{?\s*\}?$', line, re.I):
                return True
            if re.search(r'}\s*catch\s*\(', line, re.I):
                return True

        if vuln_type == VulnType.AUTH_BYPASS_USER_KEY:
            if re.search(r'\$_SESSION\s*\[\s*[\'"](?:user_?id|id)[\'"]\s*\]', line, re.I):
                return True
            if re.search(r'(?:auth|permission|owner|belongs)', line, re.I):
                return True

        if vuln_type == VulnType.WEAK_SESSION_MANAGEMENT:
            if re.search(r'session_regenerate_id\s*\(', line, re.I):
                return True
            if re.search(r'session\.sid_length.*(?:4[8-9]|[5-9]\d|[1-9]\d{2})', line):
                return True
            if re.search(r'^\s*session_start\s*\(\s*\)\s*;?\s*$', line, re.I):
                return True
            if re.search(r'(?:if|else|elseif).*session_start', line, re.I):
                return True

        return False

    def _check_safe_context(self, code: str, line_num: int, vuln_type: VulnType) -> bool:
        lines = code.split('\n')
        start = max(0, line_num - 10)
        end = min(len(lines), line_num + 5)
        context = '\n'.join(lines[start:end])
        line = lines[line_num - 1] if line_num <= len(lines) else ""

        if self._is_in_comment(code, line_num):
            return True

        if self._is_false_positive_pattern(line, vuln_type):
            return True

        if re.search(r'eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)', line, re.I):
            return True
        if re.search(r'\$_[A-Z]\s*=\s*[\'"][A-Za-z0-9+/=]{100,}[\'"]', context, re.I):
            return True


        if re.search(r'(?:intval|floatval|abs|floor|ceil)\s*\(\s*\$', context, re.I):
            if vuln_type in [VulnType.SQL_INJECTION, VulnType.IDOR]:
                return True

        if re.search(r'\((?:int|float|bool)\)\s*\$', context, re.I):
            if vuln_type in [VulnType.SQL_INJECTION, VulnType.IDOR]:
                return True

        if vuln_type == VulnType.XSS:
            if re.search(r'json_encode\s*\(', context, re.I):
                return True
            if re.search(r'Content-Type.*application/json', context, re.I):
                return True
            if re.search(r'header\s*\([^)]*application/json', context, re.I):
                return True
            if not re.search(r'(?:echo|print|die|exit)\s', line, re.I):
                if not re.search(r'<\?(?:php)?\s*=', line, re.I):
                    if re.search(r'\$_(?:REQUEST|GET|POST)\s*\[\s*["\']["\'\]]+\s*\]', line):
                        if re.search(r'(?:=|\+|-|\*|/|%|<|>|\b(?:if|while|for)\b)', line):
                            return True

        if re.search(r'return\s+response\(\)->json', context, re.I):
            return True

        if vuln_type == VulnType.FILE_INCLUSION:
            if re.search(r'(?:include|require)[^$]*["\'][^"\'$]+["\']', line, re.I):
                return True
            if re.search(r'preg_replace\s*\(\s*["\']\/\[\^[a-z0-9_ -]+\]\/[i]?["\']', context, re.I):
                return True
            if re.search(r'__(?:DIR|FILE)__\s*\.\s*[\'"]', context, re.I):
                return True

        if vuln_type == VulnType.PATH_TRAVERSAL:
            if re.search(r'__(?:DIR|FILE)__\s*\.\s*[\'"]', line, re.I):
                return True
            if re.search(r'(?:include|require)(?:_once)?\s*\(\s*["\'][^"\'$]+["\']', line, re.I):
                return True

        if vuln_type in (VulnType.FILE_WRITE, VulnType.FILE_READ):
            if re.search(r'realpath\s*\([^)]+\)\s*(?:===|!==|==|!=)', context, re.I):
                return True
            if re.search(r'basename\s*\(', context, re.I):
                return True

        if vuln_type == VulnType.FILE_READ:
            m = re.search(r'file_get_contents\s*\(\s*\$(\w+)', line)
            if m:
                var_name = m.group(1)
                assign_pat = r'\$' + re.escape(var_name) + r'\s*='
                assign_match = re.search(assign_pat, context)
                if assign_match:
                    assign_line = context[assign_match.start():context.find('\n', assign_match.start())]
                    if not re.search(r'\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)', assign_line, re.I):
                        if re.search(r'(?:_CONF|_CONFIG|ROOT|BASE|DIR|PATH|LAYOUT|THEME)\b', assign_line, re.I):
                            return True

        if vuln_type == VulnType.INSECURE_RANDOM:
            if re.search(r'header\s*\(\s*["\'](?:ETag|Cache-control|Expires)', context, re.I):
                return True
            if re.search(r'\$(?:etag|cache|css|style)\w*\s*=', context, re.I):
                if re.search(r'(?:md5|sha1)\s*\(\s*(?:microtime|time)\s*\(', line, re.I):
                    return True
            if re.search(r'function\s+(?:uuid|generateUuid|generate_uuid|uniqueId)\s*\(', context, re.I):
                return True

        if vuln_type == VulnType.COMMAND_INJECTION:
            if '`' in line and re.search(r'escapeshell(?:arg|cmd)', context, re.I):
                return True

        if vuln_type == VulnType.TYPE_JUGGLING:
            if not re.search(r'(?:password|token|auth|session|login)', context, re.I):
                return True


        if vuln_type == VulnType.SSRF:
            extended_start = max(0, line_num - 50)
            extended_context = '\n'.join(lines[extended_start:line_num])

            if re.search(r'(?:filter_var|parse_url|preg_match).*(?:url|https?)', extended_context, re.I):
                return True
            if re.search(r'(?:strpos|stripos)\s*\([^)]*[\'"]https?://', extended_context, re.I):
                return True
            if re.search(r'(?:strpos|stripos).*https?.*return\s+false', extended_context, re.I | re.DOTALL):
                return True

        if vuln_type == VulnType.IDOR:
            if re.search(r'(?:user_id|owner|author)\s*[!=]==?\s*\$', context, re.I):
                return True
            if re.search(r'(?:check|has|verify).*(?:permission|access|owner)', context, re.I):
                return True

        if vuln_type == VulnType.HARDCODED_CREDS:
            if re.search(r'(?:INSERT|UPDATE|SELECT|DELETE)\s+', context, re.I):
                if re.search(r'password\s*=\s*[\'"]?\$', context, re.I):
                    return True

        if vuln_type == VulnType.WEAK_CRYPTO:
            security_context = re.search(r'(?:password|token|secret|auth|session|login|verify)', context, re.I)
            if re.search(r'(?:cache|etag|checksum|file|content|data).*(?:md5|sha1)', context, re.I):
                if not security_context:
                    return True

        if vuln_type == VulnType.HEADER_INJECTION:
            if re.search(r'str_replace\s*\([^)]*(?:\\r|\\n|[\r\n])', context, re.I):
                return True
            if re.search(r'in_array\s*\(', context, re.I):
                return True
            if re.search(r'header\s*\(\s*["\'][^$]+["\']\s*\)', line, re.I):
                return True

        if vuln_type == VulnType.MASS_ASSIGNMENT:
            if re.search(r'\$(?:fillable|guarded)\s*=\s*\[', context, re.I):
                return True
            if re.search(r'->(?:only|validated)\s*\(', context, re.I):
                return True

        if vuln_type == VulnType.LOG_INJECTION:
            if re.search(r'(?:str_replace|preg_replace)\s*\([^)]*(?:\\r|\\n)', context, re.I):
                return True

        if vuln_type == VulnType.RACE_CONDITION:
            if re.search(r'flock\s*\(', context, re.I):
                return True
            if re.search(r'(?:beginTransaction|LOCK\s+TABLES|mutex|lock)\s*\(', context, re.I):
                return True
            if re.search(r'file_exists\s*\([^)]+\)\s*\)\s*return\b', line, re.I):
                return True
            if re.search(r'file_exists\s*\([^)]+\)\s+and\s+is_(?:file|dir)\s*\(', line, re.I):
                return True
            if re.search(r'file_exists\s*\([^)]+\)\s*&&\s*is_(?:file|dir)\s*\(', line, re.I):
                return True

        if vuln_type == VulnType.PHAR_DESERIALIZATION:
            if not re.search(r'\$_(GET|POST|REQUEST|COOKIE)', context, re.I):
                if not re.search(r'phar://', context, re.I):
                    return True

        if vuln_type == VulnType.UNSAFE_EXTRACT:
            if re.search(r'EXTR_SKIP|EXTR_PREFIX', context, re.I):
                return True

        if vuln_type == VulnType.UNSAFE_OBJECT_INSTANTIATION:
            if re.search(r'(?:in_array|class_exists|switch\s*\()\s*.*\$\w+', context, re.I):
                return True

        if vuln_type == VulnType.AUTH_BYPASS_USER_KEY:
            if re.search(r'\$_SESSION\s*\[\s*[\'"](?:user_?id|id|member_?id)[\'"]\s*\]', context, re.I):
                return True
            if re.search(r'(?:check|has|verify).*(?:permission|access|owner|auth)', context, re.I):
                return True

        if vuln_type == VulnType.IMPROPER_ERROR_HANDLING:
            pass

        return False

    def _calculate_confidence(self, pattern_match: bool, sources: List[str],
                              sanitizers: List[str],
                              framework: Optional[str], in_auth: bool,
                              is_admin_path: bool = False,
                              taint_info: dict = None,
                              vuln_type: VulnType = None) -> float:
        if not pattern_match:
            return 0.0

        confidence = 0.85

        source_independent_types = {
            VulnType.WEAK_CRYPTO, VulnType.HARDCODED_CREDS,
            VulnType.INFO_DISCLOSURE, VulnType.INSECURE_RANDOM,
            VulnType.RACE_CONDITION, VulnType.LOG_INJECTION,
            VulnType.PHPINFO_EXPOSURE, VulnType.INSECURE_PASSWORD_STORAGE,
            VulnType.INSECURE_CRYPTO_DEFAULTS, VulnType.IMPROPER_CERT_VALIDATION,
            VulnType.INSECURE_PHP_CONFIG, VulnType.IMPROPER_ERROR_HANDLING,
            VulnType.WEAK_SESSION_MANAGEMENT, VulnType.CREATE_FUNCTION,
            VulnType.UNSAFE_PUTENV, VulnType.SENSITIVE_DATA_IN_LOGS,
        }

        has_weak_source = any(s == 'WEAK_INPUT' for s in sources) if sources else False
        has_strong_source = bool(sources) and not has_weak_source
        if has_strong_source:
            confidence += 0.15
        elif has_weak_source:
            confidence += 0.05
        elif vuln_type in source_independent_types:
            confidence -= 0.05
        else:
            confidence -= 0.4

        if sanitizers:
            builtin_sanitizers = ['intval', 'htmlspecialchars', 'htmlentities', 'escapeshellarg',
                                  'escapeshellcmd', 'addslashes', 'strip_tags', 'filter_var',
                                  'prepared', 'bindParam', 'bindValue', 'quote', '(int)', '(float)']

            has_builtin = any(s.lower() in [b.lower() for b in builtin_sanitizers] for s in sanitizers)
            has_custom = any(s.lower() not in [b.lower() for b in builtin_sanitizers] for s in sanitizers)

            if has_builtin:
                confidence -= 0.35
            if has_custom:
                confidence -= 0.20

        if taint_info:
            if taint_info.get('sanitized'):
                confidence -= 0.4
            elif taint_info.get('tainted'):
                confidence += 0.1
                if taint_info.get('hops', 0) <= 2:
                    confidence += 0.05

        if framework:
            confidence -= 0.20

        if in_auth:
            confidence -= 0.15

        if is_admin_path:
            confidence -= 0.15

        stages_agree = 0
        if sources:
            stages_agree += 1
        if taint_info and taint_info.get('tainted') and not taint_info.get('sanitized'):
            stages_agree += 1

        if stages_agree >= 2:
            confidence += 0.1

        return max(0.0, min(1.0, confidence))

    def scan_code(self, code: str, filepath: str = "") -> List[Finding]:
        findings = []
        lines = code.split('\n')

        basename = os.path.basename(filepath).lower() if filepath else ""
        if any(p in basename for p in ('_utf-8.php', '_utf8.php', 'language.php', 'lang.php')):
            if re.search(r'^\s*\$(?:LANG|lang|_LANG|language|L10N)\s*\[', code[:500], re.M | re.I):
                return []
        if any(p in basename for p in ('english', 'french', 'german', 'spanish', 'russian',
                                        'turkish', 'chinese', 'japanese', 'italian', 'dutch',
                                        'portuguese', 'arabic', 'korean', 'polish', 'czech')):
            array_lines = len(re.findall(r'^\s*["\'][\w_]+["\']\s*=>', code, re.M))
            if array_lines > len(lines) * 0.5:
                return []

        if len(lines) < 20 and len(code) > 5000:
            # Check for DLE encoding pattern
            if '$_F=__FILE__' in code or '$_X=' in code:
                return []
            if 'ioncube' in code.lower() or 'sg_load' in code:
                return []

        framework = self._detect_framework(code)

        is_admin_path = self._check_admin_path(filepath)

        has_admin_check = self._check_admin_code_context(code, 0)

        is_admin_only = is_admin_path and has_admin_check

        custom_sanitizers = self._detect_custom_sanitizers(code)

        for vuln_type, compiled in self.compiled_patterns.items():
            for compiled_pattern, base_severity in compiled:
                for match in compiled_pattern.finditer(code):
                    line_num = code[:match.start()].count('\n') + 1
                    line_code = lines[line_num - 1].strip() if line_num <= len(lines) else ""

                    sources = self._find_sources(code, line_num)
                    if not sources:
                        for src_name, src_pattern in self.sources.items():
                            if re.search(src_pattern, line_code, re.IGNORECASE):
                                sources.append(src_name)
                                break
                        if not sources and re.search(r'\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)', line_code):
                            m = re.search(r'\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)', line_code)
                            sources.append(m.group(0).replace('$_', ''))
                    if not sources:
                        weak_source_vars = r'\$(?:post|data|input|request|params|args|body)\s*\['
                        if re.search(weak_source_vars, line_code, re.I):
                            sources.append('WEAK_INPUT')
                    sanitizers = self._find_sanitizers(code, line_num, vuln_type)
                    in_auth = self._check_auth_context(code, line_num)

                    detected_custom_sans = self._detect_custom_sanitizer_usage(code, line_num)
                    if detected_custom_sans:
                        sanitizers.extend(detected_custom_sans)

                    if custom_sanitizers and self._check_wrapped_in_function(code, line_num, custom_sanitizers):
                        sanitizers.append('custom_wrapper')

                    taint_info = self._track_variable_taint(code, line_num, max_depth=7)

                    if self._check_safe_context(code, line_num, vuln_type):
                        continue

                    confidence = self._calculate_confidence(
                        pattern_match=True,
                        sources=sources,
                        sanitizers=sanitizers,
                        framework=framework,
                        in_auth=in_auth,
                        is_admin_path=is_admin_path,
                        taint_info=taint_info,
                        vuln_type=vuln_type,
                    )

                    if vuln_type in (VulnType.FILE_WRITE, VulnType.FILE_READ, VulnType.PATH_TRAVERSAL):
                        ctx_start = max(0, line_num - 15)
                        ctx_end = min(len(lines), line_num + 3)
                        file_ctx = '\n'.join(lines[ctx_start:ctx_end])
                        if re.search(r'base64_decode\s*\(', file_ctx, re.I):
                            confidence += 0.20

                    admin_finding = False
                    if is_admin_only:
                        admin_finding = True
                        if vuln_type in [VulnType.CODE_INJECTION, VulnType.RCE]:
                            confidence = max(0.50, confidence * 0.7)
                        elif vuln_type == VulnType.UNSAFE_UPLOAD:
                            confidence = max(0.50, confidence * 0.75)
                        else:
                            confidence = max(0.50, confidence * 0.8)

                    has_custom_sanitizer = any(s not in ['intval', 'htmlspecialchars', 'escapeshellarg'] for s in sanitizers)
                    if admin_finding or has_custom_sanitizer:
                        min_confidence = 0.40
                    else:
                        min_confidence = 0.60
                    if confidence < min_confidence:
                        continue

                    if confidence < 0.75:
                        severity = Severity.MEDIUM
                    elif confidence < 0.90:
                        severity = Severity.HIGH
                    else:
                        severity = Severity.CRITICAL if base_severity == Severity.CRITICAL else Severity.HIGH

                    finding = Finding(
                        vuln_type=vuln_type,
                        severity=severity,
                        line=line_num,
                        code=line_code[:100],
                        file=filepath,
                        pattern_match=True,
                        taint_verified=bool(sources) and not sanitizers,

                        source=sources[0] if sources else None,
                        sink=vuln_type.value,
                        sanitizers=sanitizers,
                        confidence=confidence,
                        framework=framework,
                        in_auth_context=in_auth,
                    )
                    findings.append(finding)

        if self.enable_ast and self.ast_parser:
            try:
                vuln_flows = self.ast_parser.get_vulnerable_flows(code, filepath)
                ast_vuln_lines = set()
                for flow in vuln_flows:
                    ast_vuln_lines.add((flow.sink_line, flow.sink_type))

                for f in findings:
                    type_map = {
                        VulnType.SQL_INJECTION: 'SQL_INJECTION',
                        VulnType.XSS: 'XSS',
                        VulnType.COMMAND_INJECTION: 'COMMAND_INJECTION',
                        VulnType.CODE_INJECTION: 'CODE_INJECTION',
                        VulnType.FILE_INCLUSION: 'FILE_INCLUSION',
                    }
                    ast_type = type_map.get(f.vuln_type, f.vuln_type.name)

                    if (f.line, ast_type) in ast_vuln_lines:
                        f.confidence = min(0.98, f.confidence + 0.10)
                        f.taint_verified = True
                    else:
                        f.confidence = max(0.0, f.confidence - 0.15)
            except Exception:
                pass

        multiline_findings = self._scan_multiline(code, lines, filepath, framework, is_admin_path)
        findings.extend(multiline_findings)

        file_wide_findings = self._scan_file_wide_taint(code, lines, filepath, framework, is_admin_path)
        findings.extend(file_wide_findings)

        best = {}
        for f in findings:
            key = (f.line, f.vuln_type)
            if key not in best or f.confidence > best[key].confidence:
                best[key] = f

        unique = list(best.values())

        line_types = {}
        for f in unique:
            lt = f.vuln_type
            if lt not in line_types:
                line_types[lt] = []
            line_types[lt].append(f)

        final = []
        for vuln_type, type_findings in line_types.items():
            if len(type_findings) <= 3:
                final.extend(type_findings)
            else:
                type_findings.sort(key=lambda x: x.confidence, reverse=True)
                kept = set()
                for f in type_findings:
                    if f.severity.name == 'CRITICAL' or len(kept) < 3:
                        kept.add(id(f))
                        final.append(f)

        for f in final:
            f.confidence = min(f.confidence, 1.0)
        final = [f for f in final if f.confidence >= 0.50]

        return final

    _MULTILINE_PATTERNS = None

    @classmethod
    def _get_multiline_patterns(cls):
        if cls._MULTILINE_PATTERNS is None:
            cls._MULTILINE_PATTERNS = [
                (re.compile(r'\$(\w+)\s*=\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\][^;]*;.*?(?:mysql_query|mysqli_query|pg_query)\s*\([^)]*\$\1', re.DOTALL | re.IGNORECASE),
                 VulnType.SQL_INJECTION, Severity.HIGH),
                (re.compile(r'\$(\w+)\s*=\s*\$_(GET|POST|REQUEST)\s*\[[^\]]+\][^;]*;.*?->query\s*\([^)]*\$\1', re.DOTALL | re.IGNORECASE),
                 VulnType.SQL_INJECTION, Severity.HIGH),
                (re.compile(r'\$(\w+)\s*=\s*\$_(GET|POST|REQUEST)\s*\[[^\]]+\][^;]*;.*?(?:exec|system|passthru|shell_exec)\s*\([^)]*\$\1', re.DOTALL | re.IGNORECASE),
                 VulnType.COMMAND_INJECTION, Severity.HIGH),
                (re.compile(r'\$(\w+)\s*=\s*\$_(GET|POST|REQUEST)\s*\[[^\]]+\][^;]*;.*?echo\s+[^;]*\$\1', re.DOTALL | re.IGNORECASE),
                 VulnType.XSS, Severity.HIGH),
                (re.compile(r'\$(\w+)\s*=\s*\$_(GET|POST|REQUEST)\s*\[[^\]]+\][^;]*;.*?(?:include|require)(?:_once)?\s*[\(\s][^;]*\$\1', re.DOTALL | re.IGNORECASE),
                 VulnType.FILE_INCLUSION, Severity.HIGH),
                (re.compile(r'\$(\w+)\s*=\s*\$_(GET|POST|REQUEST)\s*\[[^\]]+\][^;]*;.*?eval\s*\([^)]*\$\1', re.DOTALL | re.IGNORECASE),
                 VulnType.CODE_INJECTION, Severity.CRITICAL),
                (re.compile(r'\$(\w+)\s*=\s*\$_(GET|POST|REQUEST)\s*\[[^\]]+\][^;]*;.*?unserialize\s*\([^)]*\$\1', re.DOTALL | re.IGNORECASE),
                 VulnType.DESERIALIZATION, Severity.CRITICAL),
                (re.compile(r'\$(\w+)\s*=\s*\$_(GET|POST|REQUEST)\s*\[[^\]]+\][^;]*;.*?file_put_contents\s*\([^,]*\$\1', re.DOTALL | re.IGNORECASE),
                 VulnType.FILE_WRITE, Severity.CRITICAL),
                (re.compile(r'\$(\w+)\s*=\s*\$_(GET|POST|REQUEST)\s*\[[^\]]+\][^;]*;.*?file_get_contents\s*\([^)]*\$\1', re.DOTALL | re.IGNORECASE),
                 VulnType.FILE_READ, Severity.HIGH),
                (re.compile(r'\$(\w+)\s*=\s*base64_decode\s*\([^)]*\)[^;]*;.*?file_put_contents\s*\(\s*\$\1', re.DOTALL | re.IGNORECASE),
                 VulnType.FILE_WRITE, Severity.HIGH),
                (re.compile(r'\$(\w+)\s*=\s*base64_decode\s*\([^)]*\)[^;]*;.*?file_get_contents\s*\(\s*\$\1', re.DOTALL | re.IGNORECASE),
                 VulnType.FILE_READ, Severity.HIGH),
                (re.compile(r'file_exists\s*\(\s*\$(\w+)\s*\).*?(?:unlink|rename|chmod|chown|rmdir)\s*\(\s*\$\1', re.DOTALL | re.IGNORECASE),
                 VulnType.RACE_CONDITION, Severity.HIGH),
                (re.compile(r'base64_decode\s*\(\s*\$_(GET|POST|REQUEST)\s*\[[^\]]+\]\s*\).*?file_put_contents\s*\(', re.DOTALL | re.IGNORECASE),
                 VulnType.FILE_WRITE, Severity.CRITICAL),
                (re.compile(r'base64_decode\s*\(\s*\$_(GET|POST|REQUEST)\s*\[[^\]]+\]\s*\).*?(?:include|require)(?:_once)?\s*[\(\s]', re.DOTALL | re.IGNORECASE),
                 VulnType.FILE_INCLUSION, Severity.CRITICAL),
                (re.compile(r'file_put_contents\s*\([^,]+,\s*\$_(GET|POST|REQUEST)\s*\[', re.IGNORECASE),
                 VulnType.FILE_WRITE, Severity.CRITICAL),
            ]
        return cls._MULTILINE_PATTERNS

    def _scan_multiline(self, code: str, lines: List[str], filepath: str,
                        framework: Optional[str], is_admin_path: bool) -> List[Finding]:
        has_superglobal = re.search(r'\$_(GET|POST|REQUEST|COOKIE)\s*[\[;]', code)
        has_base64_file_op = (re.search(r'base64_decode\s*\(', code) and
                              re.search(r'(?:file_put_contents|file_get_contents|fopen|include|require)\s*\(', code))
        # toctou: file_exists() then unlink() is a race condition even without superglobals
        has_toctou = (re.search(r'file_exists\s*\(', code) and
                      re.search(r'(?:unlink|rename|chmod|chown|rmdir)\s*\(', code))
        if not has_superglobal and not has_base64_file_op and not has_toctou:
            return []

        findings = []
        window_size = 15
        patterns = self._get_multiline_patterns()

        for i in range(len(lines)):
            end = min(i + window_size, len(lines))
            window = '\n'.join(lines[i:end])

            for compiled_pat, vuln_type, severity in patterns:
                match = compiled_pat.search(window)
                if match:
                    match_end_offset = match.end()
                    sink_line = i + 1 + window[:match_end_offset].count('\n')

                    sanitizers = self._find_sanitizers_in_context(window, vuln_type)
                    if sanitizers:
                        continue

                    sink_line_code = lines[min(sink_line - 1, len(lines) - 1)]
                    # race conditions are structural, not data-flow - skip fp filter for them
                    structural_types = {VulnType.RACE_CONDITION}
                    if vuln_type not in structural_types:
                        if self._is_false_positive_pattern(sink_line_code, vuln_type):
                            continue

                    confidence = 0.80
                    if framework:
                        confidence -= 0.15
                    if is_admin_path:
                        confidence -= 0.10

                    try:
                        source_name = f'$_{match.group(2)}'
                    except (IndexError, AttributeError):
                        source_name = 'base64_decode'

                    finding = Finding(
                        vuln_type=vuln_type,
                        severity=severity,
                        line=sink_line,
                        code=sink_line_code.strip()[:100],
                        file=filepath,
                        pattern_match=True,
                        taint_verified=True,
                        source=source_name,
                        sink=vuln_type.value,
                        sanitizers=[],
                        confidence=confidence,
                        framework=framework,
                        in_auth_context=is_admin_path,
                    )
                    findings.append(finding)

        return findings

    def _scan_file_wide_taint(self, code: str, lines: List[str], filepath: str,
                              framework: Optional[str], is_admin_path: bool) -> List[Finding]:
        findings = []

        tainted_vars = {}

        for m in re.finditer(r'\$(\w+)\s*=\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[', code):
            var_name = m.group(1)
            source = m.group(2)
            line_num = code[:m.start()].count('\n') + 1
            tainted_vars[var_name] = (line_num, source)

        for m in re.finditer(r'\$(\w+)\s*=\s*\$_(GET|POST|REQUEST|COOKIE)\s*;', code):
            var_name = m.group(1)
            source = m.group(2)
            line_num = code[:m.start()].count('\n') + 1
            tainted_vars[var_name] = (line_num, source)

        for m in re.finditer(r'\$(\w+)\s*=\s*file_get_contents\s*\(\s*["\']php://input["\']', code):
            var_name = m.group(1)
            line_num = code[:m.start()].count('\n') + 1
            tainted_vars[var_name] = (line_num, 'INPUT')

        tainted_arrays = {}
        for m in re.finditer(r'\$(\w+)\s*\[\s*\]\s*=\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[', code):
            arr_name = m.group(1)
            source = m.group(2)
            line_num = code[:m.start()].count('\n') + 1
            tainted_arrays[arr_name] = (line_num, source)
        for m in re.finditer(r'\$(\w+)\s*\[[^\]]*\]\s*=\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[', code):
            arr_name = m.group(1)
            source = m.group(2)
            line_num = code[:m.start()].count('\n') + 1
            tainted_arrays[arr_name] = (line_num, source)
        for m in re.finditer(r'\$(\w+)\s*=\s*\$(\w+)\s*\[', code):
            var_name = m.group(1)
            arr_name = m.group(2)
            if arr_name in tainted_arrays:
                line_num = code[:m.start()].count('\n') + 1
                arr_line, arr_source = tainted_arrays[arr_name]
                if line_num >= arr_line and var_name not in tainted_vars:
                    tainted_vars[var_name] = (line_num, arr_source)

        tainted_props = {}
        for m in re.finditer(r'\$(\w+)->(\w+)\s*=\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[', code):
            obj_name, prop_name, source = m.group(1), m.group(2), m.group(3)
            line_num = code[:m.start()].count('\n') + 1
            tainted_props[f"${obj_name}->{prop_name}"] = (line_num, source)
            if obj_name not in tainted_vars:
                tainted_vars[obj_name] = (line_num, source)
        for m in re.finditer(r'\$(\w+)\s*=\s*\$(\w+)->(\w+)\s*;', code):
            var_name, obj_name, prop_name = m.group(1), m.group(2), m.group(3)
            key = f"${obj_name}->{prop_name}"
            if key in tainted_props:
                line_num = code[:m.start()].count('\n') + 1
                prop_line, prop_source = tainted_props[key]
                if line_num >= prop_line and var_name not in tainted_vars:
                    tainted_vars[var_name] = (line_num, prop_source)

        wrapper_funcs = set()
        for m in re.finditer(
            r'function\s+(\w+)\s*\([^)]*\)\s*\{[^}]*?return\s+\$_(GET|POST|REQUEST|COOKIE)\s*;',
            code, re.DOTALL
        ):
            wrapper_funcs.add((m.group(1), m.group(2)))

        for m in re.finditer(
            r'function\s+(\w+)\s*\([^)]*\)\s*\{[^}]*?\$_(GET|POST|REQUEST)\b[^}]*?return\s+\$_(GET|POST|REQUEST)\s*;',
            code, re.DOTALL
        ):
            wrapper_funcs.add((m.group(1), m.group(2)))

        for func_name, source_type in wrapper_funcs:
            for m in re.finditer(rf'\$(\w+)\s*=\s*{re.escape(func_name)}\s*\(', code):
                var_name = m.group(1)
                line_num = code[:m.start()].count('\n') + 1
                tainted_vars[var_name] = (line_num, source_type + '_WRAP')

        _sanitizer_funcs = {
            'intval', 'floatval', 'boolval', 'abs',
            'htmlspecialchars', 'htmlentities', 'strip_tags', 'nl2br',
            'escapeshellarg', 'escapeshellcmd',
            'addslashes', 'mysql_real_escape_string', 'mysqli_real_escape_string',
            'filter_var', 'filter_input',
            'urlencode', 'rawurlencode', 'json_encode',
            'md5', 'sha1', 'hash', 'crc32',
            'basename', 'realpath', 'dirname',
            'preg_replace', 'preg_match', 'preg_quote',
            'trim', 'ltrim', 'rtrim', 'strtolower', 'strtoupper',
            'substr', 'mb_substr', 'str_pad',
            'number_format', 'round', 'ceil', 'floor',
            'date', 'strtotime', 'mktime',
            'count', 'strlen', 'sizeof',
            'is_numeric', 'is_int', 'is_string', 'is_array', 'is_bool',
            'in_array', 'array_key_exists', 'isset', 'empty',
            'esc_html', 'esc_attr', 'esc_url', 'wp_kses',
            'e', 'clean', 'sanitize', 'escape', 'purify',
        }
        _cast_sanitized = set()
        for m in re.finditer(r'\$(\w+)\s*=\s*\((?:int|integer|float|double|bool|boolean)\)\s*\$(\w+)', code):
            sanitized_var = m.group(1)
            source_var = m.group(2)
            _cast_sanitized.add(sanitized_var)
            if sanitized_var == source_var and sanitized_var in tainted_vars:
                del tainted_vars[sanitized_var]
        for m in re.finditer(r'\$(\w+)\s*=\s*\((?:int|integer|float|double|bool|boolean)\)\s*\$\1\b', code):
            var_name = m.group(1)
            _cast_sanitized.add(var_name)
            if var_name in tainted_vars:
                del tainted_vars[var_name]

        for m in re.finditer(r'\$(\w+)\s*=\s*"([^"]*)"', code):
            var_name = m.group(1)
            string_content = m.group(2)
            line_num = code[:m.start()].count('\n') + 1
            if var_name in tainted_vars or var_name in _cast_sanitized:
                continue
            for tainted_var, (t_line, t_source) in list(tainted_vars.items()):
                if line_num >= t_line and re.search(rf'\${re.escape(tainted_var)}\b', string_content):
                    tainted_vars[var_name] = (line_num, t_source)
                    break

        for _pass in range(3):
            new_taints = {}
            for m in re.finditer(r'\$(\w+)\s*=\s*(.+?)\s*;', code):
                var_name = m.group(1)
                rhs = m.group(2)
                line_num = code[:m.start()].count('\n') + 1

                if var_name in tainted_vars or var_name in _cast_sanitized:
                    continue

                if re.match(r'\((?:int|integer|float|double|bool|boolean)\)\s*\$', rhs.strip()):
                    _cast_sanitized.add(var_name)
                    continue

                for tainted_var, (t_line, t_source) in list(tainted_vars.items()):
                    if line_num < t_line:
                        continue

                    if re.search(rf'\${re.escape(tainted_var)}\s*\[', rhs):
                        new_taints[var_name] = (line_num, t_source)
                        break

                    func_match = re.search(rf'(\w+)\s*\([^)]*\${re.escape(tainted_var)}\b', rhs)
                    if func_match:
                        func_name = func_match.group(1).lower()
                        if func_name not in _sanitizer_funcs and not any(
                            s in func_name for s in ('sanitize', 'escape', 'clean', 'filter', 'safe', 'valid', 'protect', 'purif')
                        ):
                            new_taints[var_name] = (line_num, t_source)
                            break

                    if re.search(rf'^\$?{re.escape(tainted_var)}\s*$', rhs.strip().lstrip('$')):
                        new_taints[var_name] = (line_num, t_source)
                        break

                    if re.search(rf'\${re.escape(tainted_var)}\b', rhs) and '.' in rhs:
                        new_taints[var_name] = (line_num, t_source)
                        break

            tainted_vars.update(new_taints)
            if not new_taints:
                break

        if not tainted_vars:
            return []

        sink_patterns = [
            (r'["\'](?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\.\s*\${var}\b', VulnType.SQL_INJECTION, Severity.HIGH),
            (r'["\'].*?\.\s*\${var}\s*\.\s*["\']', VulnType.SQL_INJECTION, Severity.MEDIUM),
            (r'->query\s*\(\s*\${var}\s*\)', VulnType.SQL_INJECTION, Severity.HIGH),
            (r'(?:mysql_query|mysqli_query|pg_query)\s*\([^)]*\${var}', VulnType.SQL_INJECTION, Severity.HIGH),
            (r'\becho\s+[^;]*\${var}\b', VulnType.XSS, Severity.HIGH),
            (r'\bprint\s+[^;]*\${var}\b', VulnType.XSS, Severity.HIGH),
            (r'\bprintf\s*\([^)]*\${var}', VulnType.XSS, Severity.MEDIUM),
            (r'(?:exec|system|passthru|shell_exec|popen)\s*\([^)]*\${var}', VulnType.COMMAND_INJECTION, Severity.HIGH),
            (r'\beval\s*\([^)]*\${var}', VulnType.CODE_INJECTION, Severity.CRITICAL),
            (r'(?:include|require)(?:_once)?\s*[\(\s][^;]*\${var}', VulnType.FILE_INCLUSION, Severity.HIGH),
            (r'simplexml_load_string\s*\(\s*\${var}', VulnType.XXE, Severity.HIGH),
            (r'DOMDocument.*loadXML\s*\(\s*\${var}', VulnType.XXE, Severity.HIGH),
            (r'(?:file_get_contents|curl_init)\s*\(\s*\${var}', VulnType.SSRF, Severity.HIGH),
            (r'file_put_contents\s*\(\s*\${var}\b', VulnType.FILE_WRITE, Severity.HIGH),
            (r'file_get_contents\s*\(\s*\${var}\b', VulnType.FILE_READ, Severity.HIGH),
            (r'fopen\s*\(\s*\${var}\b', VulnType.FILE_READ, Severity.HIGH),
            (r'fwrite\s*\(\s*\${var}\b', VulnType.FILE_WRITE, Severity.HIGH),
            (r'copy\s*\([^,]*\${var}', VulnType.FILE_WRITE, Severity.HIGH),
            (r'rename\s*\([^,]*\${var}', VulnType.FILE_WRITE, Severity.HIGH),
            (r'unlink\s*\(\s*\${var}\b', VulnType.PATH_TRAVERSAL, Severity.HIGH),
            (r'readfile\s*\(\s*\${var}\b', VulnType.FILE_READ, Severity.HIGH),
            (r'file_put_contents\s*\([^,]+,\s*\${var}\b', VulnType.FILE_WRITE, Severity.CRITICAL),
            (r'file_put_contents\s*\([^,]+,\s*[^)]*\${var}', VulnType.FILE_WRITE, Severity.HIGH),
            (r'fwrite\s*\([^,]+,\s*\${var}\b', VulnType.FILE_WRITE, Severity.HIGH),
            (r'fwrite\s*\([^,]+,\s*[^)]*\${var}', VulnType.FILE_WRITE, Severity.HIGH),
            (r'unserialize\s*\(\s*\${var}', VulnType.DESERIALIZATION, Severity.CRITICAL),
            (r'header\s*\([^)]*\${var}', VulnType.HEADER_INJECTION, Severity.HIGH),
            (r'header\s*\(\s*["\']Location:\s*["\'][^)]*\${var}', VulnType.OPEN_REDIRECT, Severity.HIGH),
            (r'header\s*\(\s*["\']Location:\s*[^)]*\${var}', VulnType.OPEN_REDIRECT, Severity.HIGH),
            (r'header\s*\(\s*["\']Refresh:\s*[^)]*url=\s*[^)]*\${var}', VulnType.OPEN_REDIRECT, Severity.HIGH),
            (r'->xpath\s*\([^)]*\${var}', VulnType.XPATH_INJECTION, Severity.HIGH),
            (r'xpath_eval\s*\([^)]*\${var}', VulnType.XPATH_INJECTION, Severity.HIGH),
            (r'DOMXPath.*(?:query|evaluate)\s*\([^)]*\${var}', VulnType.XPATH_INJECTION, Severity.HIGH),
            (r'ldap_search\s*\([^)]*\${var}', VulnType.LDAP_INJECTION, Severity.HIGH),
            (r'ldap_bind\s*\([^)]*\${var}', VulnType.LDAP_INJECTION, Severity.HIGH),
            (r'ldap_read\s*\([^)]*\${var}', VulnType.LDAP_INJECTION, Severity.HIGH),
            (r'ldap_list\s*\([^)]*\${var}', VulnType.LDAP_INJECTION, Severity.HIGH),
            (r'ldap_\w+\s*\([^)]*\${var}', VulnType.LDAP_INJECTION, Severity.MEDIUM),
            (r'sprintf\s*\([^)]*\${var}', VulnType.SQL_INJECTION, Severity.MEDIUM),
            (r'(?:createTemplate|render|display)\s*\([^)]*\${var}', VulnType.SSTI, Severity.HIGH),
            (r'(?:Twig|Blade|Smarty).*(?:render|compile|evaluate)\s*\([^)]*\${var}', VulnType.SSTI, Severity.HIGH),
            (r'->assign\s*\([^,]+,\s*\${var}[^)]*\).*(?:display|fetch)', VulnType.SSTI, Severity.MEDIUM),
            (r'(?:file_exists|is_dir|is_file|filesize|filetype|stat)\s*\([^)]*\${var}', VulnType.PHAR_DESERIALIZATION, Severity.HIGH),
            (r'(?:sprintf|printf|vprintf|vsprintf)\s*\(\s*\${var}', VulnType.FORMAT_STRING, Severity.HIGH),
            (r'(?:call_user_func|call_user_func_array)\s*\(\s*\${var}', VulnType.UNSAFE_CALLBACK, Severity.CRITICAL),
            (r'(?:array_map|array_filter|array_walk|usort|uasort|uksort)\s*\(\s*\${var}', VulnType.UNSAFE_CALLBACK, Severity.HIGH),
            (r'(?:yaml_parse|Yaml::parse)\s*\(\s*\${var}', VulnType.YAML_INJECTION, Severity.HIGH),
            (r'\bassert\s*\(\s*\${var}', VulnType.ASSERT_INJECTION, Severity.CRITICAL),
            (r'\bputenv\s*\([^)]*\${var}', VulnType.UNSAFE_PUTENV, Severity.HIGH),
            (r'\bnew\s+\${var}', VulnType.UNSAFE_OBJECT_INSTANTIATION, Severity.HIGH),
            (r'\bextract\s*\(\s*\${var}', VulnType.UNSAFE_EXTRACT, Severity.HIGH),
            (r'\bparse_str\s*\(\s*\${var}\s*\)', VulnType.UNSAFE_PARSE_STR, Severity.HIGH),
            (r'->(?:find|findOne|where)\s*\(\s*\${var}', VulnType.AUTH_BYPASS_USER_KEY, Severity.MEDIUM),
        ]

        for var_name, (src_line, source_type) in tainted_vars.items():
            for pattern_template, vuln_type, severity in sink_patterns:
                pattern = pattern_template.replace('{var}', re.escape(var_name))
                try:
                    for m in re.finditer(pattern, code, re.IGNORECASE):
                        sink_line = code[:m.start()].count('\n') + 1

                        if sink_line == src_line:
                            continue

                        if sink_line < src_line:
                            continue

                        line_code = lines[sink_line - 1].strip() if sink_line <= len(lines) else ""

                        context_start = code.find(lines[src_line - 1]) if src_line <= len(lines) else 0
                        context_end = code.find(lines[sink_line - 1]) if sink_line <= len(lines) else len(code)
                        context = code[context_start:context_end + len(line_code)]
                        sanitizers = self._find_sanitizers_in_context(context, vuln_type)

                        if self._is_false_positive_pattern(line_code, vuln_type):
                            continue

                        confidence = 0.75
                        if source_type in ('GET', 'POST', 'REQUEST'):
                            confidence += 0.10
                        elif source_type.endswith('_WRAP'):
                            confidence += 0.08
                        if sanitizers:
                            confidence -= 0.25
                        if framework:
                            confidence -= 0.10
                        if is_admin_path:
                            confidence -= 0.10
                        confidence = min(confidence, 1.0)

                        if severity == Severity.MEDIUM and vuln_type == VulnType.SQL_INJECTION:
                            nearby = '\n'.join(lines[max(0, sink_line-3):min(len(lines), sink_line+2)])
                            if not re.search(r'(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b', nearby, re.I):
                                continue

                        if vuln_type in (VulnType.FILE_WRITE, VulnType.FILE_READ) and severity == Severity.CRITICAL:
                            confidence = max(confidence, 0.85)

                        if confidence < 0.50:
                            continue

                        finding = Finding(
                            vuln_type=vuln_type,
                            severity=severity,
                            line=sink_line,
                            code=line_code[:100],
                            file=filepath,
                            pattern_match=True,
                            taint_verified=True,
                            source=f'$_{source_type}',
                            sink=vuln_type.value,
                            sanitizers=sanitizers,
                            confidence=confidence,
                            framework=framework,
                            in_auth_context=is_admin_path,
                        )
                        findings.append(finding)
                except re.error:
                    continue

        return findings

    def _find_sanitizers_in_context(self, context: str, vuln_type: VulnType) -> List[str]:
        found = []
        san_map = {
            VulnType.SQL_INJECTION: ['intval', '(int)', 'escape_string', 'prepare', 'bindParam', 'bindValue', 'addslashes', 'quote'],
            VulnType.XSS: ['htmlspecialchars', 'htmlentities', 'strip_tags', 'esc_html', 'esc_attr'],
            VulnType.COMMAND_INJECTION: ['escapeshellarg', 'escapeshellcmd'],
            VulnType.FILE_INCLUSION: ['basename', 'realpath', 'in_array'],
            VulnType.CODE_INJECTION: ['intval', 'is_numeric', 'in_array'],
            VulnType.DESERIALIZATION: ['allowed_classes', 'json_decode'],
            VulnType.SSRF: ['filter_var', 'parse_url', 'FILTER_VALIDATE_URL'],
            VulnType.OPEN_REDIRECT: ['filter_var', 'parse_url', 'in_array'],
            VulnType.HEADER_INJECTION: ['str_replace', 'header_remove'],
            VulnType.MASS_ASSIGNMENT: ['fillable', 'guarded', '->only'],
            VulnType.LOG_INJECTION: ['preg_replace', 'str_replace', 'filter_var'],
            VulnType.RACE_CONDITION: ['flock', 'mutex', 'lock'],
            VulnType.REGEX_DOS: ['backtrack_limit', 'set_time_limit'],
            VulnType.FILE_WRITE: ['basename', 'realpath', 'in_array', 'is_uploaded_file', 'tempnam'],
            VulnType.FILE_READ: ['basename', 'realpath', 'in_array'],
            VulnType.PATH_TRAVERSAL: ['basename', 'realpath'],
            VulnType.IDOR: ['intval', '(int)', 'is_numeric', 'user_id', 'owner_id'],
            VulnType.XXE: ['libxml_disable_entity_loader', 'LIBXML_NONET', 'LIBXML_DTDLOAD'],
            VulnType.SSTI: ['htmlspecialchars', 'e()', 'escape', 'sandbox'],
            VulnType.PHAR_DESERIALIZATION: ['realpath', 'basename', 'pathinfo'],
            VulnType.ASSERT_INJECTION: ['intval', 'is_numeric', 'ctype_alnum'],
            VulnType.UNSAFE_OBJECT_INSTANTIATION: ['in_array', 'class_exists', 'whitelist'],
            VulnType.UNSAFE_EXTRACT: ['EXTR_SKIP', 'EXTR_PREFIX_ALL'],
            VulnType.UNSAFE_PARSE_STR: ['parse_str'],
            VulnType.FORMAT_STRING: ['intval', 'is_numeric', 'htmlspecialchars'],
            VulnType.UNSAFE_PUTENV: ['escapeshellarg', 'preg_replace', 'in_array'],
            VulnType.YAML_INJECTION: ['htmlspecialchars', 'strip_tags'],
            VulnType.UNSAFE_CALLBACK: ['in_array', 'is_callable', 'whitelist'],
            VulnType.AUTH_BYPASS_USER_KEY: ['$_SESSION', 'owner_id', 'user_id'],
        }
        for san in san_map.get(vuln_type, []):
            if san in context:
                found.append(san)
        return found

    def scan_file(self, filepath: str) -> List[Finding]:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            return self.scan_code(code, filepath)
        except Exception as e:
            return []

    def scan_directory(self, dirpath: str) -> Dict:
        results = {
            'total_files': 0,
            'total_findings': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'findings': [],
        }

        php_files = glob.glob(os.path.join(dirpath, '**', '*.php'), recursive=True)
        results['total_files'] = len(php_files)

        for filepath in php_files:
            findings = self.scan_file(filepath)
            for f in findings:
                results['total_findings'] += 1

                if f.severity == Severity.CRITICAL:
                    results['critical'] += 1
                elif f.severity == Severity.HIGH:
                    results['high'] += 1
                elif f.severity == Severity.MEDIUM:
                    results['medium'] += 1
                else:
                    results['low'] += 1

                results['findings'].append(f.to_dict())

        return results

    def scan_directory_full(self, dirpath: str, enable_interprocedural: bool = True) -> Dict:
        results = self.scan_directory(dirpath)

        if enable_interprocedural and HAS_INTERPROCEDURAL:
            try:
                flows, summary = analyze_interprocedural(dirpath)
                results['interprocedural'] = {
                    'total_functions': summary['total_functions'],
                    'total_files': summary['total_files'],
                    'tainted_params': summary['tainted_params'],
                    'tainted_returns': summary['tainted_returns'],
                    'flows': []
                }
                for flow in flows:
                    results['interprocedural']['flows'].append({
                        'type': flow.vuln_type,
                        'confidence': f"{flow.confidence:.0%}",
                        'source_func': flow.source_func,
                        'source_file': flow.source_file,
                        'sink_func': flow.sink_func,
                        'sink_file': flow.sink_file,
                        'path': flow.flow_path
                    })
                    results['total_findings'] += 1
                    if flow.confidence >= 0.8:
                        results['high'] += 1
                    else:
                        results['medium'] += 1
            except Exception as e:
                results['interprocedural'] = {'error': str(e)}

        return results


def test():
    scanner = UnifiedScanner()

    test_cases = [
        ('$id=$_GET["id"];mysql_query("SELECT * FROM x WHERE id=$id");', True, "SQL Direct"),
        ('system($_POST["cmd"]);', True, "Command Direct"),
        ('include($_GET["page"].".php");', True, "LFI Direct"),
        ('echo $_GET["name"];', True, "XSS Direct"),

        ('$id=intval($_GET["id"]);mysql_query("SELECT * FROM x WHERE id=$id");', False, "SQL Sanitized"),
        ('$cmd=escapeshellarg($_POST["cmd"]);system($cmd);', False, "Command Sanitized"),
        ('$n=htmlspecialchars($_GET["name"]);echo $n;', False, "XSS Sanitized"),
    ]

    print("=" * 60)
    print("UNIFIED SCANNER TEST")
    print("=" * 60)

    passed = 0
    for code, should_find, name in test_cases:
        results = scanner.scan_code(code)
        high_conf = [r for r in results if r.confidence > 0.5]
        found = len(high_conf) > 0

        ok = found == should_find
        if ok:
            passed += 1

        status = "[OK]" if ok else "[FAIL]"
        print(f"\n{status} {name}")
        print(f"  Expected: {'VULN' if should_find else 'SAFE'}")
        print(f"  Got: {'VULN' if found else 'SAFE'}")
        if results:
            print(f"  Confidence: {results[0].confidence:.0%}")
            if results[0].sanitizers:
                print(f"  Sanitizers: {results[0].sanitizers}")

    print(f"\n{'='*60}")
    print(f"PASSED: {passed}/{len(test_cases)}")
    print("=" * 60)


if __name__ == "__main__":
    test()
