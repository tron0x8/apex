#!/usr/bin/env python3

import re
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass


@dataclass
class VulnPattern:
    name: str
    pattern: str
    severity: str
    cwe: str
    description: str
    confidence: float
    false_positive_patterns: List[str] = None
    requires_taint_check: bool = False

    def __post_init__(self):
        if self.false_positive_patterns is None:
            self.false_positive_patterns = []


VULN_PATTERNS: List[VulnPattern] = [
    VulnPattern(
        name="SQL_INJECTION_DIRECT",
        pattern=r'(?:mysql_query|mysqli_query|pg_query|sqlite_query)\s*\([^)]*\$(?:_GET|_POST|_REQUEST|_COOKIE)',
        severity="CRITICAL",
        cwe="CWE-89",
        description="SQL query with direct user input",
        confidence=0.95,
        false_positive_patterns=[
            r'intval\s*\(\s*\$_',
            r'\(int\)\s*\$_',
            r'escape_string\s*\([^)]*\$_',
        ]
    ),
    VulnPattern(
        name="SQL_INJECTION_CONCAT",
        pattern=r'(?:mysql_query|mysqli_query|pg_query)\s*\(\s*\$\w+\s*\)',
        severity="HIGH",
        cwe="CWE-89",
        description="SQL query with variable (check taint)",
        confidence=0.7,
        requires_taint_check=True,
        false_positive_patterns=[
            r'->prepare\s*\(',
            r'intval',
            r'escape_string',
        ]
    ),
    VulnPattern(
        name="SQL_INJECTION_STRING",
        pattern=r'["\']SELECT\s+.*?FROM\s+.*?WHERE\s+.*?\$(?:_GET|_POST|_REQUEST|_COOKIE)',
        severity="CRITICAL",
        cwe="CWE-89",
        description="SQL string with user input interpolation",
        confidence=0.9,
        false_positive_patterns=[
            r'intval\s*\(\s*\$_',
            r'escape_string',
            r'->prepare',
        ]
    ),
    VulnPattern(
        name="SQL_INJECTION_VARIABLE",
        pattern=r'(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?(?:FROM|INTO|SET)\s+.*?[\'\"]\s*\.\s*\$|(?:WHERE|AND|OR)\s+\w+\s*=\s*[\'\"]\s*\.\s*\$|\$\w+\s*\.\s*[\'\"]\s*(?:SELECT|INSERT|UPDATE|DELETE)',
        severity="HIGH",
        cwe="CWE-89",
        description="SQL with string concatenation",
        confidence=0.7,
        false_positive_patterns=[
            r'prepare\s*\(',
            r'escape',
            r'intval',
            r'safesql',
            r'\(int\)',
        ]
    ),
    VulnPattern(
        name="COMMAND_INJECTION_DIRECT",
        pattern=r'(?:exec|shell_exec|system|passthru|popen|proc_open|pcntl_exec)\s*\([^)]*\$(?:_GET|_POST|_REQUEST|_COOKIE)',
        severity="CRITICAL",
        cwe="CWE-78",
        description="OS command with direct user input",
        confidence=0.95,
        false_positive_patterns=[
            r'escapeshellarg\s*\(\s*\$_',
            r'escapeshellcmd\s*\(\s*\$_',
        ]
    ),
    VulnPattern(
        name="COMMAND_INJECTION_CONCAT",
        pattern=r'(?:exec|shell_exec|system|passthru)\s*\(\s*["\'][^"\']*["\']?\s*\.\s*\$',
        severity="HIGH",
        cwe="CWE-78",
        description="OS command with variable concatenation",
        confidence=0.8,
        false_positive_patterns=[
            r'escapeshellarg',
            r'escapeshellcmd',
        ]
    ),
    VulnPattern(
        name="COMMAND_INJECTION_BACKTICK",
        pattern=r'`[^`]*\$(?:_GET|_POST|_REQUEST|_COOKIE)[^`]*`',
        severity="CRITICAL",
        cwe="CWE-78",
        description="Backtick command execution with user input",
        confidence=0.85,
        false_positive_patterns=[
            r'escapeshell',
            r'->select\s*\(',
            r'->query\s*\(',
            r'SELECT\s+`',
            r'FROM\s+`',
            r'WHERE\s+`',
            r'ORDER\s+BY\s+`',
            r'GROUP\s+BY\s+`',
            r'INSERT\s+INTO\s+`',
            r'UPDATE\s+`',
            r'db->',
            r'\$wpdb',
            r'SHOW\s+',
            r'preg_match',
            r'str_replace',
            r'FencedCode',
            r'inlineMarker',
        ]
    ),
    VulnPattern(
        name="CODE_INJECTION_EVAL_DIRECT",
        pattern=r'eval\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)',
        severity="CRITICAL",
        cwe="CWE-94",
        description="eval() with direct user input",
        confidence=0.99,
    ),
    VulnPattern(
        name="CODE_INJECTION_EVAL_VAR",
        pattern=r'eval\s*\(\s*\$[a-zA-Z_]\w*\s*\)',
        severity="HIGH",
        cwe="CWE-94",
        description="eval() with variable",
        confidence=0.75,
        requires_taint_check=True,
    ),
    VulnPattern(
        name="CODE_INJECTION_ASSERT",
        pattern=r'assert\s*\(\s*\$(?:_GET|_POST|_REQUEST)',
        severity="CRITICAL",
        cwe="CWE-94",
        description="assert() with user input",
        confidence=0.95,
    ),
    VulnPattern(
        name="CODE_INJECTION_PREG_E",
        pattern=r'preg_replace\s*\(\s*["\'][^"\']*\/[eE]["\']',
        severity="CRITICAL",
        cwe="CWE-94",
        description="preg_replace with /e modifier (code execution)",
        confidence=0.95,
    ),
    VulnPattern(
        name="CODE_INJECTION_CREATE_FUNCTION",
        pattern=r'create_function\s*\([^)]*\$',
        severity="HIGH",
        cwe="CWE-94",
        description="create_function with variable",
        confidence=0.8,
    ),
    VulnPattern(
        name="XSS_ECHO_DIRECT",
        pattern=r'(?:echo|print)\s+[^;]*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[',
        severity="HIGH",
        cwe="CWE-79",
        description="XSS via echo/print with direct user input",
        confidence=0.85,
        false_positive_patterns=[
            r'htmlspecialchars\s*\(',
            r'htmlentities\s*\(',
            r'esc_html\s*\(',
            r'strip_tags\s*\(',
            r'e\s*\(\s*\$',
            r'\{\{',
        ]
    ),
    VulnPattern(
        name="XSS_ECHO_CONCAT",
        pattern=r'(?:echo|print)\s+["\'][^"\']*["\']\s*\.\s*\$',
        severity="MEDIUM",
        cwe="CWE-79",
        description="XSS via echo with string concatenation",
        confidence=0.65,
        requires_taint_check=True,
        false_positive_patterns=[
            r'htmlspecialchars',
            r'htmlentities',
            r'esc_html',
            r'strip_tags',
            r'json_encode',
        ]
    ),
    VulnPattern(
        name="FILE_INCLUSION_DIRECT",
        pattern=r'(?:include|include_once|require|require_once)\s*[\(]?\s*\$(?:_GET|_POST|_REQUEST)',
        severity="CRITICAL",
        cwe="CWE-98",
        description="File inclusion with direct user input",
        confidence=0.95,
        false_positive_patterns=[
            r'basename\s*\(',
            r'in_array\s*\(',
        ]
    ),
    VulnPattern(
        name="FILE_INCLUSION_VAR",
        pattern=r'(?:include|include_once|require|require_once)\s*[\(]?\s*\$[a-zA-Z_]\w*\s*[\)]?;',
        severity="HIGH",
        cwe="CWE-98",
        description="File inclusion with variable",
        confidence=0.7,
        requires_taint_check=True,
        false_positive_patterns=[
            r'basename',
            r'in_array',
            r'realpath',
            r'\.php[\'"]',
        ]
    ),
    VulnPattern(
        name="PATH_TRAVERSAL_DIRECT",
        pattern=r'(?:file_get_contents|fopen|readfile|file|fread)\s*\([^)]*\$(?:_GET|_POST|_REQUEST)',
        severity="HIGH",
        cwe="CWE-22",
        description="File operation with direct user input",
        confidence=0.85,
        false_positive_patterns=[
            r'basename',
            r'realpath',
        ]
    ),
    VulnPattern(
        name="PATH_TRAVERSAL_CONCAT",
        pattern=r'(?:file_get_contents|fopen|readfile)\s*\(\s*["\'][^"\']*["\']\s*\.\s*\$',
        severity="HIGH",
        cwe="CWE-22",
        description="File operation with path concatenation",
        confidence=0.75,
        false_positive_patterns=[
            r'basename',
            r'realpath',
            r'str_replace.*?\.\.',
        ]
    ),
    VulnPattern(
        name="SSRF_FILE_GET_CONTENTS",
        pattern=r'file_get_contents\s*\(\s*\$(?:_GET|_POST|_REQUEST)',
        severity="HIGH",
        cwe="CWE-918",
        description="SSRF via file_get_contents",
        confidence=0.85,
        false_positive_patterns=[
            r'filter_var.*FILTER_VALIDATE_URL',
            r'parse_url',
            r'in_array.*host',
        ]
    ),
    VulnPattern(
        name="SSRF_CURL",
        pattern=r'curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$',
        severity="HIGH",
        cwe="CWE-918",
        description="SSRF via cURL",
        confidence=0.8,
    ),
    VulnPattern(
        name="DESERIALIZATION_DIRECT",
        pattern=r'unserialize\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)',
        severity="CRITICAL",
        cwe="CWE-502",
        description="Unsafe deserialization of user input",
        confidence=0.99,
    ),
    VulnPattern(
        name="DESERIALIZATION_VAR",
        pattern=r'unserialize\s*\(\s*\$[a-zA-Z_]\w*\s*\)',
        severity="HIGH",
        cwe="CWE-502",
        description="Deserialization of variable",
        confidence=0.8,
        requires_taint_check=True,
        false_positive_patterns=[
            r'allowed_classes.*false',
        ]
    ),
    VulnPattern(
        name="DESERIALIZATION_PHAR",
        pattern=r'(?:file_exists|is_file|is_dir|filesize|file_get_contents|include|require)\s*\([^)]*["\']phar://',
        severity="CRITICAL",
        cwe="CWE-502",
        description="PHAR deserialization attack vector",
        confidence=0.85,
    ),
    VulnPattern(
        name="XXE_SIMPLEXML",
        pattern=r'simplexml_load_string\s*\(\s*\$(?:_GET|_POST|_REQUEST)',
        severity="HIGH",
        cwe="CWE-611",
        description="XXE via SimpleXML",
        confidence=0.85,
        false_positive_patterns=[
            r'libxml_disable_entity_loader\s*\(\s*true',
            r'LIBXML_NOENT',
        ]
    ),
    VulnPattern(
        name="XXE_DOM",
        pattern=r'(?:DOMDocument|XMLReader).*?load(?:XML|HTMLFile)?\s*\(\s*\$',
        severity="HIGH",
        cwe="CWE-611",
        description="XXE via DOM/XMLReader",
        confidence=0.75,
    ),
    VulnPattern(
        name="OPEN_REDIRECT_HEADER",
        pattern=r'header\s*\(\s*["\']Location:\s*["\']?\s*\.?\s*\$(?:_GET|_POST|_REQUEST)',
        severity="MEDIUM",
        cwe="CWE-601",
        description="Open redirect via header",
        confidence=0.85,
        false_positive_patterns=[
            r'parse_url',
            r'filter_var.*URL',
            r'strpos.*\/',
        ]
    ),
    VulnPattern(
        name="HEADER_INJECTION",
        pattern=r'header\s*\(\s*[^)]*\$(?:_GET|_POST|_REQUEST|_COOKIE)',
        severity="MEDIUM",
        cwe="CWE-113",
        description="HTTP header injection",
        confidence=0.75,
        false_positive_patterns=[
            r'urlencode',
            r'rawurlencode',
        ]
    ),
    VulnPattern(
        name="LDAP_INJECTION",
        pattern=r'ldap_search\s*\([^)]*\$(?:_GET|_POST|_REQUEST)',
        severity="HIGH",
        cwe="CWE-90",
        description="LDAP injection",
        confidence=0.85,
    ),
    VulnPattern(
        name="XPATH_INJECTION",
        pattern=r'(?:xpath|query)\s*\(\s*["\'][^"\']*\$(?:_GET|_POST|_REQUEST)',
        severity="HIGH",
        cwe="CWE-643",
        description="XPath injection",
        confidence=0.8,
    ),
    VulnPattern(
        name="SSTI_TWIG",
        pattern=r'(?:Twig|Environment).*?render\s*\([^)]*\$(?:_GET|_POST|_REQUEST)',
        severity="CRITICAL",
        cwe="CWE-1336",
        description="Server-side template injection (Twig)",
        confidence=0.85,
    ),
    VulnPattern(
        name="INSECURE_UPLOAD_PATH",
        pattern=r'move_uploaded_file\s*\([^,]+,\s*[^)]*\$(?:_GET|_POST|_REQUEST)',
        severity="HIGH",
        cwe="CWE-434",
        description="File upload with user-controlled path",
        confidence=0.9,
    ),
    VulnPattern(
        name="HARDCODED_PASSWORD",
        pattern=r'(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{6,}["\']',
        severity="MEDIUM",
        cwe="CWE-798",
        description="Hardcoded password",
        confidence=0.6,
        false_positive_patterns=[
            r'example',
            r'placeholder',
            r'xxx',
            r'\*\*\*',
            r'your_?password',
            r'changeme',
        ]
    ),
    VulnPattern(
        name="HARDCODED_SECRET",
        pattern=r'(?:api_?key|secret_?key|auth_?token|access_?token)\s*[=:]\s*["\'][a-zA-Z0-9]{16,}["\']',
        severity="HIGH",
        cwe="CWE-798",
        description="Hardcoded API key/secret",
        confidence=0.75,
        false_positive_patterns=[
            r'example',
            r'xxx',
            r'your_',
            r'test',
        ]
    ),
    VulnPattern(
        name="DEBUG_ENABLED",
        pattern=r'(?:debug|DEBUG|display_errors)\s*[=:]\s*(?:true|1|TRUE|["\']on["\'])',
        severity="LOW",
        cwe="CWE-489",
        description="Debug mode enabled",
        confidence=0.5,
    ),
    VulnPattern(
        name="WEAK_MD5_PASSWORD",
        pattern=r'md5\s*\(\s*\$(?:password|passwd|pwd|pass)',
        severity="MEDIUM",
        cwe="CWE-327",
        description="Weak MD5 hash for password",
        confidence=0.85,
    ),
    VulnPattern(
        name="WEAK_SHA1_PASSWORD",
        pattern=r'sha1\s*\(\s*\$(?:password|passwd|pwd|pass)',
        severity="MEDIUM",
        cwe="CWE-327",
        description="Weak SHA1 hash for password",
        confidence=0.85,
    ),
    VulnPattern(
        name="WEAK_RANDOM",
        pattern=r'(?:mt_rand|rand)\s*\([^)]*\).*?(?:token|secret|key|password|session|csrf)',
        severity="MEDIUM",
        cwe="CWE-330",
        description="Weak random for security purposes",
        confidence=0.7,
    ),
    VulnPattern(
        name="MASS_ASSIGNMENT_EXTRACT",
        pattern=r'extract\s*\(\s*\$(?:_GET|_POST|_REQUEST)',
        severity="HIGH",
        cwe="CWE-915",
        description="Mass assignment via extract()",
        confidence=0.95,
    ),
    VulnPattern(
        name="MASS_ASSIGNMENT_PARSE_STR",
        pattern=r'parse_str\s*\(\s*\$(?:_GET|_POST|_REQUEST|_SERVER)',
        severity="HIGH",
        cwe="CWE-915",
        description="Mass assignment via parse_str()",
        confidence=0.9,
    ),
    VulnPattern(
        name="LARAVEL_RAW_SQL",
        pattern=r'DB::(?:raw|select|statement)\s*\([^)]*\$(?:_GET|_POST|request|input)',
        severity="CRITICAL",
        cwe="CWE-89",
        description="Laravel raw SQL with user input",
        confidence=0.9,
        false_positive_patterns=[
            r'->prepare',
            r'intval',
        ]
    ),
    VulnPattern(
        name="LARAVEL_WHERE_RAW",
        pattern=r'(?:->|::)whereRaw\s*\(\s*["\'][^)]*\$[a-zA-Z_]',
        severity="CRITICAL",
        cwe="CWE-89",
        description="Laravel whereRaw with variable interpolation",
        confidence=0.85,
    ),
    VulnPattern(
        name="SSRF_VAR",
        pattern=r'file_get_contents\s*\(\s*\$[a-zA-Z_]\w*\s*\)',
        severity="HIGH",
        cwe="CWE-918",
        description="SSRF via file_get_contents with variable",
        confidence=0.6,
        requires_taint_check=True,
        false_positive_patterns=[
            r'filter_var',
            r'parse_url',
            r'in_array',
            r'realpath',
            r'__DIR__',
            r'dirname',
        ]
    ),
    VulnPattern(
        name="OPEN_REDIRECT_VAR",
        pattern=r'header\s*\(\s*["\']Location:\s*["\']?\s*\.\s*\$[a-zA-Z_]',
        severity="MEDIUM",
        cwe="CWE-601",
        description="Open redirect with variable",
        confidence=0.6,
        requires_taint_check=True,
        false_positive_patterns=[
            r'parse_url',
            r'filter_var',
            r'strpos.*/',
        ]
    ),
    VulnPattern(
        name="WORDPRESS_DIRECT_QUERY",
        pattern=r'\$wpdb->query\s*\([^)]*\$(?:_GET|_POST|_REQUEST)',
        severity="CRITICAL",
        cwe="CWE-89",
        description="WordPress direct query with user input",
        confidence=0.9,
        false_positive_patterns=[
            r'\$wpdb->prepare',
        ]
    ),
    VulnPattern(
        name="LOG_INJECTION",
        pattern=r'(?:error_log|syslog|file_put_contents.*\.log)\s*\([^)]*\$(?:_GET|_POST|_REQUEST)',
        severity="LOW",
        cwe="CWE-117",
        description="Log injection",
        confidence=0.7,
    ),
    # ============================================================
    # NEW PATTERNS - CWE-95: Code Injection via Callbacks
    # ============================================================
    VulnPattern(
        name="CODE_INJECTION_ARRAY_MAP",
        pattern=r'array_map\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)',
        severity="CRITICAL",
        cwe="CWE-95",
        description="array_map with user-controlled callback",
        confidence=0.95,
    ),
    VulnPattern(
        name="CODE_INJECTION_ARRAY_FILTER",
        pattern=r'array_filter\s*\([^,]+,\s*\$(?:_GET|_POST|_REQUEST)',
        severity="CRITICAL",
        cwe="CWE-95",
        description="array_filter with user-controlled callback",
        confidence=0.95,
    ),
    VulnPattern(
        name="CODE_INJECTION_USORT",
        pattern=r'(?:usort|uasort|uksort)\s*\([^,]+,\s*\$(?:_GET|_POST|_REQUEST)',
        severity="CRITICAL",
        cwe="CWE-95",
        description="usort with user-controlled callback",
        confidence=0.95,
    ),
    VulnPattern(
        name="CODE_INJECTION_CALL_USER_FUNC",
        pattern=r'call_user_func(?:_array)?\s*\(\s*\$(?:_GET|_POST|_REQUEST)',
        severity="CRITICAL",
        cwe="CWE-95",
        description="call_user_func with user-controlled function name",
        confidence=0.98,
    ),
    VulnPattern(
        name="CODE_INJECTION_VARIABLE_FUNC",
        pattern=r'\$(?:_GET|_POST|_REQUEST)\s*\[[^\]]+\]\s*\(',
        severity="CRITICAL",
        cwe="CWE-95",
        description="Variable function call with user input",
        confidence=0.99,
    ),
    # ============================================================
    # CWE-434: File Upload Vulnerabilities
    # ============================================================
    VulnPattern(
        name="FILE_UPLOAD_NO_VALIDATION",
        pattern=r'move_uploaded_file\s*\(\s*\$_FILES\s*\[[^\]]+\]\s*\[[\'"]tmp_name[\'"]\]\s*,\s*[^)]*\$_FILES\s*\[[^\]]+\]\s*\[[\'"]name[\'"]\]',
        severity="CRITICAL",
        cwe="CWE-434",
        description="File upload using original filename without validation",
        confidence=0.95,
    ),
    VulnPattern(
        name="FILE_UPLOAD_MIME_BYPASS",
        pattern=r'\$_FILES\s*\[[^\]]+\]\s*\[[\'"]type[\'"]\]',
        severity="HIGH",
        cwe="CWE-434",
        description="Relying on client-provided MIME type (bypassable)",
        confidence=0.7,
        false_positive_patterns=[
            r'finfo_file',
            r'mime_content_type',
            r'getimagesize',
        ]
    ),
    VulnPattern(
        name="FILE_UPLOAD_DOUBLE_EXT",
        pattern=r'(?:\.php\.|\.phtml\.|\.phar\.)',
        severity="HIGH",
        cwe="CWE-434",
        description="Potential double extension upload bypass",
        confidence=0.6,
    ),
    VulnPattern(
        name="FILE_UPLOAD_EXTENSION_CHECK",
        pattern=r'pathinfo\s*\([^)]*\$_FILES[^)]*PATHINFO_EXTENSION',
        severity="MEDIUM",
        cwe="CWE-434",
        description="Extension check only (should also validate content)",
        confidence=0.5,
        false_positive_patterns=[
            r'finfo_file',
            r'getimagesize',
            r'in_array.*allowed',
        ]
    ),
    # ============================================================
    # CWE-639: IDOR - Authorization Bypass
    # ============================================================
    VulnPattern(
        name="IDOR_DIRECT_OBJECT",
        pattern=r'(?:WHERE|AND)\s+(?:id|user_id|account_id|order_id)\s*=\s*[\'"]?\s*\.\s*\$(?:_GET|_POST|_REQUEST)',
        severity="HIGH",
        cwe="CWE-639",
        description="Direct object reference without authorization check",
        confidence=0.75,
        false_positive_patterns=[
            r'session.*user',
            r'auth.*check',
            r'current_user',
            r'AND\s+user_id\s*=.*session',
        ]
    ),
    VulnPattern(
        name="IDOR_FILE_ACCESS",
        pattern=r'(?:file_get_contents|readfile|fopen)\s*\([^)]*\$(?:_GET|_POST)\s*\[[\'"](file|path|doc|id)',
        severity="HIGH",
        cwe="CWE-639",
        description="File access with user-controlled identifier",
        confidence=0.8,
        false_positive_patterns=[
            r'basename',
            r'realpath',
            r'in_array',
        ]
    ),
    # ============================================================
    # CWE-362: Race Condition / TOCTOU
    # ============================================================
    VulnPattern(
        name="TOCTOU_FILE_EXISTS",
        pattern=r'if\s*\(\s*file_exists\s*\([^)]+\)\s*\)[^{]*\{[^}]*(?:unlink|rename|copy|file_put_contents|fopen)',
        severity="MEDIUM",
        cwe="CWE-362",
        description="Time-of-check-time-of-use race condition",
        confidence=0.6,
    ),
    VulnPattern(
        name="TOCTOU_IS_FILE",
        pattern=r'if\s*\(\s*is_file\s*\([^)]+\)\s*\)[^{]*\{[^}]*(?:include|require|file_get_contents)',
        severity="MEDIUM",
        cwe="CWE-362",
        description="TOCTOU in file operation",
        confidence=0.5,
    ),
    # ============================================================
    # CWE-843: Type Juggling
    # ============================================================
    VulnPattern(
        name="TYPE_JUGGLING_PASSWORD",
        pattern=r'(?:\$password|\$pass|\$pwd)\s*==\s*(?:\$|[\'"])',
        severity="HIGH",
        cwe="CWE-843",
        description="Loose comparison for password (type juggling)",
        confidence=0.85,
    ),
    VulnPattern(
        name="TYPE_JUGGLING_AUTH",
        pattern=r'(?:token|hash|key|secret|signature)\s*==\s*(?:\$|[\'"])',
        severity="HIGH",
        cwe="CWE-843",
        description="Loose comparison for auth token (use hash_equals)",
        confidence=0.8,
    ),
    VulnPattern(
        name="TYPE_JUGGLING_STRCMP",
        pattern=r'strcmp\s*\([^)]+\)\s*==\s*0',
        severity="MEDIUM",
        cwe="CWE-843",
        description="strcmp returns NULL on array (type juggling bypass)",
        confidence=0.7,
    ),
    VulnPattern(
        name="TYPE_JUGGLING_ZERO_STRING",
        pattern=r'==\s*[\'"]0[\'"]|[\'"]0[\'"]\s*==',
        severity="LOW",
        cwe="CWE-843",
        description="Loose comparison with zero string (magic hash bypass)",
        confidence=0.4,
    ),
    # ============================================================
    # Modern PHP Vulnerabilities
    # ============================================================
    VulnPattern(
        name="NAMED_ARGS_INJECTION",
        pattern=r'\.{3}\s*\$(?:_GET|_POST|_REQUEST)',
        severity="HIGH",
        cwe="CWE-94",
        description="Spread operator with user input (named args injection)",
        confidence=0.85,
    ),
    VulnPattern(
        name="UNSAFE_REFLECTION",
        pattern=r'new\s+\$(?:_GET|_POST|_REQUEST)',
        severity="CRITICAL",
        cwe="CWE-470",
        description="Instantiation of user-controlled class",
        confidence=0.95,
    ),
    VulnPattern(
        name="UNSAFE_STATIC_CALL",
        pattern=r'\$(?:_GET|_POST|_REQUEST)\s*\[[^\]]+\]\s*::\s*\w+\s*\(',
        severity="CRITICAL",
        cwe="CWE-470",
        description="Static method call on user-controlled class",
        confidence=0.95,
    ),
    VulnPattern(
        name="PROTOTYPE_POLLUTION_MERGE",
        pattern=r'array_merge_recursive\s*\([^)]*\$(?:_GET|_POST|_REQUEST)',
        severity="MEDIUM",
        cwe="CWE-915",
        description="Recursive array merge with user input (prototype pollution)",
        confidence=0.7,
    ),
    # ============================================================
    # Regex DoS (ReDoS)
    # ============================================================
    VulnPattern(
        name="REGEX_DOS_PATTERN",
        pattern=r'preg_(?:match|replace)\s*\(\s*[\'"][^\'"]*(?:\+|\*)\+[^\'"]*[\'"]',
        severity="MEDIUM",
        cwe="CWE-1333",
        description="Potential ReDoS pattern (nested quantifiers)",
        confidence=0.6,
    ),
    VulnPattern(
        name="REGEX_USER_INPUT",
        pattern=r'preg_(?:match|replace)\s*\(\s*\$(?:_GET|_POST|_REQUEST)',
        severity="HIGH",
        cwe="CWE-1333",
        description="User-controlled regex pattern (ReDoS/injection)",
        confidence=0.9,
    ),
    # ============================================================
    # Session Security
    # ============================================================
    VulnPattern(
        name="SESSION_FIXATION",
        pattern=r'session_id\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)',
        severity="HIGH",
        cwe="CWE-384",
        description="Session ID from user input (session fixation)",
        confidence=0.95,
    ),
    VulnPattern(
        name="SESSION_NO_REGENERATE",
        pattern=r'if\s*\([^)]*(?:login|auth|password)[^)]*\)[^{]*\{(?:(?!session_regenerate_id)[^}]){0,500}\}',
        severity="MEDIUM",
        cwe="CWE-384",
        description="Login without session regeneration",
        confidence=0.5,
    ),
    # ============================================================
    # Insecure Randomness
    # ============================================================
    VulnPattern(
        name="WEAK_RANDOM_TOKEN",
        pattern=r'(?:md5|sha1)\s*\(\s*(?:time|microtime|uniqid)\s*\(',
        severity="HIGH",
        cwe="CWE-330",
        description="Weak random token generation (predictable)",
        confidence=0.9,
    ),
    VulnPattern(
        name="WEAK_RANDOM_UNIQID",
        pattern=r'uniqid\s*\(\s*\)',
        severity="MEDIUM",
        cwe="CWE-330",
        description="uniqid() without entropy is predictable",
        confidence=0.6,
        false_positive_patterns=[
            r'uniqid\s*\([^)]+,\s*true',
            r'random_bytes',
        ]
    ),
    # ============================================================
    # HTTP Security Headers
    # ============================================================
    VulnPattern(
        name="MISSING_CONTENT_TYPE",
        pattern=r'echo\s+[\'"]<\?xml|echo\s+[\'"]<html',
        severity="LOW",
        cwe="CWE-116",
        description="HTML/XML output without Content-Type header",
        confidence=0.4,
    ),
    # ============================================================
    # Email Header Injection
    # ============================================================
    VulnPattern(
        name="EMAIL_HEADER_INJECTION",
        pattern=r'mail\s*\([^,]*\$(?:_GET|_POST|_REQUEST)',
        severity="HIGH",
        cwe="CWE-93",
        description="Email header injection via user input",
        confidence=0.85,
    ),
    # ============================================================
    # NoSQL Injection
    # ============================================================
    VulnPattern(
        name="NOSQL_INJECTION_MONGO",
        pattern=r'(?:find|findOne|aggregate)\s*\([^)]*\$(?:_GET|_POST|_REQUEST)',
        severity="HIGH",
        cwe="CWE-943",
        description="MongoDB injection via user input",
        confidence=0.8,
    ),
    VulnPattern(
        name="NOSQL_INJECTION_JSON",
        pattern=r'json_decode\s*\(\s*\$(?:_GET|_POST|_REQUEST).*?\).*?(?:find|update|delete)',
        severity="HIGH",
        cwe="CWE-943",
        description="NoSQL injection via JSON input",
        confidence=0.7,
    ),
    # ============================================================
    # Template Injection
    # ============================================================
    VulnPattern(
        name="SSTI_SMARTY",
        pattern=r'(?:Smarty|->assign)\s*\([^)]*\$(?:_GET|_POST|_REQUEST)',
        severity="HIGH",
        cwe="CWE-1336",
        description="Smarty template injection",
        confidence=0.7,
    ),
    VulnPattern(
        name="SSTI_BLADE",
        pattern=r'Blade::compileString\s*\(\s*\$',
        severity="CRITICAL",
        cwe="CWE-1336",
        description="Laravel Blade template injection",
        confidence=0.9,
    ),
    # ============================================================
    # Object Injection / Deserialization
    # ============================================================
    VulnPattern(
        name="PHAR_WRAPPER",
        pattern=r'phar://\s*\.\s*\$|phar://[\'"]?\s*\.\s*\$',
        severity="CRITICAL",
        cwe="CWE-502",
        description="PHAR wrapper with user input (deserialization)",
        confidence=0.95,
    ),
    VulnPattern(
        name="YAML_UNSAFE_LOAD",
        pattern=r'yaml_parse\s*\(\s*\$(?:_GET|_POST|_REQUEST)',
        severity="CRITICAL",
        cwe="CWE-502",
        description="YAML parsing with user input (object injection)",
        confidence=0.95,
    ),
    # ============================================================
    # Business Logic
    # ============================================================
    VulnPattern(
        name="PRICE_MANIPULATION",
        pattern=r'(?:price|amount|total|cost)\s*=\s*\$(?:_GET|_POST|_REQUEST)',
        severity="HIGH",
        cwe="CWE-639",
        description="Price/amount from user input (manipulation risk)",
        confidence=0.75,
    ),
    VulnPattern(
        name="QUANTITY_NEGATIVE",
        pattern=r'(?:quantity|qty|count)\s*=\s*(?:intval|floatval)?\s*\(?\s*\$(?:_GET|_POST|_REQUEST)',
        severity="MEDIUM",
        cwe="CWE-20",
        description="Quantity from user input without range validation",
        confidence=0.5,
        false_positive_patterns=[
            r'abs\s*\(',
            r'max\s*\(\s*0',
            r'>=\s*0',
        ]
    ),
    # ============================================================
    # ARBITRARY FILE WRITE - RCE via file operations
    # ============================================================
    VulnPattern(
        name="ARBITRARY_FILE_WRITE_DIRECT",
        pattern=r'file_put_contents\s*\(\s*\$(?:_GET|_POST|_REQUEST)',
        severity="CRITICAL",
        cwe="CWE-434",
        description="Arbitrary file write with direct user input - RCE possible",
        confidence=0.99,
    ),
    VulnPattern(
        name="ARBITRARY_FILE_WRITE_VAR",
        pattern=r'file_put_contents\s*\(\s*\$[a-zA-Z_]\w*\s*,',
        severity="HIGH",
        cwe="CWE-434",
        description="File write with variable path - check for user input",
        confidence=0.7,
        requires_taint_check=True,
        false_positive_patterns=[
            r'__DIR__',
            r'dirname\s*\(',
            r'sys_get_temp_dir',
            r'CACHE',
            r'LOG',
            r'\.log[\'"]',
        ]
    ),
    VulnPattern(
        name="ARBITRARY_FILE_WRITE_POST",
        pattern=r'file_put_contents\s*\([^,]+,\s*\$(?:post|_POST|data)\s*\[',
        severity="CRITICAL",
        cwe="CWE-434",
        description="File write with POST content - RCE risk",
        confidence=0.95,
    ),
    VulnPattern(
        name="ARBITRARY_FILE_WRITE_FWRITE",
        pattern=r'(?:fwrite|fputs)\s*\(\s*\$\w+\s*,\s*\$(?:_POST|_GET|_REQUEST|post|content)',
        severity="HIGH",
        cwe="CWE-434",
        description="fwrite with user-controlled content",
        confidence=0.85,
    ),
    # ============================================================
    # ARBITRARY FILE READ - Information Disclosure
    # ============================================================
    VulnPattern(
        name="ARBITRARY_FILE_READ_VAR",
        pattern=r'(?:file_get_contents|readfile|file|fread|fgets)\s*\(\s*\$[a-zA-Z_]\w*\s*\)',
        severity="HIGH",
        cwe="CWE-22",
        description="File read with variable path - check for user input",
        confidence=0.6,
        requires_taint_check=True,
        false_positive_patterns=[
            r'__DIR__',
            r'__FILE__',
            r'dirname\s*\(',
            r'APPPATH',
            r'BASEPATH',
        ]
    ),
    VulnPattern(
        name="ARBITRARY_FILE_READ_ECHO",
        pattern=r'echo\s+file_get_contents\s*\(\s*\$',
        severity="HIGH",
        cwe="CWE-22",
        description="Direct file content output - potential LFI",
        confidence=0.85,
    ),
    # ============================================================
    # BASE64 DECODE + FILE OPERATIONS - Common bypass pattern
    # ============================================================
    VulnPattern(
        name="BASE64_FILE_PATH",
        pattern=r'base64_decode\s*\(\s*\$(?:_GET|_POST|_REQUEST|post|get)\s*\[',
        severity="HIGH",
        cwe="CWE-22",
        description="Base64 decoded user input - often used for path bypass",
        confidence=0.85,
    ),
    VulnPattern(
        name="BASE64_FILE_OP",
        pattern=r'\$\w+\s*=\s*base64_decode\s*\([^)]+\)[^;]*;[^}]*(?:file_get_contents|file_put_contents|include|require|fopen)',
        severity="CRITICAL",
        cwe="CWE-22",
        description="Base64 decoded value used in file operation",
        confidence=0.9,
    ),
    # ============================================================
    # MISSING AUTHENTICATION - Sensitive operations without auth
    # ============================================================
    VulnPattern(
        name="AUTH_BYPASS_FILE_WRITE",
        pattern=r'file_put_contents\s*\(\s*\$[a-zA-Z_]\w*\s*,\s*\$(?:post|_POST|content|data)',
        severity="CRITICAL",
        cwe="CWE-306",
        description="File write with user-controlled path and content",
        confidence=0.85,
        requires_taint_check=True,
        false_positive_patterns=[
            r'is_login\s*\(',
            r'is_admin\s*\(',
            r'check_auth',
            r'auth_check',
            r'session.*user',
            r'current_user',
            r'wp_verify_nonce',
            r'mso_check_allow',
            r'install[/\\]',
            r'\.log[\'"]',
            r'cache[/\\]',
            r'temp[/\\]',
            r'LOCK_EX',
        ]
    ),
    VulnPattern(
        name="AUTH_BYPASS_FILE_DELETE",
        pattern=r'unlink\s*\(\s*\$[a-zA-Z_]\w*\s*\)',
        severity="HIGH",
        cwe="CWE-306",
        description="File delete with variable - check for auth",
        confidence=0.5,
        requires_taint_check=True,
        false_positive_patterns=[
            r'is_login',
            r'is_admin',
            r'temp',
            r'cache',
            r'session',
        ]
    ),
    # ============================================================
    # AJAX ENDPOINT VULNERABILITIES
    # ============================================================
    VulnPattern(
        name="AJAX_NO_AUTH_FILE",
        pattern=r'(?:ajax|api).*?\.php.*?(?:file_put_contents|file_get_contents|unlink|rename)',
        severity="HIGH",
        cwe="CWE-306",
        description="AJAX endpoint with file operations - check auth",
        confidence=0.7,
    ),
    VulnPattern(
        name="AJAX_NO_CSRF",
        pattern=r'if\s*\(\s*\$(?:_POST|post)\s*(?:=|!=)',
        severity="MEDIUM",
        cwe="CWE-352",
        description="POST handler without CSRF check",
        confidence=0.4,
        false_positive_patterns=[
            r'nonce',
            r'csrf',
            r'token',
            r'verify',
        ]
    ),
    # ============================================================
    # DANGEROUS SINK PATTERNS - Generic
    # ============================================================
    VulnPattern(
        name="DANGEROUS_SINK_WRITE",
        pattern=r'(?:file_put_contents|fwrite|fputs)\s*\([^)]*\$(?:post|content|data|body|input)\s*\[',
        severity="CRITICAL",
        cwe="CWE-434",
        description="Write operation with user-controlled content",
        confidence=0.9,
    ),
    VulnPattern(
        name="DANGEROUS_SINK_INCLUDE",
        pattern=r'(?:include|require)(?:_once)?\s*\(\s*\$(?:file|path|page|template|module)\s*\)',
        severity="HIGH",
        cwe="CWE-98",
        description="Include with variable - check for user input",
        confidence=0.7,
        requires_taint_check=True,
    ),
    # ============================================================
    # WRAPPER FUNCTION BYPASS - Detecting indirect input
    # ============================================================
    VulnPattern(
        name="WRAPPER_DECODE_USE",
        pattern=r'\$\w+\s*=\s*(?:base64_decode|urldecode|rawurldecode|json_decode)\s*\(\s*\$(?:post|get|request|_POST|_GET)',
        severity="HIGH",
        cwe="CWE-20",
        description="Decoded user input stored in variable",
        confidence=0.8,
    ),
    VulnPattern(
        name="WRAPPER_POST_CHECK",
        pattern=r'if\s*\(\s*\$post\s*=\s*\w+\s*\(\s*array\s*\([^\)]+\)\s*\)\s*\)',
        severity="MEDIUM",
        cwe="CWE-20",
        description="POST wrapper function - trace to sinks",
        confidence=0.5,
    ),
]


class PatternScanner:
    def __init__(self, patterns: List[VulnPattern] = None):
        self.patterns = patterns or VULN_PATTERNS
        self._compiled = {}
        for p in self.patterns:
            try:
                self._compiled[p.name] = re.compile(p.pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            except re.error:
                pass

    def scan(self, code: str, file_path: str = "") -> List[Dict]:
        findings = []
        lines = code.split('\n')

        for pattern in self.patterns:
            if pattern.name not in self._compiled:
                continue

            compiled = self._compiled[pattern.name]

            for match in compiled.finditer(code):
                start = match.start()
                line_no = code[:start].count('\n') + 1

                line_content = lines[line_no - 1] if line_no <= len(lines) else ""

                is_false_positive = False
                for fp_pattern in pattern.false_positive_patterns:
                    context_start = max(0, start - 300)
                    context_end = min(len(code), match.end() + 100)
                    context = code[context_start:context_end]

                    if re.search(fp_pattern, context, re.IGNORECASE):
                        is_false_positive = True
                        break

                if not is_false_positive:
                    findings.append({
                        'type': '_'.join(pattern.name.split('_')[:2]),
                        'pattern_name': pattern.name,
                        'severity': pattern.severity,
                        'cwe': pattern.cwe,
                        'description': pattern.description,
                        'file': file_path,
                        'line': line_no,
                        'code': line_content.strip()[:100],
                        'confidence': pattern.confidence,
                        'match': match.group()[:100],
                        'requires_taint_check': pattern.requires_taint_check,
                    })

        findings = self._deduplicate(findings)

        return findings

    def _deduplicate(self, findings: List[Dict]) -> List[Dict]:
        seen = set()
        unique = []

        for f in findings:
            key = (f['file'], f['line'], f['type'])
            if key not in seen:
                seen.add(key)
                unique.append(f)
            else:
                for existing in unique:
                    if (existing['file'], existing['line'], existing['type']) == key:
                        if f['confidence'] > existing['confidence']:
                            existing.update(f)
                        break

        return unique

    def scan_file(self, file_path: str) -> List[Dict]:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            return self.scan(code, file_path)
        except Exception as e:
            return []


def scan_with_patterns(code: str, file_path: str = "") -> List[Dict]:
    scanner = PatternScanner()
    return scanner.scan(code, file_path)
