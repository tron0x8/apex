#!/usr/bin/env python3
"""
APEX Unified Scanner v3.0
Fully integrated: Pattern + Taint + ML

All three stages work together seamlessly.
"""

import os
import sys
import re
import glob
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

# Add paths
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

# Inter-procedural analysis
try:
    from interprocedural import InterproceduralAnalyzer, analyze_interprocedural
    HAS_INTERPROCEDURAL = True
except ImportError:
    HAS_INTERPROCEDURAL = False

# AST-based analysis (APEX v4.0)
try:
    from ast_parser import PHPASTParser, TaintFlow
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


@dataclass
class Finding:
    """Unified finding structure"""
    vuln_type: VulnType
    severity: Severity
    line: int
    code: str
    file: str

    # Detection details
    pattern_match: bool = False
    taint_verified: bool = False

    # Analysis details
    source: Optional[str] = None
    sink: Optional[str] = None
    sanitizers: List[str] = field(default_factory=list)

    # Final confidence (combined from all stages)
    confidence: float = 0.0

    # Context
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
    """
    Unified scanner combining all detection methods

    Pipeline:
    1. Pattern matching (fast initial detection)
    2. Taint tracking (data flow verification)
    3. Final decision
    """

    def __init__(self, enable_ast: bool = True, **kwargs):
        self.enable_ast = enable_ast and HAS_AST_PARSER
        self._init_patterns()
        self._compile_patterns()
        self._init_sources_sinks()
        self._init_sanitizers()
        self._init_frameworks()
        self._init_ast_parser()

    def _init_patterns(self):
        """Initialize vulnerability patterns"""
        self.patterns = {
            VulnType.SQL_INJECTION: [
                # Direct injection
                (r'(?:mysql_query|mysqli_query|pg_query|sqlite_query|oci_parse)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)', Severity.CRITICAL),
                # String concat with user input
                (r'["\'](?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\$_(GET|POST|REQUEST)', Severity.CRITICAL),
                # Variable in query (interpolation)
                (r'(?:mysql_query|mysqli_query|pg_query|sqlite_query)\s*\([^)]*\$\w+', Severity.HIGH),
                # Variable in query method (interpolated string)
                (r'->query\s*\(\s*["\'][^"\']*\$\w+', Severity.HIGH),
                # Variable passed to query (e.g., ->query($sql) where $sql built via concat)
                (r'->query\s*\(\s*\$\w+\s*\)', Severity.MEDIUM),
                # PDO exec with string interpolation (NOT prepare)
                (r'->exec\s*\(\s*["\'][^"\']*\$\w+', Severity.HIGH),
                # Variable passed to exec
                (r'->exec\s*\(\s*\$\w+\s*\)', Severity.MEDIUM),
                # LIKE injection (partial match bypass)
                (r'LIKE\s+[\'"]%?\s*\.\s*\$_(GET|POST|REQUEST)', Severity.MEDIUM),
                # ORDER BY injection
                (r'ORDER\s+BY\s+[^;]*\$_(GET|POST|REQUEST)', Severity.MEDIUM),
            ],
            VulnType.COMMAND_INJECTION: [
                (r'\b(?:exec|system|passthru|shell_exec|popen)\s*\([^)]*\$_(GET|POST|REQUEST)', Severity.CRITICAL),
                (r'\b(?:exec|system|passthru|shell_exec)\s*\(\s*["\'][^"\']*\.\s*\$', Severity.HIGH),
                (r'\b(?:exec|system|passthru|shell_exec|popen)\s*\(\s*\$\w+', Severity.HIGH),
                # Backtick execution with superglobals (real shell execution)
                (r'`[^`]*\$_(GET|POST|REQUEST)[^`]*`', Severity.CRITICAL),
                (r'\bproc_open\s*\([^)]*\$', Severity.HIGH),
                (r'\bpcntl_exec\s*\([^)]*\$', Severity.CRITICAL),
            ],
            VulnType.CODE_INJECTION: [
                # Direct user input - CRITICAL
                (r'\beval\s*\([^)]*\$_(GET|POST|REQUEST)', Severity.CRITICAL),
                (r'\bassert\s*\([^)]*\$_(GET|POST|REQUEST)', Severity.CRITICAL),
                (r'\bcreate_function\s*\([^)]*\$_(GET|POST|REQUEST)', Severity.CRITICAL),
                (r'preg_replace\s*\([^)]*[\'"][^\'"]*\/e[\'"][^)]*\$_(GET|POST|REQUEST)', Severity.CRITICAL),
                # Variable eval (lower severity - could be DB data in admin context)
                (r'\beval\s*\(\s*\$(?!_(GET|POST|REQUEST|COOKIE|FILES|SERVER))', Severity.MEDIUM),
                (r'\bassert\s*\(\s*\$(?!_(GET|POST|REQUEST))', Severity.MEDIUM),
                (r'\bcreate_function\s*\(\s*[^)]*\$(?!_(GET|POST|REQUEST))', Severity.MEDIUM),
                (r'preg_replace\s*\([^)]*[\'"][^\'"]*\/e', Severity.HIGH),
            ],
            VulnType.FILE_INCLUSION: [
                (r'\b(?:include|require)(?:_once)?\s*\(?\s*\$_(GET|POST|REQUEST)', Severity.CRITICAL),
                (r'\b(?:include|require)(?:_once)?\s*\(?\s*\$\w+', Severity.HIGH),
            ],
            VulnType.FILE_WRITE: [
                (r'file_put_contents\s*\([^,]*\$_(GET|POST|REQUEST)', Severity.CRITICAL),
                (r'file_put_contents\s*\(\s*\$\w+\s*,\s*\$_(GET|POST|REQUEST)', Severity.CRITICAL),
                (r'fwrite\s*\([^,]+,\s*\$_(GET|POST|REQUEST)', Severity.HIGH),
                # base64_decode in file path (obfuscated file write - common exploit pattern)
                (r'file_put_contents\s*\([^,]*base64_decode\s*\(', Severity.HIGH),
                # Variable path from array access + variable content (indirect write via wrapper)
                (r'file_put_contents\s*\(\s*\$\w+\s*,\s*\$\w+\s*\[', Severity.MEDIUM),
                # fwrite with base64_decode path
                (r'fwrite\s*\([^,]*base64_decode\s*\(', Severity.HIGH),
            ],
            VulnType.FILE_READ: [
                (r'file_get_contents\s*\(\s*\$_(GET|POST|REQUEST)', Severity.HIGH),
                (r'\breadfile\s*\(\s*\$_(GET|POST|REQUEST)', Severity.HIGH),
                (r'show_source\s*\(\s*\$', Severity.HIGH),
                # base64_decode in file path (obfuscated file read)
                (r'file_get_contents\s*\([^)]*base64_decode\s*\(', Severity.HIGH),
                # highlight_file with variable (source disclosure)
                (r'highlight_file\s*\(\s*\$', Severity.HIGH),
                # fopen in read mode with variable path
                (r'fopen\s*\(\s*\$\w+\s*,\s*[\'"]r[b\'"]?\s*[\'"]?\s*\)', Severity.MEDIUM),
            ],
            VulnType.XSS: [
                # Direct echo/print of user input
                (r'\becho\s+[^;]*\$_(GET|POST|REQUEST|COOKIE)', Severity.HIGH),
                (r'\bprint\s+[^;]*\$_(GET|POST|REQUEST|COOKIE)', Severity.HIGH),
                # User input in HTML attribute value (value="...{$_REQUEST}...")
                (r'value\s*=\s*["\'][^"\']*\{\s*\$_(GET|POST|REQUEST)', Severity.HIGH),
                # Direct output in HTML attribute
                (r'(?:href|src|action)\s*=\s*["\'][^"\']*\$_(GET|POST|REQUEST)', Severity.HIGH),
                # Variable interpolation with superglobal in any string
                (r'["\'][^"\']*\{\s*\$_(GET|POST|REQUEST)\s*\[[^\]]+\]\s*\}[^"\']*["\']', Severity.MEDIUM),
            ],
            VulnType.SSRF: [
                (r'file_get_contents\s*\(\s*\$_(GET|POST|REQUEST)', Severity.HIGH),
                (r'file_get_contents\s*\(\s*\$\w+\s*\)', Severity.MEDIUM),
                (r'curl_setopt[^;]+CURLOPT_URL[^;]+\$_(GET|POST|REQUEST)', Severity.HIGH),
                (r'curl_init\s*\(\s*\$_(GET|POST|REQUEST)', Severity.HIGH),
                (r'curl_init\s*\(\s*\$\w+\s*\)', Severity.MEDIUM),
                (r'fsockopen\s*\(\s*\$_(GET|POST|REQUEST)', Severity.HIGH),
                (r'fopen\s*\(\s*["\']https?://[^"\']*\$', Severity.MEDIUM),
                (r'get_headers\s*\(\s*\$_(GET|POST|REQUEST)', Severity.MEDIUM),
            ],
            VulnType.DESERIALIZATION: [
                (r'\bunserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)', Severity.CRITICAL),
                (r'\bunserialize\s*\(\s*\$\w+', Severity.HIGH),
                (r'\bunserialize\s*\(\s*base64_decode', Severity.CRITICAL),
                (r'\bunserialize\s*\(\s*gzuncompress', Severity.CRITICAL),
                (r'\bunserialize\s*\(\s*file_get_contents', Severity.HIGH),
                (r'phar://[^"\']*\$', Severity.CRITICAL),
                (r'Phar::loadPhar\s*\(\s*\$', Severity.CRITICAL),
            ],
            VulnType.PATH_TRAVERSAL: [
                (r'(?:file_get_contents|fopen|include|require)[^;]*\.\.\/', Severity.HIGH),
                # base64_decode used to construct file paths (path obfuscation)
                (r'(?:include|require|include_once|require_once)\s*[\(]?\s*base64_decode\s*\(', Severity.CRITICAL),
                # str_replace on path separators (weak path sanitization, easily bypassed)
                (r'str_replace\s*\([^)]*(?:\\\\|\/)[^)]*\$_(GET|POST|REQUEST)', Severity.MEDIUM),
            ],
            VulnType.RCE: [
                (r'call_user_func\s*\(\s*\$_(GET|POST|REQUEST)', Severity.CRITICAL),
                (r'call_user_func_array\s*\(\s*\$_(GET|POST|REQUEST)', Severity.CRITICAL),
                # Variable function call - only when variable comes from user input
                (r'\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(', Severity.CRITICAL),
                (r'array_map\s*\(\s*\$_(GET|POST|REQUEST)', Severity.HIGH),
                (r'array_filter\s*\([^,]+,\s*\$_(GET|POST|REQUEST)', Severity.HIGH),
                (r'usort\s*\([^,]+,\s*\$_(GET|POST|REQUEST)', Severity.HIGH),
                (r'\bnew\s+\$_(GET|POST|REQUEST)', Severity.CRITICAL),
                (r'::\$_(GET|POST|REQUEST)\s*\(', Severity.CRITICAL),
            ],
            VulnType.OPEN_REDIRECT: [
                (r'header\s*\(\s*["\']Location:\s*["\']?\s*\.\s*\$_(GET|POST|REQUEST)', Severity.HIGH),
                (r'header\s*\(\s*["\']Location:\s*\$', Severity.MEDIUM),
            ],
            VulnType.IDOR: [
                (r'\$_(GET|POST)\s*\[\s*["\'](?:id|user_id|order_id|file_id)["\']', Severity.MEDIUM),
            ],
            VulnType.WEAK_CRYPTO: [
                # Only in password/auth context
                (r'password\s*=\s*md5\s*\(', Severity.HIGH),
                (r'password\s*=\s*sha1\s*\(', Severity.HIGH),
                (r'(?:token|secret|hash|key)\s*=\s*md5\s*\(', Severity.HIGH),
                (r'(?:token|secret|hash|key)\s*=\s*sha1\s*\(', Severity.HIGH),
                # rand/mt_rand only when used for tokens/passwords
                (r'(?:password|token|secret|key|salt)\s*=\s*.*\brand\s*\(', Severity.HIGH),
                (r'(?:password|token|secret|key|salt)\s*=\s*.*\bmt_rand\s*\(', Severity.HIGH),
            ],
            VulnType.HARDCODED_CREDS: [
                # Direct variable assignment (not in SQL or array)
                # Must be: $password = "hardcoded" or define('PASSWORD', 'value')
                (r'\$(?:password|passwd|pwd|pass)\s*=\s*["\'][a-zA-Z0-9@#$%^&*!]{4,}["\']', Severity.HIGH),
                (r'\$(?:api_key|apikey|secret|secret_key|token|auth_token)\s*=\s*["\'][a-zA-Z0-9_-]{8,}["\']', Severity.HIGH),
                # define() constants
                (r'define\s*\(\s*["\'](?:PASSWORD|API_KEY|SECRET|TOKEN)["\'].*["\'][^"\']{8,}["\']', Severity.HIGH),
            ],
            VulnType.INFO_DISCLOSURE: [
                (r'var_dump\s*\(\s*\$', Severity.LOW),
                (r'print_r\s*\(\s*\$', Severity.LOW),
                (r'debug_backtrace\s*\(', Severity.MEDIUM),
                (r'phpinfo\s*\(\s*\)', Severity.HIGH),
                (r'display_errors.*=.*["\']?on["\']?', Severity.MEDIUM),
            ],
            VulnType.UNSAFE_UPLOAD: [
                # User-controlled filename in move_uploaded_file destination
                (r'move_uploaded_file\s*\([^,]+,\s*[^)]*\$_FILES\s*\[[^\]]+\]\s*\[[\'"]name[\'"]\]', Severity.CRITICAL),
                # Concatenating user filename to path
                (r'(?:move_uploaded_file|copy|rename)\s*\([^,]+,\s*[^)]*\.\s*\$_FILES\s*\[[^\]]+\]\s*\[[\'"]name[\'"]\]', Severity.CRITICAL),
                # Direct file write with user filename (not in echo/print context)
                (r'(?:fopen|file_put_contents)\s*\([^)]*\$_FILES\s*\[[^\]]+\]\s*\[[\'"]name[\'"]\]', Severity.HIGH),
            ],
            VulnType.TYPE_JUGGLING: [
                # Match loose == comparison in auth context (variable or string)
                # Strict === and !== exclusion handled in FP filter
                (r'\$\w*(?:password|passwd|pwd|token|hash|secret)\w*\s*==\s', Severity.HIGH),
                (r'==\s*\$\w*(?:password|passwd|pwd|token|hash|secret)', Severity.HIGH),
            ],
            VulnType.XXE: [
                # XML External Entity - direct superglobal
                (r'simplexml_load_string\s*\([^)]*\$_(GET|POST|REQUEST)', Severity.CRITICAL),
                (r'DOMDocument.*loadXML\s*\([^)]*\$_(GET|POST|REQUEST)', Severity.CRITICAL),
                (r'xml_parse\s*\([^)]*\$_(GET|POST|REQUEST)', Severity.HIGH),
                # XML functions with any variable (common: $body from php://input)
                (r'simplexml_load_string\s*\(\s*\$\w+', Severity.HIGH),
                (r'DOMDocument.*loadXML\s*\(\s*\$\w+', Severity.HIGH),
                (r'XMLReader.*xml\s*\(\s*\$\w+', Severity.HIGH),
                (r'LIBXML_NOENT', Severity.MEDIUM),  # Dangerous flag
                # php://input → XML parsing (raw POST body)
                (r'file_get_contents\s*\(\s*["\']php://input["\']', Severity.MEDIUM),
            ],
            VulnType.LDAP_INJECTION: [
                (r'ldap_search\s*\([^)]*\$_(GET|POST|REQUEST)', Severity.CRITICAL),
                (r'ldap_bind\s*\([^)]*\$_(GET|POST|REQUEST)', Severity.HIGH),
                (r'ldap_\w+\s*\([^)]*\$\w+', Severity.MEDIUM),
            ],
            VulnType.XPATH_INJECTION: [
                (r'xpath\s*\([^)]*\$_(GET|POST|REQUEST)', Severity.HIGH),
                (r'->query\s*\([^)]*xpath[^)]*\$', Severity.HIGH),
            ],
            VulnType.TEMPLATE_INJECTION: [
                # Twig/Blade/Smarty SSTI
                (r'Twig.*render\s*\([^)]*\$_(GET|POST|REQUEST)', Severity.CRITICAL),
                (r'eval\s*\(\s*\$\w+\s*\.\s*["\']<\?', Severity.CRITICAL),
                (r'Smarty.*(?:assign|display)\s*\([^)]*\$_(GET|POST|REQUEST)', Severity.HIGH),
            ],
            VulnType.CSRF: [
                (r'\$_POST\s*\[\s*["\'](?:delete|remove|update|edit|add)["\']', Severity.LOW),
            ],
            VulnType.AUTH_BYPASS: [
                # Direct admin access without auth check
                (r'(?:is_admin|isAdmin|admin)\s*=\s*\$_(GET|POST|REQUEST|COOKIE)', Severity.CRITICAL),
                # Role/privilege from user input
                (r'(?:role|privilege|permission|access_level|user_type)\s*=\s*\$_(GET|POST|REQUEST|COOKIE)', Severity.CRITICAL),
                # Auth bypass via cookie manipulation
                (r'\$_COOKIE\s*\[\s*["\'](?:admin|auth|logged|role|is_admin)', Severity.HIGH),
                # JWT/session without verification
                (r'(?:jwt|token)\s*=\s*\$_(GET|POST|REQUEST|COOKIE).*?(?:decode|base64_decode)', Severity.HIGH),
            ],
            VulnType.HEADER_INJECTION: [
                # header() with user input (HTTP response splitting)
                (r'header\s*\(\s*[^)]*\$_(GET|POST|REQUEST|COOKIE)', Severity.HIGH),
                (r'header\s*\(\s*[^)]*\.\s*\$\w+', Severity.MEDIUM),
                # setcookie with user input in name or value
                (r'setcookie\s*\(\s*\$_(GET|POST|REQUEST)', Severity.HIGH),
                (r'setcookie\s*\([^,]+,\s*\$_(GET|POST|REQUEST)', Severity.HIGH),
            ],
            VulnType.MASS_ASSIGNMENT: [
                # ORM fill/update/create from raw user input
                (r'->fill\s*\(\s*\$_(POST|REQUEST|GET)', Severity.HIGH),
                (r'->update\s*\(\s*\$_(POST|REQUEST|GET)', Severity.HIGH),
                (r'::create\s*\(\s*\$_(POST|REQUEST|GET)', Severity.HIGH),
                (r'->(?:fill|update|create)\s*\(\s*\$request->all\(\)', Severity.HIGH),
                (r'extract\s*\(\s*\$_(GET|POST|REQUEST)', Severity.CRITICAL),
                (r'extract\s*\(\s*\$_COOKIE', Severity.HIGH),
            ],
            VulnType.INSECURE_RANDOM: [
                # rand()/mt_rand() for security-sensitive operations
                (r'(?:token|nonce|csrf|secret|key|salt|password)\s*=\s*.*?\b(?:rand|mt_rand|array_rand)\s*\(', Severity.HIGH),
                (r'\bmd5\s*\(\s*(?:rand|mt_rand|uniqid|microtime)\s*\(', Severity.HIGH),
                (r'\bsha1\s*\(\s*(?:rand|mt_rand|uniqid|microtime)\s*\(', Severity.HIGH),
                (r'\buniqid\s*\(\s*\)\s*(?:;|\))', Severity.MEDIUM),  # uniqid() without prefix is predictable
            ],
            VulnType.RACE_CONDITION: [
                # TOCTOU: file_exists then modifying operation on SAME LINE
                (r'if\s*\(\s*file_exists\s*\(\s*\$\w+\s*\)\s*\)\s*\{?\s*(?:unlink|rename|chmod|chown|rmdir|copy|move_uploaded_file)\s*\(', Severity.HIGH),
                # Check-then-create (mkdir after !file_exists)
                (r'if\s*\(\s*!\s*file_exists.*?mkdir\s*\(', Severity.LOW),
                # fopen in write/append mode without flock (concurrent writes)
                (r'fopen\s*\([^)]+,\s*[\'"][wa]\+?[\'"]', Severity.LOW),
            ],
            VulnType.LOG_INJECTION: [
                # User input directly in log messages
                (r'error_log\s*\(.*?\$_(GET|POST|REQUEST|COOKIE)', Severity.MEDIUM),
                (r'(?:fwrite|file_put_contents)\s*\(.*?log.*?,.*?\$_(GET|POST|REQUEST)', Severity.MEDIUM),
                (r'->(?:log|info|warning|error|debug)\s*\(.*?\$_(GET|POST|REQUEST)', Severity.MEDIUM),
                (r'syslog\s*\(.*?\$_(GET|POST|REQUEST)', Severity.MEDIUM),
            ],
            VulnType.REGEX_DOS: [
                # Nested quantifiers in preg_match with user input (e.g. (a+)+, (x*)*,  (\d+){2,})
                (r'preg_match\s*\(\s*[\'"].*?(?:[\+\*]\)[\+\*]|[\+\*]\)\{|\{\d+,\}\)[\+\*])[^\']*[\'"][^)]*\$_(GET|POST|REQUEST)', Severity.MEDIUM),
                # User-controlled regex pattern
                (r'preg_match\s*\(\s*\$_(GET|POST|REQUEST)', Severity.HIGH),
                (r'preg_replace\s*\(\s*\$_(GET|POST|REQUEST)', Severity.CRITICAL),
            ],
        }

    def _compile_patterns(self):
        """Pre-compile all regex patterns for performance"""
        self.compiled_patterns = {}
        for vuln_type, patterns in self.patterns.items():
            compiled = []
            for pattern, severity in patterns:
                compiled.append((re.compile(pattern, re.IGNORECASE), severity))
            self.compiled_patterns[vuln_type] = compiled

    def _init_sources_sinks(self):
        """Initialize taint sources and sinks"""
        self.sources = {
            'GET': r'\$_GET\s*\[',
            'POST': r'\$_POST\s*\[',
            'REQUEST': r'\$_REQUEST\s*\[',
            'COOKIE': r'\$_COOKIE\s*\[',
            'FILES': r'\$_FILES\s*\[',
            'SERVER': r'\$_SERVER\s*\[\s*[\'"](?:REQUEST_URI|QUERY_STRING|HTTP_)',
            'INPUT': r'file_get_contents\s*\(\s*[\'"]php://input',
        }

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
        """Initialize sanitizer patterns - comprehensive list"""
        self.sanitizers = {
            # SQL sanitizers
            'intval': {'pattern': r'intval\s*\(', 'protects': [VulnType.SQL_INJECTION, VulnType.XSS, VulnType.COMMAND_INJECTION, VulnType.IDOR]},
            '(int)': {'pattern': r'\(int\)\s*\$', 'protects': [VulnType.SQL_INJECTION, VulnType.XSS, VulnType.COMMAND_INJECTION, VulnType.IDOR]},
            '(float)': {'pattern': r'\(float\)\s*\$', 'protects': [VulnType.SQL_INJECTION]},
            'escape_string': {'pattern': r'(?:real_)?escape_string\s*\(', 'protects': [VulnType.SQL_INJECTION]},
            'safesql': {'pattern': r'safesql\s*\(', 'protects': [VulnType.SQL_INJECTION, VulnType.XSS, VulnType.IDOR]},
            'addslashes': {'pattern': r'addslashes\s*\(', 'protects': [VulnType.SQL_INJECTION]},
            'prepare': {'pattern': r'->prepare\s*\(', 'protects': [VulnType.SQL_INJECTION]},
            'bindParam': {'pattern': r'->bind(?:Param|Value)\s*\(', 'protects': [VulnType.SQL_INJECTION]},
            'quote': {'pattern': r'->quote\s*\(', 'protects': [VulnType.SQL_INJECTION]},
            'pdo_placeholder': {'pattern': r'\?\s*,|\:\w+', 'protects': [VulnType.SQL_INJECTION]},

            # XSS sanitizers
            'htmlspecialchars': {'pattern': r'htmlspecialchars\s*\(', 'protects': [VulnType.XSS]},
            'htmlentities': {'pattern': r'htmlentities\s*\(', 'protects': [VulnType.XSS]},
            'strip_tags': {'pattern': r'strip_tags\s*\(', 'protects': [VulnType.XSS]},
            'esc_html': {'pattern': r'esc_html\s*\(', 'protects': [VulnType.XSS]},
            'esc_attr': {'pattern': r'esc_attr\s*\(', 'protects': [VulnType.XSS]},
            'e_helper': {'pattern': r'\be\s*\(\s*\$', 'protects': [VulnType.XSS]},
            'purify': {'pattern': r'(?:purify|clean|sanitize)\s*\(', 'protects': [VulnType.XSS]},

            # Command sanitizers
            'escapeshellarg': {'pattern': r'escapeshellarg\s*\(', 'protects': [VulnType.COMMAND_INJECTION, VulnType.RCE]},
            'escapeshellcmd': {'pattern': r'escapeshellcmd\s*\(', 'protects': [VulnType.COMMAND_INJECTION, VulnType.RCE]},

            # Path sanitizers
            'basename': {'pattern': r'basename\s*\(', 'protects': [VulnType.FILE_INCLUSION, VulnType.PATH_TRAVERSAL, VulnType.FILE_READ, VulnType.FILE_WRITE]},
            'realpath': {'pattern': r'realpath\s*\(', 'protects': [VulnType.FILE_INCLUSION, VulnType.PATH_TRAVERSAL]},
            'pathinfo': {'pattern': r'pathinfo\s*\(', 'protects': [VulnType.FILE_INCLUSION]},

            # Validation - comprehensive
            'in_array_strict': {'pattern': r'in_array\s*\([^)]*,\s*true\s*\)', 'protects': [VulnType.FILE_INCLUSION, VulnType.COMMAND_INJECTION, VulnType.RCE, VulnType.OPEN_REDIRECT, VulnType.CODE_INJECTION]},
            'in_array': {'pattern': r'in_array\s*\(', 'protects': [VulnType.FILE_INCLUSION, VulnType.OPEN_REDIRECT]},
            'is_numeric': {'pattern': r'is_numeric\s*\(', 'protects': [VulnType.SQL_INJECTION, VulnType.IDOR, VulnType.COMMAND_INJECTION]},
            'ctype_digit': {'pattern': r'ctype_digit\s*\(', 'protects': [VulnType.SQL_INJECTION, VulnType.IDOR, VulnType.COMMAND_INJECTION]},
            'ctype_alnum': {'pattern': r'ctype_alnum\s*\(', 'protects': [VulnType.SQL_INJECTION, VulnType.COMMAND_INJECTION, VulnType.CODE_INJECTION]},
            'ctype_alpha': {'pattern': r'ctype_alpha\s*\(', 'protects': [VulnType.SQL_INJECTION, VulnType.COMMAND_INJECTION]},
            'preg_match': {'pattern': r'preg_match\s*\(\s*[\'"][/^]', 'protects': [VulnType.SQL_INJECTION, VulnType.COMMAND_INJECTION, VulnType.XSS, VulnType.CODE_INJECTION]},
            'filter_var': {'pattern': r'filter_var\s*\(', 'protects': [VulnType.SQL_INJECTION, VulnType.XSS, VulnType.SSRF, VulnType.OPEN_REDIRECT]},
            'filter_input': {'pattern': r'filter_input\s*\(', 'protects': [VulnType.SQL_INJECTION, VulnType.XSS, VulnType.COMMAND_INJECTION]},
            'abs': {'pattern': r'\babs\s*\(', 'protects': [VulnType.SQL_INJECTION, VulnType.IDOR]},
            'floor': {'pattern': r'\bfloor\s*\(', 'protects': [VulnType.SQL_INJECTION]},
            'ceil': {'pattern': r'\bceil\s*\(', 'protects': [VulnType.SQL_INJECTION]},
            'round': {'pattern': r'\bround\s*\(', 'protects': [VulnType.SQL_INJECTION]},
            'min': {'pattern': r'\bmin\s*\(', 'protects': [VulnType.SQL_INJECTION, VulnType.IDOR]},
            'max': {'pattern': r'\bmax\s*\(', 'protects': [VulnType.SQL_INJECTION, VulnType.IDOR]},

            # URL sanitizers
            'urlencode': {'pattern': r'urlencode\s*\(', 'protects': [VulnType.XSS, VulnType.OPEN_REDIRECT]},
            'rawurlencode': {'pattern': r'rawurlencode\s*\(', 'protects': [VulnType.XSS, VulnType.OPEN_REDIRECT]},
            'filter_validate_url': {'pattern': r'FILTER_VALIDATE_URL', 'protects': [VulnType.SSRF, VulnType.OPEN_REDIRECT]},
            'parse_url': {'pattern': r'parse_url\s*\(', 'protects': [VulnType.SSRF, VulnType.OPEN_REDIRECT]},

            # Security functions
            'password_hash': {'pattern': r'password_hash\s*\(', 'protects': [VulnType.WEAK_CRYPTO]},
            'password_verify': {'pattern': r'password_verify\s*\(', 'protects': [VulnType.WEAK_CRYPTO, VulnType.TYPE_JUGGLING]},
            'random_bytes': {'pattern': r'random_bytes\s*\(', 'protects': [VulnType.WEAK_CRYPTO]},
            'random_int': {'pattern': r'random_int\s*\(', 'protects': [VulnType.WEAK_CRYPTO]},
            'hash_equals': {'pattern': r'hash_equals\s*\(', 'protects': [VulnType.TYPE_JUGGLING]},
            'openssl': {'pattern': r'openssl_\w+\s*\(', 'protects': [VulnType.WEAK_CRYPTO]},

            # Auth checks
            'isAuthenticated': {'pattern': r'(?:isAuthenticated|is_authenticated|checkAuth|isLoggedIn)\s*\(', 'protects': [VulnType.AUTH_BYPASS, VulnType.IDOR]},
            'hasPermission': {'pattern': r'(?:hasPermission|has_permission|checkPermission|can)\s*\(', 'protects': [VulnType.AUTH_BYPASS, VulnType.IDOR]},
            'session_check': {'pattern': r'\$_SESSION\s*\[\s*[\'"](?:user|admin|logged)', 'protects': [VulnType.AUTH_BYPASS, VulnType.IDOR]},
            'member_id': {'pattern': r'\$member_id\s*\[\s*[\'"]user_group', 'protects': [VulnType.AUTH_BYPASS, VulnType.IDOR]},
            'is_admin': {'pattern': r'(?:is_admin|isAdmin|user_group\s*==\s*1)', 'protects': [VulnType.AUTH_BYPASS]},

            # CSRF tokens
            'csrf_token': {'pattern': r'(?:csrf_token|_token|csrfToken|csrf)', 'protects': [VulnType.CSRF]},
            'verify_nonce': {'pattern': r'(?:verify_nonce|check_nonce|wp_verify_nonce)', 'protects': [VulnType.CSRF]},

            # Strict comparison
            'strict_compare': {'pattern': r'===', 'protects': [VulnType.TYPE_JUGGLING]},
            'strcmp': {'pattern': r'strcmp\s*\(', 'protects': [VulnType.TYPE_JUGGLING]},

            # JSON response (not XSS)
            'json_encode': {'pattern': r'json_encode\s*\(', 'protects': [VulnType.XSS]},
            'json_header': {'pattern': r'application/json', 'protects': [VulnType.XSS]},
            'api_response': {'pattern': r'(?:return|echo)\s+(?:json_|Response::json)', 'protects': [VulnType.XSS]},

            # File upload
            'allowed_extensions': {'pattern': r'(?:allowed_ext|valid_ext|mime_types|whitelist)', 'protects': [VulnType.UNSAFE_UPLOAD]},
            'getimagesize': {'pattern': r'getimagesize\s*\(', 'protects': [VulnType.UNSAFE_UPLOAD]},
            'finfo': {'pattern': r'finfo_(?:open|file)\s*\(', 'protects': [VulnType.UNSAFE_UPLOAD]},
            'mime_check': {'pattern': r'mime_content_type\s*\(', 'protects': [VulnType.UNSAFE_UPLOAD]},

            # Serialization
            'allowed_classes': {'pattern': r'allowed_classes', 'protects': [VulnType.DESERIALIZATION]},
            'json_decode': {'pattern': r'json_decode\s*\(', 'protects': [VulnType.DESERIALIZATION]},

            # Header injection
            'header_remove': {'pattern': r'header_remove\s*\(', 'protects': [VulnType.HEADER_INJECTION]},
            'str_replace_newline': {'pattern': r'str_replace\s*\([^)]*(?:\\r|\\n)', 'protects': [VulnType.HEADER_INJECTION]},

            # Mass assignment protection
            'fillable': {'pattern': r'\$fillable\s*=', 'protects': [VulnType.MASS_ASSIGNMENT]},
            'guarded': {'pattern': r'\$guarded\s*=', 'protects': [VulnType.MASS_ASSIGNMENT]},
            'only': {'pattern': r'->only\s*\(', 'protects': [VulnType.MASS_ASSIGNMENT]},

            # Secure randomness
            'random_bytes_san': {'pattern': r'random_bytes\s*\(', 'protects': [VulnType.INSECURE_RANDOM]},
            'random_int_san': {'pattern': r'random_int\s*\(', 'protects': [VulnType.INSECURE_RANDOM]},
            'openssl_random': {'pattern': r'openssl_random_pseudo_bytes\s*\(', 'protects': [VulnType.INSECURE_RANDOM]},

            # XXE protection
            'disable_entities': {'pattern': r'(?:LIBXML_NOENT|libxml_disable_entity_loader)', 'protects': [VulnType.XXE]},

            # Log injection sanitizers
            'log_sanitize': {'pattern': r'(?:preg_replace|str_replace)\s*\([^)]*(?:\\r|\\n|[\r\n])', 'protects': [VulnType.LOG_INJECTION]},
            'log_filter': {'pattern': r'(?:filter_var|htmlspecialchars|addslashes)\s*\(', 'protects': [VulnType.LOG_INJECTION]},

            # Race condition mitigation
            'flock': {'pattern': r'flock\s*\(', 'protects': [VulnType.RACE_CONDITION]},
            'mutex': {'pattern': r'(?:mutex|lock|semaphore|synchronized)\s*\(', 'protects': [VulnType.RACE_CONDITION]},

            # Regex DoS mitigation
            'preg_timeout': {'pattern': r'(?:pcre\.backtrack_limit|set_time_limit|ini_set)', 'protects': [VulnType.REGEX_DOS]},

            # Generic custom sanitizers (auto-detect by naming pattern)
            # These REDUCE confidence but don't eliminate findings (potential bypass)
            'custom_safe_method': {'pattern': r'->\w*(?:safe|escape|clean|sanitize|filter|validate|secure|protect)\w*\s*\(', 'protects': [VulnType.SQL_INJECTION, VulnType.XSS, VulnType.COMMAND_INJECTION, VulnType.IDOR, VulnType.CODE_INJECTION]},
            'custom_safe_func': {'pattern': r'\b\w*(?:safe|escape|clean|sanitize|filter|validate|secure|protect|purify)\w*\s*\(', 'protects': [VulnType.SQL_INJECTION, VulnType.XSS, VulnType.COMMAND_INJECTION, VulnType.IDOR, VulnType.CODE_INJECTION]},
        }

    def _detect_custom_sanitizer_usage(self, code: str, line_num: int) -> List[str]:
        """
        Dynamically detect custom sanitizer functions used in context.
        Returns list of detected sanitizer names.
        """
        lines = code.split('\n')
        start = max(0, line_num - 30)
        context = '\n'.join(lines[start:line_num])

        sanitizers_found = []

        # Pattern to find any function/method that looks like a sanitizer
        # Matches: safesql(), escape_string(), clean_input(), sanitize(), filter_var(), etc.
        sanitizer_patterns = [
            r'(\w*(?:safe|escape|clean|sanitize|filter|validate|secure|protect|purify)\w*)\s*\(',
            r'->(\w*(?:safe|escape|clean|sanitize|filter|validate|quote|protect)\w*)\s*\(',
        ]

        for pattern in sanitizer_patterns:
            matches = re.findall(pattern, context, re.I)
            for match in matches:
                if match.lower() not in ['if', 'for', 'while', 'switch']:  # Exclude keywords
                    if match not in sanitizers_found:
                        sanitizers_found.append(match)

        return sanitizers_found

    def _init_frameworks(self):
        """Initialize framework detection - generic patterns only"""
        self.frameworks = {
            # Detect by namespace/class patterns (generic)
            'laravel': [r'Illuminate\\', r'->where\s*\([^,]+,\s*\$', r'Route::', r'Eloquent'],
            'symfony': [r'Symfony\\', r'->setParameter\(', r'Doctrine\\'],
            'codeigniter': [r'\$this->db->escape', r'CI_Controller'],
            # Generic ORM/Framework detection
            'orm_protected': [r'->prepare\s*\(', r'->bind(?:Param|Value)\s*\(', r'\?\s*,\s*\['],
        }

    def _init_ast_parser(self):
        """Initialize AST parser and data flow analyzer"""
        self.ast_parser = None
        self.dataflow_analyzer = None

        if self.enable_ast and HAS_AST_PARSER:
            try:
                self.ast_parser = PHPASTParser()
            except Exception:
                pass


    def _analyze_with_ast(self, code: str, filepath: str = "") -> List[Finding]:
        """
        Analyze code using AST-based taint tracking (APEX v4.0)

        More accurate than regex-based pattern matching:
        - Proper scope handling
        - Accurate sanitization tracking per vuln type
        - Control flow aware

        NOTE: AST findings are used to VERIFY pattern findings, not to add new ones.
        This prevents AST from adding too many low-value findings.
        """
        if not self.ast_parser:
            return []

        findings = []
        lines = code.split('\n')

        # Context checks (same as pattern matcher)
        framework = self._detect_framework(code)
        is_admin_path = self._check_admin_path(filepath)
        has_admin_check = self._check_admin_code_context(code, 0)
        is_admin_only = is_admin_path and has_admin_check

        try:
            # Get vulnerable flows from AST analysis
            vuln_flows = self.ast_parser.get_vulnerable_flows(code, filepath)

            for flow in vuln_flows:
                # Map sink type to VulnType
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

                # Get the line of code
                line_code = lines[flow.sink_line - 1].strip() if flow.sink_line <= len(lines) else ""

                # Apply same filters as pattern matcher
                if self._check_safe_context(code, flow.sink_line, vuln_type):
                    continue

                if self._is_false_positive_pattern(line_code, vuln_type):
                    continue

                # Calculate confidence with context
                confidence = 0.85

                # Direct superglobal = higher confidence
                if flow.source in ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE']:
                    confidence = 0.90

                # Framework protection
                if framework in ['laravel', 'symfony', 'wordpress', 'dle']:
                    confidence -= 0.20

                # Admin context reduction
                if is_admin_only:
                    confidence -= 0.25

                # Skip low confidence
                if confidence < 0.60:
                    continue

                # Determine severity
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
                    taint_verified=True,  # AST-verified taint flow
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
        """
        Verify a finding using data flow analysis

        Returns: (is_vulnerable, confidence_adjustment)
        """
        if not self.dataflow_analyzer:
            return True, 0.0

        try:
            var_taints = self.dataflow_analyzer.analyze_code(code)

            # Get the line
            lines = code.split('\n')
            if line_num > len(lines):
                return True, 0.0

            line = lines[line_num - 1]

            # Map vuln type to sink type
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
                return True, 0.1  # Boost confidence
            else:
                return False, -0.3  # Reduce confidence

        except Exception:
            return True, 0.0

    def _detect_framework(self, code: str) -> Optional[str]:
        """Detect framework used in code"""
        for fw, patterns in self.frameworks.items():
            for pattern in patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    return fw
        return None

    def _find_sources(self, code: str, line_num: int) -> List[str]:
        """Find taint sources near a line"""
        lines = code.split('\n')
        start = max(0, line_num - 15)
        context = '\n'.join(lines[start:line_num])

        found = []
        for name, pattern in self.sources.items():
            if re.search(pattern, context, re.IGNORECASE):
                found.append(name)
        return found

    def _find_sanitizers(self, code: str, line_num: int, vuln_type: VulnType) -> List[str]:
        """Find sanitizers that protect against vulnerability type"""
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
        """Check if code is in authenticated context"""
        lines = code.split('\n')
        start = max(0, line_num - 50)  # Larger context window
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
        """Detect custom sanitizer functions defined in code"""
        custom_sanitizers = []

        # Function definitions that look like sanitizers
        sanitizer_patterns = [
            r'function\s+(sanitize\w*|clean\w*|escape\w*|filter\w*|validate\w*|safe\w*)\s*\(',
            r'function\s+(\w*_clean|\w*_escape|\w*_filter|\w*_sanitize)\s*\(',
        ]

        for pattern in sanitizer_patterns:
            matches = re.findall(pattern, code, re.I)
            custom_sanitizers.extend(matches)

        return custom_sanitizers

    def _check_wrapped_in_function(self, code: str, line_num: int, funcs: List[str]) -> bool:
        """Check if vulnerable code is wrapped in a sanitizing function call"""
        lines = code.split('\n')
        if line_num > len(lines):
            return False

        line = lines[line_num - 1]

        for func in funcs:
            # Check if the line is inside a function call
            if re.search(rf'{func}\s*\([^)]*$', line, re.I):
                return True

        return False

    def _check_admin_path(self, filepath: str) -> bool:
        """Check if file is in admin/backend path (reduces severity)"""
        # Generic admin path patterns - no CMS-specific patterns
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
        """Check if code has admin-only access checks"""
        lines = code.split('\n')
        # Check first 50 lines for admin checks
        header = '\n'.join(lines[:min(50, len(lines))])

        # Generic admin check patterns - no CMS-specific patterns
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
        """
        Advanced taint tracking - follow variable assignments
        Returns: {'tainted': bool, 'sanitized': bool, 'hops': int}
        """
        lines = code.split('\n')
        result = {'tainted': False, 'sanitized': False, 'hops': 0}

        if line_num > len(lines):
            return result

        current_line = lines[line_num - 1]

        # Find variables in current line
        var_matches = re.findall(r'\$([a-zA-Z_]\w*)', current_line)
        if not var_matches:
            return result

        tracked_vars = set(var_matches)
        visited_lines = set()

        # Track backwards through assignments
        for depth in range(max_depth):
            start = max(0, line_num - 1 - (depth * 10))
            end = line_num - 1

            for i in range(end - 1, start - 1, -1):
                if i in visited_lines or i >= len(lines):
                    continue
                visited_lines.add(i)

                line = lines[i]

                # Check for source assignment to tracked variable
                for var in list(tracked_vars):
                    # Variable assignment: $var = $_GET[...]
                    assign_pattern = rf'\${var}\s*=\s*(.+?)(?:;|$)'
                    match = re.search(assign_pattern, line)
                    if match:
                        rhs = match.group(1)

                        # Check if source
                        if re.search(r'\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)', rhs):
                            result['tainted'] = True
                            result['hops'] = depth + 1

                        # Check if sanitized
                        if re.search(r'(?:intval|htmlspecialchars|escape|sanitize|filter_var|addslashes)\s*\(', rhs, re.I):
                            result['sanitized'] = True

                        # Track new variables in RHS
                        new_vars = re.findall(r'\$([a-zA-Z_]\w*)', rhs)
                        tracked_vars.update(new_vars)

        return result

    def _is_in_comment(self, code: str, line_num: int) -> bool:
        """Check if line is inside a comment or string"""
        lines = code.split('\n')
        if line_num > len(lines):
            return False

        line = lines[line_num - 1].strip()

        # Single line comment
        if line.startswith('//') or line.startswith('#') or line.startswith('*'):
            return True

        # Check for multi-line comment
        in_comment = False
        for i in range(line_num):
            l = lines[i]
            if '/*' in l:
                in_comment = True
            if '*/' in l:
                in_comment = False

        return in_comment

    def _is_false_positive_pattern(self, line: str, vuln_type: VulnType) -> bool:
        """Check for known false positive patterns - SMART DETECTION"""

        # Empty or very short line
        if len(line.strip()) < 10:
            return True

        # Documentation/example patterns
        if re.search(r'(?:example|sample|demo|test|TODO|FIXME|NOTE):', line, re.I):
            return True

        # Error message strings
        if re.search(r'(?:echo|print)\s+["\'].*(?:error|warning|notice|failed)', line, re.I):
            return True

        # Logging statements (but NOT for log injection detection!)
        if vuln_type != VulnType.LOG_INJECTION:
            if re.search(r'(?:log|debug|trace|error_log)\s*\(', line, re.I):
                return True

        # Configuration/constant definitions
        if re.search(r'(?:define|const)\s*\(?\s*[\'"][A-Z_]+[\'"]', line, re.I):
            return True

        # ============ TYPE-SPECIFIC SMART FP DETECTION ============

        if vuln_type == VulnType.SQL_INJECTION:
            # Only filter TRULY safe patterns (prepared statements, ORM)
            # Prepared statements with placeholders
            if re.search(r'\?\s*,|\:\w+|bindParam|bindValue', line, re.I):
                return True
            # ORM methods (parameterized by design)
            if re.search(r'->(?:where|find|first|get)\s*\([^,]+,\s*\[', line, re.I):
                return True
            # PDO prepare/execute pattern
            if re.search(r'->prepare\s*\(', line, re.I):
                return True
            # Query with only constants (no variables at all in entire line)
            if re.search(r'->query\s*\(', line) and not re.search(r'\$', line):
                return True
            # Numeric ID from intval/int cast in same line
            if re.search(r'(?:intval|\(int\))\s*\([^)]*\$', line, re.I):
                return True
            # NOTE: Custom sanitizers like safesql are NOT filtered here
            # They will be reported with lower confidence (potential bypass)

        if vuln_type == VulnType.XSS:
            # Already escaped output
            if re.search(r'(?:htmlspecialchars|esc_html|e\()\s*\(', line, re.I):
                return True
            # JSON output
            if re.search(r'json_encode|application/json', line, re.I):
                return True
            # HEREDOC/NOWDOC start (not vulnerable itself - check inside)
            if re.search(r'<<<\s*[\'"]?\w+[\'"]?\s*$', line):
                return True
            # HEREDOC end marker
            if re.search(r'^\s*\w+\s*;\s*$', line):
                return True
            # Static HTML (no variable interpolation in this line)
            if re.search(r'^<[a-zA-Z][^${}]*>$', line.strip()):
                return True
            # Comparison/condition (not output) - FP reduction
            if re.search(r'\$_(GET|POST|REQUEST)\s*\[[^\]]+\]\s*(?:==|!=|===|!==|>|<|AND|OR|\|\||&&)', line, re.I):
                return True
            # Variable assignment (not output)
            if re.search(r'\$\w+\s*=\s*\$_(GET|POST|REQUEST)', line, re.I):
                if not re.search(r'(?:echo|print)\s', line, re.I):
                    return True
            # isset/empty check (not output)
            if re.search(r'(?:isset|empty)\s*\(\s*\$_(GET|POST|REQUEST)', line, re.I):
                return True
            # Hash check (CSRF token validation)
            if re.search(r'user_hash|csrf|token.*=', line, re.I):
                return True
            # Function parameter (not output)
            if re.search(r'\w+\s*\(\s*\$_(GET|POST|REQUEST)', line, re.I):
                if not re.search(r'(?:echo|print)\s', line, re.I):
                    return True
            # Array key access for comparison
            if re.search(r'\[\s*\$_(GET|POST|REQUEST)', line, re.I):
                return True

        if vuln_type == VulnType.COMMAND_INJECTION:
            # Escaped shell arguments
            if re.search(r'escapeshell(?:arg|cmd)\s*\(', line, re.I):
                return True
            # SQL exec/execute confused with shell exec
            if re.search(r'(?:mysqli?_|pg_|oci_|sqlite_|->)\s*(?:exec|execute|query)', line, re.I):
                return True
            # PDO execute
            if re.search(r'\$\w+->execute\s*\(', line, re.I):
                return True
            # Backtick FP detection - SQL backtick quoting vs shell execution
            if '`' in line:
                # Fast SQL keyword check using word tokenization (no regex)
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
                # Backtick inside a string being passed to query/SQL function
                if re.search(r'->query\s*\([^)]*`', line, re.I):
                    return True
                # Backtick inside a double-quoted or single-quoted string literal
                # Shell: $x = `command` (backtick is delimiter)
                # SQL: $x = "SELECT `col`" (backtick inside quotes)
                if re.search(r'"[^"]*`[^"]*"', line):
                    return True
                if re.search(r"'[^']*`[^']*'", line):
                    return True
                # String concatenation building SQL with backticks
                if re.search(r'\.\s*["\']\s*`', line):
                    return True
                if re.search(r'`\s*["\'].*\.', line):
                    return True
                # SQL table prefix with backtick
                if re.search(r'(?:PREFIX|TABLE_PREFIX|DB_PREFIX)', line, re.I):
                    return True
                # Line contains DB object method
                if re.search(r'\$\w*(?:db|sql|mysql|mysqli|pdo|conn|connection|query|stmt)\w*\s*->', line, re.I):
                    return True
            # safesql() sanitized - not command injection
            if re.search(r'safesql\s*\(', line, re.I):
                return True

        if vuln_type == VulnType.CODE_INJECTION:
            # DLE CMS standard encoding pattern (commercial license protection)
            # Pattern: $_F=__FILE__; $_X='...' on early lines of DLE files
            if re.search(r'\$_F\s*=\s*__FILE__', line):
                return True
            if re.search(r'\$_X\s*=\s*["\']', line):
                return True
            # ionCube/Zend Guard/SourceGuardian encoding markers
            if re.search(r'(?:ioncube|zend|sourceguardian|phpshield)\s*(?:loader|guard|encoded)', line, re.I):
                return True
            # eval of static string (no variable)
            if re.search(r'\beval\s*\(\s*["\'][^$]+["\']', line):
                return True
            # eval in template context (intentional)
            if re.search(r'(?:template|view|render|blade|twig)', line, re.I):
                return True
            # Static PHP code generation (code builders)
            if re.search(r'eval\s*\([^)]*(?:class|function|namespace)', line, re.I):
                return True
            # NOTE: eval($row['phpinstall']) type is still flagged as potential backdoor

        if vuln_type == VulnType.FILE_INCLUSION:
            # Static includes (no variable in path)
            if re.search(r'(?:include|require)[^$]+["\'][^"\'$]+\.php["\']', line, re.I):
                return True
            # DOCUMENT_ROOT + constant path (not user input)
            if re.search(r'\$_SERVER\s*\[\s*[\'"]DOCUMENT_ROOT[\'"]\s*\]\s*\.\s*[\'"]/', line, re.I):
                return True
            # Concatenation with defined constant only
            if re.search(r'(?:include|require).*\b[A-Z_]{3,}\b\s*\.\s*[\'"]', line, re.I):
                return True

        if vuln_type == VulnType.FILE_WRITE:
            # Writing to hardcoded path (not user-controlled)
            if re.search(r'file_put_contents\s*\(\s*["\'][^"\'$]+["\']', line, re.I):
                return True
            # Writing cache/temp/log files (common safe pattern)
            if re.search(r'file_put_contents\s*\([^,]*(?:cache|temp|tmp|log|\.lock)', line, re.I):
                return True

        if vuln_type == VulnType.FILE_READ:
            # Reading from hardcoded path (not user-controlled)
            if re.search(r'file_get_contents\s*\(\s*["\'][^"\'$]+["\']', line, re.I):
                return True
            # Reading config/cache/template files with constant path
            if re.search(r'file_get_contents\s*\([^)]*(?:BASEPATH|ROOT_DIR|__DIR__|dirname)', line, re.I):
                return True

        if vuln_type == VulnType.UNSAFE_UPLOAD:
            # $_FILES in echo/print (just displaying filename)
            if re.search(r'(?:echo|print|die|exit)\s*[^;]*\$_FILES', line, re.I):
                return True
            # Hardcoded/hashed destination filename
            if re.search(r'move_uploaded_file\s*\([^,]+,\s*[^)]*(?:md5|sha1|uniqid|time)\s*\(', line, re.I):
                return True

        if vuln_type == VulnType.TYPE_JUGGLING:
            # Strict comparison (=== or !==) is SAFE, not vulnerable
            if '===' in line or '!==' in line:
                # Only flag if there's ALSO a loose == on the same line
                # Remove === and !== first, then check for remaining ==
                cleaned = line.replace('!==', '').replace('===', '')
                if '==' not in cleaned:
                    return True
            # Must be actual variable comparison, not just keyword in string
            # FP: $do == "lostpassword" (not comparing password value)
            if re.search(r'==\s*["\'](?:lostpassword|login|logout|register|auth|session)', line, re.I):
                return True
            # FP: action/do/mode comparisons
            if re.search(r'\$(?:action|do|mode|act|cmd|op|type|step|page|view|tab|section|category)\s*==', line, re.I):
                return True
            # Must have actual password/token variable being compared
            if not re.search(r'\$\w*(?:pass|pwd|token|hash|secret|credential|key)\w*\s*==', line, re.I):
                # Check reverse: string == $password
                if not re.search(r'==\s*\$\w*(?:pass|pwd|token|hash|secret|credential|key)', line, re.I):
                    return True

        if vuln_type == VulnType.HARDCODED_CREDS:
            # SQL UPDATE/INSERT with password field (not hardcoded, setting from variable)
            if re.search(r'(?:UPDATE|INSERT)\s+.*password\s*=\s*[\'"]?\{?\$', line, re.I):
                return True
            # SQL query building (password column reference)
            if re.search(r'["\']password["\']?\s*(?:=>|,|\.)', line, re.I):
                return True
            # Variable assignment from hash function (not hardcoded)
            if re.search(r'password\s*=\s*(?:md5|sha1|sha256|password_hash|crypt)\s*\(', line, re.I):
                return True
            # Empty password check
            if re.search(r'password\s*=\s*["\']["\']', line, re.I):
                return True
            # Password from variable/input (various formats)
            if re.search(r'password\s*=\s*[\'"]?\{?\$', line, re.I):
                return True
            # SQL SET password='$var' or password='{$var}'
            if re.search(r'password\s*=\s*[\'"][\'"]?\s*\.\s*\$', line, re.I):
                return True
            # Array key assignment
            if re.search(r'\[\s*[\'"]password[\'"]\s*\]\s*=', line, re.I):
                return True
            # API URL (not hardcoded password)
            if re.search(r'(?:url|api|endpoint|auth_url)\s*=', line, re.I):
                return True
            # Token in URL parameter (API auth)
            if re.search(r'token=.*\$_(?:GET|POST|REQUEST)', line, re.I):
                return True

        if vuln_type == VulnType.WEAK_CRYPTO:
            # Hash for non-security purposes (cache keys, etags, checksums)
            if re.search(r'(?:cache|etag|checksum|file_?hash|content_?hash)\s*=', line, re.I):
                return True
            # md5/sha1 of file content (integrity check, not password)
            if re.search(r'(?:md5|sha1)_file\s*\(', line, re.I):
                return True
            # Hash with salt/key for non-password use (session ID, user agent, etc.)
            if re.search(r'(?:md5|sha1)\s*\([^)]*(?:SECURE|SECRET|KEY|SALT|_KEY)', line, re.I):
                # Check if it's actually for password or token
                if not re.search(r'password|passwd|pwd|token|auth', line, re.I):
                    return True  # Non-password use with salt - acceptable
            # Hash for login cookie/session (not password storage)
            if re.search(r'(?:login_?hash|session_?hash|cookie_?hash|user_?agent)', line, re.I):
                return True
            # sha1/md5 for unique ID generation (not password)
            if re.search(r'(?:uniqid|microtime|rand|time)\s*\(', line, re.I):
                return True

        if vuln_type == VulnType.XXE:
            # Entity loading explicitly disabled
            if re.search(r'libxml_disable_entity_loader\s*\(\s*true', line, re.I):
                return True
            # NOENT flag NOT set (safe default)
            if re.search(r'simplexml_load_string\s*\(', line) and 'LIBXML_NOENT' not in line:
                # Only safe if not loading from user input
                pass
            # Static XML string (not user controlled)
            if re.search(r'simplexml_load_string\s*\(\s*["\']<', line):
                return True
            if re.search(r'simplexml_load_file\s*\(\s*["\']', line):
                return True

        if vuln_type == VulnType.SSRF:
            # Protocol validation present
            if re.search(r'(?:stripos|strpos)\s*\([^)]*[\'"]https?://', line, re.I):
                return True
            # URL validation with filter_var
            if re.search(r'filter_var\s*\([^)]*FILTER_VALIDATE_URL', line, re.I):
                return True
            # Whitelist domain check
            if re.search(r'(?:in_array|preg_match)\s*\([^)]*(?:allowed|whitelist|valid)', line, re.I):
                return True

        if vuln_type == VulnType.IDOR:
            # ID comes from session (authenticated user's own ID)
            if re.search(r'\$_SESSION\s*\[\s*[\'"](?:user_?id|member_?id|id)[\'"]\s*\]', line, re.I):
                return True
            # ID validated/cast to int with ownership check nearby
            if re.search(r'intval\s*\(\s*\$_(?:GET|POST)', line, re.I):
                # Still report but this is safer
                pass

        if vuln_type == VulnType.HEADER_INJECTION:
            # Static Location header (no user input)
            if re.search(r'header\s*\(\s*["\']Location:\s*/', line) and not re.search(r'\$_(GET|POST|REQUEST)', line):
                return True
            # Newlines already stripped from value variable
            # (check context for str_replace removing \r\n)
            if re.search(r'str_replace\s*\([^)]*\\[rn]', line, re.I):
                return True

        if vuln_type == VulnType.MASS_ASSIGNMENT:
            # Using ->only() to whitelist fields (safe)
            if re.search(r'->only\s*\(', line, re.I):
                return True
            # $fillable property defined (framework protection)
            if re.search(r'\$fillable\s*=', line, re.I):
                return True

        if vuln_type == VulnType.INSECURE_RANDOM:
            # Using cryptographic random functions
            if re.search(r'(?:random_bytes|random_int|openssl_random_pseudo_bytes)\s*\(', line, re.I):
                return True

        if vuln_type == VulnType.RACE_CONDITION:
            # File locking present
            if re.search(r'flock\s*\(', line, re.I):
                return True

        return False

    def _check_safe_context(self, code: str, line_num: int, vuln_type: VulnType) -> bool:
        """Check if code is in a safe context (reduces false positives)"""
        lines = code.split('\n')
        start = max(0, line_num - 10)
        end = min(len(lines), line_num + 5)
        context = '\n'.join(lines[start:end])
        line = lines[line_num - 1] if line_num <= len(lines) else ""

        # Check if in comment
        if self._is_in_comment(code, line_num):
            return True

        # Check for known FP patterns
        if self._is_false_positive_pattern(line, vuln_type):
            return True

        # Obfuscated code (ionCube, Zend Guard, etc.) - skip entirely
        if re.search(r'eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)', line, re.I):
            return True
        if re.search(r'\$_[A-Z]\s*=\s*[\'"][A-Za-z0-9+/=]{100,}[\'"]', context, re.I):
            return True

        # NOTE: Custom sanitizers are NOT filtered here anymore
        # They will be detected and reported with lower confidence
        # User can evaluate if bypass is possible

        # Generic intval/numeric casting
        if re.search(r'(?:intval|floatval|abs|floor|ceil)\s*\(\s*\$', context, re.I):
            if vuln_type in [VulnType.SQL_INJECTION, VulnType.IDOR]:
                return True

        # Type casting
        if re.search(r'\((?:int|float|bool)\)\s*\$', context, re.I):
            if vuln_type in [VulnType.SQL_INJECTION, VulnType.IDOR]:
                return True

        # JSON response context - XSS safe
        if vuln_type == VulnType.XSS:
            if re.search(r'json_encode\s*\(', context, re.I):
                return True
            if re.search(r'Content-Type.*application/json', context, re.I):
                return True
            if re.search(r'header\s*\([^)]*application/json', context, re.I):
                return True

        # API response context
        if re.search(r'return\s+response\(\)->json', context, re.I):
            return True

        # Static file paths (not user input)
        if vuln_type == VulnType.FILE_INCLUSION:
            if re.search(r'(?:include|require)[^$]*["\'][^"\'$]+["\']', line, re.I):
                return True

        # File write/read with path validation in context
        if vuln_type in (VulnType.FILE_WRITE, VulnType.FILE_READ):
            # Path validated with realpath + comparison (safe path check)
            if re.search(r'realpath\s*\([^)]+\)\s*(?:===|!==|==|!=)', context, re.I):
                return True
            # basename used to strip directory traversal
            if re.search(r'basename\s*\(', context, re.I):
                return True

        # Backtick for shell but with escapeshellarg in context
        if vuln_type == VulnType.COMMAND_INJECTION:
            if '`' in line and re.search(r'escapeshell(?:arg|cmd)', context, re.I):
                return True

        # Loose comparison but in non-security context
        if vuln_type == VulnType.TYPE_JUGGLING:
            # Skip if it's just checking for empty/false/null in non-auth context
            if not re.search(r'(?:password|token|auth|session|login)', context, re.I):
                return True

        # ============ SMART CONTEXT-BASED FP DETECTION ============

        if vuln_type == VulnType.SSRF:
            # Extend context for SSRF to check entire function (50 lines up)
            extended_start = max(0, line_num - 50)
            extended_context = '\n'.join(lines[extended_start:line_num])

            # Check if there's URL validation in extended context
            if re.search(r'(?:filter_var|parse_url|preg_match).*(?:url|https?)', extended_context, re.I):
                return True
            # Check for protocol restriction (http/https only)
            if re.search(r'(?:strpos|stripos)\s*\([^)]*[\'"]https?://', extended_context, re.I):
                return True
            # Check for return false after protocol check
            if re.search(r'(?:strpos|stripos).*https?.*return\s+false', extended_context, re.I | re.DOTALL):
                return True

        if vuln_type == VulnType.IDOR:
            # Check for ownership validation in context
            if re.search(r'(?:user_id|owner|author)\s*[!=]==?\s*\$', context, re.I):
                return True
            # Check for permission check
            if re.search(r'(?:check|has|verify).*(?:permission|access|owner)', context, re.I):
                return True

        if vuln_type == VulnType.HARDCODED_CREDS:
            # If it's a SQL query context, likely not hardcoded
            if re.search(r'(?:INSERT|UPDATE|SELECT|DELETE)\s+', context, re.I):
                if re.search(r'password\s*=\s*[\'"]?\$', context, re.I):
                    return True

        if vuln_type == VulnType.WEAK_CRYPTO:
            # Check if it's for security-critical use
            security_context = re.search(r'(?:password|token|secret|auth|session|login|verify)', context, re.I)
            # Non-security uses of md5/sha1 (file hash, cache key, etc.)
            if re.search(r'(?:cache|etag|checksum|file|content|data).*(?:md5|sha1)', context, re.I):
                if not security_context:
                    return True

        if vuln_type == VulnType.HEADER_INJECTION:
            # Check if header value is sanitized in nearby context (newlines stripped)
            if re.search(r'str_replace\s*\([^)]*(?:\\r|\\n|[\r\n])', context, re.I):
                return True
            # Whitelist/in_array check in context
            if re.search(r'in_array\s*\(', context, re.I):
                return True
            # Static header (no variable interpolation)
            if re.search(r'header\s*\(\s*["\'][^$]+["\']\s*\)', line, re.I):
                return True

        if vuln_type == VulnType.MASS_ASSIGNMENT:
            # $fillable or $guarded in context means model is protected
            if re.search(r'\$(?:fillable|guarded)\s*=\s*\[', context, re.I):
                return True
            # Using ->only() or ->validated() to whitelist fields
            if re.search(r'->(?:only|validated)\s*\(', context, re.I):
                return True

        if vuln_type == VulnType.LOG_INJECTION:
            # Newlines stripped before logging
            if re.search(r'(?:str_replace|preg_replace)\s*\([^)]*(?:\\r|\\n)', context, re.I):
                return True

        if vuln_type == VulnType.RACE_CONDITION:
            # File locking in context
            if re.search(r'flock\s*\(', context, re.I):
                return True
            # Transaction/mutex in context
            if re.search(r'(?:beginTransaction|LOCK\s+TABLES|mutex|lock)\s*\(', context, re.I):
                return True
            # Read-only file_exists usage (return path, template loading)
            if re.search(r'file_exists\s*\([^)]+\)\s*\)\s*return\b', line, re.I):
                return True
            # file_exists with is_file/is_dir (just type checking)
            if re.search(r'file_exists\s*\([^)]+\)\s+and\s+is_(?:file|dir)\s*\(', line, re.I):
                return True
            if re.search(r'file_exists\s*\([^)]+\)\s*&&\s*is_(?:file|dir)\s*\(', line, re.I):
                return True

        return False

    def _calculate_confidence(self, pattern_match: bool, sources: List[str],
                              sanitizers: List[str],
                              framework: Optional[str], in_auth: bool,
                              is_admin_path: bool = False,
                              taint_info: dict = None,
                              vuln_type: VulnType = None) -> float:
        """
        Calculate final confidence from all stages (Multi-Stage Verification)

        Requirements for HIGH confidence:
        - Pattern match + Source found + No sanitizer

        Formula:
        - Base: 0.85 if pattern matched
        - Sources: +0.15 if found, -0.4 if not
        - Sanitizers: -0.35 for builtin, -0.20 for custom
        - Framework: -0.20 if protected framework
        - Auth/Admin: -0.15 each
        - Taint tracking: +0.1 if confirmed, -0.4 if sanitized
        """
        if not pattern_match:
            return 0.0

        confidence = 0.85

        # Some vulnerability types don't need user input sources
        # (they are inherently dangerous regardless of data source)
        source_independent_types = {
            VulnType.WEAK_CRYPTO, VulnType.HARDCODED_CREDS,
            VulnType.INFO_DISCLOSURE, VulnType.INSECURE_RANDOM,
            VulnType.RACE_CONDITION, VulnType.LOG_INJECTION,
        }

        # Source presence (critical factor for injection types)
        has_weak_source = any(s == 'WEAK_INPUT' for s in sources) if sources else False
        has_strong_source = bool(sources) and not has_weak_source
        if has_strong_source:
            confidence += 0.15
        elif has_weak_source:
            confidence += 0.05  # Weak source (wrapper variable) - moderate boost
        elif vuln_type in source_independent_types:
            confidence -= 0.05  # Minimal penalty for source-independent vulns
        else:
            confidence -= 0.4  # No source = likely FP for injection types

        # Sanitizers handling (NEW APPROACH)
        # Built-in PHP sanitizers = bigger reduction (more trusted)
        # Custom sanitizers = smaller reduction (potential bypass)
        if sanitizers:
            builtin_sanitizers = ['intval', 'htmlspecialchars', 'htmlentities', 'escapeshellarg',
                                  'escapeshellcmd', 'addslashes', 'strip_tags', 'filter_var',
                                  'prepared', 'bindParam', 'bindValue', 'quote', '(int)', '(float)']

            has_builtin = any(s.lower() in [b.lower() for b in builtin_sanitizers] for s in sanitizers)
            has_custom = any(s.lower() not in [b.lower() for b in builtin_sanitizers] for s in sanitizers)

            if has_builtin:
                confidence -= 0.35  # Trusted but still report (could be misused)
            if has_custom:
                confidence -= 0.20  # Less trusted - potential bypass

        # Advanced taint tracking results
        if taint_info:
            if taint_info.get('sanitized'):
                confidence -= 0.4  # Sanitized in taint chain
            elif taint_info.get('tainted'):
                confidence += 0.1  # Confirmed taint flow
                # Boost for direct taint (few hops)
                if taint_info.get('hops', 0) <= 2:
                    confidence += 0.05

        # Framework/ORM protection (any detected framework with built-in security)
        if framework:
            confidence -= 0.20

        # Auth context (admin-only code is lower risk)
        if in_auth:
            confidence -= 0.15

        # Admin path (even lower risk)
        if is_admin_path:
            confidence -= 0.15

        # Multi-stage verification bonus
        stages_agree = 0
        if sources:
            stages_agree += 1
        if taint_info and taint_info.get('tainted') and not taint_info.get('sanitized'):
            stages_agree += 1

        if stages_agree >= 2:
            confidence += 0.1  # Multiple stages agree = more confident

        return max(0.0, min(1.0, confidence))

    def scan_code(self, code: str, filepath: str = "") -> List[Finding]:
        """
        Scan code using unified pipeline (Multi-Stage Verification)

        Pipeline:
        1. Pattern matching (identify potential issues)
        2. Taint analysis (verify data flow + variable tracking)
        3. Context analysis (admin path, auth context)
        4. Multi-stage verification (require agreement)
        5. Final decision (filter low confidence)
        """
        findings = []
        lines = code.split('\n')

        # Performance: Skip encoded/obfuscated files (DLE trial, ionCube etc.)
        # These files have very few lines but huge content per line
        if len(lines) < 20 and len(code) > 5000:
            # Check for DLE encoding pattern
            if '$_F=__FILE__' in code or '$_X=' in code:
                return []
            # Check for ionCube/Zend encoding
            if 'ioncube' in code.lower() or 'sg_load' in code:
                return []

        # Detect framework once
        framework = self._detect_framework(code)

        # Detect if file is in admin path
        is_admin_path = self._check_admin_path(filepath)

        # Detect if code has admin-only access checks
        has_admin_check = self._check_admin_code_context(code, 0)

        # If both admin path AND admin code check, very likely intentional admin functionality
        is_admin_only = is_admin_path and has_admin_check

        # Detect custom sanitizer functions in code
        custom_sanitizers = self._detect_custom_sanitizers(code)

        # Stage 1: Pattern Matching (using pre-compiled regex)
        for vuln_type, compiled in self.compiled_patterns.items():
            for compiled_pattern, base_severity in compiled:
                for match in compiled_pattern.finditer(code):
                    line_num = code[:match.start()].count('\n') + 1
                    line_code = lines[line_num - 1].strip() if line_num <= len(lines) else ""

                    # Stage 2: Taint Analysis (basic)
                    sources = self._find_sources(code, line_num)
                    # Also check if source is directly on the matched line
                    # (handles cases like extract($_POST) where source IS the sink)
                    if not sources:
                        for src_name, src_pattern in self.sources.items():
                            if re.search(src_pattern, line_code, re.IGNORECASE):
                                sources.append(src_name)
                                break
                        # Broader source check (without bracket requirement)
                        if not sources and re.search(r'\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)', line_code):
                            m = re.search(r'\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)', line_code)
                            sources.append(m.group(0).replace('$_', ''))
                    # Stage 2.1: Weak source detection - common request wrapper variables
                    # Many CMS/frameworks use $post, $data, $input, $request, $params
                    # as wrappers for $_POST/$_GET. Detect these as weak sources.
                    if not sources:
                        weak_source_vars = r'\$(?:post|data|input|request|params|args|body)\s*\['
                        if re.search(weak_source_vars, line_code, re.I):
                            sources.append('WEAK_INPUT')
                    sanitizers = self._find_sanitizers(code, line_num, vuln_type)
                    in_auth = self._check_auth_context(code, line_num)

                    # Stage 2.3: Detect custom sanitizer functions dynamically
                    detected_custom_sans = self._detect_custom_sanitizer_usage(code, line_num)
                    if detected_custom_sans:
                        sanitizers.extend(detected_custom_sans)

                    # Stage 2.4: Check for custom sanitizers wrapping the code
                    if custom_sanitizers and self._check_wrapped_in_function(code, line_num, custom_sanitizers):
                        sanitizers.append('custom_wrapper')

                    # Stage 2.5: Advanced Taint Tracking (variable following)
                    taint_info = self._track_variable_taint(code, line_num, max_depth=7)

                    # Stage 2.6: Safe Context Check
                    if self._check_safe_context(code, line_num, vuln_type):
                        continue

                    # Stage 3: Calculate Final Confidence (Multi-Stage)
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

                    # Stage 3.5: Context-aware confidence boost for file operations
                    # base64_decode in context of file write/read = obfuscation signal
                    if vuln_type in (VulnType.FILE_WRITE, VulnType.FILE_READ, VulnType.PATH_TRAVERSAL):
                        ctx_start = max(0, line_num - 15)
                        ctx_end = min(len(lines), line_num + 3)
                        file_ctx = '\n'.join(lines[ctx_start:ctx_end])
                        if re.search(r'base64_decode\s*\(', file_ctx, re.I):
                            confidence += 0.20  # Strong suspicion: path decoded from base64

                    # Stage 4.5: Admin-only code - still report but mark as admin-only
                    # A vulnerability is still a vulnerability (admin compromise, CSRF, etc.)
                    admin_finding = False
                    if is_admin_only:
                        admin_finding = True
                        # Reduce confidence but ensure it stays above minimum
                        if vuln_type in [VulnType.CODE_INJECTION, VulnType.RCE]:
                            confidence = max(0.50, confidence * 0.7)  # Min 50%
                        elif vuln_type == VulnType.UNSAFE_UPLOAD:
                            confidence = max(0.50, confidence * 0.75)
                        else:
                            confidence = max(0.50, confidence * 0.8)

                    # Stage 5: Filter low confidence
                    # Lower threshold to include sanitized findings (potential bypass)
                    # Admin findings and sanitized findings have lower threshold
                    has_custom_sanitizer = any(s not in ['intval', 'htmlspecialchars', 'escapeshellarg'] for s in sanitizers)
                    if admin_finding or has_custom_sanitizer:
                        min_confidence = 0.40  # Show more findings with sanitizers
                    else:
                        min_confidence = 0.60
                    if confidence < min_confidence:
                        continue

                    # Stage 6: Adjust severity based on confidence
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

        # Stage 7: AST-based verification (APEX v4.0)
        # Use AST to VERIFY pattern findings, not to add new ones
        # This improves accuracy without increasing false positives
        if self.enable_ast and self.ast_parser:
            try:
                vuln_flows = self.ast_parser.get_vulnerable_flows(code, filepath)
                ast_vuln_lines = set()
                for flow in vuln_flows:
                    ast_vuln_lines.add((flow.sink_line, flow.sink_type))

                for f in findings:
                    # Map VulnType to AST sink type
                    type_map = {
                        VulnType.SQL_INJECTION: 'SQL_INJECTION',
                        VulnType.XSS: 'XSS',
                        VulnType.COMMAND_INJECTION: 'COMMAND_INJECTION',
                        VulnType.CODE_INJECTION: 'CODE_INJECTION',
                        VulnType.FILE_INCLUSION: 'FILE_INCLUSION',
                    }
                    ast_type = type_map.get(f.vuln_type, f.vuln_type.name)

                    # Check if AST confirms this finding
                    if (f.line, ast_type) in ast_vuln_lines:
                        f.confidence = min(0.98, f.confidence + 0.10)
                        f.taint_verified = True
                    else:
                        # AST says this is safe - reduce confidence
                        f.confidence = max(0.0, f.confidence - 0.15)
            except Exception:
                pass

        # Stage 8: Multi-line pattern detection (sliding window)
        multiline_findings = self._scan_multiline(code, lines, filepath, framework, is_admin_path)
        findings.extend(multiline_findings)

        # Stage 9: File-wide taint tracking (catches long-range source→sink flows)
        file_wide_findings = self._scan_file_wide_taint(code, lines, filepath, framework, is_admin_path)
        findings.extend(file_wide_findings)

        # Deduplicate (same line, same type) - keep highest confidence
        best = {}
        for f in findings:
            key = (f.line, f.vuln_type)
            if key not in best or f.confidence > best[key].confidence:
                best[key] = f

        unique = list(best.values())

        # Cross-line dedup: if taint analysis found flow A->B and pattern also
        # found B, keep only the higher-confidence one
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
                # Too many findings of same type - keep top 3 by confidence + all CRITICAL
                type_findings.sort(key=lambda x: x.confidence, reverse=True)
                kept = set()
                for f in type_findings:
                    if f.severity.name == 'CRITICAL' or len(kept) < 3:
                        kept.add(id(f))
                        final.append(f)

        # Final filter - remove findings that data flow proved safe
        final = [f for f in final if f.confidence >= 0.50]

        return final

    # Pre-compiled multi-line patterns using backreferences
    _MULTILINE_PATTERNS = None

    @classmethod
    def _get_multiline_patterns(cls):
        if cls._MULTILINE_PATTERNS is None:
            cls._MULTILINE_PATTERNS = [
                # $var = $_GET/POST/REQUEST[...]; ... mysql_query/mysqli_query(...$var...)
                (re.compile(r'\$(\w+)\s*=\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\][^;]*;.*?(?:mysql_query|mysqli_query|pg_query)\s*\([^)]*\$\1', re.DOTALL | re.IGNORECASE),
                 VulnType.SQL_INJECTION, Severity.HIGH),
                # $var = $_GET/POST[...]; ... ->query(...$var...)
                (re.compile(r'\$(\w+)\s*=\s*\$_(GET|POST|REQUEST)\s*\[[^\]]+\][^;]*;.*?->query\s*\([^)]*\$\1', re.DOTALL | re.IGNORECASE),
                 VulnType.SQL_INJECTION, Severity.HIGH),
                # $var = $_GET/POST[...]; ... exec/system/passthru/shell_exec(...$var...)
                (re.compile(r'\$(\w+)\s*=\s*\$_(GET|POST|REQUEST)\s*\[[^\]]+\][^;]*;.*?(?:exec|system|passthru|shell_exec)\s*\([^)]*\$\1', re.DOTALL | re.IGNORECASE),
                 VulnType.COMMAND_INJECTION, Severity.HIGH),
                # $var = $_GET/POST[...]; ... echo ...$var...
                (re.compile(r'\$(\w+)\s*=\s*\$_(GET|POST|REQUEST)\s*\[[^\]]+\][^;]*;.*?echo\s+[^;]*\$\1', re.DOTALL | re.IGNORECASE),
                 VulnType.XSS, Severity.HIGH),
                # $var = $_GET/POST[...]; ... include/require(...$var...)
                (re.compile(r'\$(\w+)\s*=\s*\$_(GET|POST|REQUEST)\s*\[[^\]]+\][^;]*;.*?(?:include|require)(?:_once)?\s*[\(\s][^;]*\$\1', re.DOTALL | re.IGNORECASE),
                 VulnType.FILE_INCLUSION, Severity.HIGH),
                # $var = $_GET/POST[...]; ... eval(...$var...)
                (re.compile(r'\$(\w+)\s*=\s*\$_(GET|POST|REQUEST)\s*\[[^\]]+\][^;]*;.*?eval\s*\([^)]*\$\1', re.DOTALL | re.IGNORECASE),
                 VulnType.CODE_INJECTION, Severity.CRITICAL),
                # $var = $_GET/POST[...]; ... unserialize(...$var...)
                (re.compile(r'\$(\w+)\s*=\s*\$_(GET|POST|REQUEST)\s*\[[^\]]+\][^;]*;.*?unserialize\s*\([^)]*\$\1', re.DOTALL | re.IGNORECASE),
                 VulnType.DESERIALIZATION, Severity.CRITICAL),
                # $var = $_GET/POST[...]; ... file_put_contents(...$var...)
                (re.compile(r'\$(\w+)\s*=\s*\$_(GET|POST|REQUEST)\s*\[[^\]]+\][^;]*;.*?file_put_contents\s*\([^,]*\$\1', re.DOTALL | re.IGNORECASE),
                 VulnType.FILE_WRITE, Severity.CRITICAL),
                # $var = $_GET/POST[...]; ... file_get_contents($var)
                (re.compile(r'\$(\w+)\s*=\s*\$_(GET|POST|REQUEST)\s*\[[^\]]+\][^;]*;.*?file_get_contents\s*\([^)]*\$\1', re.DOTALL | re.IGNORECASE),
                 VulnType.FILE_READ, Severity.HIGH),
                # base64_decode → file path: $var = base64_decode(...); ... file_put_contents($var, ...)
                (re.compile(r'\$(\w+)\s*=\s*base64_decode\s*\([^)]*\)[^;]*;.*?file_put_contents\s*\(\s*\$\1', re.DOTALL | re.IGNORECASE),
                 VulnType.FILE_WRITE, Severity.HIGH),
                # base64_decode → file read: $var = base64_decode(...); ... file_get_contents($var)
                (re.compile(r'\$(\w+)\s*=\s*base64_decode\s*\([^)]*\)[^;]*;.*?file_get_contents\s*\(\s*\$\1', re.DOTALL | re.IGNORECASE),
                 VulnType.FILE_READ, Severity.HIGH),
                # TOCTOU multiline: file_exists($var) ... unlink/rename/chmod($var)
                (re.compile(r'file_exists\s*\(\s*\$(\w+)\s*\).*?(?:unlink|rename|chmod|chown|rmdir)\s*\(\s*\$\1', re.DOTALL | re.IGNORECASE),
                 VulnType.RACE_CONDITION, Severity.HIGH),
            ]
        return cls._MULTILINE_PATTERNS

    def _scan_multiline(self, code: str, lines: List[str], filepath: str,
                        framework: Optional[str], is_admin_path: bool) -> List[Finding]:
        """Detect vulnerabilities spanning multiple lines using a sliding window."""
        # Quick check: skip files with no superglobal sources and no suspicious patterns
        has_superglobal = re.search(r'\$_(GET|POST|REQUEST|COOKIE)\s*\[', code)
        has_base64_file_op = (re.search(r'base64_decode\s*\(', code) and
                              re.search(r'(?:file_put_contents|file_get_contents|fopen|include|require)\s*\(', code))
        if not has_superglobal and not has_base64_file_op:
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
                    # Line number of the sink (end of match)
                    match_end_offset = match.end()
                    sink_line = i + 1 + window[:match_end_offset].count('\n')

                    # Check for sanitizers between source and sink
                    sanitizers = self._find_sanitizers_in_context(window, vuln_type)
                    if sanitizers:
                        continue  # Sanitized

                    # Check FP filter
                    sink_line_code = lines[min(sink_line - 1, len(lines) - 1)]
                    if self._is_false_positive_pattern(sink_line_code, vuln_type):
                        continue

                    confidence = 0.80
                    if framework:
                        confidence -= 0.15
                    if is_admin_path:
                        confidence -= 0.10

                    # Extract source from match group (group 2 for superglobal patterns,
                    # fallback to 'base64' for base64_decode patterns)
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
        """File-wide taint tracking: find source assignments, then check all sinks in file.

        This catches patterns where source and sink are far apart (>15 lines),
        like bWAPP's $var = $_GET['x'] ... echo func($var) patterns.
        """
        findings = []

        # Step 1: Find all tainted variable assignments
        tainted_vars = {}  # var_name -> (line_num, source_type)

        # Direct superglobal assignments: $var = $_GET/POST/REQUEST[...]
        for m in re.finditer(r'\$(\w+)\s*=\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[', code):
            var_name = m.group(1)
            source = m.group(2)
            line_num = code[:m.start()].count('\n') + 1
            tainted_vars[var_name] = (line_num, source)

        # php://input assignments: $var = file_get_contents("php://input")
        for m in re.finditer(r'\$(\w+)\s*=\s*file_get_contents\s*\(\s*["\']php://input["\']', code):
            var_name = m.group(1)
            line_num = code[:m.start()].count('\n') + 1
            tainted_vars[var_name] = (line_num, 'INPUT')

        if not tainted_vars:
            return []

        # Step 2: For each tainted variable, check sinks throughout the file
        sink_patterns = [
            # (regex_template, vuln_type, severity) - {var} replaced with variable name
            # SQLi: string concat with tainted var in SQL
            (r'["\'](?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\.\s*\${var}\b', VulnType.SQL_INJECTION, Severity.HIGH),
            (r'["\'].*?\.\s*\${var}\s*\.\s*["\']', VulnType.SQL_INJECTION, Severity.MEDIUM),  # generic concat in string
            (r'->query\s*\(\s*\${var}\s*\)', VulnType.SQL_INJECTION, Severity.HIGH),
            (r'(?:mysql_query|mysqli_query|pg_query)\s*\([^)]*\${var}', VulnType.SQL_INJECTION, Severity.HIGH),
            # XSS: echo/print with tainted var
            (r'\becho\s+[^;]*\${var}\b', VulnType.XSS, Severity.HIGH),
            (r'\bprint\s+[^;]*\${var}\b', VulnType.XSS, Severity.HIGH),
            (r'\bprintf\s*\([^)]*\${var}', VulnType.XSS, Severity.MEDIUM),
            # Command injection
            (r'(?:exec|system|passthru|shell_exec|popen)\s*\([^)]*\${var}', VulnType.COMMAND_INJECTION, Severity.HIGH),
            # Code injection
            (r'\beval\s*\([^)]*\${var}', VulnType.CODE_INJECTION, Severity.CRITICAL),
            # File inclusion
            (r'(?:include|require)(?:_once)?\s*[\(\s][^;]*\${var}', VulnType.FILE_INCLUSION, Severity.HIGH),
            # XXE: XML parsing with tainted var
            (r'simplexml_load_string\s*\(\s*\${var}', VulnType.XXE, Severity.HIGH),
            (r'DOMDocument.*loadXML\s*\(\s*\${var}', VulnType.XXE, Severity.HIGH),
            # SSRF
            (r'(?:file_get_contents|curl_init)\s*\(\s*\${var}', VulnType.SSRF, Severity.HIGH),
            # File operations
            (r'file_put_contents\s*\([^,]*\${var}', VulnType.FILE_WRITE, Severity.HIGH),
            (r'file_get_contents\s*\(\s*\${var}', VulnType.FILE_READ, Severity.HIGH),
            # Unserialize
            (r'unserialize\s*\(\s*\${var}', VulnType.DESERIALIZATION, Severity.CRITICAL),
            # Header injection
            (r'header\s*\([^)]*\${var}', VulnType.HEADER_INJECTION, Severity.HIGH),
            # Open redirect
            (r'header\s*\(\s*["\']Location:\s*["\'][^)]*\${var}', VulnType.OPEN_REDIRECT, Severity.HIGH),
        ]

        for var_name, (src_line, source_type) in tainted_vars.items():
            for pattern_template, vuln_type, severity in sink_patterns:
                pattern = pattern_template.replace('{var}', re.escape(var_name))
                try:
                    for m in re.finditer(pattern, code, re.IGNORECASE):
                        sink_line = code[:m.start()].count('\n') + 1

                        # Skip if source and sink on same line (already caught by single-line)
                        if sink_line == src_line:
                            continue

                        # Skip if sink is BEFORE source (variable reassigned or different scope)
                        if sink_line < src_line:
                            continue

                        line_code = lines[sink_line - 1].strip() if sink_line <= len(lines) else ""

                        # Check for sanitizers between source and sink
                        context_start = code.find(lines[src_line - 1]) if src_line <= len(lines) else 0
                        context_end = code.find(lines[sink_line - 1]) if sink_line <= len(lines) else len(code)
                        context = code[context_start:context_end + len(line_code)]
                        sanitizers = self._find_sanitizers_in_context(context, vuln_type)

                        # Check FP filter
                        if self._is_false_positive_pattern(line_code, vuln_type):
                            continue

                        # Calculate confidence
                        confidence = 0.75
                        if source_type in ('GET', 'POST', 'REQUEST'):
                            confidence += 0.10
                        if sanitizers:
                            confidence -= 0.25
                        if framework:
                            confidence -= 0.10
                        if is_admin_path:
                            confidence -= 0.10

                        # For generic concat pattern (MEDIUM), require SQL context
                        if severity == Severity.MEDIUM and vuln_type == VulnType.SQL_INJECTION:
                            # Check if there's actual SQL nearby
                            nearby = '\n'.join(lines[max(0, sink_line-3):min(len(lines), sink_line+2)])
                            if not re.search(r'(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b', nearby, re.I):
                                continue

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
        """Check if sanitizers are present in the multi-line context."""
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
        }
        for san in san_map.get(vuln_type, []):
            if san in context:
                found.append(san)
        return found

    def scan_file(self, filepath: str) -> List[Finding]:
        """Scan a single file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            return self.scan_code(code, filepath)
        except Exception as e:
            return []

    def scan_directory(self, dirpath: str) -> Dict:
        """Scan all PHP files in directory"""
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
        """
        Full scan with inter-procedural analysis

        Combines:
        1. Per-file pattern + taint + ML analysis
        2. Cross-function taint flow analysis
        """
        # Basic scan
        results = self.scan_directory(dirpath)

        # Add inter-procedural analysis
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
                    # Add to findings count
                    results['total_findings'] += 1
                    if flow.confidence >= 0.8:
                        results['high'] += 1
                    else:
                        results['medium'] += 1
            except Exception as e:
                results['interprocedural'] = {'error': str(e)}

        return results


def test():
    """Test unified scanner"""
    scanner = UnifiedScanner()

    test_cases = [
        # VULNERABLE
        ('$id=$_GET["id"];mysql_query("SELECT * FROM x WHERE id=$id");', True, "SQL Direct"),
        ('system($_POST["cmd"]);', True, "Command Direct"),
        ('include($_GET["page"].".php");', True, "LFI Direct"),
        ('echo $_GET["name"];', True, "XSS Direct"),

        # SAFE (sanitized)
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
