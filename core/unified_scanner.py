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
import pickle
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

# Add paths
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / 'ml'))

# Inter-procedural analysis
try:
    from interprocedural import InterproceduralAnalyzer, analyze_interprocedural
    HAS_INTERPROCEDURAL = True
except ImportError:
    HAS_INTERPROCEDURAL = False


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
    ml_score: float = 0.0

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
                'ml': self.ml_score
            }
        }


class UnifiedScanner:
    """
    Unified scanner combining all detection methods

    Pipeline:
    1. Pattern matching (fast initial detection)
    2. Taint tracking (data flow verification)
    3. ML scoring (confidence adjustment)
    4. Final decision
    """

    def __init__(self, enable_ml: bool = True):
        self.enable_ml = enable_ml
        self._init_patterns()
        self._init_sources_sinks()
        self._init_sanitizers()
        self._init_frameworks()
        self._load_ml_model()

    def _init_patterns(self):
        """Initialize vulnerability patterns"""
        self.patterns = {
            VulnType.SQL_INJECTION: [
                # Direct injection
                (r'(?:mysql_query|mysqli_query|pg_query)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)', Severity.CRITICAL),
                # String concat with user input
                (r'["\'](?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\$_(GET|POST|REQUEST)', Severity.CRITICAL),
                # Variable in query (interpolation)
                (r'(?:mysql_query|mysqli_query|pg_query)\s*\([^)]*\$\w+', Severity.HIGH),
                # Variable in query method
                (r'->query\s*\(\s*["\'][^"\']*\$\w+', Severity.HIGH),
            ],
            VulnType.COMMAND_INJECTION: [
                (r'\b(?:exec|system|passthru|shell_exec|popen)\s*\([^)]*\$_(GET|POST|REQUEST)', Severity.CRITICAL),
                (r'\b(?:exec|system|passthru|shell_exec)\s*\(\s*["\'][^"\']*\.\s*\$', Severity.HIGH),
                (r'\b(?:exec|system|passthru|shell_exec|popen)\s*\(\s*\$\w+', Severity.HIGH),
                (r'`[^`]*\$_(GET|POST|REQUEST)', Severity.CRITICAL),
                (r'`[^`]*\$\w+[^`]*`', Severity.MEDIUM),
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
            ],
            VulnType.FILE_READ: [
                (r'file_get_contents\s*\(\s*\$_(GET|POST|REQUEST)', Severity.HIGH),
                (r'\breadfile\s*\(\s*\$_(GET|POST|REQUEST)', Severity.HIGH),
                (r'show_source\s*\(\s*\$', Severity.HIGH),
            ],
            VulnType.XSS: [
                (r'\becho\s+[^;]*\$_(GET|POST|REQUEST|COOKIE)', Severity.HIGH),
                (r'\bprint\s+[^;]*\$_(GET|POST|REQUEST|COOKIE)', Severity.HIGH),
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
            ],
            VulnType.RCE: [
                (r'call_user_func\s*\(\s*\$_(GET|POST|REQUEST)', Severity.CRITICAL),
                (r'call_user_func_array\s*\(\s*\$_(GET|POST|REQUEST)', Severity.CRITICAL),
                (r'\$\w+\s*\(\s*\)', Severity.MEDIUM),  # Variable function call
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
                (r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{3,}["\']', Severity.HIGH),
                (r'(?:api_key|apikey|secret|token)\s*=\s*["\'][^"\']{8,}["\']', Severity.HIGH),
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
                # Only match in auth context - pattern includes auth keywords
                (r'(?:password|passwd|token|auth|login|session).*==\s*["\']', Severity.HIGH),
                (r'==\s*["\'].*(?:password|passwd|token|auth)', Severity.HIGH),
            ],
            VulnType.XXE: [
                # XML External Entity
                (r'simplexml_load_string\s*\([^)]*\$_(GET|POST|REQUEST)', Severity.CRITICAL),
                (r'DOMDocument.*loadXML\s*\([^)]*\$', Severity.HIGH),
                (r'xml_parse\s*\([^)]*\$_(GET|POST|REQUEST)', Severity.HIGH),
                (r'XMLReader.*xml\s*\([^)]*\$', Severity.HIGH),
                (r'LIBXML_NOENT', Severity.MEDIUM),  # Dangerous flag
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
        }

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
            'safesql': {'pattern': r'safesql\s*\(', 'protects': [VulnType.SQL_INJECTION, VulnType.XSS]},
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
            'in_array': {'pattern': r'in_array\s*\(', 'protects': [VulnType.FILE_INCLUSION, VulnType.COMMAND_INJECTION, VulnType.RCE, VulnType.OPEN_REDIRECT, VulnType.CODE_INJECTION]},
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

            # DLE specific
            'dle_safesql': {'pattern': r'\$db->safesql', 'protects': [VulnType.SQL_INJECTION]},
            'dle_parse': {'pattern': r'\$parse->(?:process|safe)', 'protects': [VulnType.XSS, VulnType.SQL_INJECTION]},
            'dle_super': {'pattern': r'\$_REQUEST\s*\[\s*[\'"]do[\'"]', 'protects': [VulnType.SQL_INJECTION]},
        }

    def _init_frameworks(self):
        """Initialize framework detection"""
        self.frameworks = {
            'laravel': [r'Illuminate\\', r'->where\s*\([^,]+,', r'Route::'],
            'symfony': [r'Symfony\\', r'->setParameter\('],
            'wordpress': [r'\$wpdb->prepare', r'esc_html\(', r'esc_attr\('],
            'codeigniter': [r'\$this->db->escape', r'xss_clean'],
            'dle': [r'DATALIFEENGINE', r'safesql\s*\('],
        }

    def _load_ml_model(self):
        """Load ML model if available"""
        self.ml_model = None
        self.ml_vectorizer = None

        if not self.enable_ml:
            return

        model_paths = [
            Path(__file__).parent.parent / 'ml' / 'vuln_model_v8.pkl',
            Path(__file__).parent.parent / 'ml' / 'vuln_model_v7.pkl',
            Path(__file__).parent.parent / 'ml' / 'vuln_model.pkl',
        ]

        for path in model_paths:
            if path.exists():
                try:
                    with open(path, 'rb') as f:
                        data = pickle.load(f)
                    self.ml_model = data.get('model')
                    self.ml_vectorizer = data.get('vectorizer')
                    break
                except:
                    pass

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
        admin_indicators = [
            r'[/\\]admin[/\\]',
            r'[/\\]backend[/\\]',
            r'[/\\]dashboard[/\\]',
            r'[/\\]panel[/\\]',
            r'[/\\]manage[/\\]',
            r'[/\\]engine[/\\]inc[/\\]',   # DLE admin
            r'[/\\]engine[/\\]ajax[/\\]',  # DLE ajax (admin)
            r'[/\\]wp-admin[/\\]',          # WordPress
            r'[/\\]administrator[/\\]',     # Joomla
            r'[/\\]bitrix[/\\]admin[/\\]',  # Bitrix
            r'[/\\]adm[/\\]',
            r'[/\\]cpanel[/\\]',
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

        admin_check_patterns = [
            r'user_group\s*[!=]=\s*1',           # DLE admin check
            r'user_group\s*==\s*1',
            r'\$member_id\s*\[\s*[\'"]user_group[\'"]\s*\]\s*[!=]=\s*1',
            r'current_user_can\s*\(\s*[\'"]manage',  # WordPress
            r'is_admin\s*\(\s*\)',
            r'isAdmin\s*\(\s*\)',
            r'->isAdmin\s*\(',
            r'check_admin\s*\(',
            r'require_admin\s*\(',
            r'auth.*admin',
            r'admin.*auth',
            r'permission.*admin',
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
        """Check for known false positive patterns"""

        # Empty or very short line
        if len(line.strip()) < 10:
            return True

        # Documentation/example patterns
        if re.search(r'(?:example|sample|demo|test|TODO|FIXME|NOTE):', line, re.I):
            return True

        # Error message strings
        if re.search(r'(?:echo|print)\s+["\'].*(?:error|warning|notice|failed)', line, re.I):
            return True

        # Logging statements
        if re.search(r'(?:log|debug|trace|error_log)\s*\(', line, re.I):
            return True

        # Configuration/constant definitions
        if re.search(r'(?:define|const)\s*\(?\s*[\'"][A-Z_]+[\'"]', line, re.I):
            return True

        # Type-specific FP patterns
        if vuln_type == VulnType.SQL_INJECTION:
            # Prepared statements
            if re.search(r'\?\s*,|\:\w+|bindParam|bindValue', line, re.I):
                return True
            # ORM methods (safe)
            if re.search(r'->(?:where|find|first|get)\s*\(', line, re.I):
                return True

        if vuln_type == VulnType.XSS:
            # Already escaped output
            if re.search(r'(?:htmlspecialchars|esc_html|e\()\s*\(', line, re.I):
                return True
            # JSON output
            if re.search(r'json_encode|application/json', line, re.I):
                return True

        if vuln_type == VulnType.COMMAND_INJECTION:
            # Escaped shell arguments
            if re.search(r'escapeshell(?:arg|cmd)\s*\(', line, re.I):
                return True

        if vuln_type == VulnType.FILE_INCLUSION:
            # Static includes (no variable in path)
            if re.search(r'(?:include|require)[^$]+["\'][^"\'$]+\.php["\']', line, re.I):
                return True

        if vuln_type == VulnType.CODE_INJECTION:
            # eval of DB row data (usually admin plugin functionality)
            if re.search(r'eval\s*\(\s*\$row\s*\[', line, re.I):
                return True
            # eval of config/settings
            if re.search(r'eval\s*\(\s*\$(?:config|settings|options)\s*\[', line, re.I):
                return True

        if vuln_type == VulnType.UNSAFE_UPLOAD:
            # $_FILES in echo/print (just displaying filename, not using it)
            if re.search(r'(?:echo|print|echo_error|die|exit)\s*[^;]*\$_FILES\s*\[[^\]]+\]\s*\[[\'"]name[\'"]\]', line, re.I):
                return True
            # $_FILES in error message
            if re.search(r'(?:error|exception|message|warning)', line, re.I) and re.search(r'\$_FILES', line):
                return True
            # Hardcoded destination filename (safe)
            if re.search(r'move_uploaded_file\s*\([^,]+,\s*[^)]*md5\s*\(', line, re.I):
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

        # Obfuscated code (DLE, ionCube, etc.) - skip entirely
        if re.search(r'eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)', line, re.I):
            return True
        if re.search(r'\$_[A-Z]\s*=\s*[\'"][A-Za-z0-9+/=]{100,}[\'"]', context, re.I):
            return True

        # DLE Framework - safesql is the main sanitizer
        if re.search(r'safesql\s*\(', context, re.I):
            if vuln_type in [VulnType.SQL_INJECTION, VulnType.XSS, VulnType.COMMAND_INJECTION]:
                return True

        # DLE intval usage
        if re.search(r'intval\s*\(\s*\$', context, re.I):
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

        # Backtick for shell but with escapeshellarg in context
        if vuln_type == VulnType.COMMAND_INJECTION:
            if '`' in line and re.search(r'escapeshell(?:arg|cmd)', context, re.I):
                return True

        # Loose comparison but in non-security context
        if vuln_type == VulnType.TYPE_JUGGLING:
            # Skip if it's just checking for empty/false/null in non-auth context
            if not re.search(r'(?:password|token|auth|session|login)', context, re.I):
                return True

        return False

    def _extract_ml_features(self, code: str, vuln_type: VulnType) -> str:
        """Extract features for ML model (matches train_v8.py format)"""
        tokens = []

        # Sources (format: SRC_GET, SRC_POST, etc.)
        source_patterns = {
            'GET': r'\$_GET',
            'POST': r'\$_POST',
            'REQUEST': r'\$_REQUEST',
            'COOKIE': r'\$_COOKIE',
            'FILES': r'\$_FILES',
            'SERVER': r'\$_SERVER',
        }
        has_source = False
        for name, pattern in source_patterns.items():
            if re.search(pattern, code, re.I):
                tokens.append(f"SRC_{name}")
                has_source = True

        # Sinks (format: SINK_SQL, SINK_CMD, etc.)
        sink_patterns = {
            'SQL': r'(?:mysql_query|mysqli_query|->query|->exec)',
            'CMD': r'(?:\bexec\b|\bsystem\b|\bpassthru\b|shell_exec|popen)',
            'ECHO': r'(?:\becho\b|\bprint\b|\bprintf\b)',
            'INCLUDE': r'(?:\binclude\b|\brequire\b)',
            'EVAL': r'(?:\beval\b|\bassert\b|create_function)',
            'FILE': r'(?:file_get_contents|file_put_contents|fopen)',
            'UNSER': r'\bunserialize\b',
        }
        has_sink = False
        for name, pattern in sink_patterns.items():
            if re.search(pattern, code, re.I):
                tokens.append(f"SINK_{name}")
                has_sink = True

        # Sanitizers (format: SAN_INTVAL, SAN_ESCAPE_SQL, etc.)
        san_patterns = {
            'INTVAL': r'(?:intval|\(int\))',
            'ESCAPE_SQL': r'(?:escape_string|addslashes|->quote)',
            'PREPARE': r'(?:->prepare|bindParam|bindValue)',
            'ESCAPE_HTML': r'(?:htmlspecialchars|htmlentities|strip_tags)',
            'ESCAPE_CMD': r'(?:escapeshellarg|escapeshellcmd)',
            'VALIDATE': r'(?:is_numeric|ctype_digit|filter_var)',
            'WHITELIST': r'(?:in_array)',
        }
        has_sanitizer = False
        for name, pattern in san_patterns.items():
            if re.search(pattern, code, re.I):
                tokens.append(f"SAN_{name}")
                has_sanitizer = True

        # Flow tokens
        if has_source and has_sink:
            if has_sanitizer:
                tokens.append("FLOW_SANITIZED")
            else:
                tokens.append("FLOW_UNSANITIZED")

        # Function tokens (format: FUNC_mysql_query, etc.)
        funcs = re.findall(r'\b([a-zA-Z_]\w*)\s*\(', code)
        for func in funcs[:20]:
            tokens.append(f"FUNC_{func.lower()}")

        return ' '.join(tokens)

    def _get_ml_score(self, code: str, vuln_type: VulnType) -> float:
        """Get ML confidence score"""
        if not self.ml_model or not self.ml_vectorizer:
            return 0.5  # Neutral if no model

        try:
            features = self._extract_ml_features(code, vuln_type)
            X = self.ml_vectorizer.transform([features])
            prob = self.ml_model.predict(X)[0]
            return float(prob)
        except:
            return 0.5

    def _calculate_confidence(self, pattern_match: bool, sources: List[str],
                              sanitizers: List[str], ml_score: float,
                              framework: Optional[str], in_auth: bool,
                              is_admin_path: bool = False,
                              taint_info: dict = None) -> float:
        """
        Calculate final confidence from all stages (Multi-Stage Verification)

        Requirements for HIGH confidence:
        - Pattern match + Source found + No sanitizer + ML agrees

        Formula:
        - Base: 0.85 if pattern matched
        - Sources: +0.15 if found, -0.4 if not
        - Sanitizers: -0.6 for first, -0.3 for each additional
        - ML: strong weight (if ML says safe, big reduction)
        - Framework: -0.25 if protected framework
        - Auth/Admin: -0.15 each
        - Taint tracking: +0.1 if confirmed, -0.3 if sanitized
        """
        if not pattern_match:
            return 0.0

        confidence = 0.85

        # Source presence (critical factor)
        if sources:
            confidence += 0.15
        else:
            confidence -= 0.4  # No source = likely FP

        # Sanitizers (major reduction)
        if sanitizers:
            confidence -= 0.6  # First sanitizer
            if len(sanitizers) > 1:
                confidence -= 0.3 * min(len(sanitizers) - 1, 2)

        # Advanced taint tracking results
        if taint_info:
            if taint_info.get('sanitized'):
                confidence -= 0.4  # Sanitized in taint chain
            elif taint_info.get('tainted'):
                confidence += 0.1  # Confirmed taint flow
                # Boost for direct taint (few hops)
                if taint_info.get('hops', 0) <= 2:
                    confidence += 0.05

        # ML score integration (higher weight)
        if self.enable_ml and ml_score > 0:
            ml_weight = 0.6
            # ML strong signal
            if ml_score > 0.8:
                confidence = max(confidence, ml_score * 0.95)
            elif ml_score > 0.6:
                confidence = confidence * (1 - ml_weight) + ml_score * ml_weight
            elif ml_score < 0.3:
                confidence = confidence * 0.4  # ML says safe - big reduction
            elif ml_score < 0.5:
                confidence = confidence * 0.7

        # Framework protection
        if framework in ['laravel', 'symfony', 'wordpress', 'dle']:
            confidence -= 0.25

        # Auth context (admin-only code is lower risk)
        if in_auth:
            confidence -= 0.15

        # Admin path (even lower risk)
        if is_admin_path:
            confidence -= 0.15

        # Multi-stage verification bonus
        # If pattern + source + ML all agree, boost confidence
        stages_agree = 0
        if sources:
            stages_agree += 1
        if self.enable_ml and ml_score > 0.6:
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
        4. ML scoring (adjust confidence)
        5. Multi-stage verification (require agreement)
        6. Final decision (filter low confidence)
        """
        findings = []
        lines = code.split('\n')

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

        # Stage 1: Pattern Matching
        for vuln_type, patterns in self.patterns.items():
            for pattern, base_severity in patterns:
                for match in re.finditer(pattern, code, re.IGNORECASE):
                    line_num = code[:match.start()].count('\n') + 1
                    line_code = lines[line_num - 1].strip() if line_num <= len(lines) else ""

                    # Stage 2: Taint Analysis (basic)
                    sources = self._find_sources(code, line_num)
                    sanitizers = self._find_sanitizers(code, line_num, vuln_type)
                    in_auth = self._check_auth_context(code, line_num)

                    # Stage 2.3: Check for custom sanitizers wrapping the code
                    if custom_sanitizers and self._check_wrapped_in_function(code, line_num, custom_sanitizers):
                        sanitizers.append('custom_sanitizer')

                    # Stage 2.5: Advanced Taint Tracking (variable following)
                    taint_info = self._track_variable_taint(code, line_num, max_depth=7)

                    # Stage 2.6: Safe Context Check
                    if self._check_safe_context(code, line_num, vuln_type):
                        continue

                    # Stage 3: ML Scoring (use local context only)
                    start_line = max(0, line_num - 10)
                    end_line = min(len(lines), line_num + 5)
                    local_context = '\n'.join(lines[start_line:end_line])
                    ml_score = self._get_ml_score(local_context, vuln_type)

                    # Stage 4: Calculate Final Confidence (Multi-Stage)
                    confidence = self._calculate_confidence(
                        pattern_match=True,
                        sources=sources,
                        sanitizers=sanitizers,
                        ml_score=ml_score,
                        framework=framework,
                        in_auth=in_auth,
                        is_admin_path=is_admin_path,
                        taint_info=taint_info
                    )

                    # Stage 4.5: Admin-only code gets severe penalty
                    # Code Injection in admin plugins is usually intentional functionality
                    if is_admin_only:
                        if vuln_type in [VulnType.CODE_INJECTION, VulnType.RCE]:
                            confidence *= 0.3  # 70% reduction - likely plugin functionality
                        elif vuln_type == VulnType.UNSAFE_UPLOAD:
                            confidence *= 0.4  # 60% reduction - admin can upload
                        else:
                            confidence *= 0.6  # 40% reduction for other types

                    # Stage 5: Filter low confidence - very aggressive
                    if confidence < 0.65:
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
                        ml_score=ml_score,
                        source=sources[0] if sources else None,
                        sink=vuln_type.value,
                        sanitizers=sanitizers,
                        confidence=confidence,
                        framework=framework,
                        in_auth_context=in_auth,
                    )
                    findings.append(finding)

        # Deduplicate (same line, same type)
        seen = set()
        unique = []
        for f in findings:
            key = (f.line, f.vuln_type)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

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
    scanner = UnifiedScanner(enable_ml=False)  # ML optional for testing

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
