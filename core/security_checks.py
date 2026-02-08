#!/usr/bin/env python3
"""
APEX Security Checks
Additional security checks for configuration, secrets, and best practices
"""

import re
from typing import List, Dict, Tuple
from dataclasses import dataclass


@dataclass
class SecurityCheck:
    name: str
    pattern: str
    severity: str
    cwe: str
    description: str
    recommendation: str
    confidence: float
    category: str
    false_positive_patterns: List[str] = None

    def __post_init__(self):
        if self.false_positive_patterns is None:
            self.false_positive_patterns = []


SECURITY_CHECKS = [
    # Hardcoded Secrets
    SecurityCheck(
        "HARDCODED_AWS_KEY",
        r'(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        "CRITICAL", "CWE-798",
        "Hardcoded AWS Access Key detected",
        "Use environment variables or secret management service",
        0.95, "secrets"
    ),
    SecurityCheck(
        "HARDCODED_AWS_SECRET",
        r'(?:aws_secret_access_key|aws_secret_key)\s*[=:]\s*[\'"][A-Za-z0-9/+=]{40}[\'"]',
        "CRITICAL", "CWE-798",
        "Hardcoded AWS Secret Key detected",
        "Use environment variables or AWS IAM roles",
        0.95, "secrets"
    ),
    SecurityCheck(
        "HARDCODED_PRIVATE_KEY",
        r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        "CRITICAL", "CWE-798",
        "Private key embedded in code",
        "Store private keys in secure key management system",
        0.99, "secrets"
    ),
    SecurityCheck(
        "HARDCODED_API_KEY",
        r'(?:api[_-]?key|apikey|api_secret|api_token)\s*[=:]\s*[\'"][a-zA-Z0-9_\-]{20,}[\'"]',
        "HIGH", "CWE-798",
        "Hardcoded API key detected",
        "Use environment variables for API keys",
        0.75, "secrets",
        ["example", "test", "xxx", "your", "dummy", "placeholder"]
    ),
    SecurityCheck(
        "HARDCODED_PASSWORD",
        r'(?:password|passwd|pwd|pass)\s*[=:]\s*[\'"][^\'"]{8,}[\'"]',
        "HIGH", "CWE-798",
        "Hardcoded password detected",
        "Use environment variables or secure vault",
        0.7, "secrets",
        ["example", "test", "xxx", "your", "dummy", "placeholder", "changeme", "password"]
    ),
    SecurityCheck(
        "HARDCODED_DB_CREDENTIALS",
        r'(?:mysql_connect|mysqli_connect|pg_connect|new\s+PDO)\s*\([^)]*[\'"][^\'"]+[\'"]\s*,\s*[\'"][^\'"]+[\'"]\s*,\s*[\'"][^\'"]+[\'"]',
        "HIGH", "CWE-798",
        "Hardcoded database credentials",
        "Use environment variables for database credentials",
        0.85, "secrets"
    ),
    SecurityCheck(
        "HARDCODED_JWT_SECRET",
        r'(?:jwt[_-]?secret|secret[_-]?key)\s*[=:]\s*[\'"][a-zA-Z0-9_\-]{20,}[\'"]',
        "CRITICAL", "CWE-798",
        "Hardcoded JWT secret",
        "Use environment variables for JWT secrets",
        0.8, "secrets",
        ["example", "test", "xxx", "your_secret"]
    ),
    SecurityCheck(
        "HARDCODED_OAUTH_SECRET",
        r'(?:client[_-]?secret|oauth[_-]?secret)\s*[=:]\s*[\'"][a-zA-Z0-9_\-]{20,}[\'"]',
        "CRITICAL", "CWE-798",
        "Hardcoded OAuth client secret",
        "Use environment variables for OAuth secrets",
        0.85, "secrets",
        ["example", "test", "xxx"]
    ),
    SecurityCheck(
        "HARDCODED_STRIPE_KEY",
        r'sk_(?:live|test)_[a-zA-Z0-9]{24,}',
        "CRITICAL", "CWE-798",
        "Hardcoded Stripe secret key",
        "Use environment variables for Stripe keys",
        0.95, "secrets"
    ),
    SecurityCheck(
        "HARDCODED_GITHUB_TOKEN",
        r'gh[pousr]_[A-Za-z0-9_]{36,}',
        "CRITICAL", "CWE-798",
        "Hardcoded GitHub token",
        "Use environment variables or GitHub secrets",
        0.95, "secrets"
    ),
    SecurityCheck(
        "HARDCODED_SLACK_TOKEN",
        r'xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}',
        "HIGH", "CWE-798",
        "Hardcoded Slack token",
        "Use environment variables for Slack tokens",
        0.95, "secrets"
    ),

    # Weak Cryptography
    SecurityCheck(
        "WEAK_MD5_HASH",
        r'md5\s*\(',
        "MEDIUM", "CWE-327",
        "MD5 hash function used (cryptographically weak)",
        "Use password_hash() for passwords or hash('sha256',...) for general hashing",
        0.6, "crypto",
        ["file", "checksum", "etag", "cache"]
    ),
    SecurityCheck(
        "WEAK_SHA1_HASH",
        r'sha1\s*\(',
        "MEDIUM", "CWE-327",
        "SHA1 hash function used (cryptographically weak)",
        "Use hash('sha256',...) or stronger algorithms",
        0.5, "crypto",
        ["file", "checksum", "etag"]
    ),
    SecurityCheck(
        "WEAK_RANDOM",
        r'(?:mt_rand|rand|srand|mt_srand)\s*\(',
        "MEDIUM", "CWE-330",
        "Weak random number generator",
        "Use random_bytes() or random_int() for security-sensitive operations",
        0.5, "crypto"
    ),
    SecurityCheck(
        "WEAK_ENCRYPTION_DES",
        r'(?:MCRYPT_DES|des-ecb|des-cbc)',
        "HIGH", "CWE-327",
        "Weak DES encryption algorithm",
        "Use AES-256-GCM or similar strong algorithm",
        0.9, "crypto"
    ),
    SecurityCheck(
        "WEAK_ENCRYPTION_RC4",
        r'(?:MCRYPT_RC4|rc4|arcfour)',
        "HIGH", "CWE-327",
        "Weak RC4 encryption algorithm",
        "Use AES-256-GCM or similar strong algorithm",
        0.9, "crypto"
    ),
    SecurityCheck(
        "WEAK_ENCRYPTION_ECB",
        r'(?:ecb|MCRYPT_MODE_ECB|aes-\d+-ecb)',
        "HIGH", "CWE-327",
        "ECB mode encryption (patterns leak)",
        "Use CBC, GCM, or CTR mode instead",
        0.85, "crypto"
    ),

    # Configuration Issues
    SecurityCheck(
        "DEBUG_ENABLED",
        r'(?:debug|DEBUG|display_errors|error_reporting)\s*[=:]\s*(?:true|TRUE|1|E_ALL|[\'"]on[\'"])',
        "MEDIUM", "CWE-489",
        "Debug mode or error display enabled",
        "Disable debug mode and error display in production",
        0.6, "config"
    ),
    SecurityCheck(
        "REGISTER_GLOBALS",
        r'register_globals\s*=\s*(?:on|On|ON|1|true)',
        "CRITICAL", "CWE-473",
        "register_globals enabled (deprecated and dangerous)",
        "Never enable register_globals",
        0.99, "config"
    ),
    SecurityCheck(
        "ALLOW_URL_INCLUDE",
        r'allow_url_include\s*=\s*(?:on|On|ON|1|true)',
        "HIGH", "CWE-829",
        "allow_url_include enabled (RFI risk)",
        "Disable allow_url_include",
        0.95, "config"
    ),
    SecurityCheck(
        "ALLOW_URL_FOPEN",
        r'allow_url_fopen\s*=\s*(?:on|On|ON|1|true)',
        "MEDIUM", "CWE-829",
        "allow_url_fopen enabled",
        "Consider disabling allow_url_fopen if not needed",
        0.5, "config"
    ),
    SecurityCheck(
        "EXPOSE_PHP",
        r'expose_php\s*=\s*(?:on|On|ON|1|true)',
        "LOW", "CWE-200",
        "PHP version exposed in headers",
        "Set expose_php = Off",
        0.9, "config"
    ),
    SecurityCheck(
        "SESSION_USE_ONLY_COOKIES_OFF",
        r'session\.use_only_cookies\s*=\s*(?:0|off|Off|OFF|false)',
        "HIGH", "CWE-384",
        "Session fixation vulnerability",
        "Set session.use_only_cookies = 1",
        0.9, "config"
    ),
    SecurityCheck(
        "SESSION_COOKIE_HTTPONLY_OFF",
        r'session\.cookie_httponly\s*=\s*(?:0|off|Off|OFF|false)',
        "MEDIUM", "CWE-1004",
        "Session cookie accessible via JavaScript",
        "Set session.cookie_httponly = 1",
        0.85, "config"
    ),
    SecurityCheck(
        "DISABLE_FUNCTIONS_EMPTY",
        r'disable_functions\s*=\s*[\'"]?\s*[\'"]?(?:\r?\n|$)',
        "MEDIUM", "CWE-693",
        "No dangerous functions disabled",
        "Disable dangerous functions like exec, shell_exec, system",
        0.7, "config"
    ),

    # Insecure Practices
    SecurityCheck(
        "EVAL_BASE64",
        r'eval\s*\(\s*base64_decode',
        "CRITICAL", "CWE-94",
        "Obfuscated code execution (common in malware/shells)",
        "Remove obfuscated code execution",
        0.95, "malicious"
    ),
    SecurityCheck(
        "EVAL_GZINFLATE",
        r'eval\s*\(\s*gzinflate',
        "CRITICAL", "CWE-94",
        "Compressed code execution (common in malware)",
        "Remove obfuscated code execution",
        0.95, "malicious"
    ),
    SecurityCheck(
        "WEBSHELL_PATTERN",
        r'(?:\$_(?:GET|POST|REQUEST)\s*\[\s*[\'"][^\'"]+[\'"]\s*\]\s*\(\s*\$_|c99|r57|b374k|wso|alfa)',
        "CRITICAL", "CWE-94",
        "Potential web shell detected",
        "Remove malicious code immediately",
        0.85, "malicious"
    ),
    SecurityCheck(
        "BACKDOOR_PATTERN",
        r'(?:assert\s*\(\s*\$_|create_function\s*\([^)]*\$_|preg_replace\s*\([^)]*\/e[\'"])',
        "CRITICAL", "CWE-94",
        "Potential backdoor detected",
        "Remove suspicious code",
        0.9, "malicious"
    ),
    SecurityCheck(
        "INSECURE_COOKIE",
        r'setcookie\s*\([^)]+\)\s*;(?!.*?(?:secure|httponly))',
        "MEDIUM", "CWE-614",
        "Cookie set without secure/httponly flags",
        "Add secure and httponly flags to cookies",
        0.6, "cookie"
    ),
    SecurityCheck(
        "INSECURE_SESSION_START",
        r'session_start\s*\(\s*\)(?!.*?session_regenerate_id)',
        "LOW", "CWE-384",
        "Session started without regenerating ID",
        "Call session_regenerate_id() after login",
        0.4, "session"
    ),
    SecurityCheck(
        "CSRF_TOKEN_MISSING",
        r'<form[^>]*method=[\'"]?post[\'"]?[^>]*>(?!.*?(?:csrf|token|_token|nonce))',
        "MEDIUM", "CWE-352",
        "Form without CSRF token",
        "Add CSRF token to all forms",
        0.5, "csrf"
    ),
    SecurityCheck(
        "SQL_STRING_CONCAT",
        r'(?:SELECT|INSERT|UPDATE|DELETE|UNION)\s+.*?[\'\"]\s*\.\s*\$(?!this->db->escape)',
        "HIGH", "CWE-89",
        "SQL query with string concatenation",
        "Use prepared statements",
        0.7, "sql"
    ),
    SecurityCheck(
        "EXEC_WITH_SHELL",
        r'exec\s*\(\s*[\'"](?:sh|bash|cmd|powershell)',
        "HIGH", "CWE-78",
        "Direct shell invocation",
        "Avoid direct shell invocation",
        0.8, "command"
    ),
    SecurityCheck(
        "UNSAFE_EXTRACT",
        r'extract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)',
        "CRITICAL", "CWE-915",
        "extract() with user input (variable injection)",
        "Never use extract() with user input",
        0.99, "injection"
    ),
    SecurityCheck(
        "UNSAFE_PARSE_STR",
        r'parse_str\s*\(\s*\$',
        "HIGH", "CWE-915",
        "parse_str() can overwrite variables",
        "Always use second parameter with parse_str()",
        0.8, "injection"
    ),
    SecurityCheck(
        "UNSAFE_PREG_REPLACE",
        r'preg_replace\s*\(\s*[\'"][^\'"]*\/[eE][\'"]',
        "CRITICAL", "CWE-94",
        "preg_replace with /e modifier (code execution)",
        "Use preg_replace_callback() instead",
        0.99, "injection"
    ),
    SecurityCheck(
        "ASSERT_WITH_INPUT",
        r'assert\s*\(\s*\$',
        "CRITICAL", "CWE-94",
        "assert() with variable (code execution)",
        "Never use assert() with user input",
        0.9, "injection"
    ),
    SecurityCheck(
        "UNFILTERED_INCLUDE",
        r'(?:include|require)(?:_once)?\s*\(\s*\$(?!(?:this->|self::))',
        "HIGH", "CWE-98",
        "Dynamic include without filtering",
        "Validate and whitelist included files",
        0.75, "include"
    ),
    SecurityCheck(
        "XXE_VULNERABLE",
        r'(?:simplexml_load|DOMDocument\s*\(\s*\)|XMLReader::open)(?!.*?libxml_disable_entity_loader)',
        "HIGH", "CWE-611",
        "XML parsing without entity loader disabled",
        "Call libxml_disable_entity_loader(true) before parsing XML",
        0.7, "xxe"
    ),
    SecurityCheck(
        "UNSAFE_FILE_UPLOAD",
        r'move_uploaded_file\s*\([^,]+,\s*[^)]*\$_(?:FILES|POST|GET|REQUEST)',
        "HIGH", "CWE-434",
        "File upload with user-controlled path",
        "Validate and sanitize upload paths",
        0.85, "upload"
    ),
    SecurityCheck(
        "UNSAFE_UNSERIALIZE",
        r'unserialize\s*\(\s*(?!\s*[\'"][^$])',
        "HIGH", "CWE-502",
        "unserialize() with potentially untrusted data",
        "Use JSON or add allowed_classes option",
        0.7, "deserialization"
    ),
    SecurityCheck(
        "OPEN_REDIRECT",
        r'header\s*\(\s*[\'"]Location:\s*[\'"]?\s*\.\s*\$',
        "MEDIUM", "CWE-601",
        "Open redirect vulnerability",
        "Validate redirect URLs against whitelist",
        0.75, "redirect"
    ),
    SecurityCheck(
        "INFORMATION_DISCLOSURE_PHPINFO",
        r'phpinfo\s*\(\s*\)',
        "MEDIUM", "CWE-200",
        "phpinfo() exposes sensitive information",
        "Remove phpinfo() from production code",
        0.9, "info_disclosure"
    ),
    SecurityCheck(
        "INFORMATION_DISCLOSURE_VAR_DUMP",
        r'(?:var_dump|print_r|var_export)\s*\(\s*\$',
        "LOW", "CWE-200",
        "Debug output in production",
        "Remove debug output from production code",
        0.5, "info_disclosure"
    ),
    SecurityCheck(
        "HARDCODED_IP",
        r'(?:192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})',
        "LOW", "CWE-200",
        "Hardcoded internal IP address",
        "Use configuration for IP addresses",
        0.5, "config"
    ),
    SecurityCheck(
        "CORS_WILDCARD",
        r'Access-Control-Allow-Origin:\s*\*',
        "MEDIUM", "CWE-346",
        "CORS wildcard allows any origin",
        "Specify allowed origins explicitly",
        0.7, "cors"
    ),
    SecurityCheck(
        "DIRECT_SUPERGLOBAL_OUTPUT",
        r'(?:echo|print)\s+\$_(?:GET|POST|REQUEST|COOKIE)\s*\[',
        "HIGH", "CWE-79",
        "Direct output of user input (XSS)",
        "Sanitize output with htmlspecialchars()",
        0.9, "xss"
    ),
    SecurityCheck(
        "UNSAFE_HEADER",
        r'header\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)',
        "HIGH", "CWE-113",
        "User input in HTTP header",
        "Sanitize header values",
        0.85, "header"
    ),
    SecurityCheck(
        "TYPE_JUGGLING_COMPARISON",
        r'(?:\$[a-zA-Z_]\w*\s*==\s*[\'"]|[\'"]\s*==\s*\$)',
        "LOW", "CWE-843",
        "Loose comparison may cause type juggling",
        "Use strict comparison (===)",
        0.4, "comparison"
    ),
    SecurityCheck(
        "DANGEROUS_FUNCTION_ENABLED",
        r'(?:passthru|shell_exec|exec|system|popen|proc_open|pcntl_exec|eval|assert|create_function)\s*\(',
        "MEDIUM", "CWE-78",
        "Potentially dangerous function used",
        "Consider if these functions are necessary",
        0.3, "dangerous_func"
    ),

    # ============================================================
    # Additional Security Checks - Type Juggling
    # ============================================================
    SecurityCheck(
        "TYPE_JUGGLING_AUTH_BYPASS",
        pattern=r'(?:password|token|hash|secret|key|api_key)\s*==\s*(?:\$|[\'"0])',
        severity="HIGH",
        cwe="CWE-843",
        description="Loose comparison in auth context (type juggling bypass)",
        recommendation="Use strict comparison (===) or hash_equals()",
        confidence=0.85,
        category="type_juggling"
    ),
    SecurityCheck(
        "STRCMP_ARRAY_BYPASS",
        pattern=r'strcmp\s*\([^)]+\)\s*==\s*0(?!\s*===)',
        severity="MEDIUM",
        cwe="CWE-843",
        description="strcmp returns NULL on array input (bypass)",
        recommendation="Use === 0 or hash_equals() for comparison",
        confidence=0.8,
        category="type_juggling"
    ),
    SecurityCheck(
        "MAGIC_HASH_VULNERABLE",
        pattern=r'md5\s*\([^)]+\)\s*==\s*[\'"]0e\d',
        severity="HIGH",
        cwe="CWE-843",
        description="Magic hash comparison vulnerability",
        recommendation="Use hash_equals() for hash comparison",
        confidence=0.9,
        category="type_juggling"
    ),

    # ============================================================
    # Race Condition Checks
    # ============================================================
    SecurityCheck(
        "RACE_CONDITION_FILE",
        pattern=r'if\s*\(\s*(?:file_exists|is_file)\s*\([^)]+\)\s*\)[^{]*\{[^}]*(?:unlink|file_put_contents|fopen)',
        severity="MEDIUM",
        cwe="CWE-367",
        description="Time-of-check-time-of-use (TOCTOU) race condition",
        recommendation="Use atomic file operations or locking",
        confidence=0.6,
        category="race_condition"
    ),
    SecurityCheck(
        "RACE_CONDITION_MKDIR",
        pattern=r'if\s*\(\s*!is_dir\s*\([^)]+\)\s*\)[^{]*\{[^}]*mkdir',
        severity="LOW",
        cwe="CWE-367",
        description="TOCTOU in directory creation",
        recommendation="Use mkdir with error handling instead",
        confidence=0.5,
        category="race_condition"
    ),

    # ============================================================
    # File Upload Security
    # ============================================================
    SecurityCheck(
        "UPLOAD_MIME_CLIENT",
        pattern=r'\$_FILES\s*\[[^\]]+\]\s*\[[\'"]type[\'"]\]',
        severity="HIGH",
        cwe="CWE-434",
        description="Relying on client-provided MIME type",
        recommendation="Use finfo_file() or mime_content_type() for server-side validation",
        confidence=0.8,
        category="upload",
        false_positive_patterns=["finfo", "getimagesize", "mime_content_type"]
    ),
    SecurityCheck(
        "UPLOAD_EXTENSION_ONLY",
        pattern=r'pathinfo\s*\([^)]+PATHINFO_EXTENSION[^)]*\)(?!.*(?:finfo|getimagesize|mime_content_type))',
        severity="MEDIUM",
        cwe="CWE-434",
        description="File validation by extension only",
        recommendation="Also validate file content with finfo_file()",
        confidence=0.6,
        category="upload"
    ),
    SecurityCheck(
        "UPLOAD_DANGEROUS_EXT",
        pattern=r'(?:\.php|\.phtml|\.phar|\.htaccess)[\'"]?\s*(?:\)|,|\])',
        severity="HIGH",
        cwe="CWE-434",
        description="Dangerous file extension in upload handling",
        recommendation="Block dangerous extensions and use content-type validation",
        confidence=0.7,
        category="upload"
    ),

    # ============================================================
    # Session Security
    # ============================================================
    SecurityCheck(
        "SESSION_FIXATION_ID",
        pattern=r'session_id\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)',
        severity="CRITICAL",
        cwe="CWE-384",
        description="Session ID from user input (session fixation)",
        recommendation="Never accept session ID from user input",
        confidence=0.95,
        category="session"
    ),
    SecurityCheck(
        "SESSION_NO_HTTPONLY",
        pattern=r'session\.cookie_httponly\s*=\s*(?:0|false|off)',
        severity="MEDIUM",
        cwe="CWE-1004",
        description="Session cookie without HttpOnly flag",
        recommendation="Set session.cookie_httponly = 1",
        confidence=0.9,
        category="session"
    ),
    SecurityCheck(
        "SESSION_NO_SECURE",
        pattern=r'session\.cookie_secure\s*=\s*(?:0|false|off)',
        severity="MEDIUM",
        cwe="CWE-614",
        description="Session cookie without Secure flag",
        recommendation="Set session.cookie_secure = 1 for HTTPS sites",
        confidence=0.7,
        category="session"
    ),

    # ============================================================
    # Object Injection
    # ============================================================
    SecurityCheck(
        "UNSAFE_WAKEUP",
        pattern=r'function\s+__wakeup\s*\(\s*\)',
        severity="LOW",
        cwe="CWE-502",
        description="__wakeup magic method (object injection target)",
        recommendation="Validate object state in __wakeup if using unserialize",
        confidence=0.4,
        category="deserialization"
    ),
    SecurityCheck(
        "UNSAFE_DESTRUCT",
        pattern=r'function\s+__destruct\s*\(\s*\)[^{]*\{[^}]*(?:unlink|exec|system|eval|include|file_)',
        severity="MEDIUM",
        cwe="CWE-502",
        description="Dangerous operation in __destruct (object injection gadget)",
        recommendation="Avoid file/command operations in destructors",
        confidence=0.6,
        category="deserialization"
    ),
    SecurityCheck(
        "PHAR_WRAPPER",
        pattern=r'phar://.*\$',
        severity="CRITICAL",
        cwe="CWE-502",
        description="PHAR wrapper with user input (deserialization attack)",
        recommendation="Never use phar:// with user-controlled paths",
        confidence=0.95,
        category="deserialization"
    ),

    # ============================================================
    # Cryptographic Issues
    # ============================================================
    SecurityCheck(
        "PREDICTABLE_TOKEN",
        pattern=r'(?:token|secret|key|csrf|nonce)\s*=\s*(?:time\(|microtime\(|uniqid\(|md5\(time)',
        severity="HIGH",
        cwe="CWE-330",
        description="Predictable token generation",
        recommendation="Use random_bytes() or random_int() for tokens",
        confidence=0.9,
        category="crypto"
    ),
    SecurityCheck(
        "WEAK_IV",
        pattern=r'openssl_encrypt\s*\([^)]*,\s*[\'"][^\'"]*[\'"],\s*[^,]+,\s*[^,]+,\s*[\'"][^\'"]*[\'"]',
        severity="HIGH",
        cwe="CWE-329",
        description="Hardcoded or empty IV in encryption",
        recommendation="Use random_bytes() for IV generation",
        confidence=0.7,
        category="crypto"
    ),
    SecurityCheck(
        "CLEARTEXT_PASSWORD_LOG",
        pattern=r'(?:error_log|syslog|fwrite|file_put_contents).*?(?:password|passwd|pwd|secret)',
        severity="HIGH",
        cwe="CWE-312",
        description="Possible password in logs",
        recommendation="Never log passwords or sensitive data",
        confidence=0.6,
        category="info_disclosure",
        false_positive_patterns=["password_hash", "password_verify", "*****"]
    ),

    # ============================================================
    # Callback Injection
    # ============================================================
    SecurityCheck(
        "CALLBACK_INJECTION_MAP",
        pattern=r'array_map\s*\(\s*\$(?:_GET|_POST|_REQUEST)',
        severity="CRITICAL",
        cwe="CWE-94",
        description="User-controlled callback in array_map",
        recommendation="Whitelist allowed callbacks",
        confidence=0.95,
        category="injection"
    ),
    SecurityCheck(
        "CALLBACK_INJECTION_FILTER",
        pattern=r'array_filter\s*\([^,]+,\s*\$(?:_GET|_POST|_REQUEST)',
        severity="CRITICAL",
        cwe="CWE-94",
        description="User-controlled callback in array_filter",
        recommendation="Whitelist allowed callbacks",
        confidence=0.95,
        category="injection"
    ),
    SecurityCheck(
        "CALLBACK_INJECTION_SORT",
        pattern=r'(?:usort|uasort|uksort|array_walk)\s*\([^,]+,\s*\$(?:_GET|_POST|_REQUEST)',
        severity="CRITICAL",
        cwe="CWE-94",
        description="User-controlled callback in sort/walk function",
        recommendation="Whitelist allowed callbacks",
        confidence=0.95,
        category="injection"
    ),
    SecurityCheck(
        "VARIABLE_FUNCTION_CALL",
        pattern=r'\$(?:_GET|_POST|_REQUEST)\s*\[[^\]]+\]\s*\(',
        severity="CRITICAL",
        cwe="CWE-94",
        description="Variable function call with user input",
        recommendation="Whitelist allowed function names",
        confidence=0.98,
        category="injection"
    ),

    # ============================================================
    # Object Creation
    # ============================================================
    SecurityCheck(
        "UNSAFE_NEW_CLASS",
        pattern=r'new\s+\$(?:_GET|_POST|_REQUEST)',
        severity="CRITICAL",
        cwe="CWE-470",
        description="Instantiation of user-controlled class",
        recommendation="Whitelist allowed class names",
        confidence=0.95,
        category="injection"
    ),
    SecurityCheck(
        "UNSAFE_STATIC_METHOD",
        pattern=r'\$(?:_GET|_POST|_REQUEST)\s*\[[^\]]+\]\s*::\s*\w+',
        severity="CRITICAL",
        cwe="CWE-470",
        description="Static method call on user-controlled class",
        recommendation="Whitelist allowed class names",
        confidence=0.95,
        category="injection"
    ),

    # ============================================================
    # Template Injection
    # ============================================================
    SecurityCheck(
        "SSTI_TWIG_RENDER",
        pattern=r'->render\s*\(\s*\$(?:_GET|_POST|_REQUEST)',
        severity="HIGH",
        cwe="CWE-1336",
        description="Template path from user input (SSTI)",
        recommendation="Whitelist allowed templates",
        confidence=0.8,
        category="template"
    ),
    SecurityCheck(
        "SSTI_BLADE_COMPILE",
        pattern=r'Blade::compileString\s*\(\s*\$',
        severity="CRITICAL",
        cwe="CWE-1336",
        description="Blade template compilation with user input",
        recommendation="Never compile user-provided template strings",
        confidence=0.95,
        category="template"
    ),
    SecurityCheck(
        "SSTI_SMARTY_FETCH",
        pattern=r'->fetch\s*\(\s*[\'"]string:\s*[\'"]?\s*\.\s*\$',
        severity="CRITICAL",
        cwe="CWE-1336",
        description="Smarty template from user input",
        recommendation="Never use user input in template strings",
        confidence=0.9,
        category="template"
    ),

    # ============================================================
    # Business Logic
    # ============================================================
    SecurityCheck(
        "PRICE_FROM_INPUT",
        pattern=r'(?:price|amount|total|discount)\s*=\s*\$(?:_GET|_POST|_REQUEST)',
        severity="HIGH",
        cwe="CWE-639",
        description="Price/amount from user input",
        recommendation="Never trust client-provided prices",
        confidence=0.85,
        category="business_logic"
    ),
    SecurityCheck(
        "ROLE_FROM_INPUT",
        pattern=r'(?:role|is_admin|permission|privilege)\s*=\s*\$(?:_GET|_POST|_REQUEST)',
        severity="CRITICAL",
        cwe="CWE-266",
        description="Role/permission from user input",
        recommendation="Never set roles based on user input",
        confidence=0.95,
        category="business_logic"
    ),

    # ============================================================
    # NoSQL Injection
    # ============================================================
    SecurityCheck(
        "NOSQL_MONGO_INJECTION",
        pattern=r'(?:find|findOne|update|delete)One?\s*\(\s*(?:json_decode\s*\()?\s*\$(?:_GET|_POST|_REQUEST)',
        severity="HIGH",
        cwe="CWE-943",
        description="MongoDB query with user input",
        recommendation="Sanitize input and use parameterized queries",
        confidence=0.85,
        category="nosql"
    ),
    SecurityCheck(
        "NOSQL_OPERATOR_INJECTION",
        pattern=r'\$(?:gt|gte|lt|lte|ne|in|nin|regex|where).*\$(?:_GET|_POST|_REQUEST)',
        severity="HIGH",
        cwe="CWE-943",
        description="MongoDB operator injection",
        recommendation="Validate and sanitize query operators",
        confidence=0.8,
        category="nosql"
    ),

    # ============================================================
    # ReDoS
    # ============================================================
    SecurityCheck(
        "REGEX_USER_PATTERN",
        pattern=r'preg_(?:match|replace)\s*\(\s*\$(?:_GET|_POST|_REQUEST)',
        severity="HIGH",
        cwe="CWE-1333",
        description="User-controlled regex pattern",
        recommendation="Validate or whitelist regex patterns",
        confidence=0.9,
        category="regex"
    ),
    SecurityCheck(
        "REGEX_NESTED_QUANTIFIER",
        pattern=r'preg_(?:match|replace)\s*\(\s*[\'"][^\'"]*\([^\)]*(?:\+|\*)\)[^\)]*(?:\+|\*)',
        severity="MEDIUM",
        cwe="CWE-1333",
        description="Nested quantifiers in regex (ReDoS risk)",
        recommendation="Simplify regex or add timeout",
        confidence=0.6,
        category="regex"
    ),
]


class SecurityChecker:
    """Run security checks on PHP code"""

    def __init__(self):
        self.checks = SECURITY_CHECKS
        self._compiled = {}
        for check in self.checks:
            try:
                self._compiled[check.name] = re.compile(check.pattern, re.IGNORECASE | re.MULTILINE)
            except re.error:
                pass

    def check_code(self, code: str, file_path: str = "") -> List[Dict]:
        """Run all security checks on code"""
        findings = []
        lines = code.split('\n')

        for check in self.checks:
            if check.name not in self._compiled:
                continue

            compiled = self._compiled[check.name]

            for match in compiled.finditer(code):
                start = match.start()
                line_no = code[:start].count('\n') + 1

                # Check for false positive patterns
                is_fp = False
                for fp_pattern in check.false_positive_patterns:
                    context_start = max(0, start - 100)
                    context_end = min(len(code), match.end() + 50)
                    context = code[context_start:context_end].lower()

                    if fp_pattern.lower() in context:
                        is_fp = True
                        break

                if not is_fp:
                    line_content = lines[line_no - 1] if line_no <= len(lines) else ""

                    findings.append({
                        'type': check.name,
                        'severity': check.severity,
                        'cwe': check.cwe,
                        'category': check.category,
                        'file': file_path,
                        'line': line_no,
                        'code': line_content.strip()[:100],
                        'confidence': check.confidence,
                        'description': check.description,
                        'recommendation': check.recommendation,
                        'match': match.group()[:80]
                    })

        return self._deduplicate(findings)

    def check_file(self, file_path: str) -> List[Dict]:
        """Check a file for security issues"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            return self.check_code(code, file_path)
        except Exception:
            return []

    def _deduplicate(self, findings: List[Dict]) -> List[Dict]:
        """Remove duplicate findings"""
        seen = set()
        unique = []

        for f in findings:
            key = (f['file'], f['line'], f['type'])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique


def run_security_checks(code: str, file_path: str = "") -> List[Dict]:
    """Convenience function"""
    checker = SecurityChecker()
    return checker.check_code(code, file_path)
