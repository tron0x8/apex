#!/usr/bin/env python3
"""
APEX Enhanced Scanner v2.1
Improved detection rate + Reduced false positives

Key improvements:
1. Context-aware taint tracking
2. Sanitizer chain validation
3. Framework detection
4. Confidence scoring based on multiple factors
"""

import re
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum


class VulnType(Enum):
    SQL_INJECTION = "sqli"
    XSS = "xss"
    COMMAND_INJECTION = "cmdi"
    FILE_INCLUSION = "lfi"
    FILE_WRITE = "file_write"
    FILE_READ = "file_read"
    SSRF = "ssrf"
    DESERIALIZATION = "deser"
    CODE_INJECTION = "codei"
    PATH_TRAVERSAL = "path"
    AUTH_BYPASS = "auth"


@dataclass
class DetectionResult:
    """Single vulnerability detection result"""
    vuln_type: VulnType
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    line: int
    code: str
    confidence: float  # 0.0 - 1.0
    source: Optional[str] = None
    sink: Optional[str] = None
    sanitizer: Optional[str] = None
    is_sanitized: bool = False
    context: Dict = field(default_factory=dict)


class EnhancedScanner:
    """
    Enhanced PHP vulnerability scanner with improved accuracy
    """

    def __init__(self):
        self._init_sources()
        self._init_sinks()
        self._init_sanitizers()
        self._init_frameworks()

    def _init_sources(self):
        """User input sources - where tainted data enters"""
        self.sources = {
            # Direct superglobals
            'GET': (r'\$_GET\s*\[\s*[\'"](\w+)[\'"]\s*\]', 1.0),
            'POST': (r'\$_POST\s*\[\s*[\'"](\w+)[\'"]\s*\]', 1.0),
            'REQUEST': (r'\$_REQUEST\s*\[\s*[\'"](\w+)[\'"]\s*\]', 1.0),
            'COOKIE': (r'\$_COOKIE\s*\[\s*[\'"](\w+)[\'"]\s*\]', 0.9),
            'FILES': (r'\$_FILES\s*\[\s*[\'"](\w+)[\'"]\s*\]', 0.9),
            'SERVER_URI': (r'\$_SERVER\s*\[\s*[\'"]REQUEST_URI[\'"]\s*\]', 0.8),
            'SERVER_QUERY': (r'\$_SERVER\s*\[\s*[\'"]QUERY_STRING[\'"]\s*\]', 0.8),
            'PHP_INPUT': (r'file_get_contents\s*\(\s*[\'"]php://input[\'"]\s*\)', 1.0),
            # Decoded input (higher risk)
            'BASE64_DECODE': (r'base64_decode\s*\(\s*\$_(GET|POST|REQUEST)', 1.0),
            'JSON_DECODE': (r'json_decode\s*\(\s*\$_(GET|POST|REQUEST)', 0.9),
            'URLDECODE': (r'urldecode\s*\(\s*\$_(GET|POST|REQUEST)', 0.9),
        }

    def _init_sinks(self):
        """Dangerous functions - where vulnerabilities occur"""
        self.sinks = {
            # SQL - CRITICAL
            VulnType.SQL_INJECTION: [
                (r'\bmysql_query\s*\(', 'CRITICAL', 'mysql_query'),
                (r'\bmysqli_query\s*\(', 'CRITICAL', 'mysqli_query'),
                (r'\$\w+->query\s*\(', 'CRITICAL', 'PDO/mysqli query'),
                (r'\$\w+->exec\s*\(', 'CRITICAL', 'PDO exec'),
                (r'\bpg_query\s*\(', 'CRITICAL', 'pg_query'),
                (r'\bsqlite_query\s*\(', 'CRITICAL', 'sqlite_query'),
                (r'\bmssql_query\s*\(', 'CRITICAL', 'mssql_query'),
            ],
            # Command - CRITICAL
            VulnType.COMMAND_INJECTION: [
                (r'\bexec\s*\(', 'CRITICAL', 'exec'),
                (r'\bsystem\s*\(', 'CRITICAL', 'system'),
                (r'\bpassthru\s*\(', 'CRITICAL', 'passthru'),
                (r'\bshell_exec\s*\(', 'CRITICAL', 'shell_exec'),
                (r'\bpopen\s*\(', 'CRITICAL', 'popen'),
                (r'\bproc_open\s*\(', 'CRITICAL', 'proc_open'),
                (r'`[^`]+\$', 'CRITICAL', 'backtick'),
            ],
            # Code Injection - CRITICAL
            VulnType.CODE_INJECTION: [
                (r'\beval\s*\(', 'CRITICAL', 'eval'),
                (r'\bassert\s*\(', 'HIGH', 'assert'),
                (r'\bcreate_function\s*\(', 'CRITICAL', 'create_function'),
                (r'preg_replace\s*\([^)]*[\'"][^\'"]*/e', 'CRITICAL', 'preg_replace /e'),
            ],
            # File Inclusion - CRITICAL
            VulnType.FILE_INCLUSION: [
                (r'\binclude\s*\(?\s*\$', 'CRITICAL', 'include'),
                (r'\binclude_once\s*\(?\s*\$', 'CRITICAL', 'include_once'),
                (r'\brequire\s*\(?\s*\$', 'CRITICAL', 'require'),
                (r'\brequire_once\s*\(?\s*\$', 'CRITICAL', 'require_once'),
            ],
            # File Write - HIGH
            VulnType.FILE_WRITE: [
                (r'\bfile_put_contents\s*\(', 'HIGH', 'file_put_contents'),
                (r'\bfwrite\s*\(', 'HIGH', 'fwrite'),
                (r'\bfputs\s*\(', 'HIGH', 'fputs'),
                (r'\bmove_uploaded_file\s*\(', 'HIGH', 'move_uploaded_file'),
                (r'\bcopy\s*\(', 'MEDIUM', 'copy'),
            ],
            # File Read - HIGH
            VulnType.FILE_READ: [
                (r'\bfile_get_contents\s*\(\s*\$', 'HIGH', 'file_get_contents'),
                (r'\bfopen\s*\(\s*\$', 'HIGH', 'fopen'),
                (r'\breadfile\s*\(\s*\$', 'HIGH', 'readfile'),
                (r'\bfile\s*\(\s*\$', 'HIGH', 'file'),
                (r'\bshow_source\s*\(', 'HIGH', 'show_source'),
                (r'\bhighlight_file\s*\(', 'HIGH', 'highlight_file'),
            ],
            # XSS - MEDIUM/HIGH
            VulnType.XSS: [
                (r'\becho\s+[^;]*\$_(GET|POST|REQUEST|COOKIE)', 'HIGH', 'echo direct'),
                (r'\bprint\s+[^;]*\$_(GET|POST|REQUEST|COOKIE)', 'HIGH', 'print direct'),
                (r'\becho\s+[^;]*\$\w+', 'MEDIUM', 'echo variable'),
            ],
            # SSRF - HIGH
            VulnType.SSRF: [
                (r'\bfile_get_contents\s*\(\s*\$', 'HIGH', 'file_get_contents'),
                (r'curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$', 'HIGH', 'curl'),
                (r'\bfopen\s*\(\s*\$[^,]+,\s*[\'"]r', 'MEDIUM', 'fopen read'),
            ],
            # Deserialization - CRITICAL
            VulnType.DESERIALIZATION: [
                (r'\bunserialize\s*\(\s*\$', 'CRITICAL', 'unserialize'),
                (r'\bunserialize\s*\(\s*base64_decode', 'CRITICAL', 'unserialize base64'),
            ],
            # Path Traversal - HIGH
            VulnType.PATH_TRAVERSAL: [
                (r'(?:file_get_contents|fopen|include|require)\s*\([^)]*\.\./', 'HIGH', 'path traversal'),
            ],
        }

    def _init_sanitizers(self):
        """Sanitization functions and what they protect against"""
        self.sanitizers = {
            # SQL sanitizers
            'mysqli_real_escape_string': {VulnType.SQL_INJECTION},
            'mysql_real_escape_string': {VulnType.SQL_INJECTION},
            'addslashes': {VulnType.SQL_INJECTION},  # Weak but counts
            'pg_escape_string': {VulnType.SQL_INJECTION},
            'sqlite_escape_string': {VulnType.SQL_INJECTION},
            'PDO::quote': {VulnType.SQL_INJECTION},
            'safesql': {VulnType.SQL_INJECTION},
            'escape_string': {VulnType.SQL_INJECTION},
            'real_escape_string': {VulnType.SQL_INJECTION},

            # Type casting (strong - multiple protections)
            'intval': {VulnType.SQL_INJECTION, VulnType.XSS, VulnType.COMMAND_INJECTION,
                      VulnType.FILE_INCLUSION, VulnType.PATH_TRAVERSAL},
            '(int)': {VulnType.SQL_INJECTION, VulnType.XSS, VulnType.COMMAND_INJECTION,
                     VulnType.FILE_INCLUSION, VulnType.PATH_TRAVERSAL},
            'floatval': {VulnType.SQL_INJECTION, VulnType.XSS},
            '(float)': {VulnType.SQL_INJECTION, VulnType.XSS},
            'abs': {VulnType.SQL_INJECTION},

            # XSS sanitizers
            'htmlspecialchars': {VulnType.XSS},
            'htmlentities': {VulnType.XSS},
            'strip_tags': {VulnType.XSS},
            'filter_var': {VulnType.XSS, VulnType.SQL_INJECTION},  # Depends on filter

            # Command sanitizers
            'escapeshellarg': {VulnType.COMMAND_INJECTION},
            'escapeshellcmd': {VulnType.COMMAND_INJECTION},

            # Path sanitizers
            'basename': {VulnType.PATH_TRAVERSAL, VulnType.FILE_INCLUSION},
            'realpath': {VulnType.PATH_TRAVERSAL, VulnType.FILE_INCLUSION},

            # Validation (indirect protection)
            'is_numeric': {VulnType.SQL_INJECTION, VulnType.COMMAND_INJECTION},
            'ctype_digit': {VulnType.SQL_INJECTION, VulnType.COMMAND_INJECTION},
            'ctype_alnum': {VulnType.SQL_INJECTION, VulnType.XSS, VulnType.COMMAND_INJECTION},
            'preg_match': {VulnType.SQL_INJECTION, VulnType.XSS, VulnType.COMMAND_INJECTION},  # If whitelist
            'in_array': {VulnType.FILE_INCLUSION, VulnType.COMMAND_INJECTION,
                        VulnType.PATH_TRAVERSAL, VulnType.SQL_INJECTION},  # Whitelist check

            # Prepared statements (complete SQL protection)
            'prepare': {VulnType.SQL_INJECTION},
            'bindParam': {VulnType.SQL_INJECTION},
            'bindValue': {VulnType.SQL_INJECTION},
            'execute': {VulnType.SQL_INJECTION},  # With prepare
        }

        # Patterns to detect sanitizer usage
        self.sanitizer_patterns = {
            'intval': r'intval\s*\(\s*\$',
            '(int)': r'\(int\)\s*\$',
            'floatval': r'floatval\s*\(\s*\$',
            '(float)': r'\(float\)\s*\$',
            'mysqli_real_escape_string': r'mysqli_real_escape_string\s*\([^,]+,\s*\$',
            'mysql_real_escape_string': r'mysql_real_escape_string\s*\(\s*\$',
            'addslashes': r'addslashes\s*\(\s*\$',
            'htmlspecialchars': r'htmlspecialchars\s*\(\s*\$',
            'htmlentities': r'htmlentities\s*\(\s*\$',
            'strip_tags': r'strip_tags\s*\(\s*\$',
            'escapeshellarg': r'escapeshellarg\s*\(\s*\$',
            'escapeshellcmd': r'escapeshellcmd\s*\(\s*\$',
            'basename': r'basename\s*\(\s*\$',
            'realpath': r'realpath\s*\(\s*\$',
            'is_numeric': r'is_numeric\s*\(\s*\$',
            'ctype_digit': r'ctype_digit\s*\(\s*\$',
            'prepare': r'->prepare\s*\(',
            'safesql': r'safesql\s*\(\s*\$',
            'escape_string': r'escape_string\s*\(\s*\$',
            'real_escape_string': r'->real_escape_string\s*\(\s*\$',
            'in_array': r'in_array\s*\(\s*\$',
            'preg_match': r'preg_match\s*\(\s*[\'"][/^]',
        }

    def _init_frameworks(self):
        """Framework detection patterns - frameworks often have built-in protection"""
        self.frameworks = {
            'laravel': [
                r'use\s+Illuminate\\',
                r'Route::(get|post|put|delete)',
                r'\$request->input\(',
                r'->where\s*\(\s*[\'"][^\'"]+[\'"]\s*,',  # Eloquent
            ],
            'symfony': [
                r'use\s+Symfony\\',
                r'\$this->getDoctrine\(',
                r'->setParameter\(',
            ],
            'wordpress': [
                r'\$wpdb->prepare\(',
                r'esc_html\(',
                r'esc_attr\(',
                r'wp_kses\(',
            ],
            'codeigniter': [
                r'->escape\(',
                r'\$this->db->query\(',
                r'xss_clean\(',
            ],
            'yii': [
                r'Yii::\$app',
                r'->createCommand\(',
                r'Html::encode\(',
            ],
        }

    def _find_sources_in_line(self, line: str, line_num: int) -> List[Tuple[str, str, float]]:
        """Find taint sources in a line"""
        sources = []
        for name, (pattern, confidence) in self.sources.items():
            if re.search(pattern, line, re.IGNORECASE):
                match = re.search(pattern, line, re.IGNORECASE)
                sources.append((name, match.group(0), confidence))
        return sources

    def _find_sanitizers_in_context(self, code: str, line_num: int,
                                     vuln_type: VulnType) -> List[str]:
        """Find sanitizers that protect against a specific vulnerability type"""
        found = []
        lines = code.split('\n')

        # Check lines before the vulnerable line
        context_start = max(0, line_num - 20)
        context = '\n'.join(lines[context_start:line_num])

        for san_name, san_types in self.sanitizers.items():
            if vuln_type in san_types:
                pattern = self.sanitizer_patterns.get(san_name)
                if pattern and re.search(pattern, context, re.IGNORECASE):
                    found.append(san_name)

        return found

    def _detect_framework(self, code: str) -> Optional[str]:
        """Detect if code uses a known framework"""
        for fw_name, patterns in self.frameworks.items():
            for pattern in patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    return fw_name
        return None

    def _check_auth_context(self, code: str, line_num: int) -> bool:
        """Check if line is in authenticated context"""
        lines = code.split('\n')
        context_start = max(0, line_num - 50)
        context = '\n'.join(lines[context_start:line_num])

        auth_patterns = [
            r'if\s*\(\s*\$.*(?:logged|auth|admin|session)',
            r'if\s*\(\s*isset\s*\(\s*\$_SESSION',
            r'->isAdmin\(',
            r'->isAuthenticated\(',
            r'user_group.*!=.*1',
            r'member_id\[.*user_group',
        ]

        for pattern in auth_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        return False

    def _calculate_confidence(self, vuln_type: VulnType, base_confidence: float,
                              has_source: bool, sanitizers: List[str],
                              framework: Optional[str], in_auth: bool) -> float:
        """Calculate final confidence score"""
        confidence = base_confidence

        # Source presence
        if not has_source:
            confidence *= 0.5  # Reduce if no direct source found

        # Sanitizers reduce confidence
        if sanitizers:
            confidence *= 0.3  # Strong reduction with sanitizers
            if len(sanitizers) > 1:
                confidence *= 0.5  # Even more with multiple

        # Framework reduces confidence
        if framework:
            if framework in ['laravel', 'symfony']:
                confidence *= 0.4  # These have good protection
            else:
                confidence *= 0.7

        # Auth context slightly reduces risk
        if in_auth:
            confidence *= 0.8

        return min(max(confidence, 0.0), 1.0)

    def scan(self, code: str, filepath: str = "") -> List[DetectionResult]:
        """
        Scan code for vulnerabilities with enhanced detection
        """
        results = []
        lines = code.split('\n')

        # Detect framework
        framework = self._detect_framework(code)

        # Scan each line
        for line_num, line in enumerate(lines, 1):
            # Find sources in this line
            sources = self._find_sources_in_line(line, line_num)

            # Check each sink type
            for vuln_type, sink_patterns in self.sinks.items():
                for pattern, severity, sink_name in sink_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Found a potential sink!

                        # Check for sanitizers
                        sanitizers = self._find_sanitizers_in_context(
                            code, line_num, vuln_type
                        )

                        # Check if in authenticated context
                        in_auth = self._check_auth_context(code, line_num)

                        # Check if source is present
                        has_source = bool(sources) or bool(
                            re.search(r'\$_(GET|POST|REQUEST|COOKIE|FILES)',
                                     '\n'.join(lines[max(0,line_num-10):line_num]))
                        )

                        # Calculate confidence
                        base_confidence = 0.9 if sources else 0.6
                        confidence = self._calculate_confidence(
                            vuln_type, base_confidence, has_source,
                            sanitizers, framework, in_auth
                        )

                        # Skip very low confidence
                        if confidence < 0.2:
                            continue

                        # Adjust severity based on confidence
                        if confidence < 0.4:
                            final_severity = "LOW"
                        elif confidence < 0.6:
                            final_severity = "MEDIUM"
                        elif confidence < 0.8:
                            final_severity = "HIGH"
                        else:
                            final_severity = severity

                        result = DetectionResult(
                            vuln_type=vuln_type,
                            severity=final_severity,
                            line=line_num,
                            code=line.strip()[:100],
                            confidence=confidence,
                            source=sources[0][0] if sources else None,
                            sink=sink_name,
                            sanitizer=', '.join(sanitizers) if sanitizers else None,
                            is_sanitized=bool(sanitizers),
                            context={
                                'framework': framework,
                                'in_auth': in_auth,
                                'filepath': filepath,
                            }
                        )
                        results.append(result)

        return results

    def scan_file(self, filepath: str) -> List[DetectionResult]:
        """Scan a single file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            return self.scan(code, filepath)
        except Exception as e:
            return []


def test_scanner():
    """Test the enhanced scanner"""
    scanner = EnhancedScanner()

    test_cases = [
        # Should detect - VULNERABLE
        ("""
$id = $_GET['id'];
$result = mysql_query("SELECT * FROM users WHERE id = '$id'");
""", "SQL Injection - Direct", True),

        # Should NOT detect (sanitized)
        ("""
$id = intval($_GET['id']);
$result = mysql_query("SELECT * FROM users WHERE id = '$id'");
""", "SQL Injection - Sanitized with intval", False),

        # Should NOT detect (prepared statement)
        ("""
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);
""", "SQL Injection - Prepared statement", False),

        # Should detect - Command Injection
        ("""
$cmd = $_POST['cmd'];
system($cmd);
""", "Command Injection - Direct", True),

        # Should NOT detect - Command sanitized
        ("""
$file = escapeshellarg($_GET['file']);
system("cat " . $file);
""", "Command Injection - Escaped", False),

        # Should detect - File Inclusion
        ("""
$page = $_GET['page'];
include($page . '.php');
""", "File Inclusion - Direct", True),

        # Should NOT detect - Whitelist check
        ("""
$pages = ['home', 'about', 'contact'];
$page = $_GET['page'];
if (in_array($page, $pages)) {
    include($page . '.php');
}
""", "File Inclusion - Whitelisted", False),
    ]

    print("=" * 70)
    print("ENHANCED SCANNER TEST")
    print("=" * 70)

    passed = 0
    for code, name, should_detect in test_cases:
        results = scanner.scan(code)
        high_results = [r for r in results if r.confidence > 0.5]
        detected = len(high_results) > 0

        status = "[OK]" if detected == should_detect else "[FAIL]"
        if detected == should_detect:
            passed += 1

        print(f"\n{status} {name}")
        print(f"  Expected: {'VULNERABLE' if should_detect else 'SAFE'}")
        print(f"  Got: {'VULNERABLE' if detected else 'SAFE'}")
        if results:
            r = results[0]
            print(f"  Confidence: {r.confidence:.0%}")
            if r.sanitizer:
                print(f"  Sanitizers: {r.sanitizer}")

    print(f"\n{'='*70}")
    print(f"PASSED: {passed}/{len(test_cases)} ({100*passed/len(test_cases):.0f}%)")
    print("=" * 70)


if __name__ == "__main__":
    test_scanner()
