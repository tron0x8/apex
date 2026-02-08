#!/usr/bin/env python3
"""
APEX Taint Tracking & Data Flow Analysis Module
Tracks data flow from sources through sanitizers to sinks

Source → [Sanitizer] → Sink

If data flows from source to sink WITHOUT proper sanitization = VULNERABILITY
If data is sanitized before reaching sink = SAFE (no alert)
"""

import re
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum


class TaintType(Enum):
    """Types of taint for different vulnerability classes"""
    SQL = "sql"
    XSS = "xss"
    COMMAND = "command"
    FILE_PATH = "file_path"
    FILE_CONTENT = "file_content"
    SSRF = "ssrf"
    LDAP = "ldap"
    XPATH = "xpath"
    GENERIC = "generic"


@dataclass
class TaintSource:
    """Represents a source of tainted data"""
    name: str
    pattern: str
    taint_types: List[TaintType]
    description: str


@dataclass
class Sanitizer:
    """Represents a sanitization function"""
    name: str
    pattern: str
    sanitizes: List[TaintType]  # Which taint types this sanitizer cleans
    description: str


@dataclass
class Sink:
    """Represents a dangerous sink"""
    name: str
    pattern: str
    vulnerable_to: List[TaintType]  # Which taint types are dangerous here
    severity: str
    description: str


@dataclass
class TaintedVariable:
    """Tracks a tainted variable through the code"""
    name: str
    line: int
    source: str
    taint_types: Set[TaintType] = field(default_factory=set)
    sanitized_for: Set[TaintType] = field(default_factory=set)

    def is_safe_for(self, taint_type: TaintType) -> bool:
        """Check if variable is sanitized for a specific taint type"""
        return taint_type in self.sanitized_for

    def get_active_taints(self) -> Set[TaintType]:
        """Get taint types that haven't been sanitized"""
        return self.taint_types - self.sanitized_for


@dataclass
class DataFlowPath:
    """Represents a complete data flow path"""
    source_var: str
    source_line: int
    source_type: str
    sink_line: int
    sink_type: str
    sanitizers_applied: List[str]
    is_vulnerable: bool
    taint_type: TaintType
    confidence: float


class TaintTracker:
    """
    Main taint tracking engine
    Performs inter-procedural data flow analysis
    """

    def __init__(self):
        self._init_sources()
        self._init_sanitizers()
        self._init_sinks()

    def _init_sources(self):
        """Initialize known taint sources"""
        self.sources = [
            # Superglobals - primary user input
            TaintSource(
                name="REQUEST",
                pattern=r'\$_REQUEST\s*\[\s*[\'"](\w+)[\'"]\s*\]',
                taint_types=[TaintType.SQL, TaintType.XSS, TaintType.COMMAND,
                            TaintType.FILE_PATH, TaintType.SSRF],
                description="User input from $_REQUEST"
            ),
            TaintSource(
                name="GET",
                pattern=r'\$_GET\s*\[\s*[\'"](\w+)[\'"]\s*\]',
                taint_types=[TaintType.SQL, TaintType.XSS, TaintType.COMMAND,
                            TaintType.FILE_PATH, TaintType.SSRF],
                description="User input from $_GET"
            ),
            TaintSource(
                name="POST",
                pattern=r'\$_POST\s*\[\s*[\'"](\w+)[\'"]\s*\]',
                taint_types=[TaintType.SQL, TaintType.XSS, TaintType.COMMAND,
                            TaintType.FILE_PATH, TaintType.FILE_CONTENT],
                description="User input from $_POST"
            ),
            TaintSource(
                name="COOKIE",
                pattern=r'\$_COOKIE\s*\[\s*[\'"](\w+)[\'"]\s*\]',
                taint_types=[TaintType.SQL, TaintType.XSS],
                description="User input from $_COOKIE"
            ),
            TaintSource(
                name="FILES",
                pattern=r'\$_FILES\s*\[\s*[\'"](\w+)[\'"]\s*\]',
                taint_types=[TaintType.FILE_PATH, TaintType.FILE_CONTENT],
                description="Uploaded file data"
            ),
            TaintSource(
                name="SERVER_URI",
                pattern=r'\$_SERVER\s*\[\s*[\'"]REQUEST_URI[\'"]\s*\]',
                taint_types=[TaintType.XSS, TaintType.SQL],
                description="Request URI from server"
            ),
            TaintSource(
                name="SERVER_QUERY",
                pattern=r'\$_SERVER\s*\[\s*[\'"]QUERY_STRING[\'"]\s*\]',
                taint_types=[TaintType.XSS, TaintType.SQL],
                description="Query string from server"
            ),
            # Common wrapper patterns
            TaintSource(
                name="INPUT_RAW",
                pattern=r'file_get_contents\s*\(\s*[\'"]php://input[\'"]\s*\)',
                taint_types=[TaintType.SQL, TaintType.XSS, TaintType.COMMAND],
                description="Raw POST input"
            ),
            # Base64 decoded user input
            TaintSource(
                name="BASE64_INPUT",
                pattern=r'base64_decode\s*\(\s*\$_(GET|POST|REQUEST)',
                taint_types=[TaintType.SQL, TaintType.XSS, TaintType.COMMAND,
                            TaintType.FILE_PATH],
                description="Base64 decoded user input"
            ),
        ]

    def _init_sanitizers(self):
        """Initialize known sanitization functions"""
        self.sanitizers = [
            # SQL Sanitizers
            Sanitizer(
                name="mysqli_real_escape_string",
                pattern=r'mysqli_real_escape_string\s*\([^,]+,\s*(\$\w+)',
                sanitizes=[TaintType.SQL],
                description="MySQL escape function"
            ),
            Sanitizer(
                name="mysql_real_escape_string",
                pattern=r'mysql_real_escape_string\s*\(\s*(\$\w+)',
                sanitizes=[TaintType.SQL],
                description="MySQL escape function (deprecated)"
            ),
            Sanitizer(
                name="PDO_quote",
                pattern=r'\$\w+->quote\s*\(\s*(\$\w+)',
                sanitizes=[TaintType.SQL],
                description="PDO quote method"
            ),
            Sanitizer(
                name="addslashes",
                pattern=r'addslashes\s*\(\s*(\$\w+)',
                sanitizes=[TaintType.SQL],  # Weak but still sanitization
                description="Add slashes function"
            ),
            Sanitizer(
                name="safesql",  # DLE specific
                pattern=r'(?:safesql|\$db->safesql)\s*\(\s*(\$\w+)',
                sanitizes=[TaintType.SQL],
                description="DLE safesql wrapper"
            ),
            Sanitizer(
                name="db_escape",  # Generic
                pattern=r'(?:escape|db_escape|escape_string)\s*\(\s*(\$\w+)',
                sanitizes=[TaintType.SQL],
                description="Generic SQL escape"
            ),

            # XSS Sanitizers
            Sanitizer(
                name="htmlspecialchars",
                pattern=r'htmlspecialchars\s*\(\s*(\$\w+)',
                sanitizes=[TaintType.XSS],
                description="HTML special chars encoding"
            ),
            Sanitizer(
                name="htmlentities",
                pattern=r'htmlentities\s*\(\s*(\$\w+)',
                sanitizes=[TaintType.XSS],
                description="HTML entities encoding"
            ),
            Sanitizer(
                name="strip_tags",
                pattern=r'strip_tags\s*\(\s*(\$\w+)',
                sanitizes=[TaintType.XSS],
                description="Strip HTML tags"
            ),
            Sanitizer(
                name="filter_var_string",
                pattern=r'filter_var\s*\(\s*(\$\w+)\s*,\s*FILTER_SANITIZE_STRING',
                sanitizes=[TaintType.XSS],
                description="Filter var string sanitization"
            ),

            # Integer/Numeric Sanitizers (sanitize multiple types)
            Sanitizer(
                name="intval",
                pattern=r'intval\s*\(\s*(\$\w+)',
                sanitizes=[TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.FILE_PATH],
                description="Integer conversion"
            ),
            Sanitizer(
                name="int_cast",
                pattern=r'\(int\)\s*(\$\w+)',
                sanitizes=[TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.FILE_PATH],
                description="Integer type cast"
            ),
            Sanitizer(
                name="floatval",
                pattern=r'floatval\s*\(\s*(\$\w+)',
                sanitizes=[TaintType.SQL, TaintType.XSS],
                description="Float conversion"
            ),
            Sanitizer(
                name="abs",
                pattern=r'abs\s*\(\s*(\$\w+)',
                sanitizes=[TaintType.SQL, TaintType.XSS],
                description="Absolute value"
            ),

            # Command Sanitizers
            Sanitizer(
                name="escapeshellarg",
                pattern=r'escapeshellarg\s*\(\s*(\$\w+)',
                sanitizes=[TaintType.COMMAND],
                description="Shell argument escaping"
            ),
            Sanitizer(
                name="escapeshellcmd",
                pattern=r'escapeshellcmd\s*\(\s*(\$\w+)',
                sanitizes=[TaintType.COMMAND],
                description="Shell command escaping"
            ),

            # Path Sanitizers
            Sanitizer(
                name="basename",
                pattern=r'basename\s*\(\s*(\$\w+)',
                sanitizes=[TaintType.FILE_PATH],
                description="Extract filename from path"
            ),
            Sanitizer(
                name="realpath",
                pattern=r'realpath\s*\(\s*(\$\w+)',
                sanitizes=[TaintType.FILE_PATH],
                description="Resolve real path"
            ),

            # URL Sanitizers
            Sanitizer(
                name="filter_var_url",
                pattern=r'filter_var\s*\(\s*(\$\w+)\s*,\s*FILTER_VALIDATE_URL',
                sanitizes=[TaintType.SSRF],
                description="URL validation"
            ),
            Sanitizer(
                name="urlencode",
                pattern=r'urlencode\s*\(\s*(\$\w+)',
                sanitizes=[TaintType.XSS, TaintType.SSRF],
                description="URL encoding"
            ),

            # Validation patterns (not sanitizers but indicate safe usage)
            Sanitizer(
                name="preg_match_validation",
                pattern=r'preg_match\s*\(\s*[\'"][/^][a-zA-Z0-9\\]+[\$/"]\s*,\s*(\$\w+)',
                sanitizes=[TaintType.SQL, TaintType.XSS, TaintType.COMMAND],
                description="Regex validation (whitelist)"
            ),
            Sanitizer(
                name="ctype_alnum",
                pattern=r'ctype_alnum\s*\(\s*(\$\w+)',
                sanitizes=[TaintType.SQL, TaintType.XSS, TaintType.COMMAND, TaintType.FILE_PATH],
                description="Alphanumeric check"
            ),
            Sanitizer(
                name="ctype_digit",
                pattern=r'ctype_digit\s*\(\s*(\$\w+)',
                sanitizes=[TaintType.SQL, TaintType.XSS, TaintType.COMMAND],
                description="Digit check"
            ),
            Sanitizer(
                name="is_numeric",
                pattern=r'is_numeric\s*\(\s*(\$\w+)',
                sanitizes=[TaintType.SQL, TaintType.COMMAND],
                description="Numeric check"
            ),
        ]

    def _init_sinks(self):
        """Initialize dangerous sinks"""
        self.sinks = [
            # SQL Sinks
            Sink(
                name="mysql_query",
                pattern=r'(?:mysql_query|mysqli_query|pg_query)\s*\([^)]*(\$\w+)',
                vulnerable_to=[TaintType.SQL],
                severity="CRITICAL",
                description="Direct SQL query execution"
            ),
            Sink(
                name="db_query",
                pattern=r'\$(?:db|pdo|conn|mysqli)\s*->\s*query\s*\(\s*["\']?[^"\']*(\$\w+)',
                vulnerable_to=[TaintType.SQL],
                severity="CRITICAL",
                description="Database query method"
            ),
            Sink(
                name="db_execute",
                pattern=r'\$\w+\s*->\s*(?:exec|execute)\s*\([^)]*(\$\w+)',
                vulnerable_to=[TaintType.SQL],
                severity="CRITICAL",
                description="Database execute method"
            ),

            # Command Sinks
            Sink(
                name="exec",
                pattern=r'\bexec\s*\([^)]*(\$\w+)',
                vulnerable_to=[TaintType.COMMAND],
                severity="CRITICAL",
                description="Command execution"
            ),
            Sink(
                name="system",
                pattern=r'\bsystem\s*\([^)]*(\$\w+)',
                vulnerable_to=[TaintType.COMMAND],
                severity="CRITICAL",
                description="System command execution"
            ),
            Sink(
                name="passthru",
                pattern=r'\bpassthru\s*\([^)]*(\$\w+)',
                vulnerable_to=[TaintType.COMMAND],
                severity="CRITICAL",
                description="Passthru command execution"
            ),
            Sink(
                name="shell_exec",
                pattern=r'\bshell_exec\s*\([^)]*(\$\w+)',
                vulnerable_to=[TaintType.COMMAND],
                severity="CRITICAL",
                description="Shell command execution"
            ),
            Sink(
                name="popen",
                pattern=r'\bpopen\s*\([^)]*(\$\w+)',
                vulnerable_to=[TaintType.COMMAND],
                severity="CRITICAL",
                description="Process open"
            ),
            Sink(
                name="proc_open",
                pattern=r'\bproc_open\s*\([^)]*(\$\w+)',
                vulnerable_to=[TaintType.COMMAND],
                severity="CRITICAL",
                description="Process open"
            ),
            Sink(
                name="backtick",
                pattern=r'`[^`]*(\$\w+)[^`]*`',
                vulnerable_to=[TaintType.COMMAND],
                severity="CRITICAL",
                description="Backtick command execution"
            ),

            # File Sinks
            Sink(
                name="include",
                pattern=r'\b(?:include|include_once|require|require_once)\s*(?:\(|\s)+[^;]*(\$\w+)',
                vulnerable_to=[TaintType.FILE_PATH],
                severity="CRITICAL",
                description="File inclusion"
            ),
            Sink(
                name="file_get_contents",
                pattern=r'file_get_contents\s*\(\s*(\$\w+)',
                vulnerable_to=[TaintType.FILE_PATH, TaintType.SSRF],
                severity="HIGH",
                description="File read or URL fetch"
            ),
            Sink(
                name="file_put_contents",
                pattern=r'file_put_contents\s*\(\s*(\$\w+)',
                vulnerable_to=[TaintType.FILE_PATH],
                severity="CRITICAL",
                description="File write"
            ),
            Sink(
                name="fopen",
                pattern=r'fopen\s*\(\s*(\$\w+)',
                vulnerable_to=[TaintType.FILE_PATH, TaintType.SSRF],
                severity="HIGH",
                description="File open"
            ),
            Sink(
                name="unlink",
                pattern=r'unlink\s*\(\s*(\$\w+)',
                vulnerable_to=[TaintType.FILE_PATH],
                severity="HIGH",
                description="File deletion"
            ),
            Sink(
                name="move_uploaded_file",
                pattern=r'move_uploaded_file\s*\([^,]+,\s*(\$\w+)',
                vulnerable_to=[TaintType.FILE_PATH],
                severity="HIGH",
                description="Move uploaded file"
            ),

            # XSS Sinks
            Sink(
                name="echo",
                pattern=r'\becho\s+[^;]*(\$\w+)',
                vulnerable_to=[TaintType.XSS],
                severity="MEDIUM",
                description="Echo output"
            ),
            Sink(
                name="print",
                pattern=r'\bprint\s+[^;]*(\$\w+)',
                vulnerable_to=[TaintType.XSS],
                severity="MEDIUM",
                description="Print output"
            ),

            # SSRF Sinks
            Sink(
                name="curl_setopt_url",
                pattern=r'curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*(\$\w+)',
                vulnerable_to=[TaintType.SSRF],
                severity="HIGH",
                description="CURL URL setting"
            ),

            # Code Execution Sinks
            Sink(
                name="eval",
                pattern=r'\beval\s*\([^)]*(\$\w+)',
                vulnerable_to=[TaintType.COMMAND],
                severity="CRITICAL",
                description="Code evaluation"
            ),
            Sink(
                name="preg_replace_e",
                pattern=r'preg_replace\s*\(\s*[\'"][^\'"]*\/e[\'"]',
                vulnerable_to=[TaintType.COMMAND],
                severity="CRITICAL",
                description="Preg replace with /e modifier"
            ),
            Sink(
                name="create_function",
                pattern=r'create_function\s*\([^)]*(\$\w+)',
                vulnerable_to=[TaintType.COMMAND],
                severity="CRITICAL",
                description="Dynamic function creation"
            ),
            Sink(
                name="unserialize",
                pattern=r'unserialize\s*\(\s*(\$\w+)',
                vulnerable_to=[TaintType.COMMAND],
                severity="CRITICAL",
                description="Object deserialization"
            ),
        ]

    def find_sources(self, code: str) -> List[Tuple[str, int, str, Set[TaintType]]]:
        """Find all taint sources in code"""
        sources_found = []
        lines = code.split('\n')

        for source in self.sources:
            for match in re.finditer(source.pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                var_match = match.group(0)
                sources_found.append((
                    var_match,
                    line_num,
                    source.name,
                    set(source.taint_types)
                ))

        return sources_found

    def find_variable_assignments(self, code: str) -> Dict[str, List[Tuple[int, str]]]:
        """
        Track variable assignments to build data flow graph
        Returns: {var_name: [(line_num, assigned_value), ...]}
        """
        assignments = {}

        # Pattern for variable assignment
        # $var = something;
        assign_pattern = r'(\$\w+)\s*=\s*([^;]+);'

        for match in re.finditer(assign_pattern, code):
            var_name = match.group(1)
            value = match.group(2)
            line_num = code[:match.start()].count('\n') + 1

            if var_name not in assignments:
                assignments[var_name] = []
            assignments[var_name].append((line_num, value))

        return assignments

    def find_sanitizations(self, code: str) -> Dict[str, List[Tuple[int, str, Set[TaintType]]]]:
        """
        Find all sanitization operations
        Returns: {var_name: [(line_num, sanitizer_name, sanitized_types), ...]}
        """
        sanitizations = {}

        for sanitizer in self.sanitizers:
            for match in re.finditer(sanitizer.pattern, code, re.IGNORECASE):
                line_num = code[:match.start()].count('\n') + 1

                # Try to extract the variable being sanitized
                if match.lastindex:
                    var_name = match.group(match.lastindex)
                else:
                    continue

                if var_name not in sanitizations:
                    sanitizations[var_name] = []

                sanitizations[var_name].append((
                    line_num,
                    sanitizer.name,
                    set(sanitizer.sanitizes)
                ))

        return sanitizations

    def find_sinks(self, code: str) -> List[Tuple[str, int, str, Set[TaintType], str]]:
        """
        Find all dangerous sinks
        Returns: [(var_in_sink, line_num, sink_name, vulnerable_types, severity), ...]
        """
        sinks_found = []

        for sink in self.sinks:
            for match in re.finditer(sink.pattern, code, re.IGNORECASE):
                line_num = code[:match.start()].count('\n') + 1

                # Extract variable used in sink
                if match.lastindex:
                    var_name = match.group(match.lastindex)
                else:
                    var_name = match.group(0)

                sinks_found.append((
                    var_name,
                    line_num,
                    sink.name,
                    set(sink.vulnerable_to),
                    sink.severity
                ))

        return sinks_found

    def trace_variable(self, var_name: str, target_line: int,
                       assignments: Dict, sanitizations: Dict,
                       code: str) -> Tuple[bool, Set[TaintType], List[str], Optional[str]]:
        """
        Trace a variable back to its source
        Returns: (is_tainted, active_taints, sanitizers_applied, source_type)
        """
        is_tainted = False
        active_taints = set()
        sanitizers_applied = []
        source_type = None

        # Check if variable is directly from a source
        for source in self.sources:
            if re.search(source.pattern.replace(r'(\w+)', var_name.replace('$', '')), var_name):
                is_tainted = True
                active_taints = set(source.taint_types)
                source_type = source.name
                break

        # Check assignments to this variable
        if var_name in assignments:
            for line_num, value in assignments[var_name]:
                if line_num > target_line:
                    continue  # Only consider assignments before the sink

                # Check if assigned value contains tainted sources
                for source in self.sources:
                    if re.search(source.pattern, value):
                        is_tainted = True
                        active_taints.update(source.taint_types)
                        source_type = source.name

                # Check if assigned from another variable
                var_refs = re.findall(r'\$\w+', value)
                for ref in var_refs:
                    if ref != var_name:
                        # Recursive trace (limited depth)
                        sub_tainted, sub_taints, sub_sanitizers, sub_source = \
                            self.trace_variable(ref, line_num, assignments, sanitizations, code)
                        if sub_tainted:
                            is_tainted = True
                            active_taints.update(sub_taints)
                            if sub_source:
                                source_type = sub_source

        # Check if variable was sanitized before target line
        if var_name in sanitizations:
            for line_num, sanitizer_name, sanitized_types in sanitizations[var_name]:
                if line_num < target_line:
                    sanitizers_applied.append(sanitizer_name)
                    active_taints -= sanitized_types

        return is_tainted, active_taints, sanitizers_applied, source_type

    def analyze(self, code: str, filepath: str = "") -> List[DataFlowPath]:
        """
        Perform complete taint analysis on code
        Returns list of vulnerable data flow paths
        """
        vulnerabilities = []

        # Step 1: Find all sources, sanitizations, and sinks
        sources = self.find_sources(code)
        assignments = self.find_variable_assignments(code)
        sanitizations = self.find_sanitizations(code)
        sinks = self.find_sinks(code)

        # Step 2: For each sink, trace back to check if data is tainted
        for var_name, sink_line, sink_name, vulnerable_types, severity in sinks:
            # Trace the variable
            is_tainted, active_taints, sanitizers_applied, source_type = \
                self.trace_variable(var_name, sink_line, assignments, sanitizations, code)

            if not is_tainted:
                continue

            # Check if any active taint matches sink vulnerability
            matching_taints = active_taints & vulnerable_types

            if matching_taints:
                # Found a vulnerable path!
                for taint_type in matching_taints:
                    # Calculate confidence based on analysis
                    confidence = 0.9
                    if sanitizers_applied:
                        confidence = 0.7  # Some sanitization but not complete
                    if not source_type:
                        confidence = 0.6  # Indirect taint

                    vuln = DataFlowPath(
                        source_var=var_name,
                        source_line=0,  # Would need more tracking
                        source_type=source_type or "INDIRECT",
                        sink_line=sink_line,
                        sink_type=sink_name,
                        sanitizers_applied=sanitizers_applied,
                        is_vulnerable=True,
                        taint_type=taint_type,
                        confidence=confidence
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities


class DataFlowAnalyzer:
    """
    Advanced data flow analyzer with context sensitivity
    """

    def __init__(self):
        self.taint_tracker = TaintTracker()
        self.function_summaries = {}  # Cache function analysis results

    def analyze_function(self, code: str, func_name: str) -> Dict:
        """Analyze a single function for data flow"""
        # Extract function body
        pattern = rf'function\s+{re.escape(func_name)}\s*\([^)]*\)\s*\{{([^}}]+)\}}'
        match = re.search(pattern, code, re.DOTALL)

        if not match:
            return {}

        func_body = match.group(1)
        return {
            'vulnerabilities': self.taint_tracker.analyze(func_body),
            'name': func_name
        }

    def analyze_file(self, code: str, filepath: str = "") -> Dict:
        """Analyze entire file with context"""
        results = {
            'filepath': filepath,
            'vulnerabilities': [],
            'sources_found': [],
            'sinks_found': [],
            'sanitizers_found': [],
            'safe_patterns': [],
        }

        # Run taint analysis
        vulns = self.taint_tracker.analyze(code, filepath)

        # Collect statistics
        sources = self.taint_tracker.find_sources(code)
        sinks = self.taint_tracker.find_sinks(code)
        sanitizations = self.taint_tracker.find_sanitizations(code)

        results['vulnerabilities'] = vulns
        results['sources_found'] = [(s[0], s[1], s[2]) for s in sources]
        results['sinks_found'] = [(s[0], s[1], s[2]) for s in sinks]
        results['sanitizers_found'] = list(sanitizations.keys())

        # Identify safe patterns (sanitized data flows)
        for var_name, san_list in sanitizations.items():
            for line, san_name, san_types in san_list:
                results['safe_patterns'].append({
                    'variable': var_name,
                    'sanitizer': san_name,
                    'line': line,
                    'protects_against': [t.value for t in san_types]
                })

        return results


# Convenience function for integration with APEX
def analyze_code_flow(code: str, filepath: str = "") -> List[Dict]:
    """
    Main entry point for APEX integration
    Returns list of verified vulnerabilities with data flow context
    """
    analyzer = DataFlowAnalyzer()
    results = analyzer.analyze_file(code, filepath)

    findings = []
    for vuln in results['vulnerabilities']:
        findings.append({
            'type': 'DATA_FLOW_VULNERABILITY',
            'taint_type': vuln.taint_type.value,
            'source': vuln.source_type,
            'sink': vuln.sink_type,
            'line': vuln.sink_line,
            'confidence': vuln.confidence,
            'sanitizers_bypassed': vuln.sanitizers_applied,
            'severity': 'CRITICAL' if vuln.confidence > 0.8 else 'HIGH',
            'filepath': filepath,
        })

    return findings


if __name__ == "__main__":
    # Test with sample code
    test_code = '''
    <?php
    $id = $_GET['id'];
    $safe_id = intval($id);

    // Vulnerable - no sanitization
    $name = $_POST['name'];
    $db->query("SELECT * FROM users WHERE name = '$name'");

    // Safe - sanitized
    $email = $_POST['email'];
    $email = $db->safesql($email);
    $db->query("SELECT * FROM users WHERE email = '$email'");

    // Vulnerable - wrong sanitizer for SQL
    $cmd = $_GET['cmd'];
    $cmd = htmlspecialchars($cmd);
    system($cmd);
    ?>
    '''

    analyzer = DataFlowAnalyzer()
    results = analyzer.analyze_file(test_code, "test.php")

    print("=" * 60)
    print("TAINT ANALYSIS RESULTS")
    print("=" * 60)

    print(f"\nSources found: {len(results['sources_found'])}")
    for src in results['sources_found']:
        print(f"  - {src[2]} at line {src[1]}")

    print(f"\nSinks found: {len(results['sinks_found'])}")
    for sink in results['sinks_found']:
        print(f"  - {sink[2]} at line {sink[1]}")

    print(f"\nVulnerabilities: {len(results['vulnerabilities'])}")
    for vuln in results['vulnerabilities']:
        print(f"\n  [{vuln.taint_type.value.upper()}] Line {vuln.sink_line}")
        print(f"    Source: {vuln.source_type}")
        print(f"    Sink: {vuln.sink_type}")
        print(f"    Confidence: {vuln.confidence:.0%}")
        if vuln.sanitizers_applied:
            print(f"    Sanitizers (insufficient): {vuln.sanitizers_applied}")
