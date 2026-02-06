#!/usr/bin/env python3
"""
APEX False Positive Pre-Filter v2.0
Filters obvious false positives BEFORE ML analysis

Catches:
1. Findings in comments (// /* */ #)
2. Findings in HTML context (not PHP)
3. Hardcoded values (not user input)
4. Documentation patterns
5. Framework/library core files
6. Function parameter tracing (SSRF in functions called with hardcoded URLs)
"""

import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass


@dataclass
class PreFilterResult:
    is_fp: bool
    reason: str
    category: str  # 'comment', 'html', 'hardcoded', 'documentation', 'framework', 'func_trace'


@dataclass
class FunctionInfo:
    name: str
    start_line: int
    end_line: int
    params: List[str]


class FPPreFilter:
    """Pre-filter for obvious false positives"""

    # Framework/library paths that are generally safe
    SAFE_PATHS = [
        r'/system/',  # CodeIgniter system
        r'/vendor/',  # Composer vendor
        r'/node_modules/',  # Node modules
        r'pclzip\.lib\.php',  # PCLZip library
        r'phpmailer',  # PHPMailer
        r'tcpdf',  # TCPDF
        r'/libraries/',  # Framework libraries
    ]

    # Documentation patterns in comments
    DOC_PATTERNS = [
        r'^\s*\*\s*\w+\s+statement',  # "* Delete statement"
        r'^\s*\*\s*@\w+',  # PHPDoc tags
        r'^\s*//\s*TODO',
        r'^\s*//\s*FIXME',
        r'^\s*//\s*NOTE',
        r'^\s*#\s*\w+:',  # Shell-style comments
    ]

    # HTML-only patterns (not in PHP)
    HTML_PATTERNS = [
        r'<title>[^<]+</title>',
        r'<meta\s+[^>]+>',
        r'<!--[^>]+-->',
        r'<script[^>]*>[^<]*</script>',
        r'<style[^>]*>[^<]*</style>',
    ]

    # Hardcoded URL patterns
    HARDCODED_URL_PATTERNS = [
        r'https?://[a-zA-Z0-9.-]+\.(com|org|net|io|gov)',
        r'https?://raw\.githubusercontent\.com',
        r'https?://cdn\.',
        r'https?://api\.',
        r'https?://codeload\.github\.com',
    ]

    # SSRF-related functions
    SSRF_FUNCTIONS = [
        'curl_setopt',
        'curl_init',
        'file_get_contents',
        'fopen',
        'readfile',
        'get_headers',
    ]

    def __init__(self):
        self._function_cache: Dict[str, List[FunctionInfo]] = {}
        self._call_cache: Dict[str, Dict[str, List[Tuple[int, List[str]]]]] = {}

    def _parse_functions(self, code: str) -> List[FunctionInfo]:
        """Parse all function definitions in the code"""
        functions = []
        lines = code.split('\n')

        # Find function definitions
        func_pattern = re.compile(r'function\s+(\w+)\s*\(([^)]*)\)')

        i = 0
        while i < len(lines):
            line = lines[i]
            match = func_pattern.search(line)
            if match:
                func_name = match.group(1)
                params_str = match.group(2)

                # Parse parameters
                params = []
                if params_str.strip():
                    for p in params_str.split(','):
                        p = p.strip()
                        # Extract variable name (e.g., "$in_file" from "$in_file = null")
                        var_match = re.search(r'\$(\w+)', p)
                        if var_match:
                            params.append(var_match.group(1))

                # Find function end (count braces)
                start_line = i + 1
                brace_count = 0
                found_open = False
                end_line = start_line

                for j in range(i, len(lines)):
                    for ch in lines[j]:
                        if ch == '{':
                            brace_count += 1
                            found_open = True
                        elif ch == '}':
                            brace_count -= 1

                    if found_open and brace_count == 0:
                        end_line = j + 1
                        break

                functions.append(FunctionInfo(
                    name=func_name,
                    start_line=start_line,
                    end_line=end_line,
                    params=params
                ))
            i += 1

        return functions

    def _find_function_calls(self, code: str, func_name: str) -> List[Tuple[int, List[str]]]:
        """Find all calls to a function and extract arguments"""
        calls = []
        lines = code.split('\n')

        # Pattern to find function calls (handles multi-line)
        call_pattern = re.compile(rf'{func_name}\s*\(', re.IGNORECASE)

        for i, line in enumerate(lines):
            if call_pattern.search(line):
                # Extract arguments (handle multi-line calls)
                full_call = line
                paren_count = line.count('(') - line.count(')')
                j = i + 1
                while paren_count > 0 and j < len(lines):
                    full_call += '\n' + lines[j]
                    paren_count += lines[j].count('(') - lines[j].count(')')
                    j += 1

                # Extract the arguments
                match = re.search(rf'{func_name}\s*\(([\s\S]*?)\);', full_call, re.IGNORECASE)
                if match:
                    args_str = match.group(1)
                    # Split by comma but respect nested parentheses and quotes
                    args = self._split_args(args_str)
                    calls.append((i + 1, args))

        return calls

    def _split_args(self, args_str: str) -> List[str]:
        """Split function arguments respecting nested structures"""
        args = []
        current = ""
        paren_depth = 0
        in_string = False
        string_char = None

        for ch in args_str:
            if ch in '"\'':
                if not in_string:
                    in_string = True
                    string_char = ch
                elif ch == string_char:
                    in_string = False
            elif ch == '(' and not in_string:
                paren_depth += 1
            elif ch == ')' and not in_string:
                paren_depth -= 1
            elif ch == ',' and paren_depth == 0 and not in_string:
                args.append(current.strip())
                current = ""
                continue
            current += ch

        if current.strip():
            args.append(current.strip())

        return args

    def _get_containing_function(self, line_num: int, functions: List[FunctionInfo]) -> Optional[FunctionInfo]:
        """Find which function contains a given line"""
        for func in functions:
            if func.start_line <= line_num <= func.end_line:
                return func
        return None

    def _is_hardcoded_url_arg(self, arg: str) -> bool:
        """Check if an argument is a hardcoded URL"""
        arg = arg.strip()

        # Check for string literals with URLs
        for pattern in self.HARDCODED_URL_PATTERNS:
            if re.search(pattern, arg, re.I):
                return True

        # Check if it's a quoted string (hardcoded)
        if (arg.startswith("'") and arg.endswith("'")) or \
           (arg.startswith('"') and arg.endswith('"')):
            if 'http' in arg.lower():
                return True

        return False

    def _has_user_input_in_arg(self, arg: str) -> bool:
        """Check if argument contains user input"""
        user_input_patterns = [
            r'\$_GET',
            r'\$_POST',
            r'\$_REQUEST',
            r'\$_COOKIE',
            r'\$_SERVER\s*\[\s*[\'"](?:REQUEST_URI|QUERY_STRING|PATH_INFO)',
        ]
        for pattern in user_input_patterns:
            if re.search(pattern, arg, re.I):
                return True
        return False

    def is_in_comment(self, code: str, line_num: int) -> Tuple[bool, str]:
        """Check if line is inside a comment"""
        lines = code.split('\n')
        if line_num <= 0 or line_num > len(lines):
            return False, ""

        line = lines[line_num - 1]

        # Single line comment
        if re.match(r'^\s*(//|#)', line):
            return True, "Single-line comment"

        # Check for PHPDoc/block comment
        stripped = line.strip()
        if stripped.startswith('*') and not stripped.startswith('*/'):
            # Likely inside /* */ block
            return True, "Block comment (PHPDoc)"

        if stripped.startswith('/*'):
            return True, "Block comment start"

        # Check if we're inside a multi-line comment
        in_comment = False
        for i in range(line_num - 1):
            l = lines[i]
            if '/*' in l:
                in_comment = True
            if '*/' in l:
                in_comment = False

        if in_comment:
            return True, "Inside multi-line comment"

        return False, ""

    def is_in_html(self, code: str, line_num: int) -> Tuple[bool, str]:
        """Check if line is in HTML context (outside PHP tags)"""
        lines = code.split('\n')
        if line_num <= 0 or line_num > len(lines):
            return False, ""

        line = lines[line_num - 1]

        # Check for HTML-only patterns
        for pattern in self.HTML_PATTERNS:
            if re.search(pattern, line, re.I):
                return True, f"HTML pattern: {pattern[:30]}"

        # Check if we're outside PHP tags
        in_php = False
        for i in range(line_num):
            l = lines[i] if i < line_num - 1 else line
            # Count PHP tag transitions
            opens = len(re.findall(r'<\?php|<\?=|<\?', l, re.I))
            closes = len(re.findall(r'\?>', l))

            if opens > closes:
                in_php = True
            elif closes > opens:
                in_php = False

        if not in_php:
            return True, "Outside PHP tags (HTML context)"

        return False, ""

    def is_hardcoded(self, code: str, line_num: int, vuln_type: str) -> Tuple[bool, str]:
        """Check if the value is hardcoded (not user input)"""
        lines = code.split('\n')
        if line_num <= 0 or line_num > len(lines):
            return False, ""

        line = lines[line_num - 1]

        # For SSRF: check if URL is hardcoded
        if 'SSRF' in vuln_type or 'CURL' in vuln_type:
            # Direct hardcoded URL check
            for pattern in self.HARDCODED_URL_PATTERNS:
                if re.search(pattern, line, re.I):
                    return True, "Hardcoded URL in line"

            # Check if the variable is assigned a hardcoded string nearby
            start = max(0, line_num - 20)
            context = '\n'.join(lines[start:line_num + 5])

            # Look for hardcoded URL assignments
            if re.search(r"['\"]https?://[^'\"]+['\"]", context):
                # Check if there's NO user input
                if not re.search(r'\$_(GET|POST|REQUEST|COOKIE)', context):
                    return True, "URL from hardcoded string, no user input"

            # Check function calls with hardcoded URLs
            if re.search(r'\w+\s*\(\s*[\'"]https?://', context):
                return True, "Function called with hardcoded URL"

            # ADVANCED: Function parameter tracing for SSRF
            is_fp, reason = self._trace_ssrf_function_param(code, line_num)
            if is_fp:
                return True, reason

        # For SQL: check if it's a method/function name, not actual SQL
        if 'SQL' in vuln_type:
            # Check if line is just a method definition or call without user input
            if re.match(r'^\s*\*\s*\w+', line):  # PHPDoc
                return True, "PHPDoc comment, not SQL"
            if re.match(r'^\s*(public|private|protected)?\s*function\s+\w+', line):
                return True, "Function definition, not SQL"
            # Check for SQL keywords in string literals only (not variables)
            if re.search(r"['\"].*\b(SELECT|INSERT|UPDATE|DELETE)\b.*['\"]", line, re.I):
                if not re.search(r'\$\w+', line):  # No variables
                    return True, "Static SQL string, no variables"

        # For XSS: check if echoing static content
        if 'XSS' in vuln_type:
            # Check if echo contains only static strings
            if re.search(r'echo\s+[\'"][^$]+[\'"]', line):
                if not re.search(r'\$\w+', line):
                    return True, "Echo static string only"

        return False, ""

    def _trace_ssrf_function_param(self, code: str, line_num: int) -> Tuple[bool, str]:
        """
        Advanced SSRF detection: trace function parameters.

        If the SSRF sink (curl_setopt, etc.) is inside a function,
        and the URL comes from a function parameter, check if ALL calls
        to that function pass hardcoded URLs.
        """
        lines = code.split('\n')
        if line_num <= 0 or line_num > len(lines):
            return False, ""

        line = lines[line_num - 1]

        # Check if this line contains an SSRF sink
        ssrf_sink_found = False
        url_var = None

        for sink in self.SSRF_FUNCTIONS:
            if sink in line.lower():
                ssrf_sink_found = True
                # Try to extract the URL variable
                # curl_setopt($ch, CURLOPT_URL, $var) -> extract $var
                match = re.search(r'curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*(\$\w+)', line)
                if match:
                    url_var = match.group(1)
                    break
                # file_get_contents($url) -> extract $url
                match = re.search(rf'{sink}\s*\(\s*(\$\w+)', line, re.I)
                if match:
                    url_var = match.group(1)
                    break

        if not ssrf_sink_found or not url_var:
            return False, ""

        # Parse all functions in the code
        functions = self._parse_functions(code)

        # Find which function contains this line
        containing_func = self._get_containing_function(line_num, functions)

        if not containing_func:
            return False, ""

        # Check if url_var matches a function parameter
        var_name = url_var.lstrip('$')
        if var_name not in containing_func.params:
            return False, ""

        # Get parameter position
        param_index = containing_func.params.index(var_name)

        # Find all calls to this function
        calls = self._find_function_calls(code, containing_func.name)

        if not calls:
            # Function defined but never called - could be library code
            return True, f"Function '{containing_func.name}' defined but not called in this file"

        # Check if ALL calls pass hardcoded URLs at this parameter position
        all_hardcoded = True
        has_user_input = False

        for call_line, args in calls:
            # Skip if the call is within the function itself (recursive)
            if containing_func.start_line <= call_line <= containing_func.end_line:
                continue

            if param_index < len(args):
                arg = args[param_index]

                if self._has_user_input_in_arg(arg):
                    has_user_input = True
                    all_hardcoded = False
                    break

                if not self._is_hardcoded_url_arg(arg):
                    # Check if it's a constant or another variable
                    # If it's a variable, we need to trace further
                    if arg.startswith('$'):
                        all_hardcoded = False
                        break

        if has_user_input:
            return False, ""

        if all_hardcoded:
            return True, f"Function '{containing_func.name}' only called with hardcoded URLs"

        return False, ""

    def is_documentation(self, code: str, line_num: int) -> Tuple[bool, str]:
        """Check if line is documentation"""
        lines = code.split('\n')
        if line_num <= 0 or line_num > len(lines):
            return False, ""

        line = lines[line_num - 1]

        for pattern in self.DOC_PATTERNS:
            if re.search(pattern, line, re.I):
                return True, f"Documentation pattern"

        # Check for common doc strings
        if re.search(r'^\s*\*\s*(Generates|Returns|Creates|Deletes|Updates|Inserts)', line, re.I):
            return True, "Method documentation"

        return False, ""

    def is_framework_core(self, file_path: str) -> Tuple[bool, str]:
        """Check if file is in a framework/library core path"""
        for pattern in self.SAFE_PATHS:
            if re.search(pattern, file_path, re.I):
                return True, f"Framework/library path: {pattern}"

        return False, ""

    def filter(self, finding: Dict, code: str) -> PreFilterResult:
        """
        Main filter method.
        Returns PreFilterResult indicating if finding is a false positive.
        """
        line_num = finding.get('line', 0)
        vuln_type = finding.get('type', '')
        file_path = finding.get('file', '')

        # 1. Check if in comment
        is_comment, reason = self.is_in_comment(code, line_num)
        if is_comment:
            return PreFilterResult(True, reason, 'comment')

        # 2. Check if documentation
        is_doc, reason = self.is_documentation(code, line_num)
        if is_doc:
            return PreFilterResult(True, reason, 'documentation')

        # 3. Check if in HTML context
        is_html, reason = self.is_in_html(code, line_num)
        if is_html:
            return PreFilterResult(True, reason, 'html')

        # 4. Check if hardcoded value
        is_hard, reason = self.is_hardcoded(code, line_num, vuln_type)
        if is_hard:
            return PreFilterResult(True, reason, 'hardcoded')

        # 5. Check if framework core (lower priority)
        # is_fw, reason = self.is_framework_core(file_path)
        # if is_fw:
        #     return PreFilterResult(True, reason, 'framework')

        return PreFilterResult(False, "", "")


class EnhancedVulnFilter:
    """
    Combined filter: PreFilter + Context Analyzer + ML
    """

    def __init__(self, ml_filter=None, context_analyzer=None):
        self.prefilter = FPPreFilter()
        self.ml_filter = ml_filter
        self.context_analyzer = context_analyzer

    def filter(self, finding: Dict, code: str) -> Tuple[bool, str, str]:
        """
        Returns (is_false_positive, reason, filter_stage)
        filter_stage: 'prefilter', 'context', 'ml', 'none'
        """

        # Stage 1: Pre-filter (fastest, catches obvious FPs)
        pre_result = self.prefilter.filter(finding, code)
        if pre_result.is_fp:
            return True, f"PREFILTER: {pre_result.reason}", pre_result.category

        # Stage 2: Context Analyzer (if available)
        if self.context_analyzer:
            try:
                line_num = finding.get('line', 0)
                source_var = finding.get('match', '')[:50]
                vuln_type = finding.get('type', '')

                is_fp, reason = self.context_analyzer.is_false_positive(
                    line_num, source_var, vuln_type
                )
                if is_fp:
                    return True, f"CONTEXT: {reason}", "context"
            except Exception as e:
                pass  # Continue to ML if context fails

        # Stage 3: ML Filter (if available)
        if self.ml_filter and self.ml_filter.is_loaded:
            try:
                lines = code.split('\n')
                start = max(0, finding.get('line', 0) - 10)
                end = min(len(lines), finding.get('line', 0) + 10)
                context = '\n'.join(lines[start:end])

                result = self.ml_filter.predict(finding, context)
                if result.is_false_positive:
                    return True, f"ML: {result.reason}", "ml"
            except Exception as e:
                pass

        return False, "", "none"


def create_enhanced_filter(ml_model_path: str = None, project_path: str = None):
    """Factory function to create enhanced filter with all components"""
    from .ml_filter import BinaryVulnFilter
    from .context_analyzer import AdvancedContextAnalyzer

    ml_filter = None
    if ml_model_path:
        ml_filter = BinaryVulnFilter(threshold=0.6)
        ml_filter.load_model(ml_model_path)

    # Context analyzer will be created per-file in the scan loop
    # since it needs the file's code

    return EnhancedVulnFilter(ml_filter=ml_filter)
