#!/usr/bin/env python3
# apex/core - tron (@tron0x8)

import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

try:
    from .rule_engine import get_rule_engine
except ImportError:
    get_rule_engine = None


@dataclass
class PreFilterResult:
    is_fp: bool
    reason: str
    category: str


@dataclass
class FunctionInfo:
    name: str
    start_line: int
    end_line: int
    params: List[str]


class FPPreFilter:

    SAFE_PATHS = [
        r'/system/',
        r'/vendor/',
        r'/node_modules/',
        r'pclzip\.lib\.php',
        r'phpmailer',
        r'tcpdf',
        r'/libraries/',
    ]

    DOC_PATTERNS = [
        r'^\s*\*\s*\w+\s+statement',
        r'^\s*\*\s*@\w+',
        r'^\s*//\s*TODO',
        r'^\s*//\s*FIXME',
        r'^\s*//\s*NOTE',
        r'^\s*#\s*\w+:',
    ]

    HTML_PATTERNS = [
        r'<title>[^<]+</title>',
        r'<meta\s+[^>]+>',
        r'<!--[^>]+-->',
        r'<script[^>]*>[^<]*</script>',
        r'<style[^>]*>[^<]*</style>',
    ]

    HARDCODED_URL_PATTERNS = [
        r'https?://[a-zA-Z0-9.-]+\.(com|org|net|io|gov)',
        r'https?://raw\.githubusercontent\.com',
        r'https?://cdn\.',
        r'https?://api\.',
        r'https?://codeload\.github\.com',
    ]

    SSRF_FUNCTIONS = [
        'curl_setopt',
        'curl_init',
        'file_get_contents',
        'fopen',
        'readfile',
        'get_headers',
    ]

    def __init__(self, rule_engine=None):
        self._function_cache: Dict[str, List[FunctionInfo]] = {}
        self._call_cache: Dict[str, Dict[str, List[Tuple[int, List[str]]]]] = {}
        self._load_rules_from_engine(rule_engine)

    def _load_rules_from_engine(self, rule_engine=None):
        try:
            if rule_engine is None and get_rule_engine is not None:
                rule_engine = get_rule_engine()
            if rule_engine is None:
                return

            fp_rules = rule_engine.get_fp_rules()
            if not fp_rules:
                return

            safe_path_rules = fp_rules.get('safe_path', [])
            hardcoded_safe = set(self.SAFE_PATHS)
            for rule in safe_path_rules:
                if rule.pattern and rule.pattern not in hardcoded_safe:
                    self.SAFE_PATHS = list(self.SAFE_PATHS) + [rule.pattern]

            doc_rules = fp_rules.get('documentation', []) + fp_rules.get('comment', [])
            hardcoded_doc = set(self.DOC_PATTERNS)
            for rule in doc_rules:
                if rule.pattern and rule.pattern not in hardcoded_doc:
                    self.DOC_PATTERNS = list(self.DOC_PATTERNS) + [rule.pattern]

            html_rules = fp_rules.get('html', [])
            hardcoded_html = set(self.HTML_PATTERNS)
            for rule in html_rules:
                if rule.pattern and rule.pattern not in hardcoded_html:
                    self.HTML_PATTERNS = list(self.HTML_PATTERNS) + [rule.pattern]

            url_rules = fp_rules.get('hardcoded_url', [])
            hardcoded_urls = set(self.HARDCODED_URL_PATTERNS)
            for rule in url_rules:
                if rule.pattern and rule.pattern not in hardcoded_urls:
                    self.HARDCODED_URL_PATTERNS = list(self.HARDCODED_URL_PATTERNS) + [rule.pattern]

        except Exception:
            pass

    def _parse_functions(self, code: str) -> List[FunctionInfo]:
        functions = []
        lines = code.split('\n')

        func_pattern = re.compile(r'function\s+(\w+)\s*\(([^)]*)\)')

        i = 0
        while i < len(lines):
            line = lines[i]
            match = func_pattern.search(line)
            if match:
                func_name = match.group(1)
                params_str = match.group(2)

                params = []
                if params_str.strip():
                    for p in params_str.split(','):
                        p = p.strip()
                        var_match = re.search(r'\$(\w+)', p)
                        if var_match:
                            params.append(var_match.group(1))

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
        calls = []
        lines = code.split('\n')

        call_pattern = re.compile(rf'{func_name}\s*\(', re.IGNORECASE)

        for i, line in enumerate(lines):
            if call_pattern.search(line):
                full_call = line
                paren_count = line.count('(') - line.count(')')
                j = i + 1
                while paren_count > 0 and j < len(lines):
                    full_call += '\n' + lines[j]
                    paren_count += lines[j].count('(') - lines[j].count(')')
                    j += 1

                match = re.search(rf'{func_name}\s*\(([\s\S]*?)\);', full_call, re.IGNORECASE)
                if match:
                    args_str = match.group(1)
                    args = self._split_args(args_str)
                    calls.append((i + 1, args))

        return calls

    def _split_args(self, args_str: str) -> List[str]:
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
        for func in functions:
            if func.start_line <= line_num <= func.end_line:
                return func
        return None

    def _is_hardcoded_url_arg(self, arg: str) -> bool:
        arg = arg.strip()

        for pattern in self.HARDCODED_URL_PATTERNS:
            if re.search(pattern, arg, re.I):
                return True

        if (arg.startswith("'") and arg.endswith("'")) or \
           (arg.startswith('"') and arg.endswith('"')):
            if 'http' in arg.lower():
                return True

        return False

    def _has_user_input_in_arg(self, arg: str) -> bool:
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
        lines = code.split('\n')
        if line_num <= 0 or line_num > len(lines):
            return False, ""

        line = lines[line_num - 1]

        if re.match(r'^\s*(//|#)', line):
            return True, "Single-line comment"

        stripped = line.strip()
        if stripped.startswith('*') and not stripped.startswith('*/'):
            return True, "Block comment (PHPDoc)"

        if stripped.startswith('/*'):
            return True, "Block comment start"

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
        lines = code.split('\n')
        if line_num <= 0 or line_num > len(lines):
            return False, ""

        line = lines[line_num - 1]

        for pattern in self.HTML_PATTERNS:
            if re.search(pattern, line, re.I):
                return True, f"HTML pattern: {pattern[:30]}"

        in_php = False
        for i in range(line_num):
            l = lines[i] if i < line_num - 1 else line
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
        lines = code.split('\n')
        if line_num <= 0 or line_num > len(lines):
            return False, ""

        line = lines[line_num - 1]

        if 'SSRF' in vuln_type or 'CURL' in vuln_type:
            for pattern in self.HARDCODED_URL_PATTERNS:
                if re.search(pattern, line, re.I):
                    return True, "Hardcoded URL in line"

            start = max(0, line_num - 20)
            context = '\n'.join(lines[start:line_num + 5])

            if re.search(r"['\"]https?://[^'\"]+['\"]", context):
                if not re.search(r'\$_(GET|POST|REQUEST|COOKIE)', context):
                    return True, "URL from hardcoded string, no user input"

            if re.search(r'\w+\s*\(\s*[\'"]https?://', context):
                return True, "Function called with hardcoded URL"

            is_fp, reason = self._trace_ssrf_function_param(code, line_num)
            if is_fp:
                return True, reason

        if 'SQL' in vuln_type:
            if re.match(r'^\s*\*\s*\w+', line):
                return True, "PHPDoc comment, not SQL"
            if re.match(r'^\s*(public|private|protected)?\s*function\s+\w+', line):
                return True, "Function definition, not SQL"
            if re.search(r"['\"].*\b(SELECT|INSERT|UPDATE|DELETE)\b.*['\"]", line, re.I):
                if not re.search(r'\$\w+', line):
                    return True, "Static SQL string, no variables"

        if 'XSS' in vuln_type:
            if re.search(r'echo\s+[\'"][^$]+[\'"]', line):
                if not re.search(r'\$\w+', line):
                    return True, "Echo static string only"

        return False, ""

    def _trace_ssrf_function_param(self, code: str, line_num: int) -> Tuple[bool, str]:
        lines = code.split('\n')
        if line_num <= 0 or line_num > len(lines):
            return False, ""

        line = lines[line_num - 1]

        ssrf_sink_found = False
        url_var = None

        for sink in self.SSRF_FUNCTIONS:
            if sink in line.lower():
                ssrf_sink_found = True
                match = re.search(r'curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*(\$\w+)', line)
                if match:
                    url_var = match.group(1)
                    break
                match = re.search(rf'{sink}\s*\(\s*(\$\w+)', line, re.I)
                if match:
                    url_var = match.group(1)
                    break

        if not ssrf_sink_found or not url_var:
            return False, ""

        functions = self._parse_functions(code)

        containing_func = self._get_containing_function(line_num, functions)

        if not containing_func:
            return False, ""

        var_name = url_var.lstrip('$')
        if var_name not in containing_func.params:
            return False, ""

        param_index = containing_func.params.index(var_name)

        calls = self._find_function_calls(code, containing_func.name)

        if not calls:
            return True, f"Function '{containing_func.name}' defined but not called in this file"

        all_hardcoded = True
        has_user_input = False

        for call_line, args in calls:
            if containing_func.start_line <= call_line <= containing_func.end_line:
                continue

            if param_index < len(args):
                arg = args[param_index]

                if self._has_user_input_in_arg(arg):
                    has_user_input = True
                    all_hardcoded = False
                    break

                if not self._is_hardcoded_url_arg(arg):
                    if arg.startswith('$'):
                        all_hardcoded = False
                        break

        if has_user_input:
            return False, ""

        if all_hardcoded:
            return True, f"Function '{containing_func.name}' only called with hardcoded URLs"

        return False, ""

    def is_documentation(self, code: str, line_num: int) -> Tuple[bool, str]:
        lines = code.split('\n')
        if line_num <= 0 or line_num > len(lines):
            return False, ""

        line = lines[line_num - 1]

        for pattern in self.DOC_PATTERNS:
            if re.search(pattern, line, re.I):
                return True, f"Documentation pattern"

        if re.search(r'^\s*\*\s*(Generates|Returns|Creates|Deletes|Updates|Inserts)', line, re.I):
            return True, "Method documentation"

        return False, ""

    def is_framework_core(self, file_path: str) -> Tuple[bool, str]:
        for pattern in self.SAFE_PATHS:
            if re.search(pattern, file_path, re.I):
                return True, f"Framework/library path: {pattern}"

        return False, ""

    def filter(self, finding: Dict, code: str) -> PreFilterResult:
        line_num = finding.get('line', 0)
        vuln_type = finding.get('type', '')
        file_path = finding.get('file', '')

        is_comment, reason = self.is_in_comment(code, line_num)
        if is_comment:
            return PreFilterResult(True, reason, 'comment')

        is_doc, reason = self.is_documentation(code, line_num)
        if is_doc:
            return PreFilterResult(True, reason, 'documentation')

        is_html, reason = self.is_in_html(code, line_num)
        if is_html:
            return PreFilterResult(True, reason, 'html')

        is_hard, reason = self.is_hardcoded(code, line_num, vuln_type)
        if is_hard:
            return PreFilterResult(True, reason, 'hardcoded')


        return PreFilterResult(False, "", "")


class EnhancedVulnFilter:

    def __init__(self, ml_filter=None, context_analyzer=None):
        self.prefilter = FPPreFilter()
        self.ml_filter = ml_filter
        self.context_analyzer = context_analyzer

    def filter(self, finding: Dict, code: str) -> Tuple[bool, str, str]:

        pre_result = self.prefilter.filter(finding, code)
        if pre_result.is_fp:
            return True, f"PREFILTER: {pre_result.reason}", pre_result.category

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
                pass

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
    from .ml_filter import BinaryVulnFilter
    from .context_analyzer import AdvancedContextAnalyzer

    ml_filter = None
    if ml_model_path:
        ml_filter = BinaryVulnFilter(threshold=0.6)
        ml_filter.load_model(ml_model_path)


    return EnhancedVulnFilter(ml_filter=ml_filter)
