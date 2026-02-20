#!/usr/bin/env python3
# apex/core - tron (@tron0x8)

import os
import re
import json
import pickle
import math
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Set
from pathlib import Path

from dataclasses import field as dataclass_field

try:
    from .rule_engine import get_rule_engine
except ImportError:
    get_rule_engine = None

try:
    from .type_inference import TypeInference, PHPType, TypeState
    _HAS_TYPE_INFERENCE = True
except ImportError:
    _HAS_TYPE_INFERENCE = False

try:
    from .alias_analysis import AliasAnalyzer
    _HAS_ALIAS = True
except ImportError:
    _HAS_ALIAS = False

try:
    from .string_domain import StringAnalyzer, StringValue
    _HAS_STRING_DOMAIN = True
except ImportError:
    _HAS_STRING_DOMAIN = False

try:
    from .abstract_interp import AbstractInterpreter, AbstractState, TaintLattice
    _HAS_ABSTRACT_INTERP = True
except ImportError:
    _HAS_ABSTRACT_INTERP = False

try:
    from .framework_models import FrameworkModelEngine
    _HAS_FRAMEWORK_MODELS = True
except ImportError:
    _HAS_FRAMEWORK_MODELS = False

try:
    from .interprocedural_v2 import InterproceduralEngine, FunctionSummary
    _HAS_INTERPROC_V2 = True
except ImportError:
    _HAS_INTERPROC_V2 = False

try:
    from .ts_adapter import parse_php_ts
    from .cfg import CFGBuilder
    _HAS_CFG = True
except ImportError:
    _HAS_CFG = False


@dataclass
class FileAnalysisResults:
    file_path: str = ""
    type_map: Dict[str, Set[str]] = dataclass_field(default_factory=dict)
    alias_sets: Dict[str, Set[str]] = dataclass_field(default_factory=dict)
    string_contexts: Dict[int, Dict] = dataclass_field(default_factory=dict)
    taint_levels: Dict[str, int] = dataclass_field(default_factory=dict)
    sanitized_types: Dict[str, Set[str]] = dataclass_field(default_factory=dict)
    func_summaries: Dict[str, Dict] = dataclass_field(default_factory=dict)
    validated_vars: Set[str] = dataclass_field(default_factory=set)
    framework: str = ""
    middleware: Set[str] = dataclass_field(default_factory=set)
    orm_vars: Set[str] = dataclass_field(default_factory=set)
    taint_info_details: Dict[str, Dict] = dataclass_field(default_factory=dict)
    cfg_metrics: Dict[str, Dict] = dataclass_field(default_factory=dict)
    phi_nodes_per_block: Dict[int, int] = dataclass_field(default_factory=dict)
    string_sink_contexts: Dict[int, Dict] = dataclass_field(default_factory=dict)
    call_graph_metrics: Dict[str, Dict] = dataclass_field(default_factory=dict)
    context_results: Dict[int, Dict] = dataclass_field(default_factory=dict)
    middleware_list: List[str] = dataclass_field(default_factory=list)


def build_file_analysis(file_path: str, code: str,
                         rule_engine=None) -> Optional['FileAnalysisResults']:
    if not _HAS_CFG:
        return None

    results = FileAnalysisResults(file_path=file_path)

    try:
        root = parse_php_ts(code)
    except Exception:
        return None

    cfg_blocks_all = []
    func_bodies = {}
    for node in root.walk_descendants():
        if node.type in ('function_definition', 'method_declaration'):
            fname_node = node.child_by_field('name')
            fname = fname_node.text if fname_node else ''
            body = node.child_by_field('body')
            if body:
                try:
                    blocks = CFGBuilder().build(body)
                    cfg_blocks_all.extend(blocks)
                    if fname:
                        func_bodies[fname] = blocks
                except Exception:
                    pass

    if not cfg_blocks_all:
        try:
            cfg_blocks_all = CFGBuilder().build(root)
        except Exception:
            pass

    if not cfg_blocks_all:
        return results

    if _HAS_TYPE_INFERENCE:
        try:
            re_arg = rule_engine or (get_rule_engine() if get_rule_engine else None)
            if re_arg:
                ti = TypeInference(re_arg)
                type_map = ti.infer(cfg_blocks_all)
                for var, types in type_map.items():
                    results.type_map[var] = {t.value if hasattr(t, 'value') else str(t) for t in types}
        except Exception:
            pass

    if _HAS_ALIAS:
        try:
            aa = AliasAnalyzer()
            aa.analyze(cfg_blocks_all)
            for var in list(aa._points_to.keys()):
                if var.startswith('$'):
                    aliases = aa.get_aliases(var)
                    if len(aliases) > 1:
                        results.alias_sets[var] = aliases
        except Exception:
            pass

    if _HAS_FRAMEWORK_MODELS:
        try:
            re_arg = rule_engine or (get_rule_engine() if get_rule_engine else None)
            if re_arg:
                fme = FrameworkModelEngine(re_arg)
                results.middleware = fme.detect_route_middleware(code)
                results.orm_vars = fme.detect_orm_usage(code)
                from .abstract_interp import AbstractState, TaintLattice, TaintInfo
                dummy_state = AbstractState()
                for var in ['$id', '$name', '$email', '$input', '$data',
                            '$request', '$value', '$param', '$query']:
                    dummy_state.set(var, TaintInfo(
                        level=TaintLattice.TAINTED,
                        taint_types={'SQL', 'XSS', 'COMMAND'},
                        sources={var}
                    ))
                new_state = fme.apply_validation_constraints('laravel', code, dummy_state)
                for var in ['$id', '$name', '$email', '$input', '$data',
                            '$request', '$value', '$param', '$query']:
                    info = new_state.get(var)
                    if info and info.sanitized_types:
                        results.validated_vars.add(var)
        except Exception:
            pass

    return results


SANITIZER_TYPE_MAP = {
    'mysql_real_escape_string': {'SQL Injection'},
    'mysqli_real_escape_string': {'SQL Injection'},
    'addslashes': {'SQL Injection'},
    'pg_escape_string': {'SQL Injection'},
    'PDO::quote': {'SQL Injection'},
    'safesql': {'SQL Injection'},
    'intval': {'SQL Injection', 'Cross-Site Scripting', 'Command Injection', 'Path Traversal'},
    'floatval': {'SQL Injection', 'Cross-Site Scripting', 'Command Injection'},
    'abs': {'SQL Injection', 'Cross-Site Scripting', 'Command Injection'},
    'htmlspecialchars': {'Cross-Site Scripting'},
    'htmlentities': {'Cross-Site Scripting'},
    'strip_tags': {'Cross-Site Scripting'},
    'wp_kses': {'Cross-Site Scripting'},
    'esc_html': {'Cross-Site Scripting'},
    'esc_attr': {'Cross-Site Scripting'},
    'e()': {'Cross-Site Scripting'},
    'escapeshellarg': {'Command Injection'},
    'escapeshellcmd': {'Command Injection'},
    'basename': {'Path Traversal', 'File Inclusion', 'Arbitrary File Read', 'Arbitrary File Write'},
    'realpath': {'Path Traversal', 'File Inclusion'},
    'filter_var': {'Cross-Site Scripting', 'SQL Injection', 'Server-Side Request Forgery'},
    'preg_replace': {'SQL Injection', 'Cross-Site Scripting', 'Command Injection'},
    'ctype_alnum': {'SQL Injection', 'Cross-Site Scripting', 'Command Injection'},
    'ctype_alpha': {'SQL Injection', 'Cross-Site Scripting', 'Command Injection'},
    'ctype_digit': {'SQL Injection', 'Cross-Site Scripting', 'Command Injection'},
    'is_numeric': {'SQL Injection', 'Cross-Site Scripting'},
}

SOURCE_RISK = {
    '$_GET': 1.0,
    '$_POST': 1.0,
    '$_REQUEST': 1.0,
    '$_COOKIE': 0.9,
    '$_FILES': 0.85,
    '$_SERVER': 0.5,
    '$_ENV': 0.3,
    '$_SESSION': 0.1,
}

SINK_DANGER = {
    'eval': 1.0, 'assert': 1.0, 'create_function': 1.0,
    'system': 1.0, 'exec': 1.0, 'passthru': 1.0, 'shell_exec': 1.0,
    'popen': 0.95, 'proc_open': 0.95, 'pcntl_exec': 1.0,
    'unserialize': 0.95,
    'mysql_query': 0.9, 'mysqli_query': 0.9, 'pg_query': 0.9,
    'query': 0.85, 'prepare': 0.3,
    'echo': 0.7, 'print': 0.7, 'die': 0.6,
    'include': 0.9, 'require': 0.9, 'include_once': 0.85, 'require_once': 0.85,
    'file_get_contents': 0.8, 'file_put_contents': 0.9,
    'fopen': 0.8, 'fwrite': 0.85,
    'header': 0.7, 'setcookie': 0.6,
    'curl_setopt': 0.8, 'file': 0.75,
    'mail': 0.6, 'preg_replace': 0.5,
    'ldap_search': 0.85, 'ldap_bind': 0.8,
    'simplexml_load_string': 0.85,
}

PREPARED_STMT_PATTERNS = [
    r'->prepare\s*\(',
    r'\?\s*,',
    r':\w+\s*[,\)]',
    r'bindParam|bindValue|bind_param',
    r'PDO::\w+',
    r'execute\s*\(\s*\[',
    r'->where\s*\(',
    r'->find\s*\(',
    r'->findOrFail\s*\(',
    r'Eloquent|Doctrine|ActiveRecord',
    r'DB::table|DB::select|DB::insert',
]

TYPE_CAST_PATTERNS = [
    r'\(int\)\s*\$',
    r'\(float\)\s*\$',
    r'\(bool\)\s*\$',
    r'\(integer\)\s*\$',
    r'intval\s*\(\s*\$',
    r'floatval\s*\(\s*\$',
    r'boolval\s*\(\s*\$',
    r'abs\s*\(\s*\$',
    r'settype\s*\(',
]

VALIDATION_PATTERNS = [
    r'is_numeric\s*\(',
    r'is_int\s*\(',
    r'is_string\s*\(',
    r'ctype_\w+\s*\(',
    r'filter_var\s*\(.*FILTER_VALIDATE',
    r'preg_match\s*\(\s*[\'"][\/~#]\^',
    r'in_array\s*\(',
    r'array_key_exists\s*\(',
    r'isset\s*\(\s*\$\w+\[',
    r'switch\s*\(\s*\$',
    r'FILTER_SANITIZE',
]

AUTH_CHECK_PATTERNS = [
    r'(?:check|is|has|verify)_?(?:auth|login|logged|admin|permission|role|access)',
    r'->isAuthenticated|->isLoggedIn|->hasRole|->can\(',
    r'\$_SESSION\s*\[\s*[\'"](?:user|admin|auth|login|token)',
    r'Auth::|Gate::|Policy::',
    r'wp_verify_nonce|check_admin_referer|current_user_can',
    r'session_start.*?(?:if|unless).*?(?:user|login|auth)',
    r'@login_required|@auth|@middleware\([\'"]auth',
]

COMMENT_PATTERNS = [
    r'^\s*(?://|#)',
    r'^\s*/?\*',
    r'^\s*\*\s',
]

CMS_SAFE_PATTERNS = [
    r'\$_F\s*=\s*__FILE__',
    r'\$_X\s*=\s*["\']',
    r'eval\s*\(\s*\$_X\)',
    r'wp_kses\s*\(',
    r'esc_sql\s*\(',
    r'wp_nonce\s*\(',
    r'\$wpdb->prepare\s*\(',
    r'sanitize_text_field\s*\(',
    r'absint\s*\(',
    r'Validator::make\s*\(',
    r'\$request->validate\(',
    r'->validated\(\)',
    r'Crypt::|encrypt\s*\(',
    r'->createQueryBuilder\(',
    r'ParamConverter',
    r'nonce_check|verify_nonce|check_referer',
    r'htmlPurifier|HTMLPurifier',
]

FRAMEWORK_PATTERNS = {
    'laravel': r'Illuminate\\|Route::|Eloquent|Auth::|\$request->input|blade\.php',
    'symfony': r'Symfony\\|AbstractController|@Route|->getRepository\(',
    'wordpress': r'wp_|WP_|WordPress|add_action|add_filter|get_option',
    'codeigniter': r'CI_Controller|->input->|->db->|codeigniter|BASEPATH',
    'yii': r'Yii::|CActiveRecord|yii\\|Yii2',
    'drupal': r'drupal_|Drupal\\|hook_|\.module$',
    'cakephp': r'CakePlugin|AppController|cake|TableRegistry',
}


def _extend_ml_patterns_from_rule_engine():
    try:
        if get_rule_engine is None:
            return
        engine = get_rule_engine()
        if engine is None:
            return

        fp_rules = engine.get_fp_rules()
        if not fp_rules:
            return

        prep_rules = fp_rules.get('prepared_stmt', [])
        existing_prep = set(PREPARED_STMT_PATTERNS)
        for rule in prep_rules:
            if rule.pattern and rule.pattern not in existing_prep:
                PREPARED_STMT_PATTERNS.append(rule.pattern)

        cast_rules = fp_rules.get('type_cast', [])
        existing_cast = set(TYPE_CAST_PATTERNS)
        for rule in cast_rules:
            if rule.pattern and rule.pattern not in existing_cast:
                TYPE_CAST_PATTERNS.append(rule.pattern)

        val_rules = fp_rules.get('validation', [])
        existing_val = set(VALIDATION_PATTERNS)
        for rule in val_rules:
            if rule.pattern and rule.pattern not in existing_val:
                VALIDATION_PATTERNS.append(rule.pattern)

        auth_rules = fp_rules.get('auth', [])
        existing_auth = set(AUTH_CHECK_PATTERNS)
        for rule in auth_rules:
            if rule.pattern and rule.pattern not in existing_auth:
                AUTH_CHECK_PATTERNS.append(rule.pattern)

        cms_rules = fp_rules.get('cms_safe', [])
        existing_cms = set(CMS_SAFE_PATTERNS)
        for rule in cms_rules:
            if rule.pattern and rule.pattern not in existing_cms:
                CMS_SAFE_PATTERNS.append(rule.pattern)

        all_sanitizers = engine.get_sanitizers()
        if all_sanitizers:
            _vuln_name_map = {
                'SQL_INJECTION': 'SQL Injection',
                'SQL': 'SQL Injection',
                'XSS': 'Cross-Site Scripting',
                'CROSS_SITE_SCRIPTING': 'Cross-Site Scripting',
                'COMMAND_INJECTION': 'Command Injection',
                'COMMAND': 'Command Injection',
                'PATH_TRAVERSAL': 'Path Traversal',
                'FILE_INCLUSION': 'File Inclusion',
                'FILE': 'Path Traversal',
                'SSRF': 'Server-Side Request Forgery',
                'CODE_INJECTION': 'Code Injection',
                'CODE': 'Code Injection',
            }
            for san_name, san_def in all_sanitizers.items():
                if san_name not in SANITIZER_TYPE_MAP:
                    vuln_types = set()
                    for prot in san_def.protects_against:
                        mapped = _vuln_name_map.get(prot.upper())
                        if mapped:
                            vuln_types.add(mapped)
                    if vuln_types:
                        SANITIZER_TYPE_MAP[san_name] = vuln_types

    except Exception:
        pass


_extend_ml_patterns_from_rule_engine()


@dataclass
class FeatureVector:
    vuln_type: str = ""
    severity: int = 0
    rule_confidence: float = 0.0

    source_type: str = ""
    source_risk: float = 0.0
    has_direct_source: bool = False

    sink_function: str = ""
    sink_danger: float = 0.0

    sanitizer_present: bool = False
    sanitizer_count: int = 0
    sanitizer_type_match: bool = False
    sanitizer_distance: int = 999

    prepared_stmt_nearby: bool = False
    type_cast_nearby: bool = False
    validation_nearby: bool = False
    orm_detected: bool = False

    in_comment: bool = False
    in_admin_path: bool = False
    auth_check_nearby: bool = False
    in_try_catch: bool = False
    in_loop: bool = False

    framework_detected: str = ""
    is_framework_safe_pattern: bool = False

    file_lines: int = 0
    is_ajax_handler: bool = False
    is_public_endpoint: bool = False

    var_reassigned: bool = False
    uses_string_concat: bool = False
    uses_interpolation: bool = False

    cms_safe_pattern: bool = False

    base64_decode_on_input: bool = False

    ssa_branch_sanitized: bool = False
    string_context_safe: bool = False
    string_tainted_ratio: float = 0.0
    type_narrowed_safe: bool = False
    alias_count: int = 0
    interproc_flow_to_sink: bool = False
    interproc_sanitized: bool = False
    framework_validated: bool = False

    ast_depth_to_sink: int = 0
    cfg_block_count: int = 0
    cyclomatic_complexity: int = 0
    branch_count_between: int = 0
    loop_nesting_depth: int = 0
    function_param_count: int = 0
    is_in_closure: bool = False
    lines_from_func_start: int = 0

    taint_lattice_level: int = 0
    effective_taint_type_count: int = 0
    taint_source_count: int = 0
    has_partial_sanitization: bool = False

    string_fragment_count: int = 0
    string_literal_ratio: float = 0.0
    string_sink_risk_level: int = 0
    string_position_dangerous: bool = False

    call_depth: int = 0
    callee_is_sanitizer: bool = False
    param_reaches_sink_count: int = 0
    scc_size: int = 0
    call_graph_in_degree: int = 0

    whitelist_check_present: bool = False
    dead_code_detected: bool = False
    data_flow_sanitizer_count: int = 0
    custom_func_sanitizes: bool = False

    middleware_count: int = 0
    validation_rule_strength: int = 0
    framework_confidence: float = 0.0

    file_function_count: int = 0
    enclosing_func_line_count: int = 0
    nesting_depth: int = 0
    has_error_handler: bool = False
    distance_from_entry: int = 0

    is_translation_file: bool = False
    is_test_file: bool = False
    is_config_file: bool = False

    code_context_raw: str = ""

    def to_dict(self) -> Dict:
        return {
            'vuln_type': self.vuln_type,
            'severity': self.severity,
            'rule_confidence': self.rule_confidence,
            'source_risk': self.source_risk,
            'has_direct_source': int(self.has_direct_source),
            'sink_danger': self.sink_danger,
            'sanitizer_present': int(self.sanitizer_present),
            'sanitizer_count': self.sanitizer_count,
            'sanitizer_type_match': int(self.sanitizer_type_match),
            'sanitizer_distance': min(self.sanitizer_distance, 100),
            'prepared_stmt_nearby': int(self.prepared_stmt_nearby),
            'type_cast_nearby': int(self.type_cast_nearby),
            'validation_nearby': int(self.validation_nearby),
            'orm_detected': int(self.orm_detected),
            'in_comment': int(self.in_comment),
            'in_admin_path': int(self.in_admin_path),
            'auth_check_nearby': int(self.auth_check_nearby),
            'in_try_catch': int(self.in_try_catch),
            'is_ajax_handler': int(self.is_ajax_handler),
            'var_reassigned': int(self.var_reassigned),
            'uses_string_concat': int(self.uses_string_concat),
            'uses_interpolation': int(self.uses_interpolation),
            'cms_safe_pattern': int(self.cms_safe_pattern),
            'ssa_branch_sanitized': int(self.ssa_branch_sanitized),
            'string_context_safe': int(self.string_context_safe),
            'string_tainted_ratio': self.string_tainted_ratio,
            'type_narrowed_safe': int(self.type_narrowed_safe),
            'alias_count': min(self.alias_count, 10),
            'interproc_flow_to_sink': int(self.interproc_flow_to_sink),
            'interproc_sanitized': int(self.interproc_sanitized),
            'framework_validated': int(self.framework_validated),
            'ast_depth_to_sink': min(self.ast_depth_to_sink, 20),
            'cfg_block_count': min(self.cfg_block_count, 100),
            'cyclomatic_complexity': min(self.cyclomatic_complexity, 50),
            'branch_count_between': min(self.branch_count_between, 20),
            'loop_nesting_depth': min(self.loop_nesting_depth, 5),
            'function_param_count': min(self.function_param_count, 15),
            'is_in_closure': int(self.is_in_closure),
            'lines_from_func_start': min(self.lines_from_func_start, 500),
            'taint_lattice_level': self.taint_lattice_level,
            'effective_taint_type_count': min(self.effective_taint_type_count, 16),
            'taint_source_count': min(self.taint_source_count, 10),
            'has_partial_sanitization': int(self.has_partial_sanitization),
            'string_fragment_count': min(self.string_fragment_count, 20),
            'string_literal_ratio': self.string_literal_ratio,
            'string_sink_risk_level': self.string_sink_risk_level,
            'string_position_dangerous': int(self.string_position_dangerous),
            'call_depth': min(self.call_depth, 10),
            'callee_is_sanitizer': int(self.callee_is_sanitizer),
            'param_reaches_sink_count': min(self.param_reaches_sink_count, 10),
            'scc_size': min(self.scc_size, 10),
            'call_graph_in_degree': min(self.call_graph_in_degree, 20),
            'whitelist_check_present': int(self.whitelist_check_present),
            'dead_code_detected': int(self.dead_code_detected),
            'data_flow_sanitizer_count': min(self.data_flow_sanitizer_count, 10),
            'custom_func_sanitizes': int(self.custom_func_sanitizes),
            'middleware_count': min(self.middleware_count, 10),
            'validation_rule_strength': self.validation_rule_strength,
            'framework_confidence': self.framework_confidence,
            'file_function_count': min(self.file_function_count, 100),
            'enclosing_func_line_count': min(self.enclosing_func_line_count, 1000),
            'nesting_depth': min(self.nesting_depth, 15),
            'has_error_handler': int(self.has_error_handler),
            'distance_from_entry': min(self.distance_from_entry, 500),
            'is_translation_file': int(self.is_translation_file),
            'is_test_file': int(self.is_test_file),
            'is_config_file': int(self.is_config_file),
        }

    def to_numeric_array(self) -> List[float]:
        d = self.to_dict()
        del d['vuln_type']
        return list(d.values())


class FeatureExtractor:

    SANITIZER_NAMES = set(SANITIZER_TYPE_MAP.keys()) | {
        'clean', 'sanitize', 'escape', 'filter', 'safe', 'validate',
        'purify', 'secure', 'protect', 'encode', 'strip', 'trim',
        'totranslit', 'DLEPlugins::Check',
    }

    def extract(self, finding_dict: Dict, code: str = "",
                file_lines: List[str] = None,
                analysis: Optional[FileAnalysisResults] = None) -> FeatureVector:
        fv = FeatureVector()

        fv.vuln_type = finding_dict.get('type', '')
        sev = finding_dict.get('severity', 'MEDIUM')
        fv.severity = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(sev, 2)

        conf_str = finding_dict.get('confidence', '50%')
        if isinstance(conf_str, str) and '%' in conf_str:
            fv.rule_confidence = float(conf_str.replace('%', '')) / 100.0
        elif isinstance(conf_str, (int, float)):
            fv.rule_confidence = float(conf_str) if conf_str <= 1 else float(conf_str) / 100.0
        else:
            fv.rule_confidence = 0.5

        code_line = finding_dict.get('code', '')
        line_num = finding_dict.get('line', 0)
        filepath = finding_dict.get('file', '')

        if file_lines is None and code:
            file_lines = code.split('\n')
        elif file_lines is None:
            file_lines = []

        fv.file_lines = len(file_lines)

        fv.source_type, fv.source_risk, fv.has_direct_source = (
            self._detect_source(code_line, file_lines, line_num)
        )

        fv.sink_function, fv.sink_danger = self._detect_sink(code_line, fv.vuln_type)

        ctx_start = max(0, line_num - 20)
        ctx_end = min(len(file_lines), line_num + 10)
        context_lines = file_lines[ctx_start:ctx_end] if file_lines else []
        context_text = '\n'.join(context_lines)

        (fv.sanitizer_present, fv.sanitizer_count,
         fv.sanitizer_type_match, fv.sanitizer_distance) = (
            self._detect_sanitizers(context_lines, fv.vuln_type, line_num, ctx_start)
        )

        fv.prepared_stmt_nearby = any(
            re.search(p, context_text) for p in PREPARED_STMT_PATTERNS
        )
        fv.orm_detected = fv.prepared_stmt_nearby

        fv.type_cast_nearby = any(
            re.search(p, context_text) for p in TYPE_CAST_PATTERNS
        )

        fv.validation_nearby = any(
            re.search(p, context_text) for p in VALIDATION_PATTERNS
        )

        fv.in_comment = self._is_in_comment(code_line)

        fv.in_admin_path = bool(re.search(
            r'(?:admin|backend|manage|cpanel|dashboard)',
            filepath, re.IGNORECASE
        ))

        fv.auth_check_nearby = any(
            re.search(p, context_text, re.IGNORECASE) for p in AUTH_CHECK_PATTERNS
        )

        fv.in_try_catch = bool(re.search(r'\btry\s*\{', context_text))

        fv.in_loop = bool(re.search(
            r'\b(?:for|foreach|while|do)\s*[\(\{]', context_text
        ))

        fv.framework_detected = self._detect_framework(code)

        fv.is_ajax_handler = bool(re.search(
            r'ajax|api|json|endpoint|xmlhttp|X-Requested-With',
            filepath + code_line, re.IGNORECASE
        ))

        fv.uses_string_concat = bool(re.search(r'\.\s*\$\w+|\$\w+\s*\.', code_line))
        fv.uses_interpolation = bool(re.search(r'"\$\w+|"\{?\$', code_line))

        fv.var_reassigned = self._check_var_reassigned(context_lines, code_line, line_num, ctx_start)

        fv.base64_decode_on_input = bool(re.search(
            r'base64_decode\s*\(\s*\$', context_text, re.IGNORECASE
        ))

        fv.cms_safe_pattern = self._check_cms_safe_patterns(context_text, code_line)

        if analysis:
            fv.type_narrowed_safe = self._real_type_narrowed(
                code_line, fv.vuln_type, analysis
            )
            fv.alias_count = self._real_alias_count(code_line, analysis)
            fv.string_context_safe = self._real_string_context(
                line_num, code_line, fv.vuln_type, analysis
            )
            fv.framework_validated = self._real_framework_validated(
                code_line, analysis
            )
            fv.interproc_sanitized = self._real_interproc_sanitized(
                code_line, context_lines, analysis
            )
            if analysis.orm_vars:
                fv.orm_detected = True
            fv.ssa_branch_sanitized = self._detect_branch_sanitization(
                context_lines, code_line, line_num, ctx_start
            )
            fv.string_tainted_ratio = self._calc_tainted_ratio(code_line)
            fv.interproc_flow_to_sink = self._detect_interproc_flow(
                context_lines, code_line, line_num, ctx_start
            )
        else:
            fv.ssa_branch_sanitized = self._detect_branch_sanitization(
                context_lines, code_line, line_num, ctx_start
            )
            fv.string_context_safe = self._detect_string_context_safe(
                code_line, fv.vuln_type
            )
            fv.string_tainted_ratio = self._calc_tainted_ratio(code_line)
            fv.type_narrowed_safe = self._detect_type_narrowing(
                context_lines, code_line, fv.vuln_type
            )
            fv.alias_count = self._count_aliases(context_text, code_line)
            fv.interproc_flow_to_sink = self._detect_interproc_flow(
                context_lines, code_line, line_num, ctx_start
            )
            fv.interproc_sanitized = self._detect_interproc_sanitizer(
                context_lines, code_line
            )
            fv.framework_validated = self._detect_framework_validation(
                context_text, code_line
            )

        self._extract_v5_features(fv, code_line, line_num, filepath,
                                   file_lines, context_text, context_lines,
                                   ctx_start, analysis)

        return fv

    def _detect_source(self, code_line: str, file_lines: List[str],
                       line_num: int) -> Tuple[str, float, bool]:
        for source, risk in SOURCE_RISK.items():
            if source in code_line:
                return source.replace('$_', ''), risk, True

        wrapper_patterns = [
            (r"\$post\s*\[", 'POST', 0.85),
            (r"\$data\s*\[", 'POST', 0.75),
            (r"\$input\s*\[", 'POST', 0.85),
            (r"\$request\s*\[", 'REQUEST', 0.85),
            (r"\$params\s*\[", 'GET', 0.75),
            (r"\$args\s*\[", 'GET', 0.70),
        ]
        for pattern, src_name, risk in wrapper_patterns:
            if re.search(pattern, code_line, re.IGNORECASE):
                return src_name, risk, False

        start = max(0, line_num - 30)
        context = '\n'.join(file_lines[start:line_num]) if file_lines else ''
        for source, risk in SOURCE_RISK.items():
            if source in context:
                return source.replace('$_', ''), risk * 0.7, False

        for pattern, src_name, risk in wrapper_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return src_name, risk * 0.7, False

        return '', 0.3, False

    def _detect_sink(self, code_line: str, vuln_type: str) -> Tuple[str, float]:
        for func, danger in SINK_DANGER.items():
            if re.search(rf'\b{re.escape(func)}\s*\(', code_line):
                return func, danger
            if re.search(rf'->{re.escape(func)}\s*\(', code_line):
                return func, danger

        type_danger = {
            'Code Injection': 0.95,
            'Remote Code Execution': 1.0,
            'Command Injection': 0.95,
            'SQL Injection': 0.85,
            'File Inclusion': 0.9,
            'Insecure Deserialization': 0.9,
            'Cross-Site Scripting': 0.7,
            'Path Traversal': 0.75,
            'Open Redirect': 0.5,
            'Information Disclosure': 0.3,
            'Weak Cryptography': 0.4,
            'Type Juggling': 0.5,
        }
        return '', type_danger.get(vuln_type, 0.5)

    def _detect_sanitizers(self, context_lines: List[str], vuln_type: str,
                           line_num: int, ctx_start: int
                           ) -> Tuple[bool, int, bool, int]:
        found = False
        count = 0
        type_match = False
        min_distance = 999

        context_text = '\n'.join(context_lines)

        for san_name, vuln_types in SANITIZER_TYPE_MAP.items():
            pattern = re.escape(san_name).replace(r'\:', ':')
            if re.search(pattern, context_text, re.IGNORECASE):
                found = True
                count += 1
                if vuln_type in vuln_types:
                    type_match = True

                for i, line in enumerate(context_lines):
                    if re.search(pattern, line, re.IGNORECASE):
                        actual_line = ctx_start + i + 1
                        dist = abs(actual_line - line_num)
                        min_distance = min(min_distance, dist)

        for line in context_lines:
            for name in ['clean', 'sanitize', 'escape', 'filter', 'safe',
                         'validate', 'purify', 'protect']:
                if re.search(rf'\b\w*{name}\w*\s*\(', line, re.IGNORECASE):
                    found = True
                    count += 1
                    break

        return found, count, type_match, min_distance

    def _is_in_comment(self, code_line: str) -> bool:
        stripped = code_line.strip()
        return (stripped.startswith('//') or stripped.startswith('#') or
                stripped.startswith('*') or stripped.startswith('/*'))

    def _detect_framework(self, code: str) -> str:
        if not code:
            return ''
        sample = code[:5000]
        for name, pattern in FRAMEWORK_PATTERNS.items():
            if re.search(pattern, sample):
                return name
        return ''

    def _check_cms_safe_patterns(self, context_text: str, code_line: str) -> bool:
        for pattern in CMS_SAFE_PATTERNS:
            if re.search(pattern, context_text, re.IGNORECASE):
                return True
        return False


    def _real_type_narrowed(self, code_line: str, vuln_type: str,
                             analysis: FileAnalysisResults) -> bool:
        if not analysis.type_map:
            return False
        safe_types = {'INT', 'FLOAT', 'BOOL', 'NULL', 'int', 'float', 'bool', 'null'}
        for var_match in re.finditer(r'\$\w+', code_line):
            var = var_match.group(0)
            if var in analysis.type_map:
                types = analysis.type_map[var]
                if types and types.issubset(safe_types):
                    return True
        return False

    def _real_alias_count(self, code_line: str,
                           analysis: FileAnalysisResults) -> int:
        if not analysis.alias_sets:
            return 0
        max_aliases = 0
        for var_match in re.finditer(r'\$\w+', code_line):
            var = var_match.group(0)
            if var in analysis.alias_sets:
                count = len(analysis.alias_sets[var]) - 1
                max_aliases = max(max_aliases, count)
        return max_aliases

    def _real_string_context(self, line_num: int, code_line: str,
                              vuln_type: str,
                              analysis: FileAnalysisResults) -> bool:
        if analysis.string_contexts and line_num in analysis.string_contexts:
            ctx = analysis.string_contexts[line_num]
            return ctx.get('safe', False)
        return self._detect_string_context_safe(code_line, vuln_type)

    def _real_framework_validated(self, code_line: str,
                                   analysis: FileAnalysisResults) -> bool:
        if not analysis.validated_vars:
            return False
        for var_match in re.finditer(r'\$\w+', code_line):
            var = var_match.group(0)
            if var in analysis.validated_vars:
                return True
        if analysis.orm_vars:
            for var_match in re.finditer(r'\$\w+', code_line):
                var = var_match.group(0)
                if var in analysis.orm_vars:
                    return True
        return False

    def _real_interproc_sanitized(self, code_line: str,
                                   context_lines: List[str],
                                   analysis: FileAnalysisResults) -> bool:
        if not analysis.func_summaries:
            return self._detect_interproc_sanitizer(context_lines, code_line)
        context_text = '\n'.join(context_lines)
        for func_name, summary in analysis.func_summaries.items():
            sanitizer_for = summary.get('sanitizer_for', set())
            if sanitizer_for and re.search(rf'\b{re.escape(func_name)}\s*\(', context_text):
                return True
        return False


    def _detect_branch_sanitization(self, context_lines: List[str],
                                     code_line: str, line_num: int,
                                     ctx_start: int) -> bool:
        var_match = re.search(r'\$(\w+)', code_line)
        if not var_match:
            return False
        var_name = re.escape(var_match.group(0))

        context_text = '\n'.join(context_lines)
        san_funcs = '|'.join(['intval', 'floatval', 'htmlspecialchars',
                              'htmlentities', 'strip_tags', 'addslashes',
                              'escapeshellarg', 'basename', 'filter_var',
                              'mysql_real_escape_string', 'mysqli_real_escape_string'])
        has_branch = bool(re.search(r'\b(?:if|else)\b', context_text))
        has_sanitizer_on_var = bool(re.search(
            rf'(?:{san_funcs})\s*\(\s*{var_name}', context_text
        ))
        has_raw_usage = bool(re.search(
            rf'(?:echo|query|exec|system|include|eval|header)\s*\(.*?{var_name}',
            context_text
        ))
        return has_branch and has_sanitizer_on_var and has_raw_usage

    def _detect_string_context_safe(self, code_line: str,
                                     vuln_type: str) -> bool:
        if 'SQL' in vuln_type or vuln_type == 'SQL Injection':
            if re.search(r'\b(?:FROM|INTO|JOIN|TABLE)\s+["\']?\s*\.\s*\$\w+',
                         code_line, re.IGNORECASE):
                return True
            if re.search(r'WHERE\s+\w+\s*=\s*[\'"][^$]*[\'"]', code_line):
                return True

        if 'XSS' in vuln_type or vuln_type == 'Cross-Site Scripting':
            if re.search(r'<!--.*\$\w+.*-->', code_line):
                return True
            if re.search(r'<meta\b.*\$\w+', code_line, re.IGNORECASE):
                return True

        if 'Command' in vuln_type:
            if re.search(r'(?:exec|system|passthru|shell_exec)\s*\(\s*["\'][a-zA-Z_/]+\s',
                         code_line):
                return True

        return False

    def _calc_tainted_ratio(self, code_line: str) -> float:
        parts = re.split(r'\s*\.\s*', code_line)
        if not parts:
            return 0.0
        n_total = len(parts)
        n_tainted = 0
        for part in parts:
            if re.search(r'\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)', part):
                n_tainted += 1
            elif re.search(r'\$\w+', part) and not re.search(r'["\'][^$]*["\']', part):
                n_tainted += 1
        return n_tainted / n_total if n_total > 0 else 0.0

    def _detect_type_narrowing(self, context_lines: List[str],
                                code_line: str, vuln_type: str) -> bool:
        var_match = re.search(r'\$(\w+)', code_line)
        if not var_match:
            return False
        var_name = re.escape(var_match.group(0))
        context_text = '\n'.join(context_lines)

        type_guard = bool(re.search(
            rf'(?:is_int|is_numeric|is_float|is_bool|ctype_digit)\s*\(\s*{var_name}\s*\)',
            context_text
        ))

        type_cast = bool(re.search(
            rf'{var_name}\s*=\s*(?:\(int\)|\(float\)|\(bool\)|\(integer\)|intval\s*\(|floatval\s*\(|boolval\s*\(|abs\s*\()',
            context_text
        ))

        settype = bool(re.search(
            rf'settype\s*\(\s*{var_name}\s*,\s*[\'"](?:int|integer|float|bool|boolean)[\'"]',
            context_text
        ))

        return type_guard or type_cast or settype

    def _count_aliases(self, context_text: str, code_line: str) -> int:
        var_match = re.search(r'\$(\w+)', code_line)
        if not var_match:
            return 0
        var_name = re.escape(var_match.group(0))
        refs = re.findall(rf'=\s*&\s*{var_name}\b', context_text)
        refs += re.findall(rf'{var_name}\s*=\s*&\s*\$\w+', context_text)
        return len(refs)

    def _detect_interproc_flow(self, context_lines: List[str],
                                code_line: str, line_num: int,
                                ctx_start: int) -> bool:
        var_match = re.search(r'\$(\w+)', code_line)
        if not var_match:
            return False
        var_name = re.escape(var_match.group(0))

        finding_idx = line_num - ctx_start - 1
        for line in context_lines[:finding_idx]:
            if re.search(
                rf'{var_name}\s*=\s*\w+\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)',
                line
            ):
                return True
            if re.search(rf'{var_name}\s*=\s*(?!(?:intval|htmlspecialchars|escapeshellarg|addslashes|strip_tags|basename|filter_var|floatval|abs)\b)\w+\s*\(\s*\$\w+', line):
                return True
        return False

    def _detect_interproc_sanitizer(self, context_lines: List[str],
                                     code_line: str) -> bool:
        var_match = re.search(r'\$(\w+)', code_line)
        if not var_match:
            return False
        var_name = re.escape(var_match.group(0))
        context_text = '\n'.join(context_lines)

        return bool(re.search(
            rf'{var_name}\s*=\s*\w*(?:sanitize|clean|escape|filter|safe|protect|purify|validate|secure)\w*\s*\(',
            context_text, re.IGNORECASE
        ))

    def _detect_framework_validation(self, context_text: str,
                                      code_line: str) -> bool:
        validation_patterns = [
            r'\$request->validate\s*\(',
            r'Validator::make\s*\(',
            r'->validate\s*\(\s*\$request',
            r'->isValid\s*\(\s*\)',
            r'\$validated\s*=\s*\$request->validated\(',
            r'->validateWithBag\s*\(',
            r'FormRequest',
            r'@validated',
        ]
        return any(re.search(p, context_text) for p in validation_patterns)

    def _check_var_reassigned(self, context_lines: List[str], code_line: str,
                              line_num: int, ctx_start: int) -> bool:
        var_match = re.search(r'\$(\w+)', code_line)
        if not var_match:
            return False
        var_name = var_match.group(0)

        finding_idx = line_num - ctx_start - 1
        for i, line in enumerate(context_lines[:finding_idx]):
            if re.search(rf'{re.escape(var_name)}\s*=', line):
                return True
        return False

    def _extract_v5_features(self, fv: FeatureVector, code_line: str,
                              line_num: int, filepath: str,
                              file_lines: List[str], context_text: str,
                              context_lines: List[str], ctx_start: int,
                              analysis: Optional[FileAnalysisResults] = None):

        fv.nesting_depth = self._calc_nesting_depth(file_lines, line_num)
        fv.distance_from_entry = line_num
        fv.has_error_handler = bool(re.search(
            r'\b(?:try\s*\{|set_error_handler|set_exception_handler)\b', context_text
        ))

        if file_lines:
            fv.file_function_count = sum(
                1 for l in file_lines if re.search(r'\bfunction\s+\w+\s*\(', l)
            )

        func_start, func_end, func_params = self._find_enclosing_function(file_lines, line_num)
        if func_start > 0:
            fv.lines_from_func_start = line_num - func_start
            fv.enclosing_func_line_count = func_end - func_start
            fv.function_param_count = func_params
            fv.distance_from_entry = line_num - func_start

        if file_lines and 0 < line_num <= len(file_lines):
            above = '\n'.join(file_lines[max(0, line_num - 10):line_num])
            fv.is_in_closure = bool(re.search(
                r'function\s*\(.*\)\s*(?:use\s*\(.*\)\s*)?\{', above
            ))

        if file_lines and line_num > 0:
            search_start = max(0, line_num - 30)
            before_sink = '\n'.join(file_lines[search_start:line_num])
            fv.branch_count_between = len(re.findall(
                r'\b(?:if|switch|elseif|else\s*if)\s*\(', before_sink
            ))
            fv.loop_nesting_depth = len(re.findall(
                r'\b(?:for|foreach|while|do)\s*[\(\{]', before_sink
            ))

        if func_start > 0 and func_end > func_start and file_lines:
            func_code = '\n'.join(file_lines[func_start:func_end])
            fv.cyclomatic_complexity = 1 + len(re.findall(
                r'\b(?:if|elseif|else\s*if|while|for|foreach|case|catch|&&|\|\||\?)\b',
                func_code
            ))
            fv.cfg_block_count = 1 + len(re.findall(
                r'\b(?:if|else|while|for|foreach|switch|case|try|catch|finally)\b',
                func_code
            ))

        fv.ast_depth_to_sink = fv.nesting_depth + 2

        fv.whitelist_check_present = bool(re.search(
            r'\b(?:in_array|array_key_exists)\s*\(.*\$|switch\s*\(\s*\$',
            context_text, re.IGNORECASE
        ))

        if file_lines and line_num > 1:
            prev_lines = file_lines[max(0, line_num - 5):line_num - 1]
            for pl in prev_lines:
                if re.search(r'^\s*(?:return|die|exit)\s*[\(;]', pl):
                    fv.dead_code_detected = True
                    break

        fv.custom_func_sanitizes = bool(re.search(
            r'\b(?:clean|sanitize|purify|safe|escape|filter)_?\w*\s*\(',
            context_text, re.IGNORECASE
        ))

        fv.data_flow_sanitizer_count = fv.sanitizer_count

        if filepath:
            basename = os.path.basename(filepath).lower()
            dirpath = filepath.lower().replace('\\', '/')
            fv.is_translation_file = bool(
                any(p in basename for p in ('_utf-8.php', '_utf8.php', 'language.php', 'lang.php'))
                or any(p in basename for p in ('english.php', 'french.php', 'german.php',
                       'spanish.php', 'russian.php', 'turkish.php', 'chinese.php',
                       'japanese.php', 'italian.php', 'dutch.php'))
                or any(p in dirpath for p in ('/lang/', '/language/', '/locale/',
                       '/translations/', '/i18n/', '/l10n/'))
            )
            fv.is_test_file = bool(
                any(p in basename for p in ('test_', '_test.php', 'test.php', 'tests.php'))
                or any(p in dirpath for p in ('/test/', '/tests/', '/testing/',
                       '/spec/', '/fixtures/', '/examples/', '/demo/'))
            )
            fv.is_config_file = bool(
                any(p in basename for p in ('config.php', 'settings.php', 'conf.php',
                       'database.php', '.env', 'bootstrap.php'))
                or any(p in dirpath for p in ('/config/', '/configs/', '/settings/'))
            )

        tfidf_start = max(0, line_num - 10)
        tfidf_end = min(len(file_lines), line_num + 10)
        fv.code_context_raw = '\n'.join(file_lines[tfidf_start:tfidf_end]) if file_lines else code_line

        if analysis:
            self._extract_analysis_features(fv, code_line, line_num, analysis)

    def _extract_analysis_features(self, fv: FeatureVector, code_line: str,
                                    line_num: int, analysis: FileAnalysisResults):
        var_name = self._extract_var_name(code_line)
        if var_name and var_name in analysis.taint_levels:
            fv.taint_lattice_level = analysis.taint_levels[var_name]
        if var_name and analysis.taint_info_details.get(var_name):
            info = analysis.taint_info_details[var_name]
            fv.effective_taint_type_count = info.get('effective_count', 0)
            fv.taint_source_count = info.get('source_count', 0)
            san_types = info.get('sanitized_types', set())
            taint_types = info.get('taint_types', set())
            fv.has_partial_sanitization = bool(san_types) and bool(taint_types - san_types)

        if line_num in analysis.string_sink_contexts:
            ctx = analysis.string_sink_contexts[line_num]
            fv.string_fragment_count = ctx.get('fragment_count', 0)
            fv.string_literal_ratio = ctx.get('literal_ratio', 0.0)
            risk = ctx.get('risk_level', 'low')
            fv.string_sink_risk_level = {'low': 0, 'medium': 1, 'high': 2}.get(risk, 0)
            fv.string_position_dangerous = ctx.get('dangerous', False)

        func_name = self._find_func_name_for_line(code_line, line_num)
        if func_name and func_name in analysis.cfg_metrics:
            m = analysis.cfg_metrics[func_name]
            fv.cfg_block_count = m.get('block_count', fv.cfg_block_count)
            fv.cyclomatic_complexity = m.get('complexity', fv.cyclomatic_complexity)

        for block_id, count in analysis.phi_nodes_per_block.items():
            fv.phi_node_count = max(fv.phi_node_count, count) if hasattr(fv, 'phi_node_count') else count

        if func_name and func_name in analysis.call_graph_metrics:
            cg = analysis.call_graph_metrics[func_name]
            fv.call_depth = cg.get('call_depth', 0)
            fv.call_graph_in_degree = cg.get('in_degree', 0)
            fv.scc_size = cg.get('scc_size', 0)

        if func_name and func_name in analysis.func_summaries:
            fs = analysis.func_summaries[func_name]
            fv.callee_is_sanitizer = bool(fs.get('sanitizer_for'))
            fv.param_reaches_sink_count = len(fs.get('params_to_sink', set()))

        if line_num in analysis.context_results:
            cr = analysis.context_results[line_num]
            fv.whitelist_check_present = cr.get('whitelist', fv.whitelist_check_present)
            fv.dead_code_detected = cr.get('dead_code', fv.dead_code_detected)
            fv.custom_func_sanitizes = cr.get('custom_sanitizer', fv.custom_func_sanitizes)
            if cr.get('orm_safe'):
                fv.orm_detected = True

        fv.middleware_count = len(analysis.middleware_list) if analysis.middleware_list else len(analysis.middleware)
        fv.framework_confidence = 0.9 if analysis.framework else 0.0

        if analysis.validated_vars:
            var = self._extract_var_name(code_line)
            if var and var in analysis.validated_vars:
                fv.validation_rule_strength = 2

    def _calc_nesting_depth(self, file_lines: List[str], line_num: int) -> int:
        if not file_lines or line_num <= 0:
            return 0
        depth = 0
        for i in range(min(line_num, len(file_lines))):
            line = file_lines[i]
            depth += line.count('{') - line.count('}')
        return max(0, depth)

    def _find_enclosing_function(self, file_lines: List[str],
                                  line_num: int) -> Tuple[int, int, int]:
        if not file_lines or line_num <= 0:
            return 0, 0, 0
        func_start = 0
        func_params = 0
        for i in range(min(line_num - 1, len(file_lines) - 1), -1, -1):
            m = re.search(r'\bfunction\s+\w+\s*\(([^)]*)\)', file_lines[i])
            if m:
                func_start = i + 1
                params = m.group(1).strip()
                func_params = len([p for p in params.split(',') if p.strip()]) if params else 0
                break
        if func_start == 0:
            return 0, 0, 0
        depth = 0
        func_end = len(file_lines)
        for i in range(func_start - 1, len(file_lines)):
            depth += file_lines[i].count('{') - file_lines[i].count('}')
            if depth <= 0 and i > func_start:
                func_end = i + 1
                break
        return func_start, func_end, func_params

    @staticmethod
    def _extract_var_name(code_line: str) -> str:
        m = re.search(r'\$(\w+)', code_line)
        return f'${m.group(1)}' if m else ''

    @staticmethod
    def _find_func_name_for_line(code_line: str, line_num: int) -> str:
        m = re.search(r'\b(\w+)\s*\(', code_line)
        return m.group(1) if m else ''


class HeuristicClassifier:

    WEIGHTS = {
        'source_risk': 0.25,
        'sink_danger': 0.20,
        'rule_confidence': 0.15,

        'sanitizer_type_match': -0.55,
        'prepared_stmt_nearby': -0.30,
        'type_cast_nearby': -0.25,
        'validation_nearby': -0.15,

        'sanitizer_present': -0.10,
        'in_comment': -0.50,
        'auth_check_nearby': -0.05,
        'orm_detected': -0.25,

        'has_direct_source': 0.10,
        'uses_string_concat': 0.05,
        'uses_interpolation': 0.05,
        'var_reassigned': -0.08,
        'is_ajax_handler': 0.05,
        'base64_decode_on_input': 0.15,

        'ssa_branch_sanitized': -0.15,
        'string_context_safe': -0.25,
        'string_tainted_ratio': 0.15,
        'type_narrowed_safe': -0.35,
        'alias_count': 0.05,
        'interproc_flow_to_sink': 0.10,
        'interproc_sanitized': -0.25,
        'framework_validated': -0.30,
    }

    VULN_TYPE_BASE = {
        'Code Injection': 0.60,
        'Remote Code Execution': 0.60,
        'Command Injection': 0.55,
        'SQL Injection': 0.45,
        'Insecure Deserialization': 0.60,
        'File Inclusion': 0.55,
        'Arbitrary File Write': 0.55,
        'Arbitrary File Read': 0.50,
        'Cross-Site Scripting': 0.40,
        'Path Traversal': 0.45,
        'Server-Side Request Forgery': 0.45,
        'Open Redirect': 0.40,
        'Type Juggling': 0.45,
        'Weak Cryptography': 0.55,
        'Hardcoded Credentials': 0.50,
        'Information Disclosure': 0.35,
        'Authentication Bypass': 0.55,
        'Insecure Direct Object Reference': 0.40,
        'XML External Entity': 0.55,
        'LDAP Injection': 0.50,
        'HTTP Header Injection': 0.50,
        'Mass Assignment': 0.55,
        'Insecure Randomness': 0.50,
        'Race Condition': 0.40,
        'Log Injection': 0.40,
        'Regular Expression DoS': 0.45,
        'Cross-Site Request Forgery': 0.35,
        'Unsafe File Upload': 0.50,
        'Template Injection': 0.55,
    }


    def predict(self, features: FeatureVector) -> Tuple[bool, float, str]:
        score = self.VULN_TYPE_BASE.get(features.vuln_type, 0.45)
        reasons = []

        if features.in_comment:
            score += self.WEIGHTS['in_comment']
            reasons.append("in comment")

        if features.sanitizer_type_match:
            score += self.WEIGHTS['sanitizer_type_match']
            reasons.append(f"matching sanitizer found")

        if features.prepared_stmt_nearby and features.vuln_type in (
            'SQL Injection', 'LDAP Injection'
        ):
            score += self.WEIGHTS['prepared_stmt_nearby']
            reasons.append("prepared statement nearby")

        if features.type_cast_nearby:
            score += self.WEIGHTS['type_cast_nearby']
            reasons.append("type cast nearby")

        if features.validation_nearby:
            score += self.WEIGHTS['validation_nearby']
            reasons.append("validation found")

        if features.sanitizer_present and not features.sanitizer_type_match:
            score += self.WEIGHTS['sanitizer_present']
            reasons.append("generic sanitizer nearby")

        if features.orm_detected and features.vuln_type == 'SQL Injection':
            score += self.WEIGHTS['orm_detected']
            reasons.append("ORM detected")

        if features.auth_check_nearby:
            score += self.WEIGHTS['auth_check_nearby']
            reasons.append("auth check nearby")

        score += features.source_risk * self.WEIGHTS['source_risk']
        score += features.sink_danger * self.WEIGHTS['sink_danger']
        score += features.rule_confidence * self.WEIGHTS['rule_confidence']

        if features.has_direct_source:
            score += self.WEIGHTS['has_direct_source']
            reasons.append("direct user input in sink")

        if features.uses_string_concat:
            score += self.WEIGHTS['uses_string_concat']

        if features.uses_interpolation:
            score += self.WEIGHTS['uses_interpolation']

        if features.var_reassigned:
            score += self.WEIGHTS['var_reassigned']

        if features.is_ajax_handler:
            score += self.WEIGHTS['is_ajax_handler']

        if features.base64_decode_on_input:
            score += self.WEIGHTS['base64_decode_on_input']
            reasons.append("base64_decode on user input")

        if features.sanitizer_present and features.sanitizer_distance < 5:
            score -= 0.15
            reasons.append("sanitizer very close")
        elif features.sanitizer_present and features.sanitizer_distance < 10:
            score -= 0.10

        if features.framework_detected:
            score -= 0.05
            if features.framework_detected in ('laravel', 'symfony') and features.orm_detected:
                score -= 0.10
                reasons.append(f"{features.framework_detected} ORM")

        if features.cms_safe_pattern:
            score -= 0.20
            reasons.append("CMS safe pattern")

        if features.ssa_branch_sanitized:
            score += self.WEIGHTS['ssa_branch_sanitized']
            reasons.append("branch-sanitized variable")

        if features.string_context_safe:
            score += self.WEIGHTS['string_context_safe']
            reasons.append("tainted data in safe string position")

        if features.string_tainted_ratio > 0:
            score += features.string_tainted_ratio * self.WEIGHTS['string_tainted_ratio']

        if features.type_narrowed_safe:
            score += self.WEIGHTS['type_narrowed_safe']
            reasons.append("type narrowed to safe type")

        if features.alias_count > 0:
            score += min(features.alias_count, 3) * self.WEIGHTS['alias_count']
            reasons.append(f"{features.alias_count} alias(es)")

        if features.interproc_flow_to_sink:
            score += self.WEIGHTS['interproc_flow_to_sink']
            reasons.append("cross-function taint flow")

        if features.interproc_sanitized:
            score += self.WEIGHTS['interproc_sanitized']
            reasons.append("custom sanitizer function")

        if features.framework_validated:
            score += self.WEIGHTS['framework_validated']
            reasons.append("framework validation applied")

        score = max(0.0, min(1.0, score))

        is_tp = score > 0.45
        confidence = abs(score - 0.45) * 2
        confidence = min(1.0, confidence)

        reason_str = "; ".join(reasons) if reasons else "baseline score"
        return is_tp, confidence, reason_str


# gradient boosting, f2-optimized - recall matters more than precision
class MLClassifier:

    MODEL_FILE = "apex_fp_classifier_v4.pkl"

    def __init__(self, model_dir: str = None):
        self.model = None
        self.feature_names = None
        self.model_dir = model_dir or str(Path(__file__).parent.parent / "models")
        self._load_model()

    def _load_model(self):
        model_path = os.path.join(self.model_dir, self.MODEL_FILE)
        if os.path.exists(model_path):
            try:
                with open(model_path, 'rb') as f:
                    data = pickle.load(f)
                self.model = data.get('model')
                self.feature_names = data.get('feature_names')
            except Exception:
                self.model = None

    def is_trained(self) -> bool:
        return self.model is not None

    def predict(self, features: FeatureVector) -> Tuple[bool, float]:
        if not self.is_trained():
            raise RuntimeError("No trained model available")

        fv = features.to_numeric_array()
        import numpy as np
        X = np.array([fv])
        prob = self.model.predict_proba(X)[0][1]

        return prob >= 0.30, prob

    def train(self, features_list: List[FeatureVector],
              labels: List[bool], verbose: bool = False) -> Dict:
        try:
            import numpy as np
            from sklearn.ensemble import GradientBoostingClassifier
            from sklearn.model_selection import cross_val_score
        except ImportError:
            raise RuntimeError(
                "scikit-learn required for ML training.\n"
                "Install: pip install scikit-learn numpy"
            )

        X = np.array([f.to_numeric_array() for f in features_list])
        y = np.array([1 if l else 0 for l in labels])

        if verbose:
            print(f"[ML] Training on {len(X)} samples "
                  f"({sum(y)} TP, {len(y) - sum(y)} FP)")

        model = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=4,
            learning_rate=0.1,
            min_samples_leaf=3,
            random_state=42,
        )

        metrics = {}
        if len(X) >= 20:
            cv_scores = cross_val_score(model, X, y, cv=min(5, len(X) // 4))
            metrics['cv_accuracy'] = float(np.mean(cv_scores))
            metrics['cv_std'] = float(np.std(cv_scores))
            if verbose:
                print(f"[ML] CV Accuracy: {metrics['cv_accuracy']:.1%} "
                      f"(+/- {metrics['cv_std']:.1%})")

        model.fit(X, y)
        self.model = model
        self.feature_names = list(FeatureVector().to_dict().keys())
        self.feature_names.remove('vuln_type')

        if verbose:
            importances = model.feature_importances_
            sorted_idx = np.argsort(importances)[::-1]
            print(f"[ML] Top features:")
            for i in sorted_idx[:10]:
                print(f"      {self.feature_names[i]}: {importances[i]:.3f}")

        metrics['n_samples'] = len(X)
        metrics['n_tp'] = int(sum(y))
        metrics['n_fp'] = int(len(y) - sum(y))

        os.makedirs(self.model_dir, exist_ok=True)
        model_path = os.path.join(self.model_dir, self.MODEL_FILE)
        with open(model_path, 'wb') as f:
            pickle.dump({
                'model': model,
                'feature_names': self.feature_names,
                'metrics': metrics,
            }, f)
        if verbose:
            print(f"[ML] Model saved to {model_path}")

        return metrics


class TrainingDataGenerator:

    def __init__(self):
        self.extractor = FeatureExtractor()

    def from_fixture_dir(self, fixture_dir: str) -> Tuple[List[FeatureVector], List[bool]]:
        features = []
        labels = []

        fixture_path = Path(fixture_dir)
        if not fixture_path.exists():
            return features, labels

        for php_file in fixture_path.glob('*.php'):
            is_vuln = php_file.name.startswith('vuln_')
            is_safe = php_file.name.startswith('safe_')
            if not (is_vuln or is_safe):
                continue

            code = php_file.read_text(encoding='utf-8', errors='ignore')
            file_lines = code.split('\n')

            try:
                from .unified_scanner import UnifiedScanner
            except ImportError:
                from core.unified_scanner import UnifiedScanner
            scanner = UnifiedScanner()
            findings = scanner.scan_code(code, str(php_file))

            for f in findings:
                fdict = f.to_dict() if hasattr(f, 'to_dict') else f
                fv = self.extractor.extract(fdict, code, file_lines)
                features.append(fv)
                labels.append(is_vuln)

        return features, labels

    def from_synthetic(self) -> Tuple[List[FeatureVector], List[bool]]:
        features = []
        labels = []

        tp_patterns = [
            {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '85%',
             'code': '$db->query("SELECT * FROM users WHERE id=" . $_GET["id"])',
             'line': 10, 'file': 'handler.php'},
            {'type': 'Cross-Site Scripting', 'severity': 'HIGH', 'confidence': '80%',
             'code': 'echo $_GET["name"];',
             'line': 5, 'file': 'page.php'},
            {'type': 'Code Injection', 'severity': 'CRITICAL', 'confidence': '90%',
             'code': 'eval($_POST["code"]);',
             'line': 15, 'file': 'ajax/exec.php'},
            {'type': 'Command Injection', 'severity': 'CRITICAL', 'confidence': '90%',
             'code': 'system("ls " . $_GET["dir"]);',
             'line': 20, 'file': 'admin/tools.php'},
            {'type': 'File Inclusion', 'severity': 'HIGH', 'confidence': '80%',
             'code': 'include($_GET["page"] . ".php");',
             'line': 8, 'file': 'index.php'},
            {'type': 'Insecure Deserialization', 'severity': 'CRITICAL', 'confidence': '90%',
             'code': 'unserialize($_COOKIE["data"]);',
             'line': 30, 'file': 'session.php'},
            {'type': 'Type Juggling', 'severity': 'HIGH', 'confidence': '85%',
             'code': 'if ($hash == $_GET["hash"]) {',
             'line': 12, 'file': 'verify.php'},
            {'type': 'Server-Side Request Forgery', 'severity': 'HIGH', 'confidence': '75%',
             'code': 'file_get_contents($_POST["url"]);',
             'line': 25, 'file': 'api/fetch.php'},
            {'type': 'Cross-Site Scripting', 'severity': 'HIGH', 'confidence': '85%',
             'code': '<?= $_GET["search"] ?>',
             'line': 15, 'file': 'search.php'},
            {'type': 'Cross-Site Scripting', 'severity': 'HIGH', 'confidence': '80%',
             'code': '{!! $request->input("content") !!}',
             'line': 20, 'file': 'views/post.blade.php'},
            {'type': 'Path Traversal', 'severity': 'HIGH', 'confidence': '85%',
             'code': 'readfile($_GET["file"]);',
             'line': 10, 'file': 'download.php'},
            {'type': 'PHAR Deserialization', 'severity': 'HIGH', 'confidence': '80%',
             'code': 'file_exists($_GET["path"]);',
             'line': 12, 'file': 'upload.php'},
            {'type': 'Cross-Site Scripting', 'severity': 'MEDIUM', 'confidence': '70%',
             'code': 'echo "Welcome, $username";',
             'line': 8, 'file': 'profile.php'},
            {'type': 'Header Injection', 'severity': 'HIGH', 'confidence': '80%',
             'code': 'header("Location: " . $_GET["url"]);',
             'line': 5, 'file': 'redirect.php'},
            {'type': 'LDAP Injection', 'severity': 'HIGH', 'confidence': '80%',
             'code': 'ldap_search($conn, "ou=users", "(uid=" . $_GET["user"] . ")");',
             'line': 15, 'file': 'auth/ldap.php'},
        ]

        fp_patterns = [
            {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '70%',
             'code': '$stmt = $db->prepare("SELECT * FROM users WHERE id = ?");',
             'line': 10, 'file': 'model.php'},
            {'type': 'Cross-Site Scripting', 'severity': 'MEDIUM', 'confidence': '50%',
             'code': 'echo htmlspecialchars($_GET["name"]);',
             'line': 5, 'file': 'view.php'},
            {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '65%',
             'code': '$db->query("SELECT * FROM posts WHERE id=" . intval($_GET["id"]))',
             'line': 10, 'file': 'post.php'},
            {'type': 'Command Injection', 'severity': 'HIGH', 'confidence': '70%',
             'code': 'exec("find " . escapeshellarg($_GET["path"]));',
             'line': 20, 'file': 'search.php'},
            {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '70%',
             'code': '// $db->query("SELECT * FROM users WHERE id=$_GET[id]")',
             'line': 5, 'file': 'old.php'},
            {'type': 'SQL Injection', 'severity': 'MEDIUM', 'confidence': '50%',
             'code': '$db->query("SELECT * FROM settings WHERE name=\'site_title\'")',
             'line': 15, 'file': 'config.php'},
            {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '65%',
             'code': '$user = User::find($request->input("id"));',
             'line': 10, 'file': 'UserController.php'},
            {'type': 'SQL Injection', 'severity': 'MEDIUM', 'confidence': '55%',
             'code': '$id = filter_var($_GET["id"], FILTER_VALIDATE_INT);',
             'line': 8, 'file': 'handler.php'},
            {'type': 'Weak Session Management', 'severity': 'MEDIUM', 'confidence': '50%',
             'code': 'session_start();',
             'line': 3, 'file': 'init.php'},
            {'type': 'Improper Error Handling', 'severity': 'LOW', 'confidence': '50%',
             'code': '} catch (Exception $e) {}',
             'line': 25, 'file': 'helper.php'},
            {'type': 'PHAR Deserialization', 'severity': 'HIGH', 'confidence': '60%',
             'code': 'if (file_exists($pluginPath)) {',
             'line': 30, 'file': 'plugins/loader.php'},
            {'type': 'Information Disclosure', 'severity': 'LOW', 'confidence': '40%',
             'code': "'phpinfo' => 'PHP Information',",
             'line': 150, 'file': 'language/english_utf-8.php'},
            {'type': 'PHPInfo Exposure', 'severity': 'MEDIUM', 'confidence': '50%',
             'code': "$features['phpinfo'] = 'Show PHP Info';",
             'line': 20, 'file': 'lang/english.php'},
            {'type': 'Information Disclosure', 'severity': 'LOW', 'confidence': '40%',
             'code': "'server_info' => 'Server Information Page',",
             'line': 200, 'file': 'language/german_utf-8.php'},
            {'type': 'Weak Session Management', 'severity': 'LOW', 'confidence': '45%',
             'code': 'if (!session_id()) { session_start(); }',
             'line': 5, 'file': 'bootstrap.php'},
            {'type': 'PHAR Deserialization', 'severity': 'HIGH', 'confidence': '55%',
             'code': '$size = filesize($cacheFile);',
             'line': 45, 'file': 'cache/manager.php'},
            {'type': 'Improper Error Handling', 'severity': 'LOW', 'confidence': '45%',
             'code': '} catch (\\Exception $e) { /* ignore */ }',
             'line': 35, 'file': 'utils.php'},
            {'type': 'Cross-Site Scripting', 'severity': 'MEDIUM', 'confidence': '50%',
             'code': '<?= htmlspecialchars($user->name) ?>',
             'line': 12, 'file': 'views/profile.php'},
            {'type': 'Cross-Site Scripting', 'severity': 'MEDIUM', 'confidence': '50%',
             'code': '{{ $user->name }}',
             'line': 8, 'file': 'resources/views/user.blade.php'},
        ]

        for pattern in tp_patterns:
            fv = self.extractor.extract(pattern, pattern['code'])
            features.append(fv)
            labels.append(True)

        for pattern in fp_patterns:
            fv = self.extractor.extract(pattern, pattern['code'])
            features.append(fv)
            labels.append(False)

        return features, labels


class FPClassifier:

    def __init__(self, model_dir: str = None, use_ml: bool = True):
        self.extractor = FeatureExtractor()
        self.heuristic = HeuristicClassifier()
        self.ml = None
        self.ml_v3 = None
        self.stats = {
            'total_classified': 0,
            'true_positives': 0,
            'false_positives': 0,
            'method': 'heuristic',
        }
        if use_ml:
            try:
                from core.ml_ensemble import MLClassifierV3
                self.ml_v3 = MLClassifierV3(model_dir)
                if self.ml_v3.is_trained():
                    self.stats['method'] = 'ml_v3'
                else:
                    self.ml_v3 = None
            except Exception:
                self.ml_v3 = None
            if self.ml_v3 is None:
                self.ml = MLClassifier(model_dir)
                if self.ml and self.ml.is_trained():
                    self.stats['method'] = 'ml'

    @dataclass
    class Result:
        is_tp: bool
        confidence: float
        reasoning: str
        score: float
        method: str
        classification: str = 'unknown'

    def classify(self, finding_dict: Dict, code: str = "",
                 file_lines: List[str] = None,
                 analysis: Optional[FileAnalysisResults] = None) -> 'FPClassifier.Result':
        features = self.extractor.extract(finding_dict, code, file_lines, analysis)

        _CRITICAL_TYPES = {
            'Arbitrary File Write', 'Arbitrary File Read',
            'Code Injection', 'Remote Code Execution',
            'Command Injection', 'Insecure Deserialization',
            'File Inclusion',
        }
        _PROPER_FILE_SANITIZERS = re.compile(
            r'\b(?:basename|realpath|is_uploaded_file|move_uploaded_file)\s*\(', re.I
        )
        vuln_type = finding_dict.get('type', '')
        code_line = finding_dict.get('code', '')
        needs_critical_override = (
            vuln_type in _CRITICAL_TYPES
            and not _PROPER_FILE_SANITIZERS.search(code_line)
        )

        if self.ml_v3 and self.ml_v3.is_trained():
            try:
                feat_dict = features.to_dict()
                code_ctx = features.code_context_raw if hasattr(features, 'code_context_raw') else ''
                is_tp, prob = self.ml_v3.predict(feat_dict, code_ctx)

                if needs_critical_override and not is_tp:
                    is_tp = True
                    prob = max(prob, 0.35)

                self.stats['total_classified'] += 1
                if is_tp:
                    self.stats['true_positives'] += 1
                else:
                    self.stats['false_positives'] += 1

                if prob < 0.25:
                    classification = 'safe'
                elif prob < 0.50:
                    classification = 'suspicious'
                else:
                    classification = 'vulnerable'

                return self.Result(
                    is_tp=is_tp,
                    confidence=abs(prob - 0.5) * 2,
                    reasoning=f"ML v3 ensemble (prob={prob:.2f}, class={classification})",
                    score=prob,
                    method='ml_v3',
                    classification=classification,
                )
            except Exception:
                pass

        if self.ml and self.ml.is_trained():
            try:
                is_tp, prob = self.ml.predict(features)

                if needs_critical_override and not is_tp:
                    is_tp = True
                    prob = max(prob, 0.35)

                self.stats['total_classified'] += 1
                if is_tp:
                    self.stats['true_positives'] += 1
                else:
                    self.stats['false_positives'] += 1

                if prob < 0.30:
                    classification = 'safe'
                elif prob < 0.55:
                    classification = 'suspicious'
                else:
                    classification = 'vulnerable'

                return self.Result(
                    is_tp=is_tp,
                    confidence=abs(prob - 0.5) * 2,
                    reasoning=f"ML model (prob={prob:.2f}, class={classification})",
                    score=prob,
                    method='ml',
                    classification=classification,
                )
            except Exception:
                pass

        is_tp, confidence, reasoning = self.heuristic.predict(features)
        self.stats['total_classified'] += 1
        if is_tp:
            self.stats['true_positives'] += 1
        else:
            self.stats['false_positives'] += 1

        score = 0.5 + (0.5 if is_tp else -0.5) * confidence

        return self.Result(
            is_tp=is_tp,
            confidence=confidence,
            reasoning=reasoning,
            score=score,
            method='heuristic',
        )

    def classify_batch(self, findings: List[Dict],
                       file_codes: Dict[str, str],
                       file_analyses: Optional[Dict[str, FileAnalysisResults]] = None
                       ) -> List[Dict]:
        results = []
        file_lines_cache = {}
        analysis_cache = {}

        if file_analyses is None and _HAS_CFG:
            file_analyses = {}
            re_engine = None
            if get_rule_engine:
                try:
                    re_engine = get_rule_engine()
                except Exception:
                    pass
            for filepath, code in file_codes.items():
                if filepath not in file_analyses and code:
                    try:
                        ar = build_file_analysis(filepath, code, re_engine)
                        if ar:
                            file_analyses[filepath] = ar
                    except Exception:
                        pass

        for f in findings:
            filepath = f.get('file', '')
            code = file_codes.get(filepath, '')

            if filepath not in file_lines_cache:
                file_lines_cache[filepath] = code.split('\n') if code else []

            analysis = file_analyses.get(filepath) if file_analyses else None

            result = self.classify(f, code, file_lines_cache[filepath], analysis)

            f['ml_is_tp'] = result.is_tp
            f['ml_confidence'] = round(result.confidence, 2)
            f['ml_reasoning'] = result.reasoning
            f['ml_method'] = result.method
            f['ml_score'] = round(result.score, 3)
            f['ml_classification'] = result.classification

            if result.is_tp:
                results.append(f)

        return results

    def train_from_fixtures(self, fixture_dir: str = None,
                            verbose: bool = False) -> Dict:
        if self.ml is None:
            self.ml = MLClassifier()

        gen = TrainingDataGenerator()

        all_features = []
        all_labels = []

        syn_features, syn_labels = gen.from_synthetic()
        all_features.extend(syn_features)
        all_labels.extend(syn_labels)
        if verbose:
            print(f"[ML] Synthetic: {len(syn_features)} samples")

        if fixture_dir is None:
            fixture_dir = str(Path(__file__).parent.parent / "tests" / "fixtures")

        if os.path.isdir(fixture_dir):
            fix_features, fix_labels = gen.from_fixture_dir(fixture_dir)
            all_features.extend(fix_features)
            all_labels.extend(fix_labels)
            if verbose:
                print(f"[ML] Fixtures: {len(fix_features)} samples")

        if len(all_features) < 10:
            if verbose:
                print(f"[ML] Not enough data ({len(all_features)} samples). "
                      f"Need at least 10.")
            return {'error': 'not enough data'}

        return self.ml.train(all_features, all_labels, verbose=verbose)
