#!/usr/bin/env python3
# apex/core - tron (@tron0x8)

import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any

from .rule_engine import get_rule_engine, RuleEngine
from .abstract_interp import AbstractState, TaintInfo, TaintLattice


_LARAVEL_VALIDATE_BLOCK = re.compile(
    r"""\$\w+->validate\s*\(\s*\[([^\]]*)\]""",
    re.DOTALL | re.IGNORECASE,
)

_VALIDATOR_MAKE_BLOCK = re.compile(
    r"""Validator::make\s*\([^,]+,\s*\[([^\]]*)\]""",
    re.DOTALL | re.IGNORECASE,
)

_VALIDATION_FIELD = re.compile(
    r"""['"](\w+)['"]\s*=>\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)

_MIDDLEWARE_ARROW = re.compile(
    r"""->middleware\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)

_MIDDLEWARE_ARRAY = re.compile(
    r"""->middleware\s*\(\s*\[([^\]]*)\]""",
    re.DOTALL | re.IGNORECASE,
)

_ROUTE_MIDDLEWARE = re.compile(
    r"""Route::middleware\s*\(\s*\[([^\]]*)\]""",
    re.DOTALL | re.IGNORECASE,
)

_MIDDLEWARE_GROUP = re.compile(
    r"""['"](\w+)['"]""",
)

_BLADE_ESCAPED = re.compile(r"""\{\{(?!\!)(.*?)\}\}""", re.DOTALL)
_BLADE_RAW = re.compile(r"""\{!!\s*(.*?)\s*!!\}""", re.DOTALL)

_ELOQUENT_WHERE = re.compile(
    r"""(\$\w+)\s*->\s*(?:where|orWhere|whereIn|whereNotIn"""
    r"""|whereBetween|whereNull|whereNotNull"""
    r"""|find|findOrFail|first|firstOrFail)\s*\(""",
    re.IGNORECASE,
)
_ELOQUENT_MODEL_CALL = re.compile(
    r"""(\w+)::\s*(?:where|find|findOrFail|all|create"""
    r"""|firstOrCreate|updateOrCreate)\s*\(""",
    re.IGNORECASE,
)
_DOCTRINE_QB = re.compile(
    r"""(\$\w+)\s*->\s*(?:createQueryBuilder|getRepository"""
    r"""|setParameter|expr)\s*\(""",
    re.IGNORECASE,
)
_PDO_PREPARE = re.compile(
    r"""(\$\w+)\s*->\s*prepare\s*\(""",
    re.IGNORECASE,
)

_ASSIGNMENT_LHS = re.compile(
    r"""(\$\w+)\s*=\s*""",
)


_DEFAULT_VALIDATION_MAP: Dict[str, Dict[str, Any]] = {
    "integer": {"php_type": "INT", "safe_for": ["SQL_INJECTION", "XSS"]},
    "numeric": {"php_type": "INT", "safe_for": ["SQL_INJECTION", "XSS"]},
    "email": {"php_type": "STRING", "safe_for": ["SQL_INJECTION"]},
    "boolean": {"php_type": "BOOL", "safe_for": ["SQL_INJECTION", "XSS", "COMMAND_INJECTION"]},
    "in": {"php_type": "STRING", "safe_for": ["SQL_INJECTION", "XSS", "COMMAND_INJECTION"]},
    "url": {"php_type": "STRING", "safe_for": ["XSS"]},
    "ip": {"php_type": "STRING", "safe_for": ["SQL_INJECTION", "XSS"]},
}


class FrameworkModelEngine:

    def __init__(self, rule_engine: RuleEngine) -> None:
        self.rule_engine = rule_engine


    def apply_validation_constraints(
        self,
        framework: str,
        code: str,
        taint_state: AbstractState,
    ) -> AbstractState:
        state = taint_state.copy()
        validation_map = self._get_validation_map(framework)
        if not validation_map:
            return state

        validated_fields = self._extract_validated_fields(code)
        if not validated_fields:
            return state

        for field_name, rules_string in validated_fields.items():
            individual_rules = [r.strip() for r in rules_string.split("|")]
            safe_types: Set[str] = set()

            for rule in individual_rules:
                rule_key = rule.split(":")[0]
                mapping = validation_map.get(rule_key)

                if mapping is None:
                    mapping = validation_map.get(f"{rule_key}:*")

                if mapping is not None:
                    safe_list = mapping.get("safe_for", [])
                    if isinstance(safe_list, list):
                        safe_types.update(safe_list)
                    elif isinstance(safe_list, str):
                        safe_types.add(safe_list)

            if not safe_types:
                continue

            var_candidates = [
                f"${field_name}",
                f"$request->{field_name}",
                f"$data['{field_name}']",
                f"$input['{field_name}']",
                f"$validated['{field_name}']",
            ]
            for var_name in var_candidates:
                existing = state.get(var_name)
                if existing.level <= TaintLattice.BOTTOM:
                    continue
                updated = existing.copy()
                updated.sanitized_types = updated.sanitized_types | safe_types
                if updated.effective_types() == set():
                    updated.level = TaintLattice.UNTAINTED
                state.set(var_name, updated)

        return state


    def detect_route_middleware(self, code: str) -> Set[str]:
        middleware: Set[str] = set()

        for match in _MIDDLEWARE_ARROW.finditer(code):
            middleware.add(match.group(1))

        for pattern in (_MIDDLEWARE_ARRAY, _ROUTE_MIDDLEWARE):
            for match in pattern.finditer(code):
                inner = match.group(1)
                for name_match in _MIDDLEWARE_GROUP.finditer(inner):
                    middleware.add(name_match.group(1))

        return middleware


    def detect_blade_escaping(self, template: str) -> Dict[int, bool]:
        escaping_map: Dict[int, bool] = {}
        lines = template.split("\n")

        for line_idx, line in enumerate(lines):
            line_number = line_idx + 1

            if _BLADE_RAW.search(line):
                escaping_map[line_number] = False

            if _BLADE_ESCAPED.search(line):
                if line_number not in escaping_map:
                    escaping_map[line_number] = True

        return escaping_map


    def detect_orm_usage(self, code: str) -> Set[str]:
        orm_vars: Set[str] = set()

        for match in _ELOQUENT_WHERE.finditer(code):
            orm_vars.add(match.group(1))

        for match in _ELOQUENT_MODEL_CALL.finditer(code):
            preceding = code[:match.start()]
            lhs_matches = list(_ASSIGNMENT_LHS.finditer(preceding))
            if lhs_matches:
                orm_vars.add(lhs_matches[-1].group(1))

        for match in _DOCTRINE_QB.finditer(code):
            orm_vars.add(match.group(1))

        for match in _PDO_PREPARE.finditer(code):
            orm_vars.add(match.group(1))

        return orm_vars


    def _get_validation_map(self, framework: str) -> Dict[str, Dict[str, Any]]:
        fw_def = self.rule_engine.get_framework(framework)
        if fw_def and fw_def.validation_type_map:
            return fw_def.validation_type_map
        return _DEFAULT_VALIDATION_MAP

    def _extract_validated_fields(self, code: str) -> Dict[str, str]:
        fields: Dict[str, str] = {}

        for pattern in (_LARAVEL_VALIDATE_BLOCK, _VALIDATOR_MAKE_BLOCK):
            for block_match in pattern.finditer(code):
                inner = block_match.group(1)
                for field_match in _VALIDATION_FIELD.finditer(inner):
                    field_name = field_match.group(1)
                    rules_str = field_match.group(2)
                    fields[field_name] = rules_str

        return fields
