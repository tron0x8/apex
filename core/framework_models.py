#!/usr/bin/env python3
"""
APEX Framework Deep Models - Framework-specific validation and routing models.

Applies framework-aware analysis to reduce false positives by understanding
how frameworks like Laravel, Symfony, and others validate input, protect
routes with middleware, escape template output, and use ORM abstractions
that prevent injection attacks.

This module bridges the gap between raw taint analysis and the semantic
guarantees provided by well-known PHP frameworks.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any

from .rule_engine import get_rule_engine, RuleEngine
from .abstract_interp import AbstractState, TaintInfo, TaintLattice


# ---------------------------------------------------------------------------
# Compiled regex patterns for framework code analysis
# ---------------------------------------------------------------------------

# Laravel validation: $request->validate([...]) or Validator::make($data, [...])
_LARAVEL_VALIDATE_BLOCK = re.compile(
    r"""\$\w+->validate\s*\(\s*\[([^\]]*)\]""",
    re.DOTALL | re.IGNORECASE,
)

_VALIDATOR_MAKE_BLOCK = re.compile(
    r"""Validator::make\s*\([^,]+,\s*\[([^\]]*)\]""",
    re.DOTALL | re.IGNORECASE,
)

# Individual field => 'rules' pairs inside a validation array
_VALIDATION_FIELD = re.compile(
    r"""['"](\w+)['"]\s*=>\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)

# Route middleware declarations
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

# Blade template escaping patterns
_BLADE_ESCAPED = re.compile(r"""\{\{(?!\!)(.*?)\}\}""", re.DOTALL)
_BLADE_RAW = re.compile(r"""\{!!\s*(.*?)\s*!!\}""", re.DOTALL)

# ORM / query-builder usage patterns that protect against SQL injection
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

# Variable name inside Eloquent chains:  $var = Model::where(...)...
_ASSIGNMENT_LHS = re.compile(
    r"""(\$\w+)\s*=\s*""",
)


# ---------------------------------------------------------------------------
# Default validation rule -> type / safety mapping (used when YAML is absent)
# ---------------------------------------------------------------------------

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
    """Apply framework-specific validation and routing models to taint state.

    Works with the RuleEngine to load ``validation_type_map``,
    ``middleware_effects``, and ``template_escaping`` data from the
    per-framework YAML files under ``rules/frameworks/``.  When YAML data
    is unavailable, sensible built-in defaults are used instead.
    """

    def __init__(self, rule_engine: RuleEngine) -> None:
        self.rule_engine = rule_engine

    # ------------------------------------------------------------------
    # Validation constraint narrowing
    # ------------------------------------------------------------------

    def apply_validation_constraints(
        self,
        framework: str,
        code: str,
        taint_state: AbstractState,
    ) -> AbstractState:
        """Narrow taint for variables that pass framework validation rules.

        For each field found inside a ``$request->validate([...])`` or
        ``Validator::make(...)`` call, the corresponding validation rules
        are inspected.  When a rule is known to guarantee a safe type
        (e.g. ``'integer'`` means the value is a safe INT), the taint
        information for the matching variable is updated: the
        ``sanitized_types`` set grows to include the vulnerability classes
        that the validation makes safe, and the effective taint level may
        be reduced accordingly.

        Args:
            framework: Framework name (e.g. ``'laravel'``).
            code: PHP source code to scan for validation blocks.
            taint_state: Current abstract taint state to refine.

        Returns:
            A (possibly modified) ``AbstractState`` with reduced taint
            for validated variables.
        """
        state = taint_state.copy()
        validation_map = self._get_validation_map(framework)
        if not validation_map:
            return state

        # Collect all validated field -> rules mappings from the code
        validated_fields = self._extract_validated_fields(code)
        if not validated_fields:
            return state

        for field_name, rules_string in validated_fields.items():
            individual_rules = [r.strip() for r in rules_string.split("|")]
            safe_types: Set[str] = set()

            for rule in individual_rules:
                # Handle parameterised rules like "in:a,b,c" or "max:255"
                rule_key = rule.split(":")[0]
                mapping = validation_map.get(rule_key)

                # Wildcard lookup: "in:*" matches any "in:..." rule
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

            # Apply safety to any variable that looks like it holds this field.
            # Common Laravel patterns: $field, $request->field, $data['field']
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
                # If every remaining taint type is now sanitized, lower the level
                if updated.effective_types() == set():
                    updated.level = TaintLattice.UNTAINTED
                state.set(var_name, updated)

        return state

    # ------------------------------------------------------------------
    # Route middleware detection
    # ------------------------------------------------------------------

    def detect_route_middleware(self, code: str) -> Set[str]:
        """Detect middleware names applied to routes in the given code.

        Recognises patterns such as::

            ->middleware('auth')
            ->middleware(['csrf', 'throttle'])
            Route::middleware(['auth', 'verified'])

        Args:
            code: PHP source code (typically a routes file).

        Returns:
            A set of middleware name strings found in the code.
        """
        middleware: Set[str] = set()

        # ->middleware('single')
        for match in _MIDDLEWARE_ARROW.finditer(code):
            middleware.add(match.group(1))

        # ->middleware(['a', 'b']) and Route::middleware(['a', 'b'])
        for pattern in (_MIDDLEWARE_ARRAY, _ROUTE_MIDDLEWARE):
            for match in pattern.finditer(code):
                inner = match.group(1)
                for name_match in _MIDDLEWARE_GROUP.finditer(inner):
                    middleware.add(name_match.group(1))

        return middleware

    # ------------------------------------------------------------------
    # Blade template escaping analysis
    # ------------------------------------------------------------------

    def detect_blade_escaping(self, template: str) -> Dict[int, bool]:
        """Analyse a Blade template for escaped vs. raw output expressions.

        ``{{ $var }}`` is auto-escaped (``htmlspecialchars``), while
        ``{!! $var !!}`` outputs raw HTML.

        Args:
            template: Blade template source text.

        Returns:
            A dict mapping 1-based line numbers to ``True`` (escaped)
            or ``False`` (raw).  Lines with no output expression are
            omitted.
        """
        escaping_map: Dict[int, bool] = {}
        lines = template.split("\n")

        for line_idx, line in enumerate(lines):
            line_number = line_idx + 1

            # Check for raw output first (more specific pattern)
            if _BLADE_RAW.search(line):
                escaping_map[line_number] = False

            # Check for auto-escaped output
            if _BLADE_ESCAPED.search(line):
                # Only mark as escaped if this line was not already marked raw.
                # A line can contain both patterns; raw takes priority for safety.
                if line_number not in escaping_map:
                    escaping_map[line_number] = True

        return escaping_map

    # ------------------------------------------------------------------
    # ORM usage detection
    # ------------------------------------------------------------------

    def detect_orm_usage(self, code: str) -> Set[str]:
        """Detect variables that flow through ORM / query-builder methods.

        Variables used via Eloquent (``->where()``, ``->find()``),
        Doctrine (``createQueryBuilder``, ``setParameter``), or PDO
        prepared statements (``->prepare()``) are considered safe from
        SQL injection because the framework binds parameters.

        Args:
            code: PHP source code to analyse.

        Returns:
            A set of PHP variable names (including the ``$`` prefix)
            that are ORM-protected.
        """
        orm_vars: Set[str] = set()

        # Eloquent instance method chains: $query->where(...)
        for match in _ELOQUENT_WHERE.finditer(code):
            orm_vars.add(match.group(1))

        # Eloquent static calls: User::where(...)  -- record the $var on LHS
        for match in _ELOQUENT_MODEL_CALL.finditer(code):
            # Look backwards from this match for an assignment LHS
            preceding = code[:match.start()]
            lhs_matches = list(_ASSIGNMENT_LHS.finditer(preceding))
            if lhs_matches:
                orm_vars.add(lhs_matches[-1].group(1))

        # Doctrine QueryBuilder / Repository
        for match in _DOCTRINE_QB.finditer(code):
            orm_vars.add(match.group(1))

        # PDO prepared statements
        for match in _PDO_PREPARE.finditer(code):
            orm_vars.add(match.group(1))

        return orm_vars

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_validation_map(self, framework: str) -> Dict[str, Dict[str, Any]]:
        """Return the validation_type_map for *framework*.

        Tries the RuleEngine first; falls back to built-in defaults.
        """
        fw_def = self.rule_engine.get_framework(framework)
        if fw_def and fw_def.validation_type_map:
            return fw_def.validation_type_map
        return _DEFAULT_VALIDATION_MAP

    def _extract_validated_fields(self, code: str) -> Dict[str, str]:
        """Parse validation blocks and return ``{field: rules_string}``."""
        fields: Dict[str, str] = {}

        for pattern in (_LARAVEL_VALIDATE_BLOCK, _VALIDATOR_MAKE_BLOCK):
            for block_match in pattern.finditer(code):
                inner = block_match.group(1)
                for field_match in _VALIDATION_FIELD.finditer(inner):
                    field_name = field_match.group(1)
                    rules_str = field_match.group(2)
                    fields[field_name] = rules_str

        return fields
