#!/usr/bin/env python3
"""
APEX Rule Engine - Single source of truth for all security rules.
Loads sources, sinks, sanitizers, patterns, frameworks, and FP rules from YAML.
"""

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any, Tuple
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None


@dataclass
class SourceDef:
    name: str
    pattern: str
    taint_level: str  # HIGH, MEDIUM, LOW
    taint_types: List[str]
    category: str = "superglobal"

    @property
    def compiled_pattern(self):
        if not hasattr(self, '_compiled'):
            self._compiled = re.compile(self.pattern, re.IGNORECASE)
        return self._compiled


@dataclass
class SinkDef:
    name: str
    pattern: str
    vuln_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    arg_positions: List[int] = field(default_factory=lambda: [0])
    cwe: str = ""
    description: str = ""

    @property
    def compiled_pattern(self):
        if not hasattr(self, '_compiled'):
            self._compiled = re.compile(self.pattern, re.IGNORECASE)
        return self._compiled


@dataclass
class SanitizerDef:
    name: str
    pattern: str
    protects_against: List[str]
    strength: str = "strong"  # strong, weak

    @property
    def compiled_pattern(self):
        if not hasattr(self, '_compiled'):
            self._compiled = re.compile(self.pattern, re.IGNORECASE)
        return self._compiled


@dataclass
class PatternDef:
    regex: str
    vuln_type: str
    severity: str
    cwe: str = ""
    description: str = ""
    remediation: str = ""

    @property
    def compiled_regex(self):
        if not hasattr(self, '_compiled'):
            self._compiled = re.compile(self.regex, re.IGNORECASE)
        return self._compiled


@dataclass
class FrameworkDef:
    name: str
    detect_patterns: List[str] = field(default_factory=list)
    sources: Dict[str, str] = field(default_factory=dict)
    sinks: Dict[str, str] = field(default_factory=dict)
    sanitizers: Dict[str, Any] = field(default_factory=dict)
    safe_patterns: List[str] = field(default_factory=list)
    validation_type_map: Dict[str, Any] = field(default_factory=dict)
    middleware_effects: Dict[str, Any] = field(default_factory=dict)
    template_escaping: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FPRule:
    name: str
    category: str  # comment, dead_code, orm, prepared_stmt, type_cast, etc.
    pattern: str
    applies_to: List[str] = field(default_factory=list)  # vuln types
    description: str = ""

    @property
    def compiled_pattern(self):
        if not hasattr(self, '_compiled'):
            self._compiled = re.compile(self.pattern, re.IGNORECASE)
        return self._compiled


@dataclass
class CWEEntry:
    code: str
    name: str


class RuleEngine:
    """Loads and provides access to all YAML-defined rules."""

    def __init__(self, rules_dir: Optional[str] = None):
        if rules_dir is None:
            rules_dir = str(Path(__file__).parent.parent / 'rules')
        self.rules_dir = rules_dir
        self.sources: Dict[str, SourceDef] = {}
        self.sinks: Dict[str, SinkDef] = {}
        self.sanitizers: Dict[str, SanitizerDef] = {}
        self.patterns: Dict[str, List[PatternDef]] = {}
        self.frameworks: Dict[str, FrameworkDef] = {}
        self.fp_rules: Dict[str, List[FPRule]] = {}
        self.cwe_map: Dict[str, CWEEntry] = {}
        self._load_all()

    def _load_all(self):
        """Load all YAML rule files."""
        if yaml is None:
            # Fallback: no YAML available, rules will be empty
            return
        self._load_sources()
        self._load_sinks()
        self._load_sanitizers()
        self._load_patterns()
        self._load_frameworks()
        self._load_fp_rules()

    def _load_yaml(self, filename: str) -> Any:
        """Load a YAML file from the rules directory."""
        filepath = os.path.join(self.rules_dir, filename)
        if not os.path.exists(filepath):
            return {}
        with open(filepath, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}

    def _load_sources(self):
        data = self._load_yaml('sources.yml')
        self.tainted_server_keys = []
        for category, sources in data.items():
            if not isinstance(sources, list):
                continue
            if category == 'tainted_server_keys':
                self.tainted_server_keys = [s for s in sources if isinstance(s, str)]
                continue
            for src in sources:
                if not isinstance(src, dict):
                    continue
                name = src.get('name', '')
                self.sources[name] = SourceDef(
                    name=name,
                    pattern=src.get('pattern', ''),
                    taint_level=src.get('taint_level', 'HIGH'),
                    taint_types=src.get('taint_types', []),
                    category=category,
                )

    def _load_sinks(self):
        data = self._load_yaml('sinks.yml')
        for vuln_type, sinks in data.items():
            if not isinstance(sinks, list):
                continue
            for sink in sinks:
                name = sink.get('name', '')
                self.sinks[name] = SinkDef(
                    name=name,
                    pattern=sink.get('pattern', name.replace('(', r'\(').replace(')', r'\)')),
                    vuln_type=vuln_type,
                    severity=sink.get('severity', 'HIGH'),
                    arg_positions=sink.get('arg_positions', [0]),
                    cwe=sink.get('cwe', ''),
                    description=sink.get('description', ''),
                )

    def _load_sanitizers(self):
        data = self._load_yaml('sanitizers.yml')
        for category, sanitizers in data.items():
            if not isinstance(sanitizers, list):
                continue
            for san in sanitizers:
                name = san.get('name', '')
                self.sanitizers[name] = SanitizerDef(
                    name=name,
                    pattern=san.get('pattern', ''),
                    protects_against=san.get('protects_against', []),
                    strength=san.get('strength', 'strong'),
                )

    def _load_patterns(self):
        data = self._load_yaml('patterns.yml')
        for vuln_type, patterns in data.items():
            if not isinstance(patterns, list):
                continue
            self.patterns[vuln_type] = []
            for pat in patterns:
                self.patterns[vuln_type].append(PatternDef(
                    regex=pat.get('regex', ''),
                    vuln_type=vuln_type,
                    severity=pat.get('severity', 'HIGH'),
                    cwe=pat.get('cwe', ''),
                    description=pat.get('description', ''),
                    remediation=pat.get('remediation', ''),
                ))

    def _load_frameworks(self):
        fw_dir = os.path.join(self.rules_dir, 'frameworks')
        if not os.path.isdir(fw_dir):
            return
        for fname in os.listdir(fw_dir):
            if not fname.endswith('.yml'):
                continue
            data = self._load_yaml(os.path.join('frameworks', fname))
            if not data:
                continue
            name = data.get('name', fname.replace('.yml', ''))
            self.frameworks[name.lower()] = FrameworkDef(
                name=name,
                detect_patterns=data.get('detect_patterns', []),
                sources=data.get('sources', {}),
                sinks=data.get('sinks', {}),
                sanitizers=data.get('sanitizers', {}),
                safe_patterns=data.get('safe_patterns', []),
                validation_type_map=data.get('validation_type_map', {}),
                middleware_effects=data.get('middleware_effects', {}),
                template_escaping=data.get('template_escaping', {}),
            )

    def _load_fp_rules(self):
        data = self._load_yaml('fp_rules.yml')
        for category, rules in data.items():
            if not isinstance(rules, list):
                continue
            self.fp_rules[category] = []
            for rule in rules:
                self.fp_rules[category].append(FPRule(
                    name=rule.get('name', ''),
                    category=category,
                    pattern=rule.get('pattern', ''),
                    applies_to=rule.get('applies_to', []),
                    description=rule.get('description', ''),
                ))

    # ==================== Query Methods ====================

    def get_sources(self, category: Optional[str] = None) -> Dict[str, SourceDef]:
        if category is None:
            return self.sources
        return {k: v for k, v in self.sources.items() if v.category == category}

    def get_sinks(self, vuln_type: Optional[str] = None) -> Dict[str, SinkDef]:
        if vuln_type is None:
            return self.sinks
        return {k: v for k, v in self.sinks.items() if v.vuln_type == vuln_type}

    def get_sanitizers(self, vuln_type: Optional[str] = None) -> Dict[str, SanitizerDef]:
        if vuln_type is None:
            return self.sanitizers
        return {k: v for k, v in self.sanitizers.items()
                if vuln_type in v.protects_against}

    def get_patterns(self, vuln_type: Optional[str] = None) -> Dict[str, List[PatternDef]]:
        if vuln_type is None:
            return self.patterns
        return {vuln_type: self.patterns.get(vuln_type, [])}

    def get_framework(self, name: str) -> Optional[FrameworkDef]:
        return self.frameworks.get(name.lower())

    def get_fp_rules(self, category: Optional[str] = None) -> Dict[str, List[FPRule]]:
        if category is None:
            return self.fp_rules
        return {category: self.fp_rules.get(category, [])}

    def is_source(self, name: str) -> bool:
        return name in self.sources

    def is_sink(self, name: str) -> bool:
        return name in self.sinks

    def is_sanitizer(self, name: str) -> bool:
        return name in self.sanitizers

    def get_sink_vuln_type(self, name: str) -> Optional[str]:
        sink = self.sinks.get(name)
        return sink.vuln_type if sink else None

    def get_sanitizer_protections(self, name: str) -> List[str]:
        san = self.sanitizers.get(name)
        return san.protects_against if san else []

    def get_source_taint_types(self, name: str) -> List[str]:
        src = self.sources.get(name)
        return src.taint_types if src else []

    def get_source_taint_level(self, name: str) -> str:
        src = self.sources.get(name)
        return src.taint_level if src else 'LOW'


# Module-level singleton for convenience
_default_engine: Optional[RuleEngine] = None

def get_rule_engine(rules_dir: Optional[str] = None) -> RuleEngine:
    """Get or create the default RuleEngine singleton."""
    global _default_engine
    if _default_engine is None or rules_dir is not None:
        _default_engine = RuleEngine(rules_dir)
    return _default_engine
