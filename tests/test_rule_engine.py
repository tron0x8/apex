#!/usr/bin/env python3
"""
Tests for core/rule_engine.py - the YAML-based rule loader and query engine.
"""

import pytest
import os
import sys
import re
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.rule_engine import (
    RuleEngine, get_rule_engine,
    SourceDef, SinkDef, SanitizerDef, PatternDef, FrameworkDef, FPRule,
)

# Use the real rules directory shipped with the project
RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")


@pytest.fixture(scope="module")
def engine():
    """Create a RuleEngine loaded from the real rules/ directory."""
    return RuleEngine(RULES_DIR)


# ---------- Loading tests ----------

class TestLoadSources:
    def test_load_sources(self, engine):
        """Sources YAML is loaded; $_GET exists with correct taint_types."""
        sources = engine.get_sources()
        assert len(sources) > 0, "No sources loaded"
        assert "$_GET" in sources
        src = sources["$_GET"]
        assert isinstance(src, SourceDef)
        assert "SQL" in src.taint_types
        assert "XSS" in src.taint_types
        assert src.taint_level == "HIGH"
        assert src.category == "superglobals"


class TestLoadSinks:
    def test_load_sinks(self, engine):
        """Sinks YAML is loaded; mysql_query maps to SQL_INJECTION."""
        sinks = engine.get_sinks()
        assert len(sinks) > 0, "No sinks loaded"
        assert "mysql_query" in sinks
        sink = sinks["mysql_query"]
        assert isinstance(sink, SinkDef)
        assert sink.vuln_type == "SQL_INJECTION"
        assert sink.severity == "CRITICAL"
        assert sink.cwe == "CWE-89"


class TestLoadSanitizers:
    def test_load_sanitizers(self, engine):
        """Sanitizers YAML is loaded; htmlspecialchars protects against XSS."""
        sanitizers = engine.get_sanitizers()
        assert len(sanitizers) > 0, "No sanitizers loaded"
        assert "htmlspecialchars" in sanitizers
        san = sanitizers["htmlspecialchars"]
        assert isinstance(san, SanitizerDef)
        assert "XSS" in san.protects_against
        assert san.strength == "strong"


class TestLoadPatterns:
    def test_load_patterns(self, engine):
        """Patterns YAML is loaded with at least 100 total patterns."""
        patterns = engine.get_patterns()
        assert len(patterns) > 0, "No pattern categories loaded"
        total = sum(len(pats) for pats in patterns.values())
        assert total >= 100, f"Expected >= 100 patterns, got {total}"
        # Verify SQL_INJECTION patterns exist
        assert "SQL_INJECTION" in patterns
        for pat in patterns["SQL_INJECTION"]:
            assert isinstance(pat, PatternDef)


class TestLoadFrameworks:
    def test_load_frameworks(self, engine):
        """Frameworks loaded from YAML files; laravel exists with detect_patterns."""
        fw = engine.get_framework("laravel")
        assert fw is not None, "Laravel framework not loaded"
        assert isinstance(fw, FrameworkDef)
        assert fw.name == "Laravel"
        assert len(fw.detect_patterns) > 0
        assert "artisan" in fw.detect_patterns


class TestLoadFPRules:
    def test_load_fp_rules(self, engine):
        """FP rules loaded with multiple categories."""
        fp_rules = engine.get_fp_rules()
        assert len(fp_rules) >= 3, f"Expected >= 3 FP categories, got {len(fp_rules)}"
        assert "comment_patterns" in fp_rules
        assert "dead_code_patterns" in fp_rules
        for category, rules in fp_rules.items():
            for rule in rules:
                assert isinstance(rule, FPRule)
                assert rule.category == category


# ---------- Query / filter tests ----------

class TestGetSourcesByCategory:
    def test_get_sources_by_category(self, engine):
        """Filtering sources by category returns only that category."""
        superglobals = engine.get_sources(category="superglobals")
        assert "$_GET" in superglobals
        assert "$_POST" in superglobals
        # Input-function sources should NOT appear in superglobals
        for name, src in superglobals.items():
            assert src.category == "superglobals"

        input_funcs = engine.get_sources(category="input_functions")
        assert len(input_funcs) > 0
        for name, src in input_funcs.items():
            assert src.category == "input_functions"


class TestGetSinksByVulnType:
    def test_get_sinks_by_vuln_type(self, engine):
        """Filtering sinks by vuln_type returns only matching sinks."""
        sql_sinks = engine.get_sinks(vuln_type="SQL_INJECTION")
        assert "mysql_query" in sql_sinks
        for name, sink in sql_sinks.items():
            assert sink.vuln_type == "SQL_INJECTION"

        # eval is in CODE_INJECTION, not SQL_INJECTION
        assert "eval" not in sql_sinks
        code_sinks = engine.get_sinks(vuln_type="CODE_INJECTION")
        assert "eval" in code_sinks


class TestIsSourceSinkSanitizer:
    def test_is_source_sink_sanitizer(self, engine):
        """Boolean check helpers return correct results."""
        assert engine.is_source("$_GET") is True
        assert engine.is_source("$_POST") is True
        assert engine.is_source("not_a_source") is False

        assert engine.is_sink("mysql_query") is True
        assert engine.is_sink("eval") is True
        assert engine.is_sink("not_a_sink") is False

        assert engine.is_sanitizer("htmlspecialchars") is True
        assert engine.is_sanitizer("intval") is True
        assert engine.is_sanitizer("not_a_sanitizer") is False


class TestPatternCompiledRegex:
    def test_pattern_compiled_regex(self, engine):
        """PatternDef.compiled_regex returns a usable compiled regex."""
        sql_patterns = engine.get_patterns(vuln_type="SQL_INJECTION")
        pats = sql_patterns.get("SQL_INJECTION", [])
        assert len(pats) > 0
        first = pats[0]
        compiled = first.compiled_regex
        assert isinstance(compiled, re.Pattern)
        # The same object should be returned on second access (cached)
        assert first.compiled_regex is compiled


class TestSingleton:
    def test_singleton(self):
        """get_rule_engine returns the same instance on repeated calls."""
        # Reset the module-level singleton so we get a fresh one
        import core.rule_engine as mod
        mod._default_engine = None

        eng1 = get_rule_engine(RULES_DIR)
        eng2 = get_rule_engine()
        assert eng1 is eng2


class TestNonexistentRulesDir:
    def test_nonexistent_rules_dir(self):
        """RuleEngine handles a missing rules directory gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            missing = os.path.join(tmpdir, "no_such_dir")
            engine = RuleEngine(missing)
            assert len(engine.get_sources()) == 0
            assert len(engine.get_sinks()) == 0
            assert len(engine.get_sanitizers()) == 0
            assert len(engine.get_patterns()) == 0
            assert len(engine.get_fp_rules()) == 0


# ---------- Convenience accessor tests ----------

class TestAccessors:
    def test_get_sink_vuln_type(self, engine):
        """get_sink_vuln_type returns the vuln_type string for known sinks."""
        assert engine.get_sink_vuln_type("eval") == "CODE_INJECTION"
        assert engine.get_sink_vuln_type("mysql_query") == "SQL_INJECTION"
        assert engine.get_sink_vuln_type("nonexistent") is None

    def test_get_sanitizer_protections(self, engine):
        """get_sanitizer_protections returns the protects_against list."""
        prots = engine.get_sanitizer_protections("intval")
        assert isinstance(prots, list)
        assert "SQL_INJECTION" in prots
        assert engine.get_sanitizer_protections("nonexistent") == []

    def test_get_source_taint_types(self, engine):
        """get_source_taint_types returns the taint_types list for a source."""
        types = engine.get_source_taint_types("$_GET")
        assert isinstance(types, list)
        assert "SQL" in types
        assert "XSS" in types
        assert engine.get_source_taint_types("nonexistent") == []
