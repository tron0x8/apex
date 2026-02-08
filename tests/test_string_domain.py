#!/usr/bin/env python3
"""Tests for core/string_domain.py -- string construction and context-aware sink checking."""

import pytest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.string_domain import StringFragment, StringValue, StringAnalyzer


# ---------------------------------------------------------------------------
# StringFragment
# ---------------------------------------------------------------------------

class TestStringFragment:
    def test_fragment_copy(self):
        """copy() produces an independent deep copy."""
        frag = StringFragment(
            value="hello",
            tainted=True,
            taint_types={"SQL", "XSS"},
            source="$_GET['x']",
        )
        copied = frag.copy()

        assert copied.value == frag.value
        assert copied.tainted == frag.tainted
        assert copied.taint_types == frag.taint_types
        assert copied.source == frag.source

        # Mutating the copy must not affect the original.
        copied.taint_types.add("COMMAND")
        assert "COMMAND" not in frag.taint_types


# ---------------------------------------------------------------------------
# StringValue -- query helpers
# ---------------------------------------------------------------------------

class TestStringValue:
    def test_string_value_literal(self):
        """is_fully_literal() is True when all fragments are literal and untainted."""
        sv = StringValue([
            StringFragment(value="SELECT 1", tainted=False),
        ])
        assert sv.is_fully_literal() is True

        # Empty StringValue is considered fully literal.
        assert StringValue().is_fully_literal() is True

        # A tainted fragment makes it non-literal.
        sv2 = StringValue([
            StringFragment(value="hello", tainted=False),
            StringFragment(value=None, tainted=True, taint_types={"SQL"}),
        ])
        assert sv2.is_fully_literal() is False

    def test_string_value_tainted(self):
        """has_tainted_fragment() detects tainted fragments."""
        clean = StringValue([StringFragment(value="safe", tainted=False)])
        assert clean.has_tainted_fragment() is False

        dirty = StringValue([
            StringFragment(value="prefix", tainted=False),
            StringFragment(value=None, tainted=True, taint_types={"XSS"}),
        ])
        assert dirty.has_tainted_fragment() is True

    def test_string_value_tainted_positions(self):
        """get_tainted_positions() returns correct indices."""
        sv = StringValue([
            StringFragment(value="a", tainted=False),
            StringFragment(value=None, tainted=True),
            StringFragment(value="b", tainted=False),
            StringFragment(value=None, tainted=True),
        ])
        assert sv.get_tainted_positions() == [1, 3]

    def test_string_value_literal_text(self):
        """get_literal_text() reconstructs text with {?} for unknown fragments."""
        sv = StringValue([
            StringFragment(value="SELECT * FROM users WHERE id=", tainted=False),
            StringFragment(value=None, tainted=True, taint_types={"SQL"}),
            StringFragment(value=" LIMIT 10", tainted=False),
        ])
        assert sv.get_literal_text() == "SELECT * FROM users WHERE id={?} LIMIT 10"

    def test_string_value_concat(self):
        """concat() produces a new StringValue joining both."""
        left = StringValue([StringFragment(value="hello", tainted=False)])
        right = StringValue([StringFragment(value=None, tainted=True, taint_types={"XSS"})])

        combined = left.concat(right)
        assert len(combined.fragments) == 2
        assert combined.fragments[0].value == "hello"
        assert combined.fragments[1].tainted is True

    def test_string_value_concat_merge_literals(self):
        """concat() merges adjacent untainted literal fragments."""
        left = StringValue([StringFragment(value="hello ", tainted=False)])
        right = StringValue([StringFragment(value="world", tainted=False)])

        combined = left.concat(right)
        assert len(combined.fragments) == 1
        assert combined.fragments[0].value == "hello world"
        assert combined.fragments[0].tainted is False

    def test_string_value_interpolate(self):
        """interpolate() replaces $var references with StringValues from the map."""
        template = StringValue([
            StringFragment(value="Hello $name, welcome!", tainted=False),
        ])
        var_map = {
            "$name": StringValue([
                StringFragment(value=None, tainted=True, taint_types={"XSS"}, source="$_GET['name']"),
            ]),
        }
        result = template.interpolate(var_map)

        # Should have three fragments: "Hello ", <tainted>, ", welcome!"
        assert len(result.fragments) == 3
        assert result.fragments[0].value == "Hello "
        assert result.fragments[0].tainted is False
        assert result.fragments[1].tainted is True
        assert result.fragments[1].source == "$_GET['name']"
        assert result.fragments[2].value == ", welcome!"
        assert result.fragments[2].tainted is False

    def test_string_value_get_all_taint_types(self):
        """get_all_taint_types() collects types across all tainted fragments."""
        sv = StringValue([
            StringFragment(value="a", tainted=False),
            StringFragment(value=None, tainted=True, taint_types={"SQL"}),
            StringFragment(value=None, tainted=True, taint_types={"XSS", "COMMAND"}),
        ])
        assert sv.get_all_taint_types() == {"SQL", "XSS", "COMMAND"}

    def test_string_value_get_all_sources(self):
        """get_all_sources() collects source identifiers from tainted fragments."""
        sv = StringValue([
            StringFragment(value=None, tainted=True, source="$_GET['a']"),
            StringFragment(value=None, tainted=True, source="$_POST['b']"),
        ])
        assert sv.get_all_sources() == {"$_GET['a']", "$_POST['b']"}


# ---------------------------------------------------------------------------
# StringAnalyzer -- context-aware sink checking
# ---------------------------------------------------------------------------

class TestStringAnalyzerSinkContext:
    """Tests for StringAnalyzer.check_sink_context().

    These tests construct StringValue objects directly and invoke the
    context analyser without needing a full AST.  The StringAnalyzer
    falls back to keyword-based heuristics for sink-to-vuln-type mapping
    when no exact rule-engine match is found.
    """

    def _analyzer(self):
        """Return a StringAnalyzer instance (uses default rule engine)."""
        return StringAnalyzer()

    # -- SQL contexts --------------------------------------------------------

    def test_sql_context_where(self):
        """Tainted data in a WHERE clause is high risk."""
        sv = StringValue([
            StringFragment(value="SELECT * FROM users WHERE id=", tainted=False),
            StringFragment(value=None, tainted=True, taint_types={"SQL"}, source="$_GET['id']"),
        ])
        # Use a sink name not in the rule engine so the keyword heuristic
        # resolves to "SQL" and the SQL-specific context handler runs.
        result = self._analyzer().check_sink_context("custom_query", sv)
        assert result["dangerous"] is True
        assert result["risk_level"] == "high"
        assert 1 in result["tainted_positions"]

    def test_sql_context_table(self):
        """Tainted data in a table-name position is medium risk."""
        sv = StringValue([
            StringFragment(value="SELECT * FROM ", tainted=False),
            StringFragment(value=None, tainted=True, taint_types={"SQL"}, source="$_GET['tbl']"),
        ])
        result = self._analyzer().check_sink_context("custom_query", sv)
        assert result["dangerous"] is True
        assert result["risk_level"] == "medium"

    # -- XSS contexts --------------------------------------------------------

    def test_xss_context_attribute(self):
        """Tainted data inside an HTML attribute is high risk."""
        sv = StringValue([
            StringFragment(value='<input value="', tainted=False),
            StringFragment(value=None, tainted=True, taint_types={"XSS"}, source="$_GET['v']"),
            StringFragment(value='">', tainted=False),
        ])
        result = self._analyzer().check_sink_context("echo", sv)
        assert result["dangerous"] is True
        assert result["risk_level"] == "high"

    def test_xss_context_comment(self):
        """Tainted data inside an HTML comment is low risk."""
        sv = StringValue([
            StringFragment(value="<!-- debug: ", tainted=False),
            StringFragment(value=None, tainted=True, taint_types={"XSS"}, source="$_GET['d']"),
            StringFragment(value=" -->", tainted=False),
        ])
        result = self._analyzer().check_sink_context("echo", sv)
        assert result["dangerous"] is False
        assert result["risk_level"] == "low"

    # -- COMMAND contexts ----------------------------------------------------

    def test_cmd_context_executable(self):
        """Tainted data as the command itself (position 0) is high risk."""
        sv = StringValue([
            StringFragment(value=None, tainted=True, taint_types={"COMMAND"}, source="$_GET['cmd']"),
            StringFragment(value=" --flag", tainted=False),
        ])
        # Use a sink name triggering the keyword heuristic for COMMAND.
        result = self._analyzer().check_sink_context("custom_exec", sv)
        assert result["dangerous"] is True
        assert result["risk_level"] == "high"

    def test_cmd_context_argument(self):
        """Tainted data used as a command argument is medium risk."""
        sv = StringValue([
            StringFragment(value="ls -la ", tainted=False),
            StringFragment(value=None, tainted=True, taint_types={"COMMAND"}, source="$_GET['dir']"),
        ])
        result = self._analyzer().check_sink_context("custom_exec", sv)
        assert result["dangerous"] is True
        assert result["risk_level"] == "medium"

    # -- No taint ------------------------------------------------------------

    def test_no_taint_safe(self):
        """A fully literal string with no tainted fragments is low risk."""
        sv = StringValue([
            StringFragment(value="SELECT 1", tainted=False),
        ])
        result = self._analyzer().check_sink_context("custom_query", sv)
        assert result["dangerous"] is False
        assert result["risk_level"] == "low"
        assert result["tainted_positions"] == []
