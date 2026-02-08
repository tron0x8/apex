#!/usr/bin/env python3
"""
Tests for core/framework_models.py - Framework-specific analysis models.

FrameworkModelEngine applies framework-aware validation, middleware detection,
Blade template escaping analysis, and ORM usage detection to reduce false
positives and refine taint states.
"""

import pytest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.framework_models import FrameworkModelEngine
from core.rule_engine import get_rule_engine, RuleEngine
from core.abstract_interp import AbstractState, TaintInfo, TaintLattice

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")


@pytest.fixture(scope="module")
def engine():
    """Create a FrameworkModelEngine backed by the real rule engine."""
    rule_eng = RuleEngine(RULES_DIR)
    return FrameworkModelEngine(rule_eng)


def _make_tainted_state(*var_names: str) -> AbstractState:
    """Build an AbstractState where each listed variable is fully tainted."""
    state = AbstractState()
    for var in var_names:
        state.set(var, TaintInfo(
            level=TaintLattice.TAINTED,
            taint_types={"SQL_INJECTION", "XSS", "COMMAND_INJECTION"},
            sources={"$_GET"},
        ))
    return state


# ---------------------------------------------------------------------------
# Validation constraint tests
# ---------------------------------------------------------------------------

class TestValidationIntegerSafe:
    def test_validation_integer_safe(self, engine):
        """Integer validation rule makes $age safe for SQL injection."""
        code = """
        $request->validate([
            'age' => 'required|integer',
        ]);
        """
        state = _make_tainted_state("$age", "$request->age")
        result = engine.apply_validation_constraints("laravel", code, state)
        age_info = result.get("$age")
        assert "SQL_INJECTION" in age_info.sanitized_types


class TestValidationEmail:
    def test_validation_email(self, engine):
        """Email validation makes $email safe for SQL but not necessarily XSS."""
        code = """
        $request->validate([
            'email' => 'required|email',
        ]);
        """
        state = _make_tainted_state("$email", "$request->email")
        result = engine.apply_validation_constraints("laravel", code, state)
        email_info = result.get("$email")
        assert "SQL_INJECTION" in email_info.sanitized_types
        # email validation does NOT protect against XSS
        assert "XSS" not in email_info.sanitized_types


class TestValidationInRule:
    def test_validation_in_rule(self, engine):
        """in:a,b,c validation makes the variable safe (whitelist)."""
        code = """
        $request->validate([
            'status' => 'required|in:active,inactive',
        ]);
        """
        state = _make_tainted_state("$status", "$request->status")
        result = engine.apply_validation_constraints("laravel", code, state)
        status_info = result.get("$status")
        assert "SQL_INJECTION" in status_info.sanitized_types
        assert "XSS" in status_info.sanitized_types


# ---------------------------------------------------------------------------
# Middleware detection tests
# ---------------------------------------------------------------------------

class TestMiddlewareSingle:
    def test_middleware_single(self, engine):
        """Detects ->middleware('auth') as a single middleware."""
        code = """Route::get('/admin', 'AdminController@index')->middleware('auth');"""
        mw = engine.detect_route_middleware(code)
        assert "auth" in mw


class TestMiddlewareArray:
    def test_middleware_array(self, engine):
        """Detects ->middleware(['csrf', 'throttle']) array syntax."""
        code = """Route::post('/submit', 'FormController@store')->middleware(['csrf', 'throttle']);"""
        mw = engine.detect_route_middleware(code)
        assert "csrf" in mw
        assert "throttle" in mw


class TestMiddlewareRoute:
    def test_middleware_route(self, engine):
        """Detects Route::middleware([...]) group syntax."""
        code = """
        Route::middleware(['auth', 'verified'])->group(function () {
            Route::get('/dashboard', 'DashController@index');
        });
        """
        mw = engine.detect_route_middleware(code)
        assert "auth" in mw
        assert "verified" in mw


# ---------------------------------------------------------------------------
# Blade escaping tests
# ---------------------------------------------------------------------------

class TestBladeEscaped:
    def test_blade_escaped(self, engine):
        """{{ $var }} is detected as escaped (True)."""
        template = "<p>{{ $user->name }}</p>"
        escaping = engine.detect_blade_escaping(template)
        assert 1 in escaping
        assert escaping[1] is True


class TestBladeRaw:
    def test_blade_raw(self, engine):
        """{!! $var !!} is detected as raw / unescaped (False)."""
        template = "<p>{!! $user->bio !!}</p>"
        escaping = engine.detect_blade_escaping(template)
        assert 1 in escaping
        assert escaping[1] is False


# ---------------------------------------------------------------------------
# ORM usage detection tests
# ---------------------------------------------------------------------------

class TestOrmEloquent:
    def test_orm_eloquent(self, engine):
        """$query->where(...) is detected as ORM-protected."""
        code = """
        $query = DB::table('users');
        $query->where('age', '>', 18);
        """
        orm_vars = engine.detect_orm_usage(code)
        assert "$query" in orm_vars


class TestOrmPrepared:
    def test_orm_prepared(self, engine):
        """$pdo->prepare(...) is detected as ORM-protected."""
        code = """
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$id]);
        """
        orm_vars = engine.detect_orm_usage(code)
        assert "$pdo" in orm_vars


# ---------------------------------------------------------------------------
# No-validation passthrough test
# ---------------------------------------------------------------------------

class TestNoValidation:
    def test_no_validation(self, engine):
        """Code without any validation block returns the same taint state."""
        code = """
        $name = $_GET['name'];
        echo $name;
        """
        state = _make_tainted_state("$name")
        result = engine.apply_validation_constraints("laravel", code, state)
        name_info = result.get("$name")
        assert name_info.level == TaintLattice.TAINTED
        assert name_info.sanitized_types == set()
