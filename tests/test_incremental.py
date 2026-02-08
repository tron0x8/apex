#!/usr/bin/env python3
"""
Tests for core/incremental.py - Incremental analysis cache.

IncrementalAnalyzer caches scan results keyed by file content hash, tracks
inter-file dependencies via PHP include/require, and invalidates dependents
when upstream files change.
"""

import pytest
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.incremental import IncrementalAnalyzer


# ---------------------------------------------------------------------------
# needs_analysis tests
# ---------------------------------------------------------------------------

class TestNeedsAnalysisNewFile:
    def test_needs_analysis_new_file(self):
        """A file never seen before requires analysis."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = IncrementalAnalyzer(cache_dir=tmpdir)
            assert analyzer.needs_analysis("/app/index.php", "<?php echo 1;") is True


class TestNeedsAnalysisCached:
    def test_needs_analysis_cached(self):
        """A cached file with identical content does not need re-analysis."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = IncrementalAnalyzer(cache_dir=tmpdir)
            content = "<?php echo 'hello';"
            analyzer.update_cache("/app/index.php", content, [], {})
            assert analyzer.needs_analysis("/app/index.php", content) is False


class TestNeedsAnalysisChanged:
    def test_needs_analysis_changed(self):
        """A cached file whose content has changed requires re-analysis."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = IncrementalAnalyzer(cache_dir=tmpdir)
            analyzer.update_cache("/app/index.php", "<?php echo 1;", [], {})
            assert analyzer.needs_analysis("/app/index.php", "<?php echo 2;") is True


# ---------------------------------------------------------------------------
# Cache round-trip tests
# ---------------------------------------------------------------------------

class TestUpdateAndGetCached:
    def test_update_and_get_cached(self):
        """Findings stored via update_cache are returned by get_cached_results."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = IncrementalAnalyzer(cache_dir=tmpdir)
            findings = [
                {"vuln_type": "SQL_INJECTION", "line": 10, "severity": "CRITICAL"},
                {"vuln_type": "XSS", "line": 25, "severity": "HIGH"},
            ]
            summaries = {"get_user": {"returns_tainted": True}}
            analyzer.update_cache("/app/db.php", "<?php /* db */", findings, summaries)

            cached = analyzer.get_cached_results("/app/db.php")
            assert cached is not None
            assert len(cached) == 2
            assert cached[0]["vuln_type"] == "SQL_INJECTION"
            assert cached[1]["line"] == 25


# ---------------------------------------------------------------------------
# Dependency tracking tests
# ---------------------------------------------------------------------------

class TestGetDependents:
    def test_get_dependents(self):
        """get_dependents returns files that include the changed file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = IncrementalAnalyzer(cache_dir=tmpdir)
            # index.php includes db.php
            code_index = "<?php require_once('db.php');"
            analyzer.update_cache("/app/index.php", code_index, [], {})
            # controller.php also includes db.php
            code_ctrl = "<?php include('db.php');"
            analyzer.update_cache("/app/controller.php", code_ctrl, [], {})
            # db.php itself
            analyzer.update_cache("/app/db.php", "<?php /* db */", [], {})

            dependents = analyzer.get_dependents("/app/db.php")
            assert os.path.normpath("/app/index.php") in dependents
            assert os.path.normpath("/app/controller.php") in dependents


class TestInvalidateDependents:
    def test_invalidate_dependents(self):
        """invalidate_dependents removes cache entries for files that depend on changed files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = IncrementalAnalyzer(cache_dir=tmpdir)
            # index.php includes db.php
            analyzer.update_cache("/app/index.php", "<?php require('db.php');", [{"v": 1}], {})
            analyzer.update_cache("/app/db.php", "<?php /* db */", [], {})

            # Before invalidation, index.php has cached results
            assert analyzer.get_cached_results("/app/index.php") is not None

            # Invalidate dependents of db.php
            analyzer.invalidate_dependents({"/app/db.php"})

            # index.php cache should now be gone
            assert analyzer.get_cached_results(os.path.normpath("/app/index.php")) is None


# ---------------------------------------------------------------------------
# Persistence tests
# ---------------------------------------------------------------------------

class TestSaveAndReload:
    def test_save_and_reload(self):
        """Cache persists to disk and can be reloaded by a new analyzer."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # First session: populate and save
            analyzer1 = IncrementalAnalyzer(cache_dir=tmpdir)
            content = "<?php echo 'persistent';"
            findings = [{"vuln_type": "XSS", "line": 1}]
            analyzer1.update_cache("/app/view.php", content, findings, {})
            analyzer1.save_cache()

            # Second session: reload from the same directory
            analyzer2 = IncrementalAnalyzer(cache_dir=tmpdir)
            assert analyzer2.needs_analysis("/app/view.php", content) is False
            cached = analyzer2.get_cached_results("/app/view.php")
            assert cached is not None
            assert len(cached) == 1
            assert cached[0]["vuln_type"] == "XSS"


# ---------------------------------------------------------------------------
# Stats test
# ---------------------------------------------------------------------------

class TestStats:
    def test_stats(self):
        """get_stats returns correct hit/miss counts and total_files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = IncrementalAnalyzer(cache_dir=tmpdir)
            content_a = "<?php echo 'a';"
            content_b = "<?php echo 'b';"
            analyzer.update_cache("/a.php", content_a, [], {})
            analyzer.update_cache("/b.php", content_b, [], {})

            # One hit, one miss
            analyzer.needs_analysis("/a.php", content_a)       # hit
            analyzer.needs_analysis("/c.php", "<?php new();")   # miss

            stats = analyzer.get_stats()
            assert stats["hits"] == 1
            assert stats["misses"] == 1
            assert stats["total_files"] == 2
