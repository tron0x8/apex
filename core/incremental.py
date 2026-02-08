"""
Incremental analysis cache for the APEX PHP security scanner.

This module provides caching of analysis results so that unchanged files are
not re-analyzed on subsequent scans. It tracks file content by SHA-256 hash,
stores serialized findings and function summaries, and understands inter-file
dependencies (PHP include/require) so that dependents of a changed file are
automatically invalidated.

Typical usage:

    analyzer = IncrementalAnalyzer(cache_dir="/path/to/project")

    for path, content in files:
        if analyzer.needs_analysis(path, content):
            findings, summaries = run_full_analysis(path, content)
            analyzer.update_cache(path, content, findings, summaries)
        else:
            findings = analyzer.get_cached_results(path)

    analyzer.save_cache()
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex for detecting PHP include / require statements.  Used by the
# dependency tracker to decide which cached entries must be invalidated when
# a file changes.
# ---------------------------------------------------------------------------
_PHP_INCLUDE_RE = re.compile(
    r"""(?:include|include_once|require|require_once)\s*"""
    r"""[\(\s]+['"]([^'"]+)['"]\s*[\)\s]*;""",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# FileCache dataclass -- one entry per analysed file
# ---------------------------------------------------------------------------

@dataclass
class FileCache:
    """Cached analysis result for a single PHP file.

    Attributes:
        file_path:          Absolute (or project-relative) path to the file.
        content_hash:       SHA-256 hex digest of the file contents at the
                            time the analysis was performed.
        findings:           Serialised finding dictionaries produced by the
                            scanner for this file.
        function_summaries: Mapping of function name to a serialised summary
                            dictionary (return type, taint info, etc.).
        timestamp:          Unix epoch timestamp of when this cache entry was
                            last written.
    """

    file_path: str
    content_hash: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    function_summaries: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    ml_results: Dict[str, Dict] = field(default_factory=dict)  # line -> {ml_score, ml_is_tp, ml_method}

    # -- serialisation helpers ------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Return a plain-dict representation suitable for JSON encoding."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FileCache":
        """Reconstruct a *FileCache* from a plain dictionary.

        Unknown keys are silently ignored so that forward-compatible cache
        files written by a newer version of APEX do not crash an older reader.
        """
        return cls(
            file_path=str(data.get("file_path", "")),
            content_hash=str(data.get("content_hash", "")),
            findings=list(data.get("findings", [])),
            function_summaries=dict(data.get("function_summaries", {})),
            timestamp=float(data.get("timestamp", 0.0)),
            ml_results=dict(data.get("ml_results", {})),
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _compute_hash(content: str) -> str:
    """Return the SHA-256 hex digest of *content* (encoded as UTF-8)."""
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def _extract_includes(content: str) -> List[str]:
    """Extract PHP include/require targets from raw source *content*.

    Returns a list of path strings exactly as they appear in the source
    (e.g. ``'../lib/db.php'``).  The caller is responsible for resolving
    them relative to the including file if necessary.
    """
    return _PHP_INCLUDE_RE.findall(content)


# ---------------------------------------------------------------------------
# IncrementalAnalyzer
# ---------------------------------------------------------------------------

class IncrementalAnalyzer:
    """Incremental analysis cache manager.

    The analyser persists its state as a single JSON file
    (``CACHE_FILE``) inside the directory given by *cache_dir*.

    Parameters:
        cache_dir: Directory where the cache file is stored.  Defaults to
                   the current working directory.
    """

    CACHE_FILE: str = ".apex_cache.json"

    def __init__(self, cache_dir: str = ".") -> None:
        self._cache_dir: str = os.path.abspath(cache_dir)
        self._cache_path: str = os.path.join(self._cache_dir, self.CACHE_FILE)

        # file_path -> FileCache
        self._entries: Dict[str, FileCache] = {}

        # Dependency graph: maps a file path to the set of file paths it
        # includes/requires.  The *reverse* mapping (dependents) is computed
        # on the fly via ``get_dependents``.
        self._dependencies: Dict[str, Set[str]] = {}

        # Simple hit / miss counters for statistics.
        self._hits: int = 0
        self._misses: int = 0

        self._load_cache()

    # -- persistence ----------------------------------------------------------

    def _load_cache(self) -> None:
        """Load the cache from disk.  Silently start fresh on any error."""
        if not os.path.isfile(self._cache_path):
            logger.debug("No existing cache file at %s", self._cache_path)
            return

        try:
            with open(self._cache_path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            logger.warning(
                "Could not load cache file %s (%s). Starting with empty cache.",
                self._cache_path,
                exc,
            )
            return

        if not isinstance(raw, dict):
            logger.warning("Cache file has unexpected top-level type; ignoring.")
            return

        # Restore file entries.
        entries_raw = raw.get("entries", {})
        if isinstance(entries_raw, dict):
            for path, entry_data in entries_raw.items():
                try:
                    self._entries[path] = FileCache.from_dict(entry_data)
                except (TypeError, KeyError, ValueError) as exc:
                    logger.debug("Skipping corrupt cache entry %s: %s", path, exc)

        # Restore dependency graph (stored as lists for JSON compat).
        deps_raw = raw.get("dependencies", {})
        if isinstance(deps_raw, dict):
            for path, dep_list in deps_raw.items():
                if isinstance(dep_list, list):
                    self._dependencies[path] = set(dep_list)

        logger.info(
            "Loaded cache with %d entries from %s",
            len(self._entries),
            self._cache_path,
        )

    def save_cache(self) -> None:
        """Persist the current cache state to disk as JSON.

        Creates the cache directory if it does not already exist.  Any
        I/O error is logged but does **not** raise -- a failed cache write
        should never abort an otherwise successful scan.
        """
        payload: Dict[str, Any] = {
            "version": 1,
            "generated_at": time.time(),
            "entries": {
                path: entry.to_dict() for path, entry in self._entries.items()
            },
            "dependencies": {
                path: sorted(deps) for path, deps in self._dependencies.items()
            },
        }

        try:
            os.makedirs(self._cache_dir, exist_ok=True)
            with open(self._cache_path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, default=str)
            logger.info("Cache saved to %s", self._cache_path)
        except OSError as exc:
            logger.error("Failed to write cache file %s: %s", self._cache_path, exc)

    # -- core query / update API ---------------------------------------------

    def needs_analysis(self, file_path: str, content: str) -> bool:
        """Determine whether *file_path* needs (re-)analysis.

        Returns ``True`` if the file is new, has changed since the last
        cached analysis, or is not present in the cache.  Returns ``False``
        when the SHA-256 hash of *content* matches the cached hash.
        """
        normalized = self._normalize_path(file_path)
        content_hash = _compute_hash(content)

        entry = self._entries.get(normalized)
        if entry is not None and entry.content_hash == content_hash:
            self._hits += 1
            return False

        self._misses += 1
        return True

    def get_cached_results(self, file_path: str) -> Optional[List[Dict[str, Any]]]:
        """Return cached findings for *file_path*, or ``None`` if absent."""
        normalized = self._normalize_path(file_path)
        entry = self._entries.get(normalized)
        if entry is not None:
            return list(entry.findings)
        return None

    def get_cached_ml_results(self, file_path: str) -> Optional[Dict]:
        """Get cached ML classification results for a file."""
        entry = self._entries.get(self._normalize_path(file_path))
        if entry and hasattr(entry, 'ml_results'):
            return entry.ml_results
        return None

    def update_cache(
        self,
        file_path: str,
        content: str,
        findings: List[Dict[str, Any]],
        summaries: Dict[str, Dict[str, Any]],
        ml_results: Optional[Dict] = None,
    ) -> None:
        """Store analysis results for *file_path* in the cache.

        This also refreshes the dependency graph for the file by scanning
        *content* for ``include`` / ``require`` statements.
        """
        normalized = self._normalize_path(file_path)
        content_hash = _compute_hash(content)

        self._entries[normalized] = FileCache(
            file_path=normalized,
            content_hash=content_hash,
            findings=list(findings),
            function_summaries=dict(summaries),
            timestamp=time.time(),
            ml_results=ml_results or {},
        )

        # Update the dependency graph.
        includes = _extract_includes(content)
        resolved: Set[str] = set()
        base_dir = os.path.dirname(normalized)
        for inc in includes:
            # Attempt a simple resolution relative to the file's directory.
            resolved_path = os.path.normpath(os.path.join(base_dir, inc))
            resolved.add(resolved_path)
        self._dependencies[normalized] = resolved

    # -- dependency tracking --------------------------------------------------

    def get_dependents(self, changed_file: str) -> Set[str]:
        """Return the set of cached files that include/require *changed_file*.

        This performs a *reverse* lookup on the dependency graph: for every
        cached file ``A`` whose dependency set contains *changed_file*, ``A``
        is included in the result.
        """
        normalized = self._normalize_path(changed_file)
        dependents: Set[str] = set()
        for file_path, deps in self._dependencies.items():
            if normalized in deps:
                dependents.add(file_path)
        return dependents

    def invalidate_dependents(self, changed_files: Set[str]) -> None:
        """Invalidate cache entries for all files that depend on any of
        *changed_files*.

        This uses a breadth-first traversal so that transitive dependents
        (A includes B includes C -- if C changed, both A and B are
        invalidated) are correctly handled.
        """
        queue = list(changed_files)
        visited: Set[str] = set()

        while queue:
            current = self._normalize_path(queue.pop(0))
            if current in visited:
                continue
            visited.add(current)

            dependents = self.get_dependents(current)
            for dep in dependents:
                if dep not in visited:
                    # Remove the cached entry so the file will be re-analysed.
                    self._entries.pop(dep, None)
                    logger.debug(
                        "Invalidated cache for %s (depends on %s)", dep, current
                    )
                    queue.append(dep)

    # -- statistics -----------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """Return a dictionary of cache statistics.

        Keys:
            hits:        Number of ``needs_analysis`` calls that returned
                         ``False`` (cache hit).
            misses:      Number of ``needs_analysis`` calls that returned
                         ``True`` (cache miss / new file).
            total_files: Number of files currently held in the cache.
            cache_size:  Size of the on-disk cache file in bytes, or 0 if
                         the file does not exist.
        """
        try:
            cache_size = os.path.getsize(self._cache_path)
        except OSError:
            cache_size = 0

        return {
            "hits": self._hits,
            "misses": self._misses,
            "total_files": len(self._entries),
            "cache_size": cache_size,
        }

    # -- internal helpers -----------------------------------------------------

    @staticmethod
    def _normalize_path(file_path: str) -> str:
        """Normalize *file_path* to a canonical, comparable form."""
        return os.path.normpath(file_path)
