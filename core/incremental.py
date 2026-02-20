# apex/core - tron (@tron0x8)

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

_PHP_INCLUDE_RE = re.compile(
    r"""(?:include|include_once|require|require_once)\s*"""
    r"""[\(\s]+['"]([^'"]+)['"]\s*[\)\s]*;""",
    re.IGNORECASE,
)


@dataclass
class FileCache:

    file_path: str
    content_hash: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    function_summaries: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    ml_results: Dict[str, Dict] = field(default_factory=dict)


    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FileCache":
        return cls(
            file_path=str(data.get("file_path", "")),
            content_hash=str(data.get("content_hash", "")),
            findings=list(data.get("findings", [])),
            function_summaries=dict(data.get("function_summaries", {})),
            timestamp=float(data.get("timestamp", 0.0)),
            ml_results=dict(data.get("ml_results", {})),
        )


def _compute_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def _extract_includes(content: str) -> List[str]:
    return _PHP_INCLUDE_RE.findall(content)


class IncrementalAnalyzer:

    CACHE_FILE: str = ".apex_cache.json"

    def __init__(self, cache_dir: str = ".") -> None:
        self._cache_dir: str = os.path.abspath(cache_dir)
        self._cache_path: str = os.path.join(self._cache_dir, self.CACHE_FILE)

        self._entries: Dict[str, FileCache] = {}

        self._dependencies: Dict[str, Set[str]] = {}

        self._hits: int = 0
        self._misses: int = 0

        self._load_cache()


    def _load_cache(self) -> None:
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

        entries_raw = raw.get("entries", {})
        if isinstance(entries_raw, dict):
            for path, entry_data in entries_raw.items():
                try:
                    self._entries[path] = FileCache.from_dict(entry_data)
                except (TypeError, KeyError, ValueError) as exc:
                    logger.debug("Skipping corrupt cache entry %s: %s", path, exc)

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


    def needs_analysis(self, file_path: str, content: str) -> bool:
        normalized = self._normalize_path(file_path)
        content_hash = _compute_hash(content)

        entry = self._entries.get(normalized)
        if entry is not None and entry.content_hash == content_hash:
            self._hits += 1
            return False

        self._misses += 1
        return True

    def get_cached_results(self, file_path: str) -> Optional[List[Dict[str, Any]]]:
        normalized = self._normalize_path(file_path)
        entry = self._entries.get(normalized)
        if entry is not None:
            return list(entry.findings)
        return None

    def get_cached_ml_results(self, file_path: str) -> Optional[Dict]:
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

        includes = _extract_includes(content)
        resolved: Set[str] = set()
        base_dir = os.path.dirname(normalized)
        for inc in includes:
            resolved_path = os.path.normpath(os.path.join(base_dir, inc))
            resolved.add(resolved_path)
        self._dependencies[normalized] = resolved


    def get_dependents(self, changed_file: str) -> Set[str]:
        normalized = self._normalize_path(changed_file)
        dependents: Set[str] = set()
        for file_path, deps in self._dependencies.items():
            if normalized in deps:
                dependents.add(file_path)
        return dependents

    def invalidate_dependents(self, changed_files: Set[str]) -> None:
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
                    self._entries.pop(dep, None)
                    logger.debug(
                        "Invalidated cache for %s (depends on %s)", dep, current
                    )
                    queue.append(dep)


    def get_stats(self) -> Dict[str, Any]:
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


    @staticmethod
    def _normalize_path(file_path: str) -> str:
        return os.path.normpath(file_path)
