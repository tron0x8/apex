#!/usr/bin/env python3

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from pathlib import Path


@dataclass
class MLFilterResult:
    is_false_positive: bool
    confidence: float
    reason: str = ""
    ml_label: str = ""
    details: Dict[str, Any] = None

    def __post_init__(self):
        if self.details is None:
            self.details = {}


class BaseMLFilter(ABC):

    def __init__(self):
        self.model = None
        self.is_loaded = False
        self.model_info = {}

    @abstractmethod
    def load_model(self, model_path: str) -> bool:
        pass

    @abstractmethod
    def predict(self, finding: Dict, code_context: str) -> MLFilterResult:
        pass

    def batch_predict(self, findings: List[Dict], code_contexts: List[str]) -> List[MLFilterResult]:
        results = []
        for finding, context in zip(findings, code_contexts):
            results.append(self.predict(finding, context))
        return results

    def get_model_info(self) -> Dict:
        return {
            'loaded': self.is_loaded,
            'type': self.__class__.__name__,
            **self.model_info
        }


class NoOpFilter(BaseMLFilter):

    def load_model(self, model_path: str) -> bool:
        self.is_loaded = True
        self.model_info = {'type': 'noop'}
        return True

    def predict(self, finding: Dict, code_context: str) -> MLFilterResult:
        return MLFilterResult(
            is_false_positive=False,
            confidence=1.0,
            reason="ML filtering disabled"
        )


class MLFilterRegistry:

    _filters: Dict[str, type] = {}

    @classmethod
    def register(cls, name: str, filter_class: type):
        if not issubclass(filter_class, BaseMLFilter):
            raise TypeError(f"{filter_class} must extend BaseMLFilter")
        cls._filters[name] = filter_class

    @classmethod
    def get(cls, name: str) -> Optional[type]:
        return cls._filters.get(name)

    @classmethod
    def list_filters(cls) -> List[str]:
        return list(cls._filters.keys())

    @classmethod
    def create(cls, name: str, model_path: str = None) -> BaseMLFilter:
        filter_class = cls.get(name)
        if not filter_class:
            raise ValueError(f"Unknown filter: {name}. Available: {cls.list_filters()}")

        instance = filter_class()
        if model_path:
            instance.load_model(model_path)
        return instance


MLFilterRegistry.register('noop', NoOpFilter)
