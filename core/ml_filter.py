#!/usr/bin/env python3
"""
APEX ML Filter v2.0
Supports both multi-class and binary models with threshold tuning
"""

import os
import re
import pickle
from typing import Dict, List, Optional, Any

from .ml_interface import BaseMLFilter, MLFilterResult, MLFilterRegistry


class BinaryVulnFilter(BaseMLFilter):
    """
    Binary classifier: SAFE vs VULN
    Optimized for low false positives with adjustable threshold
    """

    def __init__(self, threshold: float = 0.7):
        super().__init__()
        self.vectorizer = None
        self.threshold = threshold  # Higher = fewer FPs but may miss some vulns

    def load_model(self, model_path: str) -> bool:
        try:
            with open(model_path, 'rb') as f:
                data = pickle.load(f)

            self.model = data['model']
            self.vectorizer = data.get('vec') or data.get('vectorizer')
            self.is_loaded = True

            self.model_info = {
                'path': model_path,
                'type': 'BinaryVulnFilter',
                'version': data.get('version', 'unknown'),
                'threshold': self.threshold,
                'metrics': data.get('metrics', {})
            }

            return True

        except Exception as e:
            self.model_info = {'error': str(e)}
            return False

    def predict(self, finding: Dict, code_context: str) -> MLFilterResult:
        if not self.is_loaded:
            return MLFilterResult(
                is_false_positive=False,
                confidence=0.0,
                reason="Model not loaded"
            )

        features = self._extract_features(code_context)

        try:
            X = self.vectorizer.transform([features]).toarray()
            proba = self.model.predict_proba(X)[0]

            # Binary: [SAFE_prob, VULN_prob]
            safe_prob = proba[0]
            vuln_prob = proba[1]

            # If VULN probability is below threshold, mark as FP
            if vuln_prob < self.threshold:
                return MLFilterResult(
                    is_false_positive=True,
                    confidence=safe_prob,
                    reason=f"ML: VULN prob {vuln_prob:.1%} < threshold {self.threshold:.1%}",
                    ml_label="SAFE",
                    details={'vuln_prob': vuln_prob, 'safe_prob': safe_prob}
                )
            else:
                return MLFilterResult(
                    is_false_positive=False,
                    confidence=vuln_prob,
                    reason=f"ML confirms vulnerability ({vuln_prob:.1%})",
                    ml_label="VULN",
                    details={'vuln_prob': vuln_prob, 'safe_prob': safe_prob}
                )

        except Exception as e:
            return MLFilterResult(
                is_false_positive=False,
                confidence=0.5,
                reason=f"ML error: {str(e)}"
            )

    def _extract_features(self, code: str) -> str:
        tokens = []

        # Function calls
        funcs = re.findall(r'[a-zA-Z_]\w*(?=\s*\()', code)[:60]
        tokens.extend(funcs)

        # Sources
        if re.search(r'\$_GET', code): tokens.append("SRC:GET")
        if re.search(r'\$_POST', code): tokens.append("SRC:POST")
        if re.search(r'\$_REQUEST', code): tokens.append("SRC:REQ")
        if re.search(r'\$_COOKIE', code): tokens.append("SRC:COOKIE")

        # Sinks
        if re.search(r'mysql_query|mysqli_query|->query', code, re.I): tokens.append("SINK:SQL")
        if re.search(r'\becho\b|\bprint\b', code): tokens.append("SINK:OUT")
        if re.search(r'exec|system|passthru|shell_exec', code): tokens.append("SINK:CMD")
        if re.search(r'include|require', code): tokens.append("SINK:INC")
        if re.search(r'\beval\b', code): tokens.append("SINK:EVAL")

        # Sanitizers
        if re.search(r'htmlspecialchars|htmlentities', code): tokens.append("SAN:XSS")
        if re.search(r'mysqli?_real_escape|->quote', code): tokens.append("SAN:SQL")
        if re.search(r'escapeshellarg|escapeshellcmd', code): tokens.append("SAN:CMD")
        if re.search(r'intval|floatval|\(int\)', code): tokens.append("SAN:CAST")
        if re.search(r'->prepare\s*\(', code): tokens.append("SAN:PREP")
        if re.search(r'in_array|is_numeric|ctype_', code): tokens.append("SAN:CHECK")
        if re.search(r'basename|realpath', code): tokens.append("SAN:PATH")

        # Frameworks
        if re.search(r'->where\s*\(.*,', code): tokens.append("FW:ORM")
        if re.search(r'->bind', code): tokens.append("FW:BIND")

        return " ".join(tokens)

    def set_threshold(self, threshold: float):
        """Adjust threshold dynamically"""
        self.threshold = max(0.0, min(1.0, threshold))
        if self.model_info:
            self.model_info['threshold'] = self.threshold


class PHPVulnMLFilter(BaseMLFilter):
    """Multi-class classifier for vulnerability type detection"""

    LABEL_MAP = {
        'SQLi': ['SQL_INJECTION'],
        'XSS': ['XSS'],
        'CMDi': ['COMMAND_INJECTION'],
        'LFI': ['FILE_INCLUSION', 'PATH_TRAVERSAL'],
        'CODE': ['CODE_INJECTION'],
        'XXE': ['XXE'],
        'SAFE': []
    }

    VULN_TO_ML = {}
    for ml_label, apex_types in LABEL_MAP.items():
        for apex_type in apex_types:
            VULN_TO_ML[apex_type] = ml_label

    def __init__(self):
        super().__init__()
        self.vectorizer = None
        self.label_encoder = None

    def load_model(self, model_path: str) -> bool:
        try:
            with open(model_path, 'rb') as f:
                data = pickle.load(f)

            self.model = data['model']
            self.vectorizer = data.get('vec') or data.get('vectorizer')
            self.label_encoder = data.get('le') or data.get('label_encoder')
            self.is_loaded = True

            classes = list(self.label_encoder.classes_) if self.label_encoder else []
            self.model_info = {
                'path': model_path,
                'type': 'PHPVulnML',
                'classes': classes
            }

            return True

        except Exception as e:
            self.model_info = {'error': str(e)}
            return False

    def predict(self, finding: Dict, code_context: str) -> MLFilterResult:
        if not self.is_loaded:
            return MLFilterResult(
                is_false_positive=False,
                confidence=0.0,
                reason="Model not loaded"
            )

        try:
            features = self._extract_features(code_context)
            X = self.vectorizer.transform([features]).toarray()
            proba = self.model.predict_proba(X)[0]

            pred_idx = proba.argmax()
            label = self.label_encoder.inverse_transform([pred_idx])[0]
            confidence = float(proba[pred_idx])

            apex_type = finding.get('type', '')
            expected = self.VULN_TO_ML.get(apex_type, '')

            if label == 'SAFE' and confidence >= 0.8:
                return MLFilterResult(
                    is_false_positive=True,
                    confidence=confidence,
                    reason=f"ML predicts SAFE ({confidence:.0%})",
                    ml_label=label
                )

            elif label == expected:
                return MLFilterResult(
                    is_false_positive=False,
                    confidence=confidence,
                    reason=f"ML confirms {label}",
                    ml_label=label
                )

            else:
                return MLFilterResult(
                    is_false_positive=False,
                    confidence=confidence * 0.8,
                    reason=f"ML: {label}, APEX: {apex_type}",
                    ml_label=label
                )

        except Exception as e:
            return MLFilterResult(
                is_false_positive=False,
                confidence=0.5,
                reason=f"ML error: {str(e)}"
            )

    def _extract_features(self, code: str) -> str:
        tokens = []
        funcs = re.findall(r'[a-zA-Z_]\w*(?=\s*\()', code)[:50]
        tokens.extend(funcs)

        if re.search(r'\$_GET', code): tokens.append("SRC:GET")
        if re.search(r'\$_POST', code): tokens.append("SRC:POST")
        if re.search(r'\$_REQUEST', code): tokens.append("SRC:REQ")

        if re.search(r'mysql_query|mysqli_query|->query', code, re.I): tokens.append("SINK:SQL")
        if re.search(r'\becho\b|\bprint\b', code): tokens.append("SINK:OUT")
        if re.search(r'exec|system|passthru', code): tokens.append("SINK:CMD")
        if re.search(r'include|require', code): tokens.append("SINK:INC")

        if re.search(r'htmlspecialchars|htmlentities', code): tokens.append("SAN:XSS")
        if re.search(r'mysqli?_real_escape', code): tokens.append("SAN:SQL")
        if re.search(r'escapeshellarg', code): tokens.append("SAN:CMD")
        if re.search(r'intval|\(int\)', code): tokens.append("SAN:CAST")
        if re.search(r'->prepare', code): tokens.append("SAN:PREP")

        return " ".join(tokens)


class TaintFlowFilter(BaseMLFilter):
    """Rule-based taint flow analysis (no ML model required)"""

    def load_model(self, model_path: str) -> bool:
        self.is_loaded = True
        self.model_info = {'type': 'rule-based'}
        return True

    def predict(self, finding: Dict, code_context: str) -> MLFilterResult:
        flows = self._analyze_flows(code_context, finding.get('type', ''))

        if flows['has_sanitizer'] and not flows['has_direct_flow']:
            return MLFilterResult(
                is_false_positive=True,
                confidence=0.9,
                reason="Sanitizer detected, no direct flow",
                details=flows
            )

        if not flows['has_source']:
            return MLFilterResult(
                is_false_positive=True,
                confidence=0.85,
                reason="No user input source detected",
                details=flows
            )

        return MLFilterResult(
            is_false_positive=False,
            confidence=0.8,
            reason="Direct taint flow detected",
            details=flows
        )

    def _analyze_flows(self, code: str, vuln_type: str) -> Dict:
        result = {
            'has_source': bool(re.search(r'\$_(GET|POST|REQUEST|COOKIE)', code)),
            'has_sanitizer': False,
            'has_direct_flow': False
        }

        sanitizers = {
            'SQL_INJECTION': r'(mysql_real_escape|mysqli_real_escape|intval|prepare)',
            'XSS': r'(htmlspecialchars|htmlentities|strip_tags)',
            'COMMAND_INJECTION': r'(escapeshellarg|escapeshellcmd)',
            'FILE_INCLUSION': r'(basename|realpath|in_array)',
        }

        san_pattern = sanitizers.get(vuln_type, '')
        if san_pattern and re.search(san_pattern, code, re.IGNORECASE):
            result['has_sanitizer'] = True

        if result['has_source'] and not result['has_sanitizer']:
            result['has_direct_flow'] = True

        return result


# Register all filters
MLFilterRegistry.register('binary-vuln', BinaryVulnFilter)
MLFilterRegistry.register('php-vuln-ml', PHPVulnMLFilter)
MLFilterRegistry.register('taint-flow', TaintFlowFilter)
