
import re
import logging
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path

try:
    from sklearn.ensemble import (
        GradientBoostingClassifier, RandomForestClassifier,
        ExtraTreesClassifier, IsolationForest
    )
    from sklearn.linear_model import LogisticRegression
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.decomposition import TruncatedSVD
    from sklearn.model_selection import cross_val_predict, StratifiedKFold
    from sklearn.pipeline import Pipeline
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

try:
    from lightgbm import LGBMClassifier
    HAS_LGBM = True
except ImportError:
    HAS_LGBM = False

logger = logging.getLogger(__name__)


class CodeTokenizer:

    TOKEN_PATTERN = re.compile(
        r'\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER|SESSION|ENV)'
        r'|\$\w+'
        r'|\b\w+\s*\('
        r'|->\w+'
        r'|::\w+'
        r'|\b(?:if|else|elseif|for|foreach|while|do|switch|case|return|echo|print'
        r'|include|require|include_once|require_once|die|exit|throw)\b'
        r'|\b(?:function|class|public|private|protected|static|abstract|interface)\b'
        r'|\b(?:try|catch|finally|new|instanceof|array|null|true|false|TRUE|FALSE|NULL)\b'
        r'|[=!<>]=?=?'
        r'|\.='
        r'|\->'
        r'|::'
        r'|\b\d+\b'
    )

    @classmethod
    def tokenize(cls, code_snippet: str) -> str:
        if not code_snippet:
            return ''
        tokens = cls.TOKEN_PATTERN.findall(code_snippet)
        normalized = []
        for t in tokens:
            t = t.strip()
            if t.startswith('$'):
                normalized.append(t.lower())
            elif t.endswith('('):
                normalized.append(t.rstrip('(').lower() + '(')
            else:
                normalized.append(t.lower())
        return ' '.join(normalized)


def _split_tokenizer(x):
    return x.split()


def _identity_preprocessor(x):
    return x


class TFIDFFeaturePipeline:

    def __init__(self, n_components: int = 50):
        self.n_components = n_components
        self.tfidf = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 2),
            min_df=2,
            max_df=0.95,
            sublinear_tf=True,
            tokenizer=_split_tokenizer,
            preprocessor=_identity_preprocessor,
        ) if HAS_SKLEARN else None
        self.svd = TruncatedSVD(
            n_components=n_components, random_state=42
        ) if HAS_SKLEARN else None
        self.fitted = False

    def fit(self, code_snippets: List[str]):
        if not HAS_SKLEARN or not code_snippets:
            return
        tokenized = [CodeTokenizer.tokenize(s) for s in code_snippets]
        tokenized = [t if t else 'empty' for t in tokenized]
        try:
            tfidf_matrix = self.tfidf.fit_transform(tokenized)
            actual_components = min(self.n_components, tfidf_matrix.shape[1] - 1)
            if actual_components < 1:
                return
            self.svd = TruncatedSVD(n_components=actual_components, random_state=42)
            self.svd.fit(tfidf_matrix)
            self.n_components = actual_components
            self.fitted = True
        except Exception as e:
            logger.warning(f"TF-IDF fit failed: {e}")

    def transform(self, code_snippets: List[str]) -> np.ndarray:
        if not self.fitted:
            return np.zeros((len(code_snippets), self.n_components))
        tokenized = [CodeTokenizer.tokenize(s) if s else 'empty' for s in code_snippets]
        try:
            tfidf_matrix = self.tfidf.transform(tokenized)
            return self.svd.transform(tfidf_matrix)
        except Exception:
            return np.zeros((len(code_snippets), self.n_components))

    def transform_single(self, code_snippet: str) -> np.ndarray:
        return self.transform([code_snippet])[0]


class AnomalyFeatureEnhancer:

    def __init__(self):
        self.iforest = IsolationForest(
            n_estimators=200,
            contamination=0.1,
            random_state=42,
            n_jobs=-1,
        ) if HAS_SKLEARN else None
        self.fitted = False

    def fit(self, X_safe: np.ndarray):
        if not HAS_SKLEARN or len(X_safe) < 10:
            return
        try:
            self.iforest.fit(X_safe)
            self.fitted = True
        except Exception as e:
            logger.warning(f"Anomaly detector fit failed: {e}")

    def score(self, X: np.ndarray) -> np.ndarray:
        if not self.fitted:
            return np.zeros(len(X))
        try:
            return self.iforest.decision_function(X)
        except Exception:
            return np.zeros(len(X))

    def score_single(self, x: np.ndarray) -> float:
        return float(self.score(x.reshape(1, -1))[0])


TYPE_GROUPS = {
    'sqli': ['SQL Injection', 'LDAP Injection', 'XPath Injection'],
    'xss': ['Cross-Site Scripting'],
    'injection': ['Command Injection', 'Code Injection', 'Remote Code Execution'],
    'file': ['File Inclusion', 'Path Traversal', 'Arbitrary File Read',
             'Arbitrary File Write', 'Unsafe File Upload'],
    'crypto': ['Weak Cryptography', 'Insecure Randomness', 'Insecure Deserialization'],
    'other': [],
}

_TYPE_TO_GROUP = {}
for group, types in TYPE_GROUPS.items():
    for t in types:
        _TYPE_TO_GROUP[t] = group


def get_type_group(vuln_type: str) -> str:
    return _TYPE_TO_GROUP.get(vuln_type, 'other')


class PerTypeModelRegistry:

    MIN_SAMPLES = 100  # Minimum samples to train a per-type model

    def __init__(self):
        self.models: Dict[str, Any] = {}
        self.active_groups: set = set()

    def train(self, X: np.ndarray, y: np.ndarray,
              vuln_types: List[str], sample_weight=None, verbose=False):
        if not HAS_SKLEARN:
            return

        for group_name in TYPE_GROUPS:
            indices = [i for i, vt in enumerate(vuln_types)
                       if get_type_group(vt) == group_name]
            if len(indices) < self.MIN_SAMPLES:
                if verbose:
                    print(f"  [{group_name}] Skipped ({len(indices)} < {self.MIN_SAMPLES} samples)")
                continue

            X_group = X[indices]
            y_group = y[indices]
            sw = sample_weight[indices] if sample_weight is not None else None

            model = GradientBoostingClassifier(
                n_estimators=300, max_depth=5, learning_rate=0.08,
                min_samples_leaf=3, subsample=0.9, random_state=42
            )
            try:
                model.fit(X_group, y_group, sample_weight=sw)
                self.models[group_name] = model
                self.active_groups.add(group_name)
                if verbose:
                    acc = model.score(X_group, y_group)
                    print(f"  [{group_name}] Trained on {len(indices)} samples, train_acc={acc:.3f}")
            except Exception as e:
                if verbose:
                    print(f"  [{group_name}] Training failed: {e}")

    def predict(self, X: np.ndarray, vuln_type: str) -> Optional[Tuple[bool, float]]:
        group = get_type_group(vuln_type)
        model = self.models.get(group)
        if model is None:
            return None
        try:
            prob = model.predict_proba(X.reshape(1, -1))[0][1]
            return prob >= 0.5, float(prob)
        except Exception:
            return None

    def has_model(self, vuln_type: str) -> bool:
        return get_type_group(vuln_type) in self.models


class CalibratedEnsemble:

    def __init__(self):
        self.base_models = {}
        self.calibrated_models = {}
        self.weights = {'gb': 0.30, 'rf': 0.20, 'et': 0.20, 'lgbm': 0.30}
        self.meta_learner = None
        self.use_stacking = False
        self.fitted = False
        self.feature_count = 0

    def _create_base_models(self, best_params: Dict = None):
        gb_params = best_params.get('gb', {}) if best_params else {}
        rf_params = best_params.get('rf', {}) if best_params else {}

        self.base_models = {
            'gb': GradientBoostingClassifier(
                n_estimators=gb_params.get('n_estimators', 400),
                max_depth=gb_params.get('max_depth', 6),
                learning_rate=gb_params.get('learning_rate', 0.08),
                min_samples_leaf=gb_params.get('min_samples_leaf', 3),
                subsample=gb_params.get('subsample', 0.9),
                random_state=42,
            ),
            'rf': RandomForestClassifier(
                n_estimators=rf_params.get('n_estimators', 500),
                max_depth=rf_params.get('max_depth', 12),
                min_samples_leaf=rf_params.get('min_samples_leaf', 2),
                max_features='sqrt',
                n_jobs=-1, random_state=42,
            ),
            'et': ExtraTreesClassifier(
                n_estimators=500, max_depth=12,
                min_samples_leaf=2, max_features='sqrt',
                n_jobs=-1, random_state=42,
            ),
        }
        if HAS_LGBM:
            self.base_models['lgbm'] = LGBMClassifier(
                n_estimators=500, max_depth=7,
                learning_rate=0.08, num_leaves=63,
                min_child_samples=10, subsample=0.9,
                n_jobs=-1, random_state=42, verbose=-1,
            )
        else:
            self.base_models['lgbm'] = RandomForestClassifier(
                n_estimators=700, max_depth=16,
                min_samples_leaf=1, max_features='log2',
                n_jobs=-1, random_state=43,
            )
            self.weights = {'gb': 0.35, 'rf': 0.25, 'et': 0.20, 'lgbm': 0.20}

    def fit(self, X: np.ndarray, y: np.ndarray,
            sample_weight=None, verbose=False):
        if not HAS_SKLEARN:
            return
        self.feature_count = X.shape[1]
        self._create_base_models()

        kf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        oof_preds = np.zeros((len(X), len(self.base_models)))

        if verbose:
            print(f"\n  Training {len(self.base_models)}-model ensemble on {len(X)} samples, {X.shape[1]} features")

        for i, (name, model) in enumerate(self.base_models.items()):
            if verbose:
                print(f"    [{name}] Cross-validating...", end=' ')
            try:
                oof_preds[:, i] = cross_val_predict(
                    model, X, y, cv=kf, method='predict_proba',
                    n_jobs=1  # Each model already uses n_jobs=-1 internally
                )[:, 1]
                if verbose:
                    from sklearn.metrics import f1_score
                    oof_binary = (oof_preds[:, i] >= 0.5).astype(int)
                    f1 = f1_score(y, oof_binary)
                    print(f"OOF F1={f1:.3f}")
            except Exception as e:
                if verbose:
                    print(f"Failed: {e}")
                oof_preds[:, i] = 0.5

        for name, model in self.base_models.items():
            if verbose:
                print(f"    [{name}] Fitting on full data...")
            try:
                if sample_weight is not None and name != 'et':
                    model.fit(X, y, sample_weight=sample_weight)
                else:
                    model.fit(X, y)
            except Exception as e:
                logger.warning(f"Base model {name} fit failed: {e}")

        try:
            meta_X = np.hstack([oof_preds, X])
            self.meta_learner = LogisticRegression(
                C=1.0, max_iter=1000, random_state=42
            )
            self.meta_learner.fit(meta_X, y)
            self.use_stacking = True
            if verbose:
                meta_pred = self.meta_learner.predict(meta_X)
                from sklearn.metrics import f1_score, precision_score, recall_score
                print(f"    [meta] Stacking F1={f1_score(y, meta_pred):.3f}, "
                      f"P={precision_score(y, meta_pred):.3f}, R={recall_score(y, meta_pred):.3f}")
        except Exception as e:
            if verbose:
                print(f"    [meta] Stacking failed, using voting: {e}")
            self.use_stacking = False

        self.fitted = True

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if not self.fitted:
            return np.full(len(X), 0.5)

        base_preds = np.zeros((len(X), len(self.base_models)))
        for i, (name, model) in enumerate(self.base_models.items()):
            try:
                base_preds[:, i] = model.predict_proba(X)[:, 1]
            except Exception:
                base_preds[:, i] = 0.5

        if self.use_stacking and self.meta_learner is not None:
            try:
                meta_X = np.hstack([base_preds, X])
                return self.meta_learner.predict_proba(meta_X)[:, 1]
            except Exception:
                pass

        probs = np.zeros(len(X))
        for i, name in enumerate(self.base_models):
            probs += self.weights.get(name, 0.25) * base_preds[:, i]
        return probs

    def predict_single(self, X: np.ndarray) -> Tuple[bool, float]:
        prob = float(self.predict_proba(X.reshape(1, -1))[0])
        return prob >= 0.5, prob


class MLClassifierV3:

    MODEL_FILE = "apex_fp_classifier_v5.pkl"

    def __init__(self, model_dir: str = None):
        self.model_dir = model_dir or str(Path(__file__).parent.parent / "models")
        self.ensemble: Optional[CalibratedEnsemble] = None
        self.per_type: Optional[PerTypeModelRegistry] = None
        self.tfidf: Optional[TFIDFFeaturePipeline] = None
        self.anomaly: Optional[AnomalyFeatureEnhancer] = None
        self.feature_names: List[str] = []
        self.thresholds = {'safe': 0.25, 'suspicious': 0.50}
        self._trained = False
        self._load_model()

    def _load_model(self):
        model_path = Path(self.model_dir) / self.MODEL_FILE
        if not model_path.exists():
            return
        try:
            import pickle
            with open(model_path, 'rb') as f:
                artifact = pickle.load(f)
            if artifact.get('version') != 'v3':
                return
            self.ensemble = artifact.get('ensemble')
            self.per_type = artifact.get('per_type_models')
            self.tfidf = artifact.get('tfidf_pipeline')
            self.anomaly = artifact.get('anomaly_detector')
            self.feature_names = artifact.get('feature_names', [])
            self.thresholds = artifact.get('thresholds', self.thresholds)
            self._trained = True
            logger.info(f"Loaded v5 model: {len(self.feature_names)} features")
        except Exception as e:
            logger.warning(f"Failed to load v5 model: {e}")

    def is_trained(self) -> bool:
        return self._trained and self.ensemble is not None

    def predict(self, features_dict: Dict, code_context: str = "") -> Tuple[bool, float]:
        if not self.is_trained():
            return True, 0.5

        vuln_type = features_dict.pop('vuln_type', '')

        X_struct = np.array([[features_dict.get(f, 0) for f in self.feature_names]])

        X_tfidf = np.zeros((1, self.tfidf.n_components)) if self.tfidf else np.zeros((1, 50))
        if self.tfidf and self.tfidf.fitted and code_context:
            X_tfidf = self.tfidf.transform_single(code_context).reshape(1, -1)

        anomaly_score = 0.0
        if self.anomaly and self.anomaly.fitted:
            anomaly_score = self.anomaly.score_single(X_struct[0])

        X_full = np.hstack([X_struct, X_tfidf, [[anomaly_score]]])

        ensemble_prob = float(self.ensemble.predict_proba(X_full)[0])

        if self.per_type and self.per_type.has_model(vuln_type):
            type_result = self.per_type.predict(X_full[0], vuln_type)
            if type_result is not None:
                _, type_prob = type_result
                final_prob = 0.6 * type_prob + 0.4 * ensemble_prob
            else:
                final_prob = ensemble_prob
        else:
            final_prob = ensemble_prob

        return final_prob >= self.thresholds['safe'], final_prob
