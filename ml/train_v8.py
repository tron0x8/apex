#!/usr/bin/env python3
"""
APEX ML Training v8.0 - Real Training Data
Uses actual vulnerable and safe code examples
"""

import os
import sys
import re
import pickle
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
import lightgbm as lgb

print("=" * 70)
print("APEX ML Training v8.0 - Real Training Data")
print("=" * 70)


class FeatureExtractor:
    """Extract security-relevant features from PHP code"""

    SOURCES = {
        'GET': r'\$_GET',
        'POST': r'\$_POST',
        'REQUEST': r'\$_REQUEST',
        'COOKIE': r'\$_COOKIE',
        'FILES': r'\$_FILES',
        'SERVER': r'\$_SERVER',
        'INPUT': r'php://input',
    }

    SINKS = {
        'SQL': r'(?:mysql_query|mysqli_query|->query|->exec)',
        'CMD': r'(?:\bexec\b|\bsystem\b|\bpassthru\b|shell_exec|popen|`)',
        'ECHO': r'(?:\becho\b|\bprint\b|\bprintf\b)',
        'INCLUDE': r'(?:\binclude\b|\brequire\b)',
        'EVAL': r'(?:\beval\b|\bassert\b|create_function)',
        'FILE': r'(?:file_get_contents|file_put_contents|fopen|fwrite)',
        'UNSER': r'\bunserialize\b',
    }

    SANITIZERS = {
        'INTVAL': r'(?:intval|\(int\))',
        'ESCAPE_SQL': r'(?:escape_string|addslashes|->quote|safesql)',
        'PREPARE': r'(?:->prepare|bindParam|bindValue)',
        'ESCAPE_HTML': r'(?:htmlspecialchars|htmlentities|strip_tags)',
        'ESCAPE_CMD': r'(?:escapeshellarg|escapeshellcmd)',
        'ESCAPE_PATH': r'(?:basename|realpath)',
        'VALIDATE': r'(?:is_numeric|ctype_digit|ctype_alnum|filter_var)',
        'WHITELIST': r'(?:in_array|preg_match\s*\(\s*[\'"][/^])',
    }

    FRAMEWORKS = {
        'LARAVEL': r'(?:Illuminate|Eloquent|->where\s*\([^,]+,)',
        'SYMFONY': r'(?:Symfony|setParameter)',
        'WORDPRESS': r'(?:\$wpdb->prepare|esc_html|esc_attr)',
        'DOCTRINE': r'(?:Doctrine|createQuery)',
    }

    def extract(self, code: str) -> dict:
        """Extract all features"""
        features = {
            'sources': [],
            'sinks': [],
            'sanitizers': [],
            'frameworks': [],
            'has_source': False,
            'has_sink': False,
            'has_sanitizer': False,
            'has_framework': False,
        }

        for name, pattern in self.SOURCES.items():
            if re.search(pattern, code, re.I):
                features['sources'].append(name)
                features['has_source'] = True

        for name, pattern in self.SINKS.items():
            if re.search(pattern, code, re.I):
                features['sinks'].append(name)
                features['has_sink'] = True

        for name, pattern in self.SANITIZERS.items():
            if re.search(pattern, code, re.I):
                features['sanitizers'].append(name)
                features['has_sanitizer'] = True

        for name, pattern in self.FRAMEWORKS.items():
            if re.search(pattern, code, re.I):
                features['frameworks'].append(name)
                features['has_framework'] = True

        return features

    def to_tokens(self, code: str) -> str:
        """Convert code to feature tokens"""
        features = self.extract(code)
        tokens = []

        # Add source tokens
        for src in features['sources']:
            tokens.append(f"SRC_{src}")

        # Add sink tokens
        for sink in features['sinks']:
            tokens.append(f"SINK_{sink}")

        # Add sanitizer tokens
        for san in features['sanitizers']:
            tokens.append(f"SAN_{san}")

        # Add framework tokens
        for fw in features['frameworks']:
            tokens.append(f"FW_{fw}")

        # Add flow tokens
        if features['has_source'] and features['has_sink']:
            if features['has_sanitizer']:
                tokens.append("FLOW_SANITIZED")
            else:
                tokens.append("FLOW_UNSANITIZED")

        if features['has_framework']:
            tokens.append("HAS_FRAMEWORK")

        # Add some code structure tokens
        funcs = re.findall(r'\b([a-zA-Z_]\w*)\s*\(', code)
        for func in funcs[:20]:
            tokens.append(f"FUNC_{func.lower()}")

        return ' '.join(tokens)


def load_training_data():
    """Load training data from files"""
    data_dir = Path(__file__).parent / 'training_data'
    codes = []
    labels = []

    # Load vulnerable examples
    vuln_dir = data_dir / 'vulnerable'
    if vuln_dir.exists():
        for php_file in vuln_dir.glob('*.php'):
            try:
                content = php_file.read_text(encoding='utf-8', errors='ignore')
                # Split by examples (each example is a block)
                examples = re.split(r'//\s*Example\s+\d+:', content)
                for ex in examples[1:]:  # Skip first (header)
                    ex = ex.strip()
                    if len(ex) > 20:
                        codes.append(ex)
                        labels.append(1)  # Vulnerable
            except Exception as e:
                print(f"Error loading {php_file}: {e}")

    # Load safe examples
    safe_dir = data_dir / 'safe'
    if safe_dir.exists():
        for php_file in safe_dir.glob('*.php'):
            try:
                content = php_file.read_text(encoding='utf-8', errors='ignore')
                examples = re.split(r'//\s*Example\s+\d+:', content)
                for ex in examples[1:]:
                    ex = ex.strip()
                    if len(ex) > 20:
                        codes.append(ex)
                        labels.append(0)  # Safe
            except Exception as e:
                print(f"Error loading {php_file}: {e}")

    return codes, labels


def augment_data(codes, labels):
    """Augment training data with variations"""
    augmented_codes = []
    augmented_labels = []

    for code, label in zip(codes, labels):
        # Original
        augmented_codes.append(code)
        augmented_labels.append(label)

        # Variations
        variations = [
            code.replace('$_GET', '$_POST'),
            code.replace('$_POST', '$_REQUEST'),
            code.replace('mysql_query', 'mysqli_query'),
            code.replace('echo', 'print'),
            code.replace('system', 'exec'),
        ]

        for var in variations:
            if var != code:
                augmented_codes.append(var)
                augmented_labels.append(label)

    return augmented_codes, augmented_labels


def train():
    """Train the model"""
    # Load data
    print("\n[1] Loading training data...")
    codes, labels = load_training_data()
    print(f"    Loaded {len(codes)} examples")
    print(f"    Vulnerable: {labels.count(1)}")
    print(f"    Safe: {labels.count(0)}")

    if len(codes) < 20:
        print("    [!] Not enough data, adding synthetic examples...")
        # Add some synthetic examples
        synthetic_vuln = [
            '$id=$_GET["id"];mysql_query("SELECT * FROM x WHERE id=$id");',
            'system($_POST["cmd"]);',
            'include($_GET["page"]);',
            'echo $_GET["name"];',
            'eval($_POST["code"]);',
            'unserialize($_COOKIE["data"]);',
        ]
        synthetic_safe = [
            '$id=intval($_GET["id"]);mysql_query("SELECT * FROM x WHERE id=$id");',
            '$cmd=escapeshellarg($_POST["cmd"]);system($cmd);',
            'echo htmlspecialchars($_GET["name"]);',
            '$stmt=$pdo->prepare("SELECT * FROM x WHERE id=?");$stmt->execute([$_GET["id"]]);',
        ]
        codes.extend(synthetic_vuln * 5)
        labels.extend([1] * len(synthetic_vuln) * 5)
        codes.extend(synthetic_safe * 5)
        labels.extend([0] * len(synthetic_safe) * 5)

    # Augment data
    print("\n[2] Augmenting data...")
    codes, labels = augment_data(codes, labels)
    print(f"    After augmentation: {len(codes)} examples")

    # Extract features
    print("\n[3] Extracting features...")
    extractor = FeatureExtractor()
    features = [extractor.to_tokens(c) for c in codes]

    # Vectorize
    print("\n[4] Vectorizing...")
    vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1, 2))
    X = vectorizer.fit_transform(features)
    y = np.array(labels)

    # Balance classes
    print("\n[5] Balancing classes...")
    vuln_idx = np.where(y == 1)[0]
    safe_idx = np.where(y == 0)[0]
    n_samples = min(len(vuln_idx), len(safe_idx))

    np.random.seed(42)
    balanced_idx = np.concatenate([
        np.random.choice(vuln_idx, n_samples, replace=len(vuln_idx) < n_samples),
        np.random.choice(safe_idx, n_samples, replace=len(safe_idx) < n_samples)
    ])
    np.random.shuffle(balanced_idx)

    X_bal = X[balanced_idx]
    y_bal = y[balanced_idx]
    print(f"    Balanced: {len(y_bal)} samples ({n_samples} each)")

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X_bal, y_bal, test_size=0.2, random_state=42, stratify=y_bal
    )

    # Train
    print("\n[6] Training LightGBM...")
    train_data = lgb.Dataset(X_train, label=y_train)
    valid_data = lgb.Dataset(X_test, label=y_test, reference=train_data)

    params = {
        'objective': 'binary',
        'metric': 'binary_logloss',
        'boosting_type': 'gbdt',
        'num_leaves': 31,
        'learning_rate': 0.05,
        'feature_fraction': 0.9,
        'verbose': -1,
    }

    model = lgb.train(
        params,
        train_data,
        num_boost_round=300,
        valid_sets=[valid_data],
        callbacks=[
            lgb.early_stopping(stopping_rounds=30),
            lgb.log_evaluation(0)
        ]
    )

    # Evaluate
    print("\n" + "=" * 70)
    print("EVALUATION")
    print("=" * 70)

    y_pred_prob = model.predict(X_test)
    y_pred = (y_pred_prob > 0.5).astype(int)

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['SAFE', 'VULN']))

    cm = confusion_matrix(y_test, y_pred)
    print("Confusion Matrix:")
    print(f"    TN={cm[0][0]:4d}  FP={cm[0][1]:4d}")
    print(f"    FN={cm[1][0]:4d}  TP={cm[1][1]:4d}")

    # Save model
    print("\n[7] Saving model...")
    model_path = Path(__file__).parent / 'vuln_model_v8.pkl'
    with open(model_path, 'wb') as f:
        pickle.dump({
            'model': model,
            'vectorizer': vectorizer,
            'extractor_class': 'FeatureExtractor',
            'version': '8.0',
        }, f)
    print(f"    Saved to: {model_path}")

    return model, vectorizer


if __name__ == "__main__":
    train()
