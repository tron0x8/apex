#!/usr/bin/env python3
"""
APEX ML FP Classifier - Advanced Training Script

Trains GradientBoosting model from:
  1. Vulnerable app scan results (bWAPP, WackoPicko, VulnPHP, Mutillidae) = TRUE POSITIVES
  2. Test fixtures (vuln_*.php = TP, safe_*.php = FP)
  3. Synthetic patterns (hardcoded TP/FP examples)
  4. CMS scan data with ground truth labels

Usage:
    python train_ml.py                    # Train from all available data
    python train_ml.py --verbose          # Verbose output
    python train_ml.py --data-dir PATH    # Custom data directory
"""

import os
import sys
import json
import time
import argparse
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent / "core"))

from core.ml_fp_classifier import (
    FeatureExtractor, FeatureVector, MLClassifier, HeuristicClassifier,
    TrainingDataGenerator, FPClassifier
)
from core.unified_scanner import UnifiedScanner
from training_data_extended import get_extended_fp_examples, get_extended_tp_examples


def load_scan_json(filepath):
    """Load scan results from JSON file."""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def extract_features_from_scan(scan_data, label, extractor, scanner=None):
    """Extract ML features from scan results.

    Args:
        scan_data: Parsed JSON scan results
        label: True = TP (vulnerable app), False = FP (safe app)
        extractor: FeatureExtractor instance
        scanner: UnifiedScanner for re-scanning if needed

    Returns:
        (features, labels) tuple
    """
    features = []
    labels = []

    for finding in scan_data.get('findings', []):
        filepath = finding.get('file', '')
        code_line = finding.get('code', '')

        # Try to read actual file for context
        code = ""
        file_lines = []
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
                file_lines = code.split('\n')
            except Exception:
                pass

        fv = extractor.extract(finding, code, file_lines)
        features.append(fv)
        labels.append(label)

    return features, labels


def generate_augmented_fp_data(extractor):
    """Generate additional FP training samples from common safe patterns."""
    features = []
    labels = []

    fp_examples = [
        # Prepared statements (clearly safe)
        {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '70%',
         'code': '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$_GET["id"]]);',
         'line': 10, 'file': 'user.php'},
        {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '65%',
         'code': '$stmt = $db->prepare("INSERT INTO logs (msg) VALUES (:msg)"); $stmt->bindParam(":msg", $msg);',
         'line': 15, 'file': 'log.php'},
        # ORM (safe)
        {'type': 'SQL Injection', 'severity': 'MEDIUM', 'confidence': '60%',
         'code': '$users = User::where("email", $request->input("email"))->first();',
         'line': 20, 'file': 'app/Http/Controllers/AuthController.php'},
        {'type': 'SQL Injection', 'severity': 'MEDIUM', 'confidence': '55%',
         'code': 'DB::table("users")->where("id", "=", $request->id)->get();',
         'line': 25, 'file': 'app/Http/Controllers/UserController.php'},
        # htmlspecialchars (XSS safe)
        {'type': 'Cross-Site Scripting', 'severity': 'MEDIUM', 'confidence': '55%',
         'code': 'echo htmlspecialchars($_GET["q"], ENT_QUOTES, "UTF-8");',
         'line': 5, 'file': 'search.php'},
        {'type': 'Cross-Site Scripting', 'severity': 'MEDIUM', 'confidence': '50%',
         'code': '<input value="<?php echo esc_attr($name); ?>">',
         'line': 30, 'file': 'form.php'},
        # escapeshellarg (CMDi safe)
        {'type': 'Command Injection', 'severity': 'HIGH', 'confidence': '70%',
         'code': 'exec("grep " . escapeshellarg($_POST["pattern"]) . " /var/log/app.log");',
         'line': 12, 'file': 'admin/search.php'},
        # intval/type cast (safe)
        {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '65%',
         'code': '$id = intval($_GET["id"]); $db->query("SELECT * FROM items WHERE id=" . $id);',
         'line': 8, 'file': 'item.php'},
        {'type': 'Insecure Direct Object Reference', 'severity': 'HIGH', 'confidence': '60%',
         'code': '$user_id = (int)$_GET["uid"];',
         'line': 3, 'file': 'profile.php'},
        # filter_var (safe)
        {'type': 'Server-Side Request Forgery', 'severity': 'HIGH', 'confidence': '65%',
         'code': '$url = filter_var($_GET["url"], FILTER_VALIDATE_URL); if($url) file_get_contents($url);',
         'line': 15, 'file': 'proxy.php'},
        # Comments (FP)
        {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '70%',
         'code': '// $db->query("SELECT * FROM users WHERE id=" . $_GET["id"]);',
         'line': 5, 'file': 'old_code.php'},
        {'type': 'Code Injection', 'severity': 'CRITICAL', 'confidence': '80%',
         'code': '/* eval($_POST["code"]); // removed for security */',
         'line': 10, 'file': 'legacy.php'},
        # Static values (FP)
        {'type': 'Hardcoded Credentials', 'severity': 'HIGH', 'confidence': '65%',
         'code': '$db_host = "localhost"; $db_name = "test_db";',
         'line': 5, 'file': 'config.sample.php'},
        # Framework-protected patterns
        {'type': 'Cross-Site Scripting', 'severity': 'MEDIUM', 'confidence': '55%',
         'code': 'return view("user.profile", ["name" => $request->name]);',
         'line': 20, 'file': 'app/Http/Controllers/ProfileController.php'},
        {'type': 'SQL Injection', 'severity': 'MEDIUM', 'confidence': '50%',
         'code': '$result = $this->db->where("status", $this->input->post("status"))->get("orders");',
         'line': 15, 'file': 'application/controllers/Order.php'},
        # Race condition FPs (read-only checks)
        {'type': 'Race Condition', 'severity': 'MEDIUM', 'confidence': '65%',
         'code': 'if (file_exists($cache_file)) { return file_get_contents($cache_file); }',
         'line': 25, 'file': 'cache.php'},
        # Weak crypto FPs (non-security use)
        {'type': 'Weak Cryptography', 'severity': 'MEDIUM', 'confidence': '65%',
         'code': '$cache_key = md5($url); // Cache key, not security',
         'line': 10, 'file': 'cache.php'},
        {'type': 'Insecure Randomness', 'severity': 'MEDIUM', 'confidence': '65%',
         'code': '$temp_name = "tmp_" . md5(uniqid(mt_rand())); // temp file name',
         'line': 5, 'file': 'upload.php'},
        # Header injection FPs (static redirects)
        {'type': 'HTTP Header Injection', 'severity': 'HIGH', 'confidence': '70%',
         'code': 'header("Location: /login.php");',
         'line': 3, 'file': 'logout.php'},
        {'type': 'HTTP Header Injection', 'severity': 'HIGH', 'confidence': '65%',
         'code': 'header("Content-Type: application/json");',
         'line': 1, 'file': 'api.php'},
        # Type narrowed to int (safe for SQLi)
        {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '70%',
         'code': '$id = (int)$_GET["id"]; if (is_int($id)) { $db->query("SELECT * FROM items WHERE id=" . $id); }',
         'line': 10, 'file': 'item.php'},
        # Framework validation applied (safe)
        {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '60%',
         'code': '$validated = $request->validate(["id" => "required|integer"]); DB::table("users")->find($validated["id"]);',
         'line': 15, 'file': 'app/Http/Controllers/UserController.php'},
        # Custom sanitizer wrapper function
        {'type': 'Cross-Site Scripting', 'severity': 'HIGH', 'confidence': '65%',
         'code': '$clean = sanitize_html($input); echo $clean;',
         'line': 8, 'file': 'output.php'},
        # Inter-procedural sanitizer wrapper
        {'type': 'SQL Injection', 'severity': 'MEDIUM', 'confidence': '60%',
         'code': '$safe = escape_sql_input($raw); $db->query("SELECT * FROM t WHERE id=" . $safe);',
         'line': 12, 'file': 'data.php'},
        # String context safe: variable in FROM position (table name)
        {'type': 'SQL Injection', 'severity': 'MEDIUM', 'confidence': '55%',
         'code': '$db->query("SELECT * FROM " . $table_name . " WHERE active=1");',
         'line': 10, 'file': 'model.php'},
        # Branch sanitized + used raw
        {'type': 'Cross-Site Scripting', 'severity': 'MEDIUM', 'confidence': '55%',
         'code': 'if ($safe) { $out = htmlspecialchars($name); } else { $out = $name; } echo $out;',
         'line': 5, 'file': 'template.php'},
        # Info disclosure FPs
        {'type': 'Information Disclosure', 'severity': 'MEDIUM', 'confidence': '50%',
         'code': 'error_log("User login: " . $username);',
         'line': 30, 'file': 'auth.php'},
    ]

    # Generate more augmented TP examples
    tp_examples = [
        # Stored XSS via database
        {'type': 'Cross-Site Scripting', 'severity': 'HIGH', 'confidence': '80%',
         'code': 'echo $row->entry;  // Direct DB output without escaping',
         'line': 50, 'file': 'blog.php'},
        # Second-order SQL injection
        {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '75%',
         'code': '$sql = "SELECT * FROM orders WHERE user=\'" . $username . "\'";',
         'line': 35, 'file': 'orders.php'},
        # File upload without validation
        {'type': 'Unsafe File Upload', 'severity': 'HIGH', 'confidence': '80%',
         'code': 'move_uploaded_file($_FILES["file"]["tmp_name"], "uploads/" . $_FILES["file"]["name"]);',
         'line': 20, 'file': 'upload.php'},
        # LDAP injection
        {'type': 'LDAP Injection', 'severity': 'HIGH', 'confidence': '85%',
         'code': 'ldap_search($ldap, $base_dn, "(uid=" . $_POST["username"] . ")");',
         'line': 15, 'file': 'ldap_auth.php'},
        # XXE
        {'type': 'XML External Entity', 'severity': 'HIGH', 'confidence': '80%',
         'code': '$xml = simplexml_load_string($body);  // From php://input',
         'line': 10, 'file': 'api/xml_handler.php'},
        # Open redirect
        {'type': 'Open Redirect', 'severity': 'HIGH', 'confidence': '85%',
         'code': 'header("Location: " . $_GET["url"]);',
         'line': 5, 'file': 'redirect.php'},
        # Mass assignment
        {'type': 'Mass Assignment', 'severity': 'HIGH', 'confidence': '85%',
         'code': 'extract($_POST);  // All POST data becomes local variables',
         'line': 3, 'file': 'process.php'},
        # Log injection
        {'type': 'Log Injection', 'severity': 'MEDIUM', 'confidence': '70%',
         'code': 'error_log("Login failed for: " . $_POST["username"]);',
         'line': 25, 'file': 'login.php'},
        # Type juggling in auth
        {'type': 'Type Juggling', 'severity': 'HIGH', 'confidence': '85%',
         'code': 'if ($stored_hash == $_POST["token"]) { grant_access(); }',
         'line': 18, 'file': 'verify.php'},
        # Path traversal
        {'type': 'Path Traversal', 'severity': 'HIGH', 'confidence': '80%',
         'code': 'include("templates/" . $_GET["page"]);',
         'line': 7, 'file': 'index.php'},
        # Deserialization from cookie
        {'type': 'Insecure Deserialization', 'severity': 'CRITICAL', 'confidence': '90%',
         'code': '$prefs = unserialize(base64_decode($_COOKIE["settings"]));',
         'line': 12, 'file': 'settings.php'},
        # Header injection with user data
        {'type': 'HTTP Header Injection', 'severity': 'HIGH', 'confidence': '85%',
         'code': 'header("X-Custom: " . $_POST["value"]);',
         'line': 8, 'file': 'api.php'},
        # Cross-function taint flow (inter-procedural)
        {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '80%',
         'code': '$result = get_user_input(); $db->query("SELECT * FROM users WHERE id=" . $result);',
         'line': 15, 'file': 'handler.php'},
        # Alias-based taint propagation
        {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '75%',
         'code': '$b = &$input; $db->query("SELECT * FROM t WHERE x=" . $b);',
         'line': 20, 'file': 'process.php'},
        # High tainted ratio (entire query is user-controlled)
        {'type': 'SQL Injection', 'severity': 'CRITICAL', 'confidence': '95%',
         'code': '$db->query($_POST["query"]);',
         'line': 5, 'file': 'admin.php'},
    ]

    for pattern in fp_examples:
        fv = extractor.extract(pattern, pattern['code'])
        features.append(fv)
        labels.append(False)

    for pattern in tp_examples:
        fv = extractor.extract(pattern, pattern['code'])
        features.append(fv)
        labels.append(True)

    return features, labels


def train_optimized(features, labels, model_dir, verbose=True):
    """Train with optimized hyperparameters using GridSearch."""
    try:
        import numpy as np
        from sklearn.ensemble import GradientBoostingClassifier
        from sklearn.model_selection import cross_val_score, StratifiedKFold, GridSearchCV
        from sklearn.metrics import classification_report, confusion_matrix
    except ImportError:
        print("ERROR: scikit-learn required. Install: pip install scikit-learn numpy")
        sys.exit(1)

    X = np.array([f.to_numeric_array() for f in features])
    y = np.array([1 if l else 0 for l in labels])

    n_tp = int(sum(y))
    n_fp = int(len(y) - sum(y))

    if verbose:
        print(f"\n{'='*60}")
        print(f"Training ML FP Classifier")
        print(f"{'='*60}")
        print(f"  Total samples: {len(X)}")
        print(f"  True Positives: {n_tp} ({n_tp*100//len(X)}%)")
        print(f"  False Positives: {n_fp} ({n_fp*100//len(X)}%)")
        print(f"  Features: {X.shape[1]}")

    # Asymmetric class weights: penalize missing a VULNERABLE (FN) 3.5x more
    # than flagging a SAFE as dangerous (FP). This is security-critical:
    # missing a real vulnerability is much worse than a false alarm.
    weight_tp = 3.5   # Cost of missing a real vulnerability (FN)
    weight_fp = 1.0   # Cost of false alarm (FP)
    sample_weights = np.array([weight_tp if l == 1 else weight_fp for l in y])

    if verbose:
        print(f"\n[*] Asymmetric weights: TP={weight_tp}, FP={weight_fp}")
        print(f"    (Missing a vuln costs {weight_tp}x more than a false alarm)")

    # Hyperparameter search
    if verbose:
        print(f"\n[*] Running hyperparameter optimization...")

    param_grid = {
        'n_estimators': [150, 200, 300, 400],
        'max_depth': [4, 5, 6, 7],
        'learning_rate': [0.05, 0.08, 0.1, 0.15],
        'min_samples_leaf': [2, 3, 5],
        'subsample': [0.8, 0.9, 1.0],
    }

    base_model = GradientBoostingClassifier(random_state=42)

    # Use fewer CV folds if small dataset
    n_folds = min(5, max(2, len(X) // 10))
    cv = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42)

    # Fast grid search with reduced combinations
    from sklearn.model_selection import RandomizedSearchCV

    # Custom scoring: prioritize recall (catching real vulns) while maintaining precision
    from sklearn.metrics import make_scorer, fbeta_score
    # F2 score: recall is weighted 2x more than precision
    f2_scorer = make_scorer(fbeta_score, beta=2)

    search = RandomizedSearchCV(
        base_model,
        param_grid,
        n_iter=60,  # Try 60 random combinations
        cv=cv,
        scoring=f2_scorer,  # F2 = recall-focused
        n_jobs=-1,  # Use all CPU cores
        random_state=42,
        verbose=0,
    )

    t0 = time.time()
    search.fit(X, y, sample_weight=sample_weights)
    search_time = time.time() - t0

    best_model = search.best_estimator_
    best_params = search.best_params_
    best_score = search.best_score_

    if verbose:
        print(f"  Search time: {search_time:.1f}s")
        print(f"  Best F2 (recall-focused): {best_score:.3f}")
        print(f"  Best params: {best_params}")

    # Cross-validation with best model
    cv_scores = cross_val_score(best_model, X, y, cv=cv, scoring='f1')

    if verbose:
        print(f"\n[*] Cross-validation results:")
        print(f"  F1 Score: {np.mean(cv_scores):.3f} (+/- {np.std(cv_scores):.3f})")

    # Also get accuracy
    cv_acc = cross_val_score(best_model, X, y, cv=cv, scoring='accuracy')
    if verbose:
        print(f"  Accuracy: {np.mean(cv_acc):.3f} (+/- {np.std(cv_acc):.3f})")

    # Train final model on all data
    t0 = time.time()
    best_model.fit(X, y, sample_weight=sample_weights)
    train_time = time.time() - t0

    # Training accuracy (sanity check)
    y_pred = best_model.predict(X)

    if verbose:
        print(f"\n[*] Final model (trained on all data):")
        print(f"  Train time: {train_time:.2f}s")
        print(f"  Training accuracy: {np.mean(y_pred == y):.3f}")
        print(f"\n  Classification Report:")
        print(classification_report(y, y_pred, target_names=['FP', 'TP']))
        print(f"  Confusion Matrix:")
        cm = confusion_matrix(y, y_pred)
        print(f"    Predicted:   FP    TP")
        print(f"    Actual FP: {cm[0][0]:4d}  {cm[0][1]:4d}")
        print(f"    Actual TP: {cm[1][0]:4d}  {cm[1][1]:4d}")

    # Feature importance
    feature_names = list(FeatureVector().to_dict().keys())
    feature_names.remove('vuln_type')
    importances = best_model.feature_importances_

    if verbose:
        sorted_idx = np.argsort(importances)[::-1]
        print(f"\n[*] Feature Importance (top 15):")
        for i in sorted_idx[:15]:
            bar = "#" * int(importances[i] * 50)
            print(f"    {feature_names[i]:28s} {importances[i]:.4f} {bar}")

    # Prediction speed test
    t0 = time.time()
    for _ in range(1000):
        best_model.predict(X[:1])
    pred_time = (time.time() - t0) / 1000

    if verbose:
        print(f"\n[*] Prediction speed: {pred_time*1000:.2f}ms per sample ({1/pred_time:.0f}/sec)")

    # 3-class threshold analysis
    if verbose:
        probs = best_model.predict_proba(X)[:, 1]
        print(f"\n[*] 3-Class Threshold Analysis:")
        for lo, hi, label in [(0.0, 0.30, 'SAFE'), (0.30, 0.55, 'SUSPICIOUS'), (0.55, 1.01, 'VULNERABLE')]:
            mask = (probs >= lo) & (probs < hi)
            n_in_class = mask.sum()
            n_tp_in = y[mask].sum() if n_in_class > 0 else 0
            n_fp_in = n_in_class - n_tp_in
            pct_tp = n_tp_in / max(n_in_class, 1) * 100
            print(f"    {label:12s} [{lo:.2f}-{hi:.2f}): {n_in_class:5d} samples ({n_tp_in:4d} TP, {n_fp_in:4d} FP, {pct_tp:.0f}% TP)")

    # Save model
    import pickle
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, "apex_fp_classifier_v4.pkl")
    with open(model_path, 'wb') as f:
        pickle.dump({
            'model': best_model,
            'feature_names': feature_names,
            'metrics': {
                'cv_f1': float(np.mean(cv_scores)),
                'cv_f1_std': float(np.std(cv_scores)),
                'cv_accuracy': float(np.mean(cv_acc)),
                'n_samples': len(X),
                'n_tp': n_tp,
                'n_fp': n_fp,
                'best_params': best_params,
                'train_time': train_time,
                'pred_speed_ms': pred_time * 1000,
            },
        }, f)

    if verbose:
        print(f"\n[+] Model saved to {model_path}")
        size_kb = os.path.getsize(model_path) / 1024
        print(f"    Size: {size_kb:.1f} KB")

    return {
        'cv_f1': float(np.mean(cv_scores)),
        'cv_accuracy': float(np.mean(cv_acc)),
        'n_samples': len(X),
        'n_tp': n_tp,
        'n_fp': n_fp,
        'best_params': best_params,
    }


def main():
    parser = argparse.ArgumentParser(description='APEX ML FP Classifier Training')
    parser.add_argument('--verbose', '-v', action='store_true', default=True)
    # Auto-detect data dir: local Windows path or remote/relative path
    default_data_dir = 'C:/Users/User/Desktop/vuln_datasets'
    if not os.path.exists(default_data_dir):
        # Try relative path (for remote server)
        default_data_dir = str(Path(__file__).parent / 'vuln_datasets')
    parser.add_argument('--data-dir', default=default_data_dir,
                        help='Directory with scan JSON files')
    parser.add_argument('--model-dir', default=None,
                        help='Output directory for model (default: apex/models/)')
    args = parser.parse_args()

    model_dir = args.model_dir or str(Path(__file__).parent / "models")
    data_dir = args.data_dir
    verbose = args.verbose

    extractor = FeatureExtractor()
    all_features = []
    all_labels = []

    print("=" * 60)
    print("APEX ML FP Classifier - Training Pipeline")
    print("=" * 60)

    # === Source 1: Vulnerable app scan results (all findings = TP) ===
    vuln_scans = {
        'bWAPP': 'scan_bwapp_v2.json',
        'WackoPicko': 'scan_wackopicko_v2.json',
        'VulnPHP': 'scan_vulnphp_v2.json',
        'Mutillidae': 'scan_mutillidae_v2.json',
    }

    for name, filename in vuln_scans.items():
        filepath = os.path.join(data_dir, filename)
        if os.path.exists(filepath):
            scan_data = load_scan_json(filepath)
            feats, labs = extract_features_from_scan(scan_data, True, extractor)
            all_features.extend(feats)
            all_labels.extend(labs)
            if verbose:
                print(f"  [TP] {name}: {len(feats)} findings")
        else:
            if verbose:
                print(f"  [--] {name}: {filename} not found")

    # === Source 2: Test fixtures (vuln_*.php = TP, safe_*.php = FP) ===
    fixture_dir = str(Path(__file__).parent / "tests" / "fixtures")
    if os.path.isdir(fixture_dir):
        gen = TrainingDataGenerator()
        fix_feats, fix_labs = gen.from_fixture_dir(fixture_dir)
        all_features.extend(fix_feats)
        all_labels.extend(fix_labs)
        n_fix_tp = sum(1 for l in fix_labs if l)
        n_fix_fp = sum(1 for l in fix_labs if not l)
        if verbose:
            print(f"  [MX] Fixtures: {len(fix_feats)} ({n_fix_tp} TP, {n_fix_fp} FP)")

    # === Source 3: Synthetic patterns (hardcoded TP/FP) ===
    gen = TrainingDataGenerator()
    syn_feats, syn_labs = gen.from_synthetic()
    all_features.extend(syn_feats)
    all_labels.extend(syn_labs)
    if verbose:
        n_syn_tp = sum(1 for l in syn_labs if l)
        n_syn_fp = sum(1 for l in syn_labs if not l)
        print(f"  [MX] Synthetic: {len(syn_feats)} ({n_syn_tp} TP, {n_syn_fp} FP)")

    # === Source 4: Augmented FP/TP data ===
    aug_feats, aug_labs = generate_augmented_fp_data(extractor)
    all_features.extend(aug_feats)
    all_labels.extend(aug_labs)
    if verbose:
        n_aug_tp = sum(1 for l in aug_labs if l)
        n_aug_fp = sum(1 for l in aug_labs if not l)
        print(f"  [MX] Augmented: {len(aug_feats)} ({n_aug_tp} TP, {n_aug_fp} FP)")

    # === Source 5: Extended FP/TP data (160+ FP, 20 TP) ===
    ext_fp = get_extended_fp_examples()
    ext_tp = get_extended_tp_examples()
    for pattern in ext_fp:
        fv = extractor.extract(pattern, pattern['code'])
        all_features.append(fv)
        all_labels.append(False)
    for pattern in ext_tp:
        fv = extractor.extract(pattern, pattern['code'])
        all_features.append(fv)
        all_labels.append(True)
    if verbose:
        print(f"  [MX] Extended: {len(ext_fp) + len(ext_tp)} ({len(ext_tp)} TP, {len(ext_fp)} FP)")

    # === Source 6: Stivalet labeled benchmark data ===
    stivalet_path = os.path.join(data_dir, 'training_data_labeled.json')
    if not os.path.exists(stivalet_path):
        # Try scan_results dir on server
        stivalet_path = '/root/scan_results/training_data_labeled.json'
    if os.path.exists(stivalet_path):
        stiv_data = load_scan_json(stivalet_path)
        n_stiv_tp = 0
        n_stiv_fp = 0
        # Sample to avoid overwhelming other data sources
        # Take all FP (valuable), sample TP to match
        stiv_fp_list = stiv_data.get('stivalet_fp', [])
        stiv_tp_list = stiv_data.get('stivalet_tp', [])
        vuln_tp_list = stiv_data.get('vuln_app_tp', [])

        # Use stratified sampling: max 2000 FP + 2000 TP from Stivalet
        import random
        random.seed(42)
        max_per_class = 2000
        if len(stiv_fp_list) > max_per_class:
            stiv_fp_list = random.sample(stiv_fp_list, max_per_class)
        if len(stiv_tp_list) > max_per_class:
            stiv_tp_list = random.sample(stiv_tp_list, max_per_class)

        for finding in stiv_fp_list:
            fv = extractor.extract(finding, finding.get('code', ''))
            all_features.append(fv)
            all_labels.append(False)
            n_stiv_fp += 1
        for finding in stiv_tp_list:
            fv = extractor.extract(finding, finding.get('code', ''))
            all_features.append(fv)
            all_labels.append(True)
            n_stiv_tp += 1
        for finding in vuln_tp_list:
            fv = extractor.extract(finding, finding.get('code', ''))
            all_features.append(fv)
            all_labels.append(True)
            n_stiv_tp += 1
        if verbose:
            print(f"  [MX] Stivalet benchmark: {n_stiv_tp + n_stiv_fp} ({n_stiv_tp} TP, {n_stiv_fp} FP)")
    else:
        if verbose:
            print(f"  [--] Stivalet: training_data_labeled.json not found")

    # === Source 7: CMS scan results (mixed labels from heuristic) ===
    cms_scans = {
        'MaxSiteCMS': ('scan_maxsite_v2.json', data_dir),
    }
    for name, (filename, scan_dir) in cms_scans.items():
        filepath = os.path.join(scan_dir, filename)
        if os.path.exists(filepath):
            scan_data = load_scan_json(filepath)
            # Use heuristic ML score as soft label:
            # High ml_score (>0.7) = likely TP, Low ml_score (<0.4) = likely FP
            n_tp_cms = 0
            n_fp_cms = 0
            for finding in scan_data.get('findings', []):
                ml_score = finding.get('ml_score', 0.5)
                label = ml_score > 0.6  # Trust heuristic labels

                fp = finding.get('file', '')
                code = ""
                if os.path.exists(fp):
                    try:
                        with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                            code = f.read()
                    except Exception:
                        pass

                fv = extractor.extract(finding, code, code.split('\n') if code else [])
                all_features.append(fv)
                all_labels.append(label)
                if label:
                    n_tp_cms += 1
                else:
                    n_fp_cms += 1

            if verbose:
                print(f"  [MX] {name}: {n_tp_cms + n_fp_cms} ({n_tp_cms} TP, {n_fp_cms} FP)")

    # === Train ===
    if len(all_features) < 20:
        print(f"\nERROR: Not enough training data ({len(all_features)} samples, need 20+)")
        sys.exit(1)

    metrics = train_optimized(all_features, all_labels, model_dir, verbose)

    # === Verify with re-scan ===
    if verbose:
        print(f"\n{'='*60}")
        print(f"[*] Verifying trained model...")
        print(f"{'='*60}")

        classifier = FPClassifier(model_dir=model_dir)
        if classifier.ml and classifier.ml.is_trained():
            print(f"  Model loaded successfully (method: ml)")

            # Quick test on a known TP
            test_tp = {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '90%',
                       'code': '$db->query("SELECT * FROM users WHERE id=" . $_GET["id"])',
                       'line': 10, 'file': 'test.php'}
            result = classifier.classify(test_tp, test_tp['code'])
            print(f"  Test TP (SQLi): is_tp={result.is_tp}, score={result.score:.3f}, method={result.method}")

            # Quick test on a known FP
            test_fp = {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '70%',
                       'code': '$stmt = $db->prepare("SELECT * FROM users WHERE id = ?");',
                       'line': 10, 'file': 'safe.php'}
            result = classifier.classify(test_fp, test_fp['code'])
            print(f"  Test FP (prepared): is_tp={result.is_tp}, score={result.score:.3f}, method={result.method}")
        else:
            print(f"  WARNING: Model not loaded!")

    print(f"\n{'='*60}")
    print(f"Training complete!")
    print(f"  F1 Score: {metrics['cv_f1']:.3f}")
    print(f"  Accuracy: {metrics['cv_accuracy']:.3f}")
    print(f"  Samples: {metrics['n_samples']} ({metrics['n_tp']} TP, {metrics['n_fp']} FP)")
    print(f"{'='*60}")


if __name__ == '__main__':
    main()
