#!/usr/bin/env python3
"""
APEX ML FP Classifier v2 - Comprehensive Training Script

Uses ALL available data sources with NO Stivalet sample limits.
No live scanning (fast) - uses pre-computed scan JSONs + synthetic data.

Usage:
    python train_ml_v2.py                    # Train
    python train_ml_v2.py --verbose          # Verbose
"""

import os
import sys
import json
import time
import random
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent / "core"))

from core.ml_fp_classifier import (
    FeatureExtractor, FeatureVector, MLClassifier, HeuristicClassifier,
    TrainingDataGenerator, FPClassifier
)

try:
    from training_data_extended import get_extended_fp_examples, get_extended_tp_examples
    _HAS_EXTENDED = True
except ImportError:
    _HAS_EXTENDED = False


def load_json(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        return json.load(f)


def extract_from_findings(findings, label, extractor):
    features, labels = [], []
    for f in findings:
        code = f.get('code', '')
        filepath = f.get('file', '')
        file_lines = []
        full_code = ""
        if filepath and os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as fh:
                    full_code = fh.read()
                file_lines = full_code.split('\n')
            except Exception:
                pass
        fv = extractor.extract(f, full_code or code, file_lines)
        features.append(fv)
        labels.append(label)
    return features, labels


# ================================================================
# Manually labeled CMS findings from v6 analysis (most valuable data)
# ================================================================
MANUAL_CMS_LABELS = [
    # MaxSiteCMS - TRUE POSITIVES
    {'type': 'Arbitrary File Write', 'severity': 'CRITICAL', 'confidence': '90%',
     'code': 'file_put_contents(base64_decode($post["file_path"]), $post["content"]);',
     'line': 17, 'file': 'save-file-ajax.php', 'label': True},
    {'type': 'Arbitrary File Read', 'severity': 'HIGH', 'confidence': '85%',
     'code': 'echo file_get_contents(base64_decode($post["file"]));',
     'line': 10, 'file': 'load-file-ajax.php', 'label': True},
    {'type': 'Arbitrary File Write', 'severity': 'CRITICAL', 'confidence': '90%',
     'code': 'file_put_contents($up_dir . $fn, file_get_contents("php://input"));',
     'line': 44, 'file': 'uploads-require-maxsite.php', 'label': True},
    {'type': 'XML External Entity', 'severity': 'HIGH', 'confidence': '80%',
     'code': '$xml = simplexml_load_string($xml_string);',
     'line': 15, 'file': 'lib_pingback.php', 'label': True},
    # DLE CMS - TRUE POSITIVES
    {'type': 'Cross-Site Scripting', 'severity': 'HIGH', 'confidence': '85%',
     'code': 'echo $_REQUEST["action"];',
     'line': 148, 'file': 'engine/inc/userfields.php', 'label': True},
    {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '80%',
     'code': '$db->query("UPDATE " . PREFIX . "_users SET " . $_POST["field"]);',
     'line': 50, 'file': 'engine/ajax/rating.php', 'label': True},
    # DLE CMS - FALSE POSITIVES
    {'type': 'Insecure Randomness', 'severity': 'HIGH', 'confidence': '85%',
     'code': '$hash = md5(microtime(TRUE)); // ETag for CSS caching',
     'line': 137, 'file': 'templates/Default/style.css.php', 'label': False},
    {'type': 'Weak Cryptography', 'severity': 'MEDIUM', 'confidence': '65%',
     'code': '$etag = md5($content); // HTTP ETag, not security',
     'line': 15, 'file': 'engine/cache.php', 'label': False},
    # Geeklog - TRUE POSITIVES
    {'type': 'SQL Injection', 'severity': 'CRITICAL', 'confidence': '85%',
     'code': '$sql = sprintf("UPDATE %s SET value=\'%s\'", $table, serialize($_POST[$config]));',
     'line': 274, 'file': 'admin/install/rescue.php', 'label': True},
    {'type': 'Insecure Randomness', 'severity': 'HIGH', 'confidence': '70%',
     'code': '$emailconfirmid = substr(md5(uniqid(rand(),1)),1,16);',
     'line': 1466, 'file': 'system/lib-user.php', 'label': True},
    # Geeklog - FALSE POSITIVES
    {'type': 'Arbitrary File Write', 'severity': 'HIGH', 'confidence': '98%',
     'code': 'file_put_contents($etag_filename, $etag); // writing cached ETag',
     'line': 146, 'file': 'layout/style.css.php', 'label': False},
    {'type': 'Arbitrary File Read', 'severity': 'HIGH', 'confidence': '98%',
     'code': '$etag = file_get_contents($etag_filename); // reading cached ETag',
     'line': 127, 'file': 'layout/style.css.php', 'label': False},
    {'type': 'HTTP Header Injection', 'severity': 'HIGH', 'confidence': '85%',
     'code': 'header("Location: " . $_CONF["site_url"] . "/path");',
     'line': 192, 'file': 'system/lib-webservices.php', 'label': False},
    {'type': 'Information Disclosure', 'severity': 'MEDIUM', 'confidence': '65%',
     'code': 'var_dump($XML_RPC_xh[$parser]["value"]); // debug behind flag',
     'line': 1505, 'file': 'classes/XML/RPC.php', 'label': False},
    {'type': 'Race Condition', 'severity': 'HIGH', 'confidence': '65%',
     'code': '$handle = fopen($path.$file, "w"); // test file cleanup',
     'line': 390, 'file': 'tests/files/classes/tests.class.php', 'label': False},
    # ImpressPages - TRUE POSITIVES
    {'type': 'Weak Cryptography', 'severity': 'HIGH', 'confidence': '65%',
     'code': '$hash = md5($salt . $password, TRUE);',
     'line': 135, 'file': 'Ip/Lib/PasswordHash.php', 'label': True},
    {'type': 'Insecure Randomness', 'severity': 'HIGH', 'confidence': '65%',
     'code': '$public_key = substr(md5(uniqid(rand(),true)), 0, $this->chars);',
     'line': 676, 'file': 'Ip/Lib/HnCaptcha/HnCaptcha.php', 'label': True},
    # ImpressPages - FALSE POSITIVES
    {'type': 'File Inclusion', 'severity': 'HIGH', 'confidence': '85%',
     'code': '$composerPlugins = require($composerConfigFile);',
     'line': 112, 'file': 'Ip/Config.php', 'label': False},
    {'type': 'File Inclusion', 'severity': 'HIGH', 'confidence': '85%',
     'code': '$config = array_merge($config, require($envConfigFile));',
     'line': 277, 'file': 'Ip/Config.php', 'label': False},
]

# Synthetic webshell patterns (avoids slow live scanning)
WEBSHELL_PATTERNS = [
    {'type': 'Code Injection', 'severity': 'CRITICAL', 'confidence': '95%',
     'code': 'eval($_POST["cmd"]);', 'line': 3, 'file': 'shell.php'},
    {'type': 'Code Injection', 'severity': 'CRITICAL', 'confidence': '95%',
     'code': 'eval(base64_decode($_POST["e"]));', 'line': 5, 'file': 'b64.php'},
    {'type': 'Code Injection', 'severity': 'CRITICAL', 'confidence': '90%',
     'code': 'eval(gzinflate(base64_decode($x)));', 'line': 10, 'file': 'enc.php'},
    {'type': 'Command Injection', 'severity': 'CRITICAL', 'confidence': '95%',
     'code': 'system($_GET["cmd"]);', 'line': 2, 'file': 'cmd.php'},
    {'type': 'Command Injection', 'severity': 'CRITICAL', 'confidence': '95%',
     'code': 'passthru($_REQUEST["c"]);', 'line': 3, 'file': 'bd.php'},
    {'type': 'Command Injection', 'severity': 'CRITICAL', 'confidence': '90%',
     'code': 'shell_exec("bash -c " . $_POST["cmd"]);', 'line': 8, 'file': 'rce.php'},
    {'type': 'Command Injection', 'severity': 'CRITICAL', 'confidence': '90%',
     'code': '$output = `{$_GET["c"]}`;', 'line': 4, 'file': 'bt.php'},
    {'type': 'Arbitrary File Write', 'severity': 'CRITICAL', 'confidence': '90%',
     'code': 'file_put_contents($_POST["f"], $_POST["d"]);', 'line': 5, 'file': 'wr.php'},
    {'type': 'Arbitrary File Read', 'severity': 'HIGH', 'confidence': '85%',
     'code': 'echo file_get_contents($_GET["f"]);', 'line': 3, 'file': 'rd.php'},
    {'type': 'Code Injection', 'severity': 'CRITICAL', 'confidence': '90%',
     'code': 'assert($_POST["code"]);', 'line': 2, 'file': 'assert.php'},
    {'type': 'Code Injection', 'severity': 'CRITICAL', 'confidence': '90%',
     'code': 'preg_replace("/.*/e", $_POST["code"], "");', 'line': 5, 'file': 'preg.php'},
    {'type': 'Code Injection', 'severity': 'CRITICAL', 'confidence': '95%',
     'code': '$f="cr"."eate_function"; $f("",$_POST["x"])();', 'line': 4, 'file': 'obf.php'},
    {'type': 'Arbitrary File Write', 'severity': 'CRITICAL', 'confidence': '90%',
     'code': 'move_uploaded_file($_FILES["f"]["tmp_name"], $_POST["path"]);', 'line': 10, 'file': 'up.php'},
    {'type': 'Command Injection', 'severity': 'CRITICAL', 'confidence': '90%',
     'code': 'proc_open($_GET["cmd"], $desc, $pipes);', 'line': 6, 'file': 'proc.php'},
    {'type': 'Code Injection', 'severity': 'CRITICAL', 'confidence': '85%',
     'code': 'call_user_func($_GET["fn"], $_GET["arg"]);', 'line': 4, 'file': 'call.php'},
]


def collect_all_data(extractor, data_dir, verbose=True):
    all_features = []
    all_labels = []
    stats = {}

    def add(feats, labs, name):
        all_features.extend(feats)
        all_labels.extend(labs)
        n_tp = sum(1 for l in labs if l)
        n_fp = sum(1 for l in labs if not l)
        stats[name] = {'total': len(labs), 'tp': n_tp, 'fp': n_fp}
        if verbose:
            print(f"  [{name:30s}] {len(labs):5d} ({n_tp:4d} TP, {n_fp:4d} FP)")

    print("\n" + "=" * 60)
    print("Collecting Training Data")
    print("=" * 60)

    # ================================================================
    # 1. STIVALET FULL (no limit!)
    # ================================================================
    print("\n[1] Stivalet Benchmark (FULL)")

    stivalet_path = os.path.join(data_dir, 'training_data_labeled.json')
    if not os.path.exists(stivalet_path):
        stivalet_path = '/root/scan_results/training_data_labeled.json'

    if os.path.exists(stivalet_path):
        stiv = load_json(stivalet_path)

        stiv_fp = stiv.get('stivalet_fp', [])
        f, l = extract_from_findings(stiv_fp, False, extractor)
        add(f, l, "stivalet_fp")

        stiv_tp = stiv.get('stivalet_tp', [])
        f, l = extract_from_findings(stiv_tp, True, extractor)
        add(f, l, "stivalet_tp")

        vuln_tp = stiv.get('vuln_app_tp', [])
        if vuln_tp:
            f, l = extract_from_findings(vuln_tp, True, extractor)
            add(f, l, "stivalet_vuln_app")

    # ================================================================
    # 2. VULN APP SCANS (= TP)
    # ================================================================
    print("\n[2] Vulnerable App Scans (TP)")

    scan_dir = '/root/scan_results'
    if not os.path.exists(scan_dir):
        scan_dir = data_dir

    vuln_files = {
        'DVWA': ['dvwa_v6.json', 'dvwa_v2.json', 'dvwa.json'],
        'XVWA': ['xvwa_v6.json', 'xvwa.json'],
        'WebGoat': ['webgoat_v6.json', 'webgoat.json'],
        'bWAPP': ['scan_bwapp_v2.json'],
        'WackoPicko': ['scan_wackopicko_v2.json'],
        'VulnPHP': ['scan_vulnphp_v2.json'],
        'Mutillidae': ['scan_mutillidae_v2.json'],
    }

    for name, candidates in vuln_files.items():
        for fn in candidates:
            fp = os.path.join(scan_dir, fn)
            if not os.path.exists(fp):
                fp = os.path.join(data_dir, fn)
            if os.path.exists(fp):
                data = load_json(fp)
                findings = data.get('findings', [])
                feats, labs = extract_from_findings(findings, True, extractor)
                add(feats, labs, f"vuln_{name}")
                break

    # ================================================================
    # 3. WEBSHELL SYNTHETIC (TP)
    # ================================================================
    print("\n[3] Webshell Patterns (TP)")

    ws_f, ws_l = [], []
    for p in WEBSHELL_PATTERNS:
        fv = extractor.extract(p, p['code'])
        ws_f.append(fv)
        ws_l.append(True)
    add(ws_f, ws_l, "webshell_synthetic")

    # ================================================================
    # 4. SAFE FRAMEWORK SCANS (= FP)
    # ================================================================
    print("\n[4] Safe Framework Scans (FP)")

    for fn in ['pagekit_v6.json']:
        fp = os.path.join(scan_dir, fn)
        if os.path.exists(fp):
            data = load_json(fp)
            findings = data.get('findings', [])
            if findings:
                feats, labs = extract_from_findings(findings, False, extractor)
                add(feats, labs, f"safe_{fn.replace('_v6.json','')}")

    # ================================================================
    # 5. TEST FIXTURES
    # ================================================================
    print("\n[5] Test Fixtures")

    fixture_dir = str(Path(__file__).parent / "tests" / "fixtures")
    if os.path.isdir(fixture_dir):
        gen = TrainingDataGenerator()
        fix_f, fix_l = gen.from_fixture_dir(fixture_dir)
        add(fix_f, fix_l, "fixtures")

    # ================================================================
    # 6. SYNTHETIC + AUGMENTED
    # ================================================================
    print("\n[6] Synthetic/Augmented")

    gen = TrainingDataGenerator()
    syn_f, syn_l = gen.from_synthetic()
    add(syn_f, syn_l, "synthetic")

    # Augmented FP examples
    aug_fp = [
        {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '70%',
         'code': '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$_GET["id"]]);',
         'line': 10, 'file': 'user.php'},
        {'type': 'SQL Injection', 'severity': 'MEDIUM', 'confidence': '60%',
         'code': '$users = User::where("email", $request->input("email"))->first();',
         'line': 20, 'file': 'app/Http/Controllers/AuthController.php'},
        {'type': 'Cross-Site Scripting', 'severity': 'MEDIUM', 'confidence': '55%',
         'code': 'echo htmlspecialchars($_GET["q"], ENT_QUOTES, "UTF-8");',
         'line': 5, 'file': 'search.php'},
        {'type': 'Command Injection', 'severity': 'HIGH', 'confidence': '70%',
         'code': 'exec("grep " . escapeshellarg($_POST["pattern"]) . " /var/log/app.log");',
         'line': 12, 'file': 'admin/search.php'},
        {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '65%',
         'code': '$id = intval($_GET["id"]); $db->query("SELECT * FROM items WHERE id=" . $id);',
         'line': 8, 'file': 'item.php'},
        {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '70%',
         'code': '// $db->query("SELECT * FROM users WHERE id=" . $_GET["id"]);',
         'line': 5, 'file': 'old_code.php'},
        {'type': 'HTTP Header Injection', 'severity': 'HIGH', 'confidence': '70%',
         'code': 'header("Location: /login.php");',
         'line': 3, 'file': 'logout.php'},
        {'type': 'Weak Cryptography', 'severity': 'MEDIUM', 'confidence': '65%',
         'code': '$cache_key = md5($url); // Cache key, not security',
         'line': 10, 'file': 'cache.php'},
        {'type': 'Race Condition', 'severity': 'MEDIUM', 'confidence': '65%',
         'code': 'if (file_exists($cache_file)) { return file_get_contents($cache_file); }',
         'line': 25, 'file': 'cache.php'},
    ]
    aug_tp = [
        {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '85%',
         'code': '$sql = "SELECT * FROM orders WHERE user=\'" . $username . "\'";',
         'line': 35, 'file': 'orders.php'},
        {'type': 'Unsafe File Upload', 'severity': 'HIGH', 'confidence': '80%',
         'code': 'move_uploaded_file($_FILES["file"]["tmp_name"], "uploads/" . $_FILES["file"]["name"]);',
         'line': 20, 'file': 'upload.php'},
        {'type': 'Open Redirect', 'severity': 'HIGH', 'confidence': '85%',
         'code': 'header("Location: " . $_GET["url"]);',
         'line': 5, 'file': 'redirect.php'},
        {'type': 'Code Injection', 'severity': 'CRITICAL', 'confidence': '95%',
         'code': '$db->query($_POST["query"]);',
         'line': 5, 'file': 'admin.php'},
        {'type': 'Insecure Deserialization', 'severity': 'CRITICAL', 'confidence': '90%',
         'code': '$prefs = unserialize(base64_decode($_COOKIE["settings"]));',
         'line': 12, 'file': 'settings.php'},
    ]
    aug_f, aug_l = [], []
    for p in aug_fp:
        aug_f.append(extractor.extract(p, p['code']))
        aug_l.append(False)
    for p in aug_tp:
        aug_f.append(extractor.extract(p, p['code']))
        aug_l.append(True)
    add(aug_f, aug_l, "augmented")

    # Extended data (160+ FP, 30+ TP)
    if _HAS_EXTENDED:
        ext_fp = get_extended_fp_examples()
        ext_tp = get_extended_tp_examples()
        ext_f, ext_l = [], []
        for p in ext_fp:
            ext_f.append(extractor.extract(p, p['code']))
            ext_l.append(False)
        for p in ext_tp:
            ext_f.append(extractor.extract(p, p['code']))
            ext_l.append(True)
        add(ext_f, ext_l, "extended")

    # ================================================================
    # 7. MANUAL CMS LABELS (most valuable)
    # ================================================================
    print("\n[7] Manual CMS Labels")

    man_f, man_l = [], []
    for item in MANUAL_CMS_LABELS:
        finding = {k: v for k, v in item.items() if k != 'label'}
        man_f.append(extractor.extract(finding, finding.get('code', '')))
        man_l.append(item['label'])
    add(man_f, man_l, "manual_cms")

    return all_features, all_labels, stats


def train_model(features, labels, model_dir, verbose=True):
    try:
        import numpy as np
        from sklearn.ensemble import GradientBoostingClassifier
        from sklearn.model_selection import (
            cross_val_score, StratifiedKFold, RandomizedSearchCV,
            train_test_split
        )
        from sklearn.metrics import (
            classification_report, confusion_matrix, fbeta_score,
            make_scorer, precision_recall_fscore_support
        )
    except ImportError:
        print("ERROR: scikit-learn required")
        sys.exit(1)

    X = np.array([f.to_numeric_array() for f in features])
    y = np.array([1 if l else 0 for l in labels])

    n_total = len(X)
    n_tp = int(sum(y))
    n_fp = n_total - n_tp

    if verbose:
        print(f"\n{'='*60}")
        print(f"Training ML FP Classifier v2")
        print(f"{'='*60}")
        print(f"  Total: {n_total} ({n_tp} TP, {n_fp} FP)")
        print(f"  Features: {X.shape[1]}")
        print(f"  TP/FP ratio: {n_tp/max(n_fp,1):.2f}")

    # Dynamic class weights
    ratio = n_tp / max(n_fp, 1)
    if ratio > 2.0:
        weight_tp, weight_fp = 3.0, 1.5
    elif ratio < 0.5:
        weight_tp, weight_fp = 4.0, 1.0
    else:
        weight_tp, weight_fp = 3.5, 1.0

    sample_weights = np.array([weight_tp if l == 1 else weight_fp for l in y])
    if verbose:
        print(f"  Weights: TP={weight_tp}, FP={weight_fp}")

    # Hold-out test set
    X_train, X_test, y_train, y_test, w_train, w_test = train_test_split(
        X, y, sample_weights, test_size=0.15, random_state=42, stratify=y
    )
    if verbose:
        print(f"  Train: {len(X_train)}, Test: {len(X_test)}")

    # Hyperparameter search
    if verbose:
        print(f"\n[*] Hyperparameter optimization...")

    param_grid = {
        'n_estimators': [200, 300, 400, 500],
        'max_depth': [4, 5, 6, 7, 8],
        'learning_rate': [0.03, 0.05, 0.08, 0.1, 0.15],
        'min_samples_leaf': [2, 3, 5, 8],
        'min_samples_split': [2, 5, 10],
        'subsample': [0.8, 0.85, 0.9, 1.0],
        'max_features': ['sqrt', 'log2', None],
    }

    n_folds = min(5, max(3, len(X_train) // 50))
    cv = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42)
    f2_scorer = make_scorer(fbeta_score, beta=2)

    search = RandomizedSearchCV(
        GradientBoostingClassifier(random_state=42),
        param_grid, n_iter=80, cv=cv, scoring=f2_scorer,
        n_jobs=-1, random_state=42, verbose=0,
    )

    t0 = time.time()
    search.fit(X_train, y_train, sample_weight=w_train)
    if verbose:
        print(f"  Time: {time.time()-t0:.1f}s")
        print(f"  Best F2 (CV): {search.best_score_:.3f}")
        print(f"  Params: {search.best_params_}")

    best_model = search.best_estimator_

    # Test set evaluation
    y_pred_test = best_model.predict(X_test)
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred_test, average='binary')
    f2_test = fbeta_score(y_test, y_pred_test, beta=2)

    if verbose:
        print(f"\n[*] Test Set Results:")
        print(f"  Precision: {prec:.3f}")
        print(f"  Recall:    {rec:.3f}")
        print(f"  F1:        {f1:.3f}")
        print(f"  F2:        {f2_test:.3f}")
        print(classification_report(y_test, y_pred_test, target_names=['FP', 'TP']))
        cm = confusion_matrix(y_test, y_pred_test)
        print(f"  Confusion: FP-as-FP={cm[0][0]}, FP-as-TP={cm[0][1]}, TP-as-FP={cm[1][0]}, TP-as-TP={cm[1][1]}")

    # Retrain on ALL data
    if verbose:
        print(f"\n[*] Final model on all data...")

    best_model.fit(X, y, sample_weight=sample_weights)
    y_pred_all = best_model.predict(X)

    if verbose:
        print(f"  Training accuracy: {np.mean(y_pred_all == y):.3f}")
        print(classification_report(y, y_pred_all, target_names=['FP', 'TP']))

    # Feature importance
    feature_names = list(FeatureVector().to_dict().keys())
    feature_names.remove('vuln_type')
    importances = best_model.feature_importances_

    if verbose:
        sorted_idx = np.argsort(importances)[::-1]
        print(f"[*] Feature Importance (top 15):")
        for i in sorted_idx[:15]:
            bar = "#" * int(importances[i] * 50)
            print(f"    {feature_names[i]:28s} {importances[i]:.4f} {bar}")

    # 3-class thresholds
    if verbose:
        probs = best_model.predict_proba(X)[:, 1]
        print(f"\n[*] 3-Class Analysis:")
        for lo, hi, lbl in [(0, .30, 'SAFE'), (.30, .55, 'SUSPICIOUS'), (.55, 1.01, 'VULNERABLE')]:
            m = (probs >= lo) & (probs < hi)
            n = m.sum()
            tp_n = y[m].sum() if n > 0 else 0
            print(f"    {lbl:12s} [{lo:.2f}-{hi:.2f}): {n:5d} ({tp_n:4d} TP, {n-tp_n:4d} FP)")

    # Save model (backup old)
    import pickle, shutil
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, "apex_fp_classifier_v4.pkl")

    if os.path.exists(model_path):
        shutil.copy2(model_path, model_path.replace('.pkl', '_backup.pkl'))
        if verbose:
            print(f"\n[*] Old model backed up")

    with open(model_path, 'wb') as f:
        pickle.dump({
            'model': best_model,
            'feature_names': feature_names,
            'metrics': {
                'test_precision': float(prec), 'test_recall': float(rec),
                'test_f1': float(f1), 'test_f2': float(f2_test),
                'cv_f2': float(search.best_score_),
                'n_samples': n_total, 'n_tp': n_tp, 'n_fp': n_fp,
                'best_params': search.best_params_,
                'version': 'v2',
            },
        }, f)

    if verbose:
        print(f"[+] Model saved: {model_path} ({os.path.getsize(model_path)/1024:.1f} KB)")

    return {'test_f1': float(f1), 'test_f2': float(f2_test),
            'test_recall': float(rec), 'test_precision': float(prec),
            'n_samples': n_total, 'n_tp': n_tp, 'n_fp': n_fp}


def verify_model(model_dir, verbose=True):
    if verbose:
        print(f"\n{'='*60}\nModel Verification\n{'='*60}")

    classifier = FPClassifier(model_dir=model_dir)
    if not (classifier.ml and classifier.ml.is_trained()):
        print("  ERROR: Model not loaded!")
        return False

    tests = [
        ({'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '90%',
          'code': '$db->query("SELECT * FROM users WHERE id=" . $_GET["id"])',
          'line': 10, 'file': 'test.php'}, True, "SQLi direct"),
        ({'type': 'Arbitrary File Write', 'severity': 'CRITICAL', 'confidence': '90%',
          'code': 'file_put_contents(base64_decode($post["file"]), $post["content"]);',
          'line': 17, 'file': 'admin/save.php'}, True, "File write b64"),
        ({'type': 'Command Injection', 'severity': 'CRITICAL', 'confidence': '90%',
          'code': 'system("ping " . $_GET["host"]);',
          'line': 5, 'file': 'ping.php'}, True, "CMDi"),
        ({'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '70%',
          'code': '$stmt = $db->prepare("SELECT * FROM users WHERE id = ?");',
          'line': 10, 'file': 'safe.php'}, False, "Prepared stmt"),
        ({'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '75%',
          'code': '// $db->query("SELECT * FROM users WHERE id=" . $_GET["id"]);',
          'line': 5, 'file': 'old.php'}, False, "Commented"),
        ({'type': 'HTTP Header Injection', 'severity': 'HIGH', 'confidence': '70%',
          'code': 'header("Content-Type: application/json");',
          'line': 1, 'file': 'api.php'}, False, "Static header"),
    ]

    passed = 0
    for finding, exp_tp, desc in tests:
        r = classifier.classify(finding, finding['code'])
        ok = r.is_tp == exp_tp
        passed += ok
        if verbose:
            print(f"  [{'OK' if ok else 'FAIL'}] {desc:20s} exp={'TP' if exp_tp else 'FP'} got={'TP' if r.is_tp else 'FP'} score={r.score:.3f}")

    print(f"  Results: {passed}/{len(tests)} passed")
    return passed == len(tests)


def main():
    parser = argparse.ArgumentParser(description='APEX ML v2 Training')
    parser.add_argument('--verbose', '-v', action='store_true', default=True)
    default_data_dir = 'C:/Users/User/Desktop/vuln_datasets'
    if not os.path.exists(default_data_dir):
        default_data_dir = str(Path(__file__).parent / 'vuln_datasets')
    parser.add_argument('--data-dir', default=default_data_dir)
    parser.add_argument('--model-dir', default=None)
    args = parser.parse_args()

    model_dir = args.model_dir or str(Path(__file__).parent / "models")
    random.seed(42)
    extractor = FeatureExtractor()

    all_features, all_labels, stats = collect_all_data(extractor, args.data_dir, args.verbose)

    total = len(all_features)
    total_tp = sum(1 for l in all_labels if l)
    total_fp = total - total_tp

    print(f"\n{'='*60}")
    print(f"SUMMARY: {total} samples ({total_tp} TP, {total_fp} FP)")
    print(f"{'='*60}")

    if total < 50:
        print(f"ERROR: Not enough data ({total})")
        sys.exit(1)

    metrics = train_model(all_features, all_labels, model_dir, args.verbose)
    verify_model(model_dir, args.verbose)

    print(f"\n{'='*60}")
    print(f"DONE: {metrics['n_samples']} samples, Test F1={metrics['test_f1']:.3f}, "
          f"Recall={metrics['test_recall']:.3f}, Precision={metrics['test_precision']:.3f}")
    print(f"{'='*60}")


if __name__ == '__main__':
    main()
