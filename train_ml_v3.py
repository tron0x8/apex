#!/usr/bin/env python3

import os
import sys
import json
import time
import pickle
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent / "core"))

import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix, fbeta_score,
    make_scorer, precision_score, recall_score, f1_score
)

from core.ml_fp_classifier import (
    FeatureExtractor, FeatureVector, TrainingDataGenerator, FPClassifier
)
from core.ml_ensemble import (
    CalibratedEnsemble, PerTypeModelRegistry, TFIDFFeaturePipeline,
    AnomalyFeatureEnhancer, get_type_group
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
    features, labels, code_contexts, vuln_types = [], [], [], []
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
        code_contexts.append(fv.code_context_raw or code)
        vuln_types.append(f.get('type', ''))
    return features, labels, code_contexts, vuln_types


MANUAL_CMS_LABELS = [
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
    {'type': 'Cross-Site Scripting', 'severity': 'HIGH', 'confidence': '85%',
     'code': 'echo $_REQUEST["action"];',
     'line': 148, 'file': 'engine/inc/userfields.php', 'label': True},
    {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '80%',
     'code': '$db->query("UPDATE " . PREFIX . "_users SET " . $_POST["field"]);',
     'line': 50, 'file': 'engine/ajax/rating.php', 'label': True},
    {'type': 'Insecure Randomness', 'severity': 'HIGH', 'confidence': '85%',
     'code': '$hash = md5(microtime(TRUE)); // ETag for CSS caching',
     'line': 137, 'file': 'templates/Default/style.css.php', 'label': False},
    {'type': 'Weak Cryptography', 'severity': 'MEDIUM', 'confidence': '65%',
     'code': '$etag = md5($content); // HTTP ETag, not security',
     'line': 15, 'file': 'engine/cache.php', 'label': False},
    {'type': 'SQL Injection', 'severity': 'CRITICAL', 'confidence': '85%',
     'code': '$sql = sprintf("UPDATE %s SET value=\'%s\'", $table, serialize($_POST[$config]));',
     'line': 274, 'file': 'admin/install/rescue.php', 'label': True},
    {'type': 'Insecure Randomness', 'severity': 'HIGH', 'confidence': '70%',
     'code': '$emailconfirmid = substr(md5(uniqid(rand(),1)),1,16);',
     'line': 1466, 'file': 'system/lib-user.php', 'label': True},
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
    {'type': 'Weak Cryptography', 'severity': 'HIGH', 'confidence': '65%',
     'code': '$hash = md5($salt . $password, TRUE);',
     'line': 135, 'file': 'Ip/Lib/PasswordHash.php', 'label': True},
    {'type': 'Insecure Randomness', 'severity': 'HIGH', 'confidence': '65%',
     'code': '$public_key = substr(md5(uniqid(rand(),true)), 0, $this->chars);',
     'line': 676, 'file': 'Ip/Lib/HnCaptcha/HnCaptcha.php', 'label': True},
    {'type': 'File Inclusion', 'severity': 'HIGH', 'confidence': '85%',
     'code': '$composerPlugins = require($composerConfigFile);',
     'line': 112, 'file': 'Ip/Config.php', 'label': False},
    {'type': 'File Inclusion', 'severity': 'HIGH', 'confidence': '85%',
     'code': '$config = array_merge($config, require($envConfigFile));',
     'line': 277, 'file': 'Ip/Config.php', 'label': False},
]

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

AUG_FP = [
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
     'code': 'header("Location: /login.php");', 'line': 3, 'file': 'logout.php'},
    {'type': 'Weak Cryptography', 'severity': 'MEDIUM', 'confidence': '65%',
     'code': '$cache_key = md5($url); // Cache key, not security',
     'line': 10, 'file': 'cache.php'},
    {'type': 'Race Condition', 'severity': 'MEDIUM', 'confidence': '65%',
     'code': 'if (file_exists($cache_file)) { return file_get_contents($cache_file); }',
     'line': 25, 'file': 'cache.php'},
]

AUG_TP = [
    {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '85%',
     'code': '$sql = "SELECT * FROM orders WHERE user=\'" . $username . "\'";',
     'line': 35, 'file': 'orders.php'},
    {'type': 'Unsafe File Upload', 'severity': 'HIGH', 'confidence': '80%',
     'code': 'move_uploaded_file($_FILES["file"]["tmp_name"], "uploads/" . $_FILES["file"]["name"]);',
     'line': 20, 'file': 'upload.php'},
    {'type': 'Open Redirect', 'severity': 'HIGH', 'confidence': '85%',
     'code': 'header("Location: " . $_GET["url"]);', 'line': 5, 'file': 'redirect.php'},
    {'type': 'Code Injection', 'severity': 'CRITICAL', 'confidence': '95%',
     'code': '$db->query($_POST["query"]);', 'line': 5, 'file': 'admin.php'},
    {'type': 'Insecure Deserialization', 'severity': 'CRITICAL', 'confidence': '90%',
     'code': '$prefs = unserialize(base64_decode($_COOKIE["settings"]));',
     'line': 12, 'file': 'settings.php'},
]


def collect_all_data(extractor, data_dir, verbose=True):
    all_features, all_labels, all_contexts, all_vtypes = [], [], [], []
    stats = {}

    def add(feats, labs, ctxs, vtypes, name):
        all_features.extend(feats)
        all_labels.extend(labs)
        all_contexts.extend(ctxs)
        all_vtypes.extend(vtypes)
        n_tp = sum(1 for l in labs if l)
        n_fp = sum(1 for l in labs if not l)
        stats[name] = {'total': len(labs), 'tp': n_tp, 'fp': n_fp}
        if verbose:
            print(f"  [{name:30s}] {len(labs):5d} ({n_tp:4d} TP, {n_fp:4d} FP)")

    def add_simple(patterns, label, name):
        f, l, c, v = [], [], [], []
        for p in patterns:
            finding = {k: val for k, val in p.items() if k != 'label'}
            fv = extractor.extract(finding, finding.get('code', ''))
            f.append(fv)
            l.append(label if 'label' not in p else p['label'])
            c.append(fv.code_context_raw or finding.get('code', ''))
            v.append(finding.get('type', ''))
        add(f, l, c, v, name)

    print("\n" + "=" * 60)
    print("APEX ML v3 - Collecting Training Data")
    print("=" * 60)

    print("\n[1] Stivalet Benchmark (FULL)")
    stivalet_path = os.path.join(data_dir, 'training_data_labeled.json')
    if not os.path.exists(stivalet_path):
        stivalet_path = '/root/scan_results/training_data_labeled.json'

    if os.path.exists(stivalet_path):
        stiv = load_json(stivalet_path)
        for key, label in [('stivalet_fp', False), ('stivalet_tp', True), ('vuln_app_tp', True)]:
            items = stiv.get(key, [])
            if items:
                f, l, c, v = extract_from_findings(items, label, extractor)
                add(f, l, c, v, key)

    print("\n[2] Vulnerable App Scans (TP)")
    scan_dir = '/root/scan_results' if os.path.exists('/root/scan_results') else data_dir
    vuln_files = {
        'DVWA': ['dvwa_v6.json', 'dvwa_v2.json'],
        'XVWA': ['xvwa_v6.json'],
        'WebGoat': ['webgoat_v6.json'],
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
                f, l, c, v = extract_from_findings(findings, True, extractor)
                add(f, l, c, v, f"vuln_{name}")
                break

    print("\n[3] Webshell Patterns (TP)")
    add_simple(WEBSHELL_PATTERNS, True, "webshell_synthetic")

    print("\n[4] Safe Framework Scans (FP)")
    for fn in ['pagekit_v6.json']:
        fp = os.path.join(scan_dir, fn)
        if os.path.exists(fp):
            data = load_json(fp)
            findings = data.get('findings', [])
            if findings:
                f, l, c, v = extract_from_findings(findings, False, extractor)
                add(f, l, c, v, f"safe_{fn.replace('_v6.json','')}")

    print("\n[5] Test Fixtures")
    fixture_dir = str(Path(__file__).parent / "tests" / "fixtures")
    if os.path.isdir(fixture_dir):
        gen = TrainingDataGenerator()
        fix_f, fix_l = gen.from_fixture_dir(fixture_dir)
        fix_c = [fv.code_context_raw or '' for fv in fix_f]
        fix_v = [fv.vuln_type for fv in fix_f]
        add(fix_f, fix_l, fix_c, fix_v, "fixtures")

    print("\n[6] Synthetic/Augmented")
    gen = TrainingDataGenerator()
    syn_f, syn_l = gen.from_synthetic()
    syn_c = [fv.code_context_raw or '' for fv in syn_f]
    syn_v = [fv.vuln_type for fv in syn_f]
    add(syn_f, syn_l, syn_c, syn_v, "synthetic")

    add_simple(AUG_FP, False, "augmented_fp")
    add_simple(AUG_TP, True, "augmented_tp")

    if _HAS_EXTENDED:
        ext_fp = get_extended_fp_examples()
        ext_tp = get_extended_tp_examples()
        add_simple(ext_fp, False, "extended_fp")
        add_simple(ext_tp, True, "extended_tp")

    print("\n[7] Manual CMS Labels")
    f, l, c, v = [], [], [], []
    for item in MANUAL_CMS_LABELS:
        finding = {k: val for k, val in item.items() if k != 'label'}
        fv = extractor.extract(finding, finding.get('code', ''))
        f.append(fv)
        l.append(item['label'])
        c.append(fv.code_context_raw or finding.get('code', ''))
        v.append(finding.get('type', ''))
    add(f, l, c, v, "manual_cms")

    return all_features, all_labels, all_contexts, all_vtypes, stats


def train_v3(features, labels, code_contexts, vuln_types, model_dir, verbose=True):
    t0 = time.time()

    X_struct = np.array([f.to_numeric_array() for f in features])
    y = np.array([1 if l else 0 for l in labels])
    feature_names = [k for k in features[0].to_dict().keys() if k != 'vuln_type']

    n_total = len(X_struct)
    n_tp = int(sum(y))
    n_fp = n_total - n_tp

    print(f"\n{'='*60}")
    print(f"APEX ML v3 Ensemble Training")
    print(f"{'='*60}")
    print(f"  Samples: {n_total} ({n_tp} TP, {n_fp} FP)")
    print(f"  Structural features: {X_struct.shape[1]}")
    print(f"  Code contexts: {sum(1 for c in code_contexts if c)}")

    ratio = n_tp / max(n_fp, 1)
    if ratio > 2.0:
        weight_tp, weight_fp = 3.0, 1.5
    elif ratio < 0.5:
        weight_tp, weight_fp = 4.0, 1.0
    else:
        weight_tp, weight_fp = 3.5, 1.0
    sample_weights = np.array([weight_tp if l == 1 else weight_fp for l in y])
    print(f"  Class weights: TP={weight_tp}, FP={weight_fp}")

    print(f"\n[Phase 1] TF-IDF Feature Extraction")
    tfidf_pipeline = TFIDFFeaturePipeline(n_components=50)
    tfidf_pipeline.fit(code_contexts)
    X_tfidf = tfidf_pipeline.transform(code_contexts)
    print(f"  TF-IDF components: {X_tfidf.shape[1]}")
    print(f"  TF-IDF fitted: {tfidf_pipeline.fitted}")

    print(f"\n[Phase 2] Anomaly Detection (Isolation Forest)")
    anomaly = AnomalyFeatureEnhancer()
    fp_indices = np.where(y == 0)[0]
    if len(fp_indices) > 10:
        anomaly.fit(X_struct[fp_indices])
        anomaly_scores = anomaly.score(X_struct).reshape(-1, 1)
        print(f"  Trained on {len(fp_indices)} FP samples")
        print(f"  Anomaly score range: [{anomaly_scores.min():.3f}, {anomaly_scores.max():.3f}]")
    else:
        anomaly_scores = np.zeros((n_total, 1))
        print(f"  Skipped (too few FP samples)")

    X_full = np.hstack([X_struct, X_tfidf, anomaly_scores])
    print(f"\n[Phase 3] Combined Features: {X_full.shape[1]}")
    print(f"  = {X_struct.shape[1]} structural + {X_tfidf.shape[1]} TF-IDF + 1 anomaly")

    X_train, X_test, y_train, y_test, w_train, w_test, \
        vt_train, vt_test = train_test_split(
            X_full, y, sample_weights, vuln_types,
            test_size=0.15, random_state=42, stratify=y
    )
    print(f"  Train: {len(X_train)}, Test: {len(X_test)}")

    print(f"\n[Phase 4] Global Ensemble Training")
    ensemble = CalibratedEnsemble()
    ensemble.fit(X_train, y_train, sample_weight=w_train, verbose=verbose)

    ensemble_probs = ensemble.predict_proba(X_test)
    ensemble_pred = (ensemble_probs >= 0.5).astype(int)
    test_p = precision_score(y_test, ensemble_pred)
    test_r = recall_score(y_test, ensemble_pred)
    test_f1 = f1_score(y_test, ensemble_pred)
    test_f2 = fbeta_score(y_test, ensemble_pred, beta=2)
    print(f"\n  Ensemble Test Results:")
    print(f"    Precision: {test_p:.3f}")
    print(f"    Recall:    {test_r:.3f}")
    print(f"    F1:        {test_f1:.3f}")
    print(f"    F2:        {test_f2:.3f}")

    print(f"\n[Phase 5] Per-Vulnerability-Type Models")
    per_type = PerTypeModelRegistry()
    per_type.train(X_train, y_train, vt_train, sample_weight=w_train, verbose=verbose)

    print(f"\n{'='*60}")
    print(f"Final Evaluation on Test Set ({len(X_test)} samples)")
    print(f"{'='*60}")

    final_probs = np.zeros(len(X_test))
    for i in range(len(X_test)):
        vt = vt_test[i]
        ens_prob = ensemble_probs[i]

        if per_type.has_model(vt):
            type_result = per_type.predict(X_test[i], vt)
            if type_result is not None:
                _, type_prob = type_result
                final_probs[i] = 0.6 * type_prob + 0.4 * ens_prob
            else:
                final_probs[i] = ens_prob
        else:
            final_probs[i] = ens_prob

    final_pred = (final_probs >= 0.5).astype(int)
    final_p = precision_score(y_test, final_pred)
    final_r = recall_score(y_test, final_pred)
    final_f1 = f1_score(y_test, final_pred)
    final_f2 = fbeta_score(y_test, final_pred, beta=2)

    print(f"\n  Final (Ensemble + Per-Type Blend):")
    print(f"    Precision: {final_p:.3f}")
    print(f"    Recall:    {final_r:.3f}")
    print(f"    F1:        {final_f1:.3f}")
    print(f"    F2:        {final_f2:.3f}")

    n_safe = sum(1 for p in final_probs if p < 0.25)
    n_susp = sum(1 for p in final_probs if 0.25 <= p < 0.50)
    n_vuln = sum(1 for p in final_probs if p >= 0.50)
    print(f"\n  3-Class Distribution (test):")
    print(f"    SAFE (<0.25):       {n_safe}")
    print(f"    SUSPICIOUS (0.25-0.50): {n_susp}")
    print(f"    VULNERABLE (>=0.50):  {n_vuln}")

    cm = confusion_matrix(y_test, final_pred)
    print(f"\n  Confusion Matrix:")
    print(f"    TN={cm[0][0]:4d}  FP={cm[0][1]:4d}")
    print(f"    FN={cm[1][0]:4d}  TP={cm[1][1]:4d}")

    print(f"\n  Per-Type Test Metrics:")
    for group_name in sorted(set(get_type_group(vt) for vt in vt_test)):
        indices = [i for i, vt in enumerate(vt_test) if get_type_group(vt) == group_name]
        if len(indices) < 5:
            continue
        g_y = y_test[indices]
        g_pred = final_pred[indices]
        g_p = precision_score(g_y, g_pred, zero_division=0)
        g_r = recall_score(g_y, g_pred, zero_division=0)
        has_model = "+" if per_type.has_model(group_name) else "-"
        print(f"    [{group_name:10s}] {has_model} P={g_p:.3f} R={g_r:.3f} n={len(indices)}")

    print(f"\n[Phase 7] Saving Model")

    model_path = os.path.join(model_dir, 'apex_fp_classifier_v5.pkl')
    if os.path.exists(model_path):
        backup = model_path.replace('.pkl', '_backup.pkl')
        try:
            os.rename(model_path, backup)
            print(f"  Backed up old model to {backup}")
        except Exception:
            pass

    artifact = {
        'version': 'v3',
        'feature_names': feature_names,
        'ensemble': ensemble,
        'per_type_models': per_type,
        'tfidf_pipeline': tfidf_pipeline,
        'anomaly_detector': anomaly,
        'thresholds': {'safe': 0.25, 'suspicious': 0.50},
        'metrics': {
            'test_precision': float(final_p),
            'test_recall': float(final_r),
            'test_f1': float(final_f1),
            'test_f2': float(final_f2),
            'n_samples': n_total,
            'n_tp': n_tp,
            'n_fp': n_fp,
            'n_features_structural': X_struct.shape[1],
            'n_features_tfidf': X_tfidf.shape[1],
            'n_features_total': X_full.shape[1],
            'ensemble_models': list(ensemble.base_models.keys()),
            'per_type_active': list(per_type.active_groups),
            'train_time': time.time() - t0,
        },
    }

    with open(model_path, 'wb') as f:
        pickle.dump(artifact, f, protocol=4)

    model_size = os.path.getsize(model_path)
    print(f"  Saved: {model_path}")
    print(f"  Size: {model_size / 1024:.0f} KB")
    print(f"  Training time: {time.time() - t0:.1f}s")

    v4_path = os.path.join(model_dir, 'apex_fp_classifier_v4.pkl')
    try:
        gb_model = ensemble.base_models.get('gb')
        if gb_model:
            v4_artifact = {
                'model': gb_model,
                'feature_names': feature_names[:len(feature_names)],
                'metrics': {
                    'n_samples': n_total,
                    'n_tp': n_tp,
                    'n_fp': n_fp,
                },
                'version': 'v2_compat',
            }
            with open(v4_path, 'wb') as f:
                pickle.dump(v4_artifact, f, protocol=4)
            print(f"  Also saved v4-compatible: {v4_path}")
    except Exception as e:
        print(f"  v4-compat save failed: {e}")

    return artifact


def main():
    parser = argparse.ArgumentParser(description='APEX ML v3 Ensemble Training')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--data-dir', default=str(Path(__file__).parent / 'models'))
    parser.add_argument('--model-dir', default=str(Path(__file__).parent / 'models'))
    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("APEX ML FP Classifier v3 - Ensemble Training")
    print("=" * 60)

    extractor = FeatureExtractor()
    features, labels, contexts, vtypes, stats = collect_all_data(
        extractor, args.data_dir, verbose=args.verbose or True
    )

    n_total = len(features)
    n_tp = sum(1 for l in labels if l)
    n_fp = n_total - n_tp
    print(f"\nTotal: {n_total} samples ({n_tp} TP, {n_fp} FP)")

    if n_total < 50:
        print("ERROR: Not enough training data")
        sys.exit(1)

    artifact = train_v3(
        features, labels, contexts, vtypes,
        args.model_dir, verbose=args.verbose or True
    )

    print(f"\n{'='*60}")
    print(f"Training Complete!")
    print(f"{'='*60}")
    m = artifact['metrics']
    print(f"  Precision: {m['test_precision']:.3f}")
    print(f"  Recall:    {m['test_recall']:.3f}")
    print(f"  F1:        {m['test_f1']:.3f}")
    print(f"  F2:        {m['test_f2']:.3f}")
    print(f"  Features:  {m['n_features_total']}")
    print(f"  Ensemble:  {m['ensemble_models']}")
    print(f"  Per-Type:  {m['per_type_active']}")
    print(f"  Time:      {m['train_time']:.1f}s")


if __name__ == '__main__':
    main()
