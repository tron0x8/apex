#!/usr/bin/env python3

from dataclasses import dataclass
from typing import Dict, Set, List, Optional
from enum import Enum, auto

try:
    from .rule_engine import get_rule_engine
except ImportError:
    get_rule_engine = None


class Framework(Enum):
    LARAVEL = auto()
    SYMFONY = auto()
    CODEIGNITER = auto()
    WORDPRESS = auto()
    DRUPAL = auto()
    YII = auto()
    CAKEPHP = auto()
    SLIM = auto()
    UNKNOWN = auto()


@dataclass
class FrameworkConfig:
    name: str
    sanitizers: Dict[str, Set[str]]
    sources: Dict[str, str]
    sinks: Dict[str, str]
    safe_patterns: List[str]


LARAVEL_CONFIG = FrameworkConfig(
    name="Laravel",
    sanitizers={
        "SQL": {
            "DB::select", "DB::insert", "DB::update", "DB::delete",
            "DB::statement", "->where", "->whereIn", "->whereRaw",
            "->pluck", "->find", "->findOrFail", "->first",
            "->get", "->paginate", "->select", "->join",
            "Model::find", "Model::where", "Eloquent",
            "query()->where", "->whereColumn", "->orWhere",
        },
        "XSS": {
            "e(", "{{", "{!!", "@csrf", "@method",
            "htmlspecialchars", "Blade::render",
            "->with", "view(", "response()->json",
        },
        "FILE": {
            "Storage::put", "Storage::get", "Storage::delete",
            "Storage::exists", "Storage::path",
        },
        "AUTH": {
            "Auth::check", "Auth::user", "Gate::allows",
            "->authorize", "@can", "Policy",
        },
    },
    sources={
        "$request->input": "REQUEST",
        "$request->get": "GET",
        "$request->post": "POST",
        "$request->all": "REQUEST",
        "$request->query": "GET",
        "$request->file": "FILES",
        "$request->cookie": "COOKIE",
        "Request::input": "REQUEST",
        "Request::get": "GET",
        "Input::get": "GET",
        "Input::all": "REQUEST",
    },
    sinks={
        "DB::raw": "SQL_INJECTION",
        "->whereRaw": "SQL_INJECTION",
        "->selectRaw": "SQL_INJECTION",
        "->orderByRaw": "SQL_INJECTION",
        "->groupByRaw": "SQL_INJECTION",
        "->havingRaw": "SQL_INJECTION",
        "eval": "CODE_INJECTION",
        "exec": "COMMAND_INJECTION",
        "shell_exec": "COMMAND_INJECTION",
        "system": "COMMAND_INJECTION",
        "passthru": "COMMAND_INJECTION",
        "proc_open": "COMMAND_INJECTION",
        "popen": "COMMAND_INJECTION",
        "{!!": "XSS",
        "->header": "HEADER_INJECTION",
        "redirect": "OPEN_REDIRECT",
        "file_get_contents": "SSRF",
        "curl_exec": "SSRF",
        "unserialize": "DESERIALIZATION",
        "include": "FILE_INCLUSION",
        "require": "FILE_INCLUSION",
    },
    safe_patterns=[
        r'\$request->validate\(',
        r'Validator::make\(',
        r'->validated\(\)',
        r'FormRequest',
    ]
)

SYMFONY_CONFIG = FrameworkConfig(
    name="Symfony",
    sanitizers={
        "SQL": {
            "->createQueryBuilder", "->prepare", "->executeQuery",
            "->setParameter", "->getRepository", "DQL",
            "Doctrine\\ORM", "EntityManager", "->find(",
            "->findBy", "->findOneBy", "->findAll",
            "ParamConverter", "->expr()->",
        },
        "XSS": {
            "{{ ", "{% ", "|escape", "|e", "Twig",
            "->render(", "->renderView(", "|raw",
            "htmlspecialchars", "Response::create",
        },
        "CSRF": {
            "csrf_token", "isCsrfTokenValid", "CsrfToken",
        },
    },
    sources={
        "$request->query->get": "GET",
        "$request->request->get": "POST",
        "$request->get": "REQUEST",
        "$request->getContent": "REQUEST",
        "$request->files->get": "FILES",
        "$request->cookies->get": "COOKIE",
        "Request::createFromGlobals": "REQUEST",
        "->getClientIp": "SERVER",
    },
    sinks={
        "->query(": "SQL_INJECTION",
        "->exec(": "SQL_INJECTION",
        "createQuery": "SQL_INJECTION",
        "eval": "CODE_INJECTION",
        "Process(": "COMMAND_INJECTION",
        "exec": "COMMAND_INJECTION",
        "shell_exec": "COMMAND_INJECTION",
        "|raw": "XSS",
        "RedirectResponse": "OPEN_REDIRECT",
        "->redirect": "OPEN_REDIRECT",
        "file_get_contents": "SSRF",
        "HttpClient": "SSRF",
        "unserialize": "DESERIALIZATION",
    },
    safe_patterns=[
        r'->setParameter\(',
        r'ParamConverter',
        r'@Assert\\',
        r'#\[Assert\\',
    ]
)

CODEIGNITER_CONFIG = FrameworkConfig(
    name="CodeIgniter",
    sanitizers={
        "SQL": {
            "$this->db->query", "$this->db->where",
            "$this->db->get", "$this->db->insert",
            "$this->db->update", "$this->db->delete",
            "$this->db->escape", "$this->db->escape_str",
            "->getWhere", "->countAllResults",
        },
        "XSS": {
            "xss_clean", "esc(", "html_escape",
            "$this->security->xss_clean",
        },
        "CSRF": {
            "csrf_token", "csrf_hash", "csrf_field",
        },
    },
    sources={
        "$this->input->get": "GET",
        "$this->input->post": "POST",
        "$this->input->cookie": "COOKIE",
        "$this->input->server": "SERVER",
        "$this->request->getGet": "GET",
        "$this->request->getPost": "POST",
        "$this->request->getVar": "REQUEST",
        "$this->request->getFile": "FILES",
    },
    sinks={
        "->query(": "SQL_INJECTION",
        "$this->db->simple_query": "SQL_INJECTION",
        "eval": "CODE_INJECTION",
        "exec": "COMMAND_INJECTION",
        "shell_exec": "COMMAND_INJECTION",
        "system": "COMMAND_INJECTION",
        "redirect": "OPEN_REDIRECT",
        "file_get_contents": "SSRF",
        "unserialize": "DESERIALIZATION",
    },
    safe_patterns=[
        r'\$this->db->escape\(',
        r'->where\(\s*[\'"][^\'"]+[\'"]\s*,',
    ]
)

WORDPRESS_CONFIG = FrameworkConfig(
    name="WordPress",
    sanitizers={
        "SQL": {
            "$wpdb->prepare", "$wpdb->insert", "$wpdb->update",
            "$wpdb->delete", "$wpdb->replace", "esc_sql",
            "absint", "intval", "sanitize_key",
        },
        "XSS": {
            "esc_html", "esc_attr", "esc_url", "esc_js",
            "esc_textarea", "wp_kses", "wp_kses_post",
            "sanitize_text_field", "sanitize_email",
            "sanitize_file_name", "sanitize_title",
        },
        "NONCE": {
            "wp_nonce_field", "wp_verify_nonce",
            "check_admin_referer", "check_ajax_referer",
        },
    },
    sources={
        "$_GET": "GET",
        "$_POST": "POST",
        "$_REQUEST": "REQUEST",
        "$_COOKIE": "COOKIE",
        "get_query_var": "GET",
    },
    sinks={
        "$wpdb->query": "SQL_INJECTION",
        "eval": "CODE_INJECTION",
        "exec": "COMMAND_INJECTION",
        "shell_exec": "COMMAND_INJECTION",
        "system": "COMMAND_INJECTION",
        "wp_redirect": "OPEN_REDIRECT",
        "file_get_contents": "SSRF",
        "wp_remote_get": "SSRF",
        "wp_remote_post": "SSRF",
        "unserialize": "DESERIALIZATION",
        "maybe_unserialize": "DESERIALIZATION",
    },
    safe_patterns=[
        r'\$wpdb->prepare\(',
        r'wp_verify_nonce\(',
        r'current_user_can\(',
    ]
)

DRUPAL_CONFIG = FrameworkConfig(
    name="Drupal",
    sanitizers={
        "SQL": {
            "db_query", "db_select", "->condition",
            "->fields", "->execute", "Database::getConnection",
            "->select(", "->insert(", "->update(", "->delete(",
            "::load", "::loadMultiple", "EntityQuery",
        },
        "XSS": {
            "Html::escape", "Xss::filter", "check_plain",
            "t(", "\\Drupal::translation",
            "SafeMarkup::checkPlain", "SafeMarkup::format",
        },
        "CSRF": {
            "\\Drupal::csrfToken", "CsrfTokenGenerator",
        },
    },
    sources={
        "\\Drupal::request()->query->get": "GET",
        "\\Drupal::request()->request->get": "POST",
        "$request->query->get": "GET",
        "$request->request->get": "POST",
    },
    sinks={
        "db_query": "SQL_INJECTION",
        "->where(": "SQL_INJECTION",
        "eval": "CODE_INJECTION",
        "exec": "COMMAND_INJECTION",
        "shell_exec": "COMMAND_INJECTION",
        "file_get_contents": "SSRF",
        "\\Drupal::httpClient": "SSRF",
        "unserialize": "DESERIALIZATION",
    },
    safe_patterns=[
        r'->condition\(',
        r'::load\(',
        r't\(\s*[\'"]',
    ]
)

# ============================================================
# YII FRAMEWORK CONFIG
# ============================================================
YII_CONFIG = FrameworkConfig(
    name="Yii",
    sanitizers={
        "SQL": {
            "->createCommand", "->queryAll", "->queryOne",
            "->bindValue", "->bindParam", "->bindValues",
            "ActiveRecord::find", "->where", "->andWhere",
            "->orWhere", "->params", "Yii::$app->db",
            "QueryBuilder", "->addParams", "ActiveQuery",
        },
        "XSS": {
            "Html::encode", "HtmlPurifier::process",
            "->textInput", "->textarea", "->checkbox",
            "Yii::$app->formatter", "::widget(",
            "yii\\helpers\\Html", "->render(",
        },
        "CSRF": {
            "_csrf", "validateCsrfToken", "csrfParam",
            "enableCsrfValidation", "getCsrfToken",
        },
        "AUTH": {
            "Yii::$app->user->identity", "->can(",
            "AccessControl", "->checkAccess",
        },
    },
    sources={
        "Yii::$app->request->get": "GET",
        "Yii::$app->request->post": "POST",
        "Yii::$app->request->getBodyParams": "POST",
        "Yii::$app->request->getQueryParams": "GET",
        "Yii::$app->request->getRawBody": "REQUEST",
        "Yii::$app->request->cookies": "COOKIE",
        "$_GET": "GET",
        "$_POST": "POST",
    },
    sinks={
        "->createCommand(": "SQL_INJECTION",
        "Yii::$app->db->createCommand": "SQL_INJECTION",
        "eval": "CODE_INJECTION",
        "exec": "COMMAND_INJECTION",
        "shell_exec": "COMMAND_INJECTION",
        "system": "COMMAND_INJECTION",
        "->redirect": "OPEN_REDIRECT",
        "file_get_contents": "SSRF",
        "unserialize": "DESERIALIZATION",
        "include": "FILE_INCLUSION",
        "require": "FILE_INCLUSION",
    },
    safe_patterns=[
        r'->bindValue\s*\(',
        r'->bindParam\s*\(',
        r'->where\s*\(\s*\[',
        r'Html::encode\s*\(',
    ]
)

# ============================================================
# CAKEPHP FRAMEWORK CONFIG
# ============================================================
CAKEPHP_CONFIG = FrameworkConfig(
    name="CakePHP",
    sanitizers={
        "SQL": {
            "->find", "->get", "->save",
            "->query()->where", "->newEntity",
            "->patchEntity", "->contain",
            "ConnectionManager", "TableRegistry",
            "->matching", "->innerJoinWith",
            "->setConditions", "->bind",
        },
        "XSS": {
            "h(", "<?= h(", "$this->Html->",
            "htmlspecialchars", "Cake\\View\\Helper",
            "->element(", "->render(",
            "Text::truncate", "Text::excerpt",
        },
        "CSRF": {
            "csrf_token", "CsrfComponent",
            "->getParam('_Token')", "FormProtector",
        },
        "AUTH": {
            "AuthComponent", "$this->Auth->user",
            "->isAuthorized", "->authorize",
            "IdentityInterface", "->getIdentity",
        },
    },
    sources={
        "$this->request->getData": "POST",
        "$this->request->getQuery": "GET",
        "$this->request->getParam": "REQUEST",
        "$this->request->input": "REQUEST",
        "$this->request->getCookie": "COOKIE",
        "$this->request->getUploadedFile": "FILES",
    },
    sinks={
        "->query(": "SQL_INJECTION",
        "Connection::execute": "SQL_INJECTION",
        "eval": "CODE_INJECTION",
        "exec": "COMMAND_INJECTION",
        "shell_exec": "COMMAND_INJECTION",
        "system": "COMMAND_INJECTION",
        "->redirect": "OPEN_REDIRECT",
        "file_get_contents": "SSRF",
        "HttpClient": "SSRF",
        "unserialize": "DESERIALIZATION",
    },
    safe_patterns=[
        r'->find\s*\(\s*[\'"]',
        r'h\s*\(',
        r'->newEntity\s*\(',
        r'->patchEntity\s*\(',
    ]
)

# ============================================================
# SLIM FRAMEWORK CONFIG
# ============================================================
SLIM_CONFIG = FrameworkConfig(
    name="Slim",
    sanitizers={
        "SQL": {
            "->prepare", "->execute",
            "PDO::prepare", "->bindParam",
            "->bindValue", "Illuminate\\Database",
            "Eloquent", "QueryBuilder",
        },
        "XSS": {
            "htmlspecialchars", "htmlentities",
            "->withJson", "Twig_Environment",
            "|escape", "|e", "{{ ",
        },
        "CSRF": {
            "csrf_token", "Guard::class",
            "CsrfMiddleware", "csrf",
        },
    },
    sources={
        "$request->getQueryParams": "GET",
        "$request->getParsedBody": "POST",
        "$request->getCookieParams": "COOKIE",
        "$request->getUploadedFiles": "FILES",
        "$request->getAttribute": "REQUEST",
        "$args": "REQUEST",
    },
    sinks={
        "->query(": "SQL_INJECTION",
        "->exec(": "SQL_INJECTION",
        "eval": "CODE_INJECTION",
        "exec": "COMMAND_INJECTION",
        "shell_exec": "COMMAND_INJECTION",
        "system": "COMMAND_INJECTION",
        "->withRedirect": "OPEN_REDIRECT",
        "file_get_contents": "SSRF",
        "GuzzleHttp": "SSRF",
        "unserialize": "DESERIALIZATION",
    },
    safe_patterns=[
        r'->prepare\s*\(',
        r'->withJson\s*\(',
        r'ResponseInterface',
    ]
)

# ============================================================
# LAMINAS/ZEND FRAMEWORK CONFIG
# ============================================================
LAMINAS_CONFIG = FrameworkConfig(
    name="Laminas",
    sanitizers={
        "SQL": {
            "TableGateway", "->select",
            "->insert", "->update", "->delete",
            "Sql\\Select", "Sql\\Where",
            "->prepareStatementForSqlObject",
            "AbstractTableGateway", "->getSql",
        },
        "XSS": {
            "->escapeHtml", "Escaper::escapeHtml",
            "->escapeHtmlAttr", "->escapeJs",
            "->escapeCss", "->escapeUrl",
            "Laminas\\Escaper", "Zend\\Escaper",
        },
        "CSRF": {
            "Csrf", "getCsrfValidator",
            "csrf_token", "FormElementManager",
        },
    },
    sources={
        "$this->params()->fromQuery": "GET",
        "$this->params()->fromPost": "POST",
        "$this->params()->fromRoute": "REQUEST",
        "$request->getQuery": "GET",
        "$request->getPost": "POST",
    },
    sinks={
        "->query(": "SQL_INJECTION",
        "Adapter::query": "SQL_INJECTION",
        "eval": "CODE_INJECTION",
        "exec": "COMMAND_INJECTION",
        "shell_exec": "COMMAND_INJECTION",
        "->redirect": "OPEN_REDIRECT",
        "file_get_contents": "SSRF",
        "HttpClient": "SSRF",
        "unserialize": "DESERIALIZATION",
    },
    safe_patterns=[
        r'TableGateway\s*\(',
        r'->escapeHtml\s*\(',
        r'Sql\\Where',
    ]
)

# ============================================================
# PHALCON FRAMEWORK CONFIG
# ============================================================
PHALCON_CONFIG = FrameworkConfig(
    name="Phalcon",
    sanitizers={
        "SQL": {
            "::find", "::findFirst", "::count",
            "->execute", "->bind", "::query",
            "Criteria::fromInput", "PHQL",
            "Model::findFirstBy", "->setBindParams",
        },
        "XSS": {
            "Escaper::escapeHtml", "Escaper::escapeHtmlAttr",
            "->escapeHtml", "->escapeCss", "->escapeJs",
            "Tag::", "Volt", "|escape", "|e",
        },
        "CSRF": {
            "Security::checkToken", "getToken",
            "getTokenKey", "csrf", "security",
        },
    },
    sources={
        "$this->request->get": "REQUEST",
        "$this->request->getPost": "POST",
        "$this->request->getQuery": "GET",
        "$this->request->getPut": "POST",
        "$this->request->getUploadedFiles": "FILES",
    },
    sinks={
        "->execute(": "SQL_INJECTION",
        "Manager::executeQuery": "SQL_INJECTION",
        "eval": "CODE_INJECTION",
        "exec": "COMMAND_INJECTION",
        "shell_exec": "COMMAND_INJECTION",
        "->redirect": "OPEN_REDIRECT",
        "file_get_contents": "SSRF",
        "unserialize": "DESERIALIZATION",
    },
    safe_patterns=[
        r'::find\s*\(',
        r'::findFirst\s*\(',
        r'->escapeHtml\s*\(',
    ]
)

FRAMEWORKS = {
    Framework.LARAVEL: LARAVEL_CONFIG,
    Framework.SYMFONY: SYMFONY_CONFIG,
    Framework.CODEIGNITER: CODEIGNITER_CONFIG,
    Framework.WORDPRESS: WORDPRESS_CONFIG,
    Framework.DRUPAL: DRUPAL_CONFIG,
    Framework.YII: YII_CONFIG,
    Framework.CAKEPHP: CAKEPHP_CONFIG,
    Framework.SLIM: SLIM_CONFIG,
}


class FrameworkDetector:
    SIGNATURES = {
        Framework.LARAVEL: [
            "artisan", "Illuminate\\", "Laravel\\",
            "app/Http/Controllers", "routes/web.php",
            "composer.json:laravel/framework",
        ],
        Framework.SYMFONY: [
            "bin/console", "Symfony\\", "config/bundles.php",
            "src/Controller", "composer.json:symfony/",
        ],
        Framework.CODEIGNITER: [
            "system/core/CodeIgniter.php", "CI_Controller",
            "application/controllers", "BASEPATH",
        ],
        Framework.WORDPRESS: [
            "wp-config.php", "wp-content", "wp-includes",
            "add_action", "add_filter", "WP_Query",
        ],
        Framework.DRUPAL: [
            "core/includes/bootstrap.inc", "Drupal\\",
            "sites/default/settings.php", "drupal_",
        ],
        Framework.YII: [
            "yii", "Yii::", "yii\\", "yiisoft",
            "web/index.php", "config/web.php",
            "composer.json:yiisoft/yii2",
            "yii\\base\\Component", "yii\\web\\Controller",
        ],
        Framework.CAKEPHP: [
            "cakephp", "Cake\\", "CakePHP",
            "src/Controller", "config/routes.php",
            "composer.json:cakephp/cakephp",
            "Cake\\Controller\\Controller",
        ],
        Framework.SLIM: [
            "Slim\\", "slim/slim", "Slim\\App",
            "composer.json:slim/slim",
            "Slim\\Factory\\AppFactory",
            "Slim\\Routing\\RouteCollectorProxy",
        ],
    }

    _rule_engine_loaded = False

    @classmethod
    def _load_from_rule_engine(cls):
        """Load additional framework configs from RuleEngine. Hardcoded entries are kept as fallback."""
        if cls._rule_engine_loaded:
            return
        cls._rule_engine_loaded = True
        try:
            if get_rule_engine is None:
                return
            engine = get_rule_engine()
            if engine is None:
                return

            re_frameworks = engine.frameworks
            if not re_frameworks:
                return

            # Map framework names to Framework enum values
            _name_to_enum = {
                'laravel': Framework.LARAVEL,
                'symfony': Framework.SYMFONY,
                'codeigniter': Framework.CODEIGNITER,
                'wordpress': Framework.WORDPRESS,
                'drupal': Framework.DRUPAL,
                'yii': Framework.YII,
                'cakephp': Framework.CAKEPHP,
                'slim': Framework.SLIM,
            }

            for fw_name, fw_def in re_frameworks.items():
                fw_key = fw_name.lower()
                fw_enum = _name_to_enum.get(fw_key)

                # Extend SIGNATURES for known frameworks
                if fw_enum and fw_def.detect_patterns:
                    existing_sigs = set(cls.SIGNATURES.get(fw_enum, []))
                    for sig in fw_def.detect_patterns:
                        if sig not in existing_sigs:
                            cls.SIGNATURES.setdefault(fw_enum, []).append(sig)

                # Extend FRAMEWORKS config for known frameworks
                if fw_enum and fw_enum in FRAMEWORKS:
                    config = FRAMEWORKS[fw_enum]

                    # Extend sanitizers
                    if fw_def.sanitizers:
                        for vuln_type, sanitizer_set in fw_def.sanitizers.items():
                            vuln_key = vuln_type.upper().replace('_INJECTION', '').replace('CROSS_SITE_SCRIPTING', 'XSS')
                            if vuln_key not in config.sanitizers:
                                config.sanitizers[vuln_key] = set()
                            if isinstance(sanitizer_set, (list, set)):
                                for s in sanitizer_set:
                                    config.sanitizers[vuln_key].add(s)
                            elif isinstance(sanitizer_set, dict):
                                for s in sanitizer_set.values():
                                    if isinstance(s, str):
                                        config.sanitizers[vuln_key].add(s)

                    # Extend sources
                    if fw_def.sources:
                        for src, src_type in fw_def.sources.items():
                            if src not in config.sources:
                                config.sources[src] = src_type

                    # Extend sinks
                    if fw_def.sinks:
                        for sink, sink_type in fw_def.sinks.items():
                            if sink not in config.sinks:
                                config.sinks[sink] = sink_type

                    # Extend safe_patterns
                    if fw_def.safe_patterns:
                        existing_safe = set(config.safe_patterns)
                        for pat in fw_def.safe_patterns:
                            if pat not in existing_safe:
                                config.safe_patterns.append(pat)

        except Exception:
            # If RuleEngine fails, fall back to hardcoded configs silently
            pass

    @classmethod
    def detect_from_code(cls, code: str) -> Framework:
        cls._load_from_rule_engine()
        scores = {fw: 0 for fw in Framework}

        for fw, signatures in cls.SIGNATURES.items():
            for sig in signatures:
                if sig in code:
                    scores[fw] += 1

        max_score = max(scores.values())
        if max_score > 0:
            for fw, score in scores.items():
                if score == max_score:
                    return fw

        return Framework.UNKNOWN

    @classmethod
    def detect_from_files(cls, files: List[str]) -> Framework:
        cls._load_from_rule_engine()
        for fw, signatures in cls.SIGNATURES.items():
            for sig in signatures:
                for f in files:
                    if sig.replace("\\", "/") in f.replace("\\", "/"):
                        return fw
        return Framework.UNKNOWN


class FrameworkAnalyzer:
    def __init__(self, framework: Framework = Framework.UNKNOWN):
        self.framework = framework
        self.config = FRAMEWORKS.get(framework)

    def is_sanitized(self, code: str, vuln_type: str) -> bool:
        if not self.config:
            return False

        sanitizers = self.config.sanitizers.get(vuln_type, set())
        for san in sanitizers:
            if san in code:
                return True
        return False

    def get_sources(self) -> Dict[str, str]:
        if not self.config:
            return {}
        return self.config.sources

    def get_sinks(self) -> Dict[str, str]:
        if not self.config:
            return {}
        return self.config.sinks

    def is_safe_pattern(self, code: str) -> bool:
        import re
        if not self.config:
            return False

        for pattern in self.config.safe_patterns:
            if re.search(pattern, code):
                return True
        return False


EXTENDED_CWE_MAP = {
    # Injection Vulnerabilities
    'SQL_INJECTION': ('CWE-89', 'Improper Neutralization of Special Elements used in an SQL Command'),
    'COMMAND_INJECTION': ('CWE-78', 'Improper Neutralization of Special Elements used in an OS Command'),
    'CODE_INJECTION': ('CWE-94', 'Improper Control of Generation of Code'),
    'CALLBACK_INJECTION': ('CWE-95', 'Improper Neutralization of Directives in Dynamically Evaluated Code'),
    'XSS': ('CWE-79', 'Improper Neutralization of Input During Web Page Generation'),
    'XSS_REFLECTED': ('CWE-79', 'Reflected Cross-site Scripting'),
    'XSS_STORED': ('CWE-79', 'Stored Cross-site Scripting'),
    'XSS_DOM': ('CWE-79', 'DOM-based Cross-site Scripting'),
    'EMAIL_INJECTION': ('CWE-93', 'Improper Neutralization of CRLF Sequences in HTTP Headers'),
    'LDAP_INJECTION': ('CWE-90', 'Improper Neutralization of Special Elements used in an LDAP Query'),
    'XPATH_INJECTION': ('CWE-643', 'Improper Neutralization of Data within XPath Expressions'),
    'NOSQL_INJECTION': ('CWE-943', 'Improper Neutralization of Special Elements in Data Query Logic'),
    'HEADER_INJECTION': ('CWE-113', 'Improper Neutralization of CRLF Sequences in HTTP Headers'),
    'LOG_INJECTION': ('CWE-117', 'Improper Output Neutralization for Logs'),

    # File Vulnerabilities
    'FILE_INCLUSION': ('CWE-98', 'Improper Control of Filename for Include/Require Statement'),
    'LFI': ('CWE-98', 'Local File Inclusion'),
    'RFI': ('CWE-98', 'Remote File Inclusion'),
    'PATH_TRAVERSAL': ('CWE-22', 'Improper Limitation of a Pathname to a Restricted Directory'),
    'ARBITRARY_FILE_READ': ('CWE-22', 'Arbitrary File Read'),
    'ARBITRARY_FILE_WRITE': ('CWE-22', 'Arbitrary File Write'),
    'ARBITRARY_FILE_DELETE': ('CWE-22', 'Arbitrary File Delete'),
    'INSECURE_UPLOAD': ('CWE-434', 'Unrestricted Upload of File with Dangerous Type'),
    'FILE_UPLOAD_BYPASS': ('CWE-434', 'File Upload Validation Bypass'),

    # Serialization / Deserialization
    'DESERIALIZATION': ('CWE-502', 'Deserialization of Untrusted Data'),
    'OBJECT_INJECTION': ('CWE-502', 'PHP Object Injection'),
    'PHAR_DESERIALIZATION': ('CWE-502', 'PHAR Deserialization'),
    'XXE': ('CWE-611', 'Improper Restriction of XML External Entity Reference'),
    'YAML_INJECTION': ('CWE-502', 'YAML Deserialization'),

    # Template / Rendering
    'SSTI': ('CWE-1336', 'Server-Side Template Injection'),
    'TEMPLATE_INJECTION': ('CWE-1336', 'Server-Side Template Injection'),

    # Authentication / Authorization
    'IDOR': ('CWE-639', 'Authorization Bypass Through User-Controlled Key'),
    'BROKEN_ACCESS_CONTROL': ('CWE-284', 'Improper Access Control'),
    'PRIVILEGE_ESCALATION': ('CWE-266', 'Incorrect Privilege Assignment'),
    'MASS_ASSIGNMENT': ('CWE-915', 'Improperly Controlled Modification of Dynamically-Determined Object Attributes'),
    'CSRF': ('CWE-352', 'Cross-Site Request Forgery'),

    # Session / Cookie
    'SESSION_FIXATION': ('CWE-384', 'Session Fixation'),
    'INSECURE_COOKIE': ('CWE-614', 'Sensitive Cookie in HTTPS Session Without Secure Attribute'),
    'COOKIE_WITHOUT_HTTPONLY': ('CWE-1004', 'Sensitive Cookie Without HttpOnly Flag'),

    # Network
    'SSRF': ('CWE-918', 'Server-Side Request Forgery'),
    'OPEN_REDIRECT': ('CWE-601', 'URL Redirection to Untrusted Site'),
    'CLEARTEXT_TRANSMISSION': ('CWE-319', 'Cleartext Transmission of Sensitive Information'),

    # Cryptography
    'WEAK_CRYPTO': ('CWE-327', 'Use of a Broken or Risky Cryptographic Algorithm'),
    'WEAK_RANDOM': ('CWE-330', 'Use of Insufficiently Random Values'),
    'PREDICTABLE_TOKEN': ('CWE-330', 'Predictable Token Generation'),
    'WEAK_HASH': ('CWE-328', 'Reversible One-Way Hash'),
    'WEAK_IV': ('CWE-329', 'Generation of Predictable IV with CBC Mode'),

    # Credentials
    'HARDCODED_CREDS': ('CWE-798', 'Use of Hard-coded Credentials'),
    'HARDCODED_SECRET': ('CWE-798', 'Use of Hard-coded Credentials'),
    'CLEARTEXT_STORAGE': ('CWE-312', 'Cleartext Storage of Sensitive Information'),

    # Information Disclosure
    'INFO_DISCLOSURE': ('CWE-200', 'Exposure of Sensitive Information to an Unauthorized Actor'),
    'DEBUG_ENABLED': ('CWE-489', 'Active Debug Code'),
    'ERROR_DISCLOSURE': ('CWE-209', 'Generation of Error Message Containing Sensitive Information'),

    # Type / Logic
    'TYPE_JUGGLING': ('CWE-843', 'Access of Resource Using Incompatible Type'),
    'RACE_CONDITION': ('CWE-362', 'Concurrent Execution using Shared Resource with Improper Synchronization'),
    'TOCTOU': ('CWE-367', 'Time-of-check Time-of-use Race Condition'),
    'INTEGER_OVERFLOW': ('CWE-190', 'Integer Overflow or Wraparound'),

    # DoS
    'REGEX_DOS': ('CWE-1333', 'Inefficient Regular Expression Complexity'),
    'RESOURCE_EXHAUSTION': ('CWE-400', 'Uncontrolled Resource Consumption'),
    'INFINITE_LOOP': ('CWE-835', 'Loop with Unreachable Exit Condition'),

    # Other
    'PROTOTYPE_POLLUTION': ('CWE-1321', 'Improperly Controlled Modification of Object Prototype Attributes'),
    'UNSAFE_REFLECTION': ('CWE-470', 'Use of Externally-Controlled Input to Select Classes or Code'),
    'INPUT_VALIDATION': ('CWE-20', 'Improper Input Validation'),
}

EXTENDED_SINKS = {
    'eval': 'CODE_INJECTION',
    'assert': 'CODE_INJECTION',
    'create_function': 'CODE_INJECTION',
    'preg_replace': 'CODE_INJECTION',
    'call_user_func': 'CODE_INJECTION',
    'call_user_func_array': 'CODE_INJECTION',
    'usort': 'CODE_INJECTION',
    'uasort': 'CODE_INJECTION',
    'uksort': 'CODE_INJECTION',
    'array_map': 'CODE_INJECTION',
    'array_filter': 'CODE_INJECTION',
    'array_walk': 'CODE_INJECTION',
    'exec': 'COMMAND_INJECTION',
    'shell_exec': 'COMMAND_INJECTION',
    'system': 'COMMAND_INJECTION',
    'passthru': 'COMMAND_INJECTION',
    'popen': 'COMMAND_INJECTION',
    'proc_open': 'COMMAND_INJECTION',
    'pcntl_exec': 'COMMAND_INJECTION',
    'backtick': 'COMMAND_INJECTION',
    'mysql_query': 'SQL_INJECTION',
    'mysqli_query': 'SQL_INJECTION',
    'mysqli_multi_query': 'SQL_INJECTION',
    'pg_query': 'SQL_INJECTION',
    'pg_send_query': 'SQL_INJECTION',
    'sqlite_query': 'SQL_INJECTION',
    'sqlite_exec': 'SQL_INJECTION',
    'mssql_query': 'SQL_INJECTION',
    'odbc_exec': 'SQL_INJECTION',
    'sqlsrv_query': 'SQL_INJECTION',
    'PDO::query': 'SQL_INJECTION',
    'PDO::exec': 'SQL_INJECTION',
    'echo': 'XSS',
    'print': 'XSS',
    'printf': 'XSS',
    'vprintf': 'XSS',
    'die': 'XSS',
    'exit': 'XSS',
    'include': 'FILE_INCLUSION',
    'include_once': 'FILE_INCLUSION',
    'require': 'FILE_INCLUSION',
    'require_once': 'FILE_INCLUSION',
    'file_get_contents': 'SSRF',
    'file_put_contents': 'ARBITRARY_FILE_WRITE',
    'fopen': 'PATH_TRAVERSAL',
    'fwrite': 'ARBITRARY_FILE_WRITE',
    'fread': 'ARBITRARY_FILE_READ',
    'readfile': 'ARBITRARY_FILE_READ',
    'file': 'ARBITRARY_FILE_READ',
    'copy': 'ARBITRARY_FILE_WRITE',
    'rename': 'ARBITRARY_FILE_WRITE',
    'unlink': 'ARBITRARY_FILE_DELETE',
    'rmdir': 'ARBITRARY_FILE_DELETE',
    'mkdir': 'PATH_TRAVERSAL',
    'move_uploaded_file': 'INSECURE_UPLOAD',
    'curl_setopt': 'SSRF',
    'curl_exec': 'SSRF',
    'fsockopen': 'SSRF',
    'socket_connect': 'SSRF',
    'unserialize': 'DESERIALIZATION',
    'yaml_parse': 'DESERIALIZATION',
    'simplexml_load_string': 'XXE',
    'simplexml_load_file': 'XXE',
    'DOMDocument::loadXML': 'XXE',
    'XMLReader::open': 'XXE',
    'header': 'HEADER_INJECTION',
    'setcookie': 'INSECURE_COOKIE',
    'ldap_search': 'LDAP_INJECTION',
    'ldap_bind': 'LDAP_INJECTION',
    'mail': 'HEADER_INJECTION',
    'preg_match': 'REGEX_DOS',
    'preg_replace': 'REGEX_DOS',
    'extract': 'MASS_ASSIGNMENT',
    'parse_str': 'MASS_ASSIGNMENT',
    'mt_rand': 'WEAK_RANDOM',
    'rand': 'WEAK_RANDOM',
    'md5': 'WEAK_CRYPTO',
    'sha1': 'WEAK_CRYPTO',
    'base64_decode': 'INFO_DISCLOSURE',
}

EXTENDED_SANITIZERS = {
    'intval': {'SQL_INJECTION', 'XSS', 'PATH_TRAVERSAL'},
    'floatval': {'SQL_INJECTION', 'XSS'},
    'abs': {'SQL_INJECTION'},
    'htmlspecialchars': {'XSS'},
    'htmlentities': {'XSS'},
    'strip_tags': {'XSS'},
    'addslashes': {'SQL_INJECTION'},
    'mysql_real_escape_string': {'SQL_INJECTION'},
    'mysqli_real_escape_string': {'SQL_INJECTION'},
    'pg_escape_string': {'SQL_INJECTION'},
    'sqlite_escape_string': {'SQL_INJECTION'},
    'PDO::quote': {'SQL_INJECTION'},
    'escapeshellarg': {'COMMAND_INJECTION'},
    'escapeshellcmd': {'COMMAND_INJECTION'},
    'basename': {'PATH_TRAVERSAL', 'FILE_INCLUSION', 'LFI'},
    'realpath': {'PATH_TRAVERSAL', 'FILE_INCLUSION'},
    'dirname': {'PATH_TRAVERSAL'},
    'pathinfo': {'PATH_TRAVERSAL'},
    'filter_var': {'XSS', 'SQL_INJECTION', 'SSRF'},
    'filter_input': {'XSS', 'SQL_INJECTION'},
    'preg_replace': {'XSS'},
    'urlencode': {'XSS', 'HEADER_INJECTION'},
    'rawurlencode': {'XSS', 'HEADER_INJECTION'},
    'json_encode': {'XSS'},
    'ctype_digit': {'SQL_INJECTION'},
    'ctype_alnum': {'SQL_INJECTION', 'XSS'},
    'is_numeric': {'SQL_INJECTION'},
    'is_int': {'SQL_INJECTION'},
    'is_array': {'MASS_ASSIGNMENT'},
    'in_array': {'IDOR'},
    'array_key_exists': {'IDOR'},
    'password_hash': {'WEAK_CRYPTO'},
    'hash': {'WEAK_CRYPTO'},
    'openssl_encrypt': {'WEAK_CRYPTO'},
    'random_bytes': {'WEAK_RANDOM'},
    'random_int': {'WEAK_RANDOM'},
}
