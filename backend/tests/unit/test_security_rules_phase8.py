"""Phase 8 rule tests (TASK-101–105): vulnerable, safe, and partial flows.

Each rule must detect its suspicious patterns, stay silent on obvious
safe patterns, and mark unresolved flows explicitly instead of assuming
safety. Sources here are parsed with the real Python adapter so the
NCM → analyzer path is exercised, not stubbed.
"""

from app.analyzers.security.analyzer import SecurityAnalyzer
from app.analyzers.security.source import DictSourceProvider
from tests.fixtures.helpers.analyzer_helpers import make_context
from tests.fixtures.helpers.paths import read_fixture_text
from tests.fixtures.helpers.security_helpers import analyze_files, parse_files


def _rule_ids(result) -> set[str]:  # type: ignore[no-untyped-def]
    return {finding.rule_id for finding in result.findings}


def _findings(result, rule_id: str):  # type: ignore[no-untyped-def]
    return [finding for finding in result.findings if finding.rule_id == rule_id]


def _with_partial(files: dict[str, str]):  # type: ignore[no-untyped-def]
    """Parse files then mark every module partially represented."""
    ncm = parse_files(files)
    for entry in ncm.files:
        if entry.module is not None:
            entry.module.completeness = "partially"
    context = make_context(ncm=ncm)
    return SecurityAnalyzer(DictSourceProvider(files)).analyze(context)


# --- SEC-UNSAFE-DESERIALIZATION ---


def test_deserialization_pickle_loads_with_request_input() -> None:
    """Request-derived data into pickle.loads is the canonical signal."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import pickle\n"
                "def load_session(request):\n"
                "    data = request.body()\n"
                "    return pickle.loads(data)\n"
            )
        }
    )
    findings = _findings(result, "SEC-UNSAFE-DESERIALIZATION")
    assert len(findings) == 1
    assert findings[0].severity.value == "Critical"
    assert findings[0].confidence.value == "High"


def test_deserialization_pickle_load_with_external_data() -> None:
    """pickle.load with externally influenced data is flagged."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import io\n"
                "import pickle\n"
                "def restore(request):\n"
                "    stream = io.BytesIO(request.body())\n"
                "    return pickle.load(stream)\n"
            )
        }
    )
    findings = _findings(result, "SEC-UNSAFE-DESERIALIZATION")
    assert len(findings) == 1
    assert findings[0].confidence.value == "High"


def test_deserialization_marshal_loads_flagged() -> None:
    """marshal.loads with external/unresolved input is flagged."""
    result, _, _ = analyze_files(
        {"app.py": ("import marshal\ndef run(payload):\n    return marshal.loads(payload)\n")}
    )
    findings = _findings(result, "SEC-UNSAFE-DESERIALIZATION")
    assert len(findings) == 1
    assert findings[0].confidence.value == "Medium"


def test_deserialization_unresolved_flow_is_conservative() -> None:
    """Unresolved input is flagged at Medium confidence, never assumed safe."""
    result, _, _ = analyze_files(
        {"app.py": ("import pickle\ndef load_session(blob):\n    return pickle.loads(blob)\n")}
    )
    findings = _findings(result, "SEC-UNSAFE-DESERIALIZATION")
    assert len(findings) == 1
    assert findings[0].severity.value == "High"
    assert findings[0].confidence.value == "Medium"


def test_deserialization_fixed_constant_not_flagged() -> None:
    """A fixed local constant is demonstrably not attacker-controlled."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import pickle\n"
                "SNAPSHOT = b'\\x80\\x04N.'\n"
                "def load():\n"
                "    return pickle.loads(SNAPSHOT)\n"
            )
        }
    )
    assert "SEC-UNSAFE-DESERIALIZATION" not in _rule_ids(result)


def test_deserialization_json_never_flagged() -> None:
    """json.loads/loads are data-only parsing, not object deserialization."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import json\n"
                "def load(request):\n"
                "    return json.loads(request.body())\n"
                "def load_file(handle):\n"
                "    return json.load(handle)\n"
            )
        }
    )
    assert "SEC-UNSAFE-DESERIALIZATION" not in _rule_ids(result)


def test_deserialization_safe_yaml_loader_not_flagged() -> None:
    """yaml.safe_load is restricted to plain data (SEC-REQ-032)."""
    result, _, _ = analyze_files(
        {"app.py": ("import yaml\ndef load(text):\n    return yaml.safe_load(text)\n")}
    )
    assert "SEC-UNSAFE-DESERIALIZATION" not in _rule_ids(result)


def test_deserialization_yaml_unsafe_loader_flagged() -> None:
    """yaml.unsafe_load of request data is flagged."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import yaml\ndef load(request):\n    return yaml.unsafe_load(request.body())\n"
            )
        }
    )
    assert "SEC-UNSAFE-DESERIALIZATION" in _rule_ids(result)


def test_deserialization_partial_ncm_reduces_confidence() -> None:
    """Partial representation caps confidence and records coverage."""
    files = {
        "app.py": (
            "import sys\nimport pickle\nblob = sys.argv[1].encode()\nobj = pickle.loads(blob)\n"
        )
    }
    result = _with_partial(files)
    findings = _findings(result, "SEC-UNSAFE-DESERIALIZATION")
    assert len(findings) == 1
    assert findings[0].confidence.value == "Medium"
    assert any(finding.limitations for finding in findings)


def test_deserialization_evidence_recommendation_identity() -> None:
    """Findings carry evidence, a specific recommendation, stable identity."""
    files = {
        "app.py": (
            "import pickle\n"
            "def load(request):\n"
            "    payload = request.form['payload']\n"
            "    return pickle.loads(payload)\n"
        )
    }
    first, _, _ = analyze_files(files)
    second, _, _ = analyze_files(files)
    findings = _findings(first, "SEC-UNSAFE-DESERIALIZATION")
    again = _findings(second, "SEC-UNSAFE-DESERIALIZATION")
    assert len(findings) == 1
    assert findings[0].evidence is not None
    assert len(findings[0].evidence.lines) <= 51
    assert "JSON" in findings[0].recommendation or "json" in findings[0].recommendation
    assert "pickle" in findings[0].recommendation
    assert findings[0].identity_key == again[0].identity_key
    assert findings[0].to_dict() == again[0].to_dict()


def test_deserialization_fixture_file_raises_rule() -> None:
    """The checked-in deserialization fixture raises its own rule."""
    source = read_fixture_text("security", "unsafe_deserialization.py")
    result, _, _ = analyze_files({"unsafe_deserialization.py": source})
    assert "SEC-UNSAFE-DESERIALIZATION" in _rule_ids(result)


# --- SEC-DANGEROUS-DYNAMIC-EXECUTION ---


def test_dynamic_exec_eval_with_user_input() -> None:
    """eval(user_input) is the canonical signal."""
    result, _, _ = analyze_files({"app.py": "def run_plugin(source):\n    return eval(source)\n"})
    findings = _findings(result, "SEC-DANGEROUS-DYNAMIC-EXECUTION")
    assert len(findings) == 1
    assert findings[0].severity.value == "High"
    assert findings[0].confidence.value == "Medium"


def test_dynamic_exec_eval_with_external_input_is_critical() -> None:
    """External input passed directly to eval may be Critical with High confidence."""
    result, _, _ = analyze_files(
        {"app.py": ("import sys\nexpression = sys.argv[1]\nresult = eval(expression)\n")}
    )
    findings = _findings(result, "SEC-DANGEROUS-DYNAMIC-EXECUTION")
    assert len(findings) == 1
    assert findings[0].severity.value == "Critical"
    assert findings[0].confidence.value == "High"


def test_dynamic_exec_exec_with_request_body() -> None:
    """exec(code) with request-derived content is flagged."""
    result, _, _ = analyze_files(
        {"app.py": ("def handle(request):\n    code = request.body()\n    exec(code)\n")}
    )
    findings = _findings(result, "SEC-DANGEROUS-DYNAMIC-EXECUTION")
    assert len(findings) == 1
    assert findings[0].severity.value == "Critical"


def test_dynamic_exec_compile_leading_to_exec() -> None:
    """compile() of external content is flagged; its exec use is flagged too."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "def run(source):\n"
                "    compiled = compile(source, '<input>', 'exec')\n"
                "    exec(compiled)\n"
            )
        }
    )
    findings = _findings(result, "SEC-DANGEROUS-DYNAMIC-EXECUTION")
    assert {finding.location.start_line for finding in findings} == {2, 3}
    by_line = {finding.location.start_line: finding for finding in findings}
    assert by_line[2].severity.value == "High"
    assert by_line[3].severity.value == "High"


def test_dynamic_exec_fixed_expression_is_info_only() -> None:
    """A constant expression is reported at most at Info severity."""
    result, _, _ = analyze_files({"app.py": "def area(r):\n    return eval('3.14 * r')\n"})
    findings = _findings(result, "SEC-DANGEROUS-DYNAMIC-EXECUTION")
    assert len(findings) == 1
    assert findings[0].severity.value == "Info"
    assert findings[0].confidence.value == "Low"


def test_dynamic_exec_literal_eval_not_flagged() -> None:
    """ast.literal_eval is safe literal parsing, not dynamic execution."""
    result, _, _ = analyze_files(
        {"app.py": ("import ast\ndef parse(source):\n    return ast.literal_eval(source)\n")}
    )
    assert "SEC-DANGEROUS-DYNAMIC-EXECUTION" not in _rule_ids(result)


def test_dynamic_exec_sql_execute_not_flagged() -> None:
    """cursor.execute belongs to SQL injection analysis, not this rule."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import sqlite3\n"
                "def find(name):\n"
                "    conn = sqlite3.connect('x')\n"
                "    return conn.execute('SELECT * FROM u WHERE n = ' + name)\n"
            )
        }
    )
    assert "SEC-DANGEROUS-DYNAMIC-EXECUTION" not in _rule_ids(result)
    assert "SEC-SQL-INJECTION" in _rule_ids(result)


def test_dynamic_exec_subprocess_not_flagged() -> None:
    """subprocess.run belongs to command injection analysis, not this rule."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import subprocess\n"
                "def ping(host):\n"
                "    subprocess.run('ping ' + host, shell=True)\n"
            )
        }
    )
    assert "SEC-DANGEROUS-DYNAMIC-EXECUTION" not in _rule_ids(result)
    assert "SEC-COMMAND-INJECTION" in _rule_ids(result)


def test_dynamic_exec_fixture_file_raises_rule() -> None:
    """The checked-in dynamic-execution fixture raises its own rule."""
    source = read_fixture_text("security", "dangerous_dynamic_execution.py")
    result, _, _ = analyze_files({"dangerous_dynamic_execution.py": source})
    assert "SEC-DANGEROUS-DYNAMIC-EXECUTION" in _rule_ids(result)


def test_dynamic_exec_evidence_and_identity() -> None:
    """Evidence is bounded and identities are deterministic."""
    files = {"app.py": "def run(source):\n    return eval(source)\n"}
    first, _, _ = analyze_files(files)
    second, _, _ = analyze_files(files)
    findings = _findings(first, "SEC-DANGEROUS-DYNAMIC-EXECUTION")
    assert len(findings) == 1
    assert findings[0].evidence is not None
    assert findings[0].evidence.start_line == 1
    again = _findings(second, "SEC-DANGEROUS-DYNAMIC-EXECUTION")
    assert findings[0].identity_key == again[0].identity_key


# --- SEC-WEAK-CRYPTO ---


def test_crypto_md5_password_hashing() -> None:
    """MD5 over a password is High severity with High confidence."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import hashlib\n"
                "def store(password):\n"
                "    return hashlib.md5(password.encode()).hexdigest()\n"
            )
        }
    )
    findings = _findings(result, "SEC-WEAK-CRYPTO")
    assert len(findings) == 1
    assert findings[0].severity.value == "High"
    assert findings[0].confidence.value == "High"


def test_crypto_sha1_secret() -> None:
    """SHA-1 over a secret is flagged with security purpose."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import hashlib\n"
                "def sign(secret):\n"
                "    return hashlib.sha1(secret.encode()).hexdigest()\n"
            )
        }
    )
    findings = _findings(result, "SEC-WEAK-CRYPTO")
    assert len(findings) == 1
    assert findings[0].severity.value == "High"


def test_crypto_des_constructor_flagged() -> None:
    """DES cipher construction is flagged."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "from Crypto.Cipher import DES\n"
                "def encrypt(key, data):\n"
                "    cipher = DES.new(key, DES.MODE_ECB)\n"
                "    return cipher.encrypt(data)\n"
            )
        }
    )
    findings = _findings(result, "SEC-WEAK-CRYPTO")
    assert len(findings) >= 1
    assert any("ECB" in finding.title for finding in findings)


def test_crypto_rc4_constructor_flagged() -> None:
    """RC4/ARC4 cipher construction is flagged."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "from Crypto.Cipher import ARC4\n"
                "def encrypt(key, data):\n"
                "    cipher = ARC4.new(key)\n"
                "    return cipher.encrypt(data)\n"
            )
        }
    )
    assert "SEC-WEAK-CRYPTO" in _rule_ids(result)


def test_crypto_checksum_use_is_low() -> None:
    """Non-security checksums are Low severity, never High."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import hashlib\n"
                "def checksum(path):\n"
                "    digest = hashlib.md5(open(path, 'rb').read()).hexdigest()\n"
                "    cache[digest] = path\n"
                "    return digest\n"
            )
        }
    )
    findings = _findings(result, "SEC-WEAK-CRYPTO")
    assert len(findings) == 1
    assert findings[0].severity.value == "Low"
    assert findings[0].confidence.value == "Low"


def test_crypto_usedforsecurity_false_is_low() -> None:
    """An explicit not-for-security marker keeps the finding at Low."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import hashlib\n"
                "def etag(data):\n"
                "    return hashlib.md5(data, usedforsecurity=False).hexdigest()\n"
            )
        }
    )
    findings = _findings(result, "SEC-WEAK-CRYPTO")
    assert len(findings) == 1
    assert findings[0].severity.value == "Low"


def test_crypto_ambiguous_purpose_is_medium() -> None:
    """Ambiguous purpose is Medium/Medium with manual review required."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import hashlib\ndef fingerprint(data):\n    return hashlib.md5(data).hexdigest()\n"
            )
        }
    )
    findings = _findings(result, "SEC-WEAK-CRYPTO")
    assert len(findings) == 1
    assert findings[0].severity.value == "Medium"
    assert findings[0].confidence.value == "Medium"
    assert "Manual review" in findings[0].description


def test_crypto_comment_and_name_mentions_not_flagged() -> None:
    """Comments and variable names alone never trigger findings."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "# md5 is too weak for passwords, use sha256 instead\n"
                'md5_note = "do not use sha1 here"\n'
                "md5_count = 0\n"
                "def count(value):\n"
                "    global md5_count\n"
                "    md5_count += len(value)\n"
                "    return md5_count\n"
            )
        }
    )
    assert "SEC-WEAK-CRYPTO" not in _rule_ids(result)


def test_crypto_sha256_not_flagged() -> None:
    """Modern hashes are never reported by this rule."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import hashlib\n"
                "def store(password):\n"
                "    return hashlib.sha256(password.encode()).hexdigest()\n"
            )
        }
    )
    assert "SEC-WEAK-CRYPTO" not in _rule_ids(result)


def test_crypto_random_for_token_flagged() -> None:
    """stdlib random used for a token is flagged."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import random\n"
                "import string\n"
                "def make_token():\n"
                "    alphabet = string.ascii_letters\n"
                "    token = ''.join(random.choice(alphabet) for _ in range(16))\n"
                "    return token\n"
            )
        }
    )
    findings = _findings(result, "SEC-WEAK-CRYPTO")
    assert len(findings) == 1
    assert findings[0].severity.value == "Medium"


def test_crypto_random_for_nonsensitive_not_flagged() -> None:
    """random used for ordinary values is not a crypto finding."""
    result, _, _ = analyze_files(
        {"app.py": ("import random\ndef roll():\n    return random.randint(1, 6)\n")}
    )
    assert "SEC-WEAK-CRYPTO" not in _rule_ids(result)


def test_crypto_hashlib_new_weak_and_strong() -> None:
    """hashlib.new('md5') is flagged; hashlib.new('sha256') is not."""
    weak, _, _ = analyze_files(
        {
            "app.py": (
                "import hashlib\n"
                "def digest(password):\n"
                "    h = hashlib.new('md5', password.encode())\n"
                "    return h.hexdigest()\n"
            )
        }
    )
    assert "SEC-WEAK-CRYPTO" in _rule_ids(weak)
    strong, _, _ = analyze_files(
        {
            "app.py": (
                "import hashlib\n"
                "def digest(password):\n"
                "    h = hashlib.new('sha256', password.encode())\n"
                "    return h.hexdigest()\n"
            )
        }
    )
    assert "SEC-WEAK-CRYPTO" not in _rule_ids(strong)


def test_crypto_fixture_file_raises_rule() -> None:
    """The checked-in weak-crypto fixture raises its own rule."""
    source = read_fixture_text("security", "weak_crypto.py")
    result, _, _ = analyze_files({"weak_crypto.py": source})
    assert "SEC-WEAK-CRYPTO" in _rule_ids(result)


def test_crypto_recommendation_and_identity() -> None:
    """Recommendations are purpose-aware and identities deterministic."""
    files = {
        "app.py": (
            "import hashlib\n"
            "def store(password):\n"
            "    return hashlib.md5(password.encode()).hexdigest()\n"
        )
    }
    first, _, _ = analyze_files(files)
    second, _, _ = analyze_files(files)
    findings = _findings(first, "SEC-WEAK-CRYPTO")
    assert len(findings) == 1
    assert "Argon2id" in findings[0].recommendation or "bcrypt" in findings[0].recommendation
    assert findings[0].evidence is not None
    assert findings[0].identity_key == _findings(second, "SEC-WEAK-CRYPTO")[0].identity_key


# --- SEC-DISABLED-TLS ---


def test_tls_verify_false_on_get() -> None:
    """requests.get with verify=False and a dynamic URL is High/High."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import requests\ndef fetch(url):\n    return requests.get(url, verify=False)\n"
            )
        }
    )
    findings = _findings(result, "SEC-DISABLED-TLS")
    assert len(findings) == 1
    assert findings[0].severity.value == "High"
    assert findings[0].confidence.value == "High"


def test_tls_verify_false_constant_url_is_medium() -> None:
    """verify=False with a fixed URL stays at the Medium default."""
    source = read_fixture_text("security", "disabled_tls.py")
    result, _, _ = analyze_files({"disabled_tls.py": source})
    findings = _findings(result, "SEC-DISABLED-TLS")
    assert len(findings) == 1
    assert findings[0].severity.value == "Medium"
    assert findings[0].confidence.value == "High"


def test_tls_verify_false_on_request_call() -> None:
    """requests.request with verify=False is flagged."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import requests\n"
                "def fetch(url):\n"
                "    return requests.request('GET', url, verify=False)\n"
            )
        }
    )
    assert "SEC-DISABLED-TLS" in _rule_ids(result)


def test_tls_session_verify_false_assignment() -> None:
    """session.verify = False is flagged through NCM assignments."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import requests\n"
                "session = requests.Session()\n"
                "session.verify = False\n"
                "resp = session.get('https://internal.example/')\n"
            )
        }
    )
    findings = _findings(result, "SEC-DISABLED-TLS")
    assert len(findings) == 1
    assert findings[0].location.start_line == 3


def test_tls_unverified_context_flagged() -> None:
    """ssl._create_unverified_context() is flagged."""
    result, _, _ = analyze_files(
        {"app.py": ("import ssl\ndef context():\n    return ssl._create_unverified_context()\n")}
    )
    findings = _findings(result, "SEC-DISABLED-TLS")
    assert len(findings) == 1
    assert findings[0].confidence.value == "High"


def test_tls_cert_none_and_hostname_flagged() -> None:
    """CERT_NONE and check_hostname = False are flagged."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import ssl\n"
                "def wrap(sock):\n"
                "    return ssl.wrap_socket(sock, cert_reqs=ssl.CERT_NONE)\n"
                "def context():\n"
                "    ctx = ssl.create_default_context()\n"
                "    ctx.check_hostname = False\n"
                "    return ctx\n"
            )
        }
    )
    findings = _findings(result, "SEC-DISABLED-TLS")
    assert len(findings) == 2


def test_tls_normal_https_not_flagged() -> None:
    """A plain HTTPS request without any setting is never reported."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import requests\ndef fetch():\n    return requests.get('https://example.com')\n"
            )
        }
    )
    assert "SEC-DISABLED-TLS" not in _rule_ids(result)


def test_tls_verify_true_not_flagged() -> None:
    """verify=True keeps verification enabled and is never reported."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import requests\ndef fetch(url):\n    return requests.get(url, verify=True)\n"
            )
        }
    )
    assert "SEC-DISABLED-TLS" not in _rule_ids(result)


def test_tls_default_context_not_flagged() -> None:
    """ssl.create_default_context() is the safe form."""
    result, _, _ = analyze_files(
        {"app.py": ("import ssl\ndef context():\n    return ssl.create_default_context()\n")}
    )
    assert "SEC-DISABLED-TLS" not in _rule_ids(result)


def test_tls_unresolved_verify_is_medium() -> None:
    """An unresolvable verify value stays Medium, never assumed False."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import requests\n"
                "def fetch(url, options):\n"
                "    return requests.get(url, verify=options.tls_verify)\n"
            )
        }
    )
    findings = _findings(result, "SEC-DISABLED-TLS")
    assert len(findings) == 1
    assert findings[0].severity.value == "Medium"
    assert findings[0].confidence.value == "Medium"


def test_tls_evidence_recommendation_identity() -> None:
    """Evidence is bounded, recommendation keeps verification, identity stable."""
    files = {
        "app.py": ("import requests\ndef fetch(url):\n    return requests.get(url, verify=False)\n")
    }
    first, _, _ = analyze_files(files)
    second, _, _ = analyze_files(files)
    findings = _findings(first, "SEC-DISABLED-TLS")
    assert len(findings) == 1
    assert findings[0].evidence is not None
    assert "verification" in findings[0].recommendation.lower()
    assert "certificate" in findings[0].recommendation.lower()
    assert findings[0].identity_key == _findings(second, "SEC-DISABLED-TLS")[0].identity_key


# --- SEC-INSECURE-CORS ---


def test_cors_wildcard_middleware_flagged() -> None:
    """CORSMiddleware with allow_origins=['*'] is flagged at Low/Medium."""
    source = read_fixture_text("security", "cors_app.py")
    result, _, _ = analyze_files({"cors_app.py": source})
    findings = _findings(result, "SEC-INSECURE-CORS")
    assert len(findings) == 1
    assert findings[0].severity.value == "Medium"
    assert findings[0].confidence.value == "High"


def test_cors_wildcard_alone_capped_at_low() -> None:
    """A wildcard without credentials must not exceed Low severity (SEC-REQ-035)."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "from starlette.middleware.cors import CORSMiddleware\n"
                "app.add_middleware(CORSMiddleware, allow_origins=['*'])\n"
            )
        }
    )
    findings = _findings(result, "SEC-INSECURE-CORS")
    assert len(findings) == 1
    assert findings[0].severity.value == "Low"
    assert findings[0].confidence.value == "Medium"


def test_cors_explicit_allowlist_not_flagged() -> None:
    """An explicit trusted origin is never reported."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "from fastapi.middleware.cors import CORSMiddleware\n"
                "app.add_middleware(\n"
                "    CORSMiddleware,\n"
                "    allow_origins=['https://example.com'],\n"
                ")\n"
            )
        }
    )
    assert "SEC-INSECURE-CORS" not in _rule_ids(result)


def test_cors_multiple_explicit_origins_not_flagged() -> None:
    """Several explicit origins are still an allowlist, not a wildcard."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "from fastapi.middleware.cors import CORSMiddleware\n"
                "app.add_middleware(\n"
                "    CORSMiddleware,\n"
                "    allow_origins=['https://a.example', 'https://b.example'],\n"
                "    allow_credentials=True,\n"
                ")\n"
            )
        }
    )
    assert "SEC-INSECURE-CORS" not in _rule_ids(result)


def test_cors_unresolved_origins_stay_unresolved() -> None:
    """Configured origins that cannot be resolved are Info/Low, never wildcard."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "from fastapi.middleware.cors import CORSMiddleware\n"
                "def configure(app, settings):\n"
                "    app.add_middleware(\n"
                "        CORSMiddleware,\n"
                "        allow_origins=settings.cors_origins,\n"
                "    )\n"
            )
        }
    )
    findings = _findings(result, "SEC-INSECURE-CORS")
    assert len(findings) == 1
    assert findings[0].severity.value == "Info"
    assert findings[0].confidence.value == "Low"
    assert "could not be resolved" in findings[0].title.lower()


def test_cors_non_cors_middleware_not_flagged() -> None:
    """Other middleware with similar kwargs is not CORS configuration."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "from starlette.middleware.trustedhost import TrustedHostMiddleware\n"
                "app.add_middleware(TrustedHostMiddleware, allowed_hosts=['example.com'])\n"
            )
        }
    )
    assert "SEC-INSECURE-CORS" not in _rule_ids(result)


def test_cors_wildcard_header_flagged() -> None:
    """A wildcard Access-Control-Allow-Origin header assignment is flagged."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "def handle(response):\n"
                "    response.headers.add('Access-Control-Allow-Origin', '*')\n"
                "    return response\n"
            )
        }
    )
    findings = _findings(result, "SEC-INSECURE-CORS")
    assert len(findings) == 1
    assert findings[0].severity.value == "Low"


def test_cors_specific_origin_header_not_flagged() -> None:
    """A fixed, specific origin header is restrictive and never reported."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "def handle(response):\n"
                "    response.headers.add(\n"
                "        'Access-Control-Allow-Origin', 'https://example.com'\n"
                "    )\n"
                "    return response\n"
            )
        }
    )
    assert "SEC-INSECURE-CORS" not in _rule_ids(result)


def test_cors_recommendation_evidence_identity() -> None:
    """Findings explain credentials, recommend allowlists, identify stably."""
    files = {
        "app.py": (
            "from fastapi.middleware.cors import CORSMiddleware\n"
            "app.add_middleware(\n"
            "    CORSMiddleware,\n"
            "    allow_origins=['*'],\n"
            "    allow_credentials=True,\n"
            ")\n"
        )
    }
    first, _, _ = analyze_files(files)
    second, _, _ = analyze_files(files)
    findings = _findings(first, "SEC-INSECURE-CORS")
    assert len(findings) == 1
    assert "allow-list" in findings[0].recommendation
    assert findings[0].evidence is not None
    assert findings[0].identity_key == _findings(second, "SEC-INSECURE-CORS")[0].identity_key


def test_cors_coverage_metadata_is_honest() -> None:
    """The spec names actual framework coverage, not every Python framework."""
    from app.analyzers.security.metadata import SPEC_BY_RULE_ID

    spec = SPEC_BY_RULE_ID["SEC-INSECURE-CORS"]
    assert "CORSMiddleware" in " ".join(spec.supported_sinks)
    assert "FastAPI" in spec.coverage_notes or "Starlette" in spec.coverage_notes
    assert "every" not in spec.coverage_notes.lower() or "not" in spec.coverage_notes.lower()
