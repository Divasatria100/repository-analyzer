"""Phase 9 rule tests (TASK-106–108): positive, negative, and boundary flows.

Each rule must detect its suspicious patterns, stay silent on obvious
safe patterns, and mark unresolved flows explicitly instead of assuming
safety. Sources here are parsed with the real Python adapter so the
NCM → analyzer path is exercised, not stubbed.
"""

from app.analyzers.security.analyzer import SecurityAnalyzer
from app.analyzers.security.source import DictSourceProvider
from app.ncm import NcmFileEntry, NcmRepository
from tests.fixtures.helpers.analyzer_helpers import make_context
from tests.fixtures.helpers.paths import read_fixture_text
from tests.fixtures.helpers.security_helpers import analyze_files, parse_files


def _rule_ids(result) -> set[str]:  # type: ignore[no-untyped-def]
    return {finding.rule_id for finding in result.findings}


def _findings(result, rule_id: str):  # type: ignore[no-untyped-def]
    return [finding for finding in result.findings if finding.rule_id == rule_id]


def _secret_repo(
    py_files: dict[str, str],
    text_files: dict[str, str],
    languages: dict[str, str] | None = None,
) -> tuple[NcmRepository, dict[str, str]]:
    """NCM with parsed Python plus unscanned-by-parser text entries."""
    ncm = parse_files(py_files)
    contents = dict(py_files)
    contents.update(text_files)
    for path in sorted(text_files):
        language = (languages or {}).get(path, path.rpartition(".")[2] or None)
        ncm.files.append(
            NcmFileEntry(path=path, language=language, parse_state="unsupported", module=None)
        )
    return ncm, contents


def _analyze_secret(
    py_files: dict[str, str],
    text_files: dict[str, str],
    languages: dict[str, str] | None = None,
):  # type: ignore[no-untyped-def]
    ncm, contents = _secret_repo(py_files, text_files, languages)
    context = make_context(ncm=ncm)
    result = SecurityAnalyzer(DictSourceProvider(contents)).analyze(context)
    return result, context


# --- SEC-SENSITIVE-LOGGING ---


def test_logging_direct_password_high_high() -> None:
    """External password straight into a logger is High/High."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import logging\n"
                "def login(request):\n"
                "    password = request.json['password']\n"
                "    logger = logging.getLogger(__name__)\n"
                "    logger.info('password=%s', password)\n"
            )
        }
    )
    findings = _findings(result, "SEC-SENSITIVE-LOGGING")
    assert len(findings) == 1
    assert findings[0].severity.value == "High"
    assert findings[0].confidence.value == "High"


def test_logging_token_from_env_medium() -> None:
    """Configurable token by name is Medium; bare token never exceeds Medium."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import logging, os\n"
                "token = os.environ['API_TOKEN']\n"
                "logging.info('token=%s', token)\n"
            )
        }
    )
    findings = _findings(result, "SEC-SENSITIVE-LOGGING")
    assert len(findings) == 1
    assert findings[0].severity.value == "Medium"
    assert findings[0].confidence.value == "Medium"


def test_logging_authorization_header_high() -> None:
    """Sensitive header field of an external object is High/High."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import logging\n"
                "def call_api(request):\n"
                "    logging.info('Authorization: %s', request.headers['Authorization'])\n"
            )
        }
    )
    findings = _findings(result, "SEC-SENSITIVE-LOGGING")
    assert len(findings) == 1
    assert findings[0].severity.value == "High"
    assert findings[0].confidence.value == "High"


def test_logging_format_variants_flagged() -> None:
    """f-string, concat, format, and percent styles are all covered."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import logging\n"
                "def trace(secret):\n"
                "    logging.info(f'secret={secret}')\n"
                "    logging.info('secret=' + secret)\n"
                "    logging.info('secret={}'.format(secret))\n"
                "    logging.info('secret=%s' % secret)\n"
            )
        }
    )
    findings = _findings(result, "SEC-SENSITIVE-LOGGING")
    assert len(findings) == 4


def test_logging_account_attribute_medium() -> None:
    """Sensitive attribute access with unresolved base is Medium."""
    result, _, _ = analyze_files(
        {"app.py": ("import logging\ndef show(account):\n    logging.info(account.api_key)\n")}
    )
    findings = _findings(result, "SEC-SENSITIVE-LOGGING")
    assert len(findings) == 1
    assert findings[0].severity.value == "Medium"


def test_logging_whole_user_object_low() -> None:
    """A whole entity object is Low with an explicit limitation."""
    result, _, _ = analyze_files(
        {"app.py": ("import logging\ndef debug_user(user):\n    logging.info('user=%s', user)\n")}
    )
    findings = _findings(result, "SEC-SENSITIVE-LOGGING")
    assert len(findings) == 1
    assert findings[0].severity.value == "Low"
    assert findings[0].confidence.value == "Low"
    assert findings[0].limitations


def test_logging_unresolved_param_medium() -> None:
    """A sensitive-named parameter is Medium, never assumed safe."""
    result, _, _ = analyze_files(
        {"app.py": ("import logging\ndef trace(password):\n    logging.info('pw=%s', password)\n")}
    )
    findings = _findings(result, "SEC-SENSITIVE-LOGGING")
    assert len(findings) == 1
    assert findings[0].confidence.value == "Medium"


def test_logging_safe_identifiers_silent() -> None:
    """user_id, request_id, and status are not sensitive."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import logging\n"
                "def track(user_id, request_id, status):\n"
                "    logging.info('user_id=%s', user_id)\n"
                "    logging.info('request_id=%s', request_id)\n"
                "    logging.info('status=%s', status)\n"
            )
        }
    )
    assert "SEC-SENSITIVE-LOGGING" not in _rule_ids(result)


def test_logging_masked_values_silent() -> None:
    """mask()/redact() wrappers are treated as sanitized."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import logging\n"
                "def audit(password, token):\n"
                "    logging.info('password=%s', mask(password))\n"
                "    logging.info('token=%s', redact(token))\n"
            )
        }
    )
    assert "SEC-SENSITIVE-LOGGING" not in _rule_ids(result)


def test_logging_bool_len_slice_silent() -> None:
    """bool(), len(), and slices are safe representations."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import logging\n"
                "def audit(password, token):\n"
                "    logging.info('present=%s', bool(password))\n"
                "    logging.info('length=%s', len(token))\n"
                "    logging.info('prefix=%s', token[:4])\n"
            )
        }
    )
    assert "SEC-SENSITIVE-LOGGING" not in _rule_ids(result)


def test_logging_measurement_names_silent() -> None:
    """token_count and password_length hold metadata, not secrets."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import logging\n"
                "def counts(token_count, password_length):\n"
                "    logging.info('token_count=%s', token_count)\n"
                "    logging.info('password_length=%s', password_length)\n"
            )
        }
    )
    assert "SEC-SENSITIVE-LOGGING" not in _rule_ids(result)


def test_logging_static_message_silent() -> None:
    """A message merely mentioning a term without logging a value is silent."""
    result, _, _ = analyze_files(
        {"app.py": ('import logging\ndef check():\n    logging.info("password check failed")\n')}
    )
    assert "SEC-SENSITIVE-LOGGING" not in _rule_ids(result)


def test_logging_print_reduced_confidence() -> None:
    """print of a sensitive value is Low/Low at most, never High."""
    result, _, _ = analyze_files(
        {"app.py": ("import sys\ndef dump():\n    password = sys.argv[1]\n    print(password)\n")}
    )
    findings = _findings(result, "SEC-SENSITIVE-LOGGING")
    assert len(findings) == 1
    assert findings[0].severity.value == "Low"
    assert findings[0].confidence.value == "Low"


def test_logging_print_plain_values_silent() -> None:
    """print of ordinary values is not a logging finding."""
    result, _, _ = analyze_files({"app.py": "def show(user_id):\n    print(user_id)\n"})
    assert "SEC-SENSITIVE-LOGGING" not in _rule_ids(result)


def test_logging_fixture_files() -> None:
    """Checked-in positive/negative logging fixtures behave as labeled."""
    positive = read_fixture_text("security", "sensitive_logging_app.py")
    result, _, _ = analyze_files({"sensitive_logging_app.py": positive})
    assert "SEC-SENSITIVE-LOGGING" in _rule_ids(result)
    assert len(_findings(result, "SEC-SENSITIVE-LOGGING")) >= 5
    negative = read_fixture_text("security", "sensitive_logging_safe.py")
    result, _, _ = analyze_files({"sensitive_logging_safe.py": negative})
    assert "SEC-SENSITIVE-LOGGING" not in _rule_ids(result)


def test_logging_finding_hides_values() -> None:
    """Descriptions, subjects, and identities carry names, never values."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import logging\n"
                "def login(request):\n"
                "    password = request.json['password']\n"
                "    logging.info('password=%s', password)\n"
            )
        }
    )
    findings = _findings(result, "SEC-SENSITIVE-LOGGING")
    assert len(findings) == 1
    text = findings[0].description + findings[0].title + findings[0].identity_key
    assert "password" in text
    assert "hunter2" not in text
    assert findings[0].recommendation


# --- SEC-POTENTIAL-AUTHORIZATION ---


def test_auth_delete_without_check_medium() -> None:
    """A deleting route without any check is Medium/Low."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "from db import get_session\n"
                "from models import User\n"
                '@app.delete("/users/{user_id}")\n'
                "def delete_account(user_id):\n"
                "    session = get_session()\n"
                "    session.query(User).filter(User.id == user_id).delete()\n"
            )
        }
    )
    findings = _findings(result, "SEC-POTENTIAL-AUTHORIZATION")
    assert len(findings) == 1
    assert findings[0].severity.value == "Medium"
    assert findings[0].confidence.value == "Low"
    assert "Manual review is required" in findings[0].description


def test_auth_lookup_without_check_low() -> None:
    """An identifier-keyed read without a check is Low/Low."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "from db import get_session\n"
                "from models import User\n"
                '@app.get("/users/{user_id}")\n'
                "def get_user(user_id):\n"
                "    session = get_session()\n"
                "    return session.query(User).filter(User.id == user_id).first()\n"
            )
        }
    )
    findings = _findings(result, "SEC-POTENTIAL-AUTHORIZATION")
    assert len(findings) == 1
    assert findings[0].severity.value == "Low"
    assert findings[0].confidence.value == "Low"


def test_auth_inconsistency_raises_to_medium() -> None:
    """An unchecked handler next to a checked sibling is Medium."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "from db import get_session\n"
                "from models import User\n"
                '@app.get("/admin/export")\n'
                "def export_all():\n"
                "    check_permission(current_user, 'admin')\n"
                "    return get_session().query(User).all()\n"
                '@app.get("/admin/purge")\n'
                "def purge_all():\n"
                "    return get_session().query(User).delete()\n"
            )
        }
    )
    findings = _findings(result, "SEC-POTENTIAL-AUTHORIZATION")
    assert len(findings) == 1
    assert findings[0].location.start_line == 8
    assert findings[0].confidence.value == "Medium"


def test_auth_checked_route_silent() -> None:
    """A visible authorization check suppresses the finding."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "from db import get_session\n"
                "from models import User\n"
                '@app.post("/admin/users")\n'
                "def create_user(payload):\n"
                '    require_role("admin")\n'
                "    session = get_session()\n"
                "    return session.query(User).all()\n"
            )
        }
    )
    assert "SEC-POTENTIAL-AUTHORIZATION" not in _rule_ids(result)


def test_auth_depends_guard_silent() -> None:
    """Depends(require_admin) in the signature counts as a check."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "from db import get_session\n"
                "from models import User\n"
                '@app.get("/users/me")\n'
                "def get_self(current_user=Depends(require_admin)):\n"
                "    return get_session().query(User).all()\n"
            )
        }
    )
    assert "SEC-POTENTIAL-AUTHORIZATION" not in _rule_ids(result)


def test_auth_health_and_public_silent() -> None:
    """Health and public endpoints are never authorization findings."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                '@app.get("/health")\n'
                "def health():\n"
                '    return {"status": "ok"}\n'
                '@app.get("/public")\n'
                "def public_page():\n"
                "    return render('public.html')\n"
            )
        }
    )
    assert "SEC-POTENTIAL-AUTHORIZATION" not in _rule_ids(result)


def test_auth_plain_function_with_delete_silent() -> None:
    """A non-route helper is not an entry point, even with a delete call."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "from db import get_session\n"
                "from models import User\n"
                "def cleanup():\n"
                "    get_session().query(User).delete()\n"
            )
        }
    )
    assert "SEC-POTENTIAL-AUTHORIZATION" not in _rule_ids(result)


def test_auth_constant_read_silent() -> None:
    """A route reading only constants has no resource operation."""
    result, _, _ = analyze_files(
        {"app.py": ('@app.get("/version")\ndef version():\n    return {"v": "1.0"}\n')}
    )
    assert "SEC-POTENTIAL-AUTHORIZATION" not in _rule_ids(result)


def test_auth_registration_call_style_silent() -> None:
    """add_url_rule-style registration is outside V1 route support."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "from db import get_session\n"
                "from models import User\n"
                "def get_user(user_id):\n"
                "    return get_session().query(User).filter(User.id == user_id).first()\n"
                "app.add_url_rule('/users/<user_id>', view_func=get_user)\n"
            )
        }
    )
    assert "SEC-POTENTIAL-AUTHORIZATION" not in _rule_ids(result)


def test_auth_bare_helper_lookup_flagged() -> None:
    """A route handler delegating lookup to get_user(user_id) is flagged."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                '@app.get("/users/{user_id}")\n'
                "def get_user(user_id):\n"
                "    user = get_user(user_id)\n"
                "    return user\n"
            )
        }
    )
    findings = _findings(result, "SEC-POTENTIAL-AUTHORIZATION")
    assert len(findings) == 1
    assert findings[0].confidence.value != "High"
    assert "Manual review is required" in findings[0].description


def test_auth_bare_helper_constant_arg_silent() -> None:
    """A helper call with only constant arguments is not a resource signal."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                '@app.get("/users/me")\n'
                "def get_default():\n"
                "    user = get_user(1)\n"
                "    return user\n"
            )
        }
    )
    assert "SEC-POTENTIAL-AUTHORIZATION" not in _rule_ids(result)


def test_auth_multiline_decorator_flagged() -> None:
    """Route decorators spanning lines are still recognized."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "from db import get_session\n"
                "from models import User\n"
                "@app.get(\n"
                '    "/users/{user_id}"\n'
                ")\n"
                "def get_user(user_id):\n"
                "    return get_session().query(User).filter(User.id == user_id).first()\n"
            )
        }
    )
    findings = _findings(result, "SEC-POTENTIAL-AUTHORIZATION")
    assert len(findings) == 1


def test_auth_require_auth_decorator_silent() -> None:
    """@require_auth is a recognizable authorization decorator."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "from db import get_session\n"
                "from models import User\n"
                "@require_auth\n"
                '@app.get("/users/{user_id}")\n'
                "def get_user(user_id):\n"
                "    return get_session().query(User).filter(User.id == user_id).first()\n"
            )
        }
    )
    assert "SEC-POTENTIAL-AUTHORIZATION" not in _rule_ids(result)


def test_auth_confidence_never_high() -> None:
    """No authorization finding may exceed Medium confidence."""
    source = read_fixture_text("security", "authorization_app.py")
    result, _, _ = analyze_files({"authorization_app.py": source})
    findings = _findings(result, "SEC-POTENTIAL-AUTHORIZATION")
    assert len(findings) >= 2
    for finding in findings:
        assert finding.confidence.value in ("Low", "Medium")
        assert "Manual review is required" in finding.description
        assert "vulnerable" not in finding.description.lower()


def test_auth_fixture_files() -> None:
    """Checked-in positive/negative authorization fixtures behave as labeled."""
    positive = read_fixture_text("security", "authorization_app.py")
    result, _, _ = analyze_files({"authorization_app.py": positive})
    assert len(_findings(result, "SEC-POTENTIAL-AUTHORIZATION")) == 3
    negative = read_fixture_text("security", "authorization_safe.py")
    result, _, _ = analyze_files({"authorization_safe.py": negative})
    assert "SEC-POTENTIAL-AUTHORIZATION" not in _rule_ids(result)


def test_auth_partial_when_source_missing() -> None:
    """Missing source is a limitation, never a clean pass."""
    from app.analyzers.security.analyzer import SecurityAnalyzer

    ncm = parse_files(
        {"app.py": ('@app.get("/users/{user_id}")\ndef get_user(user_id):\n    return user_id\n')}
    )
    context = make_context(ncm=ncm)
    result = SecurityAnalyzer(None).analyze(context)
    assert not [f for f in result.findings if f.rule_id == "SEC-POTENTIAL-AUTHORIZATION"]
    item = next(r for r in result.rule_results if r.rule_id == "SEC-POTENTIAL-AUTHORIZATION")
    assert item.limitations


# --- SEC-HARDCODED-SECRET ---


def test_secret_aws_key_in_python() -> None:
    """An AWS-style key ID in source is High/High."""
    result, _ = _analyze_secret({"app.py": 'AWS_ACCESS_KEY_ID = "AKIAY2P4R6T8W0A2C4E6"\n'}, {})
    findings = _findings(result, "SEC-HARDCODED-SECRET")
    assert len(findings) == 1
    assert findings[0].severity.value == "High"
    assert findings[0].confidence.value == "High"
    assert findings[0].location.start_line == 1


def test_secret_documented_example_key_silent() -> None:
    """The documented AWS example key is a sample value, not a secret."""
    result, _ = _analyze_secret({"app.py": 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'}, {})
    assert "SEC-HARDCODED-SECRET" not in _rule_ids(result)


def test_secret_scans_yaml_and_env() -> None:
    """Non-Python text files are scanned with a scanned-only limitation."""
    result, _ = _analyze_secret(
        {},
        {
            "config.yaml": "database:\n  password: hunter2-hunter2-hunter2-hunter2\n",
            ".env": 'API_TOKEN="x7f3a9c2e5b1d8f4a6c0e2b5d9a3f7c1e4b2a"\n',
        },
        {"config.yaml": "yaml", ".env": None},
    )
    findings = _findings(result, "SEC-HARDCODED-SECRET")
    assert {f.location.file_path for f in findings} == {"config.yaml", ".env"}
    item = next(r for r in result.rule_results if r.rule_id == "SEC-HARDCODED-SECRET")
    assert any("only" in lim.reason for lim in item.limitations)


def test_secret_bearer_token() -> None:
    """A bearer token value is flagged without keeping the token."""
    result, _ = _analyze_secret(
        {"app.py": 'AUTH = "Bearer x7f3a9c2e5b1d8f4a6c0e2b5d9a3f7c1e4b2a"\n'}, {}
    )
    findings = _findings(result, "SEC-HARDCODED-SECRET")
    assert len(findings) == 1
    assert "x7f3a9c2e" not in findings[0].description
    assert "x7f3a9c2e" not in str(findings[0].to_dict())


def test_secret_private_key_masked() -> None:
    """Private key blocks are Critical; the body never persists."""
    body = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7\n"
    source = (
        'KEY = """\n-----BEGIN PRIVATE KEY-----\n' + body + "-----END PRIVATE KEY-----\n" + '"""\n'
    )
    result, _ = _analyze_secret({"app.py": source}, {})
    findings = _findings(result, "SEC-HARDCODED-SECRET")
    assert len(findings) == 1
    assert findings[0].severity.value == "Critical"
    assert findings[0].evidence is not None
    assert findings[0].evidence.redacted is True
    assert "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7" not in str(findings[0].to_dict())


def test_secret_password_assignment_medium() -> None:
    """A credential-shaped assignment is Medium confidence."""
    result, _ = _analyze_secret({"app.py": 'db_password = "hunter2-hunter2-hunter2"\n'}, {})
    findings = _findings(result, "SEC-HARDCODED-SECRET")
    assert len(findings) == 1
    assert findings[0].confidence.value == "Medium"


def test_secret_short_value_low() -> None:
    """A short value on a secret name is Low, still reported."""
    result, _ = _analyze_secret({"app.py": 'api_key = "abcdef12"\n'}, {})
    findings = _findings(result, "SEC-HARDCODED-SECRET")
    assert len(findings) == 1
    assert findings[0].confidence.value == "Low"


def test_secret_placeholders_silent() -> None:
    """Placeholders, env refs, and trivial values are never reported."""
    source = read_fixture_text("security", "hardcoded_secret.py")
    result, _ = _analyze_secret({"hardcoded_secret.py": source}, {})
    assert "SEC-HARDCODED-SECRET" not in _rule_ids(result)
    result, _ = _analyze_secret(
        {
            "app.py": (
                'API_KEY = "YOUR_API_KEY"\n'
                'TOKEN = "<your-token-here>"\n'
                'SECRET = "changeme"\n'
                'SECRET2 = "CHANGE_ME"\n'
                'KEY = "xxxxxxxxxxxxxxxx"\n'
                'OLD = "***"\n'
                'REF = "${API_TOKEN}"\n'
            )
        },
        {},
    )
    assert "SEC-HARDCODED-SECRET" not in _rule_ids(result)
    result, _ = _analyze_secret(
        {"app.py": ("import os\napi_key = os.getenv(\"API_KEY\")\ntoken = os.environ['TOKEN']\n")},
        {},
    )
    assert "SEC-HARDCODED-SECRET" not in _rule_ids(result)


def test_secret_binary_and_git_excluded() -> None:
    """Binaries, .git content, and null-byte files are excluded with reasons."""
    result, _ = _analyze_secret(
        {"app.py": "x = 1\n"},
        {"logo.png": "fakepngbytes", ".git/config": 'password = "hunter2-hunter2"\n'},
        {"logo.png": "png", ".git/config": None},
    )
    assert "SEC-HARDCODED-SECRET" not in _rule_ids(result)
    item = next(r for r in result.rule_results if r.rule_id == "SEC-HARDCODED-SECRET")
    reasons = " ".join(lim.reason for lim in item.limitations)
    assert "Binary" in reasons or "binary" in reasons
    assert ".git" in reasons or "version-control" in reasons


def test_secret_null_bytes_excluded() -> None:
    """Null-byte content is treated as binary, not text."""
    result, _ = _analyze_secret({"app.py": "x = 1\n"}, {"blob.dat": "ab\x00cd"})
    assert "SEC-HARDCODED-SECRET" not in _rule_ids(result)
    item = next(r for r in result.rule_results if r.rule_id == "SEC-HARDCODED-SECRET")
    assert any("inary" in lim.reason for lim in item.limitations)


def test_secret_unreadable_is_limitation() -> None:
    """Files the provider cannot read are recorded, never clean."""
    from app.analyzers.security.source import SourceProvider

    class _HalfBlindProvider:
        def read(self, path: str):  # type: ignore[no-untyped-def]
            if path == "dark.py":
                return None
            return DictSourceProvider({"app.py": "x = 1\n"}).read(path)

    ncm, _ = _secret_repo({"app.py": "x = 1\n", "dark.py": "x = 2\n"}, {})
    provider: SourceProvider = _HalfBlindProvider()  # type: ignore[assignment]
    result = SecurityAnalyzer(provider).analyze(make_context(ncm=ncm))
    item = next(r for r in result.rule_results if r.rule_id == "SEC-HARDCODED-SECRET")
    assert any(lim.path == "dark.py" for lim in item.limitations)
    assert not [f for f in result.findings if f.rule_id == "SEC-HARDCODED-SECRET"]


def test_secret_test_path_downgraded() -> None:
    """Test/example paths report one confidence level lower, still reported."""
    result, _ = _analyze_secret({}, {"tests/test_data.py": 'API_TOKEN = "AKIAY2P4R6T8W0A2C4E6"\n'})
    findings = _findings(result, "SEC-HARDCODED-SECRET")
    assert len(findings) == 1
    assert findings[0].confidence.value == "Medium"


def test_secret_evidence_window_and_redaction() -> None:
    """Secret evidence honors 10-before/40-after and masks the value."""
    filler_before = "".join(f"# pad {i}\n" for i in range(99))
    filler_after = "".join(f"# pad {i}\n" for i in range(200, 260))
    source = filler_before + 'api_key = "hunter2-hunter2-hunter2-hunter2"\n' + filler_after
    result, _ = _analyze_secret({"app.py": source}, {})
    findings = _findings(result, "SEC-HARDCODED-SECRET")
    assert len(findings) == 1
    evidence = findings[0].evidence
    assert evidence is not None
    assert evidence.start_line == 90
    assert evidence.end_line == 140
    assert len(evidence.lines) == 51
    assert evidence.redacted is True
    assert "hunter2" not in "\n".join(evidence.lines)


def test_secret_deterministic_identity() -> None:
    """Repeated scans agree on identity, location, and evidence."""
    files = ({"app.py": 'api_key = "hunter2-hunter2-hunter2-hunter2"\n'}, {})
    first, _ = _analyze_secret(*files)
    second, _, _ = analyze_files({"app.py": files[0]["app.py"]})
    first_ids = [f.identity_key for f in _findings(first, "SEC-HARDCODED-SECRET")]
    second_ids = [f.identity_key for f in _findings(second, "SEC-HARDCODED-SECRET")]
    assert first_ids == second_ids
    assert len(first_ids) == 1


def test_secret_positive_fixtures_fire() -> None:
    """Checked-in positive fixtures raise the secret rule per file."""
    for fixture in (
        "hardcoded_secret_positive.py",
        "hardcoded_secret_config.yaml",
        "hardcoded_secret_notes.txt",
    ):
        source = read_fixture_text("security", fixture)
        if fixture.endswith(".py"):
            result, _, _ = analyze_files({fixture: source})
        else:
            language = fixture.rpartition(".")[2] or None
            result, _ = _analyze_secret({}, {fixture: source}, {fixture: language})
        assert "SEC-HARDCODED-SECRET" in _rule_ids(result), fixture
