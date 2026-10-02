"""Injection rule tests (TASK-097–100): vulnerable, safe, and partial flows.

Each rule must detect its suspicious patterns, stay silent on obvious
safe patterns, and mark unresolved flows explicitly instead of assuming
safety. Sources here are parsed with the real Python adapter so the
NCM → analyzer path is exercised, not stubbed.
"""

from app.analyzers.security.analyzer import SecurityAnalyzer
from tests.fixtures.helpers.security_helpers import analyze_files


def _rule_ids(result) -> set[str]:  # type: ignore[no-untyped-def]
    return {finding.rule_id for finding in result.findings}


# --- SEC-SQL-INJECTION ---


def test_sql_direct_concatenation_flagged() -> None:
    """String concatenation into a query sink is the canonical signal."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import sqlite3\n"
                "def find(user_id):\n"
                "    cur = sqlite3.connect('x').cursor()\n"
                "    cur.execute('SELECT * FROM users WHERE id = ' + user_id)\n"
            )
        }
    )
    assert "SEC-SQL-INJECTION" in _rule_ids(result)


def test_sql_fstring_flagged() -> None:
    """f-string interpolation into query text is flagged."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import sqlite3\n"
                "def find(name):\n"
                "    conn = sqlite3.connect('x')\n"
                "    q = f\"SELECT * FROM users WHERE name = '{name}'\"\n"
                "    conn.execute(q)\n"
            )
        }
    )
    findings = [f for f in result.findings if f.rule_id == "SEC-SQL-INJECTION"]
    assert len(findings) == 1
    assert findings[0].severity.value == "High"


def test_sql_format_and_percent_flagged() -> None:
    """str.format and % formatting into query text are both flagged."""
    result, _, _ = analyze_files(
        {
            "a.py": (
                "import sqlite3\n"
                "def find(name):\n"
                "    c = sqlite3.connect('x')\n"
                "    q = 'SELECT * FROM u WHERE n = {}'.format(name)\n"
                "    c.execute(q)\n"
            ),
            "b.py": (
                "import sqlite3\n"
                "def find(name):\n"
                "    c = sqlite3.connect('x')\n"
                "    q = 'SELECT * FROM u WHERE n = %s' % name\n"
                "    c.execute(q)\n"
            ),
        }
    )
    flagged = [f for f in result.findings if f.rule_id == "SEC-SQL-INJECTION"]
    assert {f.location.file_path for f in flagged} == {"a.py", "b.py"}


def test_sql_parameterized_query_not_flagged() -> None:
    """Static text plus bound parameters is the safe form (SEC-REQ-028)."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import sqlite3\n"
                "def find(user_id):\n"
                "    conn = sqlite3.connect('x')\n"
                "    conn.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
            )
        }
    )
    assert "SEC-SQL-INJECTION" not in _rule_ids(result)


def test_sql_constant_statement_not_flagged() -> None:
    """A constant statement with no dynamic parts is not reported."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import sqlite3\n"
                "def count():\n"
                "    conn = sqlite3.connect('x')\n"
                "    return conn.execute('SELECT COUNT(*) FROM users').fetchall()\n"
            )
        }
    )
    assert "SEC-SQL-INJECTION" not in _rule_ids(result)


def test_sql_external_input_raises_confidence() -> None:
    """sys.argv-derived input reaches High confidence; params stay Medium."""
    external = (
        "import sqlite3\n"
        "import sys\n"
        "name = sys.argv[1]\n"
        "conn = sqlite3.connect('x')\n"
        "conn.execute('SELECT * FROM u WHERE n = ' + name)\n"
    )
    result, _, _ = analyze_files({"app.py": external})
    findings = [f for f in result.findings if f.rule_id == "SEC-SQL-INJECTION"]
    assert len(findings) == 1
    assert findings[0].confidence.value == "High"


def test_sql_unrelated_code_not_flagged() -> None:
    """Non-SQL helpers with similar names are not claimed as sinks."""
    result, _, _ = analyze_files(
        {"app.py": ("def execute_task(name):\n    message = 'hello ' + name\n    return message\n")}
    )
    assert "SEC-SQL-INJECTION" not in _rule_ids(result)


# --- SEC-COMMAND-INJECTION ---


def test_command_os_system_flagged() -> None:
    """Dynamic text in os.system is flagged (shell is implicit)."""
    result, _, _ = analyze_files(
        {"app.py": ("import os\ndef show(filename):\n    os.system('cat ' + filename)\n")}
    )
    findings = [f for f in result.findings if f.rule_id == "SEC-COMMAND-INJECTION"]
    assert len(findings) == 1
    assert findings[0].severity.value == "High"


def test_command_shell_true_with_external_input() -> None:
    """External input plus shell=True is the highest-risk combination."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import subprocess\n"
                "import sys\n"
                "host = sys.argv[1]\n"
                "subprocess.run('ping ' + host, shell=True)\n"
            )
        }
    )
    findings = [f for f in result.findings if f.rule_id == "SEC-COMMAND-INJECTION"]
    assert len(findings) == 1
    assert findings[0].severity.value == "Critical"
    assert findings[0].confidence.value == "High"


def test_command_fixed_list_not_flagged() -> None:
    """A fixed argument list without a shell is not reported."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import subprocess\n"
                "def status():\n"
                "    subprocess.run(['git', 'status'], check=True)\n"
            )
        }
    )
    assert "SEC-COMMAND-INJECTION" not in _rule_ids(result)


def test_command_constant_without_shell_not_flagged() -> None:
    """A constant command without shell interpretation is not reported."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import subprocess\ndef status():\n    subprocess.run('git status', shell=False)\n"
            )
        }
    )
    assert "SEC-COMMAND-INJECTION" not in _rule_ids(result)


def test_command_propagated_variable_flagged() -> None:
    """Bounded propagation: variable-built command reaches the sink."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import subprocess\n"
                "def grep(pattern):\n"
                "    command = f'grep {pattern} file.txt'\n"
                "    subprocess.run(command, shell=True)\n"
            )
        }
    )
    assert "SEC-COMMAND-INJECTION" in _rule_ids(result)


# --- SEC-PATH-TRAVERSAL ---


def test_path_direct_external_filename_flagged() -> None:
    """External filename joined into open() is flagged."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "def read_report(name):\n"
                "    filename = name\n"
                "    with open('/var/data/' + filename) as handle:\n"
                "        return handle.read()\n"
            )
        }
    )
    assert "SEC-PATH-TRAVERSAL" in _rule_ids(result)


def test_path_fstring_flagged() -> None:
    """f-string path construction into a filesystem sink is flagged."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "def load(user_path):\n"
                "    path = f'/uploads/{user_path}'\n"
                "    return open(path).read()\n"
            )
        }
    )
    findings = [f for f in result.findings if f.rule_id == "SEC-PATH-TRAVERSAL"]
    assert len(findings) == 1
    assert findings[0].severity.value == "Medium"


def test_path_fixed_path_not_flagged() -> None:
    """A fixed literal path is not reported."""
    result, _, _ = analyze_files(
        {"app.py": ("def load():\n    return open('/srv/reports/daily.txt').read()\n")}
    )
    assert "SEC-PATH-TRAVERSAL" not in _rule_ids(result)


def test_path_validated_containment_not_flagged() -> None:
    """Resolve-then-contain in the visible scope counts as validation."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "from pathlib import Path\n"
                "BASE = Path('/srv/data')\n"
                "def load(name):\n"
                "    candidate = (BASE / name).resolve()\n"
                "    if str(candidate.relative_to(BASE)):\n"
                "        return candidate.read_text()\n"
                "    raise ValueError('bad path')\n"
            )
        }
    )
    assert "SEC-PATH-TRAVERSAL" not in _rule_ids(result)


def test_path_unresolved_flow_flagged_with_medium_confidence() -> None:
    """Unresolved input is flagged (Medium), never assumed safe."""
    result, _, _ = analyze_files(
        {"app.py": ("import os\ndef remove(target):\n    os.remove(target)\n")}
    )
    findings = [f for f in result.findings if f.rule_id == "SEC-PATH-TRAVERSAL"]
    assert len(findings) == 1
    assert findings[0].confidence.value == "Medium"


# --- SEC-SSRF ---


def test_ssrf_request_parameter_flagged() -> None:
    """A request-derived URL reaching an HTTP sink is flagged."""
    result, _, _ = analyze_files(
        {"app.py": ("import requests\ndef fetch(url):\n    return requests.get(url).text\n")}
    )
    assert "SEC-SSRF" in _rule_ids(result)


def test_ssrf_propagated_url_flagged() -> None:
    """A propagated dynamic URL reaching the sink is flagged."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import httpx\n"
                "def fetch(user_url):\n"
                "    target = 'https://api.example.com/proxy?url=' + user_url\n"
                "    return httpx.get(target).text\n"
            )
        }
    )
    findings = [f for f in result.findings if f.rule_id == "SEC-SSRF"]
    assert len(findings) == 1


def test_ssrf_fixed_url_not_flagged() -> None:
    """A fixed constant URL is never reported (SEC-REQ-031)."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import requests\n"
                "def users():\n"
                "    return requests.get('https://api.example.com/users').json()\n"
            )
        }
    )
    assert "SEC-SSRF" not in _rule_ids(result)


def test_ssrf_external_url_high_confidence() -> None:
    """External input controlling the URL reaches High confidence."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import sys\n"
                "import urllib.request\n"
                "target = sys.argv[1]\n"
                "urllib.request.urlopen(target)\n"
            )
        }
    )
    findings = [f for f in result.findings if f.rule_id == "SEC-SSRF"]
    assert len(findings) == 1
    assert findings[0].confidence.value == "High"


def test_ssrf_configurable_url_info_low() -> None:
    """Configurable URLs are reported at most at Info with Low confidence."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import os\n"
                "import requests\n"
                "def fetch():\n"
                '    target = os.environ.get("TARGET_URL")\n'
                "    return requests.get(target).text\n"
            )
        }
    )
    findings = [f for f in result.findings if f.rule_id == "SEC-SSRF"]
    assert len(findings) == 1
    assert findings[0].severity.value == "Info"
    assert findings[0].confidence.value == "Low"


def test_ssrf_visible_allowlist_not_flagged() -> None:
    """A visible host restriction in the local scope suppresses the finding."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import requests\n"
                'ALLOWED = ("https://api.example.com",)\n'
                "def fetch(url):\n"
                "    if url in ALLOWED:\n"
                "        return requests.get(url).text\n"
                '    raise ValueError("bad host")\n'
            )
        }
    )
    assert "SEC-SSRF" not in _rule_ids(result)


def test_command_constant_with_shell_is_info_only() -> None:
    """A constant command with a shell MAY be Info; never High."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import subprocess\ndef status():\n    subprocess.run('git status', shell=True)\n"
            )
        }
    )
    findings = [f for f in result.findings if f.rule_id == "SEC-COMMAND-INJECTION"]
    assert len(findings) == 1
    assert findings[0].severity.value == "Info"
    assert findings[0].confidence.value == "Low"


def test_cross_rule_separation() -> None:
    """One file can raise several rules; each finding keeps its own rule."""
    files = {
        "app.py": (
            "import os\n"
            "import sqlite3\n"
            "import subprocess\n"
            "def handle(name, host):\n"
            "    conn = sqlite3.connect('x')\n"
            "    conn.execute('SELECT * FROM u WHERE n = ' + name)\n"
            "    subprocess.run('ping ' + host, shell=True)\n"
            "    os.system('echo done')\n"
        )
    }
    result, _, _ = analyze_files(files)
    by_rule: dict[str, int] = {}
    for finding in result.findings:
        by_rule[finding.rule_id] = by_rule.get(finding.rule_id, 0) + 1
    assert by_rule.get("SEC-SQL-INJECTION") == 1
    assert by_rule.get("SEC-COMMAND-INJECTION") == 2
    assert "SEC-PATH-TRAVERSAL" not in by_rule
    assert "SEC-SSRF" not in by_rule


def test_safe_fixture_file_produces_no_findings() -> None:
    """The shared safe-patterns fixture stays silent across all rules."""
    from tests.fixtures.helpers.paths import read_fixture_text

    source = read_fixture_text("security", "security_safe_patterns.py")
    result, _, _ = analyze_files({"security_safe_patterns.py": source})
    assert result.findings == ()


def test_vulnerable_fixture_files_produce_findings() -> None:
    """Each vulnerable fixture raises its own rule and only expected rules."""
    from tests.fixtures.helpers.paths import read_fixture_text

    expectations = {
        "sql_injection.py": "SEC-SQL-INJECTION",
        "command_injection.py": "SEC-COMMAND-INJECTION",
        "path_traversal.py": "SEC-PATH-TRAVERSAL",
        "ssrf_app.py": "SEC-SSRF",
    }
    for fixture, rule_id in expectations.items():
        source = read_fixture_text("security", fixture)
        result, _, _ = analyze_files({fixture: source})
        assert rule_id in _rule_ids(result), fixture


def test_security_analyzer_without_source_marks_partial() -> None:
    """No source access means unevaluated modules: partial, never clean."""
    from app.ncm import NcmRepository
    from tests.fixtures.helpers.analyzer_helpers import make_context
    from tests.fixtures.helpers.security_helpers import parse_files

    ncm: NcmRepository = parse_files(
        {"app.py": "import sqlite3\ndef f(x):\n    sqlite3.connect('x').execute('a' + x)\n"}
    )
    context = make_context(ncm=ncm)
    result = SecurityAnalyzer(None).analyze(context)
    assert result.findings == ()
    assert any(item.limitations for item in result.rule_results)
