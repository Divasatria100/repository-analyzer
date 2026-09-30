"""Redaction tests (TASK-092): centralized masking, usefulness preserved."""

from app.analyzers.redaction import mask_secrets, redaction_marker
from tests.fixtures.helpers.analyzer_helpers import make_evidence, make_finding


def test_representative_secrets_masked() -> None:
    """Password/token/key/secret patterns are masked with a single marker."""
    cases = [
        'password = "hunter2-hunter2-hunter2"',
        "api_key='AKIAIOSFODNN7EXAMPLE'",
        "token: abc123xyz",
        "Authorization: Bearer hunter2",
    ]
    for raw in cases:
        masked, had_secrets = mask_secrets(raw)
        assert had_secrets is True, raw
        assert raw not in masked
        assert redaction_marker() in masked


def test_normal_context_preserved_byte_identical() -> None:
    """Non-sensitive code passes through unchanged (usefulness preserved)."""
    lines = [
        "def handler(request):",
        "    user = request.args.get('name')",
        "    return render(user)",
    ]
    for line in lines:
        masked, had_secrets = mask_secrets(line)
        assert had_secrets is False
        assert masked == line


def test_evidence_redaction_flag_and_serialization() -> None:
    """Findings built from masked excerpts flag redaction and round-trip."""
    from app.analyzers.findings import Evidence, Finding

    raw = 'password = "hunter2-hunter2"'
    masked, had_secrets = mask_secrets(raw)
    assert had_secrets is True
    evidence = Evidence(path="src/app.py", start_line=1, end_line=1, lines=(masked,), redacted=True)
    finding = make_finding(evidence=evidence)
    assert finding.evidence is not None and finding.evidence.redacted is True
    assert "hunter2" not in str(finding.to_dict())
    rebuilt = Finding.from_dict(finding.to_dict())
    assert rebuilt.evidence is not None and rebuilt.evidence.redacted is True
    assert rebuilt == finding


def test_serialized_findings_never_leak_secrets() -> None:
    """Full serialized form contains markers, never raw secret values."""
    secret = "hunter2-hunter2-hunter2"
    masked, _ = mask_secrets(f"token = {secret!r}")
    finding = make_finding(evidence=make_evidence())
    dumped = str(finding.to_dict())
    assert secret not in dumped
    assert masked != f"token = {secret!r}"


def test_failure_messages_redacted() -> None:
    """Failure text passes through the same masking before recording."""
    from app.analyzers.base import RuleFailure

    raw = "upstream says password = hunter2-hunter2"
    masked, had_secrets = mask_secrets(raw)
    assert had_secrets is True
    failure = RuleFailure(
        rule_id="SEC-TEST-001",
        analyzer_id="security",
        analysis_id="analysis-1",
        message=masked,
    )
    assert "hunter2" not in failure.message
    assert "***" in failure.message


def test_logs_never_carry_raw_secrets() -> None:
    """Analyzer logging paths emit markers, never raw secrets."""
    import logging

    from app.core.logging import RedactingFilter, get_logger

    captured: list[str] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(self.format(record))

    logger = get_logger("analyzers")
    handler = Capture()
    handler.addFilter(RedactingFilter())
    logger.addHandler(handler)
    previous_level = logger.level
    previous_disabled = logger.disabled
    # NB: the Alembic migration test triggers fileConfig(), which disables
    # pre-existing loggers process-wide. Save/restore around the assertion.
    logger.disabled = False
    logger.setLevel(logging.INFO)
    try:
        logger.info("evidence excerpt: %s", 'password = "hunter2-hunter2"')
    finally:
        logger.setLevel(previous_level)
        logger.disabled = previous_disabled
        logger.removeHandler(handler)
    assert captured
    assert "hunter2" not in "".join(captured)
    assert "***" in "".join(captured)
