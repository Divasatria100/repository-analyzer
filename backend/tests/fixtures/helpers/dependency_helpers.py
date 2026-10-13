"""Test-only builders for Phase 8 dependency tests (never production code)."""

from __future__ import annotations

from collections.abc import Callable

import httpx

from app.analyzers.base import AnalyzerResult
from app.analyzers.context import AnalysisContext
from app.analyzers.dependency.analyzer import DependencyAnalyzer, DictManifestProvider
from app.analyzers.dependency.osv import OsvClient, osv_client_from_network_settings
from app.core.config import load_settings
from app.ncm import NcmRepository
from app.services.http_client import RetryPolicy, ServiceClient, TimeoutConfig
from tests.fixtures.helpers.analyzer_helpers import make_context
from tests.fixtures.helpers.security_helpers import parse_files

Handler = Callable[[httpx.Request], httpx.Response]


def mock_osv_client(
    handler: Handler,
    *,
    max_retries: int = 2,
) -> OsvClient:
    """OSV client over a mock transport (no real network I/O, no sleeps)."""
    network = load_settings().network
    client = ServiceClient(
        name="osv",
        base_url="https://api.osv.dev",
        timeout=TimeoutConfig(connect=network.connect_timeout_s, read=network.advisory_timeout_s),
        retry_policy=RetryPolicy(max_retries=max_retries, backoff_base_s=0),
        transport=httpx.MockTransport(handler),
    )
    return OsvClient(client)


def default_osv_client(handler: Handler) -> OsvClient:
    """OSV client built from centralized settings with an injected transport."""
    network = load_settings().network
    service = osv_client_from_network_settings(network, transport=httpx.MockTransport(handler))
    service.retry_policy = RetryPolicy(
        max_retries=service.retry_policy.max_retries, backoff_base_s=0
    )
    return OsvClient(service)


def analyze_manifests(
    manifests: dict[str, str],
    sources: dict[str, str] | None = None,
    osv_client: OsvClient | None = None,
    analysis_id: str = "analysis-1",
) -> tuple[AnalyzerResult, AnalysisContext, DependencyAnalyzer]:
    """Build context (NCM from sources) and run the dependency analyzer."""
    ncm: NcmRepository = parse_files(sources or {})
    context = make_context(analysis_id=analysis_id, ncm=ncm)
    analyzer = DependencyAnalyzer(DictManifestProvider(manifests), osv_client)
    result: AnalyzerResult = analyzer.analyze(context)
    return result, context, analyzer


def rule_result(result: AnalyzerResult, rule_id: str):  # type: ignore[no-untyped-def]
    """Fetch one rule's result by ID."""
    for item in result.rule_results:
        if item.rule_id == rule_id:
            return item
    raise AssertionError(f"missing rule result: {rule_id}")
