import type { AnalysisResult, ArchitectureDoc, Finding, FindingsPage } from "../schemas/results";

// Contract-shaped fixtures mirroring backend/app/results/canonical.py.
// Repository-derived strings include HTML-like payloads to prove inert
// rendering; secrets appear only in already-redacted form.

export function findingFixture(overrides: Partial<Finding> = {}): Finding {
  return {
    finding_id: "F-0001",
    identity_key: "ik-0001",
    rule_id: "SEC-HARDCODED-SECRET",
    rule_name: "Hardcoded Secret",
    category: "security",
    severity: "High",
    confidence: "Medium",
    subject: {
      locations: [{ path: "app/config.py", start_line: 12, end_line: 12, start_column: 0, end_column: 20 }],
      modules: [],
      dependencies: [],
    },
    evidence: {
      redacted: true,
      source_context: {
        text: 'PAYMENT_KEY = "[REDACTED]"',
        start_line: 11,
        end_line: 13,
      },
    },
    explanation: "A potential hardcoded secret may require review.",
    impact: "Exposure may allow misuse.",
    recommendation: "Rotate the credential and move it out of the repository.",
    ...overrides,
  } as Finding;
}

export function archFindingFixture(overrides: Partial<Finding> = {}): Finding {
  return findingFixture({
    finding_id: "F-0009",
    identity_key: "ik-0009",
    rule_id: "ARCH-CIRCULAR-DEPENDENCY",
    rule_name: "Circular Dependency",
    category: "architecture",
    severity: "Low",
    confidence: "High",
    subject: {
      locations: [{ path: "app/a.py", start_line: 3, end_line: 3, start_column: 0, end_column: 10 }],
      modules: ["app/a.py", "app/b.py"],
      dependencies: [],
    },
    evidence: {
      redacted: false,
      source_context: null,
      structure: {
        participants: ["app/a.py", "app/b.py"],
        paths_limited: true,
        relationships: [
          { source: "app/a.py", target: "app/b.py" },
          { source: "app/b.py", target: "app/a.py" },
        ],
      },
    },
    ...overrides,
  } as Finding);
}

export function findingsPageFixture(items: Finding[], total?: number): FindingsPage {
  return {
    page: 1,
    page_size: 25,
    total: total ?? items.length,
    items,
  };
}

export function architectureFixture(): ArchitectureDoc {
  return {
    granularity: "Source file",
    potentially_incomplete: false,
    nodes: [
      {
        node_id: "app/a.py",
        name: "a.py",
        paths: ["app/a.py"],
        partially_represented: false,
        finding_ids: ["F-0009"],
        layer: "application",
      },
      {
        node_id: "app/b.py",
        name: "b.py",
        paths: ["app/b.py"],
        partially_represented: true,
        finding_ids: ["F-0009"],
        layer: null,
      },
    ],
    edges: [
      {
        source: "app/a.py",
        target: "app/b.py",
        relationship_type: "import",
        locations: [{ path: "app/a.py", line: 3, column: 0 }],
      },
      {
        source: "app/b.py",
        target: "app/a.py",
        relationship_type: "import",
        locations: [{ path: "app/b.py", line: 4, column: 0 }],
      },
    ],
    external_and_unresolved_references: [
      { source: "app/a.py", resolution: "external", target_reference: "os", locations: [] },
    ],
    cycles: [{ finding_id: "F-0009", node_ids: ["app/a.py", "app/b.py"] }],
    metrics: [
      { metric: "fan_out", subject_path: "app/a.py", availability: "available", value: 4 },
      { metric: "fan_in", subject_path: "app/b.py", availability: "unavailable" },
    ],
    metric_definitions: {},
    findings: [archFindingFixture()],
    rule_evaluations: [{ rule_id: "ARCH-CIRCULAR-DEPENDENCY", state: "Evaluated" }],
  };
}

export function analysisResultFixture(
  overrides: Partial<AnalysisResult> = {},
): AnalysisResult {
  const base = {
    analysis: {
      analysis_id: "abc123",
      repository_id: "r1",
      timestamp: "2026-09-29T08:15:42Z",
      analyzer_version: "1.0.0",
      rule_set_version: "1.0",
    },
    repository: {
      repository_id: "r1",
      url: "https://github.com/acme/web",
      owner: "acme",
      name: "web",
      analyzed_state: {
        branch: { name: "main", origin: "Defaulted" },
        commit: { sha: "9f2c1e7a4b8d3f60a5c7e1b2d4f8a09c3e5b7d61", origin: "Defaulted" },
      },
    },
    status: {
      stage: null,
      outcome: "Completed",
      completed_at: "2026-09-29T08:16:31Z",
      explanation: "",
      snapshot: { sealed_at: "2026-09-29T08:16:32Z" },
      domains: [
        { area: "security", state: null, reason: null },
        { area: "architecture", state: null, reason: null },
        { area: "dependency", state: "No findings detected", reason: null },
        { area: "code_structure", state: "No findings detected", reason: null },
      ],
      limitations: [],
    },
    summary: {
      security: {
        state: null,
        findings: {
          total: 1,
          by_severity: { Critical: 0, High: 1, Medium: 0, Low: 0, Info: 0 },
          by_confidence: { High: 0, Medium: 1, Low: 0 },
          by_rule: { "SEC-HARDCODED-SECRET": 1 },
        },
      },
      architecture: {
        state: null,
        findings: {
          total: 1,
          by_severity: { Critical: 0, High: 0, Medium: 0, Low: 1, Info: 0 },
          by_confidence: { High: 1, Medium: 0, Low: 0 },
          by_rule: { "ARCH-CIRCULAR-DEPENDENCY": 1 },
        },
      },
      dependencies: {
        state: "No findings detected",
        findings: { total: 0, by_severity: {}, by_confidence: {}, by_rule: {} },
      },
      code_structure: {
        state: "No findings detected",
        findings: { total: 0, by_severity: {}, by_confidence: {}, by_rule: {} },
      },
    },
    security: { rule_evaluations: [], findings: [findingFixture()] },
    architecture: {
      rule_evaluations: [],
      findings: [archFindingFixture()],
      graph: {},
      cycles: [{ finding_id: "F-0009", node_ids: ["app/a.py", "app/b.py"] }],
    },
    dependencies: { rule_evaluations: [], items: [], findings: [] },
    code_structure: { rule_evaluations: [], findings: [] },
  };
  return { ...base, ...overrides } as unknown as AnalysisResult;
}

/** Minimal fetch mock routing on URL *path suffixes* (query strings
 * ignored), so `/findings` requests are never swallowed by an
 * `/api/analyses/{id}` entry that happens to be a substring. */
export function mockFetchRoutes(routes: Array<{ match: string; payload: unknown; status?: number }>) {
  const calls: string[] = [];
  window.fetch = (async (input: RequestInfo | URL) => {
    const url = String(input);
    calls.push(url);
    const path = new URL(url).pathname;
    const route = routes.find((entry) => path === entry.match || path.endsWith(entry.match));
    const status = route?.status ?? 200;
    return {
      ok: status >= 200 && status < 300,
      status,
      text: () => Promise.resolve(JSON.stringify(route?.payload ?? {})),
    } as Response;
  }) as typeof fetch;
  return calls;
}
