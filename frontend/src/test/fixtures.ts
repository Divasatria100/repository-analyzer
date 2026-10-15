import type {
  AnalysisResult,
  ArchitectureDoc,
  Comparison,
  Finding,
  FindingsPage,
  RepositoryHistory,
} from "../schemas/results";

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

export function depFindingFixture(overrides: Partial<Finding> = {}): Finding {
  return findingFixture({
    finding_id: "F-0021",
    identity_key: "ik-0021",
    rule_id: "DEP-KNOWN-VULNERABILITY",
    rule_name: "Known Vulnerability",
    category: "dependency",
    severity: "High",
    confidence: "High",
    subject: {
      locations: [{ path: "requirements.txt", start_line: 1, end_line: 1, start_column: 0, end_column: 16 }],
      modules: [],
      dependencies: ["dep-requests"],
    },
    evidence: {
      redacted: false,
      source_context: null,
      advisories: [{ advisory_id: "GHSA-xxxx", source: "OSV" }],
    },
    ...overrides,
  } as Finding);
}

export function codeFindingFixture(overrides: Partial<Finding> = {}): Finding {
  return findingFixture({
    finding_id: "F-0031",
    identity_key: "ik-0031",
    rule_id: "CODE-HIGH-COMPLEXITY",
    rule_name: "High Complexity",
    category: "code_structure",
    severity: "Medium",
    confidence: "High",
    subject: {
      locations: [{ path: "app/a.py", start_line: 40, end_line: 80, start_column: 0, end_column: 0 }],
      modules: ["app/a.py"],
      dependencies: [],
    },
    evidence: {
      redacted: false,
      source_context: null,
      measurements: [{ metric: "complexity", value: 18, exceeded: true }],
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
      advisory_data: { source: "OSV", consulted_at: "2026-09-29T08:16:05Z", outcome: "Succeeded" },
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
      metric_definitions: {},
      metrics: [],
      graph: {
        granularity: "Source file",
        potentially_incomplete: false,
        nodes: [
          {
            node_id: "app/a.py",
            name: "a.py",
            paths: ["app/a.py"],
            partially_represented: false,
            finding_ids: ["F-0009"],
          },
        ],
        edges: [],
        external_and_unresolved_references: [],
      },
      cycles: [{ finding_id: "F-0009", node_ids: ["app/a.py", "app/b.py"] }],
      findings: [archFindingFixture()],
    },
    dependencies: { rule_evaluations: [], items: [dependencyItemFixture()], findings: [depFindingFixture()] },
    code_structure: {
      rule_evaluations: [],
      metric_definitions: {
        complexity: {
          description: "Cyclomatic complexity of the function.",
          interpretation: "Higher values indicate more decision paths to exercise.",
          unit: "score",
        },
      },
      metrics: [
        { metric: "complexity", subject_path: "app/a.py", subject_name: "render", availability: "available", value: 18 },
        { metric: "nesting_depth", subject_path: "app/a.py", subject_name: "render", availability: "available", value: 5 },
        { metric: "complexity", subject_path: "app/b.py", subject_name: "load", availability: "unavailable" },
      ],
      findings: [codeFindingFixture()],
    },
    files: [fileFixture(), fileFixture({ path: "requirements.txt", file_type: "dependency manifest", language: null, support: "Unrecognized" })],
  };
  return { ...base, ...overrides } as unknown as AnalysisResult;
}

export function dependencyItemFixture(overrides: Record<string, unknown> = {}) {
  return {
    dependency_id: "dep-requests",
    name: "requests",
    version: "2.19.0",
    ecosystem: "pypi",
    classification: "direct",
    source_manifest: "requirements.txt",
    introduced_by: [],
    advisories: [{ advisory_id: "GHSA-xxxx", source: "OSV" }],
    finding_ids: ["F-0021"],
    ...overrides,
  };
}

export function fileFixture(overrides: Record<string, unknown> = {}) {
  return {
    path: "app/a.py",
    file_type: "source",
    language: "Python",
    support: "Primary Support",
    size: 2140,
    binary: false,
    generated: false,
    exclusion: null,
    eligibility: { classification: "Eligible", reason: null },
    parse_result: "Parsed",
    diagnostics: [],
    indexing_limitation: null,
    coverage: [
      { scope: { kind: "area", value: "security" }, state: "Fully analyzed" },
    ],
    finding_count: 2,
    ...overrides,
  };
}

/** Minimal fetch mock routing on URL *path suffixes* (query strings
 * ignored), so `/findings` requests are never swallowed by an
 * `/api/analyses/{id}` entry that happens to be a substring. */
export function mockFetchRoutes(
  routes: Array<{ match: string; payload: unknown; status?: number }>,
) {
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

export function repositoryHistoryFixture(): RepositoryHistory {
  const entry = (
    analysis_id: string,
    outcome: string | null,
    timestamp: string | null,
    extra: Record<string, unknown> = {},
  ) => ({
    analysis_id,
    branch: { name: "main", origin: "Defaulted" },
    commit: {
      sha: "9f2c1e7a4b8d3f60a5c7e1b2d4f8a09c3e5b7d61",
      origin: "Defaulted",
    },
    timestamp,
    analyzer_version: "1.0.0",
    rule_set_version: "1.0",
    outcome,
    explanation: outcome === "Failed" ? "Retrieval failed." : "",
    ...extra,
  });
  return {
    repository_id: "r1",
    url: "https://github.com/acme/web",
    owner: "acme",
    name: "web",
    analyses: [
      entry("target9", "Completed", "2026-09-29T08:15:42Z"),
      entry("base111", "Completed", "2026-09-22T10:03:11Z"),
      entry("fail007", "Failed", "2026-09-20T10:03:11Z"),
      entry("queue42", null, null),
    ],
  };
}

export function comparisonFixture(): Comparison {
  return {
    comparable: true,
    base: {
      commit_sha: "1a7d5c3e9b0f2846d1e3a5c7b9f0d2e4a6c8b0f2",
      timestamp: "2026-09-22T10:03:11Z",
      analyzer_version: "1.0.0",
      rule_set_version: "1.0",
    },
    target: {
      commit_sha: "9f2c1e7a4b8d3f60a5c7e1b2d4f8a09c3e5b7d61",
      timestamp: "2026-09-29T08:15:42Z",
      analyzer_version: "1.0.0",
      rule_set_version: "1.0",
    },
    context_differences: {
      analyzer_version: false,
      rule_set_version: false,
      configuration: false,
      advisory_data: true,
    },
    qualifications: [
      {
        scope: "rule",
        rule_id: "DEP-KNOWN-VULNERABILITY",
        area: "dependency",
        effect: "Resolved findings of this rule may reflect unevaluated scope.",
      },
    ],
    new: [
      {
        identity_key: "ik-0001",
        rule_id: "SEC-HARDCODED-SECRET",
        category: "security",
        target_finding_id: "F-0001",
      },
    ],
    resolved: [
      {
        identity_key: "ik-0021",
        rule_id: "DEP-KNOWN-VULNERABILITY",
        category: "dependency",
        base_finding_id: "F-0021",
        qualified: true,
      },
    ],
    unchanged: [
      {
        identity_key: "ik-0009",
        rule_id: "ARCH-CIRCULAR-DEPENDENCY",
        category: "architecture",
        base_finding_id: "F-0009",
        target_finding_id: "F-0009",
      },
    ],
  };
}
