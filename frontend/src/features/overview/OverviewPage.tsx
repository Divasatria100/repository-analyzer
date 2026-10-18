import { Link, useParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { ANALYSIS_ID_PARAM, ROUTES } from "../../router/routes";
import { useAnalysisResult } from "../analysis/useAnalysisResult";
import { isUnavailableState, type FindingsQuery } from "../../schemas/results";
import { Alert, EmptyState, LoadingState, Panel, StatusBadge } from "../../components/ui";
import { ApiRequestError, listFindings } from "../../lib/api";
import {
  CategoryBadge,
  ConfidenceBadge,
  SeverityBadge,
  formatLineRange,
} from "../findings/FindingBits";

// Analysis Overview (TASK-189, docs/14 §8.3). Panels A–E render only
// contract-backed values from the persisted canonical result: identity and
// lifecycle (A), the area summary table (B), the severity/confidence summary
// (C), the findings preview (D), and repository context (E). A null section
// renders as unavailable with its state — never as zero findings. No score,
// ranking, or combined severity/confidence figure is ever computed.

const AREA_ORDER = [
  { key: "security", domain: "security", label: "Security", to: ROUTES.analysisSecurity },
  {
    key: "architecture",
    domain: "architecture",
    label: "Architecture",
    to: ROUTES.analysisArchitecture,
  },
  {
    key: "dependencies",
    domain: "dependency",
    label: "Dependencies",
    to: ROUTES.analysisDependencies,
  },
  {
    key: "code_structure",
    domain: "code_structure",
    label: "Code Structure",
    to: ROUTES.analysisCodeStructure,
  },
] as const;

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"] as const;
const CONFIDENCE_ORDER = ["High", "Medium", "Low"] as const;
const LIMITATIONS_VISIBLE = 5;

// Section 19.2: a `No findings detected` state is not a safety claim.
const NO_FINDINGS_QUALIFIER =
  "No findings were detected by the rules evaluated in this analysis. This is a result " +
  "of static analysis and does not indicate that the repository has no issues.";

const PREVIEW_QUERY: FindingsQuery = {
  category: [],
  severity: [],
  confidence: [],
  rule_id: [],
  q: "",
  sort: "severity",
  order: "asc",
  page: 1,
  page_size: 10,
};

type FindingsBlock = {
  total: number;
  by_severity: Record<string, number>;
  by_confidence: Record<string, number>;
  by_rule: Record<string, number>;
};

type AreaSummary = { state: string | null; findings: FindingsBlock | null };

type OverviewSummary = {
  languages?: { language: string; support: string; file_count: number }[];
  files?: { indexed?: number; parse_results?: Record<string, number> };
  security?: AreaSummary;
  architecture?: AreaSummary & {
    module_count?: number;
    module_dependency_count?: number;
    cycle_count?: { value: number; unit: string };
  };
  dependencies?: AreaSummary & {
    dependency_count?: { total: number; direct: number; transitive: number };
    vulnerable_count?: number;
    duplicate_version_package_count?: number;
  };
  code_structure?: AreaSummary;
};

function areaSummary(summary: OverviewSummary | null, key: string): AreaSummary | null {
  if (!summary) {
    return null;
  }
  return (summary as Record<string, AreaSummary | undefined>)[key] ?? null;
}

function countByField(
  summary: OverviewSummary | null,
  field: "by_severity" | "by_confidence",
): Record<string, number> {
  const totals: Record<string, number> = {};
  for (const area of AREA_ORDER) {
    const block = areaSummary(summary, area.key)?.findings;
    if (!block) {
      continue;
    }
    for (const [name, value] of Object.entries(block[field] ?? {})) {
      totals[name] = (totals[name] ?? 0) + value;
    }
  }
  return totals;
}

function groupLimitations<T extends { scope_kind?: string }>(limitations: T[]): [string, T[]][] {
  const groups = new Map<string, T[]>();
  for (const limitation of limitations) {
    const key = limitation.scope_kind ?? "other";
    const list = groups.get(key) ?? [];
    list.push(limitation);
    groups.set(key, list);
  }
  return [...groups.entries()];
}

function OutcomeBadge({ outcome }: { outcome: string }) {
  if (outcome === "Failed") {
    return <StatusBadge label="Failed" tone="error" marker="✕" />;
  }
  if (outcome === "Completed with limitations") {
    return <StatusBadge label="Completed with limitations" tone="warning" marker="▲" />;
  }
  return <StatusBadge label={outcome} tone="neutral" marker="–" />;
}

function SeverityCounts({ counts }: { counts: Record<string, number> }) {
  const present = SEVERITY_ORDER.filter((severity) => (counts[severity] ?? 0) > 0);
  if (present.length === 0) {
    return <span className="text-text-secondary">—</span>;
  }
  return (
    <span className="flex flex-wrap items-center gap-2">
      {present.map((severity) => (
        <span key={severity} className="inline-flex items-center gap-1">
          <SeverityBadge severity={severity} />
          <span className="font-mono">{counts[severity]}</span>
        </span>
      ))}
    </span>
  );
}

export function OverviewPage() {
  const params = useParams();
  const analysisId = params[ANALYSIS_ID_PARAM] ?? "";
  const { data, error, isLoading, refetch, isFetching } = useAnalysisResult(analysisId);

  const outcome = data?.status.outcome ?? null;
  const previewEnabled = outcome != null && outcome !== "Failed";
  const preview = useQuery({
    queryKey: ["findings", analysisId, "overview-preview"],
    queryFn: ({ signal }) => listFindings(analysisId, PREVIEW_QUERY, signal),
    enabled: previewEnabled,
    refetchOnWindowFocus: false,
    retry: (count, queryError) =>
      !(queryError instanceof ApiRequestError && queryError.code === "ANALYSIS_NOT_FOUND") &&
      count < 1,
  });

  if (isLoading) {
    return <LoadingState label="Loading analysis overview…" />;
  }

  if (error || !data) {
    const apiError = error instanceof ApiRequestError ? error : null;
    return (
      <Panel>
        <Alert
          tone="error"
          title={
            apiError?.code === "ANALYSIS_NOT_FOUND"
              ? "Analysis not found."
              : "Could not load the overview."
          }
        >
          <p>{apiError?.message ?? "An unexpected error occurred."}</p>
        </Alert>
        <button
          type="button"
          onClick={() => void refetch()}
          disabled={isFetching}
          className="mt-4 rounded-control border border-border px-4 py-2 text-sm font-medium text-text-primary hover:border-primary disabled:opacity-50"
        >
          {isFetching ? "Retrying…" : "Retry"}
        </button>
      </Panel>
    );
  }

  const { status, repository, analysis } = data;
  const summary = data.summary as unknown as OverviewSummary | null;

  // Non-terminal and failed analyses have null sections by contract: never
  // render a completion summary for them.
  if (status.outcome == null) {
    return (
      <Panel>
        <h2 className="text-lg font-semibold">Analysis not completed</h2>
        <p className="mt-2 text-sm text-text-secondary">
          This analysis is at stage {status.stage ?? "Unknown"}. Overview data is only
          available once the backend reports a completed outcome.
        </p>
        <Link
          to={ROUTES.analysisDetail(analysisId)}
          className="mt-4 inline-block rounded-control border border-border px-4 py-2 text-sm font-medium text-text-primary hover:border-primary"
        >
          View progress
        </Link>
      </Panel>
    );
  }

  if (status.outcome === "Failed") {
    return (
      <Panel>
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-lg font-semibold">Analysis failed</h2>
          <OutcomeBadge outcome={status.outcome} />
        </div>
        <div className="mt-4">
          <Alert tone="error" title="The analysis did not produce usable results.">
            {status.explanation ? <p>{status.explanation}</p> : null}
          </Alert>
        </div>
      </Panel>
    );
  }

  const domains = new Map(status.domains.map((domain) => [domain.area, domain]));
  const branch = repository.analyzed_state.branch;
  const commit = repository.analyzed_state.commit;
  const advisory = analysis.advisory_data ?? null;
  const advisoryGap =
    advisory != null && (advisory.outcome === "Partly succeeded" || advisory.outcome === "Unavailable");
  const unavailableAreas = AREA_ORDER.filter((area) =>
    isUnavailableState(areaState(summary, area.key)),
  );
  const severityTotals = countByField(summary, "by_severity");
  const confidenceTotals = countByField(summary, "by_confidence");
  const hasNoFindingsState = AREA_ORDER.some(
    (area) => areaState(summary, area.key) === "No findings detected",
  );
  const limitations = groupLimitations(status.limitations);
  const architecture = summary?.architecture;
  const dependencies = summary?.dependencies;
  const parseResults = summary?.files?.parse_results ?? {};

  return (
    <div className="space-y-6">
      {/* A. Status, context, and limitations (docs/14 §8.3). */}
      <Panel>
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-lg font-semibold">
            {repository.owner}/{repository.name}
          </h2>
          <OutcomeBadge outcome={status.outcome} />
        </div>
        <div className="mt-3 flex flex-wrap gap-3 text-sm">
          <Link className="text-primary underline" to={ROUTES.analysisReport(analysisId)}>
            View report
          </Link>
          <Link
            className="text-primary underline"
            to={`${ROUTES.history}?repository=${encodeURIComponent(analysis.repository_id)}`}
          >
            Analysis history
          </Link>
        </div>
        <dl className="mt-4 grid gap-2 text-sm sm:grid-cols-2">
          <div>
            <dt className="text-text-secondary">Analysis ID</dt>
            <dd className="break-identifier font-mono text-xs">{analysis.analysis_id}</dd>
          </div>
          <div>
            <dt className="text-text-secondary">Analyzed at</dt>
            <dd>{analysis.timestamp ?? "—"}</dd>
          </div>
          <div>
            <dt className="text-text-secondary">Completed at</dt>
            <dd>{status.completed_at ?? "—"}</dd>
          </div>
          <div>
            <dt className="text-text-secondary">Branch</dt>
            <dd className="break-identifier font-mono text-xs">
              {branch ? `${branch.name}${branch.origin === "Defaulted" ? " (default)" : ""}` : "—"}
            </dd>
          </div>
          <div>
            <dt className="text-text-secondary">Commit</dt>
            <dd className="break-identifier font-mono text-xs" title={commit?.sha ?? undefined}>
              {commit
                ? `${commit.sha.slice(0, 7)}${commit.origin === "Defaulted" ? " (default)" : ""}`
                : "—"}
            </dd>
          </div>
          <div>
            <dt className="text-text-secondary">Advisory data</dt>
            <dd data-testid="overview-advisory">
              {advisory
                ? `${advisory.source}${advisory.consulted_at ? ` · consulted ${advisory.consulted_at}` : ""} · ${advisory.outcome}`
                : "Not consulted"}
            </dd>
          </div>
        </dl>
        {status.explanation ? (
          <p className="mt-4 text-sm text-text-secondary">{status.explanation}</p>
        ) : null}
        {advisoryGap ? (
          <div className="mt-4">
            <Alert tone="warning" title="Advisory data was incomplete.">
              <p>
                The absence of advisory associations must not be read as the absence of
                vulnerabilities.
              </p>
            </Alert>
          </div>
        ) : null}
        {status.limitations.length > 0 ? (
          <div className="mt-6">
            <h3 className="text-sm font-semibold">Limitations</h3>
            <div className="mt-2 space-y-3">
              {limitations.map(([kind, items]) => (
                <div key={kind}>
                  <p className="text-xs font-medium uppercase tracking-wide text-text-secondary">
                    {kind}
                  </p>
                  <ul className="mt-1 space-y-2 text-sm">
                    {(items.length > LIMITATIONS_VISIBLE
                      ? items.slice(0, LIMITATIONS_VISIBLE)
                      : items
                    ).map((limitation, index) => (
                      <li
                        key={index}
                        className="rounded-control border border-border px-3 py-2"
                      >
                        <span className="font-mono text-xs text-text-secondary">
                          {[limitation.scope_kind, limitation.area, limitation.rule_id, limitation.path]
                            .filter(Boolean)
                            .join(" · ")}
                        </span>
                        <p className="mt-1">{limitation.reason}</p>
                      </li>
                    ))}
                  </ul>
                  {items.length > LIMITATIONS_VISIBLE ? (
                    <details className="mt-1">
                      <summary className="cursor-pointer text-xs text-text-secondary">
                        Show {items.length - LIMITATIONS_VISIBLE} more limitations
                      </summary>
                      <ul className="mt-2 space-y-2 text-sm">
                        {items.slice(LIMITATIONS_VISIBLE).map((limitation, index) => (
                          <li
                            key={index}
                            className="rounded-control border border-border px-3 py-2"
                          >
                            <span className="font-mono text-xs text-text-secondary">
                              {[limitation.area, limitation.rule_id, limitation.path]
                                .filter(Boolean)
                                .join(" · ")}
                            </span>
                            <p className="mt-1">{limitation.reason}</p>
                          </li>
                        ))}
                      </ul>
                    </details>
                  ) : null}
                </div>
              ))}
            </div>
          </div>
        ) : null}
      </Panel>

      {/* B. Area summary table (docs/14 §8.3). */}
      <Panel title="Areas" labelledBy="overview-areas">
        <table className="w-full text-left text-sm" aria-labelledby="overview-areas">
          <thead>
            <tr className="border-b border-border text-text-secondary">
              <th scope="col" className="py-2 pr-4 font-medium">Area</th>
              <th scope="col" className="py-2 pr-4 font-medium">State</th>
              <th scope="col" className="py-2 pr-4 font-medium">Findings</th>
              <th scope="col" className="py-2 pr-4 font-medium">By severity</th>
              <th scope="col" className="py-2 font-medium">Open</th>
            </tr>
          </thead>
          <tbody>
            {AREA_ORDER.map((area) => {
              const entry = areaSummary(summary, area.key);
              const domain = domains.get(area.domain);
              const state = entry?.state ?? domain?.state ?? null;
              const unavailable = isUnavailableState(state);
              const findings = entry?.findings ?? null;
              return (
                <tr key={area.key} className="border-b border-border last:border-0">
                  <td className="py-2 pr-4 font-medium">{area.label}</td>
                  <td className="py-2 pr-4 text-text-secondary">
                    {state ? (
                      <span title={state === "No findings detected" ? NO_FINDINGS_QUALIFIER : undefined}>
                        {`${state}${domain?.reason ? ` — ${domain.reason}` : ""}`}
                      </span>
                    ) : (
                      "—"
                    )}
                  </td>
                  <td className="py-2 pr-4 font-mono">
                    {unavailable || findings == null ? "—" : String(findings.total)}
                  </td>
                  <td className="py-2 pr-4">
                    {unavailable || findings == null ? (
                      <span className="text-text-secondary">—</span>
                    ) : (
                      <SeverityCounts counts={findings.by_severity ?? {}} />
                    )}
                  </td>
                  <td className="py-2">
                    <Link className="text-primary underline" to={area.to(analysisId)}>
                      Open
                    </Link>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        <p className="mt-3 text-xs text-text-secondary">
          “—” marks an unavailable area: no data, not zero findings.
        </p>
        {hasNoFindingsState ? (
          <p className="mt-1 text-xs text-text-secondary">{NO_FINDINGS_QUALIFIER}</p>
        ) : null}
      </Panel>

      {/* C. Severity and confidence summary (docs/14 §8.3). */}
      <Panel title="Findings by severity and confidence" labelledBy="overview-severity">
        {unavailableAreas.length > 0 ? (
          <p className="mb-3 text-xs text-text-secondary">Available areas only.</p>
        ) : null}
        <div className="grid gap-6 sm:grid-cols-2">
          <div>
            <h3 className="mb-2 text-sm font-medium">By severity</h3>
            <ul className="space-y-1 text-sm">
              {SEVERITY_ORDER.map((severity) => (
                <li key={severity} className="flex items-center gap-2">
                  <SeverityBadge severity={severity} />
                  <span className="font-mono">{severityTotals[severity] ?? 0}</span>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h3 className="mb-2 text-sm font-medium">By confidence</h3>
            <ul className="space-y-1 text-sm">
              {CONFIDENCE_ORDER.map((confidence) => (
                <li key={confidence} className="flex items-center gap-2">
                  <ConfidenceBadge confidence={confidence} />
                  <span className="font-mono">{confidenceTotals[confidence] ?? 0}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </Panel>

      {/* D. Findings preview (docs/14 §8.3). */}
      <Panel title="Findings preview" labelledBy="overview-findings-preview">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <p className="text-sm text-text-secondary">Sorted by severity.</p>
          <Link className="text-primary underline text-sm" to={ROUTES.analysisFindings(analysisId)}>
            View all findings
          </Link>
        </div>
        {preview.isLoading ? <LoadingState label="Loading findings…" /> : null}
        {preview.error && !preview.data ? (
          <Alert tone="warning" title="Could not load the findings preview.">
            <p>
              {preview.error instanceof ApiRequestError
                ? preview.error.message
                : "An unexpected error occurred."}
            </p>
          </Alert>
        ) : null}
        {preview.data ? (
          preview.data.items.length === 0 ? (
            <EmptyState title="No findings were recorded.">
              <p>This is a result of static analysis and does not indicate a clean repository.</p>
            </EmptyState>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[640px] text-left text-sm" aria-label="Findings preview">
                <thead>
                  <tr className="border-b border-border text-text-secondary">
                    <th scope="col" className="py-2 pr-4 font-medium">Severity</th>
                    <th scope="col" className="py-2 pr-4 font-medium">Rule</th>
                    <th scope="col" className="py-2 pr-4 font-medium">Category</th>
                    <th scope="col" className="py-2 pr-4 font-medium">Location</th>
                    <th scope="col" className="py-2 pr-4 font-medium">Confidence</th>
                    <th scope="col" className="py-2 font-medium">Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {preview.data.items.slice(0, 10).map((finding) => {
                    const location = finding.subject.locations[0];
                    return (
                      <tr key={finding.finding_id} className="border-b border-border last:border-0">
                        <td className="py-2 pr-4">
                          <SeverityBadge severity={finding.severity} />
                        </td>
                        <td className="py-2 pr-4">
                          <span className="block font-mono text-xs">{finding.rule_id}</span>
                          <span className="block text-xs text-text-secondary">
                            {finding.rule_name}
                          </span>
                        </td>
                        <td className="py-2 pr-4">
                          <CategoryBadge category={finding.category} />
                        </td>
                        <td className="break-identifier py-2 pr-4 font-mono text-xs">
                          {location ? (
                            <>
                              {location.path}
                              <span className="block text-text-secondary">
                                {formatLineRange(location.start_line, location.end_line) ??
                                  "whole file"}
                              </span>
                            </>
                          ) : (
                            "—"
                          )}
                        </td>
                        <td className="py-2 pr-4">
                          <ConfidenceBadge confidence={finding.confidence} />
                        </td>
                        <td className="py-2">
                          <Link
                            className="text-primary underline"
                            to={ROUTES.analysisFindingDetail(analysisId, finding.finding_id)}
                          >
                            Open
                          </Link>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )
        ) : null}
      </Panel>

      {/* E. Repository context (docs/14 §8.3). */}
      <Panel title="Repository context" labelledBy="overview-context">
        <div className="grid gap-6 sm:grid-cols-2">
          <div>
            <h3 className="mb-2 text-sm font-medium">Languages</h3>
            {summary?.languages && summary.languages.length > 0 ? (
              <ul className="space-y-1 text-sm">
                {summary.languages.map((entry) => (
                  <li key={`${entry.language}:${entry.support}`} className="flex justify-between gap-4">
                    <span>
                      {entry.language} <span className="text-text-secondary">· {entry.support}</span>
                    </span>
                    <span className="font-mono">{entry.file_count}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-text-secondary">—</p>
            )}
          </div>
          <div>
            <h3 className="mb-2 text-sm font-medium">Files</h3>
            <ul className="space-y-1 text-sm">
              <li className="flex justify-between gap-4">
                <span>Indexed</span>
                <span className="font-mono">{summary?.files?.indexed ?? "—"}</span>
              </li>
              {(["Parsed", "Parsed with diagnostics", "Failed", "Not parsed"] as const).map((key) => (
                <li key={key} className="flex justify-between gap-4">
                  <span className="text-text-secondary">{key}</span>
                  <span className="font-mono">{parseResults[key] ?? 0}</span>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h3 className="mb-2 text-sm font-medium">Architecture</h3>
            <ul className="space-y-1 text-sm">
              <li className="flex justify-between gap-4">
                <span>Modules</span>
                <span className="font-mono">{architecture?.module_count ?? "—"}</span>
              </li>
              <li className="flex justify-between gap-4">
                <span>Module dependencies</span>
                <span className="font-mono">{architecture?.module_dependency_count ?? "—"}</span>
              </li>
              <li className="flex justify-between gap-4">
                <span>Circular dependency groups</span>
                <span className="font-mono">{architecture?.cycle_count?.value ?? "—"}</span>
              </li>
            </ul>
          </div>
          <div>
            <h3 className="mb-2 text-sm font-medium">Dependencies</h3>
            <ul className="space-y-1 text-sm">
              <li className="flex justify-between gap-4">
                <span>Total</span>
                <span className="font-mono">{dependencies?.dependency_count?.total ?? "—"}</span>
              </li>
              <li className="flex justify-between gap-4">
                <span>Direct</span>
                <span className="font-mono">{dependencies?.dependency_count?.direct ?? "—"}</span>
              </li>
              <li className="flex justify-between gap-4">
                <span>Transitive</span>
                <span className="font-mono">{dependencies?.dependency_count?.transitive ?? "—"}</span>
              </li>
              <li className="flex justify-between gap-4">
                <span>With known vulnerabilities</span>
                <span className="font-mono">{dependencies?.vulnerable_count ?? "—"}</span>
              </li>
              <li className="flex justify-between gap-4">
                <span>Packages with more than one version</span>
                <span className="font-mono">
                  {dependencies?.duplicate_version_package_count ?? "—"}
                </span>
              </li>
            </ul>
          </div>
        </div>
      </Panel>
    </div>
  );
}

function areaState(summary: OverviewSummary | null, key: string): string | null {
  return areaSummary(summary, key)?.state ?? null;
}
