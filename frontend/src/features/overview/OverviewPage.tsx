import { Link, useParams } from "react-router";
import { ANALYSIS_ID_PARAM, ROUTES } from "../../router/routes";
import { useAnalysisResult } from "../analysis/useAnalysisResult";
import { isUnavailableState } from "../../schemas/results";
import { Alert, EmptyState, LoadingState, Panel, StatusBadge } from "../../components/ui";
import { ApiRequestError } from "../../lib/api";

// Analysis Overview (TASK-189). Renders only contract-backed values from the
// persisted canonical result: identity, lifecycle, per-area states with
// server counts, limitations, and links. A null section renders as
// unavailable with its state — never as zero findings. No score anywhere.

const AREA_ORDER = [
  { key: "security", label: "Security", to: ROUTES.analysisSecurity },
  { key: "architecture", label: "Architecture", to: ROUTES.analysisArchitecture },
  { key: "dependencies", label: "Dependencies", to: ROUTES.analysisFindings },
  { key: "code_structure", label: "Code Structure", to: ROUTES.analysisFindings },
] as const;

function OutcomeBadge({ outcome }: { outcome: string }) {
  if (outcome === "Failed") {
    return <StatusBadge label="Failed" tone="error" marker="✕" />;
  }
  if (outcome === "Completed with limitations") {
    return <StatusBadge label="Completed with limitations" tone="warning" marker="▲" />;
  }
  return <StatusBadge label={outcome} tone="neutral" marker="–" />;
}

export function OverviewPage() {
  const params = useParams();
  const analysisId = params[ANALYSIS_ID_PARAM] ?? "";
  const { data, error, isLoading, refetch, isFetching } = useAnalysisResult(analysisId);

  if (isLoading) {
    return <LoadingState label="Loading analysis overview…" />;
  }

  if (error || !data) {
    const apiError = error instanceof ApiRequestError ? error : null;
    return (
      <Panel>
        <Alert tone="error" title={apiError?.code === "ANALYSIS_NOT_FOUND" ? "Analysis not found." : "Could not load the overview."}>
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

  const { status, summary, repository, analysis } = data;
  const outcome = status.outcome;

  // Non-terminal and failed analyses have null sections by contract: never
  // render a completion summary for them.
  if (outcome == null) {
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

  if (outcome === "Failed") {
    return (
      <Panel>
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-lg font-semibold">Analysis failed</h2>
          <OutcomeBadge outcome={outcome} />
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

  return (
    <div className="space-y-6">
      <Panel>
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-lg font-semibold">
            {repository.owner}/{repository.name}
          </h2>
          <OutcomeBadge outcome={outcome} />
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
        </dl>
        {status.explanation ? (
          <p className="mt-4 text-sm text-text-secondary">{status.explanation}</p>
        ) : null}
      </Panel>

      <Panel title="Areas" labelledBy="overview-areas">
        <table className="w-full text-left text-sm" aria-labelledby="overview-areas">
          <thead>
            <tr className="border-b border-border text-text-secondary">
              <th scope="col" className="py-2 pr-4 font-medium">Area</th>
              <th scope="col" className="py-2 pr-4 font-medium">State</th>
              <th scope="col" className="py-2 pr-4 font-medium">Findings</th>
              <th scope="col" className="py-2 font-medium">Open</th>
            </tr>
          </thead>
          <tbody>
            {AREA_ORDER.map((area) => {
              const summaryEntry = summary?.[area.key] as
                | { state: string | null; findings: { total: number } | null }
                | undefined;
              const domain = domains.get(
                area.key === "dependencies" ? "dependency" : area.key,
              );
              const state = summaryEntry?.state ?? domain?.state ?? null;
              const unavailable = isUnavailableState(state);
              const findings = summaryEntry?.findings ?? null;
              return (
                <tr key={area.key} className="border-b border-border last:border-0">
                  <td className="py-2 pr-4 font-medium">{area.label}</td>
                  <td className="py-2 pr-4 text-text-secondary">
                    {`${state ?? "—"}${domain?.reason ? ` — ${domain.reason}` : ""}`}
                  </td>
                  <td className="py-2 pr-4 font-mono">
                    {unavailable || findings == null ? "—" : String(findings.total)}
                  </td>
                  <td className="py-2">
                    <Link
                      className="text-primary underline"
                      to={area.to(analysisId)}
                    >
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
      </Panel>

      <Panel title="Limitations" labelledBy="overview-limitations">
        {status.limitations.length === 0 ? (
          <EmptyState title="No limitations recorded." />
        ) : (
          <ul className="space-y-2 text-sm">
            {status.limitations.map((limitation, index) => (
              <li key={index} className="rounded-control border border-border px-3 py-2">
                <span className="font-mono text-xs text-text-secondary">
                  {[
                    limitation.scope_kind,
                    limitation.area,
                    limitation.rule_id,
                    limitation.path,
                  ]
                    .filter(Boolean)
                    .join(" · ")}
                </span>
                <p className="mt-1">{limitation.reason}</p>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}
