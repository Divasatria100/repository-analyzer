import { Link, useLocation, useParams } from "react-router";
import { ANALYSIS_ID_PARAM, FINDING_ID_PARAM, ROUTES } from "../../router/routes";
import { useAnalysisResult } from "../analysis/useAnalysisResult";
import type { Finding } from "../../schemas/results";
import { Alert, EmptyState, LoadingState, Panel } from "../../components/ui";
import { ApiRequestError } from "../../lib/api";
import { CategoryBadge, ConfidenceBadge, SeverityBadge, areaLabel, formatLineRange } from "./FindingBits";
import { SourceContext } from "./SourceContext";

// Finding Detail (TASK-192). No GET /findings/{id} endpoint exists, so the
// detail resolves the stable finding_id against the persisted canonical
// result (shared query cache — no extra request when coming from a page that
// already loaded it). Unknown IDs render as unknown, never as empty data.

const SECTION_ORDER = ["security", "architecture", "dependencies", "code_structure"] as const;

function resolveFinding(
  data: { [key: string]: unknown },
  findingId: string,
): { finding: Finding; section: string } | null {
  for (const section of SECTION_ORDER) {
    const block = data[section];
    if (block != null && typeof block === "object") {
      const findings = (block as { findings?: unknown }).findings;
      if (Array.isArray(findings)) {
        const match = (findings as Finding[]).find((item) => item.finding_id === findingId);
        if (match) {
          return { finding: match, section };
        }
      }
    }
  }
  return null;
}

export function FindingDetailPage() {
  const params = useParams();
  const location = useLocation();
  const analysisId = params[ANALYSIS_ID_PARAM] ?? "";
  const findingId = params[FINDING_ID_PARAM] ?? "";
  const fromSearch =
    typeof (location.state as { fromSearch?: unknown } | null)?.fromSearch === "string"
      ? (location.state as { fromSearch: string }).fromSearch
      : "";
  const backTarget = `${ROUTES.analysisFindings(analysisId)}${fromSearch ? `?${fromSearch}` : ""}`;

  const { data, error, isLoading, refetch, isFetching } = useAnalysisResult(analysisId);

  if (isLoading) {
    return <LoadingState label="Loading finding…" />;
  }

  if (error || !data) {
    const apiError = error instanceof ApiRequestError ? error : null;
    return (
      <Panel>
        <Alert tone="error" title={apiError?.code === "ANALYSIS_NOT_FOUND" ? "Analysis not found." : "Could not load the finding."}>
          <p>{apiError?.message ?? "An unexpected error occurred."}</p>
        </Alert>
        <div className="mt-4 flex gap-3">
          <button
            type="button"
            onClick={() => void refetch()}
            disabled={isFetching}
            className="rounded-control border border-border px-4 py-2 text-sm font-medium hover:border-primary disabled:opacity-50"
          >
            {isFetching ? "Retrying…" : "Retry"}
          </button>
          <Link
            to={backTarget}
            className="rounded-control border border-border px-4 py-2 text-sm font-medium hover:border-primary"
          >
            Back to findings
          </Link>
        </div>
      </Panel>
    );
  }

  if (data.status.outcome == null) {
    return (
      <Panel>
        <EmptyState title="Finding detail is unavailable while the analysis is not completed.">
          <p>
            <Link className="text-primary underline" to={ROUTES.analysisDetail(analysisId)}>
              View progress
            </Link>
          </p>
        </EmptyState>
      </Panel>
    );
  }

  const { status } = data;
  const { outcome } = status;

  if (outcome === "Failed") {
    return (
      <Panel>
        <Alert tone="error" title="Finding detail is unavailable: the analysis failed.">
          <p>{status.explanation ?? "The analysis did not produce usable results."}</p>
        </Alert>
        <div className="mt-4 flex gap-3">
          <Link
            to={ROUTES.analysisDetail(analysisId)}
            className="rounded-control border border-border px-4 py-2 text-sm font-medium hover:border-primary"
          >
            View progress
          </Link>
          <Link
            to={backTarget}
            className="rounded-control border border-border px-4 py-2 text-sm font-medium hover:border-primary"
          >
            Back to findings
          </Link>
        </div>
      </Panel>
    );
  }

  const resolved = resolveFinding(data as unknown as Record<string, unknown>, findingId);
  if (!resolved) {
    return (
      <Panel>
        <Alert tone="error" title="Finding not found.">
          <p>
            No finding with ID <span className="break-identifier font-mono text-xs">{findingId}</span>{" "}
            exists in this analysis.
          </p>
        </Alert>
        <Link
          to={backTarget}
          className="mt-4 inline-block rounded-control border border-border px-4 py-2 text-sm font-medium hover:border-primary"
        >
          Back to findings
        </Link>
      </Panel>
    );
  }

  const { finding, section } = resolved;
  const location0 = finding.subject.locations[0] ?? null;
  const otherLocations = finding.subject.locations.slice(1);
  const evidence = finding.evidence ?? null;
  const extra = finding as Record<string, unknown>;

  return (
    <div className="space-y-4">
      <Link to={backTarget} className="text-sm text-primary underline">
        ← Back to findings
      </Link>
      <Panel>
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="break-identifier font-mono text-base font-semibold">{finding.rule_id}</h2>
          <SeverityBadge severity={finding.severity} />
          <ConfidenceBadge confidence={finding.confidence} />
          <CategoryBadge category={finding.category} />
        </div>
        <p className="mt-1 text-sm text-text-secondary">
          {finding.rule_name} · in {areaLabel(section)} · ID{" "}
          <span className="break-identifier font-mono text-xs">{finding.finding_id}</span>
        </p>
        <dl className="mt-4 space-y-3 text-sm">
          <div>
            <dt className="text-text-secondary">Location</dt>
            <dd className="break-identifier font-mono text-xs">
              {location0 ? (
                <>
                  {location0.path}{" "}
                  <span className="text-text-secondary">
                    {formatLineRange(location0.start_line, location0.end_line) ?? ""}
                  </span>
                </>
              ) : (
                "—"
              )}
            </dd>
            {otherLocations.length > 0 ? (
              <dd className="mt-1">
                <ul className="space-y-1">
                  {otherLocations.map((item, index) => (
                    <li key={index} className="break-identifier font-mono text-xs">
                      {item.path}{" "}
                      <span className="text-text-secondary">
                        {formatLineRange(item.start_line, item.end_line) ?? ""}
                      </span>
                    </li>
                  ))}
                </ul>
              </dd>
            ) : null}
          </div>
          <div>
            <dt className="text-text-secondary">Explanation</dt>
            <dd>{finding.explanation}</dd>
          </div>
          {finding.impact != null ? (
            <div>
              <dt className="text-text-secondary">Potential impact</dt>
              <dd>{finding.impact}</dd>
            </div>
          ) : null}
          <div>
            <dt className="text-text-secondary">Recommendation</dt>
            <dd>{finding.recommendation}</dd>
          </div>
          {finding.subject.modules.length > 0 ? (
            <div>
              <dt className="text-text-secondary">Associated modules</dt>
              <dd className="font-mono text-xs">{finding.subject.modules.join(", ")}</dd>
            </div>
          ) : null}
          {Array.isArray(extra["applied_thresholds"]) &&
          (extra["applied_thresholds"] as unknown[]).length > 0 ? (
            <div>
              <dt className="text-text-secondary">Applied thresholds</dt>
              <dd className="font-mono text-xs">
                {(extra["applied_thresholds"] as Array<{ threshold: string; value: unknown }>).map(
                  (entry) => `${entry.threshold}: ${String(entry.value)}`,
                ).join(" · ")}
              </dd>
            </div>
          ) : null}
          {extra["partial_information"] === true ? (
            <div>
              <Alert tone="warning" title="Based on partial information.">
                <p>This finding rests on incomplete structural information.</p>
              </Alert>
            </div>
          ) : null}
        </dl>
      </Panel>
      <Panel title="Evidence" labelledBy="finding-evidence">
        <SourceContext evidence={evidence} path={location0?.path ?? null} />
      </Panel>
    </div>
  );
}
