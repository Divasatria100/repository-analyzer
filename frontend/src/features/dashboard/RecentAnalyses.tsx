import type { ReactNode } from "react";
import { Link } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { ApiRequestError, getRepositoryHistory } from "../../lib/api";
import { ROUTES } from "../../router/routes";
import type { AnalysisResult, HistoryEntry } from "../../schemas/results";
import { Alert, EmptyState, LoadingState, Panel, StatusBadge } from "../../components/ui";
import { useAnalysisResult } from "../analysis/useAnalysisResult";

// Dashboard Recent Analyses (docs/14 §6.2, TASK-208/209). Shows the five
// most recent analyses of one repository (the API lists history per
// repository only — the scope is always labeled). The Findings cell sums
// `findings.total` over available areas from each persisted result and shows
// "—" for failed/non-terminal analyses; a `*` marks partial coverage with
// an accessible explanation. No cross-analysis totals, no scores.

const RECENT_LIMIT = 5;

function outcomeBadge(outcome: string | null) {
  if (outcome === "Failed") {
    return <StatusBadge label="Failed" tone="error" marker="✕" />;
  }
  if (outcome === "Completed with limitations") {
    return <StatusBadge label="Completed with limitations" tone="warning" marker="▲" />;
  }
  if (outcome) {
    return <StatusBadge label={outcome} tone="neutral" marker="–" />;
  }
  return <StatusBadge label="In progress" tone="info" marker="●" />;
}

function shortSha(sha: string): string {
  return sha.length > 7 ? sha.slice(0, 7) : sha;
}

interface FindingsCell {
  text: string;
  partial: boolean;
}

function findingsCell(result: AnalysisResult | undefined): FindingsCell | null {
  if (!result || !result.summary) {
    return null;
  }
  let total = 0;
  let partial = false;
  for (const area of ["security", "architecture", "dependencies", "code_structure"] as const) {
    const block = result.summary[area];
    if (block.findings == null) {
      partial = true;
    } else {
      total += block.findings.total;
    }
  }
  return { text: partial ? `${total} *` : String(total), partial };
}

export function RecentAnalyses({ repositoryId }: { repositoryId: string }) {
  const history = useQuery({
    queryKey: ["history", repositoryId],
    queryFn: ({ signal }) => getRepositoryHistory(repositoryId, signal),
    retry: (count, error) => {
      if (error instanceof ApiRequestError && error.code === "REPOSITORY_NOT_FOUND") {
        return false;
      }
      return count < 1;
    },
  });

  if (history.isLoading) {
    return <LoadingState label="Loading recent analyses…" />;
  }

  if (history.error || !history.data) {
    const apiError = history.error instanceof ApiRequestError ? history.error : null;
    return (
      <Panel title="Recent Analyses" labelledBy="recent-analyses">
        <Alert
          tone="error"
          title={apiError?.code === "REPOSITORY_NOT_FOUND" ? "Repository not found." : "Could not load recent analyses."}
        >
          <p>{apiError?.message ?? "An unexpected error occurred."}</p>
        </Alert>
      </Panel>
    );
  }

  const entries = history.data.analyses;
  const shown = entries.slice(0, RECENT_LIMIT);

  return (
    <Panel title="Recent Analyses" labelledBy="recent-analyses">
      <p className="mb-3 text-sm text-text-secondary">
        Showing {shown.length} of {entries.length} analyses for{" "}
        <span className="break-identifier font-mono text-xs">
          {history.data.owner}/{history.data.name}
        </span>
        .{" "}
        <Link
          className="text-primary underline"
          to={`${ROUTES.history}?repository=${encodeURIComponent(repositoryId)}`}
        >
          View full history
        </Link>
      </p>
      {shown.length === 0 ? (
        <EmptyState title="No analyses recorded for this repository.">
          <p>Analyses you submit will appear here, most recent first.</p>
        </EmptyState>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-left text-sm">
            <thead>
              <tr className="border-b border-border text-text-secondary">
                <th scope="col" className="py-2 pr-4 font-medium">Repository</th>
                <th scope="col" className="py-2 pr-4 font-medium">Branch</th>
                <th scope="col" className="py-2 pr-4 font-medium">Commit</th>
                <th scope="col" className="py-2 pr-4 font-medium">Analyzed</th>
                <th scope="col" className="py-2 pr-4 font-medium">Status</th>
                <th scope="col" className="py-2 font-medium">Findings</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((entry) => (
                <RecentRow key={entry.analysis_id} entry={entry} owner={history.data.owner} name={history.data.name} />
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="mt-3 text-xs text-text-secondary">
        Finding counts cover available areas only; a `*` marks a partial total.
      </p>
    </Panel>
  );
}

function RecentRow({
  entry,
  owner,
  name,
}: {
  entry: HistoryEntry;
  owner: string;
  name: string;
}) {
  // Detail is fetched only when it can add information: completed rows need
  // totals, non-terminal rows need the live stage. Failed rows need nothing.
  const needsDetail = entry.outcome !== "Failed";
  const detail = useAnalysisResult(entry.analysis_id, needsDetail);
  const openTo = entry.outcome
    ? ROUTES.analysisOverview(entry.analysis_id)
    : ROUTES.analysisDetail(entry.analysis_id);

  let status: ReactNode = outcomeBadge(entry.outcome);
  let findings: ReactNode = <span title="No summary for this state">—</span>;
  if (entry.outcome === "Completed" || entry.outcome === "Completed with limitations") {
    const cell = detail.data ? findingsCell(detail.data) : undefined;
    findings =
      cell == null ? (
        <span className="text-text-secondary">…</span>
      ) : (
        <span title={cell.partial ? "Total over available areas only" : undefined}>
          {cell.text}
          {cell.partial ? (
            <span className="sr-only"> (available areas only)</span>
          ) : null}
        </span>
      );
  } else if (entry.outcome == null) {
    const stage = detail.data?.status.stage;
    status = stage ? (
      <StatusBadge label={stage} tone="info" marker="●" />
    ) : (
      outcomeBadge(null)
    );
  }

  return (
    <tr className="border-b border-border last:border-0">
      <td className="py-2 pr-4">
        <Link
          className="break-identifier font-mono text-xs text-primary underline"
          to={openTo}
        >
          {owner}/{name}
        </Link>
      </td>
      <td className="break-identifier py-2 pr-4 font-mono text-xs">
        {entry.branch
          ? `${entry.branch.name}${entry.branch.origin === "Defaulted" ? " (default)" : ""}`
          : "—"}
      </td>
      <td className="py-2 pr-4 font-mono text-xs" title={entry.commit?.sha ?? undefined}>
        {entry.commit
          ? `${shortSha(entry.commit.sha)}${entry.commit.origin === "Defaulted" ? " (default)" : ""}`
          : "—"}
      </td>
      <td className="py-2 pr-4 text-xs">{entry.timestamp ?? "—"}</td>
      <td className="py-2 pr-4">
        {status}
        {entry.outcome === "Failed" && entry.explanation ? (
          <p className="mt-1 text-xs text-text-secondary">{entry.explanation}</p>
        ) : null}
      </td>
      <td className="py-2 font-mono text-xs">{findings}</td>
    </tr>
  );
}
