import { useEffect, useRef } from "react";
import { Link } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { ApiRequestError, getAnalysis } from "../../lib/api";
import { ROUTES } from "../../router/routes";
import {
  ANALYSIS_STAGES,
  isTerminalOutcome,
  type AnalysisDetail,
} from "../../schemas/analysis";
import { Alert, EmptyState, LoadingState, Panel, StatusBadge } from "../../components/ui";

// Analysis progress (docs/14-ui-requirements.md, Section 7.4; docs/17 §4.2).
// Truthful by construction: the stage list comes from the contract, the
// current stage comes from the server, and there is no percentage, no
// estimate, and no simulated motion. Polling is bounded and stops on unmount,
// on terminal states, and after POLL_BUDGET_MS with a manual Refresh.

const POLL_INTERVAL_MS = 3000;
const POLL_BUDGET_MS = 10 * 60 * 1000;

const STAGE_LABELS: Record<string, string> = {
  Queued: "Queued",
  ValidatingRepository: "Validating repository",
  ResolvingCommit: "Resolving commit",
  RetrievingRepository: "Retrieving repository",
  IndexingFiles: "Indexing files",
  DetectingLanguages: "Detecting languages",
  ParsingSource: "Parsing source",
  BuildingCodeModel: "Building code model",
  RunningAnalysis: "Running analysis",
  AggregatingResults: "Aggregating results",
  GeneratingReports: "Generating reports",
};

function stageLabel(stage: string): string {
  return STAGE_LABELS[stage] ?? stage;
}

function shortSha(sha: string): string {
  return sha.length > 7 ? sha.slice(0, 7) : sha;
}

export function useAnalysisStatus(analysisId: string, enabled: boolean) {
  const startedAtRef = useRef<number>(0);
  if (startedAtRef.current === 0) {
    startedAtRef.current = Date.now();
  }
  return useQuery({
    queryKey: ["analysis", analysisId],
    queryFn: () => getAnalysis(analysisId),
    enabled,
    // Bounded polling: only while non-terminal and within budget.
    // TanStack Query never overlaps an in-flight refetch. Polling pauses
    // on errors until the user retries, so a failure is never masked by
    // the next tick.
    refetchInterval: (query) => {
      if (query.state.error) {
        return false;
      }
      const data = query.state.data as AnalysisDetail | undefined;
      if (data?.status.outcome != null) {
        return false;
      }
      if (Date.now() - startedAtRef.current > POLL_BUDGET_MS) {
        return false;
      }
      return POLL_INTERVAL_MS;
    },
    refetchIntervalInBackground: false,
    // Transient errors retry with backoff; a missing analysis never will.
    retry: (count, error) => {
      if (error instanceof ApiRequestError && error.code === "ANALYSIS_NOT_FOUND") {
        return false;
      }
      return count < 2;
    },
  });
}

function RepositoryLine({ detail }: { detail: AnalysisDetail }) {
  const { repository } = detail;
  const branch = repository.analyzed_state.branch;
  const commit = repository.analyzed_state.commit;
  return (
    <p className="break-identifier font-mono text-sm text-text-secondary">
      {repository.owner}/{repository.name}
      {branch ? (
        <span>
          {"  ·  branch "}
          {branch.name}
          {branch.origin === "Defaulted" ? " (default)" : ""}
        </span>
      ) : null}
      {commit ? (
        <span title={commit.sha}>
          {"  ·  commit "}
          {shortSha(commit.sha)}
          {commit.origin === "Defaulted" ? " (default)" : ""}
        </span>
      ) : null}
    </p>
  );
}

function StageList({ currentStage }: { currentStage: string }) {
  const currentIndex = ANALYSIS_STAGES.indexOf(
    currentStage as (typeof ANALYSIS_STAGES)[number],
  );
  return (
    <ol className="mt-4 space-y-2">
      {ANALYSIS_STAGES.map((stage, index) => {
        const done = currentIndex >= 0 && index < currentIndex;
        const current = stage === currentStage;
        return (
          <li key={stage} className="flex items-center gap-3 text-sm">
            <span
              aria-hidden="true"
              className={
                done
                  ? "text-primary"
                  : current
                    ? "text-text-primary"
                    : "text-text-secondary"
              }
            >
              {done ? "✓" : current ? "●" : "○"}
            </span>
            <span className={current ? "font-medium text-text-primary" : "text-text-secondary"}>
              {stageLabel(stage)}
              {current ? (
                <span className="sr-only"> (current stage)</span>
              ) : null}
            </span>
          </li>
        );
      })}
    </ol>
  );
}

export function AnalysisProgress({ analysisId }: { analysisId: string }) {
  const { data, error, isLoading, isFetching, refetch } = useAnalysisStatus(analysisId, true);

  useEffect(() => {
    if (data?.status.outcome != null) {
      document.title = `Analysis ${data.status.outcome} · RepoLens`;
    }
  }, [data?.status.outcome]);

  if (isLoading) {
    return <LoadingState label="Loading analysis status…" />;
  }

  if (error) {
    const apiError = error instanceof ApiRequestError ? error : null;
    if (apiError?.code === "ANALYSIS_NOT_FOUND") {
      return (
        <Panel>
          <Alert tone="error" title="Analysis not found.">
            <p>
              No analysis with this identifier exists. It may have been removed, or the
              link may be wrong.
            </p>
          </Alert>
        </Panel>
      );
    }
    return (
      <Panel>
        <Alert tone="error" title="Could not load the analysis status.">
          <p>{apiError?.message ?? "An unexpected error occurred. Try again."}</p>
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

  if (!data) {
    return (
      <Panel>
        <EmptyState title="No analysis data.">
          <p>The backend returned an empty response. Try refreshing.</p>
        </EmptyState>
      </Panel>
    );
  }

  const { status } = data;
  const outcome = status.outcome;

  if (outcome === "Failed") {
    return (
      <Panel>
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-lg font-semibold">Analysis failed</h2>
          <StatusBadge label="Failed" tone="error" marker="✕" />
        </div>
        <div className="mt-4">
          <RepositoryLine detail={data} />
        </div>
        <div className="mt-4">
          <Alert tone="error" title="The analysis did not produce usable results.">
            {status.explanation ? <p>{status.explanation}</p> : null}
          </Alert>
        </div>
        <p className="mt-4 text-sm text-text-secondary">
          You can submit the repository again from{" "}
          <Link className="text-primary underline" to={ROUTES.analysisNew}>
            New Analysis
          </Link>
          .
        </p>
      </Panel>
    );
  }

  if (outcome != null && isTerminalOutcome(outcome)) {
    const target = ROUTES.analysisOverview(analysisId);
    return (
      <Panel>
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-lg font-semibold">
            {outcome === "Completed with limitations"
              ? "Analysis completed with limitations"
              : "Analysis completed"}
          </h2>
          <StatusBadge
            label={outcome}
            tone={outcome === "Completed with limitations" ? "warning" : "neutral"}
            marker={outcome === "Completed with limitations" ? "▲" : "–"}
          />
        </div>
        <div className="mt-4">
          <RepositoryLine detail={data} />
        </div>
        {status.explanation ? (
          <p className="mt-4 text-sm text-text-secondary">{status.explanation}</p>
        ) : null}
        <Link
          to={target}
          className="mt-6 inline-block rounded-control bg-primary px-4 py-2 text-sm font-semibold text-background hover:brightness-110"
        >
          Open analysis
        </Link>
      </Panel>
    );
  }

  // Non-terminal: honest waiting state. The backend may not advance beyond
  // Queued until the orchestrator exists; nothing here implies otherwise.
  const stage = status.stage ?? "Queued";
  return (
    <Panel>
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-lg font-semibold">Analysis in progress</h2>
        <StatusBadge label={stageLabel(stage)} tone="info" marker="●" />
      </div>
      <div className="mt-4">
        <RepositoryLine detail={data} />
      </div>
      <p className="mt-4 text-sm text-text-secondary" aria-live="polite">
        {stage === "Queued"
          ? "The request has been accepted and is awaiting processing. Results will appear once the backend completes the analysis."
          : `The backend reports stage ${stageLabel(stage)}. Results will appear once the analysis completes.`}
      </p>
      <StageList currentStage={stage} />
      <button
        type="button"
        onClick={() => void refetch()}
        disabled={isFetching}
        className="mt-6 rounded-control border border-border px-4 py-2 text-sm font-medium text-text-primary hover:border-primary disabled:opacity-50"
      >
        {isFetching ? "Refreshing…" : "Refresh now"}
      </button>
    </Panel>
  );
}
