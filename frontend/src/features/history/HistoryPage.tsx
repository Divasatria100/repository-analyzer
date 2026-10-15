import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { ApiRequestError, getRepositoryHistory } from "../../lib/api";
import { ROUTES } from "../../router/routes";
import type { HistoryEntry } from "../../schemas/results";
import { Alert, EmptyState, LoadingState, Panel, StatusBadge } from "../../components/ui";

// Analysis History (TASK-204, docs/14 §16, docs/17 §4.5). The contract
// exposes history per repository only — there is no global analysis list.
// The page therefore takes `?repository=<repository_id>` (deep-linkable,
// e.g. from an analysis Overview) plus a repository-ID field. Entries render
// as stored: same-commit analyses coexist, history entries carry no finding
// totals so the Findings column shows "—", never 0. Row checkboxes feed the
// comparison flow (TASK-205) with contract-based guards.

function outcomeBadge(outcome: string | null): React.ReactNode {
  if (outcome === "Failed") {
    return <StatusBadge label="Failed" tone="error" marker="✕" />;
  }
  if (outcome === "Completed with limitations") {
    return <StatusBadge label="Completed with limitations" tone="warning" marker="▲" />;
  }
  return <StatusBadge label={outcome ?? "In progress"} tone={outcome ? "neutral" : "info"} marker={outcome ? "–" : "●"} />;
}

function shortSha(sha: string): string {
  return sha.length > 7 ? sha.slice(0, 7) : sha;
}

export function HistoryPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const repositoryId = searchParams.get("repository") ?? "";
  const [draftRepo, setDraftRepo] = useState(repositoryId);
  const [selected, setSelected] = useState<string[]>([]);
  const [listSearch, setListSearch] = useState("");

  const { data, error, isLoading, refetch, isFetching } = useQuery({
    queryKey: ["history", repositoryId],
    queryFn: ({ signal }) => getRepositoryHistory(repositoryId, signal),
    enabled: repositoryId !== "",
    retry: (count, queryError) => {
      if (queryError instanceof ApiRequestError && queryError.code === "REPOSITORY_NOT_FOUND") {
        return false;
      }
      return count < 1;
    },
  });

  const visible = useMemo(() => {
    const needle = listSearch.trim().toLowerCase();
    const entries = data?.analyses ?? [];
    if (!needle) {
      return entries;
    }
    return entries.filter((entry) =>
      [entry.analysis_id, entry.branch?.name ?? "", entry.commit?.sha ?? "", entry.outcome ?? ""]
        .join(" ")
        .toLowerCase()
        .includes(needle),
    );
  }, [data, listSearch]);

  function loadRepository() {
    const id = draftRepo.trim();
    setSelected([]);
    setSearchParams(id ? { repository: id } : {});
  }

  if (!repositoryId) {
    return (
      <Panel>
        <h2 className="text-lg font-semibold">History</h2>
        <p className="mt-2 text-sm text-text-secondary">
          Analysis history is listed per repository. Enter a repository ID to load its
          analyses — you can copy it from any analysis Overview — or open history from
          an analysis workspace.
        </p>
        <form
          className="mt-4 flex max-w-xl flex-col gap-2 sm:flex-row"
          onSubmit={(event) => {
            event.preventDefault();
            loadRepository();
          }}
        >
          <label htmlFor="history-repo" className="sr-only">
            Repository ID
          </label>
          <input
            id="history-repo"
            type="text"
            value={draftRepo}
            onChange={(event) => setDraftRepo(event.target.value)}
            placeholder="repository ID"
            autoComplete="off"
            spellCheck={false}
            className="break-identifier min-w-0 flex-1 rounded-control border border-border bg-secondary px-3 py-2 font-mono text-sm placeholder:text-text-secondary"
          />
          <button
            type="submit"
            className="rounded-control bg-primary px-4 py-2 text-sm font-semibold text-background hover:brightness-110"
          >
            Load history
          </button>
        </form>
        <p className="mt-3 text-xs text-text-secondary">
          Note: the API exposes history per repository; there is no cross-repository
          analysis list or repository directory endpoint.
        </p>
      </Panel>
    );
  }

  if (isLoading) {
    return <LoadingState label="Loading analysis history…" />;
  }

  if (error || !data) {
    const apiError = error instanceof ApiRequestError ? error : null;
    return (
      <Panel>
        <h2 className="text-lg font-semibold">History</h2>
        <div className="mt-3">
          <Alert
            tone="error"
            title={apiError?.code === "REPOSITORY_NOT_FOUND" ? "Repository not found." : "Could not load history."}
          >
            <p>{apiError?.message ?? "An unexpected error occurred."}</p>
          </Alert>
        </div>
        <button
          type="button"
          onClick={() => void refetch()}
          disabled={isFetching}
          className="mt-4 rounded-control border border-border px-4 py-2 text-sm font-medium hover:border-primary disabled:opacity-50"
        >
          {isFetching ? "Retrying…" : "Retry"}
        </button>
      </Panel>
    );
  }

  const selectedEntries = selected
    .map((id) => data.analyses.find((entry) => entry.analysis_id === id))
    .filter((entry): entry is HistoryEntry => entry != null);
  const compareBlocker = compareBlockerReason(selectedEntries);
  const orderedForCompare =
    compareBlocker == null ? orderBaseTarget(selectedEntries) : null;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-lg font-semibold">History</h2>
        <span className="break-identifier font-mono text-sm text-text-secondary">
          {data.owner}/{data.name}
        </span>
      </div>

      <Panel>
        <div className="flex flex-col gap-3 md:flex-row md:items-end">
          <div className="min-w-0 flex-1">
            <label htmlFor="history-search" className="mb-1 block text-sm font-medium">
              Search this history
            </label>
            <input
              id="history-search"
              type="search"
              value={listSearch}
              onChange={(event) => setListSearch(event.target.value)}
              placeholder="analysis ID, branch, commit, outcome"
              autoComplete="off"
              spellCheck={false}
              className="w-full rounded-control border border-border bg-secondary px-3 py-2 font-mono text-sm placeholder:text-text-secondary"
            />
          </div>
          <p className="text-xs text-text-secondary">Most recent first. Same-commit analyses are separate rows.</p>
        </div>
      </Panel>

      {compareBlocker ? (
        <p className="text-sm text-text-secondary" role="note">
          Select two completed, non-failed analyses to compare. {compareBlocker}
        </p>
      ) : (
        orderedForCompare && (
          <Link
            to={`${ROUTES.analysisComparison(orderedForCompare.target.analysis_id)}?base=${encodeURIComponent(orderedForCompare.base.analysis_id)}`}
            className="inline-block rounded-control bg-primary px-4 py-2 text-sm font-semibold text-background hover:brightness-110"
          >
            Compare selected
          </Link>
        )
      )}

      {visible.length === 0 ? (
        <Panel>
          {data.analyses.length === 0 ? (
            <EmptyState title="No analyses recorded for this repository." />
          ) : (
            <EmptyState title="No analyses match this search.">
              <p>Clear the search to see the full history.</p>
            </EmptyState>
          )}
        </Panel>
      ) : (
        <Panel>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[840px] text-left text-sm">
              <thead>
                <tr className="border-b border-border text-text-secondary">
                  <th scope="col" className="py-2 pr-4 font-medium">
                    <span className="sr-only">Select for comparison</span>
                  </th>
                  <th scope="col" className="py-2 pr-4 font-medium">Analysis</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Branch</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Commit</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Date</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Status</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Findings</th>
                  <th scope="col" className="py-2 font-medium">Open</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((entry) => {
                  const checked = selected.includes(entry.analysis_id);
                  return (
                    <tr key={entry.analysis_id} className="border-b border-border last:border-0">
                      <td className="py-2 pr-4">
                        <input
                          type="checkbox"
                          checked={checked}
                          disabled={!checked && selected.length >= 2}
                          onChange={() =>
                            setSelected((previous) =>
                              checked
                                ? previous.filter((id) => id !== entry.analysis_id)
                                : [...previous, entry.analysis_id],
                            )
                          }
                          aria-label={`Select analysis ${entry.analysis_id} for comparison`}
                        />
                      </td>
                      <td className="break-identifier py-2 pr-4 font-mono text-xs" title={entry.analysis_id}>
                        {entry.analysis_id.length > 8 ? entry.analysis_id.slice(0, 8) : entry.analysis_id}
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
                        {outcomeBadge(entry.outcome)}
                        {entry.outcome === "Failed" && entry.explanation ? (
                          <p className="mt-1 text-xs text-text-secondary">{entry.explanation}</p>
                        ) : null}
                      </td>
                      <td className="py-2 pr-4 font-mono text-xs" title="History entries carry no finding totals">
                        —
                      </td>
                      <td className="py-2">
                        <Link
                          className="text-primary underline"
                          to={ROUTES.analysisOverview(entry.analysis_id)}
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
        </Panel>
      )}
    </div>
  );
}

/** Why the current selection cannot be compared, or null when it can. */
function compareBlockerReason(selected: HistoryEntry[]): string | null {
  if (selected.length !== 2) {
    return selected.length < 2 ? "Two analyses must be selected." : "";
  }
  const [first, second] = selected;
  if (first.analysis_id === second.analysis_id) {
    return "Select two different analyses.";
  }
  for (const entry of selected) {
    if (entry.outcome == null) {
      return "Both analyses must have reached a terminal outcome.";
    }
    if (entry.outcome === "Failed") {
      return "Failed analyses have no snapshot and cannot be compared.";
    }
  }
  return null;
}

/** Earlier analysis (by timestamp, falling back to history order) is the base. */
function orderBaseTarget(selected: HistoryEntry[]): { base: HistoryEntry; target: HistoryEntry } {
  const [first, second] = selected;
  if (first.timestamp && second.timestamp) {
    return first.timestamp <= second.timestamp
      ? { base: first, target: second }
      : { base: second, target: first };
  }
  return { base: first, target: second };
}
