import { useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { ApiRequestError, getAnalysisResult, getRepositoryHistory } from "../../lib/api";
import { ANALYSIS_ID_PARAM, ROUTES } from "../../router/routes";
import type { AnalysisResult, ComparisonEntry, Finding } from "../../schemas/results";
import { Alert, EmptyState, LoadingState, Panel, StatusBadge } from "../../components/ui";
import { CategoryBadge } from "../findings/FindingBits";
import { useAnalysisResult } from "../analysis/useAnalysisResult";

// Analysis comparison (TASK-205, docs/14 §17, docs/13 §15). The backend
// classifies findings by identity key via `?comparison_base=`; the page
// resolves entry locations from the two persisted results and links each
// entry to the finding detail in the analysis that holds it. No change
// scores, no improvement claims; identity-match limits are stated.

function useComparisonResult(targetId: string, baseId: string, enabled: boolean) {
  return useQuery({
    queryKey: ["comparison", targetId, baseId],
    queryFn: ({ signal }) => getAnalysisResult(targetId, signal, baseId),
    enabled,
    retry: (count, error) => {
      if (
        error instanceof ApiRequestError &&
        (error.code === "ANALYSIS_NOT_FOUND" || error.code === "ANALYSIS_NOT_COMPLETED")
      ) {
        return false;
      }
      return count < 1;
    },
  });
}

function shortSha(sha: string | null): string {
  if (!sha) {
    return "—";
  }
  return sha.length > 7 ? sha.slice(0, 7) : sha;
}

interface Qualification {
  scope?: unknown;
  area?: unknown;
  rule_id?: unknown;
  effect?: unknown;
}

function asQualification(value: unknown): Qualification | null {
  if (value == null || typeof value !== "object") {
    return null;
  }
  return value as Qualification;
}

function qualificationEffects(entry: ComparisonEntry, qualifications: Qualification[]): string[] {
  const effects: string[] = [];
  for (const qualification of qualifications) {
    if (!qualification) {
      continue;
    }
    if (qualification.scope === "rule" && qualification.rule_id === entry.rule_id) {
      if (typeof qualification.effect === "string") {
        effects.push(qualification.effect);
      }
    } else if (qualification.scope === "area" && qualification.area === entry.category) {
      if (typeof qualification.effect === "string") {
        effects.push(qualification.effect);
      }
    }
  }
  return effects;
}

export function ComparisonPage() {
  const params = useParams();
  const targetId = params[ANALYSIS_ID_PARAM] ?? "";
  const [searchParams, setSearchParams] = useSearchParams();
  const baseId = searchParams.get("base") ?? "";

  const comparison = useComparisonResult(targetId, baseId, baseId !== "");
  const baseResult = useAnalysisResult(baseId, baseId !== "");

  if (!baseId) {
    return <BasePicker targetId={targetId} onPick={(id) => setSearchParams({ base: id })} />;
  }

  if (comparison.isLoading || baseResult.isLoading) {
    return <LoadingState label="Loading comparison…" />;
  }

  const error = comparison.error ?? baseResult.error;
  if (error || !comparison.data || !baseResult.data) {
    const apiError =
      comparison.error instanceof ApiRequestError
        ? comparison.error
        : baseResult.error instanceof ApiRequestError
          ? baseResult.error
          : null;
    return (
      <Panel>
        <Alert
          tone="error"
          title={
            apiError?.code === "ANALYSIS_NOT_FOUND"
              ? "Analysis not found."
              : apiError?.code === "ANALYSIS_NOT_COMPLETED"
                ? "Comparison requires completed analyses."
                : "Could not load the comparison."
          }
        >
          <p>{apiError?.message ?? "An unexpected error occurred."}</p>
        </Alert>
        <button
          type="button"
          onClick={() => {
            void comparison.refetch();
            void baseResult.refetch();
          }}
          className="mt-4 rounded-control border border-border px-4 py-2 text-sm font-medium hover:border-primary"
        >
          Retry
        </button>
      </Panel>
    );
  }

  const target = comparison.data;
  const base = baseResult.data;
  const result = target.comparison ?? null;
  if (!result) {
    return (
      <Panel>
        <Alert tone="warning" title="Comparison is unavailable for this analysis state.">
          <p>The target analysis has no completed outcome to compare from.</p>
        </Alert>
      </Panel>
    );
  }

  if (!result.comparable) {
    return (
      <Panel>
        <h2 className="text-lg font-semibold">Comparison</h2>
        <div className="mt-3">
          <Alert tone="warning" title="These analyses cannot be compared.">
            <p>{result.reason}</p>
          </Alert>
        </div>
      </Panel>
    );
  }

  return (
    <ComparisonView
      targetId={targetId}
      baseId={baseId}
      target={target}
      base={base}
    />
  );
}

function BasePicker({ targetId, onPick }: { targetId: string; onPick: (id: string) => void }) {
  const target = useAnalysisResult(targetId);
  const repositoryId = target.data?.analysis.repository_id ?? "";
  const history = useQuery({
    queryKey: ["history", repositoryId],
    queryFn: ({ signal }) => getRepositoryHistory(repositoryId, signal),
    enabled: repositoryId !== "",
    retry: false,
  });
  const [manualId, setManualId] = useState("");
  const [choice, setChoice] = useState("");

  if (target.isLoading || history.isLoading) {
    return <LoadingState label="Loading comparison…" />;
  }

  const candidates = (history.data?.analyses ?? []).filter(
    (entry) =>
      entry.analysis_id !== targetId &&
      (entry.outcome === "Completed" || entry.outcome === "Completed with limitations"),
  );

  return (
    <Panel>
      <h2 className="text-lg font-semibold">Compare analyses</h2>
      <p className="mt-2 text-sm text-text-secondary">
        Select a completed analysis of the same repository as the base. The earlier
        analysis becomes the base; findings match by stable identity.
      </p>
      {history.error || candidates.length === 0 ? (
        <form
          className="mt-4 flex max-w-xl flex-col gap-2 sm:flex-row"
          onSubmit={(event) => {
            event.preventDefault();
            if (manualId.trim()) {
              onPick(manualId.trim());
            }
          }}
        >
          <label htmlFor="compare-base-id" className="sr-only">
            Base analysis ID
          </label>
          <input
            id="compare-base-id"
            type="text"
            value={manualId}
            onChange={(event) => setManualId(event.target.value)}
            placeholder="base analysis ID"
            autoComplete="off"
            spellCheck={false}
            className="break-identifier min-w-0 flex-1 rounded-control border border-border bg-secondary px-3 py-2 font-mono text-sm placeholder:text-text-secondary"
          />
          <button
            type="submit"
            className="rounded-control bg-primary px-4 py-2 text-sm font-semibold text-background hover:brightness-110"
          >
            Compare
          </button>
        </form>
      ) : (
        <form
          className="mt-4 space-y-2"
          onSubmit={(event) => {
            event.preventDefault();
            if (choice) {
              onPick(choice);
            }
          }}
        >
          {candidates.map((entry) => (
            <label key={entry.analysis_id} className="flex items-center gap-2 text-sm">
              <input
                type="radio"
                name="compare-base"
                value={entry.analysis_id}
                checked={choice === entry.analysis_id}
                onChange={() => setChoice(entry.analysis_id)}
              />
              <span className="break-identifier font-mono text-xs">{entry.analysis_id}</span>
              <span className="text-xs text-text-secondary">
                {entry.commit?.sha ? shortSha(entry.commit.sha) : "no commit"} ·{" "}
                {entry.timestamp ?? "no timestamp"} · {entry.outcome}
              </span>
            </label>
          ))}
          <button
            type="submit"
            disabled={!choice}
            className="rounded-control bg-primary px-4 py-2 text-sm font-semibold text-background hover:brightness-110 disabled:opacity-50"
          >
            Compare
          </button>
        </form>
      )}
    </Panel>
  );
}

function ComparisonView({
  targetId,
  baseId,
  target,
  base,
}: {
  targetId: string;
  baseId: string;
  target: AnalysisResult;
  base: AnalysisResult;
}) {
  const comparison = target.comparison;
  const [tab, setTab] = useState<"new" | "resolved" | "unchanged">("new");
  const result = comparison && comparison.comparable ? comparison : null;
  const qualifications = useMemoQualifications(result?.qualifications ?? []);
  const baseIndex = useMemo(() => {
    const all = [
      ...(base.security?.findings ?? []),
      ...(base.architecture?.findings ?? []),
      ...(base.dependencies?.findings ?? []),
      ...(base.code_structure?.findings ?? []),
    ];
    return new Map(all.map((finding) => [finding.finding_id, finding]));
  }, [base]);
  const targetIndex = useMemo(() => {
    const all = [
      ...(target.security?.findings ?? []),
      ...(target.architecture?.findings ?? []),
      ...(target.dependencies?.findings ?? []),
      ...(target.code_structure?.findings ?? []),
    ];
    return new Map(all.map((finding) => [finding.finding_id, finding]));
  }, [target]);
  if (!result) {
    return null;
  }

  const lists = {
    new: result.new,
    resolved: result.resolved,
    unchanged: result.unchanged,
  };
  const entries = lists[tab];
  const differences = Object.entries(result.context_differences).filter(([, changed]) => changed);

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">Comparison</h2>
      <div className="grid gap-4 md:grid-cols-2">
        <ContextPanel
          title="Base analysis"
          analysisId={baseId}
          owner={target.repository.owner}
          name={target.repository.name}
          context={result.base}
        />
        <ContextPanel
          title="Target analysis"
          analysisId={targetId}
          owner={target.repository.owner}
          name={target.repository.name}
          context={result.target}
        />
      </div>
      {differences.length > 0 ? (
        <Alert tone="warning" title="Analysis contexts differ.">
          <p>
            Changed: {differences.map(([key]) => key).join(", ")}. A change in findings
            caused by these differences must not be presented as a change in the repository.
          </p>
        </Alert>
      ) : null}
      {qualifications.length > 0 ? (
        <Panel title="Qualifications" labelledBy="compare-qualifications">
          <ul className="space-y-1 text-sm">
            {qualifications.map((qualification, index) => (
              <li key={index}>
                {qualification.scope === "rule" ? (
                  <>
                    Rule <span className="font-mono text-xs">{String(qualification.rule_id)}</span>
                  </>
                ) : (
                  <>
                    Area <span className="font-mono text-xs">{String(qualification.area)}</span>
                  </>
                )}
                {typeof qualification.effect === "string" ? ` — ${qualification.effect}` : ""}
              </li>
            ))}
          </ul>
        </Panel>
      ) : null}

      <div role="group" aria-label="Comparison lists" className="flex flex-wrap gap-2">
        {(["new", "resolved", "unchanged"] as const).map((key) => (
          <button
            key={key}
            type="button"
            onClick={() => setTab(key)}
            aria-pressed={tab === key}
            className={`rounded-pill border px-3 py-1 text-sm capitalize ${
              tab === key
                ? "border-primary text-text-primary"
                : "border-border text-text-secondary hover:text-text-primary"
            }`}
          >
            {key} ({lists[key].length})
          </button>
        ))}
      </div>

      {entries.length === 0 ? (
        <Panel>
          <EmptyState title={`No ${tab} findings.`} />
        </Panel>
      ) : (
        <Panel>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[680px] text-left text-sm">
              <thead>
                <tr className="border-b border-border text-text-secondary">
                  <th scope="col" className="py-2 pr-4 font-medium">Rule</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Category</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Location</th>
                  <th scope="col" className="py-2 font-medium">Detail</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((entry) => (
                  <EntryRow
                    key={entry.identity_key}
                    entry={entry}
                    tab={tab}
                    targetId={targetId}
                    baseId={baseId}
                    targetIndex={targetIndex}
                    baseIndex={baseIndex}
                    qualifications={qualifications}
                  />
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-3 text-xs text-text-secondary">
            Findings match by stable identity only. A renamed or moved file or symbol can
            appear as one Resolved and one New finding; identity gaps are preserved, not
            papered over. No change scores are computed.
          </p>
        </Panel>
      )}
    </div>
  );
}

function useMemoQualifications(raw: unknown[]): Qualification[] {
  return useMemo(() => raw.map(asQualification).filter((item): item is Qualification => item != null), [raw]);
}

function EntryRow({
  entry,
  tab,
  targetId,
  baseId,
  targetIndex,
  baseIndex,
  qualifications,
}: {
  entry: ComparisonEntry;
  tab: "new" | "resolved" | "unchanged";
  targetId: string;
  baseId: string;
  targetIndex: Map<string, Finding>;
  baseIndex: Map<string, Finding>;
  qualifications: Qualification[];
}) {
  const effects = entry.qualified === true ? qualificationEffects(entry, qualifications) : [];
  const holders: Array<{ analysisId: string; finding: Finding | undefined; label: string }> =
    tab === "resolved"
      ? [
          {
            analysisId: baseId,
            finding: entry.base_finding_id ? baseIndex.get(entry.base_finding_id) : undefined,
            label: "base",
          },
        ]
      : tab === "new"
        ? [
            {
              analysisId: targetId,
              finding: entry.target_finding_id ? targetIndex.get(entry.target_finding_id) : undefined,
              label: "target",
            },
          ]
        : [
            {
              analysisId: baseId,
              finding: entry.base_finding_id ? baseIndex.get(entry.base_finding_id) : undefined,
              label: "base",
            },
            {
              analysisId: targetId,
              finding: entry.target_finding_id ? targetIndex.get(entry.target_finding_id) : undefined,
              label: "target",
            },
          ];
  const primary = holders.find((holder) => holder.finding) ?? holders[0];
  const location = primary.finding?.subject.locations[0];
  return (
    <tr className="border-b border-border last:border-0">
      <td className="py-2 pr-4">
        <span className="block font-mono text-xs">{entry.rule_id}</span>
        {entry.qualified === true ? (
          <span className="mt-1 block">
            <StatusBadge label="Resolved (qualified)" tone="warning" marker="▲" />
            {effects.map((effect, index) => (
              <span key={index} className="block text-xs text-text-secondary">
                {effect}
              </span>
            ))}
          </span>
        ) : null}
      </td>
      <td className="py-2 pr-4">
        <CategoryBadge category={entry.category} />
      </td>
      <td className="break-identifier py-2 pr-4 font-mono text-xs">
        {location ? (
          <>
            {location.path}
            <span className="block text-text-secondary">
              {location.start_line != null ? `line ${location.start_line}` : "whole file"}
            </span>
          </>
        ) : (
          "location unavailable in the loaded result"
        )}
      </td>
      <td className="py-2">
        {holders.map((holder) =>
          holder.finding ? (
            <Link
              key={holder.label}
              className="mr-2 font-mono text-xs text-primary underline"
              to={ROUTES.analysisFindingDetail(holder.analysisId, holder.finding.finding_id)}
            >
              {holder.label === "base" && tab === "unchanged" ? "base" : holder.label === "target" && tab === "unchanged" ? "target" : "Open"}
            </Link>
          ) : null,
        )}
      </td>
    </tr>
  );
}

function ContextPanel({
  title,
  analysisId,
  owner,
  name,
  context,
}: {
  title: string;
  analysisId: string;
  owner: string;
  name: string;
  context: { commit_sha: string | null; timestamp: string | null; analyzer_version: string; rule_set_version: string };
}) {
  return (
    <Panel>
      <h3 className="text-base font-semibold">{title}</h3>
      <dl className="mt-2 space-y-1 text-sm">
        <div className="flex gap-2">
          <dt className="w-28 shrink-0 text-text-secondary">Repository</dt>
          <dd className="break-identifier font-mono text-xs">
            {owner}/{name}
          </dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-28 shrink-0 text-text-secondary">Analysis</dt>
          <dd>
            <Link className="break-identifier font-mono text-xs text-primary underline" to={ROUTES.analysisOverview(analysisId)}>
              {analysisId}
            </Link>
          </dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-28 shrink-0 text-text-secondary">Commit</dt>
          <dd className="font-mono text-xs">{shortSha(context.commit_sha)}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-28 shrink-0 text-text-secondary">Analyzed</dt>
          <dd className="text-xs">{context.timestamp ?? "—"}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-28 shrink-0 text-text-secondary">Analyzer</dt>
          <dd className="font-mono text-xs">{context.analyzer_version}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-28 shrink-0 text-text-secondary">Rule set</dt>
          <dd className="font-mono text-xs">{context.rule_set_version}</dd>
        </div>
      </dl>
    </Panel>
  );
}
