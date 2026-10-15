import { useMemo } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import { ANALYSIS_ID_PARAM, ROUTES } from "../../router/routes";
import { useAnalysisResult } from "../analysis/useAnalysisResult";
import type { DependencyItem, Finding } from "../../schemas/results";
import { Alert, EmptyState, LoadingState, Panel } from "../../components/ui";

// Dependencies view (TASK-199/200, docs/14 §11). The canonical
// `dependencies.items` array is the complete dataset: filters and search run
// client-side over it and are labeled as list-only. Detail selection uses
// `?dependency=<dependency_id>` so it deep-links and survives refresh.
// Advisory content stays external: only advisory_id + source are shown.

type TypeFilter = "all" | "direct" | "transitive" | "vulnerable" | "duplicate";

const TYPE_FILTERS: TypeFilter[] = ["all", "direct", "transitive", "vulnerable", "duplicate"];

function isTypeFilter(value: string | null): value is TypeFilter {
  return (TYPE_FILTERS as string[]).includes(value ?? "");
}

function distinctVersions(items: DependencyItem[]): Set<string> {
  return new Set(items.map((item) => item.version ?? "\0unknown"));
}

export function DependenciesPage() {
  const params = useParams();
  const analysisId = params[ANALYSIS_ID_PARAM] ?? "";
  const [searchParams, setSearchParams] = useSearchParams();
  const { data, error, isLoading, refetch, isFetching } = useAnalysisResult(analysisId);

  const rawType = searchParams.get("type");
  const typeFilter: TypeFilter = isTypeFilter(rawType) ? rawType : "all";
  const textFilter = searchParams.get("q") ?? "";
  const selectedId = searchParams.get("dependency");

  const duplicateNames = useMemo(() => {
    const byName = new Map<string, DependencyItem[]>();
    for (const item of data?.dependencies?.items ?? []) {
      const group = byName.get(item.name) ?? [];
      group.push(item);
      byName.set(item.name, group);
    }
    const names = new Set<string>();
    for (const [name, group] of byName) {
      if (distinctVersions(group).size > 1) {
        names.add(name);
      }
    }
    return names;
  }, [data]);

  const filteredItems = useMemo(() => {
    const needle = textFilter.trim().toLowerCase();
    return (data?.dependencies?.items ?? []).filter((item) => {
      if (typeFilter === "direct" && item.classification !== "direct") return false;
      if (typeFilter === "transitive" && item.classification !== "transitive") return false;
      if (typeFilter === "vulnerable" && item.advisories.length === 0) return false;
      if (typeFilter === "duplicate" && !duplicateNames.has(item.name)) return false;
      if (needle && !item.name.toLowerCase().includes(needle)) return false;
      return true;
    });
  }, [data, typeFilter, textFilter, duplicateNames]);

  function updateFilter(patch: Record<string, string | null>) {
    const next = new URLSearchParams(searchParams);
    for (const [key, value] of Object.entries(patch)) {
      if (value == null || value === "") {
        next.delete(key);
      } else {
        next.set(key, value);
      }
    }
    setSearchParams(next);
  }

  if (isLoading) {
    return <LoadingState label="Loading dependencies…" />;
  }

  if (error || !data) {
    return (
      <Panel>
        <Alert tone="error" title="Could not load dependencies.">
          <p>Try refreshing, or return to the analysis status.</p>
        </Alert>
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

  if (data.status.outcome == null) {
    return (
      <Panel>
        <Alert tone="info" title="Dependencies are unavailable while the analysis is not completed.">
          <p>Results appear once the backend reports a completed outcome.</p>
        </Alert>
      </Panel>
    );
  }

  if (data.dependencies == null) {
    const domain = data.status.domains.find((item) => item.area === "dependency");
    return (
      <Panel>
        <Alert tone="warning" title="Dependency results are unavailable for this analysis.">
          <p>
            State: {domain?.state ?? "unavailable"}
            {domain?.reason ? ` — ${domain.reason}` : ""}
          </p>
          <p className="mt-1">This is not a clean result: the area was not evaluated.</p>
        </Alert>
      </Panel>
    );
  }

  const section = data.dependencies;
  const advisoryOutcome = data.analysis.advisory_data?.outcome ?? null;
  const advisoryGap = advisoryOutcome === "Partly succeeded" || advisoryOutcome === "Unavailable";
  const selected = section.items.find((item) => item.dependency_id === selectedId) ?? null;
  const totalCount = section.items.length;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-lg font-semibold">Dependencies</h2>
        <span className="text-sm text-text-secondary">
          {filteredItems.length} of {totalCount} occurrences
        </span>
      </div>
      {data.analysis.advisory_data ? (
        <p className="text-sm text-text-secondary">
          Advisory data: {data.analysis.advisory_data.source}
          {data.analysis.advisory_data.consulted_at
            ? ` · consulted ${data.analysis.advisory_data.consulted_at}`
            : ""}
          {" · "}
          {data.analysis.advisory_data.outcome}
        </p>
      ) : null}
      {advisoryGap ? (
        <Alert tone="warning" title="Advisory data was incomplete.">
          <p>
            The absence of advisory associations must not be read as the absence of
            vulnerabilities.
          </p>
        </Alert>
      ) : null}

      <Panel>
        <div className="flex flex-col gap-3 md:flex-row md:items-end">
          <div className="min-w-0 flex-1">
            <label htmlFor="dep-search" className="mb-1 block text-sm font-medium">
              Search package name
            </label>
            <input
              id="dep-search"
              type="search"
              value={textFilter}
              onChange={(event) => updateFilter({ q: event.target.value })}
              placeholder="requests"
              autoComplete="off"
              spellCheck={false}
              className="w-full rounded-control border border-border bg-secondary px-3 py-2 font-mono text-sm placeholder:text-text-secondary"
            />
          </div>
          <div role="group" aria-label="Dependency type filter" className="flex flex-wrap gap-2">
            {TYPE_FILTERS.map((value) => (
              <button
                key={value}
                type="button"
                onClick={() => updateFilter({ type: value === "all" ? null : value })}
                aria-pressed={typeFilter === value}
                className={`rounded-pill border px-3 py-1 text-sm capitalize ${
                  typeFilter === value
                    ? "border-primary text-text-primary"
                    : "border-border text-text-secondary hover:text-text-primary"
                }`}
              >
                {value}
              </button>
            ))}
          </div>
          <button
            type="button"
            onClick={() => updateFilter({ type: null, q: null })}
            className="rounded-control border border-border px-2 py-1 text-sm text-text-secondary hover:text-text-primary"
          >
            Reset filters
          </button>
        </div>
        <p className="mt-2 text-xs text-text-secondary">
          Filters and search affect this list only; the backend data is unchanged.
        </p>
      </Panel>

      {filteredItems.length === 0 ? (
        <Panel>
          {totalCount === 0 ? (
            <EmptyState title="No dependency occurrences recorded.">
              <p>The analysis found no package dependencies in manifests.</p>
            </EmptyState>
          ) : (
            <Alert tone="info" title="No dependencies match these filters.">
              <p>Adjust or reset the filters. This is not missing dependency data.</p>
            </Alert>
          )}
        </Panel>
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          <Panel>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[520px] text-left text-sm">
                <thead>
                  <tr className="border-b border-border text-text-secondary">
                    <th scope="col" className="py-2 pr-4 font-medium">Name</th>
                    <th scope="col" className="py-2 pr-4 font-medium">Version</th>
                    <th scope="col" className="py-2 pr-4 font-medium">Ecosystem</th>
                    <th scope="col" className="py-2 pr-4 font-medium">Type</th>
                    <th scope="col" className="py-2 pr-4 font-medium">Adv.</th>
                    <th scope="col" className="py-2 font-medium">Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredItems.map((item) => (
                    <tr key={item.dependency_id} className="border-b border-border last:border-0">
                      <td className="break-identifier py-2 pr-4 font-mono text-xs">{item.name}</td>
                      <td className="py-2 pr-4 font-mono text-xs">
                        {item.version ?? (
                          <span title="Version could not be determined; a limitation is recorded.">
                            unknown ⚠
                          </span>
                        )}
                      </td>
                      <td className="py-2 pr-4 text-xs">{item.ecosystem ?? "—"}</td>
                      <td className="py-2 pr-4 text-xs">{item.classification}</td>
                      <td className="py-2 pr-4 font-mono text-xs">
                        {item.advisories.length > 0 ? `⚑${item.advisories.length}` : "—"}
                      </td>
                      <td className="py-2">
                        <button
                          type="button"
                          onClick={() => updateFilter({ dependency: item.dependency_id })}
                          className="text-xs text-primary underline"
                          aria-label={`Open details for ${item.name} ${item.version ?? ""}`.trim()}
                        >
                          Details
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
          <DependencyDetail
            analysisId={analysisId}
            item={selected}
            selectedId={selectedId}
            allItems={section.items}
            depFindings={section.findings}
            securityFindings={data.security?.findings ?? []}
            onClose={() => updateFilter({ dependency: null })}
          />
        </div>
      )}
    </div>
  );
}

function DependencyDetail({
  analysisId,
  item,
  selectedId,
  allItems,
  depFindings,
  securityFindings,
  onClose,
}: {
  analysisId: string;
  item: DependencyItem | null;
  selectedId: string | null;
  allItems: DependencyItem[];
  depFindings: Finding[];
  securityFindings: Finding[];
  onClose: () => void;
}) {
  if (!item) {
    if (selectedId) {
      return (
        <Panel>
          <Alert tone="warning" title={`Unknown dependency "${selectedId}".`}>
            <p>No dependency occurrence with this identity exists in this analysis.</p>
          </Alert>
        </Panel>
      );
    }
    return (
      <Panel>
        <h3 className="text-base font-semibold">Dependency detail</h3>
        <p className="mt-2 text-sm text-text-secondary">
          Select a dependency to inspect what introduced it, its advisories, and its findings.
        </p>
      </Panel>
    );
  }

  const byId = new Map(allItems.map((entry) => [entry.dependency_id, entry]));
  const related = depFindings.filter((finding) => item.finding_ids.includes(finding.finding_id));
  const securityRefs = securityFindings.filter((finding) =>
    finding.subject.dependencies.includes(item.dependency_id),
  );

  return (
    <Panel>
      <div className="flex items-start justify-between gap-3">
        <h3 className="break-identifier font-mono text-base font-semibold">{item.name}</h3>
        <button
          type="button"
          onClick={onClose}
          className="shrink-0 rounded-control border border-border px-2 py-1 text-sm text-text-secondary hover:text-text-primary"
        >
          Close
        </button>
      </div>
      <dl className="mt-3 space-y-2 text-sm">
        <div>
          <dt className="text-text-secondary">Version</dt>
          <dd className="font-mono text-xs">{item.version ?? "unknown"}</dd>
        </div>
        <div>
          <dt className="text-text-secondary">Ecosystem / Type</dt>
          <dd>
            {item.ecosystem ?? "—"} · {item.classification}
          </dd>
        </div>
        <div>
          <dt className="text-text-secondary">Source manifest</dt>
          <dd className="break-identifier font-mono text-xs">
            {item.source_manifest ? (
              <Link
                className="text-primary underline"
                to={`${ROUTES.analysisFiles(analysisId)}?path=${encodeURIComponent(item.source_manifest)}`}
              >
                {item.source_manifest}
              </Link>
            ) : (
              "—"
            )}
          </dd>
        </div>
      </dl>

      <h4 className="mt-4 text-sm font-semibold">Introduced by</h4>
      {item.introduced_by.length === 0 ? (
        <p className="mt-1 text-sm text-text-secondary">
          Direct dependency: not introduced by another recorded occurrence.
        </p>
      ) : (
        <ul className="mt-1 space-y-1 text-sm">
          <IntroducedTree item={item} byId={byId} depth={0} seen={new Set([item.dependency_id])} />
        </ul>
      )}

      <h4 className="mt-4 text-sm font-semibold">Advisories</h4>
      {item.advisories.length === 0 ? (
        <p className="mt-1 text-sm text-text-secondary">
          No advisory associations recorded for this occurrence. This is not a claim that
          the package is free of vulnerabilities.
        </p>
      ) : (
        <ul className="mt-1 space-y-1 font-mono text-xs">
          {item.advisories.map((advisory) => (
            <li key={`${advisory.source}:${advisory.advisory_id}`}>
              {advisory.advisory_id} · {advisory.source}
            </li>
          ))}
        </ul>
      )}

      <h4 className="mt-4 text-sm font-semibold">Findings</h4>
      {related.length === 0 && securityRefs.length === 0 ? (
        <p className="mt-1 text-sm text-text-secondary">No findings concern this occurrence.</p>
      ) : (
        <ul className="mt-1 space-y-1 text-sm">
          {related.map((finding) => (
            <li key={finding.finding_id}>
              <Link
                className="font-mono text-xs text-primary underline"
                to={ROUTES.analysisFindingDetail(analysisId, finding.finding_id)}
              >
                {finding.finding_id}
              </Link>{" "}
              <span className="text-xs">
                {finding.rule_id} · {finding.severity}
              </span>
            </li>
          ))}
          {securityRefs.map((finding) => (
            <li key={finding.finding_id}>
              <Link
                className="font-mono text-xs text-primary underline"
                to={ROUTES.analysisFindingDetail(analysisId, finding.finding_id)}
              >
                {finding.finding_id}
              </Link>{" "}
              <span className="text-xs">
                {finding.rule_id} · {finding.severity} · security reference
              </span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

/** Introducer tree from `introduced_by`, cycle-guarded and depth-capped. */
function IntroducedTree({
  item,
  byId,
  depth,
  seen,
}: {
  item: DependencyItem;
  byId: Map<string, DependencyItem>;
  depth: number;
  seen: Set<string>;
}) {
  if (depth > 8) {
    return (
      <li className="text-xs text-text-secondary">… deeper levels omitted for readability.</li>
    );
  }
  return (
    <>
      {item.introduced_by.map((parentId) => {
        const parent = byId.get(parentId);
        if (!parent) {
          return (
            <li key={parentId} className="break-identifier font-mono text-xs">
              {parentId} (record not present in this result)
            </li>
          );
        }
        if (seen.has(parent.dependency_id)) {
          return (
            <li key={parent.dependency_id} className="break-identifier font-mono text-xs">
              {parent.name} (already shown above)
            </li>
          );
        }
        const next = new Set(seen);
        next.add(parent.dependency_id);
        return (
          <li key={parent.dependency_id} style={{ paddingLeft: `${depth * 16}px` }}>
            <span className="break-identifier font-mono text-xs">
              {parent.name} {parent.version ?? "unknown"}
            </span>{" "}
            <span className="text-xs text-text-secondary">· {parent.classification}</span>
            {parent.introduced_by.length > 0 ? (
              <ul className="mt-1 space-y-1">
                <IntroducedTree item={parent} byId={byId} depth={depth + 1} seen={next} />
              </ul>
            ) : null}
          </li>
        );
      })}
    </>
  );
}
