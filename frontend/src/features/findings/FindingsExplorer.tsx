import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { ApiRequestError, listFindings } from "../../lib/api";
import { ROUTES } from "../../router/routes";
import {
  CATEGORIES,
  CONFIDENCES,
  FINDING_SORTS,
  SEVERITIES,
  type FindingsQuery,
} from "../../schemas/results";
import { Alert, EmptyState, LoadingState, Panel } from "../../components/ui";
import { CategoryBadge, ConfidenceBadge, SeverityBadge, formatLineRange } from "./FindingBits";

// Findings explorer (docs/17 §4.3). All filtering, searching, sorting, and
// pagination run on the backend; the URL holds the UI state so detail
// navigation and return preserve filters. `total` is the unfiltered analysis
// count from the server — global counts are never derived from the page.

const DEFAULT_QUERY: FindingsQuery = {
  category: [],
  severity: [],
  confidence: [],
  rule_id: [],
  q: "",
  sort: "severity",
  order: "asc",
  page: 1,
  page_size: 25,
};

function parseQuery(params: URLSearchParams): FindingsQuery {
  const list = (key: string): string[] => params.getAll(key).filter((value) => value !== "");
  const page = Number.parseInt(params.get("page") ?? "1", 10);
  const pageSize = Number.parseInt(params.get("page_size") ?? "25", 10);
  const sort = params.get("sort") ?? "severity";
  const order = params.get("order") ?? "asc";
  return {
    category: list("category"),
    severity: list("severity"),
    confidence: list("confidence"),
    rule_id: list("rule_id"),
    q: params.get("q") ?? "",
    sort: (FINDING_SORTS as readonly string[]).includes(sort) ? sort : "severity",
    order: order === "desc" ? "desc" : "asc",
    page: Number.isInteger(page) && page >= 1 ? page : 1,
    page_size: Number.isInteger(pageSize) && pageSize >= 1 && pageSize <= 200 ? pageSize : 25,
  };
}

function toParams(query: FindingsQuery): URLSearchParams {
  const params = new URLSearchParams();
  for (const value of query.category) params.append("category", value);
  for (const value of query.severity) params.append("severity", value);
  for (const value of query.confidence) params.append("confidence", value);
  for (const value of query.rule_id) params.append("rule_id", value);
  if (query.q.trim() !== "") params.set("q", query.q.trim());
  params.set("sort", query.sort);
  params.set("order", query.order);
  params.set("page", String(query.page));
  params.set("page_size", String(query.page_size));
  return params;
}

function toggle(values: string[], value: string): string[] {
  return values.includes(value) ? values.filter((item) => item !== value) : [...values, value];
}

export function FindingsExplorer({
  analysisId,
  lockedCategory,
}: {
  analysisId: string;
  lockedCategory?: string;
}) {
  const [searchParams, setSearchParams] = useSearchParams();
  const base = parseQuery(searchParams);
  // A locked category (Security view) always wins over the URL.
  const query: FindingsQuery = lockedCategory ? { ...base, category: [lockedCategory] } : base;
  const [draftQ, setDraftQ] = useState(query.q);
  const [draftRule, setDraftRule] = useState(query.rule_id[0] ?? "");

  // Debounced search: the URL (and therefore the request) updates 400ms
  // after the user stops typing; pagination resets on every filter change.
  // The sync effect below intentionally tracks only the serialized params.
  useEffect(() => {
    setDraftQ(query.q);
    setDraftRule(query.rule_id[0] ?? "");
  }, [searchParams.toString()]);
  useEffect(() => {
    if (draftQ === query.q) {
      return;
    }
    // Functional update so a filter change made while the user is still
    // typing is merged, not overwritten, when the debounce fires.
    const timer = window.setTimeout(() => {
      setSearchParams((previous) => toParams({ ...parseQuery(previous), q: draftQ, page: 1 }));
    }, 400);
    return () => window.clearTimeout(timer);
  }, [draftQ]);

  function update(patch: Partial<FindingsQuery>) {
    setSearchParams(toParams({ ...query, ...patch }), { replace: false });
  }

  function commitRule() {
    const value = draftRule.trim();
    update({ rule_id: value === "" ? [] : [value], page: 1 });
  }

  const { data, error, isLoading, isFetching, isPlaceholderData, refetch } = useQuery({
    queryKey: ["findings", analysisId, toParams(query).toString()],
    queryFn: ({ signal }) => listFindings(analysisId, query, signal),
    placeholderData: keepPreviousData,
    retry: (count, queryError) => {
      if (queryError instanceof ApiRequestError && queryError.code === "ANALYSIS_NOT_FOUND") {
        return false;
      }
      return count < 1;
    },
  });

  const fromSearch = searchParams.toString();

  return (
    <div className="space-y-4">
      {lockedCategory ? (
        <p className="text-sm text-text-secondary">
          Showing {lockedCategory}-category findings only, using the canonical category
          identifier.
        </p>
      ) : null}
      <Panel>
        <div className="grid gap-4 md:grid-cols-2">
          <div>
            <label htmlFor="findings-search" className="mb-1 block text-sm font-medium">
              Search path, module, rule ID, or rule name
            </label>
            <input
              id="findings-search"
              type="search"
              value={draftQ}
              onChange={(event) => setDraftQ(event.target.value)}
              placeholder="app/main.py, SEC-*, …"
              autoComplete="off"
              spellCheck={false}
              className="break-identifier w-full rounded-control border border-border bg-secondary px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-secondary"
            />
          </div>
          <div>
            <label htmlFor="findings-rule" className="mb-1 block text-sm font-medium">
              Rule ID (prefix SEC-, ARCH-, DEP-, CODE-)
            </label>
            <input
              id="findings-rule"
              type="text"
              value={draftRule}
              onChange={(event) => setDraftRule(event.target.value)}
              onBlur={commitRule}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  event.preventDefault();
                  commitRule();
                }
              }}
              placeholder="SEC-HARDCODED-SECRET"
              autoComplete="off"
              spellCheck={false}
              className="w-full rounded-control border border-border bg-secondary px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-secondary"
            />
            <p className="mt-1 text-xs text-text-secondary">Applies when you leave the field or press Enter.</p>
          </div>
        </div>
        <div className="mt-4 grid gap-4 sm:grid-cols-3">
          {lockedCategory ? null : (
            <fieldset>
              <legend className="mb-1 text-sm font-medium">Category</legend>
              <div className="space-y-1">
                {CATEGORIES.map((value) => (
                  <label key={value} className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={query.category.includes(value)}
                      onChange={() => update({ category: toggle(query.category, value), page: 1 })}
                    />
                    {value}
                  </label>
                ))}
              </div>
            </fieldset>
          )}
          <fieldset>
            <legend className="mb-1 text-sm font-medium">Severity</legend>
            <div className="space-y-1">
              {SEVERITIES.map((value) => (
                <label key={value} className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={query.severity.includes(value)}
                    onChange={() => update({ severity: toggle(query.severity, value), page: 1 })}
                  />
                  {value}
                </label>
              ))}
            </div>
          </fieldset>
          <fieldset>
            <legend className="mb-1 text-sm font-medium">Confidence</legend>
            <div className="space-y-1">
              {CONFIDENCES.map((value) => (
                <label key={value} className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={query.confidence.includes(value)}
                    onChange={() => update({ confidence: toggle(query.confidence, value), page: 1 })}
                  />
                  {value}
                </label>
              ))}
            </div>
          </fieldset>
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <label className="text-sm">
            Sort{" "}
            <select
              aria-label="Sort field"
              value={query.sort}
              onChange={(event) => update({ sort: event.target.value, page: 1 })}
              className="rounded-control border border-border bg-secondary px-2 py-1 text-sm"
            >
              {FINDING_SORTS.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            onClick={() => update({ order: query.order === "asc" ? "desc" : "asc", page: 1 })}
            className="rounded-control border border-border px-2 py-1 text-sm hover:border-primary"
            aria-label={`Sort order ${query.order}, activate to switch`}
          >
            {query.order === "asc" ? "↑ asc" : "↓ desc"}
          </button>
          <label className="text-sm">
            Per page{" "}
            <select
              aria-label="Results per page"
              value={query.page_size}
              onChange={(event) => update({ page_size: Number(event.target.value), page: 1 })}
              className="rounded-control border border-border bg-secondary px-2 py-1 text-sm"
            >
              {[10, 25, 50, 100].map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            onClick={() =>
              setSearchParams(
                toParams({ ...DEFAULT_QUERY, category: lockedCategory ? [lockedCategory] : [] }),
              )
            }
            className="rounded-control border border-border px-2 py-1 text-sm text-text-secondary hover:text-text-primary"
          >
            Reset filters
          </button>
        </div>
      </Panel>

      {isLoading ? <LoadingState label="Loading findings…" /> : null}

      {error && !data ? (
        <Panel>
          <Alert
            tone="error"
            title={
              error instanceof ApiRequestError && error.code === "VALIDATION_ERROR"
                ? "These filter values were rejected."
                : "Could not load findings."
            }
          >
            <p>{error instanceof ApiRequestError ? error.message : "An unexpected error occurred."}</p>
          </Alert>
          <button
            type="button"
            onClick={() => void refetch()}
            className="mt-4 rounded-control border border-border px-4 py-2 text-sm font-medium hover:border-primary"
          >
            Retry
          </button>
        </Panel>
      ) : null}

      {data ? (
        <Panel>
          {data.unavailable_areas && data.unavailable_areas.length > 0 ? (
            <div className="mb-4">
              <Alert tone="warning" title="Some areas are unavailable.">
                <ul>
                  {data.unavailable_areas.map((area) => (
                    <li key={area.area}>
                      {area.area}: {area.state}
                      {area.reason ? ` — ${area.reason}` : ""}
                    </li>
                  ))}
                </ul>
                <p className="mt-1">Counts below cover available areas only.</p>
              </Alert>
            </div>
          ) : null}
          <p className="mb-3 text-sm text-text-secondary" aria-live="polite">
            {data.items.length === 0
              ? `No matching findings (total ${data.total} in analysis).`
              : `Showing ${data.items.length} of ${data.total} findings in analysis · page ${data.page}.`}
            {isFetching || isPlaceholderData ? " Updating…" : ""}
          </p>
          {data.items.length === 0 ? (
            <EmptyState title="No findings match these filters.">
              <p>Adjust or reset the filters to see more results.</p>
            </EmptyState>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[720px] text-left text-sm">
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
                  {data.items.map((finding) => {
                    const location = finding.subject.locations[0];
                    return (
                      <tr key={finding.finding_id} className="border-b border-border last:border-0">
                        <td className="py-2 pr-4">
                          <SeverityBadge severity={finding.severity} />
                        </td>
                        <td className="py-2 pr-4">
                          <span className="block font-mono text-xs">{finding.rule_id}</span>
                          <span className="block text-xs text-text-secondary">{finding.rule_name}</span>
                        </td>
                        <td className="py-2 pr-4">
                          <CategoryBadge category={finding.category} />
                        </td>
                        <td className="break-identifier py-2 pr-4 font-mono text-xs">
                          {location ? (
                            <>
                              {location.path}
                              <span className="block text-text-secondary">
                                {formatLineRange(location.start_line, location.end_line) ?? "whole file"}
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
                            to={{
                              pathname: ROUTES.analysisFindingDetail(analysisId, finding.finding_id),
                            }}
                            state={{ fromSearch }}
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
          )}
          <div className="mt-4 flex items-center gap-3 text-sm">
            <button
              type="button"
              disabled={data.page <= 1}
              onClick={() => update({ page: data.page - 1 })}
              className="rounded-control border border-border px-3 py-1 hover:border-primary disabled:opacity-40"
            >
              Previous
            </button>
            <span aria-live="polite">
              {`Page ${data.page} of ${Math.max(1, Math.ceil(data.total / data.page_size))}`}
            </span>
            <button
              type="button"
              disabled={data.page * data.page_size >= data.total}
              onClick={() => update({ page: data.page + 1 })}
              className="rounded-control border border-border px-3 py-1 hover:border-primary disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </Panel>
      ) : null}
    </div>
  );
}
