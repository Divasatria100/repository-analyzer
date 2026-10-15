import { useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import { ANALYSIS_ID_PARAM, ROUTES } from "../../router/routes";
import { useAnalysisResult } from "../analysis/useAnalysisResult";
import type { Finding } from "../../schemas/results";
import { Alert, EmptyState, LoadingState, Panel, StatusBadge } from "../../components/ui";
import { ConfidenceBadge, SeverityBadge } from "../findings/FindingBits";
import { HotspotsTable } from "./HotspotsTable";

// Code Structure view (TASK-201, docs/14 §12.1–12.2). Sortable tables over
// the canonical `code_structure.metrics` array, selectable by segmented
// control (?table=). Rows link associated findings; metrics are never
// converted into findings by the interface. Unavailable renders as
// "unavailable", never 0. No health score anywhere.

type TableKey = "complexity" | "nesting" | "parameters" | "size" | "duplicates" | "hotspots";

const TABLES: Array<{ key: TableKey; label: string }> = [
  { key: "complexity", label: "Complexity" },
  { key: "nesting", label: "Nesting depth" },
  { key: "parameters", label: "Parameter count" },
  { key: "size", label: "Size" },
  { key: "duplicates", label: "Duplicate candidates" },
  { key: "hotspots", label: "Hotspots" },
];

const TABLE_METRICS: Partial<Record<TableKey, string[]>> = {
  complexity: ["complexity"],
  nesting: ["nesting_depth"],
  parameters: ["parameter_count"],
};

const TABLE_RULES: Partial<Record<TableKey, string>> = {
  complexity: "CODE-HIGH-COMPLEXITY",
  nesting: "CODE-DEEP-NESTING",
  parameters: "CODE-HIGH-PARAMETER-COUNT",
  duplicates: "CODE-DUPLICATE-CANDIDATE",
};

function isTableKey(value: string | null): value is TableKey {
  return TABLES.some((entry) => entry.key === value);
}

interface MetricRow {
  key: string;
  metric: string;
  symbol: string | null;
  path: string;
  value: number | null;
  unavailable: boolean;
  incomplete: boolean;
  finding: Finding | null;
}

/** Measurement entries recorded on a finding's evidence, if any. */
function evidenceMetrics(finding: Finding): string[] {
  const evidence = finding.evidence as { measurements?: unknown } | null | undefined;
  const list = evidence?.measurements;
  if (!Array.isArray(list)) {
    return [];
  }
  return list
    .filter((entry): entry is { metric: string } => {
      if (entry == null || typeof entry !== "object") {
        return false;
      }
      return typeof (entry as { metric?: unknown }).metric === "string";
    })
    .map((entry) => entry.metric);
}

export function CodeStructurePage() {
  const params = useParams();
  const analysisId = params[ANALYSIS_ID_PARAM] ?? "";
  const [searchParams, setSearchParams] = useSearchParams();
  const [descending, setDescending] = useState(true);
  const { data, error, isLoading, refetch, isFetching } = useAnalysisResult(analysisId);

  const tableParam = searchParams.get("table");
  const table: TableKey = isTableKey(tableParam) ? tableParam : "complexity";

  const rows = useMemo<MetricRow[]>(() => {
    const section = data?.code_structure;
    if (!section || table === "duplicates" || table === "hotspots") {
      return [];
    }
    const wanted = TABLE_METRICS[table];
    const candidates = wanted
      ? section.metrics.filter((metric) => wanted.includes(metric.metric))
      : section.metrics.filter(
          (metric) =>
            metric.metric !== "complexity" &&
            metric.metric !== "nesting_depth" &&
            metric.metric !== "parameter_count",
        );
    const findings = section.findings;
    return candidates.map((metric, index) => {
      const value = metric.value ?? null;
      const associated =
        value == null
          ? null
          : (findings.find(
              (finding) =>
                evidenceMetrics(finding).includes(metric.metric) &&
                finding.subject.locations.some(
                  (location) => location.path === metric.subject_path,
                ),
            ) ?? null);
      return {
        key: `${metric.metric}|${metric.subject_path}|${metric.subject_name ?? ""}|${index}`,
        metric: metric.metric,
        symbol: metric.subject_name ?? null,
        path: metric.subject_path,
        value,
        unavailable: value == null,
        incomplete: metric.potentially_incomplete === true,
        finding: associated,
      };
    });
  }, [data, table]);

  const orderedRows = useMemo(() => {
    const copy = [...rows];
    copy.sort((a, b) => {
      if (a.unavailable && b.unavailable) return a.path.localeCompare(b.path);
      if (a.unavailable) return 1;
      if (b.unavailable) return -1;
      const diff = (a.value ?? 0) - (b.value ?? 0);
      if (diff !== 0) return descending ? -diff : diff;
      return a.path.localeCompare(b.path);
    });
    return copy;
  }, [rows, descending]);

  if (isLoading) {
    return <LoadingState label="Loading code structure…" />;
  }

  if (error || !data) {
    return (
      <Panel>
        <Alert tone="error" title="Could not load code structure.">
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
        <Alert tone="info" title="Code structure is unavailable while the analysis is not completed.">
          <p>Results appear once the backend reports a completed outcome.</p>
        </Alert>
      </Panel>
    );
  }

  if (data.code_structure == null) {
    const domain = data.status.domains.find((item) => item.area === "code_structure");
    return (
      <Panel>
        <Alert tone="warning" title="Code structure results are unavailable for this analysis.">
          <p>
            State: {domain?.state ?? "unavailable"}
            {domain?.reason ? ` — ${domain.reason}` : ""}
          </p>
          <p className="mt-1">This is not a clean result: the area was not evaluated.</p>
        </Alert>
      </Panel>
    );
  }

  const section = data.code_structure;
  const definitions = section.metric_definitions;
  const duplicateFindings = section.findings.filter(
    (finding) => finding.rule_id === "CODE-DUPLICATE-CANDIDATE",
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-lg font-semibold">Code Structure</h2>
        <span className="text-sm text-text-secondary">
          {section.metrics.length} metrics · {section.findings.length} findings
        </span>
      </div>

      <div role="group" aria-label="Code structure tables" className="flex flex-wrap gap-2">
        {TABLES.map((entry) => (
          <button
            key={entry.key}
            type="button"
            onClick={() => {
              const next = new URLSearchParams(searchParams);
              next.set("table", entry.key);
              setSearchParams(next);
            }}
            aria-pressed={table === entry.key}
            className={`rounded-pill border px-3 py-1 text-sm ${
              table === entry.key
                ? "border-primary text-text-primary"
                : "border-border text-text-secondary hover:text-text-primary"
            }`}
          >
            {entry.label}
          </button>
        ))}
      </div>

      {table === "hotspots" ? (
        <HotspotsTable analysisId={analysisId} result={data} />
      ) : table === "duplicates" ? (
        <Panel>
          <h3 className="mb-1 text-base font-semibold">Duplicate candidates</h3>
          <p className="mb-3 text-sm text-text-secondary">
            Candidates, not determinations. The first location of each finding is the
            primary location as ordered by the backend.
          </p>
          {duplicateFindings.length === 0 ? (
            <EmptyState title="No duplicate candidates reported." />
          ) : (
            <ul className="space-y-3">
              {duplicateFindings.map((finding) => (
                <li key={finding.finding_id} className="rounded-control border border-border px-3 py-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <Link
                      className="font-mono text-xs text-primary underline"
                      to={ROUTES.analysisFindingDetail(analysisId, finding.finding_id)}
                    >
                      {finding.finding_id}
                    </Link>
                    <SeverityBadge severity={finding.severity} />
                    <ConfidenceBadge confidence={finding.confidence} />
                  </div>
                  <ol className="mt-2 space-y-1 text-xs">
                    {finding.subject.locations.map((location, index) => (
                      <li key={index} className="break-identifier font-mono">
                        {index === 0 ? "primary: " : ""}
                        {location.path}
                        {location.start_line != null ? `:${location.start_line}` : ""}
                      </li>
                    ))}
                  </ol>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      ) : (
        <Panel>
          <div className="mb-3 flex flex-wrap items-center gap-3">
            <h3 className="text-base font-semibold">
              {TABLES.find((entry) => entry.key === table)?.label}
            </h3>
            {TABLE_RULES[table] ? (
              <span className="font-mono text-xs text-text-secondary">{TABLE_RULES[table]}</span>
            ) : null}
            <button
              type="button"
              onClick={() => setDescending((value) => !value)}
              className="rounded-control border border-border px-2 py-1 text-xs hover:border-primary"
              aria-label={`Sort ${descending ? "ascending" : "descending"}`}
            >
              {descending ? "↓ highest first" : "↑ lowest first"}
            </button>
          </div>
          {definitions[rows[0]?.metric ?? ""] ? (
            <p className="mb-3 text-sm text-text-secondary">
              {definitions[rows[0]?.metric ?? ""]?.description}{" "}
              <span className="font-mono text-xs">
                (unit: {definitions[rows[0]?.metric ?? ""]?.unit})
              </span>
            </p>
          ) : null}
          {orderedRows.length === 0 ? (
            <EmptyState title="No metrics recorded for this table." />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[640px] text-left text-sm">
                <thead>
                  <tr className="border-b border-border text-text-secondary">
                    <th scope="col" className="py-2 pr-4 font-medium">Symbol</th>
                    <th scope="col" className="py-2 pr-4 font-medium">File</th>
                    <th scope="col" className="py-2 pr-4 font-medium">Value</th>
                    <th scope="col" className="py-2 font-medium">Finding</th>
                  </tr>
                </thead>
                <tbody>
                  {orderedRows.map((row) => (
                    <tr key={row.key} className="border-b border-border last:border-0">
                      <td className="break-identifier py-2 pr-4 font-mono text-xs">
                        {row.symbol ?? "—"}
                      </td>
                      <td className="break-identifier py-2 pr-4 font-mono text-xs">{row.path}</td>
                      <td className="py-2 pr-4 font-mono text-xs">
                        {row.unavailable ? (
                          "unavailable"
                        ) : (
                          <>
                            {row.value}
                            {row.incomplete ? (
                              <StatusBadge label="potentially incomplete" tone="warning" marker="▲" />
                            ) : null}
                          </>
                        )}
                      </td>
                      <td className="py-2">
                        {row.finding ? (
                          <Link
                            className="font-mono text-xs text-primary underline"
                            to={ROUTES.analysisFindingDetail(analysisId, row.finding.finding_id)}
                          >
                            {row.finding.finding_id}
                          </Link>
                        ) : (
                          <span className="text-xs text-text-secondary">—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className="mt-3 text-xs text-text-secondary">
            Metrics and findings are separate: a row without a finding is a measurement only.
          </p>
        </Panel>
      )}
    </div>
  );
}
