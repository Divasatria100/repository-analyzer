import { useEffect, useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import { ANALYSIS_ID_PARAM, ROUTES } from "../../router/routes";
import { useAnalysisResult } from "../analysis/useAnalysisResult";
import type { AnalysisResult, FileRecord, Finding } from "../../schemas/results";
import { Alert, EmptyState, LoadingState, Panel, StatusBadge } from "../../components/ui";
import { SourceContext } from "../findings/SourceContext";

// Files explorer (TASK-203, docs/14 §13). The canonical `files` array is the
// complete dataset: tree, search, and filters run client-side over it.
// Detail shows metadata, coverage, file-level metrics, findings with a
// location in this file, and their bounded evidence excerpts. Whole-file
// source is never fetched or implied.

interface TreeNode {
  name: string;
  path: string;
  isDir: boolean;
  children: TreeNode[];
  file: FileRecord | null;
  count: number;
}

function buildTree(files: FileRecord[]): TreeNode[] {
  const root: TreeNode = { name: "", path: "", isDir: true, children: [], file: null, count: 0 };
  const dirs = new Map<string, TreeNode>([["", root]]);
  const sorted = [...files].sort((a, b) => a.path.localeCompare(b.path));
  for (const file of sorted) {
    const parts = file.path.split("/");
    let prefix = "";
    for (let index = 0; index < parts.length - 1; index += 1) {
      prefix = prefix === "" ? parts[index] : `${prefix}/${parts[index]}`;
      let node = dirs.get(prefix);
      if (!node) {
        node = {
          name: parts[index],
          path: prefix,
          isDir: true,
          children: [],
          file: null,
          count: 0,
        };
        dirs.set(prefix, node);
        const parentPrefix = prefix.includes("/") ? prefix.slice(0, prefix.lastIndexOf("/")) : "";
        dirs.get(parentPrefix)?.children.push(node);
      }
    }
    const parentPrefix = parts.length > 1 ? parts.slice(0, -1).join("/") : "";
    const leaf: TreeNode = {
      name: parts[parts.length - 1],
      path: file.path,
      isDir: false,
      children: [],
      file,
      count: file.finding_count,
    };
    dirs.get(parentPrefix)?.children.push(leaf);
  }
  const aggregate = (node: TreeNode): number => {
    if (!node.isDir) {
      return node.count;
    }
    node.count = node.children.reduce((sum, child) => sum + aggregate(child), 0);
    node.children.sort((a, b) => {
      if (a.isDir !== b.isDir) {
        return a.isDir ? -1 : 1;
      }
      return a.name.localeCompare(b.name);
    });
    return node.count;
  };
  aggregate(root);
  return root.children;
}

function worstCoverage(file: FileRecord): string | null {
  const states = file.coverage.map((entry) => entry.state);
  if (states.length === 0) {
    return null;
  }
  if (states.some((state) => state === "Failed")) {
    return "Failed";
  }
  if (states.some((state) => state === "Not analyzed")) {
    return "Not analyzed";
  }
  if (states.some((state) => state === "Partially analyzed")) {
    return "Partially analyzed";
  }
  return "Fully analyzed";
}

function storageKey(analysisId: string): string {
  return `repolens-files-expanded:${analysisId}`;
}

function loadExpanded(analysisId: string): Set<string> {
  try {
    const raw = sessionStorage.getItem(storageKey(analysisId));
    if (!raw) {
      return new Set();
    }
    const parsed: unknown = JSON.parse(raw);
    return Array.isArray(parsed) ? new Set(parsed.filter((item) => typeof item === "string")) : new Set();
  } catch {
    return new Set();
  }
}

export function FilesPage() {
  const params = useParams();
  const analysisId = params[ANALYSIS_ID_PARAM] ?? "";
  const [searchParams, setSearchParams] = useSearchParams();
  const { data, error, isLoading, refetch, isFetching } = useAnalysisResult(analysisId);
  const [expanded, setExpanded] = useState<Set<string>>(() => loadExpanded(analysisId));

  const textFilter = searchParams.get("q") ?? "";
  const withFindings = searchParams.get("with_findings") === "1";
  const notAnalyzed = searchParams.get("not_analyzed") === "1";
  const parseIssue = searchParams.get("parse_issue") === "1";
  const langFilter = searchParams.get("lang") ?? "";
  const selectedPath = searchParams.get("path");

  useEffect(() => {
    try {
      sessionStorage.setItem(storageKey(analysisId), JSON.stringify([...expanded]));
    } catch {
      // Storage is a convenience only; the tree works without it.
    }
  }, [expanded, analysisId]);

  const languages = useMemo(() => {
    const values = new Set<string>();
    for (const file of data?.files ?? []) {
      if (file.language) {
        values.add(file.language);
      }
    }
    return [...values].sort();
  }, [data]);

  const matchingFiles = useMemo(() => {
    const needle = textFilter.trim().toLowerCase();
    return (data?.files ?? []).filter((file) => {
      if (needle && !file.path.toLowerCase().includes(needle)) {
        return false;
      }
      if (withFindings && file.finding_count === 0) {
        return false;
      }
      if (notAnalyzed && worstCoverage(file) === "Fully analyzed") {
        return false;
      }
      if (
        parseIssue &&
        file.parse_result !== "Failed" &&
        file.parse_result !== "Parsed with diagnostics"
      ) {
        return false;
      }
      if (langFilter && file.language !== langFilter) {
        return false;
      }
      return true;
    });
  }, [data, textFilter, withFindings, notAnalyzed, parseIssue, langFilter]);

  const tree = useMemo(() => buildTree(matchingFiles), [matchingFiles]);

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

  function toggleDir(path: string) {
    setExpanded((previous) => {
      const next = new Set(previous);
      if (next.has(path)) {
        next.delete(path);
      } else {
        next.add(path);
      }
      return next;
    });
  }

  if (isLoading) {
    return <LoadingState label="Loading files…" />;
  }

  if (error || !data) {
    return (
      <Panel>
        <Alert tone="error" title="Could not load files.">
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
        <Alert tone="info" title="Files are unavailable while the analysis is not completed.">
          <p>Results appear once the backend reports a completed outcome.</p>
        </Alert>
      </Panel>
    );
  }

  if (data.files == null) {
    return (
      <Panel>
        <Alert tone="warning" title="File results are unavailable for this analysis.">
          <p>This is not an empty repository: file data was not retained.</p>
        </Alert>
      </Panel>
    );
  }

  const totalCount = data.files.length;
  const selectedFile = selectedPath
    ? (data.files.find((file) => file.path === selectedPath) ?? null)
    : null;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-lg font-semibold">Files</h2>
        <span className="text-sm text-text-secondary">
          {matchingFiles.length} of {totalCount} files
        </span>
      </div>

      <Panel>
        <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
          <div className="lg:col-span-2">
            <label htmlFor="files-search" className="mb-1 block text-sm font-medium">
              Search path
            </label>
            <input
              id="files-search"
              type="search"
              value={textFilter}
              onChange={(event) => updateFilter({ q: event.target.value })}
              placeholder="app/api/handlers.py"
              autoComplete="off"
              spellCheck={false}
              className="break-identifier w-full rounded-control border border-border bg-secondary px-3 py-2 font-mono text-sm placeholder:text-text-secondary"
            />
          </div>
          <div>
            <label htmlFor="files-lang" className="mb-1 block text-sm font-medium">
              Language
            </label>
            <select
              id="files-lang"
              value={langFilter}
              onChange={(event) => updateFilter({ lang: event.target.value })}
              className="w-full rounded-control border border-border bg-secondary px-2 py-2 text-sm"
            >
              <option value="">All languages</option>
              {languages.map((language) => (
                <option key={language} value={language}>
                  {language}
                </option>
              ))}
            </select>
          </div>
          <fieldset>
            <legend className="mb-1 text-sm font-medium">States</legend>
            <div className="flex flex-wrap gap-3 text-sm">
              <label className="flex items-center gap-1">
                <input
                  type="checkbox"
                  checked={withFindings}
                  onChange={(event) =>
                    updateFilter({ with_findings: event.target.checked ? "1" : null })
                  }
                />
                With findings
              </label>
              <label className="flex items-center gap-1">
                <input
                  type="checkbox"
                  checked={notAnalyzed}
                  onChange={(event) =>
                    updateFilter({ not_analyzed: event.target.checked ? "1" : null })
                  }
                />
                Not fully analyzed
              </label>
              <label className="flex items-center gap-1">
                <input
                  type="checkbox"
                  checked={parseIssue}
                  onChange={(event) =>
                    updateFilter({ parse_issue: event.target.checked ? "1" : null })
                  }
                />
                Parse issues
              </label>
            </div>
          </fieldset>
        </div>
        <div className="mt-3">
          <button
            type="button"
            onClick={() => updateFilter({ q: null, with_findings: null, not_analyzed: null, parse_issue: null, lang: null })}
            className="rounded-control border border-border px-2 py-1 text-sm text-text-secondary hover:text-text-primary"
          >
            Reset filters
          </button>
        </div>
      </Panel>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel>
          <h3 className="mb-2 text-base font-semibold">Tree</h3>
          {tree.length === 0 ? (
            <EmptyState title="No files match these filters.">
              <p>Adjust or reset the filters.</p>
            </EmptyState>
          ) : (
            <ul className="space-y-1 text-sm" aria-label="Repository files">
              {tree.map((node) => (
                <TreeRow
                  key={node.path || "/"}
                  node={node}
                  depth={0}
                  expanded={expanded}
                  onToggle={toggleDir}
                  selectedPath={selectedPath}
                  onSelect={(path) => updateFilter({ path })}
                />
              ))}
            </ul>
          )}
        </Panel>
        <FileDetail analysisId={analysisId} file={selectedFile} selectedPath={selectedPath} result={data} />
      </div>
    </div>
  );
}

function TreeRow({
  node,
  depth,
  expanded,
  onToggle,
  selectedPath,
  onSelect,
}: {
  node: TreeNode;
  depth: number;
  expanded: Set<string>;
  onToggle: (path: string) => void;
  selectedPath: string | null;
  onSelect: (path: string) => void;
}) {
  if (node.isDir) {
    const open = expanded.has(node.path);
    return (
      <li>
        <button
          type="button"
          onClick={() => onToggle(node.path)}
          aria-expanded={open}
          className="flex w-full items-center gap-2 rounded-control px-2 py-1 text-left hover:bg-secondary"
        >
          <span aria-hidden="true" className="w-4 text-text-secondary">
            {open ? "▾" : "▸"}
          </span>
          <span className="break-identifier font-mono text-xs">{node.name}/</span>
          {node.count > 0 ? (
            <span className="font-mono text-xs text-text-secondary">{node.count}</span>
          ) : null}
        </button>
        {open ? (
          <ul className="ml-4 space-y-1 border-l border-border pl-2">
            {node.children.map((child) => (
              <TreeRow
                key={child.path}
                node={child}
                depth={depth + 1}
                expanded={expanded}
                onToggle={onToggle}
                selectedPath={selectedPath}
                onSelect={onSelect}
              />
            ))}
          </ul>
        ) : null}
      </li>
    );
  }
  const file = node.file;
  if (!file) {
    return null;
  }
  const coverage = worstCoverage(file);
  const selected = selectedPath === node.path;
  return (
    <li>
      <button
        type="button"
        onClick={() => onSelect(node.path)}
        aria-current={selected ? "true" : undefined}
        className={`flex w-full items-center gap-2 rounded-control px-2 py-1 text-left hover:bg-secondary ${
          selected ? "bg-secondary outline outline-1 outline-primary" : ""
        }`}
      >
        <span className="break-identifier min-w-0 flex-1 font-mono text-xs">{node.name}</span>
        {node.count > 0 ? (
          <span className="font-mono text-xs text-text-secondary" title={`${node.count} findings`}>
            {node.count}
          </span>
        ) : null}
        {coverage && coverage !== "Fully analyzed" ? (
          <span className="text-xs text-status-warning" title={`Coverage: ${coverage}`}>
            ▲
          </span>
        ) : null}
        {file.support !== "Primary Support" ? (
          <span className="text-xs text-text-secondary" title={`Support: ${file.support}`}>
            ○
          </span>
        ) : null}
      </button>
    </li>
  );
}

function FileDetail({
  analysisId,
  file,
  selectedPath,
  result,
}: {
  analysisId: string;
  file: FileRecord | null;
  selectedPath: string | null;
  result: AnalysisResult;
}) {
  if (!file) {
    if (selectedPath) {
      return (
        <Panel>
          <Alert tone="warning" title={`Unknown file "${selectedPath}".`}>
            <p>No file with this path exists in this analysis.</p>
          </Alert>
        </Panel>
      );
    }
    return (
      <Panel>
        <h3 className="text-base font-semibold">File detail</h3>
        <p className="mt-2 text-sm text-text-secondary">
          Select a file to inspect its metadata, coverage, metrics, and findings.
        </p>
      </Panel>
    );
  }

  const sections = [result.security, result.architecture, result.dependencies, result.code_structure];
  const fileFindings: Finding[] = [];
  for (const section of sections) {
    if (!section) {
      continue;
    }
    for (const finding of section.findings) {
      if (finding.subject.locations.some((location) => location.path === file.path)) {
        fileFindings.push(finding);
      }
    }
  }
  const metrics: Array<{ metric: string; value: string; area: string }> = [];
  if (result.architecture) {
    for (const metric of result.architecture.metrics) {
      if (metric.subject_path === file.path) {
        metrics.push({
          metric: metric.metric,
          value:
            metric.value == null
              ? "unavailable"
              : `${String(metric.value)}${metric.availability === "unavailable" ? " (unavailable)" : ""}${metric.potentially_incomplete ? " (potentially incomplete)" : ""}`,
          area: "architecture",
        });
      }
    }
  }
  if (result.code_structure) {
    for (const metric of result.code_structure.metrics) {
      if (metric.subject_path === file.path) {
        metrics.push({
          metric: metric.metric,
          value:
            metric.value == null
              ? "unavailable"
              : `${String(metric.value)}${metric.availability === "unavailable" ? " (unavailable)" : ""}`,
          area: "code_structure",
        });
      }
    }
  }

  return (
    <Panel>
      <h3 className="break-identifier font-mono text-base font-semibold">{file.path}</h3>
      <dl className="mt-3 space-y-2 text-sm">
        <div className="flex gap-2">
          <dt className="w-28 shrink-0 text-text-secondary">Type</dt>
          <dd>{file.file_type}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-28 shrink-0 text-text-secondary">Language</dt>
          <dd>{file.language ?? "—"}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-28 shrink-0 text-text-secondary">Support</dt>
          <dd>{file.support}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-28 shrink-0 text-text-secondary">Size</dt>
          <dd className="font-mono text-xs">{file.size != null ? `${file.size} bytes` : "—"}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-28 shrink-0 text-text-secondary">Flags</dt>
          <dd className="text-xs">
            {[
              file.binary ? "binary" : null,
              file.generated ? "generated" : null,
              file.exclusion ? `excluded (${file.exclusion.reason ?? "no reason given"})` : null,
            ]
              .filter(Boolean)
              .join(" · ") || "—"}
          </dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-28 shrink-0 text-text-secondary">Eligibility</dt>
          <dd className="text-xs">
            {file.eligibility.classification}
            {file.eligibility.reason ? ` — ${file.eligibility.reason}` : ""}
          </dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-28 shrink-0 text-text-secondary">Parse</dt>
          <dd className="text-xs">
            {file.parse_result ?? "not parsed"}
            {file.parse_result === "Failed" ? (
              <StatusBadge label="failed" tone="error" marker="✕" />
            ) : null}
          </dd>
        </div>
        {file.diagnostics.length > 0 ? (
          <div>
            <dt className="text-text-secondary">Diagnostics</dt>
            <dd>
              <ul className="mt-1 space-y-1 font-mono text-xs">
                {file.diagnostics.map((diagnostic, index) => (
                  <li key={index} className="break-identifier">
                    {String(diagnostic.message ?? diagnostic.code ?? "diagnostic")}
                    {diagnostic.line != null ? ` (line ${String(diagnostic.line)})` : ""}
                  </li>
                ))}
              </ul>
            </dd>
          </div>
        ) : null}
        {file.indexing_limitation ? (
          <div>
            <dt className="text-text-secondary">Indexing limitation</dt>
            <dd className="text-xs">{file.indexing_limitation}</dd>
          </div>
        ) : null}
      </dl>

      <h4 className="mt-4 text-sm font-semibold">Coverage</h4>
      {file.coverage.length === 0 ? (
        <p className="mt-1 text-sm text-text-secondary">No coverage records.</p>
      ) : (
        <ul className="mt-1 space-y-1 text-xs">
          {file.coverage.map((entry, index) => (
            <li key={index}>
              {entry.scope.kind}:{entry.scope.value} — {entry.state}
              {entry.reason ? ` (${entry.reason})` : ""}
            </li>
          ))}
        </ul>
      )}

      <h4 className="mt-4 text-sm font-semibold">Metrics</h4>
      {metrics.length === 0 ? (
        <p className="mt-1 text-sm text-text-secondary">No file-level metrics recorded.</p>
      ) : (
        <ul className="mt-1 space-y-1 font-mono text-xs">
          {metrics.map((metric, index) => (
            <li key={index}>
              {metric.metric} ({metric.area}): {metric.value}
            </li>
          ))}
        </ul>
      )}

      <h4 className="mt-4 text-sm font-semibold">Findings in this file ({fileFindings.length})</h4>
      {fileFindings.length === 0 ? (
        <p className="mt-1 text-sm text-text-secondary">
          No findings have a location in this file.
        </p>
      ) : (
        <ul className="space-y-4">
          {fileFindings.map((finding) => (
            <li key={finding.finding_id} className="rounded-control border border-border px-3 py-2">
              <Link
                className="font-mono text-xs text-primary underline"
                to={ROUTES.analysisFindingDetail(analysisId, finding.finding_id)}
              >
                {finding.finding_id}
              </Link>{" "}
              <span className="text-xs">
                {finding.rule_id} · {finding.severity} · {finding.confidence}
              </span>
              <div className="mt-2">
                <SourceContext
                  evidence={finding.evidence ?? null}
                  path={finding.subject.locations[0]?.path ?? null}
                />
              </div>
            </li>
          ))}
        </ul>
      )}
      <p className="mt-3 text-xs text-text-secondary">
        Only bounded evidence excerpts are shown; complete file source is not stored or viewable.
      </p>
    </Panel>
  );
}
