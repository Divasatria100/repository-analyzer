import { useEffect, useRef } from "react";
import { Link } from "react-router";
import { ROUTES } from "../../router/routes";
import type { ArchitectureDoc, Finding, GraphNode } from "../../schemas/results";
import { Alert, Panel, StatusBadge } from "../../components/ui";
import type { GraphSelection } from "./ArchGraph";

// Module detail (TASK-196, TASK-198). Every relationship shown is
// backend-provided: edges list incoming/outgoing pairs, cycles list
// membership, subject.modules links architecture findings, node paths list
// files. File → findings uses the contract search (q covers file paths),
// labeled as a search — no invented module→finding edges.

export function ModuleDetail({
  analysisId,
  node,
  doc,
  onSelect,
  onClose,
  returnFocusId,
}: {
  analysisId: string;
  node: GraphNode | null;
  doc: ArchitectureDoc;
  onSelect: (selection: GraphSelection) => void;
  onClose: () => void;
  returnFocusId: string | null;
}) {
  const headingRef = useRef<HTMLHeadingElement>(null);
  const previousNodeRef = useRef<string | null>(null);

  useEffect(() => {
    if (node && previousNodeRef.current !== node.node_id) {
      previousNodeRef.current = node.node_id;
      headingRef.current?.focus();
    }
    if (!node) {
      previousNodeRef.current = null;
    }
  }, [node]);

  function handleClose() {
    onClose();
    // Return focus to the invoking table row, or the search field.
    const target = returnFocusId ? document.getElementById(returnFocusId) : null;
    (target ?? document.getElementById("arch-node-search"))?.focus();
  }

  if (!node) {
    return (
      <Panel>
        <h2 className="text-lg font-semibold">Module detail</h2>
        <p className="mt-2 text-sm text-text-secondary">
          Select a module in the graph or the table to inspect its relationships, files,
          cycles, and findings.
        </p>
      </Panel>
    );
  }

  const incoming = doc.edges.filter((edge) => edge.target === node.node_id);
  const outgoing = doc.edges.filter((edge) => edge.source === node.node_id);
  const cycles = (doc.cycles ?? []).filter((cycle) => cycle.node_ids.includes(node.node_id));
  const relatedFindings = doc.findings.filter((finding: Finding) =>
    finding.subject.modules.includes(node.node_id),
  );
  const metrics = doc.metrics.filter((metric) => node.paths.includes(metric.subject_path));

  return (
    <Panel>
      <div className="flex items-start justify-between gap-3">
        <h2 ref={headingRef} tabIndex={-1} className="break-identifier font-mono text-base font-semibold outline-none">
          {node.node_id}
        </h2>
        <button
          type="button"
          onClick={handleClose}
          className="shrink-0 rounded-control border border-border px-2 py-1 text-sm text-text-secondary hover:text-text-primary"
        >
          Close
        </button>
      </div>
      <dl className="mt-3 space-y-2 text-sm">
        <div>
          <dt className="text-text-secondary">Name</dt>
          <dd className="break-identifier font-mono text-xs">{node.name}</dd>
        </div>
        <div>
          <dt className="text-text-secondary">Layer</dt>
          <dd>{node.layer ?? "Not assigned"}</dd>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {node.partially_represented ? (
            <StatusBadge label="Partially represented" tone="warning" marker="▲" />
          ) : (
            <StatusBadge label="Fully represented" tone="neutral" marker="–" />
          )}
          <span className="text-text-secondary">
            {incoming.length} incoming · {outgoing.length} outgoing relationships
          </span>
        </div>
      </dl>

      <h3 className="mt-4 text-sm font-semibold">Files</h3>
      {node.paths.length === 0 ? (
        <p className="mt-1 text-sm text-text-secondary">No files recorded for this module.</p>
      ) : (
        <ul className="mt-1 space-y-1 text-sm">
          {node.paths.map((path) => (
            <li key={path} className="flex flex-wrap items-center gap-2">
              <span className="break-identifier font-mono text-xs">{path}</span>
              <Link
                className="text-xs text-primary underline"
                to={`${ROUTES.analysisFindings(analysisId)}?q=${encodeURIComponent(path)}`}
              >
                Findings in file
              </Link>
            </li>
          ))}
        </ul>
      )}

      <h3 className="mt-4 text-sm font-semibold">Relationships</h3>
      {incoming.length === 0 && outgoing.length === 0 ? (
        <p className="mt-1 text-sm text-text-secondary">No recorded relationships.</p>
      ) : (
        <div className="mt-1 grid gap-3 md:grid-cols-2">
          <div>
            <h4 className="text-xs font-medium text-text-secondary">Depends on (outgoing)</h4>
            <ul className="mt-1 space-y-1 text-sm">
              {outgoing.map((edge) => (
                <li key={`${edge.source}→${edge.target}`}>
                  <button
                    type="button"
                    onClick={() => onSelect({ node_id: edge.target, via: "link" })}
                    className="break-identifier font-mono text-xs text-primary underline"
                  >
                    {edge.target}
                  </button>{" "}
                  <span className="text-xs text-text-secondary">· {edge.relationship_type}</span>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h4 className="text-xs font-medium text-text-secondary">Used by (incoming)</h4>
            <ul className="mt-1 space-y-1 text-sm">
              {incoming.map((edge) => (
                <li key={`${edge.source}→${edge.target}`}>
                  <button
                    type="button"
                    onClick={() => onSelect({ node_id: edge.source, via: "link" })}
                    className="break-identifier font-mono text-xs text-primary underline"
                  >
                    {edge.source}
                  </button>{" "}
                  <span className="text-xs text-text-secondary">· {edge.relationship_type}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      <h3 className="mt-4 text-sm font-semibold">Cycles</h3>
      {cycles.length === 0 ? (
        <p className="mt-1 text-sm text-text-secondary">This module is in no reported cycle.</p>
      ) : (
        <ul className="mt-1 space-y-1 text-sm">
          {cycles.map((cycle) => (
            <li key={cycle.finding_id}>
              <Link
                className="font-mono text-xs text-primary underline"
                to={ROUTES.analysisFindingDetail(analysisId, cycle.finding_id)}
              >
                {cycle.finding_id}
              </Link>{" "}
              <span className="font-mono text-xs text-text-secondary">{cycle.node_ids.join(" → ")}</span>
            </li>
          ))}
        </ul>
      )}

      <h3 className="mt-4 text-sm font-semibold">Architecture findings</h3>
      {relatedFindings.length === 0 ? (
        <p className="mt-1 text-sm text-text-secondary">
          No architecture findings reference this module.
        </p>
      ) : (
        <ul className="mt-1 space-y-1 text-sm">
          {relatedFindings.map((finding) => (
            <li key={finding.finding_id}>
              <Link
                className="font-mono text-xs text-primary underline"
                to={ROUTES.analysisFindingDetail(analysisId, finding.finding_id)}
              >
                {finding.finding_id}
              </Link>{" "}
              <span className="text-xs">
                {finding.rule_id} · {finding.severity} · {finding.confidence}
              </span>
            </li>
          ))}
        </ul>
      )}

      <h3 className="mt-4 text-sm font-semibold">Recorded metrics</h3>
      {metrics.length === 0 ? (
        <p className="mt-1 text-sm text-text-secondary">No metrics recorded for this module.</p>
      ) : (
        <ul className="mt-1 space-y-1 font-mono text-xs">
          {metrics.map((metric, index) => (
            <li key={`${metric.metric}-${index}`}>
              {metric.metric}: {metric.value ?? "unavailable"}
              {metric.potentially_incomplete ? " (potentially incomplete)" : ""}
            </li>
          ))}
        </ul>
      )}

      {node.finding_ids.length === 0 ? null : (
        <div className="mt-4">
          <Alert tone="info" title={`${node.finding_ids.length} finding(s) reference this module.`}>
            <p>See the architecture findings list above for the backend-confirmed links.</p>
          </Alert>
        </div>
      )}
    </Panel>
  );
}
