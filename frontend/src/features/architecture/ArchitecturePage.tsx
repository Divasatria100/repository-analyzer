import { useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { ApiRequestError, getArchitecture } from "../../lib/api";
import { ANALYSIS_ID_PARAM, ROUTES } from "../../router/routes";
import { Alert, LoadingState, Panel, StatusBadge } from "../../components/ui";
import { ArchGraph, CycleChips, MAX_RENDER_NODES, type GraphSelection } from "./ArchGraph";
import { ModuleDetail } from "./ModuleDetail";

// Architecture workspace (TASK-194–198). The bounded architecture document
// (§4.4) is the only data source: nodes, edges, cycles, findings, and
// metrics are rendered as received. Filtering/search affect only the
// client-side visualization and are labeled as such; canonical data is never
// mutated. A capped interactive graph is always accompanied by the complete
// tabular representation and explicit subset labeling.

const TABLE_PAGE_SIZE = 50;
const UNRESOLVED_DISPLAY_LIMIT = 50;

function useArchitectureDoc(analysisId: string) {
  return useQuery({
    queryKey: ["architecture", analysisId],
    queryFn: ({ signal }) => getArchitecture(analysisId, signal),
    retry: (count, error) => {
      if (error instanceof ApiRequestError && error.code === "ANALYSIS_NOT_FOUND") {
        return false;
      }
      return count < 1;
    },
  });
}

export function ArchitecturePage() {
  const params = useParams();
  const analysisId = params[ANALYSIS_ID_PARAM] ?? "";
  const [searchParams, setSearchParams] = useSearchParams();
  const [tablePage, setTablePage] = useState(1);

  const selectedId = searchParams.get("module");
  const textFilter = searchParams.get("q") ?? "";
  const layerFilter = searchParams.get("layer") ?? "";
  const relFilter = searchParams.get("rel") ?? "";
  const cyclesOnly = searchParams.get("cycles") === "1";

  const { data, error, isLoading, refetch, isFetching } = useArchitectureDoc(analysisId);

  const layers = useMemo(() => {
    const values = new Set<string>();
    for (const node of data?.nodes ?? []) {
      if (node.layer) values.add(node.layer);
    }
    return [...values].sort();
  }, [data]);

  const relTypes = useMemo(() => {
    const values = new Set<string>();
    for (const edge of data?.edges ?? []) {
      values.add(edge.relationship_type);
    }
    return [...values].sort();
  }, [data]);

  const cycleMembers = useMemo(() => {
    const members = new Set<string>();
    for (const cycle of data?.cycles ?? []) {
      for (const nodeId of cycle.node_ids) members.add(nodeId);
    }
    return members;
  }, [data]);

  const filteredNodes = useMemo(() => {
    const needle = textFilter.trim().toLowerCase();
    return (data?.nodes ?? []).filter((node) => {
      if (layerFilter && node.layer !== layerFilter) return false;
      if (cyclesOnly && !cycleMembers.has(node.node_id)) return false;
      if (!needle) return true;
      return (
        node.node_id.toLowerCase().includes(needle) ||
        node.name.toLowerCase().includes(needle) ||
        node.paths.some((path) => path.toLowerCase().includes(needle))
      );
    });
  }, [data, textFilter, layerFilter, cyclesOnly, cycleMembers]);

  const filteredEdges = useMemo(() => {
    const ids = new Set(filteredNodes.map((node) => node.node_id));
    return (data?.edges ?? []).filter(
      (edge) =>
        ids.has(edge.source) &&
        ids.has(edge.target) &&
        (!relFilter || edge.relationship_type === relFilter),
    );
  }, [data, filteredNodes, relFilter]);

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
    setTablePage(1);
  }

  function handleSelect(selection: GraphSelection) {
    updateFilter({ module: selection.node_id });
  }

  if (isLoading) {
    return <LoadingState label="Loading architecture…" />;
  }

  if (error || !data) {
    const apiError = error instanceof ApiRequestError ? error : null;
    const unavailable =
      apiError?.code === "REPORT_UNAVAILABLE" || apiError?.code === "ANALYSIS_NOT_COMPLETED";
    return (
      <Panel>
        <Alert
          tone={apiError?.code === "ANALYSIS_NOT_FOUND" ? "error" : "warning"}
          title={
            apiError?.code === "ANALYSIS_NOT_FOUND"
              ? "Analysis not found."
              : unavailable
                ? "Architecture results are unavailable for this analysis."
                : "Could not load architecture."
          }
        >
          <p>
            {unavailable
              ? "The architecture section is null for this analysis state. This is not an empty graph."
              : (apiError?.message ?? "An unexpected error occurred.")}
          </p>
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

  const renderedNodes = filteredNodes.slice(0, MAX_RENDER_NODES);
  const renderedIds = new Set(renderedNodes.map((node) => node.node_id));
  const capped = filteredNodes.length > renderedNodes.length;
  const hasActiveFilters = textFilter.trim() !== "" || layerFilter !== "" || relFilter !== "" || cyclesOnly;
  const selectedNode = data.nodes.find((node) => node.node_id === selectedId) ?? null;
  const tablePages = Math.max(1, Math.ceil(filteredNodes.length / TABLE_PAGE_SIZE));
  const tableRows = filteredNodes.slice((tablePage - 1) * TABLE_PAGE_SIZE, tablePage * TABLE_PAGE_SIZE);
  const unresolved = data.external_and_unresolved_references;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-lg font-semibold">Architecture</h2>
        {data.potentially_incomplete ? (
          <StatusBadge label="Potentially incomplete" tone="warning" marker="▲" />
        ) : (
          <StatusBadge label="Graph available" tone="neutral" marker="–" />
        )}
        <span className="text-sm text-text-secondary">
          {data.nodes.length} modules · {data.edges.length} relationships
          {data.granularity ? ` · granularity: ${data.granularity}` : ""}
        </span>
      </div>
      {data.potentially_incomplete ? (
        <Alert tone="warning" title="The graph may be incomplete.">
          <p>Unparsed files or unresolved references may affect these results.</p>
        </Alert>
      ) : null}

      <Panel>
        <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
          <div>
            <label htmlFor="arch-node-search" className="mb-1 block text-sm font-medium">
              Search modules
            </label>
            <input
              id="arch-node-search"
              type="search"
              value={textFilter}
              onChange={(event) => updateFilter({ q: event.target.value })}
              placeholder="module id, name, or path"
              autoComplete="off"
              spellCheck={false}
              className="w-full rounded-control border border-border bg-secondary px-3 py-2 font-mono text-sm placeholder:text-text-secondary"
            />
          </div>
          <div>
            <label htmlFor="arch-layer" className="mb-1 block text-sm font-medium">
              Layer
            </label>
            <select
              id="arch-layer"
              value={layerFilter}
              onChange={(event) => updateFilter({ layer: event.target.value })}
              className="w-full rounded-control border border-border bg-secondary px-2 py-2 text-sm"
            >
              <option value="">All layers</option>
              {layers.map((layer) => (
                <option key={layer} value={layer}>
                  {layer}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="arch-rel" className="mb-1 block text-sm font-medium">
              Relationship type
            </label>
            <select
              id="arch-rel"
              value={relFilter}
              onChange={(event) => updateFilter({ rel: event.target.value })}
              className="w-full rounded-control border border-border bg-secondary px-2 py-2 text-sm"
            >
              <option value="">All types</option>
              {relTypes.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
          </div>
          <div className="flex items-end gap-3">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={cyclesOnly}
                onChange={(event) => updateFilter({ cycles: event.target.checked ? "1" : null })}
              />
              In cycles only
            </label>
            <button
              type="button"
              onClick={() => {
                setSearchParams(new URLSearchParams(selectedId ? { module: selectedId } : undefined));
                setTablePage(1);
              }}
              className="rounded-control border border-border px-2 py-1 text-sm text-text-secondary hover:text-text-primary"
            >
              Reset filters
            </button>
          </div>
        </div>
        <p className="mt-2 text-xs text-text-secondary">
          Filters affect this visualization only; the backend graph is unchanged.{" "}
          {filteredNodes.length} of {data.nodes.length} modules match.
        </p>
      </Panel>

      {filteredNodes.length === 0 ? (
        <Panel>
          {hasActiveFilters ? (
            <Alert tone="info" title="No modules match these filters.">
              <p>Adjust or reset the filters. This is not missing architecture data.</p>
            </Alert>
          ) : (
            <p className="text-sm text-text-secondary">
              This architecture graph contains no modules.
            </p>
          )}
        </Panel>
      ) : (
        <Panel>
          <ArchGraph
            nodes={renderedNodes}
            edges={filteredEdges}
            renderedNodeIds={renderedIds}
            selectedId={selectedId}
            onSelect={handleSelect}
          />
          <p className="mt-2 text-xs text-text-secondary">
            {capped
              ? `Showing ${renderedNodes.length} of ${filteredNodes.length} matching modules in the interactive graph. Relationships are shown only between displayed modules. The table below lists every matching module.`
              : `Showing all ${renderedNodes.length} matching modules. The table below lists the same modules with identical identities.`}
          </p>
        </Panel>
      )}

      <ModuleDetail
        analysisId={analysisId}
        node={selectedNode}
        doc={data}
        onSelect={handleSelect}
        onClose={() => updateFilter({ module: null })}
        returnFocusId={selectedId ? `node-details-${selectedId}` : null}
      />
      {selectedId && !selectedNode ? (
        <Alert tone="warning" title={`Unknown module "${selectedId}".`}>
          <p>No module with this identity exists in the architecture result.</p>
        </Alert>
      ) : null}

      <Panel title="Dependency cycles" labelledBy="arch-cycles">
        {data.cycles == null ? (
          <p className="text-sm text-text-secondary">
            Cycle information is unavailable for this analysis — not zero cycles.
          </p>
        ) : data.cycles.length === 0 ? (
          <p className="text-sm text-text-secondary">No dependency cycles reported.</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {data.cycles.map((cycle) => (
              <li key={cycle.finding_id} className="rounded-control border border-border px-3 py-2">
                <Link
                  className="font-mono text-xs text-primary underline"
                  to={ROUTES.analysisFindingDetail(analysisId, cycle.finding_id)}
                >
                  {cycle.finding_id}
                </Link>
                <div className="mt-1">
                  <CycleChips nodeIds={cycle.node_ids} onSelect={handleSelect} />
                </div>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel title="Modules" labelledBy="arch-modules">
        <p className="mb-3 text-sm text-text-secondary" aria-live="polite">
          {`${filteredNodes.length} matching modules · page ${tablePage} of ${tablePages}. Use Details for keyboard-accessible module inspection.`}
        </p>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] text-left text-sm">
            <thead>
              <tr className="border-b border-border text-text-secondary">
                <th scope="col" className="py-2 pr-4 font-medium">Module</th>
                <th scope="col" className="py-2 pr-4 font-medium">Layer</th>
                <th scope="col" className="py-2 pr-4 font-medium">Representation</th>
                <th scope="col" className="py-2 pr-4 font-medium">Findings</th>
                <th scope="col" className="py-2 font-medium">Detail</th>
              </tr>
            </thead>
            <tbody>
              {tableRows.map((node) => (
                <tr key={node.node_id} className="border-b border-border last:border-0">
                  <td className="break-identifier py-2 pr-4 font-mono text-xs">{node.node_id}</td>
                  <td className="py-2 pr-4 text-xs">{node.layer ?? "—"}</td>
                  <td className="py-2 pr-4 text-xs">
                    {node.partially_represented ? "Partial ▲" : "Full"}
                  </td>
                  <td className="py-2 pr-4 font-mono text-xs">{node.finding_ids.length}</td>
                  <td className="py-2">
                    <button
                      id={`node-details-${node.node_id}`}
                      type="button"
                      onClick={() => handleSelect({ node_id: node.node_id, via: "table" })}
                      className="text-xs text-primary underline"
                      aria-label={`Open details for module ${node.node_id}`}
                    >
                      Details
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-4 flex items-center gap-3 text-sm">
          <button
            type="button"
            disabled={tablePage <= 1}
            onClick={() => setTablePage((page) => page - 1)}
            className="rounded-control border border-border px-3 py-1 hover:border-primary disabled:opacity-40"
          >
            Previous
          </button>
          <span>
            Page {tablePage} of {tablePages}
          </span>
          <button
            type="button"
            disabled={tablePage >= tablePages}
            onClick={() => setTablePage((page) => page + 1)}
            className="rounded-control border border-border px-3 py-1 hover:border-primary disabled:opacity-40"
          >
            Next
          </button>
        </div>
      </Panel>

      <Panel title="External and unresolved references" labelledBy="arch-unresolved">
        {unresolved.length === 0 ? (
          <p className="text-sm text-text-secondary">None recorded.</p>
        ) : (
          <>
            <p className="mb-2 text-sm text-text-secondary">
              {unresolved.length} references did not resolve to internal modules
              {unresolved.length > UNRESOLVED_DISPLAY_LIMIT
                ? ` — showing the first ${UNRESOLVED_DISPLAY_LIMIT}.`
                : "."}
            </p>
            <ul className="space-y-1 font-mono text-xs">
              {unresolved.slice(0, UNRESOLVED_DISPLAY_LIMIT).map((item, index) => {
                const record = item as Record<string, unknown>;
                return (
                  <li key={index} className="break-identifier">
                    {String(record["source"] ?? "?")} · {String(record["resolution"] ?? "?")} ·{" "}
                    {String(record["target_reference"] ?? "?")}
                  </li>
                );
              })}
            </ul>
          </>
        )}
      </Panel>
    </div>
  );
}
