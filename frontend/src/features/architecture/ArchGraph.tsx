import { Component, type ReactNode } from "react";
import { ReactFlow, type Edge, type Node } from "@xyflow/react";
import { Alert } from "../../components/ui";
import type { GraphEdge, GraphNode } from "../../schemas/results";

// Interactive graph over canonical nodes/edges (@xyflow/react is already a
// project dependency — no new visualization stack). Layout is a
// deterministic grid in canonical order, so identical snapshots render
// identically. Node selection is mirrored by the accessible table below:
// keyboard users get full access without depending on canvas interaction.

export const MAX_RENDER_NODES = 200;
const COLUMN_COUNT = 8;
const X_GAP = 200;
const Y_GAP = 110;

export interface GraphSelection {
  node_id: string;
  via: "graph" | "table" | "link";
}

function toFlowNodes(nodes: GraphNode[], selectedId: string | null): Node[] {
  return nodes.map((node, index) => ({
    id: node.node_id,
    position: { x: (index % COLUMN_COUNT) * X_GAP, y: Math.floor(index / COLUMN_COUNT) * Y_GAP },
    data: { label: node.name },
    selected: node.node_id === selectedId,
    style: {
      border: "1px solid var(--color-border)",
      borderRadius: "8px",
      background: "var(--color-surface)",
      color: "var(--color-text-primary)",
      fontSize: "12px",
      fontFamily: "var(--font-mono)",
      padding: "8px 10px",
      width: 170,
      overflow: "hidden",
      textOverflow: "ellipsis",
      whiteSpace: "nowrap",
    },
  }));
}

function toFlowEdges(edges: GraphEdge[], renderedIds: Set<string>, selectedId: string | null): Edge[] {
  return edges
    .filter((edge) => renderedIds.has(edge.source) && renderedIds.has(edge.target))
    .map((edge) => {
      const incident = edge.source === selectedId || edge.target === selectedId;
      return {
        id: `${edge.source}→${edge.target}`,
        source: edge.source,
        target: edge.target,
        label: edge.relationship_type,
        animated: false,
        style: {
          stroke: incident ? "var(--color-primary)" : "var(--color-text-secondary)",
          strokeWidth: incident ? 2.5 : 1.5,
        },
        markerEnd: { type: "arrowclosed" as const },
      };
    });
}

export class GraphErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  constructor(properties: { children: ReactNode }) {
    super(properties);
    this.state = { failed: false };
  }

  static getDerivedStateFromError(): { failed: boolean } {
    return { failed: true };
  }

  render(): ReactNode {
    if (this.state.failed) {
      return (
        <Alert tone="error" title="The interactive graph could not be rendered.">
          <p>Use the module table below — it carries the same canonical data.</p>
        </Alert>
      );
    }
    return this.props.children;
  }
}

export function ArchGraph({
  nodes,
  edges,
  renderedNodeIds,
  selectedId,
  onSelect,
}: {
  nodes: GraphNode[];
  edges: GraphEdge[];
  renderedNodeIds: Set<string>;
  selectedId: string | null;
  onSelect: (selection: GraphSelection) => void;
}) {
  const flowNodes = toFlowNodes(nodes, selectedId);
  const flowEdges = toFlowEdges(edges, renderedNodeIds, selectedId);
  return (
    <GraphErrorBoundary>
      <div
        role="region"
        aria-label={`Architecture graph: ${nodes.length} modules, ${flowEdges.length} displayed relationships`}
        className="h-[420px] w-full rounded-control border border-border bg-secondary"
      >
        <ReactFlow
          nodes={flowNodes}
          edges={flowEdges}
          onNodeClick={(_event, node) => onSelect({ node_id: node.id, via: "graph" })}
          fitView
          minZoom={0.2}
          proOptions={{ hideAttribution: false }}
          colorMode="dark"
        />
      </div>
    </GraphErrorBoundary>
  );
}

export function CycleChips({
  nodeIds,
  onSelect,
}: {
  nodeIds: string[];
  onSelect: (selection: GraphSelection) => void;
}) {
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      {nodeIds.map((nodeId, index) => (
        <span key={nodeId} className="inline-flex items-center gap-1">
          {index > 0 ? <span aria-hidden="true" className="text-text-secondary">→</span> : null}
          <button
            type="button"
            onClick={() => onSelect({ node_id: nodeId, via: "link" })}
            aria-label={`Open module ${nodeId}`}
            className="rounded-pill border border-border px-2 py-0.5 font-mono text-xs hover:border-primary"
            title={`Open module ${nodeId}`}
          >
            {nodeId}
          </button>
        </span>
      ))}
      {nodeIds.length > 0 ? <span aria-hidden="true" className="text-text-secondary">→ ↺</span> : null}
    </span>
  );
}
