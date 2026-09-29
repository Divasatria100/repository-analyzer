// Visualization smoke test (TASK-016). Components below are test-local
// fixtures proving React Flow and Recharts integrate — they are NOT
// domain graphs/charts and MUST NOT move into application state.
import { render, screen } from "@testing-library/react";
import { ReactFlow, type Edge, type Node } from "@xyflow/react";
import { describe, expect, it } from "vitest";
import { Bar, BarChart, XAxis, YAxis } from "recharts";

const nodes: Node[] = [
  { id: "a", position: { x: 0, y: 0 }, data: { label: "smoke-a" } },
  { id: "b", position: { x: 120, y: 0 }, data: { label: "smoke-b" } },
  { id: "c", position: { x: 240, y: 0 }, data: { label: "smoke-c" } },
];

const edges: Edge[] = [
  { id: "a-b", source: "a", target: "b" },
  { id: "b-c", source: "b", target: "c" },
];

const metrics = [
  { name: "m1", value: 3 },
  { name: "m2", value: 7 },
];

describe("visualization integration smoke", () => {
  it("renders a minimal React Flow graph", () => {
    render(
      <div style={{ width: 400, height: 300 }}>
        <ReactFlow nodes={nodes} edges={edges} />
      </div>,
    );
    expect(screen.getByText("smoke-a")).toBeDefined();
    expect(screen.getByText("smoke-c")).toBeDefined();
  });

  it("renders a minimal Recharts chart", () => {
    const { container } = render(
      <BarChart width={400} height={300} data={metrics}>
        <XAxis dataKey="name" />
        <YAxis />
        <Bar dataKey="value" isAnimationActive={false} />
      </BarChart>,
    );
    expect(container.querySelector("svg")).not.toBeNull();
  });
});
