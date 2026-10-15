import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ArchGraph, GraphErrorBoundary } from "./ArchGraph";
import type { GraphNode } from "../../schemas/results";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const NODES: GraphNode[] = [
  {
    node_id: "app/a.py",
    name: "a.py",
    paths: ["app/a.py"],
    partially_represented: false,
    finding_ids: [],
  },
];

function ThrowingChild(): never {
  throw new Error("render boom");
}

describe("ArchGraph", () => {
  it("renders node labels in the interactive graph", () => {
    render(
      <ArchGraph
        nodes={NODES}
        edges={[]}
        renderedNodeIds={new Set(["app/a.py"])}
        selectedId={null}
        onSelect={() => {}}
      />,
    );
    expect(screen.getByText("a.py")).toBeDefined();
    expect(
      screen.getByRole("region", { name: /Architecture graph: 1 modules/ }),
    ).toBeDefined();
  });

  it("GraphErrorBoundary shows the fallback when graph rendering fails", () => {
    const silence = vi.spyOn(console, "error").mockImplementation(() => {});
    render(
      <GraphErrorBoundary>
        <ThrowingChild />
      </GraphErrorBoundary>,
    );
    expect(
      screen.getByText("The interactive graph could not be rendered."),
    ).toBeDefined();
    silence.mockRestore();
  });
});
