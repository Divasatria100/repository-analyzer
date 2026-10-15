import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderAt } from "../../test/render";
import {
  analysisResultFixture,
  codeFindingFixture,
  mockFetchRoutes,
} from "../../test/fixtures";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function renderCodeStructure(path = "/analysis/abc123/code-structure") {
  mockFetchRoutes([{ match: "/api/analyses/abc123", payload: analysisResultFixture() }]);
  return renderAt(path);
}

describe("Code Structure page", () => {
  it("renders metric tables sorted by value descending with finding links", async () => {
    renderCodeStructure();
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Code Structure" })).toBeDefined();
    });
    expect(screen.getByText("render")).toBeDefined();
    expect(screen.getByText("18")).toBeDefined();
    expect(screen.getByText("CODE-HIGH-COMPLEXITY")).toBeDefined();
    expect(screen.getByRole("link", { name: "F-0031" }).getAttribute("href")).toBe(
      "/analysis/abc123/findings/F-0031",
    );
  });

  it("shows unavailable metrics as unavailable, never zero", async () => {
    renderCodeStructure();
    await waitFor(() => {
      expect(screen.getByText("render")).toBeDefined();
    });
    expect(screen.getByText("unavailable")).toBeDefined();
    expect(screen.queryByText("potentially incomplete")).toBeNull();
  });

  it("switches tables via the segmented control with deep-link state", async () => {
    renderCodeStructure();
    await waitFor(() => {
      expect(screen.getByText("render")).toBeDefined();
    });
    fireEvent.click(screen.getByRole("button", { name: "Nesting depth" }));
    await waitFor(() => {
      expect(screen.getByText("5")).toBeDefined();
    });
    fireEvent.click(screen.getByRole("button", { name: "Size" }));
    expect(screen.getByText("No metrics recorded for this table.")).toBeDefined();
  });

  it("groups hotspots without computing scores", async () => {
    const second = codeFindingFixture({
      finding_id: "F-0032",
      identity_key: "ik-0032",
      rule_id: "CODE-DEEP-NESTING",
      rule_name: "Deep Nesting",
      severity: "Low",
      evidence: {
        redacted: false,
        source_context: null,
        measurements: [{ metric: "nesting_depth", value: 5, exceeded: true }],
      },
    });
    const result = analysisResultFixture();
    const section = result.code_structure;
    if (section && "findings" in section) {
      section.findings.push(second);
    }
    mockFetchRoutes([{ match: "/api/analyses/abc123", payload: result }]);
    renderAt("/analysis/abc123/code-structure?table=hotspots");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Hotspots" })).toBeDefined();
    });
    expect(screen.getByText("app/a.py:40")).toBeDefined();
    expect(screen.getByText(/complexity: 18/)).toBeDefined();
    expect(screen.getByText(/nesting_depth: 5/)).toBeDefined();
    const body = document.body.textContent ?? "";
    // "score" alone also names the contract metric unit and the UI states
    // that no combined score exists; only computed judgments are forbidden.
    expect(body).not.toMatch(/health score|quality score|overall score|ranking|leaderboard/i);
    expect(screen.queryByText(/total:/i)).toBeNull();
  });

  it("shows an honest empty state when no hotspot qualifies", async () => {
    renderCodeStructure("/analysis/abc123/code-structure?table=hotspots");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Hotspots" })).toBeDefined();
    });
    expect(screen.getByText("No hotspots reported.")).toBeDefined();
  });

  it("lists duplicate candidates with the backend-ordered primary location", async () => {
    const duplicate = codeFindingFixture({
      finding_id: "F-0040",
      identity_key: "ik-0040",
      rule_id: "CODE-DUPLICATE-CANDIDATE",
      rule_name: "Duplicate Candidate",
      severity: "Info",
      confidence: "Medium",
      subject: {
        locations: [
          { path: "app/a.py", start_line: 10, end_line: 20, start_column: 0, end_column: 0 },
          { path: "app/b.py", start_line: 30, end_line: 40, start_column: 0, end_column: 0 },
        ],
        modules: [],
        dependencies: [],
      },
      evidence: { redacted: false, source_context: null },
    });
    const result = analysisResultFixture();
    const section = result.code_structure;
    if (section && "findings" in section) {
      section.findings.push(duplicate);
    }
    mockFetchRoutes([{ match: "/api/analyses/abc123", payload: result }]);
    renderAt("/analysis/abc123/code-structure?table=duplicates");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Duplicate candidates" })).toBeDefined();
    });
    expect(screen.getByText(/primary: app\/a\.py:10/)).toBeDefined();
    expect(screen.getByText(/app\/b\.py:30/)).toBeDefined();
  });

  it("never presents an unavailable section as clean", async () => {
    const result = analysisResultFixture();
    (result as { code_structure?: unknown }).code_structure = null;
    result.status.domains = [
      { area: "security", state: null, reason: null },
      { area: "architecture", state: null, reason: null },
      { area: "dependency", state: "No findings detected", reason: null },
      { area: "code_structure", state: "Analysis unavailable", reason: "No Python files." },
    ];
    mockFetchRoutes([{ match: "/api/analyses/abc123", payload: result }]);
    renderAt("/analysis/abc123/code-structure");
    await waitFor(() => {
      expect(
        screen.getByText("Code structure results are unavailable for this analysis."),
      ).toBeDefined();
    });
    expect(screen.queryByRole("table")).toBeNull();
  });
});
