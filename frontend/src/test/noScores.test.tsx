import { screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderAt } from "./render";
import {
  analysisResultFixture,
  architectureFixture,
  comparisonFixture,
  findingsPageFixture,
  findingFixture,
  mockFetchRoutes,
  repositoryHistoryFixture,
} from "./fixtures";

// TASK-215 regression: no overall score, ranking, or aggregate quality UI
// may exist anywhere in the workspace. Severity badges, confidence badges,
// individual metric values, and descriptive counts are legitimate and must
// remain; only aggregate judgments are forbidden.

const FORBIDDEN = [
  /overall score/i,
  /health score/i,
  /weighted score/i,
  /quality score/i,
  /risk score/i,
  /security score/i,
  /repository ranking/i,
  /aggregate ranking/i,
  /leaderboard/i,
  /health indicator/i,
  /\bKPI\b/,
];

function mockWorkspace() {
  mockFetchRoutes([
    { match: "/api/repositories/r1", payload: repositoryHistoryFixture() },
    { match: "/api/analyses/abc123", payload: analysisResultFixture() },
    { match: "/architecture", payload: architectureFixture() },
    { match: "/findings", payload: findingsPageFixture([findingFixture()], 1) },
  ]);
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  window.localStorage.clear();
});

describe.each([
  ["/dashboard", "Dashboard"],
  ["/analysis/abc123/overview", "Overview"],
  ["/analysis/abc123/findings", "Findings"],
  ["/analysis/abc123/security", "Security"],
  ["/analysis/abc123/architecture", "Architecture"],
  ["/analysis/abc123/dependencies", "Dependencies"],
  ["/analysis/abc123/code-structure", "Code Structure"],
  ["/analysis/abc123/files", "Files"],
  ["/analysis/abc123/report", "Report"],
])("no aggregate scores on %s", (path) => {
  it("renders without forbidden score/ranking language", async () => {
    window.localStorage.setItem("repolens-dashboard-repository", "r1");
    mockWorkspace();
    renderAt(path);
    await waitFor(
      () => {
        expect(document.body.textContent?.trim().length).toBeGreaterThan(0);
      },
      { timeout: 3000 },
    );
    // Let async content settle so the scan covers loaded states too.
    await new Promise((resolve) => setTimeout(resolve, 250));
    const body = document.body.textContent ?? "";
    for (const pattern of FORBIDDEN) {
      expect(body).not.toMatch(pattern);
    }
    // Legitimate signals must survive the prohibition.
    expect(body).toMatch(/High|Completed|finding|analysis/i);
  });
});

describe("comparison has no change scores", () => {
  it("renders labels without improvement claims", async () => {
    const target = analysisResultFixture({ comparison: comparisonFixture() } as never);
    mockFetchRoutes([
      { match: "/api/analyses/target9", payload: target },
      { match: "/api/analyses/base111", payload: analysisResultFixture() },
    ]);
    renderAt("/analysis/target9/comparison?base=base111");
    await waitFor(
      () => {
        expect(screen.getByRole("heading", { name: "Comparison" })).toBeDefined();
      },
      { timeout: 3000 },
    );
    const body = document.body.textContent ?? "";
    for (const pattern of FORBIDDEN) {
      expect(body).not.toMatch(pattern);
    }
    expect(screen.getByText(/No change scores are computed/)).toBeDefined();
  });
});
