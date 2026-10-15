import { screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderAt } from "../../test/render";
import { analysisResultFixture, findingFixture, findingsPageFixture, mockFetchRoutes } from "../../test/fixtures";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("Security page", () => {
  it("locks the category filter to the canonical security identifier", async () => {
    const calls = mockFetchRoutes([
      { match: "/api/analyses/abc123", payload: analysisResultFixture() },
      { match: "/findings", payload: findingsPageFixture([findingFixture()], 1) },
    ]);
    renderAt("/analysis/abc123/security");
    await waitFor(() => {
      expect(screen.getByText("SEC-HARDCODED-SECRET")).toBeDefined();
    });
    expect(calls.some((url) => url.includes("/findings") && url.includes("category=security"))).toBe(true);
    expect(screen.queryByText("Category", { selector: "legend" })).toBeNull();
  });

  it("never presents an unavailable section as clean", async () => {
    const result = analysisResultFixture();
    (result as { security?: unknown }).security = null;
    result.status.domains = [
      { area: "security", state: "Analysis unavailable", reason: "No supported content." },
      { area: "architecture", state: null, reason: null },
      { area: "dependency", state: "No findings detected", reason: null },
      { area: "code_structure", state: "No findings detected", reason: null },
    ];
    mockFetchRoutes([{ match: "/api/analyses/abc123", payload: result }]);
    renderAt("/analysis/abc123/security");
    await waitFor(() => {
      expect(screen.getByText("Security results are unavailable for this analysis.")).toBeDefined();
    });
    expect(screen.getByText(/not a clean result/)).toBeDefined();
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("waits for completion instead of showing an empty table", async () => {
    const result = analysisResultFixture({
      status: { stage: "RunningAnalysis", outcome: null, domains: [], limitations: [] },
      summary: null,
      security: null,
      architecture: null,
      dependencies: null,
      code_structure: null,
    } as never);
    mockFetchRoutes([{ match: "/api/analyses/abc123", payload: result }]);
    renderAt("/analysis/abc123/security");
    await waitFor(() => {
      expect(screen.getByText(/not completed/)).toBeDefined();
    });
    expect(screen.queryByRole("table")).toBeNull();
  });
});
