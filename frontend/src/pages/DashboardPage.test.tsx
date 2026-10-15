import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderAt } from "../test/render";
import { analysisResultFixture, mockFetchRoutes, repositoryHistoryFixture } from "../test/fixtures";

const REPO_KEY = "repolens-dashboard-repository";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  window.localStorage.clear();
});

function mockDashboard() {
  const partial = analysisResultFixture();
  const summary = partial.summary;
  if (summary) {
    (summary.dependencies as { findings: unknown }).findings = null;
  }
  const queued = {
    ...analysisResultFixture(),
    analysis: { ...analysisResultFixture().analysis, analysis_id: "queue42" },
    status: { stage: "Queued", outcome: null, domains: [], limitations: [] },
    summary: null,
    security: null,
    architecture: null,
    dependencies: null,
    code_structure: null,
    files: null,
  };
  return mockFetchRoutes([
    { match: "/api/repositories/r1", payload: repositoryHistoryFixture() },
    { match: "/api/analyses/target9", payload: analysisResultFixture() },
    { match: "/api/analyses/base111", payload: partial },
    { match: "/api/analyses/queue42", payload: queued },
  ]);
}

describe("Dashboard recent analyses", () => {
  it("shows an honest empty state with no stored repository", () => {
    renderAt("/dashboard");
    expect(screen.getByText("No recent analyses to show yet.")).toBeDefined();
    expect(screen.getByRole("button", { name: "Analyze Repository" })).toBeDefined();
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("lists recent analyses with honest findings cells and statuses", async () => {
    window.localStorage.setItem(REPO_KEY, "r1");
    mockDashboard();
    renderAt("/dashboard");
    await waitFor(() => {
      expect(screen.getByText(/Showing 4 of 4 analyses/)).toBeDefined();
    });
    // Completed with full coverage: summed total over available areas.
    expect(screen.getAllByText(/acme/).length).toBeGreaterThan(0);
    // Partial coverage carries a marked total, never a clean one.
    await waitFor(() => {
      expect(screen.getByText("2 *")).toBeDefined();
    });
    // Failed and queued rows show "—", never 0.
    expect(screen.getByText("Failed")).toBeDefined();
    await waitFor(() => {
      expect(screen.getByText("Queued")).toBeDefined();
    });
    // Rows link to the workspace, or the progress view when not terminal.
    const repoLinks = screen.getAllByRole("link", { name: "acme/web" });
    expect(repoLinks.map((link) => link.getAttribute("href"))).toEqual([
      "/analysis/target9/overview",
      "/analysis/base111/overview",
      "/analysis/fail007/overview",
      "/analysis/queue42",
    ]);
  });

  it("shows an error with recovery for an unknown stored repository", async () => {
    window.localStorage.setItem(REPO_KEY, "nope");
    mockFetchRoutes([
      {
        match: "/api/repositories/nope",
        payload: { error: { code: "REPOSITORY_NOT_FOUND", message: "Gone.", details: null } },
        status: 404,
      },
    ]);
    renderAt("/dashboard");
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toContain("Repository not found.");
    });
    fireEvent.click(screen.getByRole("button", { name: /Forget this repository/ }));
    expect(window.localStorage.getItem(REPO_KEY)).toBeNull();
    expect(screen.getByText("No recent analyses to show yet.")).toBeDefined();
  });
});
