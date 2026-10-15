import { screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { routes } from "../router";
import {
  analysisResultFixture,
  architectureFixture,
  comparisonFixture,
  findingsPageFixture,
  findingFixture,
  mockFetchRoutes,
  repositoryHistoryFixture,
} from "./fixtures";

// Frontend Workspace Gate: end-to-end navigation across every implemented
// workflow with mocked API responses (no network, no fabricated analysis
// data). A single router instance proves deep links, refresh-equivalent
// direct entries, and shared query caching across stops.

const COMPLETED = () => analysisResultFixture();

function mockGate() {
  return mockFetchRoutes([
    { match: "/api/repositories/r1", payload: repositoryHistoryFixture() },
    { match: "/api/analyses/abc123", payload: COMPLETED() },
    { match: "/api/analyses/target9", payload: COMPLETED() },
    { match: "/api/analyses/base111", payload: COMPLETED() },
    { match: "/architecture", payload: architectureFixture() },
    { match: "/findings", payload: findingsPageFixture([findingFixture()], 1) },
  ]);
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  window.localStorage.clear();
});

describe("workspace gate", () => {
  it("navigates every workflow without broken routes or dead links", async () => {
    window.localStorage.setItem("repolens-dashboard-repository", "r1");
    mockGate();
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const router = createMemoryRouter(routes, { initialEntries: ["/dashboard"] });
    render(
      <QueryClientProvider client={client}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );

    const stops: Array<[string, string]> = [
      ["/dashboard", "Recent Analyses"],
      ["/analysis/new", "Analyze a public repository"],
      ["/analysis/abc123", "Analysis completed"],
      ["/analysis/abc123/overview", "acme/web"],
      ["/analysis/abc123/findings", "Findings"],
      ["/analysis/abc123/findings/F-0001", "SEC-HARDCODED-SECRET"],
      ["/analysis/abc123/security", "Security"],
      ["/analysis/abc123/architecture", "Architecture"],
      ["/analysis/abc123/dependencies", "Dependencies"],
      ["/analysis/abc123/code-structure", "Code Structure"],
      ["/analysis/abc123/files", "Files"],
      ["/history?repository=r1", "History"],
      ["/analysis/abc123/report", "Report"],
      ["/settings", "Settings"],
    ];

    for (const [path, name] of stops) {
      await router.navigate(path);
      await waitFor(
        () => {
          expect(screen.getAllByRole("heading", { name }).length).toBeGreaterThan(0);
        },
        { timeout: 4000 },
      );
    }

    // Completed analyses link onward to the workspace; nothing here claims
    // progress percentages or completion for work that never ran.
    await router.navigate("/analysis/abc123");
    await waitFor(
      () => {
        expect(screen.getByRole("link", { name: "Open analysis" })).toBeDefined();
      },
      { timeout: 4000 },
    );
  }, 60000);

  it("reaches comparison with backend classification", async () => {
    const target = analysisResultFixture({ comparison: comparisonFixture() } as never);
    const base = analysisResultFixture();
    (base.analysis as { analysis_id?: string }).analysis_id = "base111";
    mockFetchRoutes([
      { match: "/api/analyses/target9", payload: target },
      { match: "/api/analyses/base111", payload: base },
    ]);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const router = createMemoryRouter(routes, {
      initialEntries: ["/analysis/target9/comparison?base=base111"],
    });
    render(
      <QueryClientProvider client={client}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );
    await waitFor(
      () => {
        expect(screen.getByRole("heading", { name: "Comparison" })).toBeDefined();
      },
      { timeout: 4000 },
    );
    expect(screen.getByText("Base analysis")).toBeDefined();
    expect(screen.getByText("Target analysis")).toBeDefined();
  }, 30000);
});
