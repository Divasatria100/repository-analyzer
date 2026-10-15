import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderAt } from "../../test/render";
import {
  analysisResultFixture,
  comparisonFixture,
  mockFetchRoutes,
  repositoryHistoryFixture,
} from "../../test/fixtures";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function baseResult() {
  const result = analysisResultFixture();
  const analysis = result.analysis as { analysis_id?: string };
  analysis.analysis_id = "base111";
  return result;
}

describe("Comparison page", () => {
  it("offers completed same-repository analyses as base candidates", async () => {
    const target = analysisResultFixture();
    let targetCalls = 0;
    const base = baseResult();
    const withComparison = analysisResultFixture({ comparison: comparisonFixture() } as never);
    window.fetch = vi.fn().mockImplementation((input: RequestInfo | URL) => {
      const url = String(input);
      let payload: unknown = {};
      if (url.includes("/api/repositories/r1")) {
        payload = repositoryHistoryFixture();
      } else if (url.includes("/api/analyses/base111")) {
        payload = base;
      } else if (url.includes("/api/analyses/target9")) {
        targetCalls += 1;
        payload = targetCalls === 1 ? target : withComparison;
      }
      return Promise.resolve({
        ok: true,
        status: 200,
        text: () => Promise.resolve(JSON.stringify(payload)),
      } as Response);
    });
    renderAt("/analysis/target9/comparison");
    await waitFor(
      () => {
        expect(screen.getByRole("heading", { name: "Compare analyses" })).toBeDefined();
      },
      { timeout: 3000 },
    );
    // Failed and queued entries are not offered; completed ones are.
    expect(screen.getByText("base111")).toBeDefined();
    expect(screen.queryByText("fail007")).toBeNull();
    expect(screen.queryByText("queue42")).toBeNull();
    fireEvent.click(screen.getByRole("radio", { name: /base111/ }));
    fireEvent.click(screen.getByRole("button", { name: "Compare" }));
    // After picking a base, the comparison view loads with identity lists.
    await waitFor(
      () => {
        expect(screen.getByRole("heading", { name: "Comparison" })).toBeDefined();
      },
      { timeout: 3000 },
    );
    expect(screen.getByRole("button", { name: /new/ })).toBeDefined();
  });

  it("renders contexts, differences, lists, and qualified marks", async () => {
    const target = analysisResultFixture({ comparison: comparisonFixture() } as never);
    mockFetchRoutes([
      { match: "/api/analyses/target9", payload: target },
      { match: "/api/analyses/base111", payload: baseResult() },
    ]);
    renderAt("/analysis/target9/comparison?base=base111");
    await waitFor(
      () => {
        expect(screen.getByRole("heading", { name: "Comparison" })).toBeDefined();
      },
      { timeout: 3000 },
    );
    expect(screen.getByText("Base analysis")).toBeDefined();
    expect(screen.getByText("Target analysis")).toBeDefined();
    expect(screen.getByText(/advisory_data/)).toBeDefined();
    // New tab is default: F-0001 with a target detail link.
    expect(screen.getByRole("link", { name: "Open" }).getAttribute("href")).toBe(
      "/analysis/target9/findings/F-0001",
    );
    fireEvent.click(screen.getByRole("button", { name: /resolved/ }));
    await waitFor(() => {
      expect(screen.getByText("Resolved (qualified)")).toBeDefined();
    });
    expect(
      screen.getAllByText(/may reflect unevaluated scope/).length,
    ).toBeGreaterThanOrEqual(2);
    fireEvent.click(screen.getByRole("button", { name: /unchanged/ }));
    await waitFor(() => {
      expect(screen.getByRole("link", { name: "base" })).toBeDefined();
    });
    expect(screen.getByRole("link", { name: "target" })).toBeDefined();
    const body = document.body.textContent ?? "";
    expect(body).not.toMatch(/improvement|percent|health|trend/i);
    expect(screen.getByText(/No change scores are computed/)).toBeDefined();
  });

  it("reports non-comparable pairs with the backend reason", async () => {
    const target = analysisResultFixture({
      comparison: { comparable: false, reason: "Analyses belong to different repositories." },
    } as never);
    mockFetchRoutes([
      { match: "/api/analyses/target9", payload: target },
      { match: "/api/analyses/base111", payload: baseResult() },
    ]);
    renderAt("/analysis/target9/comparison?base=base111");
    await waitFor(() => {
      expect(screen.getByText("These analyses cannot be compared.")).toBeDefined();
    });
    expect(screen.getByText(/different repositories/)).toBeDefined();
  });

  it("handles an unknown base analysis", async () => {
    mockFetchRoutes([
      { match: "/api/analyses/target9", payload: analysisResultFixture() },
      {
        match: "/api/analyses/nope",
        payload: { error: { code: "ANALYSIS_NOT_FOUND", message: "Gone.", details: null } },
        status: 404,
      },
    ]);
    renderAt("/analysis/target9/comparison?base=nope");
    await waitFor(
      () => {
        expect(screen.getByRole("alert").textContent).toContain("Analysis not found.");
      },
      { timeout: 3000 },
    );
  });

  it("handles a non-completed base analysis", async () => {
    mockFetchRoutes([
      { match: "/api/analyses/target9", payload: analysisResultFixture() },
      {
        match: "/api/analyses/queued1",
        payload: { error: { code: "ANALYSIS_NOT_COMPLETED", message: "Not done.", details: null } },
        status: 409,
      },
    ]);
    renderAt("/analysis/target9/comparison?base=queued1");
    await waitFor(
      () => {
        expect(screen.getByRole("alert").textContent).toContain("completed analyses");
      },
      { timeout: 3000 },
    );
  });
});
