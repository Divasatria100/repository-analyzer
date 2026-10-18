import { screen, waitFor, within } from "@testing-library/react";
import { fireEvent } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderAt } from "../../test/render";
import {
  analysisResultFixture,
  findingFixture,
  findingsPageFixture,
  mockFetchRoutes,
} from "../../test/fixtures";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function mockOverview(result: unknown, extra: Array<{ match: string; payload: unknown; status?: number }> = []) {
  return mockFetchRoutes([
    ...extra,
    { match: "/findings", payload: findingsPageFixture([findingFixture()], 1) },
    { match: "/api/analyses/abc123", payload: result },
  ]);
}

describe("Overview page", () => {
  it("renders identity, lifecycle, counts, and section links for completed analyses", async () => {
    mockOverview(analysisResultFixture());
    renderAt("/analysis/abc123/overview");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "acme/web" })).toBeDefined();
    });
    expect(screen.getByText("Completed")).toBeDefined();
    expect(
      screen.getByTitle("9f2c1e7a4b8d3f60a5c7e1b2d4f8a09c3e5b7d61"),
    ).toHaveTextContent(/9f2c1e7/);
    const areasTable = screen.getByRole("table", { name: "Areas" });
    expect(within(areasTable).getByText("Security")).toBeDefined();
    // Each area links to its dedicated tab (never a generic findings link).
    const openLinks = within(areasTable).getAllByRole("link", { name: "Open" });
    expect(openLinks.map((link) => link.getAttribute("href"))).toEqual([
      "/analysis/abc123/security",
      "/analysis/abc123/architecture",
      "/analysis/abc123/dependencies",
      "/analysis/abc123/code-structure",
    ]);
    const body = document.body.textContent ?? "";
    expect(body).not.toMatch(/score|ranking|grade/i);
  });

  it("shows advisory evaluation status and warns when it was incomplete", async () => {
    const result = analysisResultFixture();
    (result.analysis as { advisory_data: { outcome: string } }).advisory_data.outcome =
      "Unavailable";
    mockOverview(result);
    renderAt("/analysis/abc123/overview");
    await waitFor(() => {
      expect(screen.getByTestId("overview-advisory")).toBeDefined();
    });
    expect(screen.getByTestId("overview-advisory").textContent).toContain("Unavailable");
    expect(screen.getByText("Advisory data was incomplete.")).toBeDefined();
    expect(
      screen.getByText(/must not be read as the absence of vulnerabilities/),
    ).toBeDefined();
  });

  it("renders the severity summary and repository context from canonical counts", async () => {
    mockOverview(analysisResultFixture());
    renderAt("/analysis/abc123/overview");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "acme/web" })).toBeDefined();
    });
    expect(screen.getByRole("heading", { name: "Findings by severity and confidence" })).toBeDefined();
    expect(screen.getByText("Languages")).toBeDefined();
    expect(screen.getByText("Circular dependency groups")).toBeDefined();
    expect(screen.getByText("Packages with more than one version")).toBeDefined();
  });

  it("renders a findings preview with a view-all action", async () => {
    mockOverview(analysisResultFixture());
    renderAt("/analysis/abc123/overview");
    await waitFor(() => {
      expect(screen.getByRole("table", { name: "Findings preview" })).toBeDefined();
    });
    expect(screen.getByRole("link", { name: "View all findings" })).toHaveAttribute(
      "href",
      "/analysis/abc123/findings",
    );
  });

  it("shows completed-with-limitations with the explanation and limitation list", async () => {
    const result = analysisResultFixture({
      status: {
        stage: null,
        outcome: "Completed with limitations",
        completed_at: "2026-09-29T08:16:31Z",
        explanation: "One file could not be parsed.",
        snapshot: { sealed_at: "2026-09-29T08:16:32Z" },
        domains: [
          { area: "security", state: "Analysis incomplete", reason: "Parse failure." },
          { area: "architecture", state: null, reason: null },
          { area: "dependency", state: "No findings detected", reason: null },
          { area: "code_structure", state: "No findings detected", reason: null },
        ],
        limitations: [
          { scope_kind: "file", area: "security", path: "legacy/report.py", reason: "Parsing failed." },
        ],
      },
    } as never);
    mockOverview(result);
    renderAt("/analysis/abc123/overview");
    await waitFor(() => {
      expect(screen.getByText("Completed with limitations")).toBeDefined();
    });
    expect(screen.getByText("One file could not be parsed.")).toBeDefined();
    expect(screen.getByText("Parsing failed.")).toBeDefined();
  });

  it("never shows a completion summary for non-terminal analyses", async () => {
    const result = analysisResultFixture({
      status: {
        stage: "Queued",
        outcome: null,
        domains: [],
        limitations: [],
      },
      summary: null,
      security: null,
      architecture: null,
      dependencies: null,
      code_structure: null,
    } as never);
    mockFetchRoutes([{ match: "/api/analyses/abc123", payload: result }]);
    renderAt("/analysis/abc123/overview");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Analysis not completed" })).toBeDefined();
    });
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("renders the failure explanation for failed analyses", async () => {
    const result = analysisResultFixture({
      status: {
        stage: null,
        outcome: "Failed",
        explanation: "Retrieval failed.",
        domains: [],
        limitations: [],
      },
      summary: null,
      security: null,
      architecture: null,
      dependencies: null,
      code_structure: null,
    } as never);
    mockFetchRoutes([{ match: "/api/analyses/abc123", payload: result }]);
    renderAt("/analysis/abc123/overview");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Analysis failed" })).toBeDefined();
    });
    expect(screen.getByText("Retrieval failed.")).toBeDefined();
  });

  it("distinguishes zero findings from unavailable sections", async () => {
    const result = analysisResultFixture({
      summary: {
        ...(analysisResultFixture().summary as object),
        dependencies: { state: "Analysis unavailable", findings: null },
      },
    } as never);
    (result as { dependencies?: unknown }).dependencies = null;
    result.status.domains = [
      { area: "security", state: null, reason: null },
      { area: "architecture", state: null, reason: null },
      { area: "dependency", state: "Analysis unavailable", reason: "No manifest." },
      { area: "code_structure", state: "No findings detected", reason: null },
    ];
    mockOverview(result);
    renderAt("/analysis/abc123/overview");
    await waitFor(() => {
      expect(screen.getByText(/No manifest\./)).toBeDefined();
    });
    // Unavailable row shows "—", never 0; empty row shows 0.
    const areasTable = screen.getByRole("table", { name: "Areas" });
    const rows = within(areasTable).getAllByRole("row");
    const depRow = rows.find((row) => row.textContent?.includes("Dependencies"));
    expect(depRow?.textContent).toContain("—");
    expect(depRow?.textContent).not.toMatch(/Findings\s*0/);
  });

  it("handles unknown analyses", async () => {
    mockFetchRoutes([
      {
        match: "/api/analyses/nope",
        payload: { error: { code: "ANALYSIS_NOT_FOUND", message: "Gone.", details: null } },
        status: 404,
      },
    ]);
    renderAt("/analysis/nope/overview");
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toContain("Analysis not found.");
    });
  });

  it("retries after API failures", async () => {
    mockFetchRoutes([
      {
        match: "/api/analyses/abc123",
        payload: { error: { code: "INTERNAL_ERROR", message: "Boom.", details: null } },
        status: 500,
      },
    ]);
    renderAt("/analysis/abc123/overview");
    await waitFor(
      () => {
        expect(screen.getByRole("button", { name: "Retry" })).toBeDefined();
      },
      { timeout: 3000 },
    );
    mockOverview(analysisResultFixture());
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "acme/web" })).toBeDefined();
    });
  });
});
