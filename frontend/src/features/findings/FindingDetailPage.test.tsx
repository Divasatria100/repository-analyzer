import { screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderAt } from "../../test/render";
import { analysisResultFixture, findingFixture, mockFetchRoutes } from "../../test/fixtures";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("Finding detail", () => {
  it("renders the persisted finding with severity and confidence kept separate", async () => {
    mockFetchRoutes([{ match: "/api/analyses/abc123", payload: analysisResultFixture() }]);
    const router = renderAt("/analysis/abc123/findings/F-0001");
    expect(router.state.location.pathname).toBe("/analysis/abc123/findings/F-0001");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "SEC-HARDCODED-SECRET" })).toBeDefined();
    });
    expect(screen.getByText("High")).toBeDefined();
    expect(screen.getByText(/confidence: Medium/)).toBeDefined();
    expect(screen.getByText("app/config.py")).toBeDefined();
    expect(screen.getByText("A potential hardcoded secret may require review.")).toBeDefined();
    expect(screen.getByText("Redacted")).toBeDefined();
    expect(screen.getByText('PAYMENT_KEY = "[REDACTED]"')).toBeDefined();
  });

  it("reports unknown finding IDs without fabricating data", async () => {
    mockFetchRoutes([{ match: "/api/analyses/abc123", payload: analysisResultFixture() }]);
    renderAt("/analysis/abc123/findings/F-9999");
    await waitFor(() => {
      expect(screen.getByText("Finding not found.")).toBeDefined();
    });
    expect(screen.getByText("F-9999")).toBeDefined();
  });

  it("renders HTML-like evidence as inert text", async () => {
    const evil = findingFixture({
      finding_id: "F-0007",
      explanation: "<img src=x onerror=alert(1)> explanation",
      evidence: {
        redacted: false,
        source_context: {
          text: "<script>alert(1)</script>",
          start_line: 1,
          end_line: 1,
        },
      },
    });
    const result = analysisResultFixture();
    (result.security as { findings: unknown }).findings = [evil];
    mockFetchRoutes([{ match: "/api/analyses/abc123", payload: result }]);
    renderAt("/analysis/abc123/findings/F-0007");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "SEC-HARDCODED-SECRET" })).toBeDefined();
    });
    expect(document.querySelector("main script")).toBeNull();
    expect(document.querySelector("main img")).toBeNull();
    const evidenceBlock = document.querySelector("main pre")?.innerHTML ?? "";
    expect(evidenceBlock).toContain("&lt;script&gt;");
    expect(document.querySelector("script")).toBeNull();
  });

  it("handles missing optional fields gracefully", async () => {
    const minimal = findingFixture({
      finding_id: "F-0008",
      impact: null,
      evidence: null,
      subject: { locations: [], modules: ["app/a.py"], dependencies: [] },
    });
    const result = analysisResultFixture();
    (result.security as { findings: unknown }).findings = [minimal];
    mockFetchRoutes([{ match: "/api/analyses/abc123", payload: result }]);
    renderAt("/analysis/abc123/findings/F-0008");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "SEC-HARDCODED-SECRET" })).toBeDefined();
    });
    expect(screen.queryByText("Potential impact")).toBeNull();
    expect(screen.getByText("No evidence recorded for this finding.")).toBeDefined();
    expect(screen.getByText("app/a.py")).toBeDefined();
  });

  it("uses an unfiltered back link on direct navigation", async () => {
    mockFetchRoutes([{ match: "/api/analyses/abc123", payload: analysisResultFixture() }]);
    const router = renderAt("/analysis/abc123/findings/F-0001?severity=High&page=2");
    await waitFor(() => {
      expect(screen.getByRole("link", { name: /Back to findings/ })).toBeDefined();
    });
    // Direct navigation carries no from-search state: back link is unfiltered.
    expect(screen.getByRole("link", { name: /Back to findings/ }).getAttribute("href")).toBe(
      "/analysis/abc123/findings",
    );
    expect(router.state.location.pathname).toBe("/analysis/abc123/findings/F-0001");
  });

  it("keeps the explorer search when navigating from a row", async () => {
    mockFetchRoutes([{ match: "/api/analyses/abc123", payload: analysisResultFixture() }]);
    renderAt({
      pathname: "/analysis/abc123/findings/F-0001",
      search: "",
      state: { fromSearch: "severity=High&page=2" },
    });
    await waitFor(() => {
      expect(screen.getByRole("link", { name: /Back to findings/ })).toBeDefined();
    });
    expect(screen.getByRole("link", { name: /Back to findings/ }).getAttribute("href")).toBe(
      "/analysis/abc123/findings?severity=High&page=2",
    );
  });

  it("shows line numbers and the truncated marker from metadata", async () => {
    const truncated = findingFixture({
      finding_id: "F-0010",
      evidence: {
        redacted: true,
        source_context: { text: "a\nb", start_line: 40, end_line: 41, truncated: true },
      },
    });
    const result = analysisResultFixture();
    (result.security as { findings: unknown }).findings = [truncated];
    mockFetchRoutes([{ match: "/api/analyses/abc123", payload: result }]);
    renderAt("/analysis/abc123/findings/F-0010");
    await waitFor(() => {
      expect(screen.getByText("Truncated excerpt")).toBeDefined();
    });
    expect(screen.getByText("40", { selector: "span" })).toBeDefined();
  });

  it("long evidence scrolls horizontally without breaking layout", async () => {
    const long = findingFixture({
      finding_id: "F-0011",
      evidence: {
        redacted: false,
        source_context: { text: `x = "${"y".repeat(500)}"`, start_line: 1, end_line: 1 },
      },
    });
    const result = analysisResultFixture();
    (result.security as { findings: unknown }).findings = [long];
    mockFetchRoutes([{ match: "/api/analyses/abc123", payload: result }]);
    renderAt("/analysis/abc123/findings/F-0011");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "SEC-HARDCODED-SECRET" })).toBeDefined();
    });
    const pre = document.querySelector("pre");
    expect(pre?.className).toContain("overflow-x-auto");
  });
});
