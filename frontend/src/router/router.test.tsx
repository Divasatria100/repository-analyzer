import { screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderAt } from "../test/render";

function mockAnalysisFetch(payload: unknown, status = 200) {
  window.fetch = vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(typeof payload === "string" ? payload : JSON.stringify(payload)),
  } as Response);
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe.each([
  ["/analysis/new", "Analyze a public repository"],
  ["/analysis/abc123/overview", "Overview"],
  ["/analysis/abc123/security", "Security"],
  ["/analysis/abc123/architecture", "Architecture"],
  ["/analysis/abc123/dependencies", "Dependencies"],
  ["/analysis/abc123/code-structure", "Code Structure"],
  ["/analysis/abc123/files", "Files"],
  ["/analysis/abc123/findings", "Findings"],
  ["/history", "History"],
  ["/settings", "Settings"],
])("route %s", (path, title) => {
  it(`renders the ${title} page inside the shell`, () => {
    renderAt(path);
    // The shell top bar and the page can share a title; at least one
    // heading with the page title must be present.
    expect(screen.getAllByRole("heading", { name: title }).length).toBeGreaterThan(0);
    // Shell navigation is present on every page.
    expect(screen.getByRole("link", { name: "New Analysis" })).toBeDefined();
  });
});

describe("router fallbacks", () => {
  it("renders the dashboard at root", () => {
    renderAt("/");
    expect(screen.getByRole("button", { name: "Analyze Repository" })).toBeDefined();
  });

  it("loads the real analysis status for bare analysis detail", async () => {
    mockAnalysisFetch({
      analysis: { analysis_id: "abc123", repository_id: "r", timestamp: null },
      repository: {
        repository_id: "r",
        url: "https://github.com/acme/web",
        owner: "acme",
        name: "web",
        analyzed_state: { branch: null, commit: null },
      },
      status: { stage: "Queued", outcome: null },
    });
    renderAt("/analysis/abc123");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Analysis in progress" })).toBeDefined();
    });
  });

  it("renders Not Found for unknown routes", () => {
    renderAt("/does-not-exist");
    expect(screen.getByRole("heading", { name: "Page not found" })).toBeDefined();
  });
});
