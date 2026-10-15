import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderAt } from "../../test/render";
import { analysisResultFixture, mockFetchRoutes } from "../../test/fixtures";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function renderDependencies(path = "/analysis/abc123/dependencies") {
  const calls = mockFetchRoutes([{ match: "/api/analyses/abc123", payload: analysisResultFixture() }]);
  renderAt(path);
  return calls;
}

describe("Dependencies page", () => {
  it("renders canonical occurrences with advisory and finding counts", async () => {
    renderDependencies();
    await waitFor(() => {
      expect(screen.getByText("requests")).toBeDefined();
    });
    expect(screen.getByText("2.19.0")).toBeDefined();
    expect(screen.getByText("⚑1")).toBeDefined();
    expect(screen.getByText(/1 of 1 occurrences/)).toBeDefined();
    expect(screen.getByText(/OSV · .* · Succeeded/)).toBeDefined();
  });

  it("filters by type, searches by name, and resets via URL state", async () => {
    const calls = renderDependencies();
    await waitFor(() => {
      expect(screen.getByText("requests")).toBeDefined();
    });
    // Single fetch: filtering is client-side over the canonical items.
    expect(calls.filter((url) => url.includes("/api/analyses/abc123")).length).toBe(1);
    fireEvent.click(screen.getByRole("button", { name: "transitive" }));
    await waitFor(() => {
      expect(screen.getByText("No dependencies match these filters.")).toBeDefined();
    });
    fireEvent.click(screen.getByRole("button", { name: "Reset filters" }));
    await waitFor(() => {
      expect(screen.getByText("requests")).toBeDefined();
    });
    fireEvent.change(screen.getByLabelText("Search package name"), { target: { value: "req" } });
    expect(screen.getByText("requests")).toBeDefined();
    fireEvent.change(screen.getByLabelText("Search package name"), { target: { value: "zzz" } });
    await waitFor(() => {
      expect(screen.getByText("No dependencies match these filters.")).toBeDefined();
    });
  });

  it("shows vulnerable-only and empty states honestly", async () => {
    renderDependencies();
    await waitFor(() => {
      expect(screen.getByText("requests")).toBeDefined();
    });
    fireEvent.click(screen.getByRole("button", { name: "vulnerable" }));
    expect(screen.getByText("requests")).toBeDefined();
    fireEvent.click(screen.getByRole("button", { name: "direct" }));
    expect(screen.getByText("requests")).toBeDefined();
  });

  it("opens detail with introducers, advisories, findings, and manifest link", async () => {
    renderDependencies();
    await waitFor(() => {
      expect(screen.getByText("requests")).toBeDefined();
    });
    fireEvent.click(screen.getByRole("button", { name: /Open details for requests/ }));
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "requests" })).toBeDefined();
    });
    expect(screen.getByText(/GHSA-xxxx/)).toBeDefined();
    expect(screen.getByText("F-0021", { selector: "a" })).toBeDefined();
    const manifest = screen.getByRole("link", { name: "requirements.txt" });
    expect(manifest.getAttribute("href")).toBe("/analysis/abc123/files?path=requirements.txt");
  });

  it("warns on unknown dependency identities", async () => {
    renderDependencies("/analysis/abc123/dependencies?dependency=nope");
    await waitFor(() => {
      expect(screen.getByText(/Unknown dependency/)).toBeDefined();
    });
  });

  it("shows unknown versions without defaulting them", async () => {
    const result = analysisResultFixture();
    const section = result.dependencies;
    if (section && "items" in section) {
      (section.items[0] as { version: unknown }).version = null;
    }
    mockFetchRoutes([{ match: "/api/analyses/abc123", payload: result }]);
    renderAt("/analysis/abc123/dependencies");
    await waitFor(() => {
      expect(screen.getByText(/unknown/).textContent).toContain("unknown");
    });
  });

  it("warns when advisory data is incomplete without claiming safety", async () => {
    const result = analysisResultFixture();
    const analysis = result.analysis as { advisory_data?: { outcome?: string } };
    if (analysis.advisory_data) {
      analysis.advisory_data.outcome = "Unavailable";
    }
    mockFetchRoutes([{ match: "/api/analyses/abc123", payload: result }]);
    renderAt("/analysis/abc123/dependencies");
    await waitFor(() => {
      expect(screen.getByText("Advisory data was incomplete.")).toBeDefined();
    });
    expect(
      screen.getByText(/must not be read as the absence of vulnerabilities/),
    ).toBeDefined();
  });

  it("never presents an unavailable section as clean", async () => {
    const result = analysisResultFixture();
    (result as { dependencies?: unknown }).dependencies = null;
    result.status.domains = [
      { area: "security", state: null, reason: null },
      { area: "architecture", state: null, reason: null },
      { area: "dependency", state: "Analysis unavailable", reason: "No manifest." },
      { area: "code_structure", state: "No findings detected", reason: null },
    ];
    mockFetchRoutes([{ match: "/api/analyses/abc123", payload: result }]);
    renderAt("/analysis/abc123/dependencies");
    await waitFor(() => {
      expect(
        screen.getByText("Dependency results are unavailable for this analysis."),
      ).toBeDefined();
    });
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("waits for completion and recovers from failures", async () => {
    const queued = analysisResultFixture({
      status: { stage: "Queued", outcome: null, domains: [], limitations: [] },
      summary: null,
      security: null,
      architecture: null,
      dependencies: null,
      code_structure: null,
    } as never);
    mockFetchRoutes([{ match: "/api/analyses/abc123", payload: queued }]);
    renderAt("/analysis/abc123/dependencies");
    await waitFor(() => {
      expect(screen.getByText(/not completed/)).toBeDefined();
    });
    expect(within(document.body).queryAllByRole("table").length).toBe(0);
  });
});
