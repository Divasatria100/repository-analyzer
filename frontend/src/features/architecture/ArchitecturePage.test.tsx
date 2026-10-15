import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderAt } from "../../test/render";
import { architectureFixture, mockFetchRoutes } from "../../test/fixtures";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function renderArchitecture() {
  mockFetchRoutes([{ match: "/architecture", payload: architectureFixture() }]);
  return renderAt("/analysis/abc123/architecture");
}

describe("Architecture page", () => {
  it("renders canonical nodes, edges, and counts", async () => {
    renderArchitecture();
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Architecture" })).toBeDefined();
    });
    expect(screen.getByText(/2 modules · 2 relationships/)).toBeDefined();
    // Graph region carries the same identities as the table.
    const region = screen.getByRole("region", { name: /Architecture graph/ });
    expect(within(region).getByText("a.py")).toBeDefined();
    expect(screen.getByRole("cell", { name: "app/a.py" })).toBeDefined();
    expect(screen.getByRole("cell", { name: "app/b.py" })).toBeDefined();
  });

  it("marks potentially incomplete graphs honestly", async () => {
    const doc = architectureFixture();
    doc.potentially_incomplete = true;
    mockFetchRoutes([{ match: "/architecture", payload: doc }]);
    renderAt("/analysis/abc123/architecture");
    await waitFor(() => {
      expect(screen.getByText("Potentially incomplete")).toBeDefined();
    });
  });

  it("renders unavailable architecture as unavailable, never empty", async () => {
    mockFetchRoutes([
      {
        match: "/architecture",
        payload: { error: { code: "REPORT_UNAVAILABLE", message: "No architecture.", details: null } },
        status: 404,
      },
    ]);
    renderAt("/analysis/abc123/architecture");
    await waitFor(
      () => {
        expect(
          screen.getByRole("alert").textContent,
        ).toContain("Architecture results are unavailable for this analysis.");
      },
      { timeout: 3000 },
    );
    expect(screen.queryByRole("region", { name: /Architecture graph/ })).toBeNull();
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("renders an empty graph distinctly from missing data", async () => {
    const doc = architectureFixture();
    doc.nodes = [];
    doc.edges = [];
    doc.cycles = [];
    mockFetchRoutes([{ match: "/architecture", payload: doc }]);
    renderAt("/analysis/abc123/architecture");
    await waitFor(() => {
      expect(screen.getByText("This architecture graph contains no modules.")).toBeDefined();
    });
    expect(screen.getByText("No dependency cycles reported.")).toBeDefined();
  });

  it("selects a module from the table and shows backend relationships", async () => {
    renderArchitecture();
    await waitFor(() => {
      expect(screen.getByRole("cell", { name: "app/a.py" })).toBeDefined();
    });
    fireEvent.click(screen.getByRole("button", { name: "Open details for module app/a.py" }));
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "app/a.py" })).toBeDefined();
    });
    expect(screen.getByText("Depends on (outgoing)")).toBeDefined();
    expect(screen.getByText("Used by (incoming)")).toBeDefined();
    // Backend-confirmed links appear in cycles, findings, and detail sections.
    const findingLinks = screen.getAllByRole("link", { name: "F-0009" });
    expect(findingLinks.length).toBeGreaterThanOrEqual(2);
    expect(findingLinks[0].getAttribute("href")).toBe("/analysis/abc123/findings/F-0009");
    // Recorded metric shown with its real value; unavailable stays unavailable.
    expect(screen.getByText(/fan_out: 4/)).toBeDefined();
  });

  it("warns on unknown module identities", async () => {
    mockFetchRoutes([{ match: "/architecture", payload: architectureFixture() }]);
    renderAt("/analysis/abc123/architecture?module=nope.py");
    await waitFor(() => {
      expect(screen.getByText(/Unknown module/)).toBeDefined();
    });
  });

  it("closes the detail panel and returns focus to the table row", async () => {
    renderArchitecture();
    await waitFor(() => {
      expect(screen.getByRole("cell", { name: "app/a.py" })).toBeDefined();
    });
    fireEvent.click(screen.getByRole("button", { name: "Open details for module app/a.py" }));
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "app/a.py" })).toBeDefined();
    });
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    await waitFor(() => {
      expect(document.activeElement?.getAttribute("aria-label")).toBe(
        "Open details for module app/a.py",
      );
    });
  });

  it("searches modules case-insensitively without mutating canonical data", async () => {
    const calls = mockFetchRoutes([{ match: "/architecture", payload: architectureFixture() }]);
    renderAt("/analysis/abc123/architecture");
    await waitFor(() => {
      expect(screen.getByRole("cell", { name: "app/a.py" })).toBeDefined();
    });
    fireEvent.change(screen.getByLabelText("Search modules"), { target: { value: "A.PY" } });
    await waitFor(() => {
      expect(screen.getByText(/1 of 2 modules match/)).toBeDefined();
    });
    expect(screen.queryByRole("cell", { name: "app/b.py" })).toBeNull();
    // The backend document was fetched once; filtering is client-side only.
    expect(calls.filter((url) => url.includes("/architecture")).length).toBe(1);
    fireEvent.change(screen.getByLabelText("Search modules"), { target: { value: "" } });
    await waitFor(() => {
      expect(screen.getByRole("cell", { name: "app/b.py" })).toBeDefined();
    });
  });

  it("filters by layer, relationship type, and cycle membership with reset", async () => {
    renderArchitecture();
    await waitFor(() => {
      expect(screen.getByRole("cell", { name: "app/a.py" })).toBeDefined();
    });
    fireEvent.change(screen.getByLabelText("Layer"), { target: { value: "application" } });
    await waitFor(() => {
      expect(screen.getByText(/1 of 2 modules match/)).toBeDefined();
    });
    fireEvent.click(screen.getByRole("button", { name: "Reset filters" }));
    await waitFor(() => {
      expect(screen.getByText(/2 of 2 modules match/)).toBeDefined();
    });
    fireEvent.change(screen.getByLabelText("Relationship type"), { target: { value: "calls" } });
    await waitFor(() => {
      expect(screen.getByText(/2 of 2 modules match/)).toBeDefined();
    });
    fireEvent.click(screen.getByLabelText("In cycles only"));
    await waitFor(() => {
      expect(screen.getByText(/2 of 2 modules match/)).toBeDefined();
    });
  });

  it("lists cycles with navigation to modules and findings", async () => {
    renderArchitecture();
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Dependency cycles" })).toBeDefined();
    });
    const cycleSection = screen.getByRole("heading", { name: "Dependency cycles" }).parentElement;
    expect(cycleSection == null).toBe(false);
    expect(within(cycleSection as HTMLElement).getByText("F-0009", { selector: "a" })).toBeDefined();
    const moduleButtons = within(cycleSection as HTMLElement).getAllByRole("button", {
      name: /Open module/,
    });
    expect(moduleButtons.length).toBe(2);
    fireEvent.click(moduleButtons[0]);
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "app/a.py" })).toBeDefined();
    });
  });

  it("distinguishes missing cycle data from zero cycles", async () => {
    const doc = architectureFixture();
    (doc as { cycles?: unknown }).cycles = null;
    mockFetchRoutes([{ match: "/architecture", payload: doc }]);
    renderAt("/analysis/abc123/architecture");
    await waitFor(() => {
      expect(screen.getByText(/Cycle information is unavailable/)).toBeDefined();
    });
  });

  it("drills from module files into the findings search", async () => {
    renderArchitecture();
    await waitFor(() => {
      expect(screen.getByRole("cell", { name: "app/a.py" })).toBeDefined();
    });
    fireEvent.click(screen.getByRole("button", { name: "Open details for module app/a.py" }));
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "app/a.py" })).toBeDefined();
    });
    const fileLink = screen.getByRole("link", { name: "Findings in file" });
    expect(fileLink.getAttribute("href")).toBe("/analysis/abc123/findings?q=app%2Fa.py");
  });

  it("caps the interactive graph with an explicit subset label", async () => {
    const doc = architectureFixture();
    doc.nodes = Array.from({ length: 250 }, (_, index) => ({
      node_id: `app/m${String(index).padStart(3, "0")}.py`,
      name: `m${index}.py`,
      paths: [`app/m${index}.py`],
      partially_represented: false,
      finding_ids: [],
      layer: null,
    }));
    doc.edges = [];
    doc.cycles = [];
    mockFetchRoutes([{ match: "/architecture", payload: doc }]);
    renderAt("/analysis/abc123/architecture");
    await waitFor(() => {
      expect(screen.getByText(/Showing 200 of 250 matching modules/)).toBeDefined();
    });
    // The table still pages through the complete matching set.
    expect(screen.getByText("Page 1 of 5")).toBeDefined();
  });

  it("lists external and unresolved references as diagnostics", async () => {
    renderArchitecture();
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "External and unresolved references" })).toBeDefined();
    });
    expect(screen.getByText(/did not resolve to internal modules/)).toBeDefined();
  });
});
