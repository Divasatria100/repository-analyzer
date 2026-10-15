import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderAt } from "../../test/render";
import { analysisResultFixture, fileFixture, mockFetchRoutes } from "../../test/fixtures";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  sessionStorage.clear();
});

function renderFiles(path = "/analysis/abc123/files") {
  mockFetchRoutes([{ match: "/api/analyses/abc123", payload: analysisResultFixture() }]);
  return renderAt(path);
}

describe("Files explorer", () => {
  it("renders the directory tree with finding counts", async () => {
    renderFiles();
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Files" })).toBeDefined();
    });
    expect(screen.getByText(/2 of 2 files/)).toBeDefined();
    fireEvent.click(screen.getByRole("button", { name: /app\// }));
    expect(screen.getByRole("button", { name: /a\.py/ })).toBeDefined();
  });

  it("selects a file and shows metadata, coverage, metrics, and findings", async () => {
    renderFiles();
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Files" })).toBeDefined();
    });
    fireEvent.click(screen.getByRole("button", { name: /app\// }));
    fireEvent.click(screen.getByRole("button", { name: /a\.py/ }));
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "app/a.py" })).toBeDefined();
    });
    expect(screen.getByText("Primary Support")).toBeDefined();
    expect(screen.getByText(/Fully analyzed/)).toBeDefined();
    expect(screen.getByText(/complexity \(code_structure\): 18/)).toBeDefined();
    expect(screen.getByRole("link", { name: "F-0031" })).toBeDefined();
    expect(screen.getByRole("link", { name: "F-0009" })).toBeDefined();
    expect(screen.getByText("Findings in this file (2)")).toBeDefined();
  });

  it("searches paths and filters states via URL", async () => {
    renderFiles();
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Files" })).toBeDefined();
    });
    fireEvent.change(screen.getByLabelText("Search path"), { target: { value: "requirements" } });
    await waitFor(() => {
      expect(screen.getByText(/1 of 2 files/)).toBeDefined();
    });
    fireEvent.click(screen.getByRole("button", { name: "Reset filters" }));
    await waitFor(() => {
      expect(screen.getByText(/2 of 2 files/)).toBeDefined();
    });
  });

  it("supports direct navigation with encoded special-character paths", async () => {
    const special = fileFixture({ path: "docs/a b#c&d%e.py", finding_count: 0, coverage: [] });
    const result = analysisResultFixture();
    (result as { files?: unknown }).files = [special];
    mockFetchRoutes([{ match: "/api/analyses/abc123", payload: result }]);
    renderAt("/analysis/abc123/files?path=docs%2Fa%20b%23c%26d%25e.py");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "docs/a b#c&d%e.py" })).toBeDefined();
    });
    expect(screen.getByText("No findings have a location in this file.")).toBeDefined();
  });

  it("warns on unknown file paths", async () => {
    renderFiles("/analysis/abc123/files?path=nope.py");
    await waitFor(() => {
      expect(screen.getByText(/Unknown file/)).toBeDefined();
    });
  });

  it("marks failed parses instead of showing them as clean", async () => {
    const failed = fileFixture({ path: "legacy/report.py", parse_result: "Failed" });
    const result = analysisResultFixture();
    (result as { files?: unknown }).files = [failed];
    mockFetchRoutes([{ match: "/api/analyses/abc123", payload: result }]);
    renderAt("/analysis/abc123/files?path=legacy%2Freport.py");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "legacy/report.py" })).toBeDefined();
    });
    expect(screen.getByText("failed")).toBeDefined();
  });

  it("distinguishes unavailable file data from an empty repository", async () => {
    const result = analysisResultFixture();
    (result as { files?: unknown }).files = null;
    mockFetchRoutes([{ match: "/api/analyses/abc123", payload: result }]);
    renderAt("/analysis/abc123/files");
    await waitFor(() => {
      expect(screen.getByText("File results are unavailable for this analysis.")).toBeDefined();
    });
  });

  it("never fetches source code from external locations", async () => {
    const calls = mockFetchRoutes([{ match: "/api/analyses/abc123", payload: analysisResultFixture() }]);
    renderFiles();
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Files" })).toBeDefined();
    });
    expect(calls.every((url) => url.startsWith("http://localhost:8000/api/"))).toBe(true);
  });
});
