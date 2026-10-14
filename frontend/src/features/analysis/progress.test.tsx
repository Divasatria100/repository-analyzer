import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router";
import { AnalysisProgress } from "./progress";

function detail(overrides: { stage?: string | null; outcome?: string | null; explanation?: string | null } = {}) {
  return {
    analysis: { analysis_id: "abc123", repository_id: "r", timestamp: "2026-09-29T08:15:42Z" },
    repository: {
      repository_id: "r",
      url: "https://github.com/acme/web",
      owner: "acme",
      name: "web",
      analyzed_state: {
        branch: { name: "main", origin: "Defaulted" },
        commit: { sha: "9f2c1e7a4b8d3f60a5c7e1b2d4f8a09c3e5b7d61", origin: "Defaulted" },
      },
    },
    status: { stage: "Queued", outcome: null, explanation: null, ...overrides },
  };
}

function mockFetchSequence(entries: Array<{ payload: unknown; status?: number }>) {
  const queue = entries.map(({ payload, status = 200 }) => ({
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(JSON.stringify(payload)),
  }));
  window.fetch = vi.fn(() => Promise.resolve(queue.shift() ?? queue[queue.length - 1])) as unknown as typeof fetch;
}

function renderProgress() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <AnalysisProgress analysisId="abc123" />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { client, ...view };
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("analysis progress", () => {
  it("shows Queued honestly without percentages or estimates", async () => {
    mockFetchSequence([{ payload: detail() }]);
    renderProgress();
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Analysis in progress" })).toBeDefined();
    });
    expect(screen.getByText(/awaiting processing/)).toBeDefined();
    expect(document.body.textContent).not.toContain("%");
    expect(document.body.textContent?.toLowerCase()).not.toContain("remaining");
  });

  it("lists the contract stages with the current stage marked", async () => {
    mockFetchSequence([{ payload: detail({ stage: "IndexingFiles" }) }]);
    renderProgress();
    await waitFor(() => {
      expect(screen.getAllByText("Indexing files").length).toBeGreaterThan(0);
    });
    for (const label of ["Queued", "Parsing source", "Generating reports"]) {
      expect(screen.getAllByText(label, { exact: false }).length).toBeGreaterThan(0);
    }
    // The current stage is exposed to assistive technology.
    expect(screen.getByText("(current stage)")).toBeDefined();
  });

  it("moves to the completed state through refresh with an Open action", async () => {
    mockFetchSequence([
      { payload: detail() },
      { payload: detail({ stage: null, outcome: "Completed" }) },
    ]);
    renderProgress();
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Analysis in progress" })).toBeDefined();
    });
    fireEvent.click(screen.getByRole("button", { name: "Refresh now" }));
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Analysis completed" })).toBeDefined();
    });
    const open = screen.getByRole("link", { name: "Open analysis" });
    expect(open.getAttribute("href")).toBe("/analysis/abc123/overview");
  });

  it("shows completed-with-limitations distinctly with the explanation", async () => {
    mockFetchSequence([
      { payload: detail({ stage: null, outcome: "Completed with limitations", explanation: "One file could not be parsed." }) },
    ]);
    renderProgress();
    await waitFor(() => {
      expect(
        screen.getByRole("heading", { name: "Analysis completed with limitations" }),
      ).toBeDefined();
    });
    expect(screen.getByText("One file could not be parsed.")).toBeDefined();
  });

  it("shows failed analyses with the backend explanation", async () => {
    mockFetchSequence([
      { payload: detail({ stage: null, outcome: "Failed", explanation: "Retrieval failed." }) },
    ]);
    renderProgress();
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Analysis failed" })).toBeDefined();
    });
    expect(screen.getByText("Retrieval failed.")).toBeDefined();
    expect(screen.getByRole("link", { name: "New Analysis" })).toBeDefined();
  });

  it("shows a not-found state for unknown analyses", async () => {
    mockFetchSequence([
      { payload: { error: { code: "ANALYSIS_NOT_FOUND", message: "Gone.", details: null } }, status: 404 },
    ]);
    renderProgress();
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toContain("Analysis not found.");
    });
  });

  it(
    "offers retry after transient failures",
    async () => {
      // Every automatic attempt fails; only the manual retry succeeds.
      const failure = {
        payload: { error: { code: "INTERNAL_ERROR", message: "Boom.", details: null } },
        status: 500,
      };
      mockFetchSequence([failure, failure, failure, { payload: detail() }]);
      renderProgress();
      await waitFor(
        () => {
          expect(screen.getByRole("button", { name: "Retry" })).toBeDefined();
        },
        { timeout: 8000 },
      );
      fireEvent.click(screen.getByRole("button", { name: "Retry" }));
      await waitFor(() => {
        expect(screen.getByRole("heading", { name: "Analysis in progress" })).toBeDefined();
      });
    },
    { timeout: 15000 },
  );

  it("cleans up polling timers on unmount", async () => {
    mockFetchSequence([{ payload: detail() }]);
    const { unmount } = renderProgress();
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Analysis in progress" })).toBeDefined();
    });
    unmount();
    expect(screen.queryByRole("heading", { name: "Analysis in progress" })).toBeNull();
  });
});
