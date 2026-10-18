import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { AnalysisDetail } from "../../schemas/analysis";
import { ApiRequestError } from "../../lib/api";
import { AnalysisTerminal } from "./AnalysisTerminal";

function detail(
  overrides: {
    stage?: string | null;
    outcome?: string | null;
    completed_at?: string | null;
  } = {},
): AnalysisDetail {
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
    status: { stage: "Queued", outcome: null, explanation: null, completed_at: null, ...overrides },
  };
}

function renderTerminal(props: Partial<Parameters<typeof AnalysisTerminal>[0]> = {}) {
  return render(
    <AnalysisTerminal
      analysisId="abc123"
      detail={undefined}
      error={undefined}
      isFetching={false}
      {...props}
    />,
  );
}

describe("analysis terminal", () => {
  it("waits honestly before the first status arrives", () => {
    renderTerminal();
    expect(screen.getByText("Waiting for the first status update…")).toBeDefined();
    expect(document.body.textContent).not.toContain("%");
  });

  it("renders the backend-reported acceptance time", () => {
    renderTerminal({ detail: detail() });
    expect(screen.getByText("Analysis accepted")).toBeDefined();
    expect(screen.getByText("08:15:42Z")).toBeDefined();
  });

  it("does not duplicate entries when the same status is polled repeatedly", () => {
    const { rerender } = renderTerminal({ detail: detail({ stage: "RetrievingRepository" }) });
    expect(screen.getAllByText("Retrieving repository")).toHaveLength(1);
    // Repeated polls deliver equal content in a fresh object each time.
    for (let poll = 0; poll < 3; poll += 1) {
      rerender(
        <AnalysisTerminal
          analysisId="abc123"
          detail={detail({ stage: "RetrievingRepository" })}
          error={undefined}
          isFetching
        />,
      );
    }
    expect(screen.getAllByText("Retrieving repository")).toHaveLength(1);
    expect(screen.getAllByText("Analysis accepted")).toHaveLength(1);
  });

  it("appends each distinct stage once, in observation order", () => {
    const { rerender } = renderTerminal({ detail: detail({ stage: "Queued" }) });
    rerender(
      <AnalysisTerminal
        analysisId="abc123"
        detail={detail({ stage: "DetectingLanguages" })}
        error={undefined}
        isFetching
      />,
    );
    const text = screen.getByRole("log").textContent ?? "";
    expect(text.indexOf("Queued")).toBeLessThan(text.indexOf("Detecting languages"));
    expect(screen.getAllByText("Queued")).toHaveLength(1);
    expect(screen.getAllByText("Detecting languages")).toHaveLength(1);
  });

  it("reports the terminal outcome and stops claiming the analysis is running", () => {
    const { rerender } = renderTerminal({ detail: detail({ stage: "RunningAnalysis" }) });
    rerender(
      <AnalysisTerminal
        analysisId="abc123"
        detail={detail({ stage: null, outcome: "Completed", completed_at: "2026-09-29T08:20:00Z" })}
        error={undefined}
        isFetching={false}
      />,
    );
    expect(screen.getByRole("log").textContent).toContain("Completed");
    expect(screen.getByText("Status polling stopped.")).toBeDefined();
    expect(screen.queryByText(/running ·/)).toBeNull();
  });

  it("keeps the last confirmed status when a poll fails", () => {
    const confirmed = detail({ stage: "RetrievingRepository" });
    const { rerender } = renderTerminal({ detail: confirmed, isFetching: false });
    rerender(
      <AnalysisTerminal
        analysisId="abc123"
        detail={confirmed}
        error={new ApiRequestError("INTERNAL_ERROR", "Boom.", 500)}
        isFetching={false}
      />,
    );
    const text = screen.getByRole("log").textContent ?? "";
    expect(text).toContain("Retrieving repository");
    expect(text).toContain("Status refresh failed (INTERNAL_ERROR)");
    expect(screen.getByText("last confirmed status (refresh failing)")).toBeDefined();
  });

  it("never fabricates progress percentages or estimates", () => {
    renderTerminal({ detail: detail({ stage: "RunningAnalysis" }) });
    const text = (screen.getByRole("log").textContent ?? "").toLowerCase();
    expect(text).not.toContain("%");
    expect(text).not.toContain("remaining");
    expect(text).not.toContain("estimate");
  });

  it("does not carry one analysis's log into another", () => {
    const { rerender } = renderTerminal({ detail: detail({ stage: "Queued" }) });
    expect(screen.getAllByText("Queued")).toHaveLength(1);
    rerender(
      <AnalysisTerminal
        analysisId="other999"
        detail={detail({ stage: "IndexingFiles" })}
        error={undefined}
        isFetching
      />,
    );
    const text = screen.getByRole("log").textContent ?? "";
    expect(text).toContain("Indexing files");
    expect(text).not.toContain("Queued");
  });

  it("can collapse and expand the log", () => {
    renderTerminal({ detail: detail() });
    expect(screen.getByRole("log")).toBeDefined();
    fireEvent.click(screen.getByRole("button", { name: "Hide log" }));
    expect(screen.queryByRole("log")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Show log" }));
    expect(screen.getByRole("log")).toBeDefined();
  });
});
