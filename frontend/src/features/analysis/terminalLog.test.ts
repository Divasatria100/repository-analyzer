import { describe, expect, it } from "vitest";
import type { AnalysisDetail } from "../../schemas/analysis";
import { STAGE_LABELS, backendEntries, formatElapsed, stageLabel } from "./terminalLog";

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

describe("terminal log model", () => {
  it("derives only backend-reported events for an accepted analysis", () => {
    const entries = backendEntries(detail({ stage: "Queued" }));
    expect(entries.map((entry) => entry.key)).toEqual(["accepted", "stage:Queued"]);
    expect(entries[0].source).toBe("backend");
    expect(entries[0].timestamp).toBe("2026-09-29T08:15:42Z");
    // The stage value is server-reported; only its observation time is client-side.
    expect(entries[1].source).toBe("observed");
    expect(entries[1].timestamp).toBeNull();
    expect(entries[1].text).toBe("Queued");
  });

  it("invents no events when no stage is reported", () => {
    const entries = backendEntries(detail({ stage: null }));
    expect(entries.map((entry) => entry.key)).toEqual(["accepted"]);
  });

  it("emits one terminal event carrying the backend completion time", () => {
    const entries = backendEntries(
      detail({
        stage: null,
        outcome: "Failed",
        completed_at: "2026-09-29T08:16:00Z",
      }),
    );
    expect(entries.map((entry) => entry.key)).toEqual(["accepted", "terminal:Failed"]);
    const terminal = entries[1];
    expect(terminal.source).toBe("backend");
    expect(terminal.level).toBe("error");
    expect(terminal.timestamp).toBe("2026-09-29T08:16:00Z");
    // A terminal analysis never carries a running stage line.
    expect(entries.some((entry) => entry.key.startsWith("stage:"))).toBe(false);
  });

  it("marks limitations as a warning and success as a plain completion", () => {
    expect(backendEntries(detail({ stage: null, outcome: "Completed with limitations" }))[1].level).toBe(
      "warning",
    );
    expect(backendEntries(detail({ stage: null, outcome: "Completed" }))[1].level).toBe("success");
  });

  it("contains no percentage, estimate, or countdown", () => {
    const text = backendEntries(detail({ stage: "IndexingFiles" }))
      .map((entry) => `${entry.text} ${entry.timestamp ?? ""}`)
      .join(" ")
      .toLowerCase();
    expect(text).not.toContain("%");
    expect(text).not.toContain("remaining");
    expect(text).not.toContain("estimate");
    expect(text).not.toContain("eta");
  });

  it("labels contract stages and preserves unknown values verbatim", () => {
    for (const stage of Object.keys(STAGE_LABELS)) {
      expect(stageLabel(stage)).toBeTruthy();
    }
    expect(stageLabel("DetectingLanguages")).toBe("Detecting languages");
    expect(stageLabel("SomethingElse")).toBe("SomethingElse");
  });

  it("formats observed elapsed durations readably", () => {
    expect(formatElapsed(4200)).toBe("+4.2s");
    expect(formatElapsed(12500)).toBe("+13s");
    expect(formatElapsed(65000)).toBe("+1m05s");
    expect(formatElapsed(-5)).toBe("+0.0s");
  });
});
