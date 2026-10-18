import type { AnalysisDetail } from "../../schemas/analysis";

// Truthful log model for the live analysis terminal
// (docs/14-ui-requirements.md §7.4; docs/17 §4.2; docs/13 §6.1).
//
// Every stage value comes from the server. An entry is either:
//   - "backend": carries a timestamp the backend reported, or
//   - "observed": carries an elapsed duration measured by the browser
//     relative to the backend-reported acceptance time and is labelled as
//     observed. No historical event timestamp is ever invented, and no
//     ordering is inferred beyond what the server reports.

export const STAGE_LABELS: Record<string, string> = {
  Queued: "Queued",
  ValidatingRepository: "Validating repository",
  ResolvingCommit: "Resolving commit",
  RetrievingRepository: "Retrieving repository",
  IndexingFiles: "Indexing files",
  DetectingLanguages: "Detecting languages",
  ParsingSource: "Parsing source",
  BuildingCodeModel: "Building code model",
  RunningAnalysis: "Running analysis",
  AggregatingResults: "Aggregating results",
  GeneratingReports: "Generating reports",
};

export function stageLabel(stage: string): string {
  return STAGE_LABELS[stage] ?? stage;
}

export type TerminalEntryLevel = "info" | "success" | "warning" | "error";
export type TerminalEntrySource = "backend" | "observed";

export interface TerminalEntry {
  /** Deterministic dedupe key: repeated polls must never duplicate a line. */
  key: string;
  source: TerminalEntrySource;
  level: TerminalEntryLevel;
  /** Backend-reported ISO-8601 time (backend entries only). */
  timestamp: string | null;
  /** Elapsed time since acceptance, measured by the browser (observed only). */
  elapsedMs: number | null;
  text: string;
}

export function terminalEntryLevelForOutcome(outcome: string): TerminalEntryLevel {
  if (outcome === "Failed") {
    return "error";
  }
  if (outcome === "Completed with limitations") {
    return "warning";
  }
  return "success";
}

// The entries a single status snapshot truthfully implies. The caller dedupes
// by key across polls and fills observed durations (which need the acceptance
// anchor and the observation instant).
export function backendEntries(detail: AnalysisDetail): TerminalEntry[] {
  const entries: TerminalEntry[] = [
    {
      key: "accepted",
      source: "backend",
      level: "info",
      timestamp: detail.analysis.timestamp,
      elapsedMs: null,
      text: "Analysis accepted",
    },
  ];

  const { stage, outcome, completed_at: completedAt } = detail.status;

  if (outcome == null) {
    if (stage) {
      entries.push({
        key: `stage:${stage}`,
        source: "observed",
        level: "info",
        timestamp: null,
        elapsedMs: null,
        text: stageLabel(stage),
      });
    }
    return entries;
  }

  entries.push({
    key: `terminal:${outcome}`,
    source: "backend",
    level: terminalEntryLevelForOutcome(outcome),
    timestamp: completedAt ?? null,
    elapsedMs: null,
    text: outcome,
  });
  return entries;
}

export function formatBackendTimestamp(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return iso;
  }
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}Z`;
}

export function formatElapsed(ms: number): string {
  const safe = ms < 0 ? 0 : ms;
  const seconds = safe / 1000;
  if (seconds < 10) {
    return `+${seconds.toFixed(1)}s`;
  }
  if (seconds < 60) {
    return `+${Math.round(seconds)}s`;
  }
  const minutes = Math.floor(seconds / 60);
  const rest = Math.round(seconds - minutes * 60);
  return `+${minutes}m${String(rest).padStart(2, "0")}s`;
}
