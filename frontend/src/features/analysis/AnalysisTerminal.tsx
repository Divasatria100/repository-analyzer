import { useEffect, useRef, useState } from "react";
import { ApiRequestError } from "../../lib/api";
import type { AnalysisDetail } from "../../schemas/analysis";
import {
  backendEntries,
  formatBackendTimestamp,
  formatElapsed,
  stageLabel,
  type TerminalEntry,
} from "./terminalLog";

// Live analysis terminal (docs/14-ui-requirements.md §7.4; docs/17 §4.2).
// It renders only real backend state plus explicitly labelled browser
// observations. There is no simulated output, no fabricated log line, and no
// percentage or estimate. Repeated polls of the same status do not add lines.

const LEVEL_MARKER: Record<TerminalEntry["level"], { glyph: string; className: string }> = {
  info: { glyph: "·", className: "text-text-secondary" },
  success: { glyph: "✓", className: "text-primary" },
  warning: { glyph: "▲", className: "text-status-warning" },
  error: { glyph: "✕", className: "text-status-error" },
};

function useTerminalLog(
  analysisId: string,
  detail: AnalysisDetail | undefined,
  error: unknown,
): TerminalEntry[] {
  const [entries, setEntries] = useState<TerminalEntry[]>([]);
  const seenRef = useRef<Set<string>>(new Set());
  const acceptedAtRef = useRef<number | null>(null);
  const episodeRef = useRef(0);
  const failingRef = useRef(false);

  // Switching analyses must never carry another analysis's log forward.
  useEffect(() => {
    setEntries([]);
    seenRef.current = new Set();
    acceptedAtRef.current = null;
    episodeRef.current = 0;
    failingRef.current = false;
  }, [analysisId]);

  useEffect(() => {
    if (!detail) {
      return;
    }
    const createdMs = detail.analysis.timestamp ? Date.parse(detail.analysis.timestamp) : Number.NaN;
    if (acceptedAtRef.current == null && !Number.isNaN(createdMs)) {
      acceptedAtRef.current = createdMs;
    }
    const now = Date.now();
    const additions: TerminalEntry[] = [];
    const record = (entry: TerminalEntry) => {
      if (seenRef.current.has(entry.key)) {
        return;
      }
      seenRef.current.add(entry.key);
      if (entry.source === "observed" && entry.elapsedMs == null && acceptedAtRef.current != null) {
        entry.elapsedMs = now - acceptedAtRef.current;
      }
      additions.push(entry);
    };

    for (const entry of backendEntries(detail)) {
      record(entry);
    }

    if (failingRef.current) {
      failingRef.current = false;
      record({
        key: `refresh-recovered:${episodeRef.current}`,
        source: "observed",
        level: "info",
        timestamp: null,
        elapsedMs: null,
        text: "Status connection restored",
      });
    }

    if (additions.length > 0) {
      setEntries((previous) => [...previous, ...additions]);
    }
  }, [detail]);

  useEffect(() => {
    if (!error || failingRef.current) {
      return;
    }
    failingRef.current = true;
    episodeRef.current += 1;
    const key = `refresh-failed:${episodeRef.current}`;
    if (seenRef.current.has(key)) {
      return;
    }
    seenRef.current.add(key);
    const now = Date.now();
    setEntries((previous) => [
      ...previous,
      {
        key,
        source: "observed",
        level: "error",
        timestamp: null,
        elapsedMs: acceptedAtRef.current != null ? now - acceptedAtRef.current : null,
        text:
          error instanceof ApiRequestError
            ? `Status refresh failed (${error.code})`
            : "Status refresh failed",
      },
    ]);
  }, [error]);

  return entries;
}

function TerminalLine({ entry }: { entry: TerminalEntry }) {
  const marker = LEVEL_MARKER[entry.level];
  const time =
    entry.source === "backend" && entry.timestamp
      ? formatBackendTimestamp(entry.timestamp)
      : entry.elapsedMs != null
        ? `~${formatElapsed(entry.elapsedMs)}`
        : "—";
  return (
    <p className="flex gap-3">
      <span
        className="shrink-0 tabular-nums text-text-secondary"
        title={entry.source === "observed" ? "Observed by the browser" : "Reported by the backend"}
      >
        {time}
      </span>
      <span aria-hidden="true" className={`shrink-0 ${marker.className}`}>
        {marker.glyph}
      </span>
      <span className={marker.className}>
        <span className="text-text-primary">{entry.text}</span>
        {entry.source === "observed" ? (
          <span className="sr-only"> (observed in the browser)</span>
        ) : null}
      </span>
    </p>
  );
}

export function AnalysisTerminal({
  analysisId,
  detail,
  error,
  isFetching,
}: {
  analysisId: string;
  detail: AnalysisDetail | undefined;
  error: unknown;
  isFetching: boolean;
}) {
  const entries = useTerminalLog(analysisId, detail, error);
  const [expanded, setExpanded] = useState(true);
  const logRef = useRef<HTMLDivElement>(null);
  const followRef = useRef(true);

  useEffect(() => {
    const node = logRef.current;
    if (!node || !followRef.current) {
      return;
    }
    node.scrollTop = node.scrollHeight;
  }, [entries]);

  function handleScroll() {
    const node = logRef.current;
    if (!node) {
      return;
    }
    followRef.current = node.scrollHeight - node.scrollTop - node.clientHeight < 24;
  }

  const outcome = detail?.status.outcome ?? null;
  const stage = detail?.status.stage ?? null;
  const running = outcome == null;

  let stateWord: string;
  if (error && !detail) {
    stateWord = "connection error";
  } else if (error) {
    stateWord = "last confirmed status (refresh failing)";
  } else if (outcome != null) {
    stateWord = outcome;
  } else if (stage) {
    stateWord = `running · ${stageLabel(stage)}`;
  } else {
    stateWord = "starting";
  }

  return (
    <section
      aria-labelledby="analysis-terminal-title"
      className="overflow-hidden rounded-panel border border-border bg-secondary font-mono text-sm shadow-panel"
    >
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-4 py-3">
        <h2
          id="analysis-terminal-title"
          className="flex items-center gap-2 text-text-primary"
        >
          <span aria-hidden="true" className={running ? "text-primary" : "text-text-secondary"}>
            {running ? "▶" : "■"}
          </span>
          <span className="t-label">Analysis terminal</span>
        </h2>
        <div className="flex items-center gap-3">
          <span className="text-xs text-text-secondary" aria-live="polite">
            {stateWord}
          </span>
          <button
            type="button"
            aria-expanded={expanded}
            onClick={() => setExpanded((value) => !value)}
            className="rounded-control border border-border px-2 py-1 text-xs text-text-secondary hover:border-primary hover:text-text-primary"
          >
            {expanded ? "Hide log" : "Show log"}
          </button>
        </div>
      </header>

      {expanded ? (
        <div
          ref={logRef}
          role="log"
          aria-live="polite"
          aria-label="Analysis status log"
          onScroll={handleScroll}
          className="max-h-80 overflow-y-auto px-4 py-3 leading-6"
        >
          {entries.length === 0 ? (
            <p className="text-text-secondary">Waiting for the first status update…</p>
          ) : (
            entries.map((entry) => <TerminalLine key={entry.key} entry={entry} />)
          )}
        </div>
      ) : null}

      <footer className="border-t border-border px-4 py-2 text-xs text-text-secondary">
        {isFetching
          ? "Refreshing status…"
          : running
            ? "Status refreshes automatically while the analysis runs."
            : "Status polling stopped."}
      </footer>
    </section>
  );
}
