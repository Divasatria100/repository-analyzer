import type { FindingEvidence } from "../../schemas/results";
import { StatusBadge } from "../../components/ui";

// Bounded source-context viewer (TASK-193, docs/17 §6 viewer Level 2).
// Displays ONLY the persisted, redacted evidence excerpt supplied by the
// backend. Never fetches repository source, never invents surrounding lines,
// never interprets evidence as markup: React renders all text as inert text.

export function SourceContext({
  evidence,
  path,
}: {
  evidence: FindingEvidence | null | undefined;
  path: string | null;
}) {
  if (!evidence) {
    return <p className="text-sm text-text-secondary">No evidence recorded for this finding.</p>;
  }
  const context = evidence.source_context ?? null;
  if (context == null || context.text == null) {
    return (
      <div className="space-y-2">
        {evidence.redacted ? (
          <StatusBadge label="Redacted" tone="neutral" marker="–" />
        ) : null}
        <p className="text-sm text-text-secondary">
          No source excerpt is available for this finding.
        </p>
      </div>
    );
  }
  const lines = context.text.split("\n");
  const gutterStart = context.start_line ?? null;
  const range =
    context.start_line != null
      ? context.end_line != null && context.end_line !== context.start_line
        ? `lines ${context.start_line}–${context.end_line}`
        : `line ${context.start_line}`
      : "bounded excerpt";
  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center gap-2 text-xs">
        {evidence.redacted ? <StatusBadge label="Redacted" tone="neutral" marker="–" /> : null}
        {context.truncated ? <StatusBadge label="Truncated excerpt" tone="warning" marker="▲" /> : null}
        <span className="text-text-secondary">
          Bounded excerpt{path ? ` from ${path}` : ""} ({range}); not the full file.
        </span>
      </div>
      <pre className="overflow-x-auto rounded-control border border-border bg-secondary p-3 font-mono text-xs leading-5">
        <code>
          {lines.map((line, index) => (
            <span key={index} className="block min-w-max">
              {gutterStart != null ? (
                <span aria-hidden="true" className="mr-3 inline-block w-10 text-right text-text-secondary select-none">
                  {gutterStart + index}
                </span>
              ) : null}
              {line === "" ? " " : line}
            </span>
          ))}
        </code>
      </pre>
    </div>
  );
}
