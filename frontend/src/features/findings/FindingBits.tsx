import { StatusBadge } from "../../components/ui";

// Finding presentation bits. Severity and confidence stay separate members
// everywhere (docs/13 §8.5); no combined measure is ever computed.

// Architecture findings never carry Critical, but the badge renders whatever
// the server reports — the frontend does not rescale or reinterpret values.
const SEVERITY_TONE = {
  Critical: "error",
  High: "error",
  Medium: "warning",
  Low: "info",
  Info: "neutral",
} as const;

export function SeverityBadge({ severity }: { severity: string }) {
  const tone = (SEVERITY_TONE as Record<string, "error" | "warning" | "info" | "neutral">)[
    severity
  ] ?? "neutral";
  const marker = severity === "Critical" || severity === "High" ? "✕" : severity === "Medium" ? "▲" : "–";
  return <StatusBadge label={severity} tone={tone} marker={marker} />;
}

export function ConfidenceBadge({ confidence }: { confidence: string }) {
  return <StatusBadge label={`confidence: ${confidence}`} tone="neutral" marker="●" />;
}

export function CategoryBadge({ category }: { category: string }) {
  return <StatusBadge label={category} tone="neutral" marker="–" />;
}

const AREA_LABELS: Record<string, string> = {
  security: "Security",
  architecture: "Architecture",
  dependency: "Dependencies",
  code_structure: "Code Structure",
};

export function areaLabel(area: string): string {
  return AREA_LABELS[area] ?? area;
}

/** First location is the display location (serialized contract has no primary flag). */
export function displayPath(paths: Array<{ path: string }>): string | null {
  return paths.length > 0 ? paths[0].path : null;
}

export function formatLineRange(
  start: number | null | undefined,
  end: number | null | undefined,
): string | null {
  if (start == null) {
    return null;
  }
  if (end == null || end === start) {
    return `line ${start}`;
  }
  return `lines ${start}–${end}`;
}
