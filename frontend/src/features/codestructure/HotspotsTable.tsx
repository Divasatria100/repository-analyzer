import { useMemo } from "react";
import { Link } from "react-router";
import { ROUTES } from "../../router/routes";
import type { AnalysisResult, Finding } from "../../schemas/results";
import { EmptyState, Panel } from "../../components/ui";
import { SeverityBadge } from "../findings/FindingBits";

// Hotspots (TASK-202, docs/14 §12.3, FR-064/065). Groups measurement-based
// findings from the code-structure and architecture size findings by file
// and start line, keeping groups with more than one finding. "Notable" is
// decided by the rule set (a finding exists); the table shows each
// measurement separately and computes no combined score, rank, or index.

const ARCH_SIZE_RULE_PREFIX = "ARCH-LARGE-";

interface HotspotMeasurement {
  metric: string;
  value: unknown;
  exceeded: boolean | null;
  rule_id: string;
  finding_id: string;
  severity: string;
}

interface Hotspot {
  key: string;
  path: string;
  line: number | null;
  findings: Finding[];
  measurements: HotspotMeasurement[];
}

function findingMeasurements(finding: Finding): HotspotMeasurement[] {
  const evidence = finding.evidence as { measurements?: unknown } | null | undefined;
  const list = evidence?.measurements;
  if (!Array.isArray(list) || list.length === 0) {
    return [];
  }
  const out: HotspotMeasurement[] = [];
  for (const entry of list) {
    if (entry == null || typeof entry !== "object") {
      continue;
    }
    const record = entry as { metric?: unknown; value?: unknown; exceeded?: unknown };
    if (typeof record.metric !== "string") {
      continue;
    }
    out.push({
      metric: record.metric,
      value: record.value ?? null,
      exceeded: typeof record.exceeded === "boolean" ? record.exceeded : null,
      rule_id: finding.rule_id,
      finding_id: finding.finding_id,
      severity: finding.severity,
    });
  }
  return out;
}

function groupKey(finding: Finding): string | null {
  const location = finding.subject.locations[0];
  if (!location) {
    return null;
  }
  return `${location.path}:${location.start_line ?? ""}`;
}

export function HotspotsTable({
  analysisId,
  result,
}: {
  analysisId: string;
  result: AnalysisResult;
}) {
  const hotspots = useMemo<Hotspot[]>(() => {
    const candidates: Finding[] = [];
    if (result.code_structure) {
      candidates.push(...result.code_structure.findings);
    }
    if (result.architecture) {
      candidates.push(
        ...result.architecture.findings.filter((finding) =>
          finding.rule_id.startsWith(ARCH_SIZE_RULE_PREFIX),
        ),
      );
    }
    const groups = new Map<string, Finding[]>();
    for (const finding of candidates) {
      if (findingMeasurements(finding).length === 0) {
        continue;
      }
      const key = groupKey(finding);
      if (!key) {
        continue;
      }
      const group = groups.get(key) ?? [];
      group.push(finding);
      groups.set(key, group);
    }
    const spots: Hotspot[] = [];
    for (const [key, findings] of groups) {
      if (findings.length < 2) {
        continue;
      }
      const location = findings[0].subject.locations[0];
      spots.push({
        key,
        path: location.path,
        line: location.start_line ?? null,
        findings,
        measurements: findings.flatMap(findingMeasurements),
      });
    }
    spots.sort((a, b) => a.path.localeCompare(b.path) || (a.line ?? 0) - (b.line ?? 0));
    return spots;
  }, [result]);

  return (
    <Panel>
      <h3 className="mb-1 text-base font-semibold">Hotspots</h3>
      <p className="mb-3 text-sm text-text-secondary">
        Code areas with more than one measurement-based finding, grouped by file and
        start line. Each measurement is shown separately; there is no combined score.
        These are observations for review, not a verdict on code quality.
      </p>
      {hotspots.length === 0 ? (
        <EmptyState title="No hotspots reported.">
          <p>No location has more than one measurement-based finding in this analysis.</p>
        </EmptyState>
      ) : (
        <ul className="space-y-3">
          {hotspots.map((spot) => (
            <li key={spot.key} className="rounded-control border border-border px-3 py-2">
              <p className="break-identifier font-mono text-xs">
                {spot.path}
                {spot.line != null ? `:${spot.line}` : ""}
              </p>
              <ul className="mt-2 space-y-1 text-sm">
                {spot.measurements.map((measurement, index) => (
                  <li key={`${measurement.finding_id}-${measurement.metric}-${index}`} className="flex flex-wrap items-center gap-2">
                    <Link
                      className="font-mono text-xs text-primary underline"
                      to={ROUTES.analysisFindingDetail(analysisId, measurement.finding_id)}
                    >
                      {measurement.finding_id}
                    </Link>
                    <span className="font-mono text-xs">
                      {measurement.metric}: {String(measurement.value)}
                      {measurement.exceeded == null ? "" : measurement.exceeded ? " (exceeded)" : " (within threshold)"}
                    </span>
                    <SeverityBadge severity={measurement.severity} />
                  </li>
                ))}
              </ul>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
