import { z } from "zod";

// Canonical result shapes (docs/13-analysis-result-format.md, docs/17 §4).
// Field names mirror backend/app/results/canonical.py exactly. The backend
// remains authoritative: unknown members pass through, missing required
// members fail validation loudly instead of rendering as a false clean.

// docs/13 §8 — one canonical finding. Locations carry no `primary` marker in
// the serialized contract (backend/app/results/canonical.py::_location_entry),
// so the first location is the display location.
const findingLocationSchema = z.object({
  path: z.string(),
  start_line: z.number().nullable().optional(),
  end_line: z.number().nullable().optional(),
  start_column: z.number().nullable().optional(),
  end_column: z.number().nullable().optional(),
});

const findingSubjectSchema = z.object({
  locations: z.array(findingLocationSchema),
  modules: z.array(z.string()),
  dependencies: z.array(z.string()),
});

const sourceContextSchema = z.object({
  text: z.string().nullable(),
  start_line: z.number().nullable().optional(),
  end_line: z.number().nullable().optional(),
  truncated: z.boolean().optional(),
});

export const findingEvidenceSchema = z
  .object({
    redacted: z.boolean(),
    source_context: sourceContextSchema.nullable().optional(),
  })
  .passthrough();

export const findingSchema = z
  .object({
    finding_id: z.string(),
    identity_key: z.string(),
    rule_id: z.string(),
    rule_name: z.string(),
    category: z.string(),
    severity: z.string(),
    confidence: z.string(),
    subject: findingSubjectSchema,
    evidence: findingEvidenceSchema.nullable().optional(),
    explanation: z.string(),
    impact: z.string().nullable().optional(),
    recommendation: z.string(),
  })
  .passthrough();

export type Finding = z.infer<typeof findingSchema>;
export type FindingEvidence = z.infer<typeof findingEvidenceSchema>;

// docs/17 §4.3 — findings page envelope. `total` is the UNFILTERED finding
// count; `items` is the filtered, sorted page. Never derive global counts
// from `items`.
export const findingsPageSchema = z
  .object({
    page: z.number(),
    page_size: z.number(),
    total: z.number(),
    items: z.array(findingSchema),
    unavailable_areas: z
      .array(z.object({ area: z.string(), state: z.string(), reason: z.string().nullable() }))
      .optional(),
  })
  .passthrough();

export type FindingsPage = z.infer<typeof findingsPageSchema>;

// docs/17 §4.3 vocabularies (backend/app/api/analyses.py).
export const FINDING_SORTS = ["severity", "confidence", "rule", "category", "file"] as const;

export const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"] as const;
export const CONFIDENCES = ["High", "Medium", "Low"] as const;
export const CATEGORIES = ["security", "architecture", "dependency", "code_structure"] as const;

export interface FindingsQuery {
  category: string[];
  severity: string[];
  confidence: string[];
  rule_id: string[];
  q: string;
  sort: string;
  order: string;
  page: number;
  page_size: number;
}

// docs/17 §4.4 — bounded architecture document.
const graphNodeSchema = z
  .object({
    node_id: z.string(),
    name: z.string(),
    paths: z.array(z.string()),
    partially_represented: z.boolean(),
    finding_ids: z.array(z.string()),
    layer: z.string().nullable().optional(),
  })
  .passthrough();

const graphEdgeSchema = z
  .object({
    source: z.string(),
    target: z.string(),
    relationship_type: z.string(),
    qualifiers: z.record(z.string(), z.boolean()).optional(),
    locations: z.array(
      z.object({
        path: z.string(),
        line: z.number().nullable(),
        column: z.number().nullable(),
      }),
    ),
  })
  .passthrough();

const cycleSchema = z.object({
  finding_id: z.string(),
  node_ids: z.array(z.string()),
});

// Canonical metric record (backend/app/results/canonical.py::_metric_record).
// `value` is absent when unavailable — never zero-filled by the frontend.
const metricRecordSchema = z
  .object({
    metric: z.string(),
    subject_path: z.string(),
    subject_name: z.string().nullable().optional(),
    availability: z.string(),
    value: z.number().nullable().optional(),
    potentially_incomplete: z.boolean().optional(),
  })
  .passthrough();

export const architectureDocSchema = z.object({
  granularity: z.string().nullable(),
  potentially_incomplete: z.boolean(),
  nodes: z.array(graphNodeSchema),
  edges: z.array(graphEdgeSchema),
  external_and_unresolved_references: z.array(z.unknown()),
  cycles: z.array(cycleSchema).nullable(),
  metrics: z.array(metricRecordSchema),
  metric_definitions: z.unknown(),
  findings: z.array(findingSchema),
  rule_evaluations: z.array(z.unknown()),
});

export type ArchitectureDoc = z.infer<typeof architectureDocSchema>;
export type GraphNode = z.infer<typeof graphNodeSchema>;
export type GraphEdge = z.infer<typeof graphEdgeSchema>;

// docs/13 §6–7 — status and summary slices for the Overview.
const domainStateSchema = z.object({
  area: z.string(),
  state: z.string().nullable(),
  reason: z.string().nullable(),
});

const limitationSchema = z
  .object({
    scope_kind: z.string().optional(),
    area: z.string().nullable().optional(),
    rule_id: z.string().nullable().optional(),
    path: z.string().nullable().optional(),
    reason: z.string(),
  })
  .passthrough();

export const analysisStatusSchema = z
  .object({
    stage: z.string().nullable(),
    outcome: z.string().nullable(),
    completed_at: z.string().nullable().optional(),
    explanation: z.string().nullable().optional(),
    snapshot: z.object({ sealed_at: z.string() }).nullable().optional(),
    domains: z.array(domainStateSchema),
    limitations: z.array(limitationSchema),
  })
  .passthrough();

const areaFindingsBlockSchema = z.object({
  total: z.number(),
  by_severity: z.record(z.string(), z.number()),
  by_confidence: z.record(z.string(), z.number()),
  by_rule: z.record(z.string(), z.number()),
});

const areaSummarySchema = z
  .object({
    state: z.string().nullable(),
    findings: areaFindingsBlockSchema.nullable(),
  })
  .passthrough();

export const analysisSummarySchema = z.record(z.string(), z.unknown()).and(
  z.object({
    security: areaSummarySchema,
    architecture: areaSummarySchema,
    dependencies: areaSummarySchema,
    code_structure: areaSummarySchema,
  }),
);

// Full §4.2 result for completed analyses. Sections are null when the area
// is unavailable (docs/13 §3.3) — never an empty stand-in.
const areaSectionSchema = z
  .object({ findings: z.array(findingSchema) })
  .passthrough()
  .nullable();

export const analysisResultSchema = z
  .object({
    analysis: z
      .object({
        analysis_id: z.string(),
        repository_id: z.string(),
        timestamp: z.string().nullable(),
        analyzer_version: z.string().nullable().optional(),
        rule_set_version: z.string().nullable().optional(),
      })
      .passthrough(),
    repository: z
      .object({
        repository_id: z.string(),
        url: z.string(),
        owner: z.string(),
        name: z.string(),
        analyzed_state: z.object({
          branch: z.object({ name: z.string(), origin: z.string() }).nullable(),
          commit: z.object({ sha: z.string(), origin: z.string() }).nullable(),
        }),
      })
      .passthrough(),
    status: analysisStatusSchema,
    summary: analysisSummarySchema.nullable(),
    security: areaSectionSchema,
    architecture: areaSectionSchema,
    dependencies: areaSectionSchema,
    code_structure: areaSectionSchema,
  })
  .passthrough();

export type AnalysisResult = z.infer<typeof analysisResultSchema>;

// Sections whose null means "unavailable", never "clean"
// (backend/app/api/common.py::NULL_SECTION_STATES).
export const NULL_SECTION_STATES = new Set([
  "Analysis not performed",
  "Analysis failed",
  "Analysis unavailable",
]);

export function isUnavailableState(state: string | null): boolean {
  return state !== null && NULL_SECTION_STATES.has(state);
}
