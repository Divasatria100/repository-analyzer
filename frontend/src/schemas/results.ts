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
export const graphNodeSchema = z
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

export const cycleSchema = z.object({
  finding_id: z.string(),
  node_ids: z.array(z.string()),
});

// Canonical metric record (backend/app/results/canonical.py::_metric_record).
// `value` is absent when unavailable — never zero-filled by the frontend.
export const metricRecordSchema = z
  .object({
    metric: z.string(),
    subject_path: z.string(),
    subject_name: z.string().nullable().optional(),
    availability: z.string(),
    value: z.number().nullable().optional(),
    potentially_incomplete: z.boolean().optional(),
  })
  .passthrough();

export type MetricRecord = z.infer<typeof metricRecordSchema>;

// Canonical dependency item (backend/app/results/canonical.py::_dependency_items,
// docs/13 §11). Identity is the occurrence id: one package with different
// versions is several items. Never merge items by display name.
export const dependencyItemSchema = z
  .object({
    dependency_id: z.string(),
    name: z.string(),
    version: z.string().nullable(),
    ecosystem: z.string().nullable().optional(),
    classification: z.string(),
    source_manifest: z.string().nullable().optional(),
    introduced_by: z.array(z.string()),
    advisories: z.array(
      z.object({ advisory_id: z.string(), source: z.string() }).passthrough(),
    ),
    finding_ids: z.array(z.string()),
  })
  .passthrough();

export type DependencyItem = z.infer<typeof dependencyItemSchema>;

export const dependenciesSectionSchema = z
  .object({
    rule_evaluations: z.array(z.unknown()),
    items: z.array(dependencyItemSchema),
    findings: z.array(findingSchema),
  })
  .passthrough()
  .nullable();

export const codeStructureSectionSchema = z
  .object({
    rule_evaluations: z.array(z.unknown()),
    metric_definitions: z.record(
      z.string(),
      z
        .object({
          description: z.string(),
          interpretation: z.string(),
          unit: z.string(),
        })
        .passthrough(),
    ),
    metrics: z.array(metricRecordSchema),
    findings: z.array(findingSchema),
  })
  .passthrough()
  .nullable();

export type CodeStructureSection = z.infer<typeof codeStructureSectionSchema>;

// Canonical file record (backend/app/results/canonical.py::_file_entry,
// docs/13 §13). The tree, filters, and detail render only these fields.
export const fileRecordSchema = z
  .object({
    path: z.string(),
    file_type: z.string(),
    language: z.string().nullable(),
    support: z.string(),
    size: z.number().nullable().optional(),
    binary: z.boolean().nullable().optional(),
    generated: z.boolean().nullable().optional(),
    exclusion: z.object({ status: z.string(), reason: z.string().nullable() }).nullable(),
    eligibility: z.object({
      classification: z.string(),
      reason: z.string().nullable(),
    }),
    parse_result: z.string().nullable(),
    diagnostics: z.array(
      z.object({
        code: z.unknown(),
        message: z.unknown(),
        line: z.unknown(),
        column: z.unknown(),
      }),
    ),
    indexing_limitation: z.string().nullable().optional(),
    coverage: z.array(
      z.object({
        scope: z.object({ kind: z.string(), value: z.string() }),
        state: z.string(),
        reason: z.string().nullable().optional(),
      }),
    ),
    finding_count: z.number(),
  })
  .passthrough();

export type FileRecord = z.infer<typeof fileRecordSchema>;

// Canonical comparison (backend/app/results/canonical.py::comparison_to_dict,
// docs/13 §15). Findings match by identity key only; `qualified` marks
// resolved entries whose scope was not evaluated in the target.
const comparisonEntrySchema = z
  .object({
    identity_key: z.string(),
    rule_id: z.string(),
    category: z.string(),
    base_finding_id: z.string().nullable().optional(),
    target_finding_id: z.string().nullable().optional(),
    qualified: z.boolean().optional(),
  })
  .passthrough();

export const comparisonSchema = z.union([
  z.object({ comparable: z.literal(false), reason: z.string() }).passthrough(),
  z
    .object({
      comparable: z.literal(true),
      base: z
        .object({
          commit_sha: z.string().nullable(),
          timestamp: z.string().nullable(),
          analyzer_version: z.string(),
          rule_set_version: z.string(),
        })
        .passthrough(),
      target: z
        .object({
          commit_sha: z.string().nullable(),
          timestamp: z.string().nullable(),
          analyzer_version: z.string(),
          rule_set_version: z.string(),
        })
        .passthrough(),
      context_differences: z.record(z.string(), z.boolean()),
      qualifications: z.array(z.unknown()),
      new: z.array(comparisonEntrySchema),
      resolved: z.array(comparisonEntrySchema),
      unchanged: z.array(comparisonEntrySchema),
    })
    .passthrough(),
]);

export type Comparison = z.infer<typeof comparisonSchema>;
export type ComparisonEntry = z.infer<typeof comparisonEntrySchema>;

// Repository history (backend/app/api/repositories.py, docs/17 §4.5).
// Most-recent-first; same-commit analyses coexist as separate entries.
// Entries carry no finding totals — the UI shows "—", never 0.
export const historyEntrySchema = z
  .object({
    analysis_id: z.string(),
    branch: z.object({ name: z.string(), origin: z.string() }).nullable(),
    commit: z.object({ sha: z.string(), origin: z.string() }).nullable(),
    timestamp: z.string().nullable(),
    analyzer_version: z.string().nullable().optional(),
    rule_set_version: z.string().nullable().optional(),
    outcome: z.string().nullable(),
    explanation: z.string().nullable().optional(),
  })
  .passthrough();

export type HistoryEntry = z.infer<typeof historyEntrySchema>;

export const repositoryHistorySchema = z
  .object({
    repository_id: z.string(),
    url: z.string(),
    owner: z.string(),
    name: z.string(),
    analyses: z.array(historyEntrySchema),
  })
  .passthrough();

export type RepositoryHistory = z.infer<typeof repositoryHistorySchema>;

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

// Architecture section inside the canonical result: same graph/cycles/
// metrics as the §4.4 document plus rule evaluations and findings.
export const architectureSectionSchema = z
  .object({
    rule_evaluations: z.array(z.unknown()),
    metric_definitions: z.unknown(),
    metrics: z.array(metricRecordSchema),
    graph: z
      .object({
        granularity: z.string().nullable(),
        potentially_incomplete: z.boolean(),
        nodes: z.array(graphNodeSchema),
        edges: z.array(graphEdgeSchema),
        external_and_unresolved_references: z.array(z.unknown()),
      })
      .passthrough(),
    cycles: z.array(cycleSchema).nullable(),
    findings: z.array(findingSchema),
  })
  .passthrough()
  .nullable();

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
        advisory_data: z
          .object({
            source: z.string(),
            consulted_at: z.string().nullable(),
            outcome: z.string(),
          })
          .nullable()
          .optional(),
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
    architecture: architectureSectionSchema,
    dependencies: dependenciesSectionSchema,
    code_structure: codeStructureSectionSchema,
    files: z.array(fileRecordSchema).nullable(),
    comparison: comparisonSchema.nullable().optional(),
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
