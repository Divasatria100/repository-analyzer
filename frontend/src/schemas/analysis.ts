import { z } from "zod";

// API shapes for the New Analysis workflow (docs/17-api-contract.md).
// The backend remains authoritative: client validation is structural only,
// mirroring backend/app/repository/identity.py without guessing extra rules.

// docs/17 §4.1 — POST /api/analyses request body.
export const analysisCreateRequestSchema = z.object({
  url: z.string(),
  branch: z.string().nullable().optional(),
  commit: z.string().nullable().optional(),
});

export type AnalysisCreateRequest = z.infer<typeof analysisCreateRequestSchema>;

// docs/17 §3.4 — the single error envelope.
export const apiErrorEnvelopeSchema = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
    details: z.unknown().nullable().optional(),
  }),
});

export type ApiErrorEnvelope = z.infer<typeof apiErrorEnvelopeSchema>;

// Frozen contract error codes (backend/app/api/errors.py, docs/17 §3.4).
export const API_ERROR_CODES = [
  "INVALID_URL",
  "REPOSITORY_NOT_ACCESSIBLE",
  "INVALID_BRANCH",
  "INVALID_COMMIT",
  "ANALYSIS_NOT_FOUND",
  "REPOSITORY_NOT_FOUND",
  "ANALYSIS_FAILED",
  "ANALYSIS_NOT_COMPLETED",
  "REPORT_UNAVAILABLE",
  "VALIDATION_ERROR",
  "RATE_LIMITED",
  "INTERNAL_ERROR",
] as const;

export type ApiErrorCode = (typeof API_ERROR_CODES)[number];

// docs/17 §2 + docs/13 §6.1 — lifecycle vocabulary. No invented states.
export const ANALYSIS_STAGES = [
  "Queued",
  "ValidatingRepository",
  "ResolvingCommit",
  "RetrievingRepository",
  "IndexingFiles",
  "DetectingLanguages",
  "ParsingSource",
  "BuildingCodeModel",
  "RunningAnalysis",
  "AggregatingResults",
  "GeneratingReports",
] as const;

export type AnalysisStage = (typeof ANALYSIS_STAGES)[number];

export const TERMINAL_OUTCOMES = ["Completed", "Completed with limitations", "Failed"] as const;

export type TerminalOutcome = (typeof TERMINAL_OUTCOMES)[number];

export function isTerminalOutcome(value: unknown): value is TerminalOutcome {
  return (
    typeof value === "string" && (TERMINAL_OUTCOMES as readonly string[]).includes(value)
  );
}

// docs/17 §4.1 — 202 response. `stage` is the persisted acceptance stage.
export const analysisAcceptedSchema = z.object({
  analysis_id: z.string(),
  repository_id: z.string(),
  stage: z.string(),
});

export type AnalysisAccepted = z.infer<typeof analysisAcceptedSchema>;

// docs/17 §4.2 — GET /api/analyses/{id}. Sections stay permissive: this
// phase only needs identity, lifecycle, and failure explanation. Unknown
// members pass through; missing members fail validation loudly instead of
// being rendered as a misleading success.
const analyzedStateSchema = z.object({
  branch: z.object({ name: z.string(), origin: z.string() }).nullable(),
  commit: z.object({ sha: z.string(), origin: z.string() }).nullable(),
});

export const analysisDetailSchema = z
  .object({
    analysis: z.object({
      analysis_id: z.string(),
      repository_id: z.string(),
      timestamp: z.string().nullable(),
    }),
    repository: z.object({
      repository_id: z.string(),
      url: z.string(),
      owner: z.string(),
      name: z.string(),
      analyzed_state: analyzedStateSchema,
    }),
    status: z.object({
      stage: z.string().nullable(),
      outcome: z.string().nullable(),
      completed_at: z.string().nullable().optional(),
      explanation: z.string().nullable().optional(),
    }),
  })
  .passthrough();

export type AnalysisDetail = z.infer<typeof analysisDetailSchema>;
