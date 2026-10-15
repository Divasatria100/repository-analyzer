import { apiBaseUrl } from "./appConfig";
import {
  type AnalysisAccepted,
  type AnalysisCreateRequest,
  type AnalysisDetail,
  analysisAcceptedSchema,
  analysisDetailSchema,
  apiErrorEnvelopeSchema,
} from "../schemas/analysis";
import {
  type AnalysisResult,
  type ArchitectureDoc,
  type FindingsPage,
  type FindingsQuery,
  type RepositoryHistory,
  analysisResultSchema,
  architectureDocSchema,
  findingsPageSchema,
  repositoryHistorySchema,
} from "../schemas/results";

// Transport layer for the analyses API (docs/17-api-contract.md).
// Serialization, envelope parsing, and HTTP error normalization live here;
// components only handle the resulting ApiRequestError or typed data.

export class ApiRequestError extends Error {
  /** Frozen contract code, or a transport-level code below. */
  readonly code: string;
  readonly status: number | null;
  readonly details: unknown;

  constructor(code: string, message: string, status: number | null = null, details: unknown = null) {
    super(message);
    this.name = "ApiRequestError";
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

function joinUrl(path: string): string {
  return `${apiBaseUrl.replace(/\/+$/, "")}${path}`;
}

async function parseBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) {
    return null;
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    // Non-JSON bodies (proxies, gateways) must not crash parsing.
    return null;
  }
}

function contractError(payload: unknown, status: number): ApiRequestError | null {
  const parsed = apiErrorEnvelopeSchema.safeParse(payload);
  if (!parsed.success) {
    return null;
  }
  const { code, message } = parsed.data.error;
  return new ApiRequestError(code, message || "The request could not be completed.", status);
}

async function request<T>(
  path: string,
  init: RequestInit,
  parse: (payload: unknown) => T,
): Promise<T> {
  let response: Response;
  try {
    response = await fetch(joinUrl(path), {
      ...init,
      headers: { "content-type": "application/json", ...(init.headers ?? {}) },
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw error;
    }
    throw new ApiRequestError(
      "NETWORK_ERROR",
      "Could not reach the backend. Check that it is running and try again.",
    );
  }
  const payload = await parseBody(response);
  if (!response.ok) {
    throw (
      contractError(payload, response.status) ??
      new ApiRequestError(
        "UNKNOWN_ERROR",
        `The request failed (HTTP ${response.status}). Try again.`,
        response.status,
      )
    );
  }
  try {
    return parse(payload);
  } catch {
    throw new ApiRequestError(
      "UNKNOWN_ERROR",
      "The backend returned a response the app does not understand. Try again.",
      response.status,
    );
  }
}

/** POST /api/analyses — accept a public repository for analysis (docs/17 §4.1). */
export async function postAnalysis(body: AnalysisCreateRequest): Promise<AnalysisAccepted> {
  return request(
    "/api/analyses",
    { method: "POST", body: JSON.stringify(body) },
    (payload) => analysisAcceptedSchema.parse(payload),
  );
}

/** GET /api/analyses/{id} — current stage/outcome and completed result (docs/17 §4.2). */
export async function getAnalysis(analysisId: string): Promise<AnalysisDetail> {
  return request(
    `/api/analyses/${encodeURIComponent(analysisId)}`,
    { method: "GET" },
    (payload) => analysisDetailSchema.parse(payload),
  );
}

/** GET /api/analyses/{id} parsed as the full canonical result (completed only). */
export async function getAnalysisResult(
  analysisId: string,
  signal?: AbortSignal,
  comparisonBase?: string,
): Promise<AnalysisResult> {
  const suffix =
    comparisonBase != null && comparisonBase !== ""
      ? `?comparison_base=${encodeURIComponent(comparisonBase)}`
      : "";
  return request(
    `/api/analyses/${encodeURIComponent(analysisId)}${suffix}`,
    { method: "GET", signal },
    (payload) => analysisResultSchema.parse(payload),
  );
}

function repeatParams(params: URLSearchParams, key: string, values: string[]): void {
  for (const value of values) {
    if (value !== "") {
      params.append(key, value);
    }
  }
}

/** GET /api/analyses/{id}/findings — server-side filter/sort/paginate (§4.3). */
export async function listFindings(
  analysisId: string,
  query: FindingsQuery,
  signal?: AbortSignal,
): Promise<FindingsPage> {
  const params = new URLSearchParams();
  repeatParams(params, "category", query.category);
  repeatParams(params, "severity", query.severity);
  repeatParams(params, "confidence", query.confidence);
  repeatParams(params, "rule_id", query.rule_id);
  if (query.q.trim() !== "") {
    params.set("q", query.q.trim());
  }
  params.set("sort", query.sort);
  params.set("order", query.order);
  params.set("page", String(query.page));
  params.set("page_size", String(query.page_size));
  const suffix = params.toString();
  return request(
    `/api/analyses/${encodeURIComponent(analysisId)}/findings${suffix ? `?${suffix}` : ""}`,
    { method: "GET", signal },
    (payload) => findingsPageSchema.parse(payload),
  );
}

/** GET /api/analyses/{id}/architecture — bounded graph document (docs/17 §4.4). */
export async function getArchitecture(
  analysisId: string,
  signal?: AbortSignal,
): Promise<ArchitectureDoc> {
  return request(
    `/api/analyses/${encodeURIComponent(analysisId)}/architecture`,
    { method: "GET", signal },
    (payload) => architectureDocSchema.parse(payload),
  );
}

/** GET /api/repositories/{id} — repository identity plus analysis history (§4.5). */
export async function getRepositoryHistory(
  repositoryId: string,
  signal?: AbortSignal,
): Promise<RepositoryHistory> {
  return request(
    `/api/repositories/${encodeURIComponent(repositoryId)}`,
    { method: "GET", signal },
    (payload) => repositoryHistorySchema.parse(payload),
  );
}

export const REPORT_FORMATS = ["json", "markdown", "html"] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];

export const REPORT_CONTENT_TYPES: Record<ReportFormat, string> = {
  json: "application/json",
  markdown: "text/markdown",
  html: "text/html",
};

export const REPORT_FILE_EXTENSIONS: Record<ReportFormat, string> = {
  json: "json",
  markdown: "md",
  html: "html",
};

export interface ReportBlob {
  format: ReportFormat;
  contentType: string;
  text: string;
}

/** GET /api/analyses/{id}/report — raw server bytes for view/export (§4.6).
 *
 * Returns text for every format (JSON included) so the caller downloads
 * exactly what the server sealed. Non-2xx responses raise ApiRequestError
 * and must never be saved as reports.
 */
export async function fetchReport(
  analysisId: string,
  format: ReportFormat,
  signal?: AbortSignal,
): Promise<ReportBlob> {
  let response: Response;
  try {
    response = await fetch(
      joinUrl(`/api/analyses/${encodeURIComponent(analysisId)}/report?format=${format}`),
      { method: "GET", signal, cache: "no-store" },
    );
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw error;
    }
    throw new ApiRequestError(
      "NETWORK_ERROR",
      "Could not reach the backend. Check that it is running and try again.",
    );
  }
  const text = await response.text();
  if (!response.ok) {
    let payload: unknown = null;
    try {
      payload = text ? (JSON.parse(text) as unknown) : null;
    } catch {
      payload = null;
    }
    throw (
      contractError(payload, response.status) ??
      new ApiRequestError(
        "UNKNOWN_ERROR",
        `The request failed (HTTP ${response.status}). Try again.`,
        response.status,
      )
    );
  }
  return {
    format,
    contentType: response.headers.get("content-type") ?? REPORT_CONTENT_TYPES[format],
    text,
  };
}
