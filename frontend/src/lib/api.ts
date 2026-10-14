import { apiBaseUrl } from "./appConfig";
import {
  type AnalysisAccepted,
  type AnalysisCreateRequest,
  type AnalysisDetail,
  analysisAcceptedSchema,
  analysisDetailSchema,
  apiErrorEnvelopeSchema,
} from "../schemas/analysis";

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
  } catch {
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
