import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiRequestError, getAnalysis, postAnalysis } from "./api";

function mockFetch(handler: () => Promise<Response>) {
  window.fetch = vi.fn(handler);
  return window.fetch as unknown as ReturnType<typeof vi.fn>;
}

function jsonResponse(payload: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(JSON.stringify(payload)),
  } as Response;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("API client", () => {
  it("submits the create payload and parses the 202 response", async () => {
    const fetchMock = mockFetch(() =>
      Promise.resolve(jsonResponse({ analysis_id: "a", repository_id: "r", stage: "Queued" }, 202)),
    );
    const accepted = await postAnalysis({ url: "https://github.com/acme/web" });
    expect(accepted).toEqual({ analysis_id: "a", repository_id: "r", stage: "Queued" });
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ url: "https://github.com/acme/web" });
  });

  it("surfaces the contract error envelope with its code", async () => {
    mockFetch(() =>
      Promise.resolve(
        jsonResponse({ error: { code: "INVALID_BRANCH", message: "Branch not found.", details: null } }, 422),
      ),
    );
    const failure = await postAnalysis({ url: "https://github.com/acme/web", branch: "nope" }).catch(
      (error: unknown) => error,
    );
    expect(failure).toBeInstanceOf(ApiRequestError);
    expect((failure as ApiRequestError).code).toBe("INVALID_BRANCH");
  });

  it("handles non-JSON error bodies without crashing", async () => {
    mockFetch(() => Promise.resolve({ ok: false, status: 502, text: () => Promise.resolve("<html>bad gateway</html>") } as Response));
    const failure = await getAnalysis("abc").catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ApiRequestError);
    expect((failure as ApiRequestError).code).toBe("UNKNOWN_ERROR");
  });

  it("handles connection failures with a retryable message", async () => {
    mockFetch(() => Promise.reject(new TypeError("fetch failed")));
    const failure = await getAnalysis("abc").catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ApiRequestError);
    expect((failure as ApiRequestError).code).toBe("NETWORK_ERROR");
  });

  it("rejects malformed success payloads instead of misrendering them", async () => {
    mockFetch(() => Promise.resolve(jsonResponse({ unexpected: true })));
    const failure = await getAnalysis("abc").catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ApiRequestError);
    expect((failure as ApiRequestError).code).toBe("UNKNOWN_ERROR");
  });
});
