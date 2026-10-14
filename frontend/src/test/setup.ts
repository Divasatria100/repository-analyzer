import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";
import "@testing-library/jest-dom/vitest";

// Explicit imports are used (no globals); register DOM cleanup manually.
afterEach(() => {
  cleanup();
});

// jsdom lacks ResizeObserver, which visualization libraries require.
// Minimal test-environment stub (no production code depends on it).
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}

if (typeof window.ResizeObserver === "undefined") {
  window.ResizeObserver = ResizeObserverStub;
}

// jsdom ships its own AbortController/AbortSignal while Request/Response
// come from Node's undici stack, so react-router's internal
// `new Request(url, { signal })` during client-side navigation throws a
// realm TypeError. Tests never need request cancellation, so drop the
// foreign-realm signal at the boundary (no production code depends on it).
const NativeRequest = globalThis.Request;
class TestRequest extends NativeRequest {
  constructor(input: RequestInfo | URL, init?: RequestInit) {
    const { signal: _dropped, ...rest } = init ?? {};
    super(input, rest);
  }
}
globalThis.Request = TestRequest as typeof Request;
