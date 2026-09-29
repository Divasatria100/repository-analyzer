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
