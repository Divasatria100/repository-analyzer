import { describe, expect, it } from "vitest";
import { apiBaseUrl } from "./appConfig";

describe("appConfig foundation", () => {
  it("exposes a host-reachable backend base URL", () => {
    expect(apiBaseUrl.startsWith("http")).toBe(true);
    expect(apiBaseUrl).not.toContain("backend:8000");
  });
});
