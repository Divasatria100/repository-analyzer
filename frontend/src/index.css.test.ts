import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Stylesheet contract tests (TASK-210, TASK-214): density row heights and
// reduced-motion rules must exist and stay scoped. jsdom cannot compute
// layout, so these assert the authored rules directly from the file.

const css = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "index.css"), "utf-8");

describe("design stylesheet", () => {
  it("defines Comfortable 40px and Compact 32px data-table row heights", () => {
    expect(css).toContain("--rl-row-h: 40px");
    expect(css).toContain("--rl-row-h: 32px");
    expect(css).toContain('[data-density="compact"]');
    expect(css).toContain("main table tbody tr");
  });

  it("applies row height as a minimum so multiline content can grow", () => {
    expect(css).toMatch(/main table tbody tr\s*\{\s*height:/);
  });

  it("disables non-essential motion under prefers-reduced-motion", () => {
    expect(css).toContain("@media (prefers-reduced-motion: reduce)");
    expect(css).toContain("animation-duration");
    expect(css).toContain("transition-duration");
  });

  it("keeps a visible keyboard focus indicator", () => {
    expect(css).toContain(":focus-visible");
  });
});
