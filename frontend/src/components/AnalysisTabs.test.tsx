import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { renderAt } from "../test/render";

describe("analysis tab navigation", () => {
  it("preserves the analysis identifier across all tabs", () => {
    renderAt("/analysis/abc123/security");
    const tabs = screen.getByRole("navigation", { name: "Analysis views" });
    for (const [label, href] of [
      ["Overview", "/analysis/abc123/overview"],
      ["Security", "/analysis/abc123/security"],
      ["Architecture", "/analysis/abc123/architecture"],
      ["Dependencies", "/analysis/abc123/dependencies"],
      ["Code Structure", "/analysis/abc123/code-structure"],
      ["Files", "/analysis/abc123/files"],
      ["Findings", "/analysis/abc123/findings"],
    ]) {
      const link = tabs.querySelector(`a[href="${href}"]`);
      expect(link, label).not.toBeNull();
    }
  });

  it("marks the active tab for assistive technology", () => {
    renderAt("/analysis/abc123/files");
    const tabs = screen.getByRole("navigation", { name: "Analysis views" });
    const active = tabs.querySelector('a[href="/analysis/abc123/files"]');
    expect(active?.getAttribute("aria-current")).toBe("page");
    const inactive = tabs.querySelector('a[href="/analysis/abc123/security"]');
    expect(inactive?.getAttribute("aria-current")).toBeNull();
  });

  it("keeps workspace tabs out of the global sidebar", () => {
    renderAt("/analysis/abc123/security");
    const primary = screen.getAllByRole("navigation", { name: "Primary" })[0];
    expect(primary.textContent).not.toContain("Security");
  });
});
