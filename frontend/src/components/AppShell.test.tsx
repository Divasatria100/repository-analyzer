import { fireEvent, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { renderAt } from "../test/render";

describe("application shell", () => {
  it("shows the four primary navigation destinations", () => {
    renderAt("/dashboard");
    for (const label of ["Dashboard", "New Analysis", "History", "Settings"]) {
      expect(screen.getAllByRole("link", { name: label }).length).toBeGreaterThan(0);
    }
  });

  it("marks the current route as active", () => {
    renderAt("/history");
    const active = screen.getAllByRole("link", { name: "History" })[0];
    expect(active.getAttribute("aria-current")).toBe("page");
    const inactive = screen.getAllByRole("link", { name: "Dashboard" })[0];
    expect(inactive.getAttribute("aria-current")).toBeNull();
  });

  it("sets the document title per page", () => {
    renderAt("/analysis/new");
    expect(document.title).toContain("New Analysis");
  });

  it("opens and closes the navigation drawer with keyboard support", () => {
    renderAt("/dashboard");
    const menu = screen.getByRole("button", { name: "Open navigation" });
    fireEvent.click(menu);
    expect(screen.getByRole("dialog", { name: "Primary navigation" })).toBeDefined();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog", { name: "Primary navigation" })).toBeNull();
  });

  it("closes the drawer when navigating", () => {
    renderAt("/dashboard");
    fireEvent.click(screen.getByRole("button", { name: "Open navigation" }));
    expect(screen.getByRole("dialog", { name: "Primary navigation" })).toBeDefined();
    fireEvent.click(screen.getAllByRole("link", { name: "Settings" })[0]);
    expect(screen.queryByRole("dialog", { name: "Primary navigation" })).toBeNull();
    expect(screen.getAllByRole("heading", { name: "Settings" }).length).toBeGreaterThan(0);
  });
});
