import { fireEvent, screen, waitFor } from "@testing-library/react";
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

  it("offers a skip link targeting focusable main content", () => {
    renderAt("/dashboard");
    const skip = screen.getByRole("link", { name: "Skip to main content" });
    expect(skip.getAttribute("href")).toBe("#main-content");
    const main = document.getElementById("main-content");
    expect(main).not.toBeNull();
    expect(main?.getAttribute("tabindex")).toBe("-1");
  });

  it("moves focus to the page heading when navigation drops focus", async () => {
    const router = renderAt("/dashboard");
    // Simulate focus lost with the unmounted page, then navigate.
    (document.activeElement as HTMLElement | null)?.blur?.();
    expect(document.activeElement).toBe(document.body);
    await router.navigate("/history");
    await waitFor(() => {
      const headings = screen.getAllByRole("heading", { name: "History" });
      expect(document.activeElement).toBe(headings[0]);
    });
  });

  it("applies the density preference to the document", async () => {
    const { usePreferencesStore } = await import("../stores/usePreferencesStore");
    renderAt("/dashboard");
    await waitFor(() => {
      expect(document.documentElement.dataset.density).toBe("comfortable");
    });
    usePreferencesStore.getState().setDensity("compact");
    await waitFor(() => {
      expect(document.documentElement.dataset.density).toBe("compact");
    });
    usePreferencesStore.getState().setDensity("comfortable");
  });
});
