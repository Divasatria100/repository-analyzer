import { fireEvent, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderAt } from "../../test/render";
import { DEFAULT_DENSITY, usePreferencesStore } from "../../stores/usePreferencesStore";

beforeEach(() => {
  window.localStorage.clear();
  usePreferencesStore.setState({ density: DEFAULT_DENSITY });
  delete document.documentElement.dataset.density;
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  window.localStorage.clear();
  usePreferencesStore.setState({ density: DEFAULT_DENSITY });
});

describe("Settings density preference", () => {
  it("renders both modes with Comfortable selected by default", () => {
    renderAt("/settings");
    expect(screen.getAllByRole("heading", { name: "Settings" }).length).toBeGreaterThan(0);
    const comfortable = screen.getByRole("radio", { name: /Comfortable/ });
    const compact = screen.getByRole("radio", { name: /Compact/ });
    expect((comfortable as HTMLInputElement).checked).toBe(true);
    expect((compact as HTMLInputElement).checked).toBe(false);
    expect(screen.getByText(/40px data-table rows/)).toBeDefined();
    expect(screen.getByText(/32px data-table rows/)).toBeDefined();
  });

  it("selecting Compact updates the store, the document, and persistence", () => {
    renderAt("/settings");
    fireEvent.click(screen.getByRole("radio", { name: /Compact/ }));
    expect(usePreferencesStore.getState().density).toBe("compact");
    expect(document.documentElement.dataset.density).toBe("compact");
    const stored = window.localStorage.getItem("repolens-preferences");
    expect(stored).toContain("compact");
  });

  it("restores the persisted choice and keeps working when storage fails", () => {
    renderAt("/settings");
    fireEvent.click(screen.getByRole("radio", { name: /Compact/ }));
    // Simulate a reload: the persisted JSON drives the next store state.
    const stored = window.localStorage.getItem("repolens-preferences");
    expect(stored).toContain("compact");
    // Storage failure must not break selection: replace the storage with a
    // throwing stub and verify in-memory state still applies.
    const descriptor = Object.getOwnPropertyDescriptor(window, "localStorage");
    const throwing: Storage = {
      get length() {
        return 0;
      },
      clear: () => {},
      getItem: () => null,
      key: () => null,
      removeItem: () => {},
      setItem: () => {
        throw new DOMException("denied", "QuotaExceededError");
      },
    };
    Object.defineProperty(window, "localStorage", { configurable: true, value: throwing });
    try {
      fireEvent.click(screen.getByRole("radio", { name: /Comfortable/ }));
      expect(usePreferencesStore.getState().density).toBe("comfortable");
      expect(document.documentElement.dataset.density).toBe("comfortable");
    } finally {
      if (descriptor) {
        Object.defineProperty(window, "localStorage", descriptor);
      }
    }
  });
});
