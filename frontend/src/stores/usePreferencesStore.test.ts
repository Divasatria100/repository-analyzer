import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import {
  DEFAULT_DENSITY,
  normalizeDensity,
  usePreferencesStore,
} from "./usePreferencesStore";

beforeEach(() => {
  window.localStorage.clear();
  usePreferencesStore.setState({ density: DEFAULT_DENSITY });
});

describe("preferences store foundation", () => {
  it("defaults to Comfortable", () => {
    expect(usePreferencesStore.getState().density).toBe("comfortable");
  });

  it("reads and updates density through the hook", () => {
    const { result } = renderHook(() => usePreferencesStore());
    act(() => {
      result.current.setDensity("compact");
    });
    expect(result.current.density).toBe("compact");
  });

  it("falls back to default for unknown values", () => {
    expect(normalizeDensity("ultra-wide")).toBe(DEFAULT_DENSITY);
    expect(normalizeDensity(undefined)).toBe(DEFAULT_DENSITY);
  });
});
