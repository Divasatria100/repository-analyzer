import { create } from "zustand";
import { persist } from "zustand/middleware";

// Client-side UI preferences only (docs/14-ui-requirements.md, Section 5.1).
// V1.0 defines exactly one user-facing setting: interface density.
// Server/API data MUST NOT live here — that belongs to TanStack Query.
export const DENSITIES = ["comfortable", "compact"] as const;
export type InterfaceDensity = (typeof DENSITIES)[number];

export const DEFAULT_DENSITY: InterfaceDensity = "comfortable";

export function normalizeDensity(value: unknown): InterfaceDensity {
  return DENSITIES.includes(value as InterfaceDensity) ? (value as InterfaceDensity) : DEFAULT_DENSITY;
}

interface PreferencesState {
  density: InterfaceDensity;
  setDensity: (density: InterfaceDensity) => void;
}

export const usePreferencesStore = create<PreferencesState>()(
  persist(
    (set) => ({
      density: DEFAULT_DENSITY,
      setDensity: (density) => set({ density: normalizeDensity(density) }),
    }),
    {
      name: "repolens-preferences",
      // Unknown persisted values fall back to the default (14, Section 5.1).
      merge: (persisted, current) => ({
        ...current,
        density: normalizeDensity((persisted as Partial<PreferencesState> | undefined)?.density),
      }),
    },
  ),
);
