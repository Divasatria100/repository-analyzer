import { create } from "zustand";
import { createJSONStorage, persist } from "zustand/middleware";

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

// Storage access can throw (private mode, disabled cookies, quota).
// Fall back to an in-memory store so the UI keeps working with defaults.
function safeStorage(): Storage {
  const memory = new Map<string, string>();
  const fallback: Storage = {
    get length() {
      return memory.size;
    },
    clear: () => memory.clear(),
    getItem: (key: string) => (memory.has(key) ? memory.get(key) as string : null),
    key: (index: number) => [...memory.keys()][index] ?? null,
    removeItem: (key: string) => {
      memory.delete(key);
    },
    setItem: (key: string, value: string) => {
      memory.set(key, value);
    },
  };
  try {
    const probe = "__repolens_probe__";
    window.localStorage.setItem(probe, probe);
    window.localStorage.removeItem(probe);
    return window.localStorage;
  } catch {
    return fallback;
  }
}

export const usePreferencesStore = create<PreferencesState>()(
  persist(
    (set) => ({
      density: DEFAULT_DENSITY,
      setDensity: (density) => set({ density: normalizeDensity(density) }),
    }),
    {
      name: "repolens-preferences",
      storage: createJSONStorage(() => safeStorage()),
      // Unknown persisted values fall back to the default (14, Section 5.1).
      merge: (persisted, current) => ({
        ...current,
        density: normalizeDensity((persisted as Partial<PreferencesState> | undefined)?.density),
      }),
    },
  ),
);
