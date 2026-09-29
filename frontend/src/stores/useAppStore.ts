import { create } from "zustand";

// Zustand foundation — client-side state only (see docs/09).
// Server state belongs to TanStack Query.
interface AppState {
  ready: boolean;
}

export const useAppStore = create<AppState>(() => ({
  ready: true,
}));
