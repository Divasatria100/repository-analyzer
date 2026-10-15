// Last-viewed repository for the Dashboard's Recent Analyses (docs/14 §6.2).
// There is no cross-repository listing endpoint, so the Dashboard shows the
// history of one repository: the most recently submitted or opened one.
// A single localStorage id — never analysis data, never secrets.

const STORAGE_KEY = "repolens-dashboard-repository";

export function getRecentRepositoryId(): string | null {
  try {
    const value = window.localStorage.getItem(STORAGE_KEY);
    return value && value.trim() !== "" ? value : null;
  } catch {
    return null;
  }
}

export function setRecentRepositoryId(repositoryId: string): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, repositoryId);
  } catch {
    // Persistence is a convenience; the workflow works without it.
  }
}

export function clearRecentRepositoryId(): void {
  try {
    window.localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Nothing to do when storage is unavailable.
  }
}
