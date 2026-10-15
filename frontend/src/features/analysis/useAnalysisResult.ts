import { useQuery } from "@tanstack/react-query";
import { ApiRequestError, getAnalysisResult } from "../../lib/api";

// Full canonical result for completed analyses (docs/17 §4.2).
// Shares the ["analysis", id] key with the progress status query, so
// navigating between status, overview, findings, and architecture never
// refetches. No polling here: lifecycle polling belongs to the progress
// view; these pages render whatever the server reports, once.
export function useAnalysisResult(analysisId: string, enabled = true) {
  return useQuery({
    queryKey: ["analysis", analysisId],
    queryFn: ({ signal }) => getAnalysisResult(analysisId, signal),
    enabled,
    refetchOnWindowFocus: false,
    retry: (count, error) => {
      if (error instanceof ApiRequestError && error.code === "ANALYSIS_NOT_FOUND") {
        return false;
      }
      return count < 1;
    },
  });
}
