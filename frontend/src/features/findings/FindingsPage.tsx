import { useParams } from "react-router";
import { ANALYSIS_ID_PARAM } from "../../router/routes";
import { FindingsExplorer } from "./FindingsExplorer";

// Findings explorer route (TASK-190): cross-area table over the §4.3
// endpoint with server-side filter/sort/search/pagination.
export function FindingsPage() {
  const params = useParams();
  const analysisId = params[ANALYSIS_ID_PARAM] ?? "";
  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">Findings</h2>
      <FindingsExplorer analysisId={analysisId} />
    </div>
  );
}
