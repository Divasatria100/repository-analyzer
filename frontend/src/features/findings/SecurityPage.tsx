import { useParams } from "react-router";
import { ANALYSIS_ID_PARAM } from "../../router/routes";
import { useAnalysisResult } from "../analysis/useAnalysisResult";
import { Alert, LoadingState, Panel } from "../../components/ui";
import { FindingsExplorer } from "./FindingsExplorer";

// Security view (TASK-191): the same explorer, category locked to the
// canonical `security` identifier. No separate data model, no severity
// inference, no score. An unavailable security section renders as
// unavailable — never as a clean result.

export function SecurityPage() {
  const params = useParams();
  const analysisId = params[ANALYSIS_ID_PARAM] ?? "";
  const { data, error, isLoading } = useAnalysisResult(analysisId);

  if (isLoading) {
    return <LoadingState label="Loading security findings…" />;
  }

  if (error || !data) {
    return (
      <Panel>
        <Alert tone="error" title="Could not load security findings.">
          <p>Try refreshing, or return to the analysis status.</p>
        </Alert>
      </Panel>
    );
  }

  if (data.status.outcome == null) {
    return (
      <Panel>
        <Alert tone="info" title="Security findings are unavailable while the analysis is not completed.">
          <p>Results appear once the backend reports a completed outcome.</p>
        </Alert>
      </Panel>
    );
  }

  if (data.security == null) {
    const domain = data.status.domains.find((item) => item.area === "security");
    return (
      <Panel>
        <Alert tone="warning" title="Security results are unavailable for this analysis.">
          <p>
            State: {domain?.state ?? "unavailable"}
            {domain?.reason ? ` — ${domain.reason}` : ""}
          </p>
          <p className="mt-1">This is not a clean result: the area was not evaluated.</p>
        </Alert>
      </Panel>
    );
  }

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">Security</h2>
      <FindingsExplorer analysisId={analysisId} lockedCategory="security" />
    </div>
  );
}
