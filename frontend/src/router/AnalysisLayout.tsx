import { Outlet } from "react-router";
import { AnalysisTabs } from "../components/AnalysisTabs";

// Analysis workspace frame (docs/14-ui-requirements.md, Section 8).
// The shell stays visible; workspace tabs live inside the workspace, never
// in the global sidebar. Section contents arrive in later phases.
export function AnalysisLayout() {
  return (
    <div className="min-w-0">
      <AnalysisTabs />
      <div className="pt-6">
        <Outlet />
      </div>
    </div>
  );
}
