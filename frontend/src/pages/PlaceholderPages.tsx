import { Link } from "react-router";
import { useParams } from "react-router";
import { ANALYSIS_ID_PARAM, ROUTES } from "../router/routes";
import { AnalysisProgress } from "../features/analysis/progress";
import { EmptyState, Panel } from "../components/ui";

// Placeholders for routes whose full functionality belongs to later phases.
// Each states plainly what is (and is not) available; none fabricates data.

export function SectionPlaceholder({ title }: { title: string }) {
  return (
    <Panel>
      <h2 className="text-lg font-semibold">{title}</h2>
      <EmptyState title={`${title} is not implemented yet.`}>
        <p>This view arrives in a later phase. No data is shown rather than mock data.</p>
      </EmptyState>
    </Panel>
  );
}

/** Index route of /analysis/:id — renders the real server state (TASK-188). */
export function AnalysisStatusPage() {
  const params = useParams();
  const analysisId = params[ANALYSIS_ID_PARAM];
  if (!analysisId) {
    return (
      <Panel>
        <EmptyState title="No analysis selected.">
          <p>
            Start with{" "}
            <Link className="text-primary underline" to={ROUTES.analysisNew}>
              New Analysis
            </Link>
            .
          </p>
        </EmptyState>
      </Panel>
    );
  }
  return <AnalysisProgress analysisId={analysisId} />;
}

export function HistoryPage() {
  return (
    <Panel>
      <h2 className="text-lg font-semibold">History</h2>
      <EmptyState title="Analysis history is not implemented yet.">
        <p>Per-repository history arrives in a later phase.</p>
      </EmptyState>
    </Panel>
  );
}

export function SettingsPage() {
  return (
    <Panel>
      <h2 className="text-lg font-semibold">Settings</h2>
      <EmptyState title="Settings are not implemented yet.">
        <p>The interface-density preference arrives in a later phase.</p>
      </EmptyState>
    </Panel>
  );
}

export function NotFoundPage() {
  return (
    <Panel>
      <h2 className="text-lg font-semibold">Page not found</h2>
      <EmptyState title="Nothing exists at this address.">
        <p>
          Go back to the{" "}
          <Link className="text-primary underline" to={ROUTES.dashboard}>
            Dashboard
          </Link>
          .
        </p>
      </EmptyState>
    </Panel>
  );
}
