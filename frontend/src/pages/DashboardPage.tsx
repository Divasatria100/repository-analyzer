import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router";
import { ROUTES } from "../router/routes";
import { EmptyState, Panel } from "../components/ui";
import { clearRecentRepositoryId, getRecentRepositoryId } from "../lib/recentRepository";
import { RecentAnalyses } from "../features/dashboard/RecentAnalyses";

// Dashboard entry point (docs/14-ui-requirements.md, Section 6; TASK-208/209).
// First viewport: headline, scope note, primary action. The inline URL input
// submits into the New Analysis flow. Recent Analyses shows the history of
// one repository — the API lists history per repository only, so the scope
// is always labeled and no global counts are fabricated.

export function DashboardPage() {
  const navigate = useNavigate();
  const [quickUrl, setQuickUrl] = useState("");

  function handleQuickSubmit(event: FormEvent) {
    event.preventDefault();
    const trimmed = quickUrl.trim();
    navigate(trimmed ? `${ROUTES.analysisNew}?url=${encodeURIComponent(trimmed)}` : ROUTES.analysisNew);
  }
  return (
    <div className="space-y-6">
      <section className="py-20">
        <p className="t-label mb-4 text-primary">Static repository analysis</p>
        <h2 className="t-display max-w-3xl text-[40px] md:text-[64px]">
          Understand Your Codebase
        </h2>
        <p className="mt-2 text-sm text-text-secondary">
          Public GitHub repositories · static analysis
        </p>
        <form
          className="mt-6 flex max-w-2xl flex-col gap-3 sm:flex-row"
          onSubmit={(event) => void handleQuickSubmit(event)}
        >
          <label htmlFor="dashboard-url" className="sr-only">
            Repository URL
          </label>
          <input
            id="dashboard-url"
            name="url"
            type="url"
            placeholder="https://github.com/owner/repository"
            value={quickUrl}
            onChange={(event) => setQuickUrl(event.target.value)}
            className="break-identifier min-w-0 flex-1 rounded-control border border-border bg-secondary px-3 py-2.5 font-mono text-sm text-text-primary placeholder:text-text-secondary"
          />
          <button
            type="submit"
            className="rounded-control bg-primary px-5 py-2.5 text-center text-sm font-semibold text-background hover:brightness-110"
          >
            Analyze Repository
          </button>
        </form>
        <p className="mt-3 text-sm text-text-secondary">
          Security · Architecture · Dependencies · Code Structure
        </p>
      </section>
      <Panel title="Recent Analyses" labelledBy="recent-analyses">
        <DashboardRecents />
      </Panel>
    </div>
  );
}

function DashboardRecents() {
  const [repositoryId, setRepositoryId] = useState<string | null>(() => getRecentRepositoryId());
  if (!repositoryId) {
    return (
      <EmptyState title="No recent analyses to show yet.">
        <p>
          Analyses you submit will appear here. Start with{" "}
          <Link className="text-primary underline" to={ROUTES.analysisNew}>
            New Analysis
          </Link>
          .
        </p>
      </EmptyState>
    );
  }
  return (
    <div>
      <RecentAnalyses repositoryId={repositoryId} />
      <button
        type="button"
        onClick={() => {
          clearRecentRepositoryId();
          setRepositoryId(null);
        }}
        className="mt-3 text-xs text-text-secondary underline hover:text-text-primary"
      >
        Forget this repository
      </button>
    </div>
  );
}
