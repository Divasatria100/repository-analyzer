import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router";
import { ROUTES } from "../router/routes";
import { EmptyState, Panel } from "../components/ui";

// Dashboard entry point (docs/14-ui-requirements.md, Section 6).
// First viewport only: headline, scope note, primary action. The inline URL
// input submits into the New Analysis flow (the value travels as a query
// parameter and pre-fills the form there). The recent analyses table belongs
// to a later phase (no per-dashboard listing endpoint exists in the API
// contract), so nothing here fabricates analyses or stats.

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
      <section className="py-10">
        <h2 className="max-w-3xl text-3xl font-bold tracking-tight">
          RepoLens analyzes public GitHub repositories for security, architecture,
          dependencies, and code structure.
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
        <div id="recent-analyses" className="sr-only">
          Recent Analyses
        </div>
        <EmptyState title="No recent analyses to show yet.">
          <p>
            Start with{" "}
            <Link className="text-primary underline" to={ROUTES.analysisNew}>
              New Analysis
            </Link>
            .
          </p>
        </EmptyState>
      </Panel>
    </div>
  );
}
