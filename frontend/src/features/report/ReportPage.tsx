import { Link, useParams } from "react-router";
import { ANALYSIS_ID_PARAM, ROUTES } from "../../router/routes";
import { useAnalysisResult } from "../analysis/useAnalysisResult";
import type { AnalysisResult, Finding } from "../../schemas/results";
import { Alert, EmptyState, LoadingState, Panel } from "../../components/ui";
import { ApiRequestError } from "../../lib/api";
import { ConfidenceBadge, SeverityBadge } from "../findings/FindingBits";
import { ExportButtons } from "./ExportButtons";

// Report view (TASK-206, docs/14 §18.1). A document rendered from the JSON
// canonical result in the §18 section order, with a table of contents. All
// repository-derived text renders as React text (inert); redacted evidence
// appears exactly as persisted. No score, no re-analysis, no raw HTML.

const SECTIONS = [
  { id: "report-repository", label: "Repository" },
  { id: "report-context", label: "Analysis Context" },
  { id: "report-summary", label: "Summary" },
  { id: "report-security", label: "Security" },
  { id: "report-architecture", label: "Architecture" },
  { id: "report-dependencies", label: "Dependencies" },
  { id: "report-codestructure", label: "Code Structure" },
  { id: "report-files", label: "Files" },
  { id: "report-findings", label: "Findings" },
  { id: "report-limitations", label: "Limitations / Warnings" },
] as const;

function shortSha(sha: string): string {
  return sha.length > 7 ? sha.slice(0, 7) : sha;
}

export function ReportPage() {
  const params = useParams();
  const analysisId = params[ANALYSIS_ID_PARAM] ?? "";
  const { data, error, isLoading, refetch, isFetching } = useAnalysisResult(analysisId);

  if (isLoading) {
    return <LoadingState label="Loading report…" />;
  }

  if (error || !data) {
    const apiError = error instanceof ApiRequestError ? error : null;
    return (
      <Panel>
        <Alert
          tone="error"
          title={apiError?.code === "ANALYSIS_NOT_FOUND" ? "Analysis not found." : "Could not load the report."}
        >
          <p>{apiError?.message ?? "An unexpected error occurred."}</p>
        </Alert>
        <button
          type="button"
          onClick={() => void refetch()}
          disabled={isFetching}
          className="mt-4 rounded-control border border-border px-4 py-2 text-sm font-medium hover:border-primary disabled:opacity-50"
        >
          {isFetching ? "Retrying…" : "Retry"}
        </button>
      </Panel>
    );
  }

  if (data.status.outcome == null) {
    return (
      <Panel>
        <Alert tone="info" title="The report is unavailable while the analysis is not completed.">
          <p>Reports are rendered from sealed results only.</p>
        </Alert>
        <Link
          to={ROUTES.analysisDetail(analysisId)}
          className="mt-4 inline-block rounded-control border border-border px-4 py-2 text-sm font-medium hover:border-primary"
        >
          View progress
        </Link>
      </Panel>
    );
  }

  if (data.status.outcome === "Failed") {
    return (
      <Panel>
        <Alert tone="error" title="No report exists for a failed analysis.">
          <p>{data.status.explanation ?? "The analysis did not produce usable results."}</p>
        </Alert>
      </Panel>
    );
  }

  return (
    <div className="mx-auto w-full max-w-[960px] space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-lg font-semibold">Report</h2>
        <Link className="text-sm text-primary underline" to={ROUTES.analysisOverview(analysisId)}>
          Back to overview
        </Link>
      </div>

      <Panel title="Contents" labelledBy="report-toc">
        <nav aria-label="Report contents">
          <ol className="list-decimal space-y-1 pl-5 text-sm">
            {SECTIONS.map((section) => (
              <li key={section.id}>
                <a className="text-primary underline" href={`#${section.id}`}>
                  {section.label}
                </a>
              </li>
            ))}
          </ol>
        </nav>
      </Panel>

      <ReportSection id="report-repository" title="Repository">
        <dl className="grid gap-2 text-sm sm:grid-cols-2">
          <div>
            <dt className="text-text-secondary">Repository</dt>
            <dd className="break-identifier font-mono text-xs">
              {data.repository.owner}/{data.repository.name}
            </dd>
          </div>
          <div>
            <dt className="text-text-secondary">URL</dt>
            <dd className="break-identifier font-mono text-xs">{data.repository.url}</dd>
          </div>
        </dl>
      </ReportSection>

      <ReportSection id="report-context" title="Analysis Context">
        <AnalysisContext result={data} />
      </ReportSection>

      <ReportSection id="report-summary" title="Summary">
        <ReportSummary result={data} />
      </ReportSection>

      <ReportSection id="report-security" title="Security">
        <AreaFindings analysisId={analysisId} title="Security" findings={data.security?.findings ?? null} state={data.summary?.security.state ?? null} />
      </ReportSection>

      <ReportSection id="report-architecture" title="Architecture">
        <AreaFindings analysisId={analysisId} title="Architecture" findings={data.architecture?.findings ?? null} state={data.summary?.architecture.state ?? null} />
        {data.architecture?.graph ? (
          <div className="mt-4 overflow-x-auto">
            <table className="w-full min-w-[520px] text-left text-sm">
              <caption className="pb-2 text-left text-xs text-text-secondary">
                Modules and relationships ({data.architecture.graph.nodes.length} modules,{" "}
                {data.architecture.graph.edges.length} relationships)
              </caption>
              <thead>
                <tr className="border-b border-border text-text-secondary">
                  <th scope="col" className="py-2 pr-4 font-medium">Module</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Layer</th>
                  <th scope="col" className="py-2 font-medium">Findings</th>
                </tr>
              </thead>
              <tbody>
                {data.architecture.graph.nodes.map((node) => (
                  <tr key={node.node_id} className="border-b border-border last:border-0">
                    <td className="break-identifier py-2 pr-4 font-mono text-xs">{node.node_id}</td>
                    <td className="py-2 pr-4 text-xs">{node.layer ?? "—"}</td>
                    <td className="py-2 font-mono text-xs">{node.finding_ids.length}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
        {data.architecture?.cycles && data.architecture.cycles.length > 0 ? (
          <div className="mt-3">
            <h4 className="text-sm font-semibold">Cycles</h4>
            <ul className="mt-1 space-y-1 font-mono text-xs">
              {data.architecture.cycles.map((cycle) => (
                <li key={cycle.finding_id}>
                  {cycle.finding_id}: {cycle.node_ids.join(" → ")}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </ReportSection>

      <ReportSection id="report-dependencies" title="Dependencies">
        <AreaFindings analysisId={analysisId} title="Dependencies" findings={data.dependencies?.findings ?? null} state={data.summary?.dependencies.state ?? null} />
        {data.dependencies ? (
          <div className="mt-4 overflow-x-auto">
            <table className="w-full min-w-[520px] text-left text-sm">
              <caption className="pb-2 text-left text-xs text-text-secondary">
                Dependency occurrences ({data.dependencies.items.length})
              </caption>
              <thead>
                <tr className="border-b border-border text-text-secondary">
                  <th scope="col" className="py-2 pr-4 font-medium">Name</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Version</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Ecosystem</th>
                  <th scope="col" className="py-2 font-medium">Type</th>
                </tr>
              </thead>
              <tbody>
                {data.dependencies.items.map((item) => (
                  <tr key={item.dependency_id} className="border-b border-border last:border-0">
                    <td className="break-identifier py-2 pr-4 font-mono text-xs">{item.name}</td>
                    <td className="py-2 pr-4 font-mono text-xs">{item.version ?? "unknown"}</td>
                    <td className="py-2 pr-4 text-xs">{item.ecosystem ?? "—"}</td>
                    <td className="py-2 text-xs">{item.classification}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </ReportSection>

      <ReportSection id="report-codestructure" title="Code Structure">
        <AreaFindings analysisId={analysisId} title="Code Structure" findings={data.code_structure?.findings ?? null} state={data.summary?.code_structure.state ?? null} />
        {data.code_structure && data.code_structure.metrics.length > 0 ? (
          <div className="mt-4 overflow-x-auto">
            <table className="w-full min-w-[520px] text-left text-sm">
              <caption className="pb-2 text-left text-xs text-text-secondary">
                Structural metrics ({data.code_structure.metrics.length})
              </caption>
              <thead>
                <tr className="border-b border-border text-text-secondary">
                  <th scope="col" className="py-2 pr-4 font-medium">Metric</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Subject</th>
                  <th scope="col" className="py-2 font-medium">Value</th>
                </tr>
              </thead>
              <tbody>
                {data.code_structure.metrics.map((metric, index) => (
                  <tr key={`${metric.metric}-${metric.subject_path}-${index}`} className="border-b border-border last:border-0">
                    <td className="py-2 pr-4 font-mono text-xs">{metric.metric}</td>
                    <td className="break-identifier py-2 pr-4 font-mono text-xs">
                      {metric.subject_name ?? metric.subject_path}
                    </td>
                    <td className="py-2 font-mono text-xs">
                      {metric.value == null ? "unavailable" : String(metric.value)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </ReportSection>

      <ReportSection id="report-files" title="Files">
        {data.files == null || data.files.length === 0 ? (
          <p className="text-sm text-text-secondary">
            {data.files == null ? "File data is unavailable for this analysis." : "No files recorded."}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[520px] text-left text-sm">
              <caption className="pb-2 text-left text-xs text-text-secondary">
                Indexed files ({data.files.length})
              </caption>
              <thead>
                <tr className="border-b border-border text-text-secondary">
                  <th scope="col" className="py-2 pr-4 font-medium">Path</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Language</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Support</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Parse</th>
                  <th scope="col" className="py-2 font-medium">Findings</th>
                </tr>
              </thead>
              <tbody>
                {data.files.map((file) => (
                  <tr key={file.path} className="border-b border-border last:border-0">
                    <td className="break-identifier py-2 pr-4 font-mono text-xs">{file.path}</td>
                    <td className="py-2 pr-4 text-xs">{file.language ?? "—"}</td>
                    <td className="py-2 pr-4 text-xs">{file.support}</td>
                    <td className="py-2 pr-4 text-xs">{file.parse_result ?? "not parsed"}</td>
                    <td className="py-2 font-mono text-xs">{file.finding_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </ReportSection>

      <ReportSection id="report-findings" title="Findings">
        <FindingsIndex analysisId={analysisId} result={data} />
      </ReportSection>

      <ReportSection id="report-limitations" title="Limitations / Warnings">
        <dl className="space-y-2 text-sm">
          <div className="flex gap-2">
            <dt className="w-28 shrink-0 text-text-secondary">Outcome</dt>
            <dd>{data.status.outcome}</dd>
          </div>
          {data.status.explanation ? (
            <div className="flex gap-2">
              <dt className="w-28 shrink-0 text-text-secondary">Explanation</dt>
              <dd>{data.status.explanation}</dd>
            </div>
          ) : null}
        </dl>
        {data.status.domains.length > 0 ? (
          <ul className="mt-3 space-y-1 text-sm">
            {data.status.domains.map((domain) => (
              <li key={domain.area}>
                <span className="font-mono text-xs">{domain.area}</span>: {domain.state ?? "evaluated with findings"}
                {domain.reason ? ` — ${domain.reason}` : ""}
              </li>
            ))}
          </ul>
        ) : null}
        {data.status.limitations.length > 0 ? (
          <ul className="mt-3 space-y-1 text-sm">
            {data.status.limitations.map((limitation, index) => (
              <li key={index} className="break-identifier">
                {limitation.reason}
              </li>
            ))}
          </ul>
        ) : (
          <p className="mt-3 text-sm text-text-secondary">No limitations recorded.</p>
        )}
        <p className="mt-4 text-sm text-text-secondary">
          Findings are static-analysis indicators to be validated by manual review.
          Static analysis cannot prove exploitability or the absence of issues.
        </p>
      </ReportSection>

      <Panel title="Export" labelledBy="report-export">
        <p className="mb-3 text-sm text-text-secondary">
          The complete result, not any filtered view, in the sealed server rendering.
        </p>
        <ExportButtons analysisId={analysisId} />
      </Panel>
    </div>
  );
}

function ReportSection({ id, title, children }: { id: string; title: string; children: React.ReactNode }) {
  return (
    <section aria-labelledby={id} className="rounded-panel border border-border bg-surface p-6">
      <h3 id={id} className="mb-4 text-base font-semibold" tabIndex={-1}>
        {title}
      </h3>
      {children}
    </section>
  );
}

function AnalysisContext({ result }: { result: AnalysisResult }) {
  const branch = result.repository.analyzed_state.branch;
  const commit = result.repository.analyzed_state.commit;
  const advisory = result.analysis.advisory_data ?? null;
  const configuration = (result.analysis as { configuration?: unknown }).configuration;
  return (
    <dl className="grid gap-2 text-sm sm:grid-cols-2">
      <div>
        <dt className="text-text-secondary">Analysis ID</dt>
        <dd className="break-identifier font-mono text-xs">{result.analysis.analysis_id}</dd>
      </div>
      <div>
        <dt className="text-text-secondary">Analyzed at</dt>
        <dd>{result.analysis.timestamp ?? "—"}</dd>
      </div>
      <div>
        <dt className="text-text-secondary">Analyzer / Rule set</dt>
        <dd className="font-mono text-xs">
          {result.analysis.analyzer_version ?? "—"} / {result.analysis.rule_set_version ?? "—"}
        </dd>
      </div>
      <div>
        <dt className="text-text-secondary">Branch / Commit</dt>
        <dd className="break-identifier font-mono text-xs">
          {branch ? `${branch.name}${branch.origin === "Defaulted" ? " (default)" : ""}` : "—"}
          {" / "}
          {commit ? `${shortSha(commit.sha)}${commit.origin === "Defaulted" ? " (default)" : ""}` : "—"}
        </dd>
      </div>
      <div>
        <dt className="text-text-secondary">Advisory data</dt>
        <dd className="text-xs">
          {advisory
            ? `${advisory.source} · ${advisory.consulted_at ?? "unknown time"} · ${advisory.outcome}`
            : "none consulted"}
        </dd>
      </div>
      {configuration !== undefined ? (
        <div className="sm:col-span-2">
          <dt className="text-text-secondary">Effective configuration</dt>
          <dd>
            <pre className="mt-1 overflow-x-auto rounded-control border border-border bg-secondary p-3 font-mono text-xs">
              {JSON.stringify(configuration, null, 2)}
            </pre>
          </dd>
        </div>
      ) : null}
    </dl>
  );
}

function ReportSummary({ result }: { result: AnalysisResult }) {
  const summary = result.summary;
  if (!summary) {
    return <p className="text-sm text-text-secondary">Summary is unavailable for this analysis.</p>;
  }
  const areas = [
    { key: "security", label: "Security" },
    { key: "architecture", label: "Architecture" },
    { key: "dependencies", label: "Dependencies" },
    { key: "code_structure", label: "Code Structure" },
  ] as const;
  return (
    <div>
      <ul className="space-y-1 text-sm">
        {areas.map((area) => {
          const entry = summary[area.key];
          return (
            <li key={area.key}>
              {area.label}: state {entry.state ?? "evaluated with findings"} · findings{" "}
              {entry.findings == null ? "—" : entry.findings.total}
            </li>
          );
        })}
      </ul>
      <p className="mt-2 text-xs text-text-secondary">
        Counts with area states; unavailable areas show "—", never zero.
      </p>
    </div>
  );
}

function AreaFindings({
  analysisId,
  title,
  findings,
  state,
}: {
  analysisId: string;
  title: string;
  findings: Finding[] | null;
  state: string | null;
}) {
  if (findings == null) {
    return (
      <p className="text-sm text-text-secondary">
        {title} results are not available (state: {state ?? "unavailable"}). This is not a
        clean result.
      </p>
    );
  }
  if (findings.length === 0) {
    return <p className="text-sm text-text-secondary">No {title.toLowerCase()} findings.</p>;
  }
  return (
    <ul className="space-y-2">
      {findings.map((finding) => (
        <li key={finding.finding_id} className="flex flex-wrap items-center gap-2 text-sm">
          <Link
            className="font-mono text-xs text-primary underline"
            to={ROUTES.analysisFindingDetail(analysisId, finding.finding_id)}
          >
            {finding.finding_id}
          </Link>
          <span className="font-mono text-xs">{finding.rule_id}</span>
          <SeverityBadge severity={finding.severity} />
          <ConfidenceBadge confidence={finding.confidence} />
          <span className="break-identifier font-mono text-xs text-text-secondary">
            {finding.subject.locations[0]?.path ?? ""}
          </span>
        </li>
      ))}
    </ul>
  );
}

function FindingsIndex({ analysisId, result }: { analysisId: string; result: AnalysisResult }) {
  const groups: Array<{ area: string; findings: Finding[] }> = [
    { area: "security", findings: result.security?.findings ?? [] },
    { area: "architecture", findings: result.architecture?.findings ?? [] },
    { area: "dependency", findings: result.dependencies?.findings ?? [] },
    { area: "code_structure", findings: result.code_structure?.findings ?? [] },
  ];
  const total = groups.reduce((sum, group) => sum + group.findings.length, 0);
  if (total === 0) {
    return <EmptyState title="No findings recorded in any area." />;
  }
  return (
    <div className="space-y-4">
      {groups.map((group) =>
        group.findings.length === 0 ? null : (
          <div key={group.area}>
            <h4 className="mb-2 text-sm font-semibold capitalize">{group.area}</h4>
            <ul className="space-y-1 text-sm">
              {group.findings.map((finding) => (
                <li key={finding.finding_id}>
                  <Link
                    className="font-mono text-xs text-primary underline"
                    to={ROUTES.analysisFindingDetail(analysisId, finding.finding_id)}
                  >
                    {finding.finding_id}
                  </Link>{" "}
                  <span className="font-mono text-xs">{finding.rule_id}</span>{" "}
                  <span className="break-identifier font-mono text-xs text-text-secondary">
                    {finding.subject.locations[0]
                      ? `${finding.subject.locations[0].path}${
                          finding.subject.locations[0].start_line != null
                            ? `:${finding.subject.locations[0].start_line}`
                            : ""
                        }`
                      : ""}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        ),
      )}
    </div>
  );
}
