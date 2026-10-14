import { NavLink, useParams } from "react-router";
import { ANALYSIS_ID_PARAM, ROUTES } from "../router/routes";

// Workspace tab navigation (docs/14-ui-requirements.md, Sections 5 and 8.2).
// Tab order is the contract order: Overview, Security, Architecture,
// Dependencies, Code Structure, Files, Findings. Links preserve the analysis
// identifier; area state markers arrive with the workspace views (later
// phases) and no tab fabricates data.
//
// Note: react-router's NavLink marks the active tab with
// aria-current="page" automatically.

export function AnalysisTabs() {
  const params = useParams();
  const analysisId = params[ANALYSIS_ID_PARAM] ?? "";

  const tabs = [
    { to: ROUTES.analysisOverview(analysisId), label: "Overview", end: false },
    { to: ROUTES.analysisSecurity(analysisId), label: "Security", end: true },
    { to: ROUTES.analysisArchitecture(analysisId), label: "Architecture", end: true },
    { to: ROUTES.analysisDependencies(analysisId), label: "Dependencies", end: true },
    { to: ROUTES.analysisCodeStructure(analysisId), label: "Code Structure", end: true },
    { to: ROUTES.analysisFiles(analysisId), label: "Files", end: true },
    { to: ROUTES.analysisFindings(analysisId), label: "Findings", end: true },
  ] as const;

  return (
    <nav aria-label="Analysis views" className="border-b border-border">
      <ul className="flex gap-1 overflow-x-auto">
        {tabs.map((tab) => (
          <li key={tab.label} className="shrink-0">
            <NavLink
              to={tab.to}
              end={tab.end}
              className={({ isActive }) =>
                `block border-b-2 px-3 py-2 text-sm font-medium whitespace-nowrap transition-colors ${
                  isActive
                    ? "border-primary text-text-primary"
                    : "border-transparent text-text-secondary hover:text-text-primary"
                }`
              }
            >
              {tab.label}
            </NavLink>
          </li>
        ))}
      </ul>
    </nav>
  );
}
