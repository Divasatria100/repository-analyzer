import { createBrowserRouter, type RouteObject } from "react-router";
import { AppShell } from "../components/AppShell";
import { ArchitecturePage } from "../features/architecture/ArchitecturePage";
import { CodeStructurePage } from "../features/codestructure/CodeStructurePage";
import { ComparisonPage } from "../features/comparison/ComparisonPage";
import { DependenciesPage } from "../features/dependencies/DependenciesPage";
import { FilesPage } from "../features/files/FilesPage";
import { FindingDetailPage } from "../features/findings/FindingDetailPage";
import { FindingsPage } from "../features/findings/FindingsPage";
import { SecurityPage } from "../features/findings/SecurityPage";
import { HistoryPage } from "../features/history/HistoryPage";
import { OverviewPage } from "../features/overview/OverviewPage";
import { ReportPage } from "../features/report/ReportPage";
import { SettingsPage } from "../features/settings/SettingsPage";
import { DashboardPage } from "../pages/DashboardPage";
import { NewAnalysisPage } from "../pages/NewAnalysisPage";
import {
  AnalysisStatusPage,
  NotFoundPage,
} from "../pages/PlaceholderPages";
import { AnalysisLayout } from "./AnalysisLayout";
import { ANALYSIS_ID_PARAM, FINDING_ID_PARAM, ROUTES } from "./routes";

// Route architecture per docs/14-ui-requirements.md (Sections 4–5).
// Every page renders inside the shared AppShell. All analysis workspace
// views, history, comparison, report, dashboard, and settings are
// implemented; only Settings holds a placeholder-free single preference.
// Exported as data so tests can build a memory router from the same tree.
export const routes: RouteObject[] = [
  {
    element: <AppShell />,
    children: [
      {
        path: ROUTES.root,
        element: <DashboardPage />,
      },
      {
        path: ROUTES.dashboard,
        element: <DashboardPage />,
      },
      {
        path: ROUTES.analysisNew,
        element: <NewAnalysisPage />,
      },
      {
        path: `/analysis/:${ANALYSIS_ID_PARAM}`,
        element: <AnalysisLayout />,
        children: [
          {
            index: true,
            element: <AnalysisStatusPage />,
          },
          {
            path: "overview",
            element: <OverviewPage />,
          },
          {
            path: "security",
            element: <SecurityPage />,
          },
          {
            path: "architecture",
            element: <ArchitecturePage />,
          },
          {
            path: "dependencies",
            element: <DependenciesPage />,
          },
          {
            path: "code-structure",
            element: <CodeStructurePage />,
          },
          {
            path: "files",
            element: <FilesPage />,
          },
          {
            path: "findings",
            element: <FindingsPage />,
          },
          {
            path: `findings/:${FINDING_ID_PARAM}`,
            element: <FindingDetailPage />,
          },
          {
            path: "comparison",
            element: <ComparisonPage />,
          },
          {
            path: "report",
            element: <ReportPage />,
          },
        ],
      },
      {
        path: ROUTES.history,
        element: <HistoryPage />,
      },
      {
        path: ROUTES.settings,
        element: <SettingsPage />,
      },
      {
        path: "*",
        element: <NotFoundPage />,
      },
    ],
  },
];

export const router = createBrowserRouter(routes);
