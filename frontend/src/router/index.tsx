import { createBrowserRouter, type RouteObject } from "react-router";
import { AppShell } from "../components/AppShell";
import { ArchitecturePage } from "../features/architecture/ArchitecturePage";
import { FindingDetailPage } from "../features/findings/FindingDetailPage";
import { FindingsPage } from "../features/findings/FindingsPage";
import { SecurityPage } from "../features/findings/SecurityPage";
import { OverviewPage } from "../features/overview/OverviewPage";
import { DashboardPage } from "../pages/DashboardPage";
import { NewAnalysisPage } from "../pages/NewAnalysisPage";
import {
  AnalysisStatusPage,
  HistoryPage,
  NotFoundPage,
  SectionPlaceholder,
  SettingsPage,
} from "../pages/PlaceholderPages";
import { AnalysisLayout } from "./AnalysisLayout";
import { ANALYSIS_ID_PARAM, FINDING_ID_PARAM, ROUTES } from "./routes";

// Route architecture per docs/14-ui-requirements.md (Sections 4–5).
// Every page renders inside the shared AppShell. Overview, Findings,
// Security, Finding Detail, and Architecture are implemented (TASK-189–198);
// Dependencies, Code Structure, and Files keep honest placeholders.
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
            element: <SectionPlaceholder title="Dependencies" />,
          },
          {
            path: "code-structure",
            element: <SectionPlaceholder title="Code Structure" />,
          },
          {
            path: "files",
            element: <SectionPlaceholder title="Files" />,
          },
          {
            path: "findings",
            element: <FindingsPage />,
          },
          {
            path: `findings/:${FINDING_ID_PARAM}`,
            element: <FindingDetailPage />,
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
