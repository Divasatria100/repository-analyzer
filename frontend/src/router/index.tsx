import { createBrowserRouter, type RouteObject } from "react-router";
import { AppShell } from "../components/AppShell";
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
import { ANALYSIS_ID_PARAM, ROUTES } from "./routes";

// Route architecture per docs/14-ui-requirements.md (Sections 4–5).
// Every page renders inside the shared AppShell. The New Analysis workflow
// and the analysis status gate are fully implemented (TASK-180–188);
// workspace sections keep honest placeholders until their phases.
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
            element: <SectionPlaceholder title="Overview" />,
          },
          {
            path: "security",
            element: <SectionPlaceholder title="Security" />,
          },
          {
            path: "architecture",
            element: <SectionPlaceholder title="Architecture" />,
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
            element: <SectionPlaceholder title="Findings" />,
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
