import { createBrowserRouter, type RouteObject } from "react-router";
import { RoutePlaceholder } from "../pages/RoutePlaceholder";
import { AnalysisLayout } from "./AnalysisLayout";
import { ANALYSIS_ID_PARAM, ROUTES } from "./routes";

// Route architecture per docs/14-ui-requirements.md (Section 5).
// No page content, no auth guards, no data loading — placeholders only.
// Exported as data so tests can build a memory router from the same tree.
export const routes: RouteObject[] = [
  {
    path: ROUTES.root,
    element: <RoutePlaceholder title="Dashboard" />,
  },
  {
    path: ROUTES.dashboard,
    element: <RoutePlaceholder title="Dashboard" />,
  },
  {
    path: ROUTES.analysisNew,
    element: <RoutePlaceholder title="New Analysis" />,
  },
  {
    path: `/analysis/:${ANALYSIS_ID_PARAM}`,
    element: <AnalysisLayout />,
    children: [
      {
        index: true,
        element: <RoutePlaceholder title="Overview" />,
      },
      {
        path: "overview",
        element: <RoutePlaceholder title="Overview" />,
      },
      {
        path: "security",
        element: <RoutePlaceholder title="Security" />,
      },
      {
        path: "architecture",
        element: <RoutePlaceholder title="Architecture" />,
      },
      {
        path: "dependencies",
        element: <RoutePlaceholder title="Dependencies" />,
      },
      {
        path: "code-structure",
        element: <RoutePlaceholder title="Code Structure" />,
      },
      {
        path: "files",
        element: <RoutePlaceholder title="Files" />,
      },
      {
        path: "findings",
        element: <RoutePlaceholder title="Findings" />,
      },
    ],
  },
  {
    path: ROUTES.history,
    element: <RoutePlaceholder title="History" />,
  },
  {
    path: ROUTES.settings,
    element: <RoutePlaceholder title="Settings" />,
  },
  {
    path: "*",
    element: <RoutePlaceholder title="Not Found" />,
  },
];

export const router = createBrowserRouter(routes);
