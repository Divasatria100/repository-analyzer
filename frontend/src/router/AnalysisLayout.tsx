import { Outlet } from "react-router";
import { RoutePlaceholder } from "../pages/RoutePlaceholder";

// Routing foundation (docs/14-ui-requirements.md, Section 5).
// Elements are minimal placeholders; page content arrives in later phases.
export function AnalysisLayout() {
  return (
    <>
      <RoutePlaceholder title="Analysis" />
      <Outlet />
    </>
  );
}
