import { createBrowserRouter } from "react-router";
import { App } from "../App";

// Routing foundation (skeleton) — routes per docs/14-ui-requirements.md
// will be added in later phases.
export const router = createBrowserRouter([
  {
    path: "/",
    element: <App />,
  },
]);
