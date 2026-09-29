import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { RouterProvider, createMemoryRouter } from "react-router";
import { routes } from "./index";

function renderAt(path: string) {
  const router = createMemoryRouter(routes, { initialEntries: [path] });
  render(<RouterProvider router={router} />);
}

describe.each([
  ["/dashboard", "Dashboard"],
  ["/analysis/new", "New Analysis"],
  ["/analysis/abc123/overview", "Overview"],
  ["/analysis/abc123/security", "Security"],
  ["/analysis/abc123/architecture", "Architecture"],
  ["/analysis/abc123/dependencies", "Dependencies"],
  ["/analysis/abc123/code-structure", "Code Structure"],
  ["/analysis/abc123/files", "Files"],
  ["/analysis/abc123/findings", "Findings"],
  ["/history", "History"],
  ["/settings", "Settings"],
])("route %s", (path, title) => {
  it(`renders the ${title} placeholder without warnings`, () => {
    renderAt(path);
    expect(screen.getByRole("heading", { name: title })).toBeDefined();
  });
});

describe("router fallbacks", () => {
  it("renders dashboard at root", () => {
    renderAt("/");
    expect(screen.getByRole("heading", { name: "Dashboard" })).toBeDefined();
  });

  it("renders overview for bare analysis detail", () => {
    renderAt("/analysis/abc123");
    expect(screen.getByRole("heading", { name: "Overview" })).toBeDefined();
  });

  it("renders Not Found for unknown routes", () => {
    renderAt("/does-not-exist");
    expect(screen.getByRole("heading", { name: "Not Found" })).toBeDefined();
  });
});
