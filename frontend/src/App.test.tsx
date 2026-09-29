import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { App } from "./App";

describe("App skeleton", () => {
  it("renders the RepoLens heading", () => {
    render(<App />);
    expect(screen.getByRole("heading", { name: "RepoLens" })).toBeDefined();
  });
});
