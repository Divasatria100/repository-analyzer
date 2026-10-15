import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderAt } from "../../test/render";
import { mockFetchRoutes, repositoryHistoryFixture } from "../../test/fixtures";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("History page", () => {
  it("asks for a repository when none is given, without fabricating rows", async () => {
    renderAt("/history");
    expect(screen.getAllByRole("heading", { name: "History" }).length).toBeGreaterThan(0);
    expect(screen.queryByRole("table")).toBeNull();
    expect(
      screen.getByText(/no cross-repository.*analysis list.*endpoint/),
    ).toBeDefined();
  });

  it("loads history from the repository endpoint and links each analysis", async () => {
    mockFetchRoutes([{ match: "/api/repositories/r1", payload: repositoryHistoryFixture() }]);
    renderAt("/history?repository=r1");
    await waitFor(() => {
      expect(screen.getByText("acme/web")).toBeDefined();
    });
    expect(screen.getAllByText(/9f2c1e7/).length).toBeGreaterThan(0);
    expect(screen.getByText("Failed")).toBeDefined();
    expect(screen.getByText("Retrieval failed.")).toBeDefined();
    // History entries carry no totals: Findings column shows "—".
    const dashes = screen.getAllByText("—", { selector: "td" });
    expect(dashes.length).toBeGreaterThan(0);
    expect(screen.getAllByRole("link", { name: "Open" })[0].getAttribute("href")).toBe(
      "/analysis/target9/overview",
    );
  });

  it("searches within the loaded history", async () => {
    mockFetchRoutes([{ match: "/api/repositories/r1", payload: repositoryHistoryFixture() }]);
    renderAt("/history?repository=r1");
    await waitFor(() => {
      expect(screen.getByText("acme/web")).toBeDefined();
    });
    fireEvent.change(screen.getByLabelText("Search this history"), {
      target: { value: "fail007" },
    });
    expect(screen.queryByText("target9")).toBeNull();
    expect(screen.getByText("fail007")).toBeDefined();
  });

  it("enables comparison only for two completed analyses, oldest as base", async () => {
    mockFetchRoutes([{ match: "/api/repositories/r1", payload: repositoryHistoryFixture() }]);
    renderAt("/history?repository=r1");
    await waitFor(() => {
      expect(screen.getByText("acme/web")).toBeDefined();
    });
    fireEvent.click(screen.getByRole("checkbox", { name: "Select analysis fail007 for comparison" }));
    fireEvent.click(screen.getByRole("checkbox", { name: "Select analysis target9 for comparison" }));
    expect(screen.getByText(/Failed analyses have no snapshot/)).toBeDefined();
    fireEvent.click(screen.getByRole("checkbox", { name: "Select analysis fail007 for comparison" }));
    fireEvent.click(screen.getByRole("checkbox", { name: "Select analysis base111 for comparison" }));
    const compare = await screen.findByRole("link", { name: "Compare selected" });
    // Earlier timestamp (base111) is the base; later (target9) is the target.
    expect(compare.getAttribute("href")).toBe("/analysis/target9/comparison?base=base111");
  });

  it("blocks non-terminal selections with an explanation", async () => {
    mockFetchRoutes([{ match: "/api/repositories/r1", payload: repositoryHistoryFixture() }]);
    renderAt("/history?repository=r1");
    await waitFor(() => {
      expect(screen.getByText("acme/web")).toBeDefined();
    });
    fireEvent.click(screen.getByRole("checkbox", { name: "Select analysis queue42 for comparison" }));
    fireEvent.click(screen.getByRole("checkbox", { name: "Select analysis target9 for comparison" }));
    expect(screen.getByText(/terminal outcome/)).toBeDefined();
    expect(screen.queryByRole("link", { name: "Compare selected" })).toBeNull();
  });

  it("handles unknown repositories and retryable failures", async () => {
    mockFetchRoutes([
      {
        match: "/api/repositories/nope",
        payload: { error: { code: "REPOSITORY_NOT_FOUND", message: "Gone.", details: null } },
        status: 404,
      },
    ]);
    renderAt("/history?repository=nope");
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toContain("Repository not found.");
    });
  });
});
