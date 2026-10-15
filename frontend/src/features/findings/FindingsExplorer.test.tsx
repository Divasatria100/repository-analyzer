import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderAt } from "../../test/render";
import { archFindingFixture, findingFixture, findingsPageFixture, mockFetchRoutes } from "../../test/fixtures";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const PAGE = findingsPageFixture([findingFixture(), archFindingFixture()], 2);

describe("Findings explorer", () => {
  it("loads and renders server-provided rows with stable detail links", async () => {
    const calls = mockFetchRoutes([{ match: "/findings", payload: PAGE }]);
    renderAt("/analysis/abc123/findings");
    await waitFor(() => {
      expect(screen.getByText("SEC-HARDCODED-SECRET")).toBeDefined();
    });
    expect(screen.getByText("ARCH-CIRCULAR-DEPENDENCY")).toBeDefined();
    expect(screen.getByText(/Showing 2 of 2 findings in analysis/)).toBeDefined();
    expect(calls[0]).toContain("sort=severity");
    const openLinks = screen.getAllByRole("link", { name: "Open" });
    expect(openLinks[0].getAttribute("href")).toBe("/analysis/abc123/findings/F-0001");
  });

  it("renders an empty result set distinctly from failures", async () => {
    mockFetchRoutes([{ match: "/findings", payload: findingsPageFixture([], 0) }]);
    renderAt("/analysis/abc123/findings");
    await waitFor(() => {
      expect(screen.getByText("No findings match these filters.")).toBeDefined();
    });
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("sends server-side filters and resets pagination on change", async () => {
    const calls = mockFetchRoutes([{ match: "/findings", payload: PAGE }]);
    renderAt("/analysis/abc123/findings?page=3");
    await waitFor(() => {
      expect(screen.getByText("SEC-HARDCODED-SECRET")).toBeDefined();
    });
    expect(calls[0]).toContain("page=3");
    const severityGroup = screen.getByRole("group", { name: "Severity" });
    fireEvent.click(within(severityGroup).getByLabelText("High"));
    await waitFor(() => {
      expect(calls.some((url) => url.includes("severity=High") && url.includes("page=1"))).toBe(true);
    });
  });

  it("debounces text search into the q parameter", async () => {
    const calls = mockFetchRoutes([{ match: "/findings", payload: PAGE }]);
    renderAt("/analysis/abc123/findings");
    await waitFor(() => {
      expect(screen.getByText("SEC-HARDCODED-SECRET")).toBeDefined();
    });
    const before = calls.length;
    fireEvent.change(screen.getByLabelText(/Search path/), { target: { value: "app" } });
    fireEvent.change(screen.getByLabelText(/Search path/), { target: { value: "app/config" } });
    await waitFor(() => {
      expect(calls.some((url) => url.includes("q=app%2Fconfig"))).toBe(true);
    });
    // One debounced request, not one per keystroke.
    expect(calls.length).toBe(before + 1);
  });

  it("changes sort and order server-side", async () => {
    const calls = mockFetchRoutes([{ match: "/findings", payload: PAGE }]);
    renderAt("/analysis/abc123/findings");
    await waitFor(() => {
      expect(screen.getByText("SEC-HARDCODED-SECRET")).toBeDefined();
    });
    fireEvent.change(screen.getByLabelText("Sort field"), { target: { value: "file" } });
    await waitFor(() => {
      expect(calls.some((url) => url.includes("sort=file"))).toBe(true);
    });
    fireEvent.click(screen.getByRole("button", { name: /Sort order/ }));
    await waitFor(() => {
      expect(calls.some((url) => url.includes("order=desc"))).toBe(true);
    });
  });

  it("paginates with server metadata", async () => {
    const calls = mockFetchRoutes([
      { match: "/findings", payload: { ...PAGE, total: 30 } },
    ]);
    renderAt("/analysis/abc123/findings");
    await waitFor(() => {
      expect(screen.getByText("SEC-HARDCODED-SECRET")).toBeDefined();
    });
    expect(screen.getByText(/Page 1 of 2/)).toBeDefined();
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => {
      expect(calls.some((url) => url.includes("page=2"))).toBe(true);
    });
  });

  it("lets the latest request win filter races", async () => {
    const resolvers: Array<(value: Response) => void> = [];
    window.fetch = vi.fn(
      () =>
        new Promise<Response>((resolve) => {
          resolvers.push(resolve);
        }),
    );
    const respond = (payload: unknown) =>
      ({
        ok: true,
        status: 200,
        text: () => Promise.resolve(JSON.stringify(payload)),
      }) as Response;
    renderAt("/analysis/abc123/findings");
    await waitFor(() => {
      expect(window.fetch).toHaveBeenCalledTimes(1);
    });
    // Two rapid filter changes: first response arrives last and must be ignored.
    const severityGroup = screen.getByRole("group", { name: "Severity" });
    fireEvent.click(within(severityGroup).getByLabelText("High"));
    fireEvent.click(within(severityGroup).getByLabelText("Low"));
    await waitFor(() => {
      expect(window.fetch).toHaveBeenCalledTimes(3);
    });
    const pending = [...resolvers];
    pending[1](respond(findingsPageFixture([findingFixture()], 1)));
    pending[2](respond(findingsPageFixture([archFindingFixture()], 1)));
    pending[0](respond(findingsPageFixture([findingFixture()], 1)));
    await waitFor(() => {
      expect(screen.getByText("ARCH-CIRCULAR-DEPENDENCY")).toBeDefined();
    });
    expect(screen.queryByText("SEC-HARDCODED-SECRET")).toBeNull();
  });

  it("shows validation errors for invalid filters without fabricating rows", async () => {
    mockFetchRoutes([
      {
        match: "/findings",
        payload: { error: { code: "VALIDATION_ERROR", message: "Unknown severity filter.", details: null } },
        status: 400,
      },
    ]);
    renderAt("/analysis/abc123/findings?severity=Bogus");
    await waitFor(
      () => {
        expect(screen.getByRole("alert").textContent).toContain("rejected");
      },
      { timeout: 3000 },
    );
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("surfaces unavailable areas from the page envelope", async () => {
    mockFetchRoutes([
      {
        match: "/findings",
        payload: {
          ...PAGE,
          unavailable_areas: [{ area: "dependency", state: "Analysis unavailable", reason: "No manifest." }],
        },
      },
    ]);
    renderAt("/analysis/abc123/findings");
    await waitFor(() => {
      expect(screen.getByText("Some areas are unavailable.")).toBeDefined();
    });
    expect(screen.getByText(/available areas only/)).toBeDefined();
  });

  it("recovers from request failures with retry", async () => {
    mockFetchRoutes([
      {
        match: "/findings",
        payload: { error: { code: "INTERNAL_ERROR", message: "Boom.", details: null } },
        status: 500,
      },
    ]);
    renderAt("/analysis/abc123/findings");
    await waitFor(
      () => {
        expect(screen.getByRole("button", { name: "Retry" })).toBeDefined();
      },
      { timeout: 3000 },
    );
    mockFetchRoutes([{ match: "/findings", payload: PAGE }]);
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    await waitFor(() => {
      expect(screen.getByText("SEC-HARDCODED-SECRET")).toBeDefined();
    });
  });
});
