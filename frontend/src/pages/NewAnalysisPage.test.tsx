import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderAt } from "../test/render";

function mockFetchOnce(payload: unknown, status = 200) {
  window.fetch = vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(JSON.stringify(payload)),
  } as Response);
}

function fillUrl(value: string) {
  fireEvent.change(screen.getByLabelText("Repository URL"), { target: { value } });
}

function submit() {
  fireEvent.click(screen.getByRole("button", { name: /start analysis/i }));
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("New Analysis form", () => {
  it("rejects empty input without calling the API", () => {
    const spy = vi.spyOn(window, "fetch");
    renderAt("/analysis/new");
    submit();
    expect(screen.getByRole("alert")).toBeDefined();
    expect(spy).not.toHaveBeenCalled();
  });

  it("rejects an invalid URL without calling the API", () => {
    const spy = vi.spyOn(window, "fetch");
    renderAt("/analysis/new");
    fillUrl("https://gitlab.com/acme/web");
    submit();
    expect(screen.getByRole("alert").textContent).toContain("github.com/owner/repository");
    expect(spy).not.toHaveBeenCalled();
  });

  it("submits url, branch, and commit and navigates on HTTP 202", async () => {
    mockFetchOnce({ analysis_id: "abc123", repository_id: "r1", stage: "Queued" }, 202);
    const router = renderAt("/analysis/new");
    fillUrl("https://github.com/acme/web");
    fireEvent.change(screen.getByLabelText("Branch"), { target: { value: "main" } });
    fireEvent.change(screen.getByLabelText("Commit"), { target: { value: "9f2c1e7" } });
    submit();
    const [, init] = (window.fetch as unknown as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(JSON.parse(init.body as string)).toEqual({
      url: "https://github.com/acme/web",
      branch: "main",
      commit: "9f2c1e7",
    });
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/analysis/abc123");
    });
  });

  it("sends null branch/commit when left empty", async () => {
    mockFetchOnce({ analysis_id: "a", repository_id: "r", stage: "Queued" }, 202);
    renderAt("/analysis/new");
    fillUrl("https://github.com/acme/web");
    submit();
    const [, init] = (window.fetch as unknown as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(JSON.parse(init.body as string)).toEqual({
      url: "https://github.com/acme/web",
      branch: null,
      commit: null,
    });
  });

  it("prevents duplicate submissions while pending", async () => {
    let release!: (value: Response) => void;
    window.fetch = vi.fn(
      () =>
        new Promise<Response>((resolve) => {
          release = resolve;
        }),
    );
    renderAt("/analysis/new");
    fillUrl("https://github.com/acme/web");
    const button = screen.getByRole("button", { name: /start analysis/i });
    fireEvent.click(button);
    fireEvent.click(button);
    expect(window.fetch).toHaveBeenCalledTimes(1);
    release({
      ok: true,
      status: 202,
      text: () => Promise.resolve(JSON.stringify({ analysis_id: "a", repository_id: "r", stage: "Queued" })),
    } as Response);
  });

  it("maps server INVALID_URL to the URL field and preserves input", async () => {
    mockFetchOnce(
      { error: { code: "INVALID_URL", message: "Not a valid URL.", details: null } },
      422,
    );
    renderAt("/analysis/new");
    fillUrl("https://github.com/acme/web");
    submit();
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toContain("Not a valid URL.");
    });
    expect((screen.getByLabelText("Repository URL") as HTMLInputElement).value).toBe(
      "https://github.com/acme/web",
    );
  });

  it("shows request-level failures in an alert and preserves input", async () => {
    mockFetchOnce(
      {
        error: {
          code: "REPOSITORY_NOT_ACCESSIBLE",
          message: "Not accessible as a public repository.",
          details: null,
        },
      },
      422,
    );
    renderAt("/analysis/new");
    fillUrl("https://github.com/acme/web");
    submit();
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toContain("not accessible");
    });
    expect((screen.getByLabelText("Repository URL") as HTMLInputElement).value).toBe(
      "https://github.com/acme/web",
    );
  });

  it("handles network failures safely", async () => {
    window.fetch = vi.fn(() => Promise.reject(new TypeError("down")));
    renderAt("/analysis/new");
    fillUrl("https://github.com/acme/web");
    submit();
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toContain("Could not reach the backend");
    });
  });

  it("shows analysis areas as a fixed list, not toggles", () => {
    renderAt("/analysis/new");
    expect(screen.getByText(/Security · Architecture · Dependencies · Code Structure/)).toBeDefined();
    expect(screen.queryByRole("checkbox")).toBeNull();
  });

  it("prefills the URL from the dashboard quick input", () => {
    renderAt("/analysis/new?url=https%3A%2F%2Fgithub.com%2Facme%2Fweb");
    expect((screen.getByLabelText("Repository URL") as HTMLInputElement).value).toBe(
      "https://github.com/acme/web",
    );
  });
});
