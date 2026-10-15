import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderAt } from "../../test/render";
import { analysisResultFixture, mockFetchRoutes } from "../../test/fixtures";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("Report page", () => {
  it("renders the canonical document with contents, states, and limitations", async () => {
    mockFetchRoutes([{ match: "/api/analyses/abc123", payload: analysisResultFixture() }]);
    renderAt("/analysis/abc123/report");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Report" })).toBeDefined();
    });
    const toc = screen.getByRole("navigation", { name: "Report contents" });
    const tocLinks = toc.querySelectorAll("a[href^='#report-']");
    expect(tocLinks.length).toBe(10);
    for (const section of ["Repository", "Analysis Context", "Summary", "Limitations / Warnings"]) {
      expect(
        Array.from(tocLinks).some((link) => link.textContent === section),
      ).toBe(true);
    }
    expect(screen.getByRole("heading", { name: "Security" })).toBeDefined();
    expect(screen.getAllByText("SEC-HARDCODED-SECRET").length).toBeGreaterThanOrEqual(2);
    expect(screen.getAllByText("app/a.py").length).toBeGreaterThan(0);
    expect(screen.getByText("No limitations recorded.")).toBeDefined();
    const body = document.body.textContent ?? "";
    expect(body).not.toMatch(/score|ranking|grade/i);
  });

  it("shows unavailable sections as unavailable, never clean", async () => {
    const result = analysisResultFixture();
    (result as { dependencies?: unknown }).dependencies = null;
    mockFetchRoutes([{ match: "/api/analyses/abc123", payload: result }]);
    renderAt("/analysis/abc123/report");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Report" })).toBeDefined();
    });
    expect(screen.getByText(/not available/)).toBeDefined();
  });

  it("refuses reports for non-terminal and failed analyses", async () => {
    const queued = analysisResultFixture({
      status: { stage: "Queued", outcome: null, domains: [], limitations: [] },
      summary: null,
      security: null,
      architecture: null,
      dependencies: null,
      code_structure: null,
    } as never);
    mockFetchRoutes([{ match: "/api/analyses/abc123", payload: queued }]);
    renderAt("/analysis/abc123/report");
    await waitFor(() => {
      expect(screen.getByText(/sealed results only/)).toBeDefined();
    });
  });
});

describe("Export buttons", () => {
  const REPORT_BODIES: Record<string, { text: string; contentType: string }> = {
    json: { text: '{"analysis":{}}', contentType: "application/json" },
    markdown: { text: "# Report", contentType: "text/markdown" },
    html: { text: "<html></html>", contentType: "text/html" },
  };

  function mockReportFetch(
    reportImpl: (url: string) => Promise<Response>,
  ): ReturnType<typeof vi.fn> {
    const fetchMock = vi.fn().mockImplementation((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/report?format=")) {
        return reportImpl(url);
      }
      return Promise.resolve({
        ok: true,
        status: 200,
        headers: new Headers(),
        text: () => Promise.resolve(JSON.stringify(analysisResultFixture())),
      } as Response);
    });
    window.fetch = fetchMock;
    return fetchMock;
  }

  function okReport(url: string): Promise<Response> {
    const format = (["json", "markdown", "html"] as const).find((key) =>
      url.includes(`format=${key}`),
    );
    const entry = REPORT_BODIES[format ?? "json"];
    return Promise.resolve({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": entry.contentType }),
      text: () => Promise.resolve(entry.text),
    } as Response);
  }

  it("downloads each format with the contract filename and content", async () => {
    const calls: string[] = [];
    const created: { href: string; download: string }[] = [];
    const originalCreate = URL.createObjectURL;
    const originalRevoke = URL.revokeObjectURL;
    URL.createObjectURL = vi.fn(() => "blob:report") as unknown as typeof URL.createObjectURL;
    URL.revokeObjectURL = vi.fn() as unknown as typeof URL.revokeObjectURL;
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      created.push({ href: this.href, download: this.download });
    });
    try {
      mockReportFetch((url) => {
        calls.push(url);
        return okReport(url);
      });
      renderAt("/analysis/abc123/report");
      await waitFor(() => {
        expect(screen.getByRole("heading", { name: "Report" })).toBeDefined();
      });
      for (const [format, extension, label] of [["json", "json", "JSON"], ["markdown", "md", "MARKDOWN"], ["html", "html", "HTML"]] as const) {
        fireEvent.click(screen.getByRole("button", { name: `Export report as ${label}` }));
        await waitFor(() => {
          expect(calls.some((url) => url.includes(`/report?format=${format}`))).toBe(true);
        });
        await waitFor(() => {
          expect(
            created.some((entry) => entry.download === `repolens-abc123.${extension}`),
          ).toBe(true);
        });
      }
      expect(URL.createObjectURL).toHaveBeenCalledTimes(3);
    } finally {
      URL.createObjectURL = originalCreate;
      URL.revokeObjectURL = originalRevoke;
      clickSpy.mockRestore();
    }
  });

  it("never saves error responses as reports", async () => {
    mockReportFetch(() =>
      Promise.resolve({
        ok: false,
        status: 409,
        headers: new Headers(),
        text: () =>
          Promise.resolve(
            JSON.stringify({
              error: { code: "ANALYSIS_NOT_COMPLETED", message: "Not done.", details: null },
            }),
          ),
      } as Response),
    );
    const createSpy = vi.spyOn(URL, "createObjectURL");
    renderAt("/analysis/abc123/report");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Report" })).toBeDefined();
    });
    fireEvent.click(screen.getByRole("button", { name: "Export report as JSON" }));
    await waitFor(() => {
      expect(screen.getByText("The export failed.")).toBeDefined();
    });
    expect(screen.getByText("Not done.")).toBeDefined();
    expect(createSpy).not.toHaveBeenCalled();
    createSpy.mockRestore();
  });

  it("prevents duplicate export submissions while pending", async () => {
    let release!: (value: Response) => void;
    const baseFetch = mockReportFetch(
      (url) =>
        new Promise<Response>((resolve) => {
          if (url.includes("/report?format=")) {
            release = resolve;
          } else {
            resolve({
              ok: true,
              status: 200,
              headers: new Headers(),
              text: () => Promise.resolve(JSON.stringify(analysisResultFixture())),
            } as Response);
          }
        }),
    );
    renderAt("/analysis/abc123/report");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Report" })).toBeDefined();
    });
    const button = screen.getByRole("button", { name: "Export report as JSON" });
    fireEvent.click(button);
    fireEvent.click(button);
    expect(baseFetch.mock.calls.filter(([url]) => String(url).includes("/report?format=")).length).toBe(1);
    release({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      text: () => Promise.resolve("{}"),
    } as Response);
  });
});
