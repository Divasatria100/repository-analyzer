import { screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderAt } from "../test/render";
import {
  analysisResultFixture,
  architectureFixture,
  findingsPageFixture,
  findingFixture,
} from "../test/fixtures";

function mockAnalysisFetch(payload: unknown, status = 200) {
  window.fetch = vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(typeof payload === "string" ? payload : JSON.stringify(payload)),
  } as Response);
}

function mockWorkspaceFetch() {
  const routes = [
    { match: "/architecture", payload: architectureFixture() },
    { match: "/findings", payload: findingsPageFixture([findingFixture()], 1) },
    { match: "/api/analyses/abc123", payload: analysisResultFixture() },
  ];
  window.fetch = vi.fn().mockImplementation((input: RequestInfo | URL) => {
    const url = String(input);
    const route = routes.find((entry) => url.includes(entry.match));
    const status = 200;
    return Promise.resolve({
      ok: true,
      status,
      text: () => Promise.resolve(JSON.stringify(route?.payload ?? {})),
    } as Response);
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe.each([
  ["/analysis/new", "Analyze a public repository"],
  ["/history", "History"],
  ["/settings", "Settings"],
])("route %s", (path, title) => {
  it(`renders the ${title} page inside the shell`, () => {
    renderAt(path);
    // The shell top bar and the page can share a title; at least one
    // heading with the page title must be present.
    expect(screen.getAllByRole("heading", { name: title }).length).toBeGreaterThan(0);
    // Shell navigation is present on every page.
    expect(screen.getByRole("link", { name: "New Analysis" })).toBeDefined();
  });
});

describe("implemented workspace routes", () => {
  it("renders the Overview from persisted data", async () => {
    mockWorkspaceFetch();
    renderAt("/analysis/abc123/overview");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "acme/web" })).toBeDefined();
    });
    expect(screen.getByRole("link", { name: "New Analysis" })).toBeDefined();
  });

  it("renders the Security explorer", async () => {
    mockWorkspaceFetch();
    renderAt("/analysis/abc123/security");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Security" })).toBeDefined();
    });
  });

  it("renders the Architecture workspace", async () => {
    mockWorkspaceFetch();
    renderAt("/analysis/abc123/architecture");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Architecture" })).toBeDefined();
    });
  });

  it("renders the Findings explorer", async () => {
    mockWorkspaceFetch();
    renderAt("/analysis/abc123/findings");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Findings" })).toBeDefined();
    });
  });

  it("renders Finding Detail for a stable identity", async () => {
    mockWorkspaceFetch();
    renderAt("/analysis/abc123/findings/F-0001");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "SEC-HARDCODED-SECRET" })).toBeDefined();
    });
  });

  it("renders the Dependencies view", async () => {
    mockWorkspaceFetch();
    renderAt("/analysis/abc123/dependencies");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Dependencies" })).toBeDefined();
    });
  });

  it("renders the Code Structure view", async () => {
    mockWorkspaceFetch();
    renderAt("/analysis/abc123/code-structure");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Code Structure" })).toBeDefined();
    });
  });

  it("renders the Files explorer", async () => {
    mockWorkspaceFetch();
    renderAt("/analysis/abc123/files");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Files" })).toBeDefined();
    });
  });

  it("renders the Report view", async () => {
    mockWorkspaceFetch();
    renderAt("/analysis/abc123/report");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Report" })).toBeDefined();
    });
  });
});

describe("router fallbacks", () => {
  it("renders the dashboard at root", () => {
    renderAt("/");
    expect(screen.getByRole("button", { name: "Analyze Repository" })).toBeDefined();
  });

  it("loads the real analysis status for bare analysis detail", async () => {
    mockAnalysisFetch({
      analysis: { analysis_id: "abc123", repository_id: "r", timestamp: null },
      repository: {
        repository_id: "r",
        url: "https://github.com/acme/web",
        owner: "acme",
        name: "web",
        analyzed_state: { branch: null, commit: null },
      },
      status: { stage: "Queued", outcome: null },
    });
    renderAt("/analysis/abc123");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Analysis in progress" })).toBeDefined();
    });
    // The live terminal restates the same server state; it fabricates nothing.
    expect(screen.getByRole("heading", { name: "Analysis terminal" })).toBeDefined();
    const log = screen.getByRole("log");
    expect(log.textContent).toContain("Analysis accepted");
    expect(log.textContent).toContain("Queued");
  });

  it("renders Not Found for unknown routes", () => {
    renderAt("/does-not-exist");
    expect(screen.getByRole("heading", { name: "Page not found" })).toBeDefined();
  });
});
