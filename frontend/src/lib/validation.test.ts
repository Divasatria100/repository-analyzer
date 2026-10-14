import { describe, expect, it } from "vitest";
import { checkBranchName, checkCommitRef, checkRepositoryUrl } from "./validation";

describe("repository URL validation", () => {
  it("accepts canonical and equivalent forms", () => {
    expect(checkRepositoryUrl("https://github.com/acme/web").ok).toBe(true);
    expect(checkRepositoryUrl("  https://github.com/acme/web/  ").ok).toBe(true);
    expect(checkRepositoryUrl("https://github.com/acme/web.git").ok).toBe(true);
  });

  it("rejects empty input", () => {
    expect(checkRepositoryUrl("   ")).toEqual({ ok: false, message: "Enter a repository URL." });
  });

  it("rejects non-GitHub hosts, schemes, and extra parts", () => {
    for (const url of [
      "https://gitlab.com/acme/web",
      "http://github.com/acme/web",
      "https://github.com/acme",
      "https://github.com/acme/web/extra",
      "https://github.com/acme/web?tab=readme",
      "https://github.com:443/acme/web",
      "not a url",
    ]) {
      expect(checkRepositoryUrl(url).ok, url).toBe(false);
    }
  });

  it("rejects credentials without echoing them", () => {
    const result = checkRepositoryUrl("https://user:s3cret@github.com/acme/web");
    expect(result.ok).toBe(false);
    expect(result.message).not.toContain("s3cret");
  });
});

describe("branch and commit validation", () => {
  it("treats empty references as default", () => {
    expect(checkBranchName("").ok).toBe(true);
    expect(checkCommitRef("  ").ok).toBe(true);
  });

  it("accepts well-formed references", () => {
    expect(checkBranchName("main").ok).toBe(true);
    expect(checkBranchName("feature/new-parser").ok).toBe(true);
    expect(checkCommitRef("9f2c1e7").ok).toBe(true);
    expect(checkCommitRef("9f2c1e7a4b8d3f60a5c7e1b2d4f8a09c3e5b7d61").ok).toBe(true);
  });

  it("rejects malformed references", () => {
    expect(checkBranchName("has space").ok).toBe(false);
    expect(checkBranchName("bad..name").ok).toBe(false);
    expect(checkCommitRef("xyz").ok).toBe(false);
    expect(checkCommitRef("9f2c1e").ok).toBe(false);
  });
});
