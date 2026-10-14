// Client-side structural validation for the New Analysis form.
// Mirrors backend/app/repository/identity.py (owner/repo shapes, https-only,
// no credentials/ports/queries). Usability only — the backend is authoritative
// and every submission still goes through server validation.

const OWNER_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const REPO_PATTERN = /^[A-Za-z0-9_.-]{1,100}$/;
const SHA_PATTERN = /^[0-9a-fA-F]{7,64}$/;

const BRANCH_FORBIDDEN = ["..", "@{", "~", "^", ":", "?", "*", "[", "\\"];

export const URL_PLACEHOLDER = "https://github.com/owner/repository";
export const URL_EXPECTED_FORM = "https://github.com/owner/repository";

export interface UrlCheck {
  ok: boolean;
  /** User-facing reason when `ok` is false. Never echoes credentials. */
  message?: string;
}

function invalid(message: string): UrlCheck {
  return { ok: false, message };
}

/** Structural check only; returns `ok: true` when the backend should decide. */
export function checkRepositoryUrl(raw: string): UrlCheck {
  const text = (raw ?? "").trim();
  if (!text) {
    return invalid("Enter a repository URL.");
  }
  let parsed: URL;
  try {
    parsed = new URL(text);
  } catch {
    return invalid(
      `That is not a well-formed GitHub repository URL. Expected form: ${URL_EXPECTED_FORM}.`,
    );
  }
  if (parsed.protocol !== "https:") {
    return invalid(
      `Only https GitHub URLs are accepted. Expected form: ${URL_EXPECTED_FORM}.`,
    );
  }
  if (parsed.hostname.toLowerCase() !== "github.com") {
    return invalid(
      `Only public github.com repositories are supported. Expected form: ${URL_EXPECTED_FORM}.`,
    );
  }
  // Never send or echo credentials: reject userinfo before any request.
  if (parsed.username || parsed.password) {
    return invalid("Remove any username, password, or token from the URL and try again.");
  }
  // Note: the URL parser normalizes a default :443 away (both `port` and
  // `host` drop it), so an explicitly written port is detected on the raw
  // authority text instead — matching the backend's rejection of any port.
  const schemeEnd = text.indexOf("://");
  const authority = (schemeEnd >= 0 ? text.slice(schemeEnd + 3) : text).split("/")[0];
  const hostPort = authority.includes("@")
    ? authority.slice(authority.lastIndexOf("@") + 1)
    : authority;
  if (hostPort.includes(":") || parsed.search || parsed.hash) {
    return invalid(
      `That URL has extra parts that are not accepted. Expected form: ${URL_EXPECTED_FORM}.`,
    );
  }
  const segments = parsed.pathname.split("/").filter((segment) => segment.length > 0);
  if (segments.length !== 2) {
    return invalid(
      `That URL does not point to a single repository. Expected form: ${URL_EXPECTED_FORM}.`,
    );
  }
  const [owner, rawName] = segments;
  const name = rawName.toLowerCase().endsWith(".git")
    ? rawName.slice(0, -".git".length)
    : rawName;
  if (!OWNER_PATTERN.test(owner) || !REPO_PATTERN.test(name) || name === "." || name === "..") {
    return invalid(
      `That URL does not look like a GitHub owner/repository path. Expected form: ${URL_EXPECTED_FORM}.`,
    );
  }
  return { ok: true };
}

/** Light branch syntax check mirroring backend validate_branch_name. */
export function checkBranchName(raw: string): UrlCheck {
  const text = (raw ?? "").trim();
  if (!text) {
    return { ok: true };
  }
  if (
    text.length > 255 ||
    [...text].some((char) => /\s/.test(char) || (char.codePointAt(0) ?? 0) < 32) ||
    text.startsWith("/") ||
    text.startsWith(".") ||
    text.startsWith("-") ||
    text.endsWith("/") ||
    text.endsWith(".") ||
    text.endsWith(".lock") ||
    BRANCH_FORBIDDEN.some((forbidden) => text.includes(forbidden))
  ) {
    return invalid("That branch name contains characters Git does not accept.");
  }
  return { ok: true };
}

/** Light commit check mirroring backend validate_commit_sha (7–64 hex). */
export function checkCommitRef(raw: string): UrlCheck {
  const text = (raw ?? "").trim();
  if (!text) {
    return { ok: true };
  }
  if (!SHA_PATTERN.test(text)) {
    return invalid("Enter a commit SHA (7 to 64 hexadecimal characters).");
  }
  return { ok: true };
}
