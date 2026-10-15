import { useState, type FormEvent } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { ApiRequestError, postAnalysis } from "../lib/api";
import { setRecentRepositoryId } from "../lib/recentRepository";
import { URL_PLACEHOLDER, checkBranchName, checkCommitRef, checkRepositoryUrl } from "../lib/validation";
import { ROUTES } from "../router/routes";
import { Alert, FieldError, Panel } from "../components/ui";

// New Analysis (docs/14-ui-requirements.md, Section 7; docs/17 §4.1).
// Single focused form. Analysis areas are a fixed read-only list (FR-012):
// the API runs all four areas and accepts no category parameter, so no
// toggles are shown. Branch/commit are optional plain references — the API
// exposes no listing endpoint, and the backend resolves them.

const ANALYSIS_AREAS = ["Security", "Architecture", "Dependencies", "Code Structure"] as const;

interface FieldErrors {
  url?: string;
  branch?: string;
  commit?: string;
}

function messageForCode(code: string, fallback: string): string {
  switch (code) {
    case "INVALID_URL":
      return fallback;
    case "REPOSITORY_NOT_ACCESSIBLE":
      return "The repository could not be retrieved or is not accessible as a public repository.";
    case "INVALID_BRANCH":
      return "The branch could not be found.";
    case "INVALID_COMMIT":
      return "The commit could not be found or resolved.";
    case "RATE_LIMITED":
      return "Too many requests are running. Wait a moment and try again.";
    case "NETWORK_ERROR":
    case "UNKNOWN_ERROR":
      return fallback;
    default:
      return fallback;
  }
}

export function NewAnalysisPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  // The dashboard quick input arrives here as ?url= (docs/14 §6.1).
  const [url, setUrl] = useState(() => searchParams.get("url") ?? "");
  const [branch, setBranch] = useState("");
  const [commit, setCommit] = useState("");
  const [touched, setTouched] = useState({ url: false, branch: false, commit: false });
  const [errors, setErrors] = useState<FieldErrors>({});
  const [requestError, setRequestError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  function validateAll(current: { url: string; branch: string; commit: string }): FieldErrors {
    const next: FieldErrors = {};
    const urlCheck = checkRepositoryUrl(current.url);
    if (!urlCheck.ok && urlCheck.message) {
      next.url = urlCheck.message;
    }
    const branchCheck = checkBranchName(current.branch);
    if (!branchCheck.ok && branchCheck.message) {
      next.branch = branchCheck.message;
    }
    const commitCheck = checkCommitRef(current.commit);
    if (!commitCheck.ok && commitCheck.message) {
      next.commit = commitCheck.message;
    }
    return next;
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (pending) {
      return;
    }
    const values = { url, branch, commit };
    const fieldErrors = validateAll(values);
    setTouched({ url: true, branch: true, commit: true });
    setErrors(fieldErrors);
    setRequestError(null);
    if (fieldErrors.url ?? fieldErrors.branch ?? fieldErrors.commit) {
      return;
    }
    setPending(true);
    try {
      const accepted = await postAnalysis({
        url: values.url.trim(),
        branch: values.branch.trim() ? values.branch.trim() : null,
        commit: values.commit.trim() ? values.commit.trim().toLowerCase() : null,
      });
      // HTTP 202: accepted, not completed. The progress view shows the
      // actual returned stage; nothing here claims execution has started.
      // Remember the repository so the Dashboard can offer it back.
      setRecentRepositoryId(accepted.repository_id);
      navigate(ROUTES.analysisDetail(accepted.analysis_id));
    } catch (error) {
      // Inputs are preserved for correction; only the error is shown.
      if (error instanceof ApiRequestError) {
        const message = messageForCode(error.code, error.message);
        if (error.code === "INVALID_URL") {
          setErrors((previous) => ({ ...previous, url: message }));
        } else if (error.code === "INVALID_BRANCH") {
          setErrors((previous) => ({ ...previous, branch: message }));
        } else if (error.code === "INVALID_COMMIT") {
          setErrors((previous) => ({ ...previous, commit: message }));
        } else {
          setRequestError(message);
        }
      } else {
        setRequestError("An unexpected error occurred. Try again.");
      }
      setPending(false);
    }
  }

  const showUrlError = touched.url ? errors.url : undefined;
  const showBranchError = touched.branch ? errors.branch : undefined;
  const showCommitError = touched.commit ? errors.commit : undefined;

  return (
    <div className="mx-auto w-full max-w-[960px]">
      <Panel>
        <h2 className="mb-1 text-xl font-semibold">Analyze a public repository</h2>
        <p className="mb-6 text-sm text-text-secondary">
          Repository code is analyzed without being executed.
        </p>
        <form onSubmit={(event) => void handleSubmit(event)} noValidate>
          <div>
            <label htmlFor="repository-url" className="mb-1 block text-sm font-medium">
              Repository URL
            </label>
            <input
              id="repository-url"
              name="url"
              type="url"
              autoFocus
              autoComplete="off"
              spellCheck={false}
              placeholder={URL_PLACEHOLDER}
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              onBlur={() => {
                setTouched((previous) => ({ ...previous, url: true }));
                const check = checkRepositoryUrl(url);
                setErrors((previous) => ({
                  ...previous,
                  url: !check.ok ? check.message : undefined,
                }));
              }}
              aria-invalid={showUrlError ? true : undefined}
              aria-describedby={showUrlError ? "repository-url-error" : "repository-url-help"}
              disabled={pending}
              className="break-identifier w-full rounded-control border border-border bg-secondary px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-secondary disabled:opacity-50"
            />
            <p id="repository-url-help" className="mt-1 text-sm text-text-secondary">
              Public GitHub repositories only. No GitHub sign-in is required.
            </p>
            {showUrlError ? <FieldError id="repository-url-error" message={showUrlError} /> : null}
          </div>

          <details className="mt-6 rounded-control border border-border">
            <summary className="cursor-pointer px-3 py-2 text-sm font-medium text-text-secondary hover:text-text-primary">
              Branch and commit (optional)
            </summary>
            <div className="space-y-4 border-t border-border px-3 py-4">
              <p className="text-sm text-text-secondary">
                Leave empty to use the default branch and commit, shown once the analysis
                starts. When both are given, the commit is the analyzed state and the
                branch is context.
              </p>
              <div>
                <label htmlFor="branch" className="mb-1 block text-sm font-medium">
                  Branch
                </label>
                <input
                  id="branch"
                  name="branch"
                  type="text"
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="main"
                  value={branch}
                  onChange={(event) => setBranch(event.target.value)}
                  onBlur={() => {
                    setTouched((previous) => ({ ...previous, branch: true }));
                    const check = checkBranchName(branch);
                    setErrors((previous) => ({
                      ...previous,
                      branch: !check.ok ? check.message : undefined,
                    }));
                  }}
                  aria-invalid={showBranchError ? true : undefined}
                  aria-describedby={showBranchError ? "branch-error" : undefined}
                  disabled={pending}
                  className="w-full rounded-control border border-border bg-secondary px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-secondary disabled:opacity-50"
                />
                {showBranchError ? <FieldError id="branch-error" message={showBranchError} /> : null}
              </div>
              <div>
                <label htmlFor="commit" className="mb-1 block text-sm font-medium">
                  Commit
                </label>
                <input
                  id="commit"
                  name="commit"
                  type="text"
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="40-character SHA, or 7+ character prefix"
                  value={commit}
                  onChange={(event) => setCommit(event.target.value)}
                  onBlur={() => {
                    setTouched((previous) => ({ ...previous, commit: true }));
                    const check = checkCommitRef(commit);
                    setErrors((previous) => ({
                      ...previous,
                      commit: !check.ok ? check.message : undefined,
                    }));
                  }}
                  aria-invalid={showCommitError ? true : undefined}
                  aria-describedby={showCommitError ? "commit-error" : undefined}
                  disabled={pending}
                  className="break-identifier w-full rounded-control border border-border bg-secondary px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-secondary disabled:opacity-50"
                />
                {showCommitError ? <FieldError id="commit-error" message={showCommitError} /> : null}
              </div>
            </div>
          </details>

          <div className="mt-6">
            <h3 className="text-sm font-medium text-text-secondary">
              Analysis areas (all included)
            </h3>
            <p className="mt-1 text-sm text-text-primary">
              {ANALYSIS_AREAS.join(" · ")}
            </p>
          </div>

          {requestError ? (
            <div className="mt-6">
              <Alert tone="error" title="The analysis could not be started.">
                <p>{requestError}</p>
              </Alert>
            </div>
          ) : null}

          <button
            type="submit"
            disabled={pending}
            aria-busy={pending}
            className="mt-6 rounded-control bg-primary px-5 py-2.5 text-sm font-semibold text-background hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {pending ? "Starting analysis…" : "Start Analysis"}
          </button>
        </form>
      </Panel>
    </div>
  );
}
