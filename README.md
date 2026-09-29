# RepoLens: GitHub Repository Security & Architecture Analyzer

RepoLens analyzes a public GitHub repository without running it, and shows which files, modules, dependencies, and code patterns deserve further review.

Give it a repository URL. It resolves the branch and commit, retrieves a snapshot of that commit into an isolated workspace, parses the source, and runs four analyses over the result: security, dependencies, architecture, and code structure. Every finding carries its rule, severity, confidence, location, evidence, and a recommendation for what to check next.

The core principle:

> **Analyze the repository without executing the repository.**

The analyzed repository is treated as untrusted input from retrieval through reporting. RepoLens never runs its code, installs its dependencies, executes its hooks or filters, or builds anything from it.

## Status

RepoLens is in active V1.0 development. It is a working codebase, not a finished product.

Implemented so far:

* FastAPI backend with validated configuration, structured logging, and secret redaction
* Repository ingestion: URL normalization, public-repository validation, branch resolution, immutable commit SHA resolution, commit-based analysis identity
* Safe Git retrieval with hooks/filters hardening, no submodule recursion, timeouts, retries, and size limits
* Disposable per-analysis workspaces with isolation checks, cleanup, stale sweeping, and bounded concurrency (2)
* PostgreSQL persistence for repository and analysis context, with Alembic migrations
* React + TypeScript frontend foundation: routing, state, validation schemas, graph and chart libraries wired up
* Docker Compose local environment (Postgres 17, backend, frontend)
* Test suites on both sides, including tests that prove fixture content is never executed

Not implemented yet:

* File indexing, language detection, parsing, and the Normalized Code Model
* The security, dependency, architecture, and code-structure analyzers and their rules
* Analysis result pages, findings views, architecture graph UI, and reports
* The analysis API endpoints beyond the existing health check

If you open the frontend today you get route scaffolding and placeholders. If you call the backend you get a health check and the ingestion machinery underneath. The analysis features listed below describe the V1.0 direction defined in `docs/`, not the current behavior.

## How it works

```text
GitHub Repository
       │
       ▼
Validate
       │
       ▼
Resolve Branch
       │
       ▼
Resolve Commit SHA
       │
       ▼
Retrieve Snapshot
       │
       ▼
Index Files
       │
       ▼
Detect Languages
       │
       ▼
Parse Source
       │
       ▼
Normalized Code Model
       │
       ├── Security
       ├── Dependencies
       ├── Architecture
       └── Code Structure
              │
              ▼
        Findings & Metrics
              │
              ▼
           Reports
```

The stages up to "Retrieve Snapshot" exist. Everything from "Index Files" onward is planned.

The Normalized Code Model (NCM) is the shared representation between parsing and analysis. Parsers for different languages normalize into the same concepts (modules, imports, classes, functions, calls, locations), so analyzers work from one consistent view of the repository instead of each analyzer understanding every language on its own.

## What it analyzes

### Security

Twelve static rules are defined for V1.0:

* `SEC-HARDCODED-SECRET`
* `SEC-SQL-INJECTION`
* `SEC-COMMAND-INJECTION`
* `SEC-PATH-TRAVERSAL`
* `SEC-SSRF`
* `SEC-UNSAFE-DESERIALIZATION`
* `SEC-WEAK-CRYPTO`
* `SEC-DISABLED-TLS`
* `SEC-INSECURE-CORS`
* `SEC-SENSITIVE-LOGGING`
* `SEC-DANGEROUS-DYNAMIC-EXECUTION`
* `SEC-POTENTIAL-AUTHORIZATION`

Each rule reports a severity (Critical, High, Medium, Low, Info) and a confidence (High, Medium, Low) independently. Severity describes impact if the pattern turned out to be real; confidence describes how certain the static analysis is. Detected secrets are masked before they reach any finding, report, log, or stored result.

A finding is a signal for review, not proof that the code is exploitable.

### Dependencies

* Known dependency vulnerabilities, matched against OSV advisory data for exact versions
* Duplicate dependency versions across direct and transitive occurrences
* High dependency count (default threshold: 200 occurrences per ecosystem scope)
* Unused dependency candidates (reported as candidates, never determinations)

Supported ecosystems: PyPI, plus npm with partial support (direct and lockfile-recorded transitive dependencies, no range solving). Advisory matches are presented as information for review.

### Architecture

* Circular dependencies
* High fan-out, high fan-in, high coupling
* Large modules, classes, and functions
* Layer violations
* Multiple-responsibility candidates

These are observations with evidence attached, not architectural verdicts. Thresholds are explicit and recorded with the rule-set version, and metrics that cannot be computed are reported as unavailable rather than zero.

### Code structure

* High cyclomatic complexity (default threshold: 10 per function/method)
* Deep nesting (default threshold: 4)
* High parameter count (default threshold: 5)
* Duplicate-code candidates (default minimum: 50 normalized tokens)

Measurements shared with architecture analysis use identical values in both places. Structural findings describe what was measured; they do not grade the code.

### No overall score

RepoLens does not produce a single security or quality score. Scores hide what was actually found and invite exactly the misreading this tool tries to avoid. Each finding stands on its own with its rule, severity, confidence, file and line, evidence, and recommendation. An empty result means nothing was found, not that the repository is secure.

## What RepoLens does not do

* Execute analyzed code, install its dependencies, or run its scripts, builds, tests, hooks, or filters
* Recursively fetch submodules
* Require GitHub credentials or integrate with GitHub Apps, OAuth, pull requests, or CI
* Analyze private repositories
* Fix code, open pull requests, or generate patches
* Run dynamic analysis or monitor anything at runtime
* Produce exploitability claims, security certifications, or quality grades
* Use AI/LLM services anywhere in the pipeline

## Why non-execution matters

A repository under review is input you did not write and should not trust. Build scripts, install hooks, Git filters, and submodule configuration can all run arbitrary commands on the machine that processes them. Most review tooling either ignores this or handles it as an afterthought.

RepoLens treats it as a design constraint: retrieval uses a controlled Git workflow (no checkout-time behavior, no hooks, no filters, no credential helpers, no submodule recursion), archive contents are extracted with path containment and size caps into a disposable workspace, and the test suite includes canary fixtures that fail the build if analyzed content is ever executed. The point is not a sandbox. The point is simpler: there is no step in the pipeline where running repository code would even be possible.

## Technology stack

Backend (Python 3.13+):

| Component | Choice |
|---|---|
| API | FastAPI on Uvicorn |
| Validation / settings | Pydantic 2.x, pydantic-settings |
| Database | PostgreSQL 17 via SQLAlchemy 2.x, Alembic migrations |
| Outbound HTTP | HTTPX (GitHub REST, OSV advisories) |
| Parsing (planned) | Tree-sitter, Python `ast` |
| Graph (planned) | NetworkX, in memory |
| Quality gates | pytest, Ruff, mypy |

Frontend:

| Component | Choice |
|---|---|
| UI | React 19, TypeScript 5, Vite 7 |
| Styling | Tailwind CSS 4 |
| Routing | React Router 7 |
| Server state | TanStack Query 5 |
| Client state | Zustand 5 |
| Validation | Zod 4 |
| Visualization (planned) | React Flow 12, Recharts 3 |
| Testing | Vitest, React Testing Library |

Local environment: Docker Compose with Postgres 17, backend, and frontend services. Compose is for local development, not production deployment.

## Repository structure

```text
repolens/
├── frontend/          # React + TypeScript client (foundation + route scaffolding)
├── backend/           # FastAPI application
│   ├── app/
│   │   ├── api/         # HTTP layer (health check today)
│   │   ├── core/        # Settings, database, logging
│   │   ├── models/      # SQLAlchemy models (repository, analysis context)
│   │   ├── repositories/# Persistence gateway
│   │   ├── repository/  # Ingestion: validation, retrieval, workspace
│   │   ├── services/    # Outbound HTTP client
│   │   ├── analyzers/   # Reserved for the four analysis domains
│   │   ├── parsers/     # Reserved for parser adapters
│   │   ├── rules/       # Reserved for analysis rules
│   │   ├── graph/       # Reserved for graph representation
│   │   └── reports/     # Reserved for report rendering
│   ├── alembic/         # Migrations
│   └── tests/           # unit, integration, mocks, fixtures/helpers
├── fixtures/          # Analysis fixture inputs (security, dependencies,
│                       # architecture, code-structure, malformed, ingestion)
├── tests/             # Cross-cutting tests (later phases)
├── docs/              # Frozen requirements 00–17 plus DESIGN.md
├── docker/            # Backend and frontend Dockerfiles
├── docker-compose.yml
└── README.md
```

Detailed requirements live in `docs/00` through `docs/17`, with visual direction in `docs/DESIGN.md`. Those documents are frozen source of truth for V1.0 scope.

## Running it locally

### Backend

```powershell
cd backend
pip install -e ".[dev]"
uvicorn app.main:app --reload --port 8000
```

Health check: `http://localhost:8000/api/health`

Configuration uses `REPOLENS_`-prefixed environment variables (see `backend/.env.example`). Invalid configuration fails startup instead of falling back silently.

### Frontend

```powershell
cd frontend
npm install
npm run dev
```

Dev server: `http://localhost:5173`

### Docker Compose

```powershell
docker compose up --build
```

This starts Postgres 17 (localhost-only port 5432), the backend on port 8000, and the frontend on port 5173. Safe defaults work without a `.env` file; copy `.env.example` to `.env` to override. The backend waits for a healthy database before starting.

## Testing

Backend (186 tests collected):

```powershell
cd backend
pytest
ruff check .
ruff format --check .
mypy app
```

Frontend (26 tests):

```powershell
cd frontend
npm run test
npm run build
```

Backend tests are split into `unit`, `integration`, and `security` markers. Integration tests use local git repositories and SQLite; GitHub and OSV are covered by `MockTransport` mocks, never the real network (a socket tripwire fails any test that tries).

The non-execution tests deserve a mention because they guard the project's main invariant. `fixtures/security/execution_canary.py` contains content that would create a marker file if it were ever executed. Tests read, parse, and scan it, then assert the marker does not exist. Retrieval tests do the same with repositories rigged with malicious hooks, smudge filters, credential helpers, and submodules. If any code path ever runs repository content, these tests fail.

## Limitations

* Static analysis cannot see runtime behavior, configuration-dependent flaws, or deployment context. Coverage is bounded by what the source shows.
* Architecture and code-structure findings need human interpretation. A large module or a dense dependency graph is something to look at, not something proven wrong.
* No findings means nothing was detected under the implemented rules. It does not mean the repository is secure.
* A finding means a pattern matched with stated confidence. It does not mean the issue is exploitable.
* Language support starts with Python. Other languages are out of scope until explicitly added; unsupported content is reported as unsupported, never as clean.

## Roadmap

V1.0 direction, in order:

```text
Foundation
    ↓
Repository Ingestion
    ↓
Indexing & Language Detection
    ↓
Parsing & Normalized Code Model
    ↓
Security / Dependency / Architecture / Code Structure
    ↓
Web Interface
    ↓
Reports
    ↓
Hardening
```

The first two rows exist. The rest is planned work against the frozen requirements in `docs/`.

Possible future work, not committed to V1.0: more languages, framework-aware analysis, custom rules, commit comparison, private repository support, GitHub App integration, PR/CI integration, dynamic or hybrid analysis, IDE integration, AI-assisted explanations, remediation suggestions.

## Contributing

Useful contributions right now:

* Tests, especially around ingestion edge cases and fixture coverage
* Fixture repositories exercising tricky retrieval or parsing shapes
* Parser work toward the Normalized Code Model
* Analysis rule implementations matching the rule definitions in `docs/07`, `docs/08`, and `docs/10`
* Architecture analysis and graph work
* Frontend implementation of the routed views
* Documentation fixes where behavior and text disagree
* Bug fixes and developer tooling improvements

There is no `CONTRIBUTING.md` yet. Match the existing code style (Ruff and mypy pass clean), keep tests deterministic and network-free, and do not add dependencies without a clear reason. Open an issue or a pull request describing what you changed and which requirement or behavior it covers.

## License

No license file is present in the repository yet, so there is currently no license to refer to. If you plan to use or distribute this code, that needs to be resolved first.
