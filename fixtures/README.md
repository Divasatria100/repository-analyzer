# RepoLens analysis fixtures (test data, never executed).

Canonical source for repository content consumed by future analyzer tests.
Each file is read as **data**: parsed, scanned, or indexed — never imported,
evaluated, or run. Filenames never match pytest collection patterns
(`test_*.py` / `*_test.py`), and this tree sits outside `testpaths`.

| Directory      | Purpose                                              |
| -------------- | ---------------------------------------------------- |
| `security/`    | Rule-shaped snippets (secrets, injection, TLS, …)    |
| `dependencies/`| Manifest/lockfile excerpts (pip, npm)                |
| `architecture/`| Module-relationship shapes (clean, circular, fan-out)|
| `code-structure/` | Complexity/nesting/params/duplicate shapes        |
| `malformed/`   | Intentionally unparseable source (failure isolation) |

Safety rules:

* Secret-like values are obvious fakes (`FAKE_…`, `…_NOT_REAL`, `EXAMPLE_…`).
* No personal data, no real credentials, no network targets that matter.
* `execution_canary.py` (security/) would create a marker file **only if
  executed**; tests assert the marker never appears (see `tests/unit/`).
* Keep fixtures small, deterministic, and descriptive.
