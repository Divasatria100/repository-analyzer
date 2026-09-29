# RepoLens Backend

Foundation skeleton (see `docs/11-system-architecture.md`).

## Local development

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
uvicorn app.main:app --reload --port 8000
```

Health check: `GET http://localhost:8000/api/health`

## Configuration

Centralized Pydantic settings (`app/core/config.py`) — the single source
of the 23 operational values in `docs/15 §9.1`. Environment overrides use
the `REPOLENS_` prefix with `__` nesting (see `.env.example`).
Invalid configuration fails closed at startup. `.env` is git-ignored.

## Database

PostgreSQL target via SQLAlchemy 2.x + Alembic (RepoLens database only):

```powershell
alembic revision --autogenerate -m "describe change"
alembic upgrade head
```

## Quality baseline

```powershell
pytest
ruff check app tests
mypy app
```
