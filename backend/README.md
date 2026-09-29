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
