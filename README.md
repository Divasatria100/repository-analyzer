# RepoLens — GitHub Repository Security & Architecture Analyzer

Foundation skeleton (V1.0).

## Structure

```text
repolens/
├── frontend/          # React 19 + TypeScript + Vite client
├── backend/           # FastAPI (Python 3.13+) application
├── fixtures/          # Analysis fixture inputs (later phases)
├── tests/             # Cross-cutting tests (later phases)
├── docs/              # Frozen source of truth (requirements + DESIGN.md)
├── docker/            # Local development environment files
├── docker-compose.yml # Local multi-component environment
└── README.md
```

## Local development

Backend:

```powershell
cd backend
pip install -e ".[dev]"
uvicorn app.main:app --reload --port 8000
```

Frontend:

```powershell
cd frontend
npm install
npm run dev
```

Docker (local development environment only) will be defined in later phases.
