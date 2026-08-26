# AGENTS.md - Public Repo Security Dashboard

## Project Overview
A Python/FastAPI dashboard that monitors public GitHub repos for:
- Leaked secrets (gitleaks)
- Vulnerable dependencies (OSV.dev API)
- Weak branch protection
- Dangerous workflow patterns

## Tech Stack
- **Backend**: FastAPI + SQLAlchemy + Celery + Redis
- **Database**: PostgreSQL (via psycopg2)
- **Auth**: GitHub OAuth (Authlib)
- **External Tools**: gitleaks (secret scanning)

## Project Structure
```
repo-security-dashboard/
├── app/
│   ├── main.py              # FastAPI entrypoint
│   ├── config.py            # Settings (pydantic-settings)
│   ├── auth/                # GitHub OAuth
│   ├── github_connector/    # PyGithub wrappers
│   ├── scanners/            # Core scanning logic
│   ├── models/              # SQLAlchemy models
│   ├── routers/             # FastAPI routes
│   ├── tasks/               # Celery tasks
│   └── templates/           # Jinja2 HTML
├── alembic/                 # DB migrations
└── tests/
```

## Development Commands
```bash
# Install dependencies
pip install -r requirements.txt

# Run dev server
uvicorn app.main:app --reload

# Run Celery worker
celery -A app.tasks worker --loglevel=info

# Database migrations
alembic upgrade head
alembic revision --autogenerate -m "description"
```

## Coding Conventions
- Python 3.11+
- Use async/await in FastAPI routes
- SQLAlchemy 2.0 style (mapped_column, DeclarativeBase)
- Pydantic models for API request/response
- Keep scanners modular (secrets, dependency, branch, workflow)

## Environment Variables
Required in `.env`:
```
DATABASE_URL=postgresql+psycopg2://...
REDIS_URL=redis://localhost:6379/0
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
SECRET_KEY=change-me
```
