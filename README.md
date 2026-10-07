# Public Repository Security Dashboard

An experimental project for monitoring the security posture of public GitHub
repositories. The backend is planned with FastAPI; React will be the frontend
when the web milestones begin.

## Milestone 1: local repository scanner

The current deliverable is a CLI that scans a local Git repository for leaked
secrets with [gitleaks](https://github.com/gitleaks/gitleaks) and vulnerable
dependencies with the [OSV.dev API](https://osv.dev/). It does not start a web
server or require a database.

Install the Python dependencies and make gitleaks available on `PATH`, or set
`GITLEAKS_PATH` in the environment (see `.env.example`). Then run:

```powershell
python scan_repo.py C:\path\to\repository
python scan_repo.py C:\path\to\repository --json
```

To run the scanner tests:

```powershell
python -m unittest discover -s tests -v
```

The `app/` and `alembic/` directories mirror the planned backend structure.
They are placeholders for later milestones; the scanner remains at the
repository root during Milestone 1.

