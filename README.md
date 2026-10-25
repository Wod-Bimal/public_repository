# Public Repository Security Dashboard

An experimental project for monitoring the security posture of public GitHub
repositories. The backend is planned with FastAPI; React will be the frontend
when the web milestones begin.

## Milestone 1: local secret scanner

The CLI scans a local Git repository for leaked secrets with
[gitleaks](https://github.com/gitleaks/gitleaks). It does not start a web
server or require a database.

Make gitleaks available on `PATH`, or set the `GITLEAKS_PATH` environment
variable to its executable. Then run:

```powershell
python repo_scanner.py C:\path\to\repository
python repo_scanner.py C:\path\to\repository --json
```

To run the scanner tests (Python 3.11+):

```powershell
python -m unittest discover -s tests -v
```

Dependency scanning via OSV.dev will be added as the next Milestone 1 feature.
