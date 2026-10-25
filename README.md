# Public Repository Security Dashboard

An experimental project for monitoring the security posture of public GitHub
repositories. The backend is planned with FastAPI; React will be the frontend
when the web milestones begin.

## Milestone 1: local repository scanner

The CLI scans a local Git repository for leaked secrets with
[gitleaks](https://github.com/gitleaks/gitleaks) and checks supported
dependency manifests against the [OSV.dev API](https://osv.dev/). It does not
start a web server or require a database.

Make gitleaks available on `PATH`, or set the `GITLEAKS_PATH` environment
variable to its executable. Then run:

```powershell
python repo_scanner.py C:\path\to\repository
python repo_scanner.py C:\path\to\repository --json
```

Dependency checks currently cover exact versions in `requirements*.txt`,
`setup.py`, `pyproject.toml`, `Pipfile`, `package.json`, `go.mod`, and
`Gemfile`. Version ranges are skipped because OSV queries require a specific
version. Scanner and manifest errors are reported; the CLI exits with status
1 when a scan is incomplete.

To run the scanner tests (Python 3.11+):

```powershell
python -m unittest discover -s tests -v
```
