#!/usr/bin/env python3
"""
Stage 1: Local CLI proof of concept for the Public Repo Security Dashboard.

Usage:
    python scan_repo.py /path/to/repository

Scans a local git repository for:
    - Leaked secrets            (gitleaks, external binary)
    - Vulnerable dependencies   (OSV.dev REST API)
and prints findings to the console.

Requires: gitleaks binary on PATH or GITLEAKS_PATH env var.
Zero installs required beyond Python stdlib + httpx.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import toml

GITLEAKS_TIMEOUT_SECONDS = 300
OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_REQUEST_SLEEP = 0.5  # be polite to the free API


@dataclass
class Finding:
    severity: str          # critical | high | medium | low
    title: str
    details: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Scan a local git repo for leaked secrets and vulnerable dependencies."
    )
    parser.add_argument("repo_path", help="Path to the local repository to scan")
    parser.add_argument(
        "--gitleaks",
        help="Path to the gitleaks binary (defaults to GITLEAKS_PATH env or 'gitleaks' on PATH)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output findings as JSON (for piping into other tools)",
    )
    return parser.parse_args()


def resolve_gitleaks(explicit: str | None) -> str | None:
    """Return the path to the gitleaks binary, or None if unavailable."""
    candidates = [explicit, os.environ.get("GITLEAKS_PATH"), shutil.which("gitleaks")]
    for c in candidates:
        if c:
            return c
    return None


# ---------------------------------------------------------------------------
# Secrets scanner (gitleaks)
# ---------------------------------------------------------------------------

def scan_secrets(repo_path: Path, gitleaks_bin: str) -> list[Finding]:
    findings: list[Finding] = []

    if not gitleaks_bin:
        findings.append(
            Finding(
                severity="high",
                title="gitleaks binary not found",
                details=[
                    "Install it: https://github.com/gitleaks/gitleaks/releases",
                    "or set GITLEAKS_PATH env var to point at the binary.",
                ],
            )
        )
        return findings

    cmd = [
        gitleaks_bin,
        "detect",
        "--source",
        str(repo_path),
        "--report-format",
        "json",
        "--report-path",
        "-",
        "--no-banner",
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=GITLEAKS_TIMEOUT_SECONDS
        )
    except FileNotFoundError:
        findings.append(
            Finding(
                severity="high",
                title="gitleaks binary not found",
                details=["The configured path does not exist: " + gitleaks_bin],
            )
        )
        return findings
    except subprocess.TimeoutExpired:
        findings.append(
            Finding(
                severity="medium",
                title="Secret scan timed out",
                details=[f"Exceeded {GITLEAKS_TIMEOUT_SECONDS}s timeout"],
            )
        )
        return findings

    if not result.stdout.strip():
        return findings  # no secrets found

    try:
        leaks = json.loads(result.stdout)
    except json.JSONDecodeError:
        return findings  # nothing parseable -> treat as no findings

    for leak in leaks:
        desc = leak.get("Description") or "Leaked secret"
        rule = leak.get("RuleID") or "unknown-rule"
        file_ = leak.get("File") or "unknown"
        start = leak.get("StartLine")
        end = leak.get("EndLine")
        line = f"{start}" if start == end else f"{start}-{end}"
        findings.append(
            Finding(
                severity="critical",
                title=f"Leaked secret: {desc}",
                details=[
                    f"Rule:     {rule}",
                    f"File:     {file_}:{line}",
                    f"Commit:   {leak.get('Commit', 'unknown')}",
                    f"Author:   {leak.get('Author', 'unknown')}",
                    f"Author email: {leak.get('Email', 'unknown')}",
                ],
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Dependency scanner (OSV.dev)
# ---------------------------------------------------------------------------

MANIFEST_PATTERNS = [
    "requirements*.txt",
    "setup.py",
    "pyproject.toml",
    "Pipfile",
    "package.json",
    "go.mod",
    "Gemfile",
]


def find_manifests(repo_path: Path) -> list[Path]:
    manifests: list[Path] = []
    for pattern in MANIFEST_PATTERNS:
        manifests.extend(repo_path.glob(pattern))
        manifests.extend(repo_path.glob(f"**/{pattern}"))
    # de-duplicate while preserving order
    seen = set()
    unique = []
    for m in manifests:
        if m not in seen:
            seen.add(m)
            unique.append(m)
    return unique


def parse_requirements_txt(path: Path) -> list[dict]:
    deps = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # ignore direct URLs / editable installs
        if line.startswith(("git+", "hg+", "svn+", "http", "-e")) or "@ " in line:
            continue
        match = re.match(r"^([a-zA-Z0-9_.-]+)\s*([=<>!~]+)\s*([^\s,]+)", line)
        if match:
            name = match.group(1)
            version = match.group(3)
            deps.append({"name": name, "version": version, "ecosystem": "PyPI"})
    return deps


def parse_setup_py(path: Path) -> list[dict]:
    deps = []
    content = path.read_text(encoding="utf-8", errors="ignore")
    match = re.search(r"install_requires\s*=\s*\[(.*?)\]", content, re.DOTALL)
    if not match:
        return deps
    for entry in re.findall(r"'([^']+)'|\"([^\"]+)\"", match.group(1)):
        spec = entry[0] or entry[1]
        m = re.match(r"^([a-zA-Z0-9_.-]+)\s*([=<>!~]+)\s*([^\s]+)", spec)
        if m:
            deps.append(
                {
                    "name": m.group(1),
                    "version": m.group(3),
                    "ecosystem": "PyPI",
                }
            )
    return deps


def parse_pyproject_toml(path: Path) -> list[dict]:
    deps = []
    data = toml.loads(path.read_text(encoding="utf-8", errors="ignore"))
    for dep_str in data.get("project", {}).get("dependencies", []):
        m = re.match(r"^([a-zA-Z0-9_.-]+)\s*([=<>!~]+)?\s*([^\s;]+)?", dep_str)
        if m and m.group(1):
            deps.append(
                {
                    "name": m.group(1),
                    "version": m.group(3) or "",
                    "ecosystem": "PyPI",
                }
            )
    return deps


def parse_pipfile(path: Path) -> list[dict]:
    deps = []
    data = toml.loads(path.read_text(encoding="utf-8", errors="ignore"))
    for section in ("packages", "dev-packages"):
        for name, version in data.get(section, {}).items():
            clean = version.lstrip("=<>~ ").strip('"')
            deps.append({"name": name, "version": clean, "ecosystem": "PyPI"})
    return deps


def parse_package_json(path: Path) -> list[dict]:
    deps = []
    data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    for section in ("dependencies", "devDependencies"):
        for name, version in data.get(section, {}).items():
            clean = re.sub(r"[\^~>=<]", "", version)
            deps.append({"name": name, "version": clean, "ecosystem": "npm"})
    return deps


def parse_go_mod(path: Path) -> list[dict]:
    deps = []
    in_require = False
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if line == ")":
            in_require = False
            continue
        if in_require or line.startswith("require "):
            parts = line.split()
            if len(parts) >= 2:
                name = parts[0]
                version = parts[1].lstrip("v")
                # skip indirect-only lines with "// indirect" -> check comment
                deps.append({"name": name, "version": version, "ecosystem": "Go"})
    return deps


def parse_gemfile(path: Path) -> list[dict]:
    deps = []
    content = path.read_text(encoding="utf-8", errors="ignore")
    for m in re.finditer(r"gem\s+['\"]([^'\"]+)['\"](?:[^#]*?(?:,\s*['\"]([^'\"]+)['\"]))?", content):
        name = m.group(1)
        version = m.group(2)
        if version is None:
            version = ""
        deps.append({"name": name, "version": version, "ecosystem": "RubyGems"})
    return deps


def parse_manifest(path: Path) -> list[dict]:
    """Dispatch to the right parser for a manifest file. Never raises."""
    name = path.name.lower()
    try:
        if name.startswith("requirements") or name == "requirements.txt":
            return parse_requirements_txt(path)
        if name == "setup.py":
            return parse_setup_py(path)
        if name == "pyproject.toml":
            return parse_pyproject_toml(path)
        if name == "pipfile":
            return parse_pipfile(path)
        if name == "package.json":
            return parse_package_json(path)
        if name == "go.mod":
            return parse_go_mod(path)
        if name == "gemfile":
            return parse_gemfile(path)
    except Exception:
        pass
    return []


def collect_dependencies(repo_path: Path) -> tuple[list[dict], list[str]]:
    """Return (deps, problems) where problems are manifest paths we could not parse."""
    deps: list[dict] = []
    problems: list[str] = []
    for manifest in find_manifests(repo_path):
        parsed = parse_manifest(manifest)
        if not parsed:
            if manifest.stat().st_size == 0:
                continue
            problems.append(str(manifest))
        for dep in parsed:
            if dep["version"]:  # only check deps with a pinned version
                deps.append({"manifest": str(manifest), **dep})
    return deps, problems


def query_osv(name: str, version: str, ecosystem: str, client: httpx.Client) -> dict | None:
    payload = {
        "package": {"name": name, "ecosystem": ecosystem},
        "version": version,
    }
    try:
        resp = client.post(OSV_API_URL, json=payload, timeout=30)
        if resp.status_code == 200:
            return resp.json()
    except httpx.HTTPError:
        pass
    return None


def cvss_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def extract_severity(vuln: dict) -> str:
    for sev in vuln.get("severity", []):
        score = sev.get("score", "")
        m = re.search(r"(\d+\.?\d*)", score)
        if m:
            return cvss_severity(float(m.group(1)))
    return "medium"


def scan_dependencies(repo_path: Path) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    deps, problems = collect_dependencies(repo_path)
    if not deps:
        return findings, problems

    # de-duplicate (name, version, ecosystem)
    seen, unique_deps = set(), []
    for d in deps:
        key = (d["name"].lower(), d["version"], d["ecosystem"])
        if key not in seen:
            seen.add(key)
            unique_deps.append(d)

    headers = {"Content-Type": "application/json", "User-Agent": "repo-security-dashboard/0.1"}
    with httpx.Client(headers=headers) as client:
        for dep in unique_deps:
            result = query_osv(dep["name"], dep["version"], dep["ecosystem"], client)
            time.sleep(OSV_REQUEST_SLEEP)
            if not result:
                continue
            for vuln in result.get("vulns", []):
                refs = vuln.get("references") or []
                url = refs[0].get("url", "") if refs else ""
                findings.append(
                    Finding(
                        severity=extract_severity(vuln),
                        title=f"{dep['name']}@{dep['version']} is vulnerable",
                        details=[
                            f"Package:  {dep['name']}@{dep['version']} "
                            f"({dep['ecosystem']})",
                            f"Vuln ID:  {vuln.get('id', 'unknown')}",
                            f"Manifest: {dep['manifest']}",
                            f"Summary:  {vuln.get('summary', 'n/a')}",
                            f"Detail:   {url}",
                        ],
                    )
                )
    return findings, problems


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def as_dict(findings: list[Finding]) -> list[dict]:
    return [
        {
            "severity": f.severity,
            "title": f.title,
            "details": f.details,
        }
        for f in findings
    ]


def print_report(repo_path: Path, secrets: list[Finding], deps: list[Finding], problems: list[str]):
    all_findings = sorted(
        secrets + deps, key=lambda f: SEVERITY_ORDER.get(f.severity, 99)
    )

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in all_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print("=" * 60)
    print("REPO SECURITY SCAN REPORT")
    print("=" * 60)
    print(f"Repository:   {repo_path}")
    print(f"Secrets:      {len(secrets)} finding(s)")
    print(f"Dependencies: {len(deps)} finding(s)")
    print(f"Total:        {sum(counts.values())} finding(s)")
    print(f"  critical:   {counts['critical']}")
    print(f"  high:       {counts['high']}")
    print(f"  medium:     {counts['medium']}")
    print(f"  low:        {counts['low']}")
    print("=" * 60)

    if problems:
        print(f"\nNOTE: could not parse {len(problems)} manifest file(s):")
        for p in problems:
            print(f"  - {p}")

    if not all_findings:
        print("\nNo security findings.")
        return

    for i, f in enumerate(all_findings, 1):
        print()
        print(f"[{i}] [{f.severity.upper()}] {f.title}")
        for detail in f.details:
            print(f"    {detail}")

    print()
    print("=" * 60)
    print("Scan complete.")


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    args = parse_args()

    repo_path = Path(args.repo_path).resolve()
    if not repo_path.exists():
        print(f"ERROR: path does not exist: {repo_path}", file=sys.stderr)
        sys.exit(1)
    if not repo_path.is_dir():
        print(f"ERROR: not a directory: {repo_path}", file=sys.stderr)
        sys.exit(1)
    if not (repo_path / ".git").exists():
        print(f"ERROR: not a git repository (no .git): {repo_path}", file=sys.stderr)
        sys.exit(1)

    gitleaks_bin = resolve_gitleaks(args.gitleaks)

    secrets = scan_secrets(repo_path, gitleaks_bin)
    deps, problems = scan_dependencies(repo_path)

    if args.json:
        payload = {
            "repo_path": str(repo_path),
            "secrets": as_dict(secrets),
            "dependencies": as_dict(deps),
            "problems": problems,
        }
        print(json.dumps(payload, indent=2))
    else:
        print_report(repo_path, secrets, deps, problems)

    # Exit 0 even with findings: this is a report tool, not a CI gate (Stage 1).
    sys.exit(0)


if __name__ == "__main__":
    main()