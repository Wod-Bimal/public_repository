#!/usr/bin/env python3
"""Scan a local Git repository for security findings."""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


GITLEAKS_TIMEOUT_SECONDS = 300
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_TIMEOUT_SECONDS = 15
OSV_REQUEST_DELAY_SECONDS = 0.5
MANIFEST_NAMES = {
    "gemfile",
    "go.mod",
    "package.json",
    "pipfile",
    "pyproject.toml",
    "setup.py",
}
IGNORED_DIRECTORIES = {
    ".git",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "target",
    "venv",
    "vendor",
}


@dataclass(frozen=True)
class Finding:
    scanner: str
    severity: str
    title: str
    details: dict[str, Any]


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    ecosystem: str
    manifest: str


class ScanError(RuntimeError):
    """Raised when a scanner cannot complete successfully."""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan a local Git repository for leaked secrets."
    )
    parser.add_argument("repo", type=Path, help="path to the local Git repository")
    parser.add_argument(
        "--gitleaks-path",
        help="path to the gitleaks executable (also configurable with GITLEAKS_PATH)",
    )
    parser.add_argument(
        "--json", action="store_true", help="print machine-readable JSON"
    )
    return parser.parse_args(argv)


def validate_repository(repo_path: Path) -> Path:
    try:
        resolved_path = repo_path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"repository path does not exist: {repo_path}") from exc

    if not resolved_path.is_dir():
        raise ValueError(f"repository path is not a directory: {resolved_path}")
    if not (resolved_path / ".git").exists():
        raise ValueError(f"path is not a Git repository (missing .git): {resolved_path}")
    return resolved_path


def resolve_gitleaks(explicit_path: str | None) -> str | None:
    candidate = explicit_path or os.environ.get("GITLEAKS_PATH")
    if candidate:
        candidate_path = Path(candidate).expanduser()
        if candidate_path.is_file():
            return str(candidate_path.resolve())
        return shutil.which(candidate)
    return shutil.which("gitleaks")


def scan_secrets(repo_path: Path, gitleaks_binary: str) -> list[Finding]:
    try:
        with tempfile.TemporaryDirectory(prefix="repo-scanner-") as temp_dir:
            report_path = Path(temp_dir) / "gitleaks-report.json"
            result = subprocess.run(
                [
                    gitleaks_binary,
                    "detect",
                    "--source",
                    str(repo_path),
                    "--report-format",
                    "json",
                    "--report-path",
                    str(report_path),
                    "--no-banner",
                ],
                capture_output=True,
                text=True,
                timeout=GITLEAKS_TIMEOUT_SECONDS,
                check=False,
            )
            report = (
                report_path.read_text(encoding="utf-8") if report_path.exists() else ""
            )
    except subprocess.TimeoutExpired as exc:
        raise ScanError(
            f"gitleaks exceeded the {GITLEAKS_TIMEOUT_SECONDS}-second timeout"
        ) from exc
    except OSError as exc:
        raise ScanError(f"could not run gitleaks: {exc}") from exc

    try:
        results = json.loads(report or "[]")
    except json.JSONDecodeError as exc:
        message = result.stderr.strip() or "gitleaks returned invalid JSON"
        raise ScanError(message) from exc

    if not isinstance(results, list):
        raise ScanError("gitleaks returned an unexpected report format")
    if result.returncode not in (0, 1):
        message = result.stderr.strip() or f"gitleaks exited with code {result.returncode}"
        raise ScanError(message)

    findings: list[Finding] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        rule = item.get("RuleID")
        title = item.get("Description") or rule or "Secret detected"
        details = {
            key: item[source_key]
            for key, source_key in (
                ("file", "File"),
                ("line", "StartLine"),
                ("rule", "RuleID"),
                ("commit", "Commit"),
                ("author", "Author"),
            )
            if item.get(source_key) not in (None, "")
        }
        findings.append(
            Finding(
                scanner="gitleaks",
                severity="high",
                title=str(title),
                details=details,
            )
        )
    return findings


def find_manifests(repo_path: Path) -> list[Path]:
    manifests: list[Path] = []
    for root, directories, filenames in os.walk(repo_path):
        directories[:] = sorted(
            name for name in directories if name not in IGNORED_DIRECTORIES
        )
        for filename in filenames:
            lowered = filename.lower()
            if lowered.startswith("requirements") and lowered.endswith(".txt"):
                manifests.append(Path(root) / filename)
            elif filename in MANIFEST_NAMES:
                manifests.append(Path(root) / filename)
    return sorted(manifests)


def _dependency(
    name: str, version: str, ecosystem: str, manifest: Path, repo_path: Path
) -> Dependency | None:
    clean_name = name.strip()
    clean_version = version.strip()
    if not clean_name or not clean_version or clean_version in {"*", "latest"}:
        return None
    return Dependency(
        name=clean_name,
        version=clean_version[1:] if clean_version[:1].lower() == "v" else clean_version,
        ecosystem=ecosystem,
        manifest=manifest.relative_to(repo_path).as_posix(),
    )


def _pinned_specification(specification: str) -> tuple[str, str] | None:
    match = re.match(
        r"^\s*([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*(?:===|==)\s*"
        r"([A-Za-z0-9_.+-]+)",
        specification,
    )
    return (match.group(1), match.group(2)) if match else None


def parse_requirements_txt(path: Path, repo_path: Path) -> list[Dependency]:
    dependencies: list[Dependency] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-")):
            continue
        pinned = _pinned_specification(stripped)
        if pinned:
            item = _dependency(*pinned, "PyPI", path, repo_path)
            if item:
                dependencies.append(item)
    return dependencies


def _python_requirement(
    requirement: str, manifest: Path, repo_path: Path
) -> Dependency | None:
    pinned = _pinned_specification(requirement)
    return _dependency(*pinned, "PyPI", manifest, repo_path) if pinned else None


def _poetry_dependency(
    name: str, value: Any, manifest: Path, repo_path: Path
) -> Dependency | None:
    version = value.get("version") if isinstance(value, dict) else value
    if not isinstance(version, str) or not re.fullmatch(
        r"v?\d+(?:\.\d+)*(?:[-+][A-Za-z0-9.-]+)?", version
    ):
        return None
    return _dependency(name, version, "PyPI", manifest, repo_path)


def parse_pyproject_toml(path: Path, repo_path: Path) -> list[Dependency]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    project = data.get("project", {})
    dependencies = [
        item
        for requirement in project.get("dependencies", [])
        if isinstance(requirement, str)
        if (item := _python_requirement(requirement, path, repo_path))
    ]
    for optional in project.get("optional-dependencies", {}).values():
        if isinstance(optional, list):
            dependencies.extend(
                item
                for requirement in optional
                if isinstance(requirement, str)
                if (item := _python_requirement(requirement, path, repo_path))
            )

    poetry = data.get("tool", {}).get("poetry", {})
    poetry_packages = dict(poetry.get("dependencies", {}))
    poetry_packages.update(poetry.get("dev-dependencies", {}))
    dependencies.extend(
        item
        for name, version in poetry_packages.items()
        if name.lower() != "python"
        if (item := _poetry_dependency(name, version, path, repo_path))
    )
    return dependencies


def parse_setup_py(path: Path, repo_path: Path) -> list[Dependency]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    dependencies: list[Dependency] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        is_setup_call = (
            isinstance(node.func, ast.Name) and node.func.id == "setup"
        ) or (isinstance(node.func, ast.Attribute) and node.func.attr == "setup")
        if not is_setup_call:
            continue
        for keyword in node.keywords:
            if keyword.arg != "install_requires":
                continue
            try:
                requirements = ast.literal_eval(keyword.value)
            except (ValueError, TypeError):
                continue
            if isinstance(requirements, list):
                dependencies.extend(
                    item
                    for requirement in requirements
                    if isinstance(requirement, str)
                    if (item := _python_requirement(requirement, path, repo_path))
                )
    return dependencies


def parse_pipfile(path: Path, repo_path: Path) -> list[Dependency]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    dependencies: list[Dependency] = []
    for section in ("packages", "dev-packages"):
        for name, value in data.get(section, {}).items():
            version = value.get("version") if isinstance(value, dict) else value
            if isinstance(version, str):
                version = re.sub(r"^==\s*", "", version)
            item = _poetry_dependency(name, version, path, repo_path)
            if item:
                dependencies.append(item)
    return dependencies


def parse_package_json(path: Path, repo_path: Path) -> list[Dependency]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("package.json root must be an object")
    dependencies: list[Dependency] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        section_dependencies = data.get(section, {})
        if not isinstance(section_dependencies, dict):
            continue
        for name, version in section_dependencies.items():
            if not isinstance(version, str) or not re.fullmatch(
                r"v?\d+(?:\.\d+)*(?:[-+][A-Za-z0-9.-]+)?", version
            ):
                continue
            item = _dependency(name, version, "npm", path, repo_path)
            if item:
                dependencies.append(item)
    return dependencies


def parse_go_mod(path: Path, repo_path: Path) -> list[Dependency]:
    dependencies: list[Dependency] = []
    in_require_block = False
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("require ("):
            in_require_block = True
            continue
        if in_require_block and line == ")":
            in_require_block = False
            continue
        parts = line.split()
        if parts[0] == "require" and len(parts) == 3:
            parts = parts[1:]
        if len(parts) == 2 and (in_require_block or line.startswith("require ")):
            item = _dependency(parts[0], parts[1], "Go", path, repo_path)
            if item:
                dependencies.append(item)
    return dependencies


def parse_gemfile(path: Path, repo_path: Path) -> list[Dependency]:
    dependencies: list[Dependency] = []
    pattern = re.compile(
        r"""^\s*gem\s+["']([^"']+)["']\s*,\s*["']=?([0-9][^"']*)["']"""
    )
    for line in path.read_text(encoding="utf-8").splitlines():
        match = pattern.match(line)
        if match:
            item = _dependency(match.group(1), match.group(2), "RubyGems", path, repo_path)
            if item:
                dependencies.append(item)
    return dependencies


def parse_manifest(path: Path, repo_path: Path) -> list[Dependency]:
    filename = path.name.lower()
    if filename.startswith("requirements") and filename.endswith(".txt"):
        return parse_requirements_txt(path, repo_path)
    parsers = {
        "gemfile": parse_gemfile,
        "go.mod": parse_go_mod,
        "package.json": parse_package_json,
        "pipfile": parse_pipfile,
        "pyproject.toml": parse_pyproject_toml,
        "setup.py": parse_setup_py,
    }
    parser = parsers.get(filename)
    return parser(path, repo_path) if parser else []


def collect_dependencies(repo_path: Path) -> tuple[list[Dependency], list[str]]:
    dependencies: list[Dependency] = []
    issues: list[str] = []
    for manifest in find_manifests(repo_path):
        try:
            dependencies.extend(parse_manifest(manifest, repo_path))
        except (OSError, SyntaxError, ValueError, TypeError, AttributeError) as exc:
            relative_path = manifest.relative_to(repo_path)
            issues.append(f"could not parse {relative_path}: {exc}")

    unique_dependencies = {
        (item.ecosystem, item.name.lower(), item.version): item
        for item in dependencies
    }
    return list(unique_dependencies.values()), issues


def query_osv(dependency: Dependency) -> list[dict[str, Any]]:
    payload = {
        "package": {"name": dependency.name, "ecosystem": dependency.ecosystem},
        "version": dependency.version,
    }
    request = Request(
        OSV_QUERY_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=OSV_TIMEOUT_SECONDS) as response:
            result = json.loads(response.read())
    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        raise ScanError(f"OSV query failed for {dependency.name}@{dependency.version}: {exc}") from exc

    if not isinstance(result, dict) or not isinstance(result.get("vulns", []), list):
        raise ScanError(f"OSV returned an unexpected response for {dependency.name}")
    return result.get("vulns", [])


def _vulnerability_severity(vulnerability: dict[str, Any]) -> str:
    for section_name in ("database_specific", "ecosystem_specific"):
        section = vulnerability.get(section_name)
        if isinstance(section, dict):
            severity = section.get("severity")
            if isinstance(severity, str) and severity.lower() in {
                "critical",
                "high",
                "medium",
                "low",
            }:
                return severity.lower()
    return "medium"


def scan_dependencies(repo_path: Path) -> tuple[list[Finding], list[str]]:
    dependencies, issues = collect_dependencies(repo_path)
    findings: list[Finding] = []
    for index, dependency in enumerate(dependencies):
        if index:
            time.sleep(OSV_REQUEST_DELAY_SECONDS)
        try:
            vulnerabilities = query_osv(dependency)
        except ScanError as exc:
            issues.append(str(exc))
            continue

        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue
            vulnerability_id = vulnerability.get("id", "Unknown vulnerability")
            aliases = vulnerability.get("aliases", [])
            details = {
                "package": dependency.name,
                "version": dependency.version,
                "ecosystem": dependency.ecosystem,
                "manifest": dependency.manifest,
                "vulnerability_id": vulnerability_id,
                "aliases": aliases if isinstance(aliases, list) else [],
                "url": f"https://osv.dev/vulnerability/{vulnerability_id}",
            }
            summary = vulnerability.get("summary")
            findings.append(
                Finding(
                    scanner="osv",
                    severity=_vulnerability_severity(vulnerability),
                    title=str(summary or vulnerability_id),
                    details=details,
                )
            )
    return findings, issues


def report_data(
    repo_path: Path, findings: list[Finding], issues: list[str] | None = None
) -> dict[str, Any]:
    return {
        "repository": str(repo_path),
        "findings": [asdict(finding) for finding in findings],
        "issues": issues or [],
        "summary": {
            "total": len(findings),
            "by_severity": {
                severity: sum(item.severity == severity for item in findings)
                for severity in ("critical", "high", "medium", "low")
            },
        },
    }


def print_report(
    repo_path: Path,
    findings: list[Finding],
    as_json: bool,
    issues: list[str] | None = None,
) -> None:
    data = report_data(repo_path, findings, issues)
    if as_json:
        print(json.dumps(data, indent=2))
        return

    print(f"Repository: {repo_path}")
    print(f"Findings: {data['summary']['total']}")
    if issues:
        for issue in issues:
            print(f"Warning: {issue}", file=sys.stderr)
    if not findings:
        print("No findings found.")
        return

    for scanner, heading in (("gitleaks", "SECRETS"), ("osv", "DEPENDENCIES")):
        scanner_findings = [item for item in findings if item.scanner == scanner]
        if not scanner_findings:
            continue
        print(f"\n{heading}")
        for finding in scanner_findings:
            details = finding.details
            print(f"[{finding.severity.upper()}] {finding.title}")
            if scanner == "gitleaks":
                location = details.get("file", "unknown file")
                if details.get("line") is not None:
                    location += f":{details['line']}"
                print(f"  Location: {location}")
                if details.get("commit"):
                    print(f"  Commit: {details['commit']}")
                if details.get("author"):
                    print(f"  Author: {details['author']}")
            else:
                print(
                    f"  Package: {details['package']}@{details['version']} "
                    f"({details['ecosystem']})"
                )
                print(f"  Manifest: {details['manifest']}")
                print(f"  Advisory: {details['url']}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        repo_path = validate_repository(args.repo)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    gitleaks_binary = resolve_gitleaks(args.gitleaks_path)
    findings: list[Finding] = []
    issues: list[str] = []
    if gitleaks_binary is None:
        issues.append("gitleaks was not found; secret scan was skipped")
    else:
        try:
            findings.extend(scan_secrets(repo_path, gitleaks_binary))
        except ScanError as exc:
            issues.append(f"secret scan failed: {exc}")
    try:
        dependency_findings, dependency_issues = scan_dependencies(repo_path)
        findings.extend(dependency_findings)
        issues.extend(dependency_issues)
    except ScanError as exc:
        issues.append(f"dependency scan failed: {exc}")
    print_report(repo_path, findings, args.json, issues)
    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
