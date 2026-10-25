#!/usr/bin/env python3
"""Scan a local Git repository for security findings."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


GITLEAKS_TIMEOUT_SECONDS = 300


@dataclass(frozen=True)
class Finding:
    scanner: str
    severity: str
    title: str
    details: dict[str, Any]


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
        result = subprocess.run(
            [
                gitleaks_binary,
                "detect",
                "--source",
                str(repo_path),
                "--report-format",
                "json",
                "--report-source",
                "stdout",
                "--no-banner",
            ],
            capture_output=True,
            text=True,
            timeout=GITLEAKS_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScanError(
            f"gitleaks exceeded the {GITLEAKS_TIMEOUT_SECONDS}-second timeout"
        ) from exc
    except OSError as exc:
        raise ScanError(f"could not run gitleaks: {exc}") from exc

    try:
        results = json.loads(result.stdout or "[]")
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


def report_data(repo_path: Path, findings: list[Finding]) -> dict[str, Any]:
    return {
        "repository": str(repo_path),
        "findings": [asdict(finding) for finding in findings],
        "summary": {
            "total": len(findings),
            "by_severity": {
                severity: sum(item.severity == severity for item in findings)
                for severity in ("critical", "high", "medium", "low")
            },
        },
    }


def print_report(repo_path: Path, findings: list[Finding], as_json: bool) -> None:
    data = report_data(repo_path, findings)
    if as_json:
        print(json.dumps(data, indent=2))
        return

    print(f"Repository: {repo_path}")
    print(f"Findings: {data['summary']['total']}")
    if not findings:
        print("No leaked secrets found.")
        return

    print("\nSECRETS")
    for finding in findings:
        details = finding.details
        location = details.get("file", "unknown file")
        if details.get("line") is not None:
            location += f":{details['line']}"
        print(f"[{finding.severity.upper()}] {finding.title}")
        print(f"  Location: {location}")
        if details.get("commit"):
            print(f"  Commit: {details['commit']}")
        if details.get("author"):
            print(f"  Author: {details['author']}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        repo_path = validate_repository(args.repo)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    gitleaks_binary = resolve_gitleaks(args.gitleaks_path)
    if gitleaks_binary is None:
        print(
            "Error: gitleaks was not found. Install it or set GITLEAKS_PATH.",
            file=sys.stderr,
        )
        return 1

    try:
        findings = scan_secrets(repo_path, gitleaks_binary)
    except ScanError as exc:
        print(f"Error: secret scan failed: {exc}", file=sys.stderr)
        return 1
    print_report(repo_path, findings, args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
