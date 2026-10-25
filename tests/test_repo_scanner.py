import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import Mock, patch

import repo_scanner


class ValidateRepositoryTests(unittest.TestCase):
    def test_accepts_repository_with_git_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            (repository / ".git").mkdir()

            self.assertEqual(repo_scanner.validate_repository(repository), repository)

    def test_rejects_path_without_git_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "not a Git repository"):
                repo_scanner.validate_repository(Path(directory))

    def test_rejects_missing_path(self):
        path = Path(tempfile.gettempdir()) / "repo-scanner-path-that-does-not-exist"
        with self.assertRaisesRegex(ValueError, "does not exist"):
            repo_scanner.validate_repository(path)


class SecretScannerTests(unittest.TestCase):
    @patch("repo_scanner.subprocess.run")
    def test_parses_gitleaks_report_without_exposing_secret(self, run):
        report = json.dumps(
            [
                {
                    "RuleID": "generic-api-key",
                    "Description": "Generic API Key",
                    "File": "config.py",
                    "StartLine": 12,
                    "Commit": "abc123",
                    "Author": "Example",
                    "Secret": "must-not-appear-in-output",
                }
            ]
        )

        def write_report(command, **_kwargs):
            report_path = Path(command[command.index("--report-path") + 1])
            report_path.write_text(report, encoding="utf-8")
            return Mock(stderr="", returncode=1)

        run.side_effect = write_report

        findings = repo_scanner.scan_secrets(Path("repo"), "gitleaks")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].details["file"], "config.py")
        self.assertEqual(findings[0].details["line"], 12)
        self.assertNotIn("Secret", findings[0].details)
        serialized_report = json.dumps(repo_scanner.report_data(Path("repo"), findings))
        self.assertNotIn("must-not-appear", serialized_report)
        command = run.call_args.args[0]
        report_path = command[command.index("--report-path") + 1]
        self.assertTrue(report_path.endswith("gitleaks-report.json"))
        self.assertNotIn("--report-source", command)

    @patch("repo_scanner.subprocess.run")
    def test_empty_report_has_no_findings(self, run):
        run.return_value.stdout = "[]"
        run.return_value.stderr = ""
        run.return_value.returncode = 0

        self.assertEqual(repo_scanner.scan_secrets(Path("repo"), "gitleaks"), [])

    @patch("repo_scanner.subprocess.run")
    def test_rejects_unexpected_gitleaks_exit_code(self, run):
        run.return_value.stdout = "[]"
        run.return_value.stderr = "scanner failed"
        run.return_value.returncode = 2

        with self.assertRaisesRegex(repo_scanner.ScanError, "scanner failed"):
            repo_scanner.scan_secrets(Path("repo"), "gitleaks")


class DependencyScannerTests(unittest.TestCase):
    def test_requirements_parser_reads_exact_pins_only(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            manifest = repo / "requirements-dev.txt"
            manifest.write_text(
                "# comment\nrequests==2.31.0\nflask>=2.0\n"
                "urllib3[secure]===1.26.18\n",
                encoding="utf-8",
            )

            dependencies = repo_scanner.parse_requirements_txt(manifest, repo)

        self.assertEqual(
            [(item.name, item.version, item.ecosystem) for item in dependencies],
            [
                ("requests", "2.31.0", "PyPI"),
                ("urllib3", "1.26.18", "PyPI"),
            ],
        )

    def test_pyproject_parser_handles_pep_621_and_poetry_pins(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            manifest = repo / "pyproject.toml"
            manifest.write_text(
                '[project]\ndependencies = ["httpx==0.27.2", "fastapi>=0.1"]\n'
                '[tool.poetry.dependencies]\npython = "^3.11"\nclick = "8.1.7"\n',
                encoding="utf-8",
            )

            dependencies = repo_scanner.parse_pyproject_toml(manifest, repo)

        self.assertEqual(
            [(item.name, item.version) for item in dependencies],
            [("httpx", "0.27.2"), ("click", "8.1.7")],
        )

    def test_package_json_parser_skips_version_ranges(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            manifest = repo / "package.json"
            manifest.write_text(
                '{"dependencies":{"lodash":"4.17.21","react":"^18.2.0"}}',
                encoding="utf-8",
            )

            dependencies = repo_scanner.parse_package_json(manifest, repo)

        self.assertEqual(
            [(item.name, item.version, item.ecosystem) for item in dependencies],
            [("lodash", "4.17.21", "npm")],
        )

    def test_pipfile_parser_reads_exact_package_versions(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            manifest = repo / "Pipfile"
            manifest.write_text(
                '[packages]\nrequests = {version = "==2.31.0"}\n'
                'flask = "*"\n',
                encoding="utf-8",
            )

            dependencies = repo_scanner.parse_pipfile(manifest, repo)

        self.assertEqual([(item.name, item.version) for item in dependencies], [("requests", "2.31.0")])

    def test_setup_py_parser_does_not_execute_project_code(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            manifest = repo / "setup.py"
            manifest.write_text(
                'from setuptools import setup\n'
                'setup(name="sample", install_requires=["requests==2.31.0"])\n',
                encoding="utf-8",
            )

            dependencies = repo_scanner.parse_setup_py(manifest, repo)

        self.assertEqual([(item.name, item.version) for item in dependencies], [("requests", "2.31.0")])

    def test_gemfile_parser_reads_exact_gem_versions(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            manifest = repo / "Gemfile"
            manifest.write_text(
                'gem "rack", "2.2.8"\ngem "rails", "~> 7.0"\n',
                encoding="utf-8",
            )

            dependencies = repo_scanner.parse_gemfile(manifest, repo)

        self.assertEqual([(item.name, item.version) for item in dependencies], [("rack", "2.2.8")])

    def test_go_mod_parser_reads_single_and_block_requirements(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            manifest = repo / "go.mod"
            manifest.write_text(
                "module example.com/app\n"
                "require github.com/pkg/errors v0.9.1\n"
                "require (\n  golang.org/x/text v0.3.7 // indirect\n)\n",
                encoding="utf-8",
            )

            dependencies = repo_scanner.parse_go_mod(manifest, repo)

        self.assertEqual(
            [(item.name, item.version) for item in dependencies],
            [
                ("github.com/pkg/errors", "0.9.1"),
                ("golang.org/x/text", "0.3.7"),
            ],
        )

    def test_manifest_discovery_prunes_vendor_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "requirements.txt").write_text("requests==2.31.0", encoding="utf-8")
            nested = repo / "node_modules" / "sample"
            nested.mkdir(parents=True)
            (nested / "package.json").write_text("{}", encoding="utf-8")

            manifests = repo_scanner.find_manifests(repo)

        self.assertEqual(manifests, [repo / "requirements.txt"])

    @patch("repo_scanner.urlopen")
    def test_osv_query_posts_package_and_version(self, open_url):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = b'{"vulns":[{"id":"GHSA-example"}]}'
        open_url.return_value = response
        dependency = repo_scanner.Dependency("requests", "2.31.0", "PyPI", "requirements.txt")

        vulnerabilities = repo_scanner.query_osv(dependency)

        self.assertEqual(vulnerabilities[0]["id"], "GHSA-example")
        request = open_url.call_args.args[0]
        self.assertEqual(
            json.loads(request.data),
            {
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "version": "2.31.0",
            },
        )

    @patch("repo_scanner.query_osv")
    def test_dependency_scan_maps_osv_vulnerabilities(self, query):
        query.return_value = [
            {
                "id": "GHSA-example",
                "summary": "Example vulnerability",
                "aliases": ["CVE-2026-12345"],
                "database_specific": {"severity": "HIGH"},
            }
        ]
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "requirements.txt").write_text("requests==2.31.0", encoding="utf-8")

            findings, issues = repo_scanner.scan_dependencies(repo)

        self.assertEqual(issues, [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].details["aliases"], ["CVE-2026-12345"])
        self.assertEqual(findings[0].details["manifest"], "requirements.txt")

    @patch("repo_scanner.time.sleep")
    @patch("repo_scanner.query_osv", side_effect=[repo_scanner.ScanError("offline"), []])
    def test_dependency_scan_reports_api_errors_and_continues(self, _query, _sleep):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "requirements.txt").write_text(
                "requests==2.31.0\nurllib3==1.26.18\n", encoding="utf-8"
            )

            findings, issues = repo_scanner.scan_dependencies(repo)

        self.assertEqual(findings, [])
        self.assertEqual(len(issues), 1)
        self.assertIn("offline", issues[0])

    @patch("repo_scanner.scan_dependencies")
    @patch("repo_scanner.resolve_gitleaks", return_value=None)
    def test_missing_gitleaks_still_runs_dependency_scan(
        self, _resolve_gitleaks, scan_dependencies
    ):
        scan_dependencies.return_value = ([], [])
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / ".git").mkdir()
            with patch("sys.stdout") as stdout, patch("sys.stderr"):
                result = repo_scanner.main([str(repo), "--json"])

        self.assertEqual(result, 1)
        scan_dependencies.assert_called_once()
        output = "".join(call.args[0] for call in stdout.write.call_args_list)
        self.assertIn("gitleaks was not found", output)

    def test_main_emits_combined_json_report(self):
        secret = repo_scanner.Finding(
            "gitleaks", "high", "Leaked key", {"file": "config.py", "line": 3}
        )
        dependency = repo_scanner.Finding(
            "osv",
            "critical",
            "Vulnerable package",
            {"package": "example", "version": "1.0"},
        )
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / ".git").mkdir()
            with (
                patch("repo_scanner.resolve_gitleaks", return_value="gitleaks"),
                patch("repo_scanner.scan_secrets", return_value=[secret]),
                patch("repo_scanner.scan_dependencies", return_value=([dependency], [])),
                redirect_stdout(StringIO()) as stdout,
                redirect_stderr(StringIO()),
            ):
                result = repo_scanner.main([str(repo), "--json"])

        report = json.loads(stdout.getvalue())
        self.assertEqual(result, 0)
        self.assertEqual(report["summary"]["total"], 2)
        self.assertEqual({item["scanner"] for item in report["findings"]}, {"gitleaks", "osv"})


if __name__ == "__main__":
    unittest.main()
