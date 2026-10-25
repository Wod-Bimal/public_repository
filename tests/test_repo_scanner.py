import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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
        run.return_value.stdout = json.dumps(
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
        run.return_value.stderr = ""
        run.return_value.returncode = 1

        findings = repo_scanner.scan_secrets(Path("repo"), "gitleaks")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].details["file"], "config.py")
        self.assertEqual(findings[0].details["line"], 12)
        self.assertNotIn("Secret", findings[0].details)
        self.assertNotIn("must-not-appear", json.dumps(repo_scanner.report_data(Path("repo"), findings)))

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


if __name__ == "__main__":
    unittest.main()
