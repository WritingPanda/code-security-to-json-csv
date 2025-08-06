#!/usr/bin/env python3
"""
Test suite for the GitHub Security Alerts CLI tool.
Tests all functions and CLI options.
"""

import unittest
import json
import csv
import os
import tempfile
import shutil
import time
from unittest.mock import patch, Mock, MagicMock
from click.testing import CliRunner
import main


class TestGitHubAlertsAPI(unittest.TestCase):
    """Test suite for GitHub Security Alerts CLI tool."""

    def setUp(self) -> None:
        """Set up test fixtures before each test method."""
        self.runner = CliRunner()
        self.test_dir = tempfile.mkdtemp()
        self.sample_alerts: list[dict[str, object]] = [
            {
                "number": 1,
                "state": "open",
                "severity": "critical",
                "rule": {"id": "test-rule-1", "description": "Test rule 1"},
                "tool": {"name": "CodeQL"},
                "created_at": "2023-01-01T00:00:00Z",
                "repository": {"name": "test-repo", "full_name": "org/test-repo"},
            },
            {
                "number": 2,
                "state": "dismissed",
                "severity": "high",
                "rule": {"id": "test-rule-2", "description": "Test rule 2"},
                "tool": {"name": "CodeQL"},
                "created_at": "2023-01-02T00:00:00Z",
                "repository": {"name": "test-repo-2", "full_name": "org/test-repo-2"},
            },
        ]

    def tearDown(self) -> None:
        """Clean up after each test method."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_write_to_json(self) -> None:
        """Test JSON output functionality."""
        test_file = os.path.join(self.test_dir, "test.json")

        main.write_to_json(self.sample_alerts, test_file)

        # Verify file was created
        self.assertTrue(os.path.exists(test_file))

        # Verify content
        with open(test_file, "r") as f:
            data = json.load(f)

        self.assertEqual(len(data), 2)
        self.assertEqual(data[0]["number"], 1)
        self.assertEqual(data[1]["severity"], "high")

    def test_write_to_json_empty_data(self) -> None:
        """Test JSON output with empty data."""
        test_file = os.path.join(self.test_dir, "empty.json")

        main.write_to_json([], test_file)

        # Verify file was created
        self.assertTrue(os.path.exists(test_file))

        # Verify content is empty array
        with open(test_file, "r") as f:
            data = json.load(f)

        self.assertEqual(data, [])

    def test_write_to_csv(self) -> None:
        """Test CSV output functionality."""
        test_file = os.path.join(self.test_dir, "test.csv")

        main.write_to_csv(self.sample_alerts, test_file)

        # Verify file was created
        self.assertTrue(os.path.exists(test_file))

        # Verify content
        with open(test_file, "r", newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["number"], "1")
        self.assertEqual(rows[1]["severity"], "high")

        # Verify nested objects are JSON-encoded
        self.assertIn("rule", rows[0])
        rule_data = json.loads(rows[0]["rule"])
        self.assertEqual(rule_data["id"], "test-rule-1")

    def test_write_to_csv_empty_data(self) -> None:
        """Test CSV output with empty data."""
        test_file = os.path.join(self.test_dir, "empty.csv")

        with patch("click.echo") as mock_echo:
            main.write_to_csv([], test_file)
            mock_echo.assert_called_with("No data to write to CSV")

        # Verify file was not created
        self.assertFalse(os.path.exists(test_file))

    @patch("requests.get")
    def test_get_security_alerts_paginated_success(self, mock_get: MagicMock) -> None:
        """Test successful alert fetching with pagination."""
        # Mock responses for pagination
        mock_response_1 = Mock()
        mock_response_1.status_code = 200
        mock_response_1.json.return_value = [self.sample_alerts[0]]

        mock_response_2 = Mock()
        mock_response_2.status_code = 200
        mock_response_2.json.return_value = [self.sample_alerts[1]]

        mock_response_3 = Mock()
        mock_response_3.status_code = 200
        mock_response_3.json.return_value = []  # Empty response to end pagination

        mock_get.side_effect = [mock_response_1, mock_response_2, mock_response_3]

        # Set up token
        main.github_token = "test_token"

        with patch("click.echo"):
            alerts = main.get_security_alerts_paginated("test-org", "open", "critical")

        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts[0]["number"], 1)
        self.assertEqual(alerts[1]["number"], 2)

        # Verify API calls
        self.assertEqual(mock_get.call_count, 3)

        # Check first call parameters
        first_call = mock_get.call_args_list[0]
        # First argument is the URL, second argument contains kwargs like headers and params
        first_call_url = first_call[0][0]  # positional args
        first_call_kwargs = first_call[1]  # keyword args

        self.assertIn("api.github.com", first_call_url)  # Default GitHub.com URL
        self.assertIn("test-org", first_call_url)
        self.assertEqual(first_call_kwargs["params"]["state"], "open")
        self.assertEqual(first_call_kwargs["params"]["severity"], "critical")
        self.assertEqual(first_call_kwargs["params"]["tool_name"], "CodeQL")

    @patch("requests.get")
    def test_get_security_alerts_paginated_enterprise_url(
        self, mock_get: MagicMock
    ) -> None:
        """Test alert fetching with enterprise URL."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = []
        mock_get.return_value = mock_response

        main.github_token = "test_token"

        with patch("click.echo"):
            main.get_security_alerts_paginated(
                "test-org", "open", None, "https://github.example.com"
            )

        # Check that enterprise URL is used correctly
        first_call = mock_get.call_args_list[0]
        first_call_url = first_call[0][0]
        self.assertIn("github.example.com/api/v3", first_call_url)
        self.assertNotIn("api.github.com", first_call_url)

    @patch("requests.get")
    def test_get_security_alerts_paginated_no_severity_filter(
        self, mock_get: MagicMock
    ) -> None:
        """Test alert fetching without severity filter."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = []
        mock_get.return_value = mock_response

        main.github_token = "test_token"

        with patch("click.echo"):
            main.get_security_alerts_paginated("test-org", "closed", None)

        # Verify severity parameter is not included when None
        call_params = mock_get.call_args[1]["params"]
        self.assertNotIn("severity", call_params)
        self.assertEqual(call_params["state"], "closed")

    @patch("requests.get")
    def test_get_security_alerts_paginated_error_handling(
        self, mock_get: MagicMock
    ) -> None:
        """Test error handling in alert fetching."""
        main.github_token = "test_token"

        # Test 403 error
        mock_response = Mock()
        mock_response.status_code = 403
        mock_get.return_value = mock_response

        with patch("click.echo") as mock_echo:
            alerts = main.get_security_alerts_paginated("test-org")
            mock_echo.assert_any_call(
                "Error: Access forbidden. Check your token permissions.", err=True
            )

        self.assertEqual(alerts, [])

        # Test 404 error
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        with patch("click.echo") as mock_echo:
            alerts = main.get_security_alerts_paginated("test-org")
            mock_echo.assert_any_call(
                "Error: Organization 'test-org' not found or not accessible.", err=True
            )

        # Test other error
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_get.return_value = mock_response

        with patch("click.echo") as mock_echo:
            alerts = main.get_security_alerts_paginated("test-org")
            mock_echo.assert_any_call(
                "Error fetching security alerts: 500 - Internal Server Error", err=True
            )

    def test_get_security_alerts_paginated_no_token(self) -> None:
        """Test alert fetching without token."""
        main.github_token = None

        with patch("click.echo") as mock_echo:
            alerts = main.get_security_alerts_paginated("test-org")
            mock_echo.assert_called_with(
                "GitHub token is not set. Please set the GITHUB_TOKEN environment variable.",
                err=True,
            )

        self.assertEqual(alerts, [])

    def test_cli_help(self) -> None:
        """Test CLI help command."""
        result = self.runner.invoke(main.main, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Fetch GitHub security alerts", result.output)
        self.assertIn("--format", result.output)
        self.assertIn("--state", result.output)
        self.assertIn("--severity", result.output)
        self.assertIn("--token", result.output)
        self.assertIn("--output", result.output)
        self.assertIn("--enterprise-url", result.output)

    def test_cli_missing_token(self) -> None:
        """Test CLI without token."""
        with patch.dict(os.environ, {}, clear=True):
            result = self.runner.invoke(main.main, ["test-org"])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("GitHub token is required", result.output)

    @patch("main.get_security_alerts_paginated")
    @patch("main.write_to_json")
    def test_cli_json_output(
        self, mock_write_json: MagicMock, mock_get_alerts: MagicMock
    ) -> None:
        """Test CLI JSON output."""
        mock_get_alerts.return_value = self.sample_alerts

        with tempfile.TemporaryDirectory() as temp_dir:
            os.chdir(temp_dir)
            result = self.runner.invoke(
                main.main,
                [
                    "test-org",
                    "--token",
                    "test_token",
                    "--format",
                    "json",
                    "--output",
                    "test-output.json",
                ],
            )

        self.assertEqual(result.exit_code, 0)
        mock_get_alerts.assert_called_once_with("test-org", "open", None, None)
        mock_write_json.assert_called_once_with(self.sample_alerts, "test-output.json")

    @patch("main.get_security_alerts_paginated")
    @patch("main.write_to_csv")
    def test_cli_csv_output(
        self, mock_write_csv: MagicMock, mock_get_alerts: MagicMock
    ) -> None:
        """Test CLI CSV output."""
        mock_get_alerts.return_value = self.sample_alerts

        with tempfile.TemporaryDirectory() as temp_dir:
            os.chdir(temp_dir)
            result = self.runner.invoke(
                main.main,
                [
                    "test-org",
                    "--token",
                    "test_token",
                    "--format",
                    "csv",
                    "--state",
                    "closed",
                    "--severity",
                    "high",
                ],
            )

        self.assertEqual(result.exit_code, 0)
        mock_get_alerts.assert_called_once_with("test-org", "closed", "high", None)
        mock_write_csv.assert_called_once_with(
            self.sample_alerts, "test-org-alerts.csv"
        )

    @patch("main.get_security_alerts_paginated")
    def test_cli_no_alerts_found(self, mock_get_alerts: MagicMock) -> None:
        """Test CLI when no alerts are found."""
        mock_get_alerts.return_value = []

        result = self.runner.invoke(main.main, ["test-org", "--token", "test_token"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("No alerts found or error occurred", result.output)

    @patch("main.get_security_alerts_paginated")
    @patch("main.write_to_json")
    def test_cli_all_state_options(
        self, mock_write_json: MagicMock, mock_get_alerts: MagicMock
    ) -> None:
        """Test CLI with all state filter options."""
        mock_get_alerts.return_value = self.sample_alerts

        states = ["open", "closed", "dismissed", "fixed"]

        for state in states:
            with tempfile.TemporaryDirectory() as temp_dir:
                os.chdir(temp_dir)
                result = self.runner.invoke(
                    main.main, ["test-org", "--token", "test_token", "--state", state]
                )

                self.assertEqual(result.exit_code, 0)
                self.assertIn(f"state={state}", result.output)

    @patch("main.get_security_alerts_paginated")
    @patch("main.write_to_json")
    def test_cli_all_severity_options(
        self, mock_write_json: MagicMock, mock_get_alerts: MagicMock
    ) -> None:
        """Test CLI with all severity filter options."""
        mock_get_alerts.return_value = self.sample_alerts

        severities = ["critical", "high", "medium", "low", "warning", "note", "error"]

        for severity in severities:
            with tempfile.TemporaryDirectory() as temp_dir:
                os.chdir(temp_dir)
                result = self.runner.invoke(
                    main.main,
                    ["test-org", "--token", "test_token", "--severity", severity],
                )

                self.assertEqual(result.exit_code, 0)
                self.assertIn(f"severity={severity}", result.output)

    @patch("main.get_security_alerts_paginated")
    @patch("main.write_to_json")
    def test_cli_default_filename_generation(
        self, mock_write_json: MagicMock, mock_get_alerts: MagicMock
    ) -> None:
        """Test CLI default filename generation."""
        mock_get_alerts.return_value = self.sample_alerts

        with tempfile.TemporaryDirectory() as temp_dir:
            os.chdir(temp_dir)

            # Test JSON default
            result = self.runner.invoke(
                main.main, ["my-test-org", "--token", "test_token"]
            )

            self.assertEqual(result.exit_code, 0)
            mock_write_json.assert_called_with(
                self.sample_alerts, "my-test-org-alerts.json"
            )

    @patch("main.get_security_alerts_paginated")
    @patch("main.write_to_csv")
    def test_cli_csv_default_filename(
        self, mock_write_csv: MagicMock, mock_get_alerts: MagicMock
    ) -> None:
        """Test CLI CSV default filename generation."""
        mock_get_alerts.return_value = self.sample_alerts

        with tempfile.TemporaryDirectory() as temp_dir:
            os.chdir(temp_dir)

            # Test CSV default
            result = self.runner.invoke(
                main.main, ["another-org", "--token", "test_token", "--format", "csv"]
            )

            self.assertEqual(result.exit_code, 0)
            mock_write_csv.assert_called_with(
                self.sample_alerts, "another-org-alerts.csv"
            )

    @patch.dict(os.environ, {"GITHUB_TOKEN": "env_token"})
    @patch("main.get_security_alerts_paginated")
    @patch("main.write_to_json")
    def test_cli_token_priority(
        self, mock_write_json: MagicMock, mock_get_alerts: MagicMock
    ) -> None:
        """Test token priority: CLI argument > environment variable."""
        mock_get_alerts.return_value = self.sample_alerts

        with tempfile.TemporaryDirectory() as temp_dir:
            os.chdir(temp_dir)

            # Test CLI token takes priority
            result = self.runner.invoke(main.main, ["test-org", "--token", "cli_token"])

            self.assertEqual(result.exit_code, 0)
            # Check that the global token was set to CLI token
            self.assertEqual(main.github_token, "cli_token")

    @patch.dict(os.environ, {"GITHUB_TOKEN": "env_token"})
    @patch("main.get_security_alerts_paginated")
    @patch("main.write_to_json")
    def test_cli_environment_token(
        self, mock_write_json: MagicMock, mock_get_alerts: MagicMock
    ) -> None:
        """Test using environment variable token."""
        mock_get_alerts.return_value = self.sample_alerts

        with tempfile.TemporaryDirectory() as temp_dir:
            os.chdir(temp_dir)

            # Test environment token is used when no CLI token provided
            result = self.runner.invoke(main.main, ["test-org"])

            self.assertEqual(result.exit_code, 0)
            # Check that the global token was set to environment token
            self.assertEqual(main.github_token, "env_token")

    @patch("main.get_security_alerts_paginated")
    @patch("main.write_to_json")
    def test_cli_enterprise_url(
        self, mock_write_json: MagicMock, mock_get_alerts: MagicMock
    ) -> None:
        """Test CLI with enterprise URL."""
        mock_get_alerts.return_value = self.sample_alerts

        with tempfile.TemporaryDirectory() as temp_dir:
            os.chdir(temp_dir)

            result = self.runner.invoke(
                main.main,
                [
                    "test-org",
                    "--token",
                    "test_token",
                    "--enterprise-url",
                    "https://github.company.com",
                ],
            )

            self.assertEqual(result.exit_code, 0)
            self.assertIn(
                "Using GitHub Enterprise Server: https://github.company.com",
                result.output,
            )
            mock_get_alerts.assert_called_once_with(
                "test-org", "open", None, "https://github.company.com"
            )

    def test_cli_invalid_options(self) -> None:
        """Test CLI with invalid option values."""
        # Test invalid format
        result = self.runner.invoke(
            main.main, ["test-org", "--token", "test_token", "--format", "xml"]
        )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Invalid value for '--format'", result.output)

        # Test invalid state
        result = self.runner.invoke(
            main.main, ["test-org", "--token", "test_token", "--state", "invalid"]
        )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Invalid value for '--state'", result.output)

        # Test invalid severity
        result = self.runner.invoke(
            main.main, ["test-org", "--token", "test_token", "--severity", "invalid"]
        )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Invalid value for '--severity'", result.output)

    def test_check_rate_limit_normal(self):
        """Test check_rate_limit with normal remaining requests."""
        mock_response = MagicMock()
        mock_response.headers = {
            "X-RateLimit-Remaining": "4500",
            "X-RateLimit-Reset": "1640995200",
        }

        with patch("time.sleep") as mock_sleep:
            main.check_rate_limit(mock_response)
            # Always sleeps 0.1 seconds between requests
            mock_sleep.assert_called_once_with(0.1)

    def test_check_rate_limit_low_remaining(self):
        """Test check_rate_limit with low remaining requests."""
        mock_response = MagicMock()
        mock_response.headers = {
            "X-RateLimit-Remaining": "5",
            "X-RateLimit-Reset": str(int(time.time()) + 300),  # 5 minutes from now
        }

        with (
            patch("time.sleep") as mock_sleep,
            patch("click.echo") as mock_echo,
            patch("time.time", return_value=1640995200),
        ):
            main.check_rate_limit(mock_response)
            # Should sleep for the calculated time + 0.1 for the regular delay
            self.assertEqual(mock_sleep.call_count, 2)
            mock_echo.assert_called_once()
            self.assertIn("Rate limit nearly exhausted", mock_echo.call_args[0][0])

    def test_check_rate_limit_very_low_remaining(self):
        """Test check_rate_limit with very low remaining requests."""
        mock_response = MagicMock()
        mock_response.headers = {
            "X-RateLimit-Remaining": "2",
            "X-RateLimit-Reset": str(int(time.time()) + 60),  # 1 minute from now
        }

        with (
            patch("time.sleep") as mock_sleep,
            patch("click.echo") as mock_echo,
            patch("time.time", return_value=1640995200),
        ):
            main.check_rate_limit(mock_response)
            # Should sleep for the calculated time + 0.1 for the regular delay
            self.assertEqual(mock_sleep.call_count, 2)
            mock_echo.assert_called_once()
            self.assertIn("Rate limit nearly exhausted", mock_echo.call_args[0][0])

    def test_check_rate_limit_missing_headers(self):
        """Test check_rate_limit with missing rate limit headers."""
        mock_response = MagicMock()
        mock_response.headers = {}

        with patch("time.sleep") as mock_sleep:
            main.check_rate_limit(mock_response)
            # Always sleeps 0.1 seconds between requests
            mock_sleep.assert_called_once_with(0.1)

    def test_handle_rate_limit_response_success(self):
        """Test handle_rate_limit_response with successful handling."""
        mock_response = MagicMock()
        mock_response.headers = {"Retry-After": "60", "X-RateLimit-Reset": "1640995200"}

        with patch("time.sleep") as mock_sleep, patch("click.echo") as mock_echo:
            result = main.handle_rate_limit_response(mock_response)
            self.assertTrue(result)
            mock_sleep.assert_called_once_with(60)
            mock_echo.assert_called()
            self.assertIn("Rate limit exceeded", mock_echo.call_args[0][0])

    def test_handle_rate_limit_response_no_retry_after(self):
        """Test handle_rate_limit_response without Retry-After header."""
        mock_response = MagicMock()
        mock_response.headers = {"X-RateLimit-Reset": "1640995200"}

        with (
            patch("time.sleep") as mock_sleep,
            patch("click.echo") as mock_echo,
            patch("time.time", return_value=1640995140),
        ):  # 60 seconds before reset
            result = main.handle_rate_limit_response(mock_response)
            self.assertTrue(result)
            mock_sleep.assert_called_once_with(60)
            mock_echo.assert_called()

    def test_handle_rate_limit_response_no_headers(self):
        """Test handle_rate_limit_response without rate limit headers."""
        mock_response = MagicMock()
        mock_response.headers = {}

        with patch("time.sleep") as mock_sleep, patch("click.echo") as mock_echo:
            result = main.handle_rate_limit_response(mock_response)
            self.assertTrue(result)
            mock_sleep.assert_called_once_with(60)  # Default wait time
            mock_echo.assert_called()


if __name__ == "__main__":
    # Run the tests
    unittest.main(verbosity=2)
