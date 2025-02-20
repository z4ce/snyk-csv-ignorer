import unittest
from unittest.mock import patch, mock_open, MagicMock
import io

import os

from snyk_ignore_csv import (
    parse_issue_id,
    parse_project_id,
    call_snyk_ignore_api,
    process_csv
)

class TestSnykIgnoreFunctions(unittest.TestCase):

    def test_parse_issue_id(self):
        url = "https://app.snyk.io/org/test-org/project/test-proj#issue-snyk%3Alic%3Apip%3Acommon-lib%3AUnknown"
        issue_id = parse_issue_id(url)
        self.assertEqual(issue_id, "snyk:lic:pip:common-lib:Unknown")

    def test_parse_project_id(self):
        url = "https://app.snyk.io/org/test-org/project/1234abcd-5678efgh"
        project_id = parse_project_id(url)
        self.assertEqual(project_id, "1234abcd-5678efgh")

    @patch("requests.post")
    def test_call_snyk_ignore_api_success(self, mock_requests_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_requests_post.return_value = mock_response

        response = call_snyk_ignore_api(
            org_id="test-org-id",
            project_id="test-proj-id",
            issue_id="snyk:lic:pip:common-lib:Unknown",
            token="fake-token",
            reason_text="test-reason",
            reason_type="wont-fix",
            disregard_if_fixable=False,
            expires=None,
            ignore_path="*"
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(mock_requests_post.called)

    @patch("requests.post")
    def test_call_snyk_ignore_api_rate_limit(self, mock_requests_post):
        # Simulate 429 for first request, then 200
        mock_response_429 = MagicMock()
        mock_response_429.status_code = 429
        mock_response_429.headers = {"Retry-After": "1"}

        mock_response_200 = MagicMock()
        mock_response_200.status_code = 200

        mock_requests_post.side_effect = [mock_response_429, mock_response_200]

        response = call_snyk_ignore_api(
            org_id="test-org-id",
            project_id="test-proj-id",
            issue_id="snyk:lic:pip:common-lib:Unknown",
            token="fake-token",
            reason_text="test-reason",
            reason_type="wont-fix",
            disregard_if_fixable=False,
            expires=None,
            ignore_path="*",
            max_retries=2
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(mock_requests_post.call_count, 2)

    @patch("requests.post")
    def test_process_csv(self, mock_requests_post):
        # Mock CSV contents
        mock_csv_data = """ISSUE_URL
"https://app.snyk.io/org/test-org/project/test-proj#issue-snyk%3Alic%3Apip%3Acommon-lib%3AUnknown"
"""

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_requests_post.return_value = mock_response

        with patch("builtins.open", mock_open(read_data=mock_csv_data)):
            process_csv(
                file_path="fake.csv",
                token="fake-token",
                reason_text="test-reason",
                reason_type="wont-fix",
                disregard_if_fixable=False,
                expires=None,
                ignore_path="*"
            )

        self.assertTrue(mock_requests_post.called)
        args, kwargs = mock_requests_post.call_args
        self.assertIn("test-org", args[0])  # URL should contain 'test-org'
        self.assertIn("test-proj", args[0])  # URL should contain 'test-proj'
        self.assertIn("snyk:lic:pip:common-lib:Unknown", args[0])  # URL should contain the issue ID

    @patch("requests.post")
    def test_process_csv_with_ignore_text_column(self, mock_requests_post):
        # Mock CSV contents with an additional column for ignore text
        mock_csv_data = """ISSUE_URL,IGNORE_REASON
"https://app.snyk.io/org/test-org/project/test-proj#issue-snyk%3Alic%3Apip%3Acommon-lib%3AUnknown","Custom ignore reason"
"""

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_requests_post.return_value = mock_response

        with patch("builtins.open", mock_open(read_data=mock_csv_data)):
            # Test with only ignore text column
            process_csv(
                file_path="fake.csv",
                token="fake-token",
                reason_text=None,
                reason_type="wont-fix",
                disregard_if_fixable=False,
                expires=None,
                ignore_path="*",
                ignore_text_column="IGNORE_REASON"
            )

            # Verify the API was called with the text from the column
            args, kwargs = mock_requests_post.call_args
            self.assertEqual(kwargs["json"]["reason"], "Custom ignore reason")

    @patch("requests.post")
    def test_process_csv_with_combined_text(self, mock_requests_post):
        # Mock CSV contents with an additional column for ignore text
        mock_csv_data = """ISSUE_URL,IGNORE_REASON
"https://app.snyk.io/org/test-org/project/test-proj#issue-snyk%3Alic%3Apip%3Acommon-lib%3AUnknown","Custom ignore reason"
"""

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_requests_post.return_value = mock_response

        with patch("builtins.open", mock_open(read_data=mock_csv_data)):
            # Test with both text argument and ignore text column
            process_csv(
                file_path="fake.csv",
                token="fake-token",
                reason_text="Base reason:",
                reason_type="wont-fix",
                disregard_if_fixable=False,
                expires=None,
                ignore_path="*",
                ignore_text_column="IGNORE_REASON"
            )

            # Verify the API was called with the combined text
            args, kwargs = mock_requests_post.call_args
            self.assertEqual(kwargs["json"]["reason"], "Base reason: Custom ignore reason")

if __name__ == "__main__":
    unittest.main()