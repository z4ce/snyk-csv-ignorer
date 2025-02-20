#!/usr/bin/env python3

import os
import csv
import time
import argparse
import requests
from urllib.parse import unquote
from typing import Optional

def parse_args():
    """
    Parse command-line arguments for ignoring issues in Snyk.
    """
    parser = argparse.ArgumentParser(description="Ignore issues in Snyk using CSV input.")
    parser.add_argument(
        "--file",
        required=True,
        help="Path to the CSV file."
    )
    parser.add_argument(
        "--text",
        required=False,
        help="The reason text for ignoring the issue."
    )
    parser.add_argument(
        "--ignore-text-column",
        required=False,
        help="Name of the CSV column containing the ignore reason text."
    )
    parser.add_argument(
        "--type",
        required=True,
        help=(
            "The classification of the ignore reason. "
            "Valid options include: 'not-vulnerable', 'wont-fix', 'temporary-ignore'."
        )
    )
    parser.add_argument(
        "--disregard-if-fixable",
        action="store_true",
        default=False,
        help="Ignore only if no upgrade or patch is available."
    )
    parser.add_argument(
        "--expires",
        default=None,
        help="Timestamp (ISO 8601) when the ignore expires, e.g. 2025-12-31."
    )
    parser.add_argument(
        "--ignore-path",
        default="*",
        help="Path to ignore, default is '*'."
    )
    args = parser.parse_args()
    
    # Validate that at least one of text or ignore-text-column is provided
    if not args.text and not args.ignore_text_column:
        parser.error("At least one of --text or --ignore-text-column must be provided")
    
    return args

def parse_issue_id(issue_url: str) -> Optional[str]:
    """
    Extract the issue ID from a Snyk issue URL.
    For example: 
    https://app.snyk.io/org/my-org/project/my-proj#issue-snyk%3Alic%3Apip%3Acommon-lib%3AUnknown
    returns snyk:lic:pip:common-lib:Unknown
    """
    if "#issue-" not in issue_url:
        return None
    encoded_issue_id = issue_url.split("#issue-")[1]
    # Decode URL-encoded parts (e.g., %3A -> :)
    return unquote(encoded_issue_id)

def parse_project_id(project_url: str) -> Optional[str]:
    """
    Extract the project ID from a Snyk project URL.
    For example:
    https://app.snyk.io/org/my-org/project/1234abcd-5678efgh#issue-xyz
    returns 1234abcd-5678efgh
    """
    if "/project/" not in project_url:
        return None
    project_part = project_url.split("/project/")[1]
    # Split on either # or / to get just the project ID
    project_id = project_part.split("#")[0].split("/")[0]
    return project_id

def parse_org_id(url: str) -> Optional[str]:
    """
    Extract the organization ID from a Snyk URL.
    For example:
    https://app.snyk.io/org/my-org/project/1234abcd-5678efgh
    returns my-org
    """
    if "/org/" not in url:
        return None
    parts = url.split("/org/")[1].split("/")
    if not parts:
        return None
    return parts[0]

def call_snyk_ignore_api(
    org_id: str,
    project_id: str,
    issue_id: str,
    token: str,
    reason_text: str,
    reason_type: str,
    disregard_if_fixable: bool,
    expires: Optional[str],
    ignore_path: str,
    max_retries: int = 3
) -> requests.Response:
    """
    Call the Snyk v1 ignore API to ignore a specific issue. Handles simple rate limiting.
    """
    url = f"https://api.snyk.io/v1/org/{org_id}/project/{project_id}/ignore/{issue_id}"
    payload = {
        "reason": reason_text,
        "reasonType": reason_type,
        "disregardIfFixable": disregard_if_fixable,
        "ignorePath": ignore_path
    }
    if expires:
        payload["expires"] = expires

    headers = {
        "Authorization": f"token {token}",
        "Content-Type": "application/json"
    }

    if max_retries <= 0:
        max_retries = 1
    
    for attempt in range(max_retries):
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code == 429:
            # Rate limit encountered
            retry_after = int(response.headers.get("Retry-After", "10"))
            time.sleep(retry_after)
        else:
            return response

    # Return the last response if still failing after retries
    return response

def process_csv(
    file_path: str,
    token: str,
    reason_text: Optional[str],
    reason_type: str,
    disregard_if_fixable: bool,
    expires: Optional[str],
    ignore_path: str,
    ignore_text_column: Optional[str] = None
):
    """
    Read a CSV file and ignore issues in Snyk based on its contents.
    Assumes the CSV has a column named ISSUE_URL containing the full Snyk issue URL.
    If ignore_text_column is provided, the text from that column will be used or appended to reason_text.
    """
    with open(file_path, newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            issue_url = row.get("ISSUE_URL", "").strip()

            if not issue_url:
                print(f"Skipping row due to missing ISSUE_URL: {row}")
                continue

            org_id = parse_org_id(issue_url)
            project_id = parse_project_id(issue_url)
            issue_id = parse_issue_id(issue_url)

            if not org_id or not project_id or not issue_id:
                print(f"Skipping row because org_id, project_id or issue_id could not be parsed: {row}")
                continue

            # Handle the ignore text from column if specified
            final_reason_text = reason_text or ""
            if ignore_text_column:
                column_text = row.get(ignore_text_column, "").strip()
                if not column_text:
                    print(f"Warning: Missing text in column {ignore_text_column} for row: {row}")
                    if not reason_text:
                        print("Skipping row due to missing ignore text")
                        continue
                else:
                    if reason_text:
                        final_reason_text = f"{reason_text} {column_text}"
                    else:
                        final_reason_text = column_text

            response = call_snyk_ignore_api(
                org_id=org_id,
                project_id=project_id,
                issue_id=issue_id,
                token=token,
                reason_text=final_reason_text,
                reason_type=reason_type,
                disregard_if_fixable=disregard_if_fixable,
                expires=expires,
                ignore_path=ignore_path
            )

            if response.status_code == 200:
                print(f"Successfully ignored issue '{issue_id}' in org '{org_id}' project '{project_id}'.")
            else:
                print(
                    f"Failed to ignore issue '{issue_id}' in org '{org_id}' project '{project_id}'. "
                    f"Status code: {response.status_code}, Response: {response.text}"
                )

def main():
    args = parse_args()
    token = os.environ.get("SNYK_TOKEN")
    if not token:
        print("Error: SNYK_TOKEN environment variable not set.")
        return

    process_csv(
        file_path=args.file,
        token=token,
        reason_text=args.text,
        reason_type=args.type,
        disregard_if_fixable=args.disregard_if_fixable,
        expires=args.expires,
        ignore_path=args.ignore_path,
        ignore_text_column=args.ignore_text_column
    )

if __name__ == "__main__":
    main()
