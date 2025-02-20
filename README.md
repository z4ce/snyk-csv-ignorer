# Snyk CSV Ignorer

A command-line tool to bulk ignore Snyk issues using a CSV file input. This tool helps automate the process of ignoring multiple Snyk issues across projects and organizations using Snyk's API. The CSV file must contain a column named `ISSUE_URL` with the full Snyk issue URLs as it is returned by the Snyk CSV or Snowflake export.

## Features

- Bulk ignore Snyk issues from a CSV file
- Support for different ignore types (not-vulnerable, wont-fix, temporary-ignore)
- Configurable ignore expiration
- Path-specific ignores
- Rate limiting handling
- Support for disregarding issues only if they're not fixable

## Prerequisites

- Python 3.x
- Snyk API token
- CSV file containing Snyk issue URLs

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/snyk-csv-ignorer.git
cd snyk-csv-ignorer
```

2. Install the required dependencies:
```bash
pip install requests
```

3. Set up your Snyk API token as an environment variable:
```bash
export SNYK_TOKEN='your-snyk-api-token'
```

## Usage

```bash
./snyk_ignore_csv.py --file <path-to-csv> --text <reason-text> --type <ignore-type> [options]
```

### Required Arguments

- `--file`: Path to the CSV file containing Snyk issue URLs
- `--text`: The reason text for ignoring the issues
- `--type`: The classification of the ignore reason (valid options: 'not-vulnerable', 'wont-fix', 'temporary-ignore')

### Optional Arguments

- `--disregard-if-fixable`: Only ignore issues if no upgrade or patch is available
- `--expires`: Timestamp (ISO 8601) when the ignore expires (e.g., 2025-12-31)
- `--ignore-path`: Path to ignore (default: '*')

### CSV File Format

The CSV file must contain a column named `ISSUE_URL` with the full Snyk issue URLs. Example:

```csv
ISSUE_URL
https://app.snyk.io/org/my-org/project/1234abcd-5678efgh#issue-snyk%3Alic%3Apip%3Acommon-lib%3AUnknown
```

## Example

```bash
./snyk_ignore_csv.py \
  --file issues.csv \
  --text "False positive confirmed by security team" \
  --type temporary-ignore \
  --expires 2024-12-31
```

