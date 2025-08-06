# GitHub Security Alerts CLI Tool

This project provides a command-line tool for pulling security alerts from GitHub organizations. It can efficiently retrieve thousands of security alerts using pagination and export them to JSON or CSV format.

## Features

- Fetch security alerts from GitHub organizations using CodeQL
- **Support for GitHub Enterprise Server** with custom URLs
- Filter alerts by state (open, closed, dismissed, fixed)
- Filter alerts by severity (critical, high, medium, low, warning, note, error)
- Automatic pagination to retrieve all results
- Export data to JSON or CSV format
- Command-line interface with helpful options
- Environment variable support for GitHub token
- Token can be provided via command line flag

## Requirements

- Python 3.13 or higher
- `uv` command-line tool for running the script (install via `pip install uv`)
- GitHub token with appropriate permissions for accessing security alerts

## Setup

1. Clone this repository
2. Install dependencies using uv:
   ```bash
   uv sync
   ```
3. Create a `.env` file from the example:
   ```bash
   cp .env.example .env
   ```
4. Add your GitHub token to the `.env` file:
   ```
   GITHUB_TOKEN=your_github_token_here
   ```

## Usage

Run the CLI tool using uv:

```bash
# Basic usage - exports to JSON by default (uses .env file)
uv run python -m main your-org-name

# Provide token via command line
uv run python -m main your-org-name --token your_github_token_here

# Use GitHub Enterprise Server
uv run python -m main your-org-name --enterprise-url https://github.company.com

# Enterprise Server without protocol (will add https:// automatically)
uv run python -m main your-org-name --enterprise-url github.internal.company.com

# Filter by state (default is 'open')
uv run python -m main your-org-name --state closed

# Filter by severity
uv run python -m main your-org-name --severity critical

# Combine filters with enterprise URL
uv run python -m main your-org-name --enterprise-url https://github.company.com --state dismissed --severity high

# Export to CSV format with filters and enterprise URL
uv run python -m main your-org-name --enterprise-url https://github.company.com --format csv --state open --severity critical

# Specify custom output filename with enterprise URL
uv run python -m main your-org-name --enterprise-url https://github.company.com --output my-alerts.json --state fixed

# Combine all options
uv run python -m main your-org-name --token your_token --enterprise-url https://github.company.com --format csv --output custom-alerts.csv --state open --severity medium

# Show help
uv run python -m main --help
```

### Options

- `ORGANIZATION`: The GitHub organization name (required)
- `-f, --format [json|csv]`: Output format (default: json)
- `-o, --output TEXT`: Output filename (default: {org}-alerts.{format})
- `-t, --token TEXT`: GitHub token (if not provided, uses GITHUB_TOKEN environment variable)
- `-s, --state [open|closed|dismissed|fixed]`: Filter alerts by state (default: open)
- `--severity [critical|high|medium|low|warning|note|error]`: Filter alerts by severity (optional)
- `-e, --enterprise-url TEXT`: GitHub Enterprise Server URL (optional)
- `--help`: Show help message

## GitHub Token

You can provide your GitHub token in two ways:

1. **Environment Variable** (recommended for regular use):
   - Create a `.env` file with your token: `GITHUB_TOKEN=your_token_here`
   - Or export it in your shell: `export GITHUB_TOKEN=your_token_here`

2. **Command Line Flag** (useful for one-time use or different tokens):
   - Use the `--token` or `-t` flag: `--token your_token_here`

The command line token takes priority over the environment variable if both are provided.

## GitHub Enterprise Server Support

The tool supports both GitHub.com and GitHub Enterprise Server instances:

### GitHub.com (Default)
When no `--enterprise-url` is provided, the tool connects to `https://api.github.com`

### GitHub Enterprise Server
Use the `--enterprise-url` flag to specify your enterprise instance:

```bash
# Full URL format
uv run python -m main your-org --enterprise-url https://github.company.com

# Hostname only (https:// will be added automatically)
uv run python -m main your-org --enterprise-url github.company.com
```

**URL Format**: The tool automatically constructs the API endpoint using the pattern:
- Input: `https://github.company.com` or `github.company.com`
- API URL: `https://github.company.com/api/v3/orgs/{org}/code-scanning/alerts`

**Enterprise Server Requirements**:
- Your GitHub Enterprise Server must have the Code Scanning API enabled
- Your token must have appropriate permissions for the target organization
- Network connectivity to your enterprise server is required

## Token Requirements

Your GitHub token needs the following permissions:
- `security_events:read` - To read security alerts
- `repo:read` or `public_repo` - To access repository information

## Examples

```bash
# Fetch all open alerts for Microsoft organization as JSON (GitHub.com)
uv run python -m main microsoft

# Fetch alerts from GitHub Enterprise Server
uv run python -m main my-org --enterprise-url https://github.company.com

# Fetch all critical severity alerts from enterprise server
uv run python -m main google --enterprise-url github.internal.com --severity critical --state open

# Fetch all closed alerts from enterprise server and export to CSV
uv run python -m main facebook --enterprise-url https://github.company.com --state closed --format csv

# Fetch high severity dismissed alerts from enterprise server with custom filename
uv run python -m main netflix --enterprise-url github.company.com --state dismissed --severity high --output dismissed-high-alerts.json

# Fetch all fixed alerts from enterprise server for compliance reporting
uv run python -m main airbnb --enterprise-url https://github.internal.company.com --state fixed --format csv --output security-review.csv
```

### Filtering Options

**State Filters:**
- `open`: Currently unresolved alerts (default)
- `closed`: Alerts that have been closed
- `dismissed`: Alerts that have been dismissed as false positives or acceptable risk
- `fixed`: Alerts that have been resolved by fixing the underlying issue

**Severity Filters:**
- `critical`: The most severe security issues
- `high`: High severity security issues
- `medium`: Medium severity security issues  
- `low`: Low severity security issues
- `warning`: Security warnings
- `note`: Security notes and informational alerts
- `error`: Security errors

**Tool Specification:**
All queries automatically filter for CodeQL results only, focusing on static analysis security findings.

The tool will automatically paginate through all results and provide progress updates as it fetches each page of alerts.

## Rate Limiting

The tool implements intelligent rate limiting to respect GitHub's API limits:

### Automatic Rate Limit Handling
- **Proactive Monitoring**: Checks remaining API quota before each request
- **Intelligent Delays**: When quota is low (≤10 requests), waits until rate limit resets
- **429 Response Handling**: Automatically retries when rate limit is exceeded
- **Progress Feedback**: Shows remaining API requests and wait times

### Rate Limit Features
- **Respectful Pacing**: Adds small delays (0.1s) between requests to be respectful
- **Retry Logic**: Up to 3 retries for rate limit exceeded responses
- **Smart Waiting**: Uses `Retry-After` header or calculates wait time from reset timestamp
- **User Feedback**: Displays clear messages about rate limiting status and wait times

### GitHub API Limits
- **GitHub.com**: 5,000 requests per hour for authenticated users
- **Enterprise Server**: Varies by configuration (typically 5,000 requests per hour)

The tool will automatically handle these limits without user intervention, ensuring reliable operation even for large organizations with many security alerts.

