import requests
import json
import csv
import os
import dotenv
import click
import time
from typing import List, Dict, Any, Optional


dotenv.load_dotenv()

# Global variable to store the token, will be set by CLI or environment
github_token = None


def check_rate_limit(response: requests.Response) -> None:
    """
    Check and handle GitHub API rate limiting.

    Args:
        response: The HTTP response from GitHub API
    """
    remaining = int(response.headers.get("X-RateLimit-Remaining", 0))
    reset_time = int(response.headers.get("X-RateLimit-Reset", 0))

    if remaining <= 10:  # When we're close to the limit
        current_time = int(time.time())
        sleep_time = max(0, reset_time - current_time + 5)  # Add 5 seconds buffer

        if sleep_time > 0:
            click.echo(
                f"Rate limit nearly exhausted ({remaining} requests remaining). Waiting {sleep_time} seconds...",
                err=True,
            )
            time.sleep(sleep_time)

    # Add a small delay between requests to be respectful
    time.sleep(0.1)


def handle_rate_limit_response(
    response: requests.Response, enterprise_url: Optional[str] = None
) -> bool:
    """
    Handle rate limit exceeded response (HTTP 429).

    Args:
        response: The HTTP response from GitHub API
        enterprise_url: Enterprise URL if applicable

    Returns:
        bool: True if we should retry the request, False otherwise
    """
    if response.status_code == 429:
        retry_after = int(response.headers.get("Retry-After", 60))
        reset_time = int(response.headers.get("X-RateLimit-Reset", 0))

        if reset_time:
            current_time = int(time.time())
            wait_time = max(retry_after, reset_time - current_time + 5)
        else:
            wait_time = retry_after

        server_type = (
            f"GitHub Enterprise Server at {enterprise_url}"
            if enterprise_url
            else "GitHub.com"
        )
        click.echo(
            f"Rate limit exceeded on {server_type}. Waiting {wait_time} seconds before retrying...",
            err=True,
        )
        time.sleep(wait_time)
        return True

    return False


def get_security_alerts_paginated(
    org_name: str,
    state: str = "open",
    severity: Optional[str] = None,
    enterprise_url: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Fetch all security alerts for a given GitHub organization with pagination.

    Args:
        org_name (str): The name of the GitHub organization.
        state (str): Filter by alert state (open, closed, dismissed, fixed).
        severity (str): Filter by alert severity (critical, high, medium, low, warning, note, error).
        enterprise_url (str): Base URL for GitHub Enterprise Server (e.g., https://github.example.com).
                             If provided, will use https://HOSTNAME/api/v3/ format.

    Returns:
        List[Dict[str, Any]]: A list of all security alerts.
    """
    if not github_token:
        click.echo(
            "GitHub token is not set. Please set the GITHUB_TOKEN environment variable.",
            err=True,
        )
        return []

    all_alerts: List[Dict[str, Any]] = []
    page = 1
    per_page = 100  # Maximum allowed by GitHub API

    # Determine base URL
    if enterprise_url:
        # Remove trailing slash if present and ensure proper format
        base_url = enterprise_url.rstrip("/")
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"
        api_base = f"{base_url}/api/v3"
    else:
        api_base = "https://api.github.com"

    while True:
        url = f"{api_base}/orgs/{org_name}/code-scanning/alerts"
        headers = {
            "Authorization": f"Bearer {github_token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "Accept": "application/vnd.github+json",
        }
        params: Dict[str, Any] = {
            "state": state,
            "per_page": per_page,
            "page": page,
            "tool_name": "CodeQL",
        }

        # Add severity filter if specified
        if severity:
            params["severity"] = severity

        click.echo(f"Fetching page {page}...", err=True)

        # Retry loop for rate limiting
        max_retries = 3
        retry_count = 0

        while retry_count < max_retries:
            try:
                response = requests.get(url, headers=headers, params=params)

                # Handle rate limiting
                if response.status_code == 429:
                    if handle_rate_limit_response(response, enterprise_url):
                        retry_count += 1
                        continue
                    else:
                        break

                # Check rate limit status and add delays
                check_rate_limit(response)

                # Process successful responses
                if response.status_code == 200:
                    alerts = response.json()
                    if not alerts:  # No more alerts to fetch
                        break
                    all_alerts.extend(alerts)

                    # Display rate limit info
                    remaining = response.headers.get("X-RateLimit-Remaining", "unknown")
                    if remaining != "unknown":
                        click.echo(f"API requests remaining: {remaining}", err=True)

                    page += 1
                    break  # Success, exit retry loop

                elif response.status_code == 403:
                    click.echo(
                        f"Error: Access forbidden. Check your token permissions.",
                        err=True,
                    )
                    return all_alerts
                elif response.status_code == 404:
                    click.echo(
                        f"Error: Organization '{org_name}' not found or not accessible.",
                        err=True,
                    )
                    return all_alerts
                else:
                    click.echo(
                        f"Error fetching security alerts: {response.status_code} - {response.text}",
                        err=True,
                    )
                    return all_alerts

            except requests.exceptions.ConnectionError as e:
                if enterprise_url:
                    click.echo(
                        f"Error: Cannot connect to GitHub Enterprise Server at {enterprise_url}. Please check the URL and network connectivity.",
                        err=True,
                    )
                else:
                    click.echo(
                        f"Error: Cannot connect to GitHub.com. Please check your network connectivity.",
                        err=True,
                    )
                click.echo(f"Connection error details: {str(e)}", err=True)
                return all_alerts
            except requests.exceptions.RequestException as e:
                click.echo(f"Error: Request failed - {str(e)}", err=True)
                return all_alerts

        # If we've exhausted retries
        if retry_count >= max_retries:
            click.echo(
                "Maximum retries exceeded due to rate limiting. Please try again later.",
                err=True,
            )
            break

    click.echo(f"Total alerts fetched: {len(all_alerts)}", err=True)
    return all_alerts


def write_to_json(data: List[Dict[str, Any]], filename: str) -> None:
    """Write data to a JSON file."""
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    click.echo(f"Data written to {filename}")


def write_to_csv(data: List[Dict[str, Any]], filename: str) -> None:
    """Write data to a CSV file."""
    if not data:
        click.echo("No data to write to CSV")
        return

    # Get all unique keys from all alerts for CSV headers
    fieldnames: List[str] = sorted({key for alert in data for key in alert.keys()})

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for alert in data:
            # Flatten nested objects for CSV
            flattened_alert: Dict[str, Any] = {}
            for key, value in alert.items():
                if isinstance(value, (dict, list)):
                    flattened_alert[key] = json.dumps(value)
                else:
                    flattened_alert[key] = value
            writer.writerow(flattened_alert)
    click.echo(f"Data written to {filename}")


@click.command()
@click.argument("organization")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "csv"], case_sensitive=False),
    default="json",
    help="Output format (json or csv). Default is json.",
)
@click.option(
    "--output",
    "-o",
    help="Output filename. If not provided, uses org-alerts.json or org-alerts.csv",
)
@click.option(
    "--token",
    "-t",
    help="GitHub token. If not provided, will use GITHUB_TOKEN environment variable.",
)
@click.option(
    "--state",
    "-s",
    type=click.Choice(["open", "closed", "dismissed", "fixed"], case_sensitive=False),
    default="open",
    help="Filter alerts by state. Default is open.",
)
@click.option(
    "--severity",
    type=click.Choice(
        ["critical", "high", "medium", "low", "warning", "note", "error"],
        case_sensitive=False,
    ),
    help="Filter alerts by severity. If not specified, all severities are included.",
)
@click.option(
    "--enterprise-url",
    "-e",
    help="GitHub Enterprise Server URL (e.g., https://github.example.com). If not provided, uses GitHub.com.",
)
def main(
    organization: str,
    format: str,
    output: str,
    token: str,
    state: str,
    severity: str,
    enterprise_url: str,
) -> None:
    """
    Fetch GitHub security alerts for an organization.

    ORGANIZATION is the GitHub organization name to fetch alerts from.
    """
    global github_token

    # Set token priority: CLI argument > environment variable
    github_token = token or os.getenv("GITHUB_TOKEN")

    if not github_token:
        click.echo(
            "Error: GitHub token is required. Provide it via --token flag or set GITHUB_TOKEN environment variable.",
            err=True,
        )
        return

    # Build filter description
    filter_info = f"state={state}"
    if severity:
        filter_info += f", severity={severity}"
    filter_info += ", tool=CodeQL"

    click.echo(f"Fetching security alerts for organization: {organization}")
    if enterprise_url:
        click.echo(f"Using GitHub Enterprise Server: {enterprise_url}")
    click.echo(f"Filters: {filter_info}")

    alerts = get_security_alerts_paginated(
        organization, state, severity, enterprise_url
    )

    if not alerts:
        click.echo("No alerts found or error occurred.")
        return

    # Determine output filename
    if not output:
        output = f"{organization}-alerts.{format.lower()}"

    # Write output based on format
    if format.lower() == "csv":
        write_to_csv(alerts, output)
    else:
        write_to_json(alerts, output)


if __name__ == "__main__":
    main()
