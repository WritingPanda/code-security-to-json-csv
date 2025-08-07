import json
import csv
import os
import dotenv
import click
import time
import asyncio
import aiohttp
import aiofiles
from typing import List, Dict, Any, Optional


# dotenv will be loaded when main() is called

# Global variable to store the token, will be set by CLI or environment
github_token = None


def check_rate_limit(response: aiohttp.ClientResponse) -> None:
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
    response: aiohttp.ClientResponse, enterprise_url: Optional[str] = None
) -> bool:
    """
    Handle rate limit exceeded response (HTTP 429).

    Args:
        response: The HTTP response from GitHub API
        enterprise_url: Enterprise URL if applicable

    Returns:
        bool: True if we should retry the request, False otherwise
    """
    if response.status == 429:
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


async def check_rate_limit_async(response_headers: Dict[str, str]) -> None:
    """
    Async version of rate limit checking.
    
    Args:
        session: The aiohttp session
        response_headers: Headers from the HTTP response
    """
    remaining = int(response_headers.get('X-RateLimit-Remaining', 0))
    reset_time = int(response_headers.get('X-RateLimit-Reset', 0))
    
    if remaining <= 10:  # When we're close to the limit
        current_time = int(time.time())
        sleep_time = max(0, reset_time - current_time + 5)  # Add 5 seconds buffer
        
        if sleep_time > 0:
            click.echo(
                f"Rate limit nearly exhausted ({remaining} requests remaining). Waiting {sleep_time} seconds...",
                err=True,
            )
            await asyncio.sleep(sleep_time)
    
    # Add a small delay between requests to be respectful
    await asyncio.sleep(0.1)


async def handle_rate_limit_response_async(
    response_headers: Dict[str, str], status_code: int, enterprise_url: Optional[str] = None
) -> bool:
    """
    Async version of rate limit response handling.
    
    Args:
        response_headers: Headers from the HTTP response
        status_code: HTTP status code
        enterprise_url: Enterprise URL if applicable
        
    Returns:
        bool: True if we should retry the request, False otherwise
    """
    if status_code == 429:
        retry_after = int(response_headers.get('Retry-After', 60))
        reset_time = int(response_headers.get('X-RateLimit-Reset', 0))
        
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
        await asyncio.sleep(wait_time)
        return True
    
    return False


async def fetch_page_async(
    session: aiohttp.ClientSession,
    url: str,
    headers: Dict[str, str],
    params: Dict[str, Any],
    page: int,
    enterprise_url: Optional[str] = None,
    max_retries: int = 3
) -> Optional[List[Dict[str, Any]]]:
    """
    Fetch a single page of alerts asynchronously.
    
    Args:
        session: The aiohttp session
        url: API endpoint URL
        headers: Request headers
        params: Request parameters
        page: Page number
        enterprise_url: Enterprise URL if applicable
        max_retries: Maximum retry attempts
        
    Returns:
        List of alerts or None if failed
    """
    params_with_page: Dict[str, Any] = {**params, 'page': page}
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            async with session.get(url, headers=headers, params=params_with_page) as response:
                # Handle rate limiting
                if response.status == 429:
                    if await handle_rate_limit_response_async(dict(response.headers), response.status, enterprise_url):
                        retry_count += 1
                        continue
                    else:
                        break
                
                # Check rate limit status and add delays
                await check_rate_limit_async(dict(response.headers))
                
                # Process successful responses
                if response.status == 200:
                    alerts = await response.json()
                    if not alerts:  # No more alerts to fetch
                        return None
                    
                    # Display rate limit info
                    remaining = response.headers.get('X-RateLimit-Remaining', 'unknown')
                    if remaining != 'unknown':
                        click.echo(f"Page {page} - API requests remaining: {remaining}", err=True)
                    
                    return alerts
                
                elif response.status == 403:
                    click.echo(f"Error: Access forbidden. Check your token permissions.", err=True)
                    return None
                elif response.status == 404:
                    click.echo(f"Error: Organization not found or not accessible.", err=True)
                    return None
                else:
                    error_text = await response.text()
                    click.echo(f"Error fetching page {page}: {response.status} - {error_text}", err=True)
                    return None
                    
        except aiohttp.ClientConnectorError as e:
            if enterprise_url:
                click.echo(f"Error: Cannot connect to GitHub Enterprise Server at {enterprise_url}. Please check the URL and network connectivity.", err=True)
            else:
                click.echo(f"Error: Cannot connect to GitHub.com. Please check your network connectivity.", err=True)
            click.echo(f"Connection error details: {str(e)}", err=True)
            return None
        except Exception as e:
            click.echo(f"Error: Request failed - {str(e)}", err=True)
            return None
    
    # If we've exhausted retries
    if retry_count >= max_retries:
        click.echo(f"Maximum retries exceeded for page {page} due to rate limiting.", err=True)
    
    return None


async def get_security_alerts_async(
    org_name: str,
    state: str = "open",
    severity: Optional[str] = None,
    enterprise_url: Optional[str] = None,
    max_concurrent: int = 5
) -> List[Dict[str, Any]]:
    """
    Fetch all security alerts asynchronously with concurrent requests.
    
    Args:
        org_name: The name of the GitHub organization
        state: Filter by alert state
        severity: Filter by alert severity
        enterprise_url: Base URL for GitHub Enterprise Server
        max_concurrent: Maximum concurrent requests
        
    Returns:
        List of all security alerts
    """
    if not github_token:
        click.echo("GitHub token is not set. Please set the GITHUB_TOKEN environment variable.", err=True)
        return []
    
    # Determine base URL
    if enterprise_url:
        base_url = enterprise_url.rstrip("/")
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"
        api_base = f"{base_url}/api/v3"
    else:
        api_base = "https://api.github.com"
    
    url = f"{api_base}/orgs/{org_name}/code-scanning/alerts"
    headers = {
        "Authorization": f"Bearer {github_token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "Accept": "application/vnd.github+json",
    }
    params: Dict[str, Any] = {
        "state": state,
        "per_page": 100,  # Maximum allowed by GitHub API
        "tool_name": "CodeQL",
    }
    
    # Add severity filter if specified
    if severity:
        params["severity"] = severity
    
    all_alerts: List[Dict[str, Any]] = []
    
    # Create aiohttp session with connection limits
    connector = aiohttp.TCPConnector(limit=max_concurrent, limit_per_host=max_concurrent)
    timeout = aiohttp.ClientTimeout(total=300)  # 5 minute timeout
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        # First, fetch page 1 to see if there are any results
        click.echo("Fetching first page to determine total scope...", err=True)
        first_page = await fetch_page_async(session, url, headers, params, 1, enterprise_url)
        
        if first_page is None:
            return []
        
        if not first_page:
            click.echo("No alerts found.", err=True)
            return []
        
        all_alerts.extend(first_page)
        click.echo(f"Found {len(first_page)} alerts on first page, fetching remaining pages concurrently...", err=True)
        
        # Now fetch multiple pages concurrently
        # Start with a reasonable batch size and expand as needed
        page = 2
        semaphore = asyncio.Semaphore(max_concurrent)  # Limit concurrent requests
        
        async def fetch_with_semaphore(page_num: int) -> Optional[List[Dict[str, Any]]]:
            async with semaphore:
                return await fetch_page_async(session, url, headers, params, page_num, enterprise_url)
        
        # Fetch pages in batches to avoid overwhelming the API
        batch_size = 10
        while True:
            # Create tasks for the current batch
            tasks: List[Any] = []
            for i in range(batch_size):
                current_page = page + i
                task = asyncio.create_task(fetch_with_semaphore(current_page))
                tasks.append(task)
            
            # Execute batch concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            pages_with_data = 0
            for i, result in enumerate(results):
                current_page = page + i
                if isinstance(result, Exception):
                    click.echo(f"Error fetching page {current_page}: {result}", err=True)
                    continue
                
                if result is None:  # No more data or error
                    continue
                
                if result and isinstance(result, list):  # Has data and is a list
                    typed_result: List[Dict[str, Any]] = result  # type: ignore
                    all_alerts.extend(typed_result)
                    pages_with_data += 1
                    click.echo(f"Fetched page {current_page} ({len(typed_result)} alerts)", err=True)
            
            # If no pages in this batch had data, we're done
            if pages_with_data == 0:
                break
            
            page += batch_size
        
        click.echo(f"Total alerts fetched: {len(all_alerts)}", err=True)
        return all_alerts


async def write_to_json_async(data: List[Dict[str, Any]], filename: str) -> None:
    """Write data to a JSON file asynchronously."""
    async with aiofiles.open(filename, "w") as f:
        await f.write(json.dumps(data, indent=2))
    click.echo(f"Data written to {filename}")


async def write_to_csv_async(data: List[Dict[str, Any]], filename: str) -> None:
    """Write data to a CSV file asynchronously."""
    if not data:
        click.echo("No data to write to CSV")
        return
    
    # Get all unique keys from all alerts for CSV headers
    fieldnames: List[str] = sorted({key for alert in data for key in alert.keys()})
    
    # Prepare CSV content in memory first
    import io
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
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
    
    # Write to file asynchronously
    async with aiofiles.open(filename, "w", newline="") as f:
        await f.write(output.getvalue())
    
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
@click.option(
    "--max-concurrent",
    default=5,
    type=click.IntRange(1, 20),
    help="Maximum concurrent requests in async mode (1-20, default: 5).",
)
def main(
    organization: str,
    format: str,
    output: str,
    token: str,
    state: str,
    severity: str,
    enterprise_url: str,
    max_concurrent: int,
) -> None:
    """
    Fetch GitHub security alerts for an organization.

    ORGANIZATION is the GitHub organization name to fetch alerts from.
    """
    # Load environment variables when the command is actually run
    dotenv.load_dotenv()
    
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
    click.echo(f"Using async mode with max {max_concurrent} concurrent requests", err=True)

    # Choose async or sync method
    alerts = asyncio.run(get_security_alerts_async(
        organization, state, severity, enterprise_url, max_concurrent
    ))

    if not alerts:
        click.echo("No alerts found or error occurred.")
        return

    # Determine output filename
    if not output:
        output = f"{organization}-alerts.{format.lower()}"

    # Write output based on format - use async if enabled
    if format.lower() == "csv":
        asyncio.run(write_to_csv_async(alerts, output))
    else:
        asyncio.run(write_to_json_async(alerts, output))


if __name__ == "__main__":
    main()
