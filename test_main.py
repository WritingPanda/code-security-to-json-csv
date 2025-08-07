import pytest
import json
import os
import aiohttp
from unittest.mock import patch, AsyncMock
from typing import Dict, List, Any
from pathlib import Path
import main

@pytest.mark.asyncio
async def test_check_rate_limit_async_normal():
    headers = {"X-RateLimit-Remaining": "4500", "X-RateLimit-Reset": "1640995200"}
    with patch("asyncio.sleep", new_callable=AsyncMock):
        await main.check_rate_limit_async(headers)

@pytest.mark.asyncio
async def test_check_rate_limit_async_low_remaining():
    headers = {"X-RateLimit-Remaining": "5", "X-RateLimit-Reset": str(int(1640995200) + 300)}
    with patch("asyncio.sleep", new_callable=AsyncMock):
        await main.check_rate_limit_async(headers)

@pytest.mark.asyncio
async def test_handle_rate_limit_response_async_429():
    headers = {"Retry-After": "1", "X-RateLimit-Reset": str(int(1640995200) + 300)}
    with patch("asyncio.sleep", new_callable=AsyncMock):
        result = await main.handle_rate_limit_response_async(headers, 429)
        assert result is True

@pytest.mark.asyncio
async def test_handle_rate_limit_response_async_not_429():
    headers: Dict[str, str] = {}
    result = await main.handle_rate_limit_response_async(headers, 200)
    assert result is False

@pytest.mark.asyncio
async def test_fetch_page_async_success():
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value=[{"number": 1}])
    mock_response.headers = {"X-RateLimit-Remaining": "4000"}
    
    # Create a proper async context manager mock
    mock_cm = AsyncMock()
    mock_cm.__aenter__.return_value = mock_response
    mock_cm.__aexit__.return_value = None
    
    with patch("aiohttp.ClientSession.get", return_value=mock_cm), \
         patch("asyncio.sleep", new_callable=AsyncMock), \
         patch("click.echo"):
        async with aiohttp.ClientSession() as session:
            result = await main.fetch_page_async(session, "url", {}, {}, 1)
            assert isinstance(result, list)
            assert result[0]["number"] == 1

@pytest.mark.asyncio
async def test_fetch_page_async_429():
    mock_response = AsyncMock()
    mock_response.status = 429
    mock_response.headers = {"Retry-After": "1", "X-RateLimit-Reset": "1640995200"}
    
    # Create a proper async context manager mock
    mock_cm = AsyncMock()
    mock_cm.__aenter__.return_value = mock_response
    mock_cm.__aexit__.return_value = None
    
    with patch("aiohttp.ClientSession.get", return_value=mock_cm):
        async with aiohttp.ClientSession() as session:
            result = await main.fetch_page_async(session, "url", {}, {}, 1)
            assert result is None

@pytest.mark.asyncio
async def test_get_security_alerts_async_no_token():
    main.github_token = None
    result = await main.get_security_alerts_async("org")
    assert result == []

@pytest.mark.asyncio
async def test_get_security_alerts_async_success():
    main.github_token = "test_token"
    with patch("main.fetch_page_async", new_callable=AsyncMock) as mock_fetch:
        mock_fetch.side_effect = [[{"number": 1}], [{"number": 2}], None]
        result = await main.get_security_alerts_async("org")
        assert isinstance(result, list)
        assert result[0]["number"] == 1
        assert result[1]["number"] == 2

@pytest.mark.asyncio
async def test_write_to_json_async(tmp_path: Path) -> None:
    data: List[Dict[str, Any]] = [{"number": 1}]
    file_path = tmp_path / "out.json"
    await main.write_to_json_async(data, str(file_path))
    assert os.path.exists(file_path)
    with open(file_path) as f:
        loaded = json.load(f)
    assert loaded[0]["number"] == 1

@pytest.mark.asyncio
async def test_write_to_csv_async(tmp_path: Path) -> None:
    data: List[Dict[str, Any]] = [{"number": 1, "state": "open"}]
    file_path = tmp_path / "out.csv"
    await main.write_to_csv_async(data, str(file_path))
    assert os.path.exists(file_path)
    with open(file_path) as f:
        content = f.read()
    assert "number" in content and "open" in content

@pytest.mark.asyncio
async def test_write_to_csv_async_empty(tmp_path: Path) -> None:
    file_path = tmp_path / "empty.csv"
    await main.write_to_csv_async([], str(file_path))
    assert not os.path.exists(file_path)
