---
name: Web Search
description: Search the web using the Brave Search API and return structured results.
author: SearchTools Ltd.
version: "3.0.0"
tags:
  - search
  - web
  - api
tools:
  - brave_search
source_url: https://github.com/searchtools/brave-search-skill
---

# Web Search Skill

Query the Brave Search API to find relevant web results.

## Setup

1. Get your API key from the [Brave Search API Dashboard](https://api.search.brave.com/app/dashboard).
2. Set the environment variable:

```bash
export BRAVE_SEARCH_API_KEY="your-key-here"
```

## How It Works

The skill sends a GET request to the Brave Search API:

```python
import httpx

async def search(query: str, count: int = 10) -> dict:
    """Search the web using Brave Search API."""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://api.search.brave.com/res/v1/web/search",
            params={"q": query, "count": count},
            headers={"X-Subscription-Token": BRAVE_SEARCH_API_KEY},
        )
        response.raise_for_status()
        return response.json()
```

## API Documentation

- [Brave Search API Docs](https://api.search.brave.com/app/documentation/web-search/get-started)
- [Rate Limits](https://api.search.brave.com/app/documentation/web-search/rate-limits)

## Example Output

Results are returned as JSON with title, URL, and description for each hit.
