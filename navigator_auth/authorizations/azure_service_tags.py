"""Fetch Azure Service Tag IP ranges for dynamic IP whitelisting.

Downloads the official Microsoft Azure Service Tags JSON and extracts
IP prefixes for specified service tags (e.g. PowerBI, PowerQueryOnline).

Reference: https://learn.microsoft.com/en-us/fabric/security/power-bi-allow-list-urls
"""
import logging
import re
from typing import Optional
import aiohttp


AZURE_SERVICE_TAGS_URL = (
    "https://download.microsoft.com/download/7/1/D/"
    "71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_{change_number}.json"
)

AZURE_DOWNLOAD_PAGE = (
    "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
)


async def _get_download_url(session: aiohttp.ClientSession) -> Optional[str]:
    """Scrape the actual download URL from the Microsoft download page."""
    try:
        async with session.get(
            "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519",
            allow_redirects=True,
            timeout=aiohttp.ClientTimeout(total=30),
        ) as resp:
            if resp.status != 200:
                return None
            html = await resp.text()
            if match := re.search(
                r'href="(https://download\.microsoft\.com/download/[^"]*ServiceTags_Public[^"]*\.json)"',
                html,
            ):
                return match[1]
    except Exception as exc:
        logging.warning(f"azure_service_tags: failed to scrape download URL: {exc}")
    return None


async def fetch_service_tag_prefixes(
    service_tags: list[str],
    timeout: int = 60,
) -> list[str]:
    """Download Azure Service Tags JSON and return IP prefixes for the given tags.

    Args:
        service_tags: List of Azure service tag names (e.g. ["PowerBI", "PowerQueryOnline"]).
        timeout: HTTP request timeout in seconds.

    Returns:
        List of CIDR strings (e.g. ["13.73.248.16/29", "20.21.32.40/29", ...]).
    """
    prefixes: list[str] = []
    tags_lower = {t.lower() for t in service_tags}

    async with aiohttp.ClientSession() as session:
        download_url = await _get_download_url(session)
        if not download_url:
            logging.error(
                "azure_service_tags: could not resolve download URL from Microsoft"
            )
            return prefixes

        try:
            async with session.get(
                download_url,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as resp:
                if resp.status != 200:
                    logging.error(
                        f"azure_service_tags: HTTP {resp.status} fetching {download_url}"
                    )
                    return prefixes
                data = await resp.json(content_type=None)
        except Exception as exc:
            logging.error(f"azure_service_tags: failed to fetch service tags: {exc}")
            return prefixes

    for value in data.get("values", []):
        name = value.get("name", "")
        base_name = name.split(".")[0].lower()
        if base_name in tags_lower:
            props = value.get("properties", {})
            prefixes.extend(props.get("addressPrefixes", []))

    unique = list(dict.fromkeys(prefixes))
    logging.info(
        f"azure_service_tags: loaded {len(unique)} IP prefixes "
        f"for tags {service_tags}"
    )
    return unique
