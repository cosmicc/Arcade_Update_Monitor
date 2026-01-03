#!/usr/bin/env python3
from __future__ import annotations

import sys
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


def is_http_url(u: str) -> bool:
    try:
        p = urlparse(u)
        return p.scheme in ("http", "https")
    except Exception:
        return False


def extract_nth_links(page_url: str, positions=(1, 3, 12), timeout=20) -> dict[int, str]:
    """
    Extract Nth <a href="..."> links (1-based positions) from a webpage, in DOM order.
    - Resolves relative links to absolute using the page URL.
    - Filters to http(s) only.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; LinkExtractor/1.0; +https://example.invalid)"
    }

    r = requests.get(page_url, headers=headers, timeout=timeout)
    r.raise_for_status()

    soup = BeautifulSoup(r.text, "html.parser")

    links: list[str] = []
    for a in soup.find_all("a", href=True):
        href = a.get("href", "").strip()
        if not href:
            continue

        abs_url = urljoin(page_url, href)
        if is_http_url(abs_url):
            links.append(abs_url)

    results: dict[int, str] = {}
    for pos in positions:
        idx = pos - 1
        if idx < 0 or idx >= len(links):
            raise IndexError(
                f"Requested link #{pos}, but only found {len(links)} http(s) <a href> links."
            )
        results[pos] = links[idx]

    return results


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <page_url>", file=sys.stderr)
        sys.exit(2)

    url = sys.argv[1]
    positions = (1, 2, 3, 4, 5, 6, 17, 18, 19, 20, 25, 29)

    try:
        got = extract_nth_links(url, positions=positions)
        for pos in positions:
            print(f"{pos}: {got[pos]}")
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
