from __future__ import annotations

from typing import Iterable
import requests
from bs4 import BeautifulSoup


def extract_magnets_from_anchor(
    page_url: str = "https://pleasuredome.github.io/pleasuredome/mame/index.html",
    anchor_substring: str = "xt=urn:btih:661d5b6a5434cb8e230cd5385db7bfa3e30ff084",
    offsets: Iterable[int] = (0, 1, 5),  # 0=first(anchor), 1=next, 6=7th from anchor
    timeout: int = 20,
) -> list[str]:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    r = requests.get(page_url, headers=headers, timeout=timeout, allow_redirects=True)
    r.raise_for_status()

    soup = BeautifulSoup(r.text, "lxml")

    wrapper = soup.select_one("div.wrapper")
    if not wrapper:
        raise RuntimeError("Could not find div.wrapper in fetched HTML")

    magnets: list[str] = [
        (a.get("href") or "").strip()
        for a in wrapper.select('a[href^="magnet:"]')
        if (a.get("href") or "").strip()
    ]

    if not magnets:
        raise RuntimeError("Found 0 magnet links in div.wrapper")

    # Find anchor index
    anchor_idx = next((i for i, m in enumerate(magnets) if anchor_substring in m), None)
    if anchor_idx is None:
        # Optional fallback: try by visible text if the infohash changes but text is stable
        # (You can remove this block if you want strict matching only.)
        for i, a in enumerate(wrapper.select('a[href^="magnet:"]')):
            if "Update ROMs" in a.get_text(" ", strip=True):
                anchor_idx = i
                break

    if anchor_idx is None:
        raise RuntimeError(
            f"Anchor magnet not found. Tried substring: {anchor_substring!r}. "
            f"Total magnets found: {len(magnets)}"
        )

    out: list[str] = []
    for off in offsets:
        if off < 0:
            raise ValueError(f"Offset must be >= 0, got {off}")
        idx = anchor_idx + off
        if idx >= len(magnets):
            raise IndexError(
                f"Requested offset {off} (magnet #{off+1} from anchor), but only "
                f"{len(magnets) - anchor_idx} magnet(s) exist from the anchor onward "
                f"({len(magnets)} total)."
            )
        out.append(magnets[idx])

    return "\n".join(out)

links = extract_magnets_from_anchor()

print(links)

