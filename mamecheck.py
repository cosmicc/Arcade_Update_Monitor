#!/usr/bin/env python3
"""
MAME Version Checker

- Scrapes Pleasuredome's MAME page to detect the latest "update ROMs" target version.
- Compares against the locally stored version in data_dir/mame.ver.
- On change, updates the version file, records last-check info, and sends a Pushover notification.
- Logs all actions to /var/log/arcadecheck.log (or the path defined in config.ini).

All configuration (URLs, paths, Pushover creds) is taken from config.ini.

Expected version file format (mame.ver):
    line 0: version string (e.g. "0.283")
    line 1: date string   (e.g. "03-05-2025" in %m-%d-%Y)

Expected lastcheck file format (shared with other checkers, e.g. lastcheck):
    line 0: timestamp string   (e.g. "03-05-2025 15:30:22" in %m-%d-%Y %H:%M:%S)
    line 1: app label string   (e.g. "MAME")

This script is intended to be run periodically (e.g. via cron or a scheduler),
and to share the same config.ini and data_dir structure as the arcade web dashboard.
"""

from __future__ import annotations
import os
import sys
import re
import configparser
from datetime import datetime
from typing import Optional, Tuple

from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

# ==========================
# CONFIG / GLOBALS
# ==========================

CONFIG_ENV_VAR = "ARCADE_APP_CONFIG"
DEFAULT_CONFIG_PATH = "/config/arcade_app/config.ini"

CONFIG_PATH = os.environ.get(CONFIG_ENV_VAR, DEFAULT_CONFIG_PATH)

# Defaults (overridden by config.ini)
MAME_URL = "https://pleasuredome.github.io/pleasuredome/mame/index.html"
DATA_DIR = "./data"
VERSION_FILE = "mame.ver"
LASTCHECK_FILE = "lastcheck"
LOG_PATH = "/var/log/arcadecheck.log"
MAME_LABEL = "MAME"

PUSHOVER_TOKEN: Optional[str] = None
PUSHOVER_USER: Optional[str] = None
PUSHOVER_DEVICE: Optional[str] = None
PUSHOVER_PRIORITY: int = 0
PUSHOVER_ENABLED: bool = True
NOTIFY_ON_UPDATE: bool = True
NOTIFY_ON_ERROR: bool = True

QB_ENABLED = False
QB_HOST = "10.100.10.10"
QB_PORT = 8080
QB_USER = None
QB_PASS = None
QB_CATEGORY = "games"
QB_PAUSED = False
QB_URL_TEMPLATE = ""


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


def load_config(path: str) -> None:
    """
    Load settings from config.ini.
    """
    global MAME_URL, DATA_DIR, VERSION_FILE, LASTCHECK_FILE, LOG_PATH, MAME_LABEL
    global PUSHOVER_TOKEN, PUSHOVER_USER, PUSHOVER_DEVICE, PUSHOVER_PRIORITY
    global PUSHOVER_ENABLED, NOTIFY_ON_UPDATE, NOTIFY_ON_ERROR
    global QB_ENABLED, QB_HOST, QB_PORT, QB_USER, QB_PASS, QB_CATEGORY, QB_PAUSED, QB_URL_TEMPLATE

    parser = configparser.ConfigParser()
    read_files = parser.read(path)

    if not read_files:
        print(f"WARNING: config file {path} not found; using built-in defaults.",
              file=sys.stderr)

    # [web] – shared paths with the web dashboard
    if parser.has_section("web"):
        web = parser["web"]
        DATA_DIR = web.get("data_dir", DATA_DIR)
        LASTCHECK_FILE = web.get("lastcheck_file", LASTCHECK_FILE)
        LOG_PATH = web.get("log_path", LOG_PATH)

    # [mame] – checker-specific settings
    if parser.has_section("mame"):
        mame = parser["mame"]
        MAME_URL = mame.get("url", MAME_URL)
        VERSION_FILE = mame.get("version_file", VERSION_FILE)
        MAME_LABEL = mame.get("label", MAME_LABEL)
        NOTIFY_ON_UPDATE = mame.getboolean("notify_on_update", NOTIFY_ON_UPDATE)
        NOTIFY_ON_ERROR = mame.getboolean("notify_on_error", NOTIFY_ON_ERROR)

    # [pushover] – notification settings
    if parser.has_section("pushover"):
        po = parser["pushover"]
        PUSHOVER_TOKEN = po.get("token", "").strip() or None
        PUSHOVER_USER = po.get("user", "").strip() or None
        PUSHOVER_DEVICE = po.get("device", "").strip() or None
        PUSHOVER_PRIORITY = po.getint("priority", 0)
        PUSHOVER_ENABLED = po.getboolean("enabled", True) and bool(
            PUSHOVER_TOKEN and PUSHOVER_USER
        )
    else:
        PUSHOVER_ENABLED = False

    if parser.has_section("qbittorrent"):
        qb = parser["qbittorrent"]
        QB_ENABLED = qb.getboolean("enabled", False)
        QB_HOST = qb.get("host", QB_HOST).strip()
        QB_PORT = qb.getint("port", QB_PORT)
        QB_USER = qb.get("username", "").strip() or None
        QB_PASS = qb.get("password", "").strip() or None
        QB_CATEGORY = qb.get("category", "").strip()
        QB_PAUSED = qb.getboolean("paused", False)
        QB_URL_TEMPLATE = qb.get("url_template", "").strip()
        if QB_ENABLED and not (QB_USER and QB_PASS):
            logf(False, "qBittorrent enabled but username/password missing; disabling.")
            QB_ENABLED = False

    QB_URL_TEMPLATE = extract_magnets_from_anchor()

    # Normalize paths
    DATA_DIR = os.path.abspath(DATA_DIR)
    LOG_PATH = os.path.abspath(LOG_PATH)

    print("[mamecheck] Loaded config:")
    print(f"  CONFIG_PATH      = {path}")
    print(f"  MAME_URL         = {MAME_URL}")
    print(f"  DATA_DIR         = {DATA_DIR}")
    print(f"  VERSION_FILE     = {VERSION_FILE}")
    print(f"  LASTCHECK_FILE   = {LASTCHECK_FILE}")
    print(f"  LOG_PATH         = {LOG_PATH}")
    print(f"  MAME_LABEL       = {MAME_LABEL}")
    print(f"  PUSHOVER_ENABLED = {PUSHOVER_ENABLED}")


# Load config at import time
load_config(CONFIG_PATH)

# ==========================
# LOGGING & NOTIFICATION
# ==========================

def logf(ok: bool, message: str) -> None:
    """
    Append a log line to LOG_PATH.

    Format:
        YYYY-MM-DD HH:MM:SS (+) Message...
        YYYY-MM-DD HH:MM:SS (-) Message...
    """
    status = "(+)" if ok else "(-)"
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts} {status} {message}\n"

    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError as e:
        print(f"ERROR: unable to write log file '{LOG_PATH}': {e}",
              file=sys.stderr)

def qb_add_urls(urls: list[str]) -> bool:
    """Add one or more torrent URLs/magnets to qBittorrent. Returns True on success."""
    if not QB_ENABLED:
        return False

    base = f"http://{QB_HOST}:{QB_PORT}"
    s = requests.Session()

    try:
        r = s.post(f"{base}/api/v2/auth/login",
                   data={"username": QB_USER, "password": QB_PASS},
                   timeout=10)
        if r.status_code != 200 or r.text.strip() != "Ok.":
            logf(False, f"qBittorrent login failed: HTTP {r.status_code} body={r.text[:120]}")
            return False

        payload = {
            "urls": "\n".join(urls),
            "paused": "true" if QB_PAUSED else "false",
        }
        if QB_CATEGORY:
            payload["category"] = QB_CATEGORY

        r = s.post(f"{base}/api/v2/torrents/add", data=payload, timeout=15)
        logf(True, f"qBittorrent add response: HTTP {r.status_code} body={r.text!r}")
        if r.status_code != 200:
            logf(False, f"qBittorrent add failed: HTTP {r.status_code} body={r.text[:200]}")
            return False

        # qBittorrent often returns plain text like "Ok." or "Fails."
        if "fail" in r.text.lower():
            logf(False, f"qBittorrent add returned failure: {r.text[:200]}")
            return False

        logf(True, f"qBittorrent: added {len(urls)} URL(s) successfully.")
        return True

    except Exception as e:
        logf(False, f"qBittorrent error: {e}")
        return False


def send_pushover(title: str, message: str, priority: Optional[int] = None) -> None:
    """
    Send a Pushover notification, if enabled.

    Uses HTTP API directly via requests. Errors are logged but do not raise.
    """
    if not PUSHOVER_ENABLED:
        return

    prio = PUSHOVER_PRIORITY if priority is None else priority

    payload = {
        "token": PUSHOVER_TOKEN,
        "user": PUSHOVER_USER,
        "title": title,
        "message": message,
        "priority": str(prio),
    }
    if PUSHOVER_DEVICE:
        payload["device"] = PUSHOVER_DEVICE

    try:
        resp = requests.post("https://api.pushover.net/1/messages.json", data=payload, timeout=10)
        if resp.status_code != 200:
            logf(False, f"Pushover API error {resp.status_code}: {resp.text[:200]}")
            return

        # extra visibility
        try:
            j = resp.json()
        except Exception:
            logf(False, f"Pushover: HTTP 200 but non-JSON response: {resp.text[:200]}")
            return

        if j.get("status") != 1:
            logf(False, f"Pushover: HTTP 200 but status != 1: {j}")
        else:
            logf(True, f"Pushover: sent OK (title={title!r})")
    except Exception as e:
        logf(False, f"Failed to send Pushover notification: {e}")


# ==========================
# CORE LOGIC
# ==========================

def read_local_version() -> Optional[str]:
    """
    Read the currently stored MAME version from VERSION_FILE in DATA_DIR.

    Returns the version string, or None if the file doesn't exist or is invalid.
    """
    path = os.path.join(DATA_DIR, VERSION_FILE)
    if not os.path.exists(path):
        logf(False, f"MAME: local version file not found at {path}")
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            first_line = f.readline().strip()
            return first_line or None
    except OSError as e:
        logf(False, f"MAME: error reading local version file '{path}': {e}")
        return None


def write_local_version(version: str, date_str: str) -> None:
    """
    Write the updated version and date to VERSION_FILE in DATA_DIR.

    Format:
        line 0: version
        line 1: date (%m-%d-%Y)
    """
    path = os.path.join(DATA_DIR, VERSION_FILE)
    os.makedirs(DATA_DIR, exist_ok=True)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"{version}\n")
            f.write(f"{date_str}\n")
    except OSError as e:
        logf(False, f"MAME: error writing local version file '{path}': {e}")


def update_lastcheck(timestamp_str: str, label: str) -> None:
    """
    Update the shared "lastcheck" file (or equivalent) with the latest run.

    Format:
        line 0: timestamp (%m-%d-%Y %H:%M:%S)
        line 1: app label (e.g. "MAME")
    """
    path = os.path.join(DATA_DIR, LASTCHECK_FILE)
    os.makedirs(DATA_DIR, exist_ok=True)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"{timestamp_str}\n")
            f.write(f"{label}\n")
    except OSError as e:
        logf(False, f"MAME: error writing lastcheck file '{path}': {e}")


def fetch_mame_page(url: str) -> str:
    """
    Retrieve the HTML content of the Pleasuredome MAME page.

    Raises RuntimeError on HTTP/network issues.
    """
    try:
        resp = requests.get(url, timeout=20)
    except Exception as e:
        raise RuntimeError(f"HTTP request failed: {e}") from e

    if resp.status_code != 200:
        raise RuntimeError(f"Unexpected HTTP status {resp.status_code}")

    return resp.text

def parse_mame_versions(html: str) -> Tuple[str, str]:
    """
    Parse Pleasuredome MAME page HTML and extract the "from" and "to"
    versions for the MAME update ROMs set.

    We look for a pattern like:

        MAME - Update ROMs (v0.282 to v0.283)

    anywhere in the page text.

    Returns:
        (from_version, to_version)

    Raises:
        ValueError if the version pattern cannot be found.
    """
    soup = BeautifulSoup(html, "html.parser")

    # Get the full text of the page in one string
    text = soup.get_text(" ", strip=True)

    # Normalize whitespace a bit so the regex is simpler
    text = re.sub(r"\s+", " ", text)

    # Look for "MAME - Update ROMs (vX to vY)" case-insensitively
    pattern = r"MAME\s*-\s*Update ROMs\s*\(v([0-9.]+)\s+to\s+v([0-9.]+)\)"
    m = re.search(pattern, text, flags=re.IGNORECASE)

    if not m:
        # Optional: log a short snippet to help debug if the page format changes again
        snippet = text[:200]
        raise ValueError(
            "Could not find 'MAME - Update ROMs' version string "
            f"in Pleasuredome page. First 200 chars: {snippet!r}"
        )

    from_ver = m.group(1)
    to_ver = m.group(2)
    return from_ver, to_ver

def main() -> int:
    """
    Main entry point.

    - Loads the Pleasuredome HTML
    - Parses the update ROMs versions
    - Compares with local version
    - Logs and optionally notifies via Pushover on update or errors
    """
    now = datetime.now()
    now_date = now.strftime("%m-%d-%Y")
    now_ts = now.strftime("%m-%d-%Y %H:%M:%S")

    # Record this check in the lastcheck file regardless of outcome
    update_lastcheck(now_ts, MAME_LABEL)

    try:
        html = fetch_mame_page(MAME_URL)
    except Exception as e:
        msg = f"MAME ERROR: failed to fetch Pleasuredome page: {e}"
        logf(False, msg)
        if NOTIFY_ON_ERROR:
            send_pushover("MAME Check Error", msg)
        return 1

    try:
        from_ver, to_ver = parse_mame_versions(html)
    except Exception as e:
        msg = f"MAME ERROR: failed to parse versions from Pleasuredome page: {e}"
        logf(False, msg)
        if NOTIFY_ON_ERROR:
            send_pushover("MAME Check Error", msg)
        return 1

    local_ver = read_local_version()

    if local_ver is None:
        logf(False, f"MAME: no local version found; treating {to_ver} as new.")
    else:
        logf(True, f"MAME: local version {local_ver}, Pleasuredome target v{to_ver} (from v{from_ver})")

    if local_ver == to_ver:
        logf(True, f"MAME: version {local_ver} is current (Pleasuredome {to_ver})")
        return 0

    # New version detected
    logf(
        True,
        f"MAME: new version detected. Local={local_ver or 'none'}, "
        f"Pleasuredome={to_ver} (from {from_ver})",
    )
    write_local_version(to_ver, now_date)

    if NOTIFY_ON_UPDATE:
        send_pushover(
            "New MAME Version",
            f"New MAME update ROMs version {to_ver} is available (from {from_ver}).",
        )

    if QB_ENABLED and QB_URL_TEMPLATE:
        url = QB_URL_TEMPLATE.format(version=to_ver)
        ok = qb_add_urls([url])
        if NOTIFY_ON_UPDATE:
            send_pushover(
                "MAME Download Queued" if ok else "MAME Download Queue Failed",
                f"qBittorrent: {'queued' if ok else 'failed to queue'} download for MAME {to_ver}.",
            )
    else:
        logf(True, "qBittorrent: not enabled or url_template not set; skipping queue.")

    return 0


if __name__ == "__main__":
    rc = main()
    sys.exit(rc)
