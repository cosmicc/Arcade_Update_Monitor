#!/usr/bin/env python3
"""
Arcade App Alerter - Web Server

Serves a dashboard showing:
- Current versions for each monitored app (from *.ver files)
- Last check info (from lastcheck file)
- Recent log lines from the shared log file

All paths and settings are driven by config.ini.
"""

from __future__ import annotations

import os
import configparser
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from flask import Flask, request, render_template, abort, redirect, url_for

# -----------------------------------------------------------------------------
# Config loading
# -----------------------------------------------------------------------------

CONFIG_ENV_VAR = "ARCADE_APP_CONFIG"
DEFAULT_CONFIG_PATH = "/config/arcade_app/config.ini"
CONFIG_PATH = os.environ.get(CONFIG_ENV_VAR, DEFAULT_CONFIG_PATH)

parser = configparser.ConfigParser()
parser.read(CONFIG_PATH)

if not parser.has_section("web"):
    raise RuntimeError(f"[web] section missing in config file: {CONFIG_PATH}")

WEB = parser["web"]

DATA_DIR: str = WEB.get("data_dir", "/data/arcade_app")
LASTCHECK_FILE: str = WEB.get("lastcheck_file", "lastcheck")
LOG_PATH: str = WEB.get("log_path", "/var/log/arcadecheck.log")
LOG_LINES: int = WEB.getint("log_lines", 40)
TITLE: str = WEB.get("title", "Arcade App Version Monitor")
FLASK_PORT: int = WEB.getint("port", 5000)

# allowed_hosts: comma or space separated
_raw_hosts = WEB.get("allowed_hosts", "").replace(",", " ")
ALLOWED_HOSTS = [h.strip() for h in _raw_hosts.split() if h.strip()]

# [apps] section lists app ids used in [app.<id>]
if not parser.has_section("apps"):
    raise RuntimeError(f"[apps] section missing in config file: {CONFIG_PATH}")

APPS_SECTION = parser["apps"]
APP_IDS: List[str] = [a.strip() for a in APPS_SECTION.get("apps", "").split(",") if a.strip()]

# Normalize data dir
DATA_DIR = os.path.abspath(DATA_DIR)


# -----------------------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------------------

def elapsed_time(start_time_str: str, withsecs: bool, append: Optional[str] = None) -> str:
    """
    Convert a timestamp string to a human-readable elapsed time.

    start_time_str:
        If withsecs=True:  '%m-%d-%Y %H:%M:%S'
        If withsecs=False: '%m-%d-%Y'
    append:
        Text to append at the end (e.g., "ago").
    """
    if withsecs:
        fmt = "%m-%d-%Y %H:%M:%S"
    else:
        fmt = "%m-%d-%Y"

    try:
        start = datetime.strptime(start_time_str, fmt)
    except ValueError:
        # If parsing fails, just return the original string
        return start_time_str

    now = datetime.now()

    if not withsecs:
        # "Today" / "Yesterday" shortcuts for date-only values
        if start.date() == now.date():
            return f"Today {append}" if append else "Today"
        if start.date() == (now.date() - timedelta(days=1)):
            return f"Yesterday {append}" if append else "Yesterday"

    seconds = int((now - start).total_seconds())
    intervals = (
        ("Years", 31536000),
        ("Months", 2592000),
        ("Weeks", 604800),
        ("Days", 86400),
        ("Hours", 3600),
        ("Minutes", 60),
        ("Seconds", 1),
    )

    parts: List[str] = []
    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            if value == 1:
                name = name.rstrip("s")
            parts.append(f"{value} {name}")
            if len(parts) == 2:
                break

    if not parts:
        parts = ["0 Seconds"]

    s = ", ".join(parts)
    if append:
        s += f" {append}"
    return s


def load_app_versions() -> List[Dict[str, Any]]:
    """
    Load version info for each app defined in [apps] and [app.<id>].

    Each entry in the returned list has:
        {
          "id": "<id>",
          "label": "<label>",
          "version": "<version or None>",
          "date": "<date string or None>",
          "elapsed": "<human-readable age or None>",
        }
    """
    apps: List[Dict[str, Any]] = []

    for app_id in APP_IDS:
        sec_name = f"app.{app_id}"
        label = app_id
        ver_file = f"{app_id}.ver"

        if parser.has_section(sec_name):
            sec = parser[sec_name]
            label = sec.get("label", label)
            ver_file = sec.get("file", ver_file)

        path = os.path.join(DATA_DIR, ver_file)
        version: Optional[str] = None
        date_str: Optional[str] = None
        elapsed_str: Optional[str] = None

        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    lines = f.read().splitlines()
                if lines:
                    version = (lines[0] or "").strip() or None
                if len(lines) > 1:
                    date_str = (lines[1] or "").strip() or None
                    if date_str:
                        elapsed_str = elapsed_time(date_str, withsecs=False, append="ago")
            except OSError:
                # Ignore read errors and leave fields as None
                pass

        apps.append(
            {
                "id": app_id,
                "label": label,
                "version": version,
                "date": date_str,
                "elapsed": elapsed_str,
            }
        )

    return apps


def load_lastcheck() -> Optional[Dict[str, str]]:
    """
    Load lastcheck info from LASTCHECK_FILE in DATA_DIR.

    Expected format:
        line 0: timestamp '%m-%d-%Y %H:%M:%S'
        line 1: app label
    """
    path = os.path.join(DATA_DIR, LASTCHECK_FILE)
    if not os.path.exists(path):
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return None

    if len(lines) < 2:
        return None

    ts_str = (lines[0] or "").strip()
    app_name = (lines[1] or "").strip()
    if not ts_str or not app_name:
        return None

    elapsed_str = elapsed_time(ts_str, withsecs=True, append="ago")
    return {
        "timestamp": ts_str,
        "app": app_name,
        "elapsed": elapsed_str,
    }


def load_log_text() -> str:
    """
    Load the last LOG_LINES lines from LOG_PATH.

    Implemented purely in Python (no external 'tail' dependency).
    """
    if not os.path.exists(LOG_PATH):
        return ""

    try:
        with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return ""

    if not lines:
        return ""

    tail = lines[-LOG_LINES:]
    return "\n".join(tail)


# -----------------------------------------------------------------------------
# Flask app
# -----------------------------------------------------------------------------

app = Flask(__name__)


@app.before_request
def limit_remote_addr():
    """
    Optional source IP filtering based on [web].allowed_hosts.

    If allowed_hosts is empty, no restriction is applied.
    """
    if not ALLOWED_HOSTS:
        return

    remote = request.remote_addr
    if remote not in ALLOWED_HOSTS:
        abort(403, description="You're not allowed to access this resource")


@app.route("/health")
def health() -> tuple[str, int]:
    """
    Simple health endpoint for Docker healthcheck.
    """
    return "ok", 200


@app.route("/")
def index():
    apps = load_app_versions()
    lastcheck = load_lastcheck()
    log_text = load_log_text()

    return render_template(
        "index.html",
        title=TITLE,
        apps=apps,
        lastcheck=lastcheck,
        log=log_text,
        log_lines=LOG_LINES,
        log_path=LOG_PATH,
    )


@app.route("/clear-log", methods=["POST"])
def clear_log():
    """
    Clear the contents of the log file, then redirect back to the dashboard.
    """
    try:
        # Truncate the file to zero length (create if missing)
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "w", encoding="utf-8"):
            pass
    except OSError:
        # If something goes wrong, just ignore; the next page load will show the old log
        pass

    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=FLASK_PORT, debug=True)
