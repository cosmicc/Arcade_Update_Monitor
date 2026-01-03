# Dockerfile for Arcade App Alerter (web + checkers)

FROM python:3.12-slim

# Install curl for Docker HEALTHCHECK
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/arcade_app

ENV ARCADE_APP_CONFIG=/config/arcade_app/config.ini

# Add scummvmcheck.py to this COPY
COPY webserver.py mamecheck.py launchboxcheck.py retroarchcheck.py ledblinkycheck.py scummvmcheck.py entrypoint.py ./
COPY templates ./templates

# Install Python dependencies
RUN pip install --no-cache-dir \
      flask \
      requests \
      beautifulsoup4 \
      lxml

# Ensure log directory exists in container
RUN mkdir -p /var/log

# Expose web port (actual port comes from config, but 5000 is default)
EXPOSE 5000

# Healthcheck: check webserver /health endpoint
HEALTHCHECK --interval=60s --timeout=5s --retries=3 CMD curl -fsS http://127.0.0.1:5000/health || exit 1

# Run the entrypoint
CMD ["python", "/opt/arcade_app/entrypoint.py"]
