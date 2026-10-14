# syntax=docker/dockerfile:1
# Purple-Team Cyber Range Rootless Container Image
FROM python:3.12-slim-bookworm AS base

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install minimal OS utilities required for non-destructive cyber range emulation
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    procps \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated unprivileged system group and user (UID/GID 10001)
RUN groupadd -g 10001 purpleteam && \
    useradd -u 10001 -g purpleteam -s /bin/bash -m -d /home/purpleteam purpleteam

WORKDIR /app

# Install project dependencies
COPY pyproject.toml README.md /app/
RUN pip install --no-cache-dir hatchling && \
    pip install --no-cache-dir ".[dev]"

# Copy source code and default data directories
COPY src/ /app/src/
RUN pip install --no-cache-dir -e .

# Create persistent storage directory owned by unprivileged user
RUN mkdir -p /app/data && chown -R purpleteam:purpleteam /app

# Switch to rootless user
USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

ENTRYPOINT ["uvicorn", "purple_range.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
