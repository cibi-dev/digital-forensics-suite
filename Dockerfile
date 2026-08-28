# ==============================================================================
# Enterprise Multi-Stage Dockerfile for Digital Forensics Suite
# ==============================================================================

# Build Stage
FROM python:3.11-slim AS builder

WORKDIR /build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir --prefix=/install .

# Production Stage
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="digital-forensics-suite" \
      org.opencontainers.image.description="Enterprise Digital Forensics & Incident Response Suite" \
      org.opencontainers.image.authors="cibi-dev" \
      org.opencontainers.image.vendor="DFIR Operations" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/app:/app/packages/crime-network-analyzer/src:/app/packages/forensic-timeline-reconstructor/src:/app/packages/entropy-file-carver/src:/app/packages/merkle-chain-custody/src:/app/packages/text-to-sql-forensic-agent:/app/packages/threat-log-detector/src"

# Copy installed dependencies from builder
COPY --from=builder /install /usr/local

# Create non-root user for DevSecOps compliance
RUN groupadd -r forensic && useradd -r -g forensic -u 1001 -m -d /app forensic_user

# Copy application files
COPY --chown=forensic_user:forensic cli.py pyproject.toml README.md ./
COPY --chown=forensic_user:forensic packages/ ./packages/

USER forensic_user

ENTRYPOINT ["python3", "/app/cli.py"]
CMD ["demo"]
