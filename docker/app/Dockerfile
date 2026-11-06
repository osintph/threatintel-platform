# Base image pinned by digest; .github/dependabot.yml proposes updates monthly.
FROM python:3.11-slim@sha256:65bd3d9f1d7fa268dd1909973ba7eb4bdf41f6dcf2cfbe76ba9528b170f3fd79

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libxml2-dev \
    libxslt-dev \
    curl \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libcairo2 \
    libatspi2.0-0 \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Chromium goes to a shared path so the runtime user (appuser) can launch it.
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Dependencies come only from the lock file, every one checked against its hash.
# Regenerate it with `make lock`. The app itself runs from /app/src (PYTHONPATH).
COPY requirements.lock ./
RUN pip install --require-hashes -r requirements.lock && \
    playwright install chromium && \
    chmod -R a+rX /opt/playwright

COPY src/ ./src/
COPY config/ ./config/

RUN mkdir -p /app/data \
    && useradd -m -u 1000 appuser \
    && chown -R appuser:appuser /app

USER appuser

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/src

EXPOSE 8080

CMD ["python", "-m", "darkweb_scanner.main", "--help"]
