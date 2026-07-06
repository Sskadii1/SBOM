# syntax=docker/dockerfile:1.7

FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive
ENV PIP_DEFAULT_TIMEOUT=300
ENV PIP_RETRIES=10
ENV PIP_PROGRESS_BAR=off
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

# System deps:
# - git + Debian Node.js/npm for the pipeline
# - cairo/pango/font stack for WeasyPrint PDF rendering
# Avoid the NodeSource bootstrap here because it is heavier on low-memory Docker Desktop setups.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        curl \
        ca-certificates \
        nodejs \
        npm \
        libcairo2 \
        libfontconfig1 \
        libharfbuzz0b \
        libharfbuzz-subset0 \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libpangoft2-1.0-0 \
        libgdk-pixbuf-2.0-0 \
        libffi8 \
        shared-mime-info \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

RUN --mount=type=cache,target=/root/.npm,sharing=locked \
    npm install -g --no-fund --no-audit @cyclonedx/cdxgen \
    && apt-get clean \
    && npm cache clean --force

WORKDIR /app

# Install Python deps (pipeline first, then gui — avoids duplicate downloads)
COPY requirements.txt requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    pip install --upgrade pip \
    && pip install --prefer-binary -r requirements.txt

# Copy source code
COPY knowledge_graph/ /app/knowledge_graph/
COPY gui_retrieval/ /app/gui_retrieval/

RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8501

# Streamlit runs from gui_retrieval/
WORKDIR /app/gui_retrieval
CMD ["streamlit", "run", "main.py", "--server.port=8501", "--server.address=0.0.0.0"]
