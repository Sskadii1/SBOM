FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive
ENV PIP_DEFAULT_TIMEOUT=300
ENV PIP_RETRIES=10
ENV PIP_PROGRESS_BAR=off

# System deps: git + Debian Node.js/npm for the pipeline.
# Avoid the NodeSource bootstrap here because it is heavier on low-memory Docker Desktop setups.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl ca-certificates nodejs npm \
    && npm install -g @cyclonedx/cdxgen \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps (pipeline first, then gui — avoids duplicate downloads)
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir --prefer-binary -r requirements.txt

# Copy source code
COPY knowledge_graph/ /app/knowledge_graph/
COPY gui_retrieval/ /app/gui_retrieval/

EXPOSE 8501

# Streamlit runs from gui_retrieval/
WORKDIR /app/gui_retrieval
CMD ["streamlit", "run", "main.py", "--server.port=8501", "--server.address=0.0.0.0"]
