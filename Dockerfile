FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# System deps: git + Node.js/cdxgen for the pipeline
RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl ca-certificates gnupg \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && npm install -g @cyclonedx/cdxgen \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps (pipeline first, then gui — avoids duplicate downloads)
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY knowledge_graph/ /app/knowledge_graph/
COPY gui_retrieval/ /app/gui_retrieval/

EXPOSE 8501

# Streamlit runs from gui_retrieval/
WORKDIR /app/gui_retrieval
CMD ["streamlit", "run", "main.py", "--server.port=8501", "--server.address=0.0.0.0"]
