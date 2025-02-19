FROM python:3.9-slim

ARG NODE_PORT=8000
ENV NODE_PORT=${NODE_PORT}

# Install OS dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    python3-dev \
    libffi-dev \
    libpq-dev \
    iputils-ping \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip first, then install sokoweb
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir sokoweb==0.1.42

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

EXPOSE ${NODE_PORT}/tcp
EXPOSE ${NODE_PORT}/udp

# Example invocation: run uvicorn
CMD ["sh", "-c", "uvicorn sokoweb.sokoweb.api:app --host 0.0.0.0 --port ${NODE_PORT}"]