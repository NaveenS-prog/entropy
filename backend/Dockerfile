FROM python:3.11-slim

# Install system dependencies including git (needed for git clone)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency definition
COPY pyproject.toml ./
COPY requirements.lock* ./

# Install python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Copy application source code
COPY app/ ./app/

# Environment defaults
ENV PYTHONUNBUFFERED=1 \
    PORT=8000 \
    ENTROPY_ALLOW_LOCALHOST_NO_KEY=true \
    SCAN_ALLOWED_ROOTS="/tmp,.scans,."

EXPOSE 8000

# Start FastAPI application binding to $PORT dynamically
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
