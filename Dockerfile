FROM python:3.12-slim

LABEL maintainer="VenomStrike Contributors"
LABEL description="VenomStrike — Advanced Security Testing Framework (Educational)"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create reports directory
RUN mkdir -p /app/reports

# Environment variables
ENV FLASK_HOST=0.0.0.0
ENV FLASK_PORT=5000
ENV VS_DB_PATH=/app/data/venomstrike.db
ENV VS_REPORTS_DIR=/app/reports

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# Default: run web UI
CMD ["python", "run.py"]
