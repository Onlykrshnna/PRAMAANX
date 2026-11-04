# ==============================================================================
# PRAMAANX Forensic Backend - Production Dockerfile
# Hardened, non-root, Python 3.11 environment for untrusted document analysis
# ==============================================================================

FROM python:3.11-slim AS base

# Prevent Python from writing .pyc files and enable unbuffered output for real-time logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install essential system libraries for OpenCV headless, Tesseract OCR, and compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    libgl1 \
    libglib2.0-0 \
    tesseract-ocr \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Set up isolated non-root user for principle of least privilege (Security Requirement)
# Running as non-root prevents container escape and host compromise if an exploit occurs.
RUN groupadd -g 10001 pramaanx && \
    useradd -u 10001 -g pramaanx -m -s /bin/bash pramaanx

WORKDIR /app

# Install Python dependencies
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy backend codebase into container
COPY backend/ /app/backend/

# Create safe upload and temporary scratch directories with appropriate permissions
RUN mkdir -p /app/uploads_tmp /app/backend/models && \
    chown -R pramaanx:pramaanx /app

# Switch to non-root user
USER pramaanx

# Expose internal API port
EXPOSE 8000

# Healthcheck for container orchestration
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Launch production server
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]

