# ══════════════════════════════════════════════════════════════════════════
# Apex-PQ — Post-Quantum Identity Ecosystem Dockerfile
# FIPS 204 ML-DSA-44 Lattice Signatures + 3-Node BFT Decentralized Ledger
# ══════════════════════════════════════════════════════════════════════════

FROM python:3.11-slim AS base

# Install system utilities & libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Set up library and app environment
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH \
    PORT=8080

WORKDIR /app

# Install Post-Quantum liboqs shared library
# Copies precompiled liboqs into standard system dynamic library path
COPY liboqs/install/usr/local/lib/liboqs.so* /usr/local/lib/
COPY liboqs/install/usr/local/include/oqs /usr/local/include/oqs
RUN ldconfig /usr/local/lib

# Install Python application dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy Apex-PQ backend application and wallet assets
COPY pqc-identity /app

# Ensure database directory exists with correct permissions
RUN mkdir -p /app/db

# Health check endpoint
HEALTHCHECK --interval=20s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT}/login || exit 1

EXPOSE 8080

# Run the Apex-PQ Gateway & BFT Ledger application
CMD ["python", "app.py"]
