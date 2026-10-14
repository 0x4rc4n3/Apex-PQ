# ── Stage 1: build liboqs (ML-DSA-44 only) from pinned upstream source ───────
# Building from source avoids shipping a prebuilt binary tied to one glibc/OpenSSL/CPU.
FROM python:3.12-slim-bookworm AS oqs-build
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git cmake ninja-build gcc g++ \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs.git /src/liboqs
RUN cmake -S /src/liboqs -B /build -GNinja \
        -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
        -DOQS_MINIMAL_BUILD="SIG_ml_dsa_44" -DOQS_USE_OPENSSL=OFF \
        -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_INSTALL_PREFIX=/opt/oqs \
    && cmake --build /build && cmake --install /build

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM python:3.12-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PORT=8080 HOST=0.0.0.0 \
    OQS_LIB=/opt/oqs/lib/liboqs.so
COPY --from=oqs-build /opt/oqs /opt/oqs
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --system --uid 10001 --home /app apex \
    && mkdir -p /data && chown apex /data
COPY --chown=apex pqc-identity /app
USER apex
ENV APEX_DATA_DIR=/data
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=20s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,os;urllib.request.urlopen('http://127.0.0.1:%s/login'%os.environ.get('PORT','8080'))"
# One worker: rate limiting and the ledger write-lock are in-process.
CMD ["sh", "-c", "exec gunicorn -w 1 --threads 8 -b ${HOST}:${PORT} app:app"]
