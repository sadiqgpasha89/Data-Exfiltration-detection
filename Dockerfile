# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    APP_ENV=production \
    LEDGER_PATH=/var/lib/sentinel/ledger.jsonl

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY src ./src
# Sample reference data. In production, mount your own directory and point the *_PATH settings at it.
COPY data ./data

RUN useradd --create-home --uid 10001 sentinel \
    && mkdir -p /var/lib/sentinel \
    && chown sentinel /var/lib/sentinel
USER sentinel
VOLUME ["/var/lib/sentinel"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/readyz', timeout=4).status == 200 else 1)"

# One worker on purpose. The case queue, feature windows, rate limiter and the ledger file are per process; running several
# workers would give each its own copy and let them interleave appends to one ledger. Scale by sharding telemetry across
# instances (one ledger each), or move that state to shared stores first.
CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "--proxy-headers"]
