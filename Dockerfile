# Hermes v2 — production image (python:3.13-slim, non-root, stateless code)
FROM python:3.13-slim AS base

ARG VERSION=2.0.0
ARG GIT_SHA=dev
ARG BUILD_TIME=unknown
ENV HERMES_GIT_SHA=${GIT_SHA} \
    HERMES_BUILD_TIME=${BUILD_TIME} \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# runtime deps only (kept deliberately small: aiohttp, PyYAML, pydantic)
WORKDIR /app
COPY pyproject.toml README.md ./
COPY hermes ./hermes
RUN pip install --no-cache-dir .

# openssh-client: the guarded executor dispatches through the hardened SSH
# operator (fixed argv verbs, no shell); no docker.sock is ever mounted
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*

# dedicated service user (matches the legacy Hermes uid so /data ownership
# migrates 1:1 on the Unraid host)
RUN useradd --uid 10000 --user-group --home-dir /data --shell /usr/sbin/nologin hermes \
    && mkdir -p /data && chown hermes:hermes /data

USER hermes
WORKDIR /app
VOLUME ["/data"]
EXPOSE 8643

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:8643/health', timeout=4); sys.exit(0 if r.status==200 else 1)"

ENTRYPOINT ["python", "-m", "hermes"]
CMD ["--config", "/data/config.yaml", "daemon"]
