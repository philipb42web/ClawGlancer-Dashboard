FROM ghcr.io/phioranex/openclaw-docker:latest

USER root
RUN set -eux; \
  if command -v apt-get >/dev/null 2>&1; then \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      python3 python3-pip python3-requests ca-certificates curl; \
    rm -rf /var/lib/apt/lists/*; \
  elif command -v apk >/dev/null 2>&1; then \
    apk add --no-cache python3 py3-pip ca-certificates curl; \
    python3 -m pip install --no-cache-dir --break-system-packages requests; \
  else \
    echo "Unsupported base image: no apt-get or apk found" >&2; exit 1; \
  fi

USER node
