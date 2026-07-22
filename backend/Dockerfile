FROM python:3.13-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

RUN apt-get update && apt-get install -y --no-install-recommends \
      libmagic1 \
      libyara9 \
      sleuthkit \
      libewf2 \
      ewf-tools \
      fonts-dejavu-core \
      tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app
COPY migrations ./migrations
COPY alembic.ini ./alembic.ini
COPY rules ./rules

RUN groupadd --gid 10001 micepp \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin micepp \
    && mkdir -p /evidence /work /reports /models \
    && chown -R micepp:micepp /app /evidence /work /reports /models

USER 10001:10001
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
