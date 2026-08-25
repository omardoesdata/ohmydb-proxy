FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd --system sqlsafety \
    && useradd --system --gid sqlsafety --home-dir /nonexistent sqlsafety

COPY pyproject.toml README.md LICENSE ./
COPY sql_safety_proxy ./sql_safety_proxy

RUN python -m pip install --upgrade pip \
    && python -m pip install .

USER sqlsafety

EXPOSE 5433 3307

ENTRYPOINT ["ohmydb"]
