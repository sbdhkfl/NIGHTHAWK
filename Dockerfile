# NIGHTHAWK OSINT Dockerfile
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NIGHTHAWK_HOST=0.0.0.0 \
    NIGHTHAWK_PORT=8000 \
    NIGHTHAWK_DATABASE_URL=sqlite:////data/nighthawk.db \
    NIGHTHAWK_DATA_DIR=/data

WORKDIR /app

# System dependencies: minimal (cairo/pango for Pillow image handling)
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libpq5 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir "fastapi>=0.111.0" "uvicorn[standard]>=0.30.0" "jinja2>=3.1.0" "python-multipart>=0.0.9"

COPY . /app

RUN mkdir -p /data exports && chmod 777 /data exports

EXPOSE 8000

# Run the CLI by default; use `docker compose up` for the dashboard.
CMD ["nighthawk", "--help"]
