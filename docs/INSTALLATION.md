# Installation — NIGHTHAWK OSINT

## Requirements

- Python 3.11+
- pip

## From source (Windows, Linux, Kali, Ubuntu, Debian)

```bash
git clone https://github.com/<you>/nighthawk-osint.git
cd nighthawk-osint

python -m venv .venv
# Windows: .venv\Scripts\Activate.ps1
# Linux/macOS: source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
```

The dashboard (FastAPI) requires extra dependencies:

```bash
pip install "fastapi>=0.111.0" "uvicorn[standard]>=0.30.0" "jinja2>=3.1.0" "python-multipart>=0.0.9"
```

## Configuration

Copy `.env.example` to `.env` and review the values. No API keys are required to
run the core modules; optional search/HIBP integrations need keys set in the
environment.

```bash
cp .env.example .env
```

## Verification

```bash
nighthawk --help
nighthawk username octocat
nighthawk domain example.com
```

## Docker

```bash
docker compose up --build
```

The dashboard is then available at http://127.0.0.1:8000.

## Data directory

SQLite database and exports are written to `nighthawk_data/` (or the path set by
`NIGHTHAWK_DATA_DIR`) relative to the working directory.
