# Contributing to NIGHTHAWK OSINT

Thank you for considering a contribution. NIGHTHAWK OSINT is a defensive OSINT
framework: only public, legally obtainable information is collected.

## Ground rules

1. **No offensive functionality.** Contributions must not add credential theft,
   password cracking, authentication bypass, scraping protections evasion,
   intrusive scanning, exploits, malware or phishing.
2. **No fake data.** Modules must never invent or simulate results.
3. **No committed secrets.** API keys must come from environment variables only.
4. **Tests.** New modules must include pytest tests with mocked external calls.
5. **Keep it small.** Prefer the smallest change that fully solves the problem.

## Development setup

```bash
git clone https://github.com/<you>/nighthawk-osint.git
cd nighthawk-osint
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
pip install "fastapi>=0.111.0" "uvicorn[standard]>=0.30.0" "jinja2>=3.1.0" "python-multipart>=0.0.9"
pip install pytest pytest-asyncio ruff
```

## Running checks

```bash
pytest
ruff check .
```

## Submitting changes

1. Fork the repository.
2. Create a feature branch from `main`.
3. Add or update tests for your change.
4. Run the full test suite and `ruff`.
5. Open a pull request describing the change and any privacy impact.

## Code style

- Python 3.11+ type hints.
- Docstrings on public functions.
- Follow the existing file layout under `nighthawk/`.
