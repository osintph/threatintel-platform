.PHONY: help install dev-install lock test lint format run stop logs shell stats hits check-tor users clean

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ── Setup ───────────────────────────────────────────────────────────────────
install:  ## Install production dependencies
	pip install -e ".[all]"

dev-install:  ## Install all dependencies including dev tools
	pip install -e ".[dev,all]"
	@echo "✅ Dev environment ready"

setup:  ## First-time setup: copy config examples
	@cp -n .env.example .env || true
	@cp -n config/keywords.example.yaml config/keywords.yaml || true
	@cp -n config/seeds.example.txt config/seeds.txt || true
	@echo "✅ Config files created. Edit .env, config/keywords.yaml, and config/seeds.txt"

lock:  ## Regenerate requirements.lock (exact versions with hashes; needs uv)
	uv pip compile pyproject.toml --extra all --universal --python-version 3.11 \
		--generate-hashes --upgrade --custom-compile-command "make lock" -o requirements.lock

# ── Testing ─────────────────────────────────────────────────────────────────
test:  ## Run unit tests
	pytest tests/unit/ -v

test-all:  ## Run all tests including integration (requires Tor)
	TOR_INTEGRATION=1 pytest tests/ -v

test-cov:  ## Run tests with coverage report
	pytest tests/unit/ --cov=darkweb_scanner --cov-report=html
	@echo "Coverage report: htmlcov/index.html"

# ── Code quality ─────────────────────────────────────────────────────────────
lint:  ## Run ruff linter + mypy
	ruff check src/ tests/
	mypy src/

format:  ## Auto-format code with ruff
	ruff format src/ tests/

security:  ## Run bandit security scanner
	bandit -r src/ -ll

# ── Docker ───────────────────────────────────────────────────────────────────
build:  ## Build Docker images
	docker compose build

run:  ## Start dashboard (and Tor) in background
	docker compose up -d
	@echo "✅ Dashboard running at https://localhost (self-signed certificate unless DOMAIN is set)"

scan:  ## Run a crawl scan (foreground)
	docker compose --profile scan run --rm scanner python -m darkweb_scanner.main scan

stop:  ## Stop all containers
	docker compose down

logs:  ## Tail logs from all containers
	docker compose logs -f

logs-scanner:  ## Tail scanner logs only
	docker compose logs -f scanner

shell:  ## Open shell in app container
	docker compose exec dashboard bash

# ── CLI shortcuts ─────────────────────────────────────────────────────────────
check-tor:  ## Verify Tor connectivity
	docker compose exec dashboard python -m darkweb_scanner.main check-tor

stats:  ## Show scan statistics
	docker compose exec dashboard python -m darkweb_scanner.main stats

hits:  ## Show recent keyword hits
	docker compose exec dashboard python -m darkweb_scanner.main hits

users:  ## List accounts and sign-in locks (unlock: see docs/runbook.md)
	docker compose exec dashboard python -m darkweb_scanner.main user-list

# ── Maintenance ───────────────────────────────────────────────────────────────
check-seeds:  ## Show currently configured seed URLs
	docker compose exec dashboard python -c "from pathlib import Path; f=Path('/app/data/seeds.txt'); print(f.read_text() if f.exists() else 'No seeds in /app/data/seeds.txt — add via dashboard Seeds tab')"


telegram-auth:  ## Authenticate with Telegram (run once before telegram-scan)
	docker compose exec dashboard python -m darkweb_scanner.main telegram-auth

telegram-scan:  ## Scrape configured Telegram channels for keyword hits
	docker compose exec dashboard python -m darkweb_scanner.main telegram-scan

clean:  ## Remove build artifacts and cache
	rm -rf dist/ build/ *.egg-info htmlcov/ .coverage .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

clean-data:  ## ⚠️  Delete all scan data (irreversible)
	@read -p "Delete all scan data? [y/N] " confirm; \
	[ "$$confirm" = "y" ] && docker volume rm darkweb-scanner_app_data || echo "Aborted."
