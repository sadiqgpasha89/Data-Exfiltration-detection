.PHONY: install run test test-unit test-integration test-edge test-perf test-eval benchmark lint audit keys docker clean

VENV := .venv
PYTHON := $(VENV)/bin/python
PYTEST := $(PYTHON) -m pytest
UVICORN := $(PYTHON) -m uvicorn

install:
	python3 -m venv $(VENV)
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements-dev.txt
	$(PYTHON) -m pip install -e .

run:  # development server: authentication off, simulator on. Use `docker compose up` for the production-shaped run.
	AUTH_DISABLED=true $(UVICORN) src.api.main:app --host 127.0.0.1 --port 8080 --reload

test:
	$(PYTEST) tests -v --cov=src --cov-report=term-missing

test-unit:
	$(PYTEST) tests/unit -v

test-integration:
	$(PYTEST) tests/integration -v

test-edge:
	$(PYTEST) tests/edge_case -v

test-perf:
	$(PYTEST) tests/performance -v

test-eval:
	$(PYTEST) tests/evaluation -v

benchmark:  # measured model quality on the labelled synthetic benchmark
	$(PYTHON) -W ignore -m src.evaluation.benchmark

lint:
	$(PYTHON) -m ruff check src tests

audit:  # known vulnerabilities in the dependency set
	$(PYTHON) -m pip_audit -r requirements.txt

keys:  # one API key and one tokenization key, to paste into .env
	@$(PYTHON) -c "import secrets; print('TOKENIZATION_KEY_HEX=' + secrets.token_hex(32)); print('API_KEYS=admin:admin:' + secrets.token_urlsafe(32))"

docker:
	docker build -t sentinel-exfil .

clean:
	rm -rf __pycache__ .pytest_cache .coverage .ruff_cache
	find . -type d -name "__pycache__" -not -path "./.venv/*" -exec rm -rf {} +
