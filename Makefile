.PHONY: install run test test-unit test-integration test-edge test-perf lint clean

VENV := .venv
PYTHON := $(VENV)/bin/python
PYTEST := $(VENV)/bin/pytest
UVICORN := $(VENV)/bin/uvicorn

install:
	/home/sgp-z/.local/bin/uv pip install --python $(PYTHON) -r requirements.txt
	/home/sgp-z/.local/bin/uv pip install --python $(PYTHON) -e .

run:
	$(UVICORN) src.api.main:app --host 0.0.0.0 --port 8080 --reload

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

clean:
	rm -rf __pycache__ .pytest_cache .coverage
	find . -type d -name "__pycache__" -exec rm -rf {} +
