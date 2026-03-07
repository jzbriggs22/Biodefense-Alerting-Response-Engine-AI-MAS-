.PHONY: test test-cov verify adversarial traceability clean

test:
	python -m pytest tests/ -v --tb=short

test-cov:
	python -m pytest tests/ -v --tb=short --cov=src --cov-report=term-missing

verify:
	python scripts/verify_gate.py

adversarial:
	python scripts/verify_gate.py --step adversarial

traceability:
	python scripts/verify_gate.py --step traceability

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	rm -rf .coverage htmlcov/ dist/ build/ *.egg-info/
