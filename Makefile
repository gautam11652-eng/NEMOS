.PHONY: test compile audit build clean

test:
	python -m pytest -q

compile:
	python -m compileall -q main.py nemos tests

audit:
	python -m pip_audit -r requirements.txt

build:
	python -m build

clean:
	rm -rf build dist *.egg-info .pytest_cache .coverage
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

.PHONY: demo
demo:
	PYTHONPATH=. python tools/validate_detection.py
