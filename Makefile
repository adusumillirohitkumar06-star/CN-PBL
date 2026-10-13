.PHONY: help setup test lint demo report fuzz dashboard clean

help:
	@echo "Syntactica — make targets"
	@echo "  setup      install package with dev + nn extras"
	@echo "  test       run the test suite"
	@echo "  lint       run ruff"
	@echo "  demo       fast end-to-end smoke run (n-gram only)"
	@echo "  report     full pipeline -> dashboard artefacts"
	@echo "  fuzz       grammar-guided fuzzing vs the mock resolver"
	@echo "  dashboard  serve the dashboard at http://localhost:8000"

setup:
	python -m pip install -e ".[nn,dev]"

test:
	pytest -q

lint:
	ruff check src tests

demo:
	syntactica demo

report:
	syntactica report

fuzz:
	syntactica fuzz -n 500 --temperature 1.3

dashboard:
	cd dashboard && python -m http.server 8000

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
