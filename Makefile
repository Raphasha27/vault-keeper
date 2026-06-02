.PHONY: install
test:
	python -m pytest tests/
install:
	pip install -e .
