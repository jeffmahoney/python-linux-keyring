.PHONY: install-dev lint test check pre-commit-install

install-dev:
	python -m pip install --upgrade pip
	pip install -e .
	pip install '.[dev]' pre-commit

lint:
	flake8 src tests
	pylint src/linux_keyring tests
	mypy src/linux_keyring tests

test:
	pytest -q --maxfail=1 --disable-warnings

check: lint test

pre-commit-install:
	pre-commit install
	pre-commit install --hook-type pre-push
	@echo "Installed pre-commit hooks:"
	@pre-commit run --all-files || true
