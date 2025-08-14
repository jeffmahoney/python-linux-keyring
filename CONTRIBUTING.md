# Contributing / Local checks

## One-time setup

```bash
python -m venv .venv
source .venv/bin/activate
make install-dev
pre-commit install
pre-commit install --hook-type pre-push
```

## Before you commit

Pre-commit runs `black`, `flake8`, and `pylint` on staged files.

```bash
git add -p
pre-commit run
```

## Before you push

A pre-push hook runs the test suite:

```bash
git push  # will run pytest via pre-commit
```
