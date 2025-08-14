# linux-keyutils

Python API for interfacing with Linux Kernel Keyrings

This module is a wrapper around the libkeyutils library maintained at:
    https://git.kernel.org/pub/scm/linux/kernel/git/dhowells/keyutils.git

This module is used to control the key management system built into the Linux

 Tests focus on unprivileged and error-path cases you can run safely.

## Build & Test

```bash
# Install system deps (examples)
#   openSUSE: sudo zypper in keyutils keyutils-devel python3-devel
#   Debian/Ubuntu: sudo apt-get install keyutils libkeyutils-dev python3-dev

pip install .
```

## Documentation

Build the Sphinx docs:

```bash
python -m pip install -r docs/requirements.txt  # optional if you want pinned deps
sphinx-build -b html docs docs/_build/html
```

Open `docs/_build/html/index.html` in your browser.

## Tests

Unit tests that do not require a running kernel keyring are under `tests/test_wrappers_unit.py`.
Integration tests that exercise the kernel keyring are under `tests/test_keyutils_unpriv.py`
and are skipped automatically on non-Linux hosts.  Not that I can think of a good reason why
you'd want to install this on a non-Linux host.

```bash
pytest -q
```
