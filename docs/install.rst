
Installation
============

This package wraps **libkeyutils** and requires a Linux system with the development
headers for the *keyutils* library.

Prerequisites
-------------

- Linux kernel with keyrings enabled.
- keyutils development package:
  - Debian/Ubuntu: ``sudo apt-get install libkeyutils-dev``
  - Fedora/RHEL: ``sudo dnf install keyutils-libs-devel``
  - openSUSE: ``sudo zypper install libkeyutils-devel``

From source
-----------

.. code-block:: bash

   python -m pip install --upgrade build
   python -m build
   python -m pip install dist/keyutils-0.3.0-*.whl

Editable install (for development)
----------------------------------

.. code-block:: bash

   python -m pip install -e .[test]
   pytest -q
