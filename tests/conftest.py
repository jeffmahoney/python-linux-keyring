# pylint: disable=missing-module-docstring,missing-function-docstring,missing-class-docstring

import os
import platform
import pytest


def _kernel_supports_keyrings() -> bool:
    return platform.system() == "Linux" and os.path.exists("/proc")


def pytest_runtest_setup(item: pytest.Item) -> None:  # pylint: disable=unused-argument
    if not _kernel_supports_keyrings():
        pytest.skip("Keyrings unsupported in this environment")
