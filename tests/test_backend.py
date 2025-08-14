# pylint: disable=missing-module-docstring,missing-function-docstring,missing-class-docstring

from typing import Optional

from keyring.testing.backend import BackendBasicTests

from linux_keyring.backend import LinuxKernelKeyringBackend, InvalidEmptyPasswordError


class TestLinuxKernelKeyringBackend(BackendBasicTests):
    def init_keyring(self) -> LinuxKernelKeyringBackend:
        class TestableLinuxKernelKeyringBackend(LinuxKernelKeyringBackend):
            empty_password = "empty-password"

            def get_password(self, service: str, username: str) -> Optional[str]:
                password = super().get_password(service, username)
                if password == self.empty_password:
                    return ''
                return password

            def set_password(self, service: str, username: str, password: str) -> None:
                try:
                    super().set_password(service, username, password)
                except InvalidEmptyPasswordError:
                    super().set_password(service, username, self.empty_password)

        return TestableLinuxKernelKeyringBackend(parent_keyring="@s")
